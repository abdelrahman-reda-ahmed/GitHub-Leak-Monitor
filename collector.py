#!/usr/bin/env python3
"""
collector.py - GH Archive tailer (Oct 7, 2025 API changes + fallbacks)
"""
import gzip
import json
import time
from datetime import datetime, timedelta
from urllib.request import urlopen

from db import get_connection, now_iso, hour_start, hour_finalize, heartbeat, upsert_secret_finding, upsert_exposure
from apiqueue import github_api_request
from scanner import scan_content
from config import config


def should_include_repo(repo_name, repo_id):
    if not config.SCOPE_ALLOWLIST_ORGS and not config.SCOPE_ALLOWLIST_KEYWORDS:
        return True  # log warning in main
    if config.SCOPE_ALLOWLIST_ORGS:
        for org in config.SCOPE_ALLOWLIST_ORGS:
            if repo_name.startswith(org + '/') or repo_name == org:
                return True
    if config.SCOPE_ALLOWLIST_KEYWORDS:
        rn = repo_name.lower()
        for kw in config.SCOPE_ALLOWLIST_KEYWORDS:
            if kw.lower() in rn:
                return True
    return False


def process_hour(hour_key):
    hour_start(hour_key)
    heartbeat('collector', 'running')
    gap_reasons = []
    
    url = f'https://data.gharchive.org/{hour_key}.json.gz'
    try:
        resp = urlopen(url, timeout=60)
        data = gzip.decompress(resp.read())
    except Exception as e:
        gap_reasons.append(f'download_failed: {e}')
        hour_finalize(hour_key, gap_reasons)
        return
    
    for line in data.decode('utf-8').splitlines():
        try:
            event = json.loads(line)
        except:
            continue
        if event.get('type') != 'PushEvent':
            continue
        repo = event.get('repo', {})
        repo_name = repo.get('name', '')
        repo_id = repo.get('id')
        if not should_include_repo(repo_name, repo_id):
            continue
        
        payload = event.get('payload', {})
        before = payload.get('before')
        head = payload.get('head')
        if not before or not head:
            continue
        
        # Fast path: compare
        if before == '0000000000000000000000000000000000000000':
            # New branch
            res = github_api_request('GET', f'/repos/{repo_name}/commits/{head}')
            if res.get('_error'):
                gap_reasons.append(f'commit_fetch_error:{repo_name}:{head[:7]}')
                continue
            commits = [res]
        else:
            res = github_api_request('GET', f'/repos/{repo_name}/compare/{before}...{head}')
            if res.get('_error'):
                gap_reasons.append(f'compare_error:{repo_name}')
                # Try fallback
                commits = []
            else:
                commits = res.get('commits', [])
                files = res.get('files', [])
                # Check truncation
                if len(commits) >= 250 or len(files) >= 300:
                    # Fallback needed
                    gap_reasons.append(f'truncation_detected:{repo_name}')
                # Process files from compare
                for f in files:
                    patch = f.get('patch')
                    if patch:
                        secrets, exposures = scan_content(patch, f.get('filename', ''), is_diff=True)
                        for s in secrets:
                            s.target = repo_name
                            s.commit_sha_or_url = head
                            upsert_secret_finding(s, 'github', repo_name, head)
                        for ex in exposures:
                            ex.target = repo_name
                            upsert_exposure('github', repo_name, ex.file_path, ex.exposure_type)
                continue  # already processed
        
        # Process commits if fallback/new branch
        for c in commits:
            sha = c.get('sha') if isinstance(c, dict) else None
            if not sha:
                continue
            cres = github_api_request('GET', f'/repos/{repo_name}/commits/{sha}')
            if cres.get('_error'):
                gap_reasons.append(f'commit_detail_error:{repo_name}:{sha[:7]}')
                continue
            for f in cres.get('files', []):
                patch = f.get('patch')
                if not patch:
                    continue  # binary or truncated
                secrets, exposures = scan_content(patch, f.get('filename', ''), is_diff=True)
                for s in secrets:
                    s.target = repo_name
                    s.commit_sha_or_url = sha
                    upsert_secret_finding(s, 'github', repo_name, sha)
                for ex in exposures:
                    ex.target = repo_name
                    upsert_exposure('github', repo_name, ex.file_path, ex.exposure_type)
        
        heartbeat('collector', 'running', update_progress=False)
    
    hour_finalize(hour_key, gap_reasons)
    heartbeat('collector', 'idle', progress_key='last_hour', progress_value=hour_key, update_progress=True)
    print(f'Processed {hour_key}')


def main():
    if not config.SCOPE_ALLOWLIST_ORGS and not config.SCOPE_ALLOWLIST_KEYWORDS:
        print('WARNING: Unfiltered firehose coverage may exhaust free API budget quickly')
    heartbeat('collector', 'running')
    while True:
        try:
            # Process last hour
            now = datetime.utcnow()
            hour_key = (now - timedelta(hours=1)).strftime('%Y-%m-%d-%H')
            process_hour(hour_key)
        except Exception as e:
            print(f'Collector error: {e}')
            heartbeat('collector', 'crashed')
        time.sleep(config.GH_POLL_INTERVAL_SECONDS)


if __name__ == '__main__':
    main()
