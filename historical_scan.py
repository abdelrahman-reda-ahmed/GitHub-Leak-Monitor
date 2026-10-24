#!/usr/bin/env python3
"""
historical_scan.py - on-demand ref history scan (NOT full-history)
Walks commit history reachable from one specified ref via REST API.
"""
import argparse
import uuid
from db import get_connection, now_iso, heartbeat, upsert_secret_finding, upsert_exposure
from apiqueue import github_api_request
from scanner import scan_content


def main():
    parser = argparse.ArgumentParser(description='Ref history scan (not full-history)')
    parser.add_argument('--repo', required=True, help='owner/name')
    parser.add_argument('--ref', required=True, help='branch_or_tag (required)')
    parser.add_argument('--since-days', type=int, help='limit to recent days')
    args = parser.parse_args()
    
    run_id = str(uuid.uuid4())
    conn = get_connection()
    cur = conn.cursor()
    now = now_iso()
    
    # Get current head
    res = github_api_request('GET', f'/repos/{args.repo}/git/refs/heads/{args.ref}')
    if res.get('_error'):
        res = github_api_request('GET', f'/repos/{args.repo}/git/refs/tags/{args.ref}')
    head_sha = None
    if not res.get('_error'):
        head_sha = res.get('object', {}).get('sha')
    
    cur.execute("""INSERT INTO state (component_name, progress_key, progress_value, run_id, heartbeat_at, component_state, updated_at)
                   VALUES ('historical_scan', 'repo_ref', ?, ?, ?, 'running', ?)""",
                (f'{args.repo}:{args.ref}', run_id, now, now))
    if head_sha:
        cur.execute("UPDATE state SET progress_value = ? WHERE component_name='historical_scan' AND run_id=?",
                    (f'{args.repo}:{args.ref}:head:{head_sha}', run_id))
    conn.commit()
    conn.close()
    
    heartbeat('historical_scan', 'running', run_id=run_id)
    
    # List commits
    path = f'/repos/{args.repo}/commits?sha={args.ref}'
    page = 1
    all_commits = []
    while True:
        res = github_api_request('GET', f'{path}&per_page=100&page={page}')
        if res.get('_error') or not isinstance(res, list):
            break
        if not res:
            break
        all_commits.extend(res)
        page += 1
        if page > 100:  # safety
            break
    
    # Process oldest to newest
    all_commits = list(reversed(all_commits))
    seen_secrets_by_path = {}
    
    for c in all_commits:
        sha = c.get('sha')
        if not sha:
            continue
        cres = github_api_request('GET', f'/repos/{args.repo}/commits/{sha}')
        if cres.get('_error'):
            continue
        for f in cres.get('files', []):
            patch = f.get('patch')
            fname = f.get('filename', '')
            if not patch:
                continue
            secrets, exposures = scan_content(patch, fname, is_diff=True)
            for s in secrets:
                s.target = args.repo
                s.commit_sha_or_url = sha
                upsert_secret_finding(s, 'github', args.repo, sha)
                key = (s.secret_hash, fname)
                if key not in seen_secrets_by_path:
                    seen_secrets_by_path[key] = []
                seen_secrets_by_path[key].append((sha, 'added' if s.diff_status == 'added' else s.diff_status))
            for ex in exposures:
                ex.target = args.repo
                upsert_exposure('github', args.repo, ex.file_path, ex.exposure_type)
        heartbeat('historical_scan', 'running', run_id=run_id)
    
    # Determine exposure_state
    conn2 = get_connection()
    cur2 = conn2.cursor()
    for (shash, fpath), entries in seen_secrets_by_path.items():
        # Check if removed in later commit
        removed = any(e[1] == 'removed' for e in entries)
        if removed and head_sha:
            # Mark earlier as historical_only
            cur2.execute("""UPDATE occurrences SET exposure_state='historical_only' 
                           WHERE secret_id=(SELECT id FROM secrets WHERE secret_hash=?) 
                           AND file_path=? AND exposure_state='live'""", (shash, fpath))
    conn2.commit()
    conn2.close()
    
    heartbeat('historical_scan', 'idle', run_id=run_id, update_progress=True)
    print(f'Completed historical scan run {run_id}')


if __name__ == '__main__':
    main()
