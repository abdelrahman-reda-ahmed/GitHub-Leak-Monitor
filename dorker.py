#!/usr/bin/env python3
"""
dorker.py - exposure search scheduler (provider-agnostic)
All searches through search_provider.search() - never vendor call directly
"""
import time
from db import heartbeat, upsert_secret_finding, upsert_exposure
from search_provider import search, quota_available
from safe_fetch import safe_fetch
from scanner import scan_content
from config import config

# Per-provider templates (not assumed identical)
TAVILY_QUERY_TEMPLATES = [
    '"AKIA" filetype:txt',
    '"ghp_" site:github.io',
    '"-----BEGIN RSA PRIVATE KEY-----"',
    'password filetype:env',
]

GOOGLE_CSE_QUERY_TEMPLATES = [
    '"AKIA" intext:key',
    'filetype:env password',
]


def main():
    heartbeat('dorker', 'running')
    idx = 0
    templates = TAVILY_QUERY_TEMPLATES if config.SEARCH_PROVIDER == 'tavily' else GOOGLE_CSE_QUERY_TEMPLATES
    while True:
        try:
            if not quota_available():
                heartbeat('dorker', 'rate_limited')
                time.sleep(300)
                continue
            
            if not templates:
                time.sleep(config.DORK_INTERVAL_SECONDS)
                continue
            
            query = templates[idx % len(templates)]
            idx += 1
            results = search(query, num=10)
            
            for r in results:
                url = r.get('url', '')
                if not url:
                    continue
                content = safe_fetch(url)
                if not content:
                    continue
                secrets, exposures = scan_content(content, url, is_diff=False)
                for s in secrets:
                    s.target = url
                    upsert_secret_finding(s, 'search', url)
                for ex in exposures:
                    ex.target = url
                    upsert_exposure('search', url, ex.file_path, ex.exposure_type)
            
            heartbeat('dorker', 'idle', progress_key='last_query', progress_value=query, update_progress=True)
        except Exception as e:
            print(f'Dorker error: {e}')
            heartbeat('dorker', 'crashed')
        time.sleep(config.DORK_INTERVAL_SECONDS)


if __name__ == '__main__':
    main()
