#!/usr/bin/env python3
"""
search_provider.py - web search abstraction layer (Tavily primary, credit-aware)
Never scrapes search engine HTML. Only official documented JSON APIs.
"""
import json
import time
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from config import config
from db import get_connection, now_iso


def _state_get(conn, key):
    cur = conn.cursor()
    cur.execute("SELECT progress_value FROM state WHERE component_name='search' AND progress_key=?", (key,))
    row = cur.fetchone()
    return row['progress_value'] if row else None


def _state_set(conn, key, value):
    cur = conn.cursor()
    cur.execute("""INSERT INTO state (component_name, progress_key, progress_value, updated_at)
                   VALUES ('search', ?, ?, ?)
                   ON CONFLICT(component_name) DO UPDATE SET progress_value=?, updated_at=?""",
                (key, value, now_iso(), value, now_iso()))
    conn.commit()


def _month_key():
    return datetime.utcnow().strftime('%Y-%m')


def _day_key():
    return datetime.utcnow().strftime('%Y-%m-%d')


def _track_credits(conn, credits):
    """Track Tavily credits consumed this month."""
    key = f'credits_{_month_key()}'
    cur = conn.cursor()
    cur.execute("SELECT progress_value FROM state WHERE component_name='search_quota' AND progress_key=?", (key,))
    row = cur.fetchone()
    total = int(row['progress_value']) if row else 0
    total += int(credits)
    cur.execute("""INSERT INTO state (component_name, progress_key, progress_value, updated_at)
                   VALUES ('search_quota', ?, ?, ?)
                   ON CONFLICT(component_name) DO UPDATE SET progress_value=?, updated_at=?""",
                (key, str(total), now_iso(), str(total), now_iso()))
    conn.commit()
    return total


def _credits_used(conn):
    key = f'credits_{_month_key()}'
    cur = conn.cursor()
    cur.execute("SELECT progress_value FROM state WHERE component_name='search_quota' AND progress_key=?", (key,))
    row = cur.fetchone()
    return int(row['progress_value']) if row else 0


def _daily_used(conn):
    key = f'daily_{_day_key()}'
    cur = conn.cursor()
    cur.execute("SELECT progress_value FROM state WHERE component_name='search_quota' AND progress_key=?", (key,))
    row = cur.fetchone()
    return int(row['progress_value']) if row else 0


def _daily_inc(conn):
    key = f'daily_{_day_key()}'
    cur = conn.cursor()
    used = _daily_used(conn) + 1
    cur.execute("""INSERT INTO state (component_name, progress_key, progress_value, updated_at)
                   VALUES ('search_quota', ?, ?, ?)
                   ON CONFLICT(component_name) DO UPDATE SET progress_value=?, updated_at=?""",
                (key, str(used), now_iso(), str(used), now_iso()))
    conn.commit()
    return used


def quota_available():
    conn = get_connection()
    try:
        if config.SEARCH_PROVIDER == 'tavily':
            return _credits_used(conn) < config.SEARCH_MONTHLY_QUOTA
        elif config.SEARCH_PROVIDER == 'google_cse':
            return _daily_used(conn) < config.SEARCH_DAILY_QUOTA
        return False
    finally:
        conn.close()


def tavily_search(query: str, num: int = 10) -> list:
    conn = get_connection()
    try:
        if _credits_used(conn) >= config.SEARCH_MONTHLY_QUOTA:
            print('Tavily monthly credit quota exhausted')
            return []
        
        body = json.dumps({
            'api_key': config.TAVILY_API_KEY,
            'query': query,
            'max_results': num,
            'search_depth': 'basic',       # pin - never omit
            'auto_parameters': False,      # never let it upgrade to advanced
            'include_answer': False,
            'include_raw_content': False,
        }).encode()
        req = Request('https://api.tavily.com/search', data=body,
                      headers={'Content-Type': 'application/json'}, method='POST')
        try:
            resp = urlopen(req, timeout=30)
            data = json.loads(resp.read())
        except HTTPError as e:
            print(f'Tavily HTTP error {e.code}')
            return []
        except Exception as e:
            print(f'Tavily error: {e}')
            return []
        
        credits = data.get('usage', {}).get('credits', 1)
        _track_credits(conn, credits)
        
        results = []
        for r in data.get('results', []):
            results.append({
                'title': r.get('title', ''),
                'url': r.get('url', ''),
                'snippet': r.get('content', ''),
            })
        return results
    finally:
        conn.close()


def google_cse_search(query: str, num: int = 10) -> list:
    conn = get_connection()
    try:
        if _daily_used(conn) >= config.SEARCH_DAILY_QUOTA:
            print('Google CSE daily quota exhausted')
            return []
        
        from urllib.parse import urlencode
        params = urlencode({
            'key': config.GOOGLE_API_KEY,
            'cx': config.GOOGLE_CX,
            'q': query,
            'num': min(num, 10),
        })
        url = f'https://www.googleapis.com/customsearch/v1?{params}'
        req = Request(url, headers={'User-Agent': 'leakmon/1.0'})
        try:
            resp = urlopen(req, timeout=30)
            data = json.loads(resp.read())
        except HTTPError as e:
            print(f'Google CSE HTTP error {e.code}')
            return []
        except Exception as e:
            print(f'Google CSE error: {e}')
            return []
        
        _daily_inc(conn)
        results = []
        for item in data.get('items', []):
            results.append({
                'title': item.get('title', ''),
                'url': item.get('link', ''),
                'snippet': item.get('snippet', ''),
            })
        return results
    finally:
        conn.close()


PROVIDERS = {
    'tavily': tavily_search,
    'google_cse': google_cse_search,
}


def search(query: str, num: int = 10) -> list:
    fn = PROVIDERS.get(config.SEARCH_PROVIDER)
    if fn is None:
        raise RuntimeError(f'Unknown search provider: {config.SEARCH_PROVIDER}')
    return fn(query, num)
