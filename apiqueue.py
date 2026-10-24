#!/usr/bin/env python3
"""
apiqueue.py - SQLite-backed cross-process GitHub API coordinator (corrected)
Reserve-then-confirm protocol with stale response protection
"""
import sqlite3
import json
import time
import uuid
from datetime import datetime, timedelta
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from db import get_connection, now_iso
try:
    from config import config
except Exception:
    config = None


GITHUB_API_BASE = 'https://api.github.com'


def cleanup_expired_reservations(conn):
    """Return capacity for expired unconfirmed reservations"""
    cur = conn.cursor()
    now = now_iso()
    # Find expired unconfirmed
    cur.execute("SELECT reservation_id, resource FROM reservations WHERE expires_at < ? AND confirmed_at IS NULL", (now,))
    expired = cur.fetchall()
    for res in expired:
        # Decrement reserved
        cur.execute("UPDATE api_budget SET reserved = MAX(0, reserved - 1), updated_at = ? WHERE resource = ?", (now, res['resource']))
        cur.execute("DELETE FROM reservations WHERE reservation_id = ?", (res['reservation_id'],))
    conn.commit()


def github_api_request(method: str, path: str, **kwargs) -> dict:
    """
    ONLY function allowed to call GitHub's REST API directly.
    Reject any method other than GET/HEAD.
    """
    if method not in ('GET', 'HEAD'):
        raise RuntimeError(f'HTTP method {method} not allowed - only GET/HEAD permitted')
    
    if config is None:
        raise RuntimeError('Config not loaded')
    
    resource = 'core'  # GitHub REST API is core
    
    # Reserve
    conn = get_connection()
    cleanup_expired_reservations(conn)
    cur = conn.cursor()
    
    reservation_id = str(uuid.uuid4())
    expires_at = (datetime.utcnow() + timedelta(seconds=30)).isoformat() + 'Z'
    
    try:
        cur.execute('BEGIN IMMEDIATE')
        # Check budget
        cur.execute('SELECT remaining, reserved, secondary_limit_until FROM api_budget WHERE resource = ?', (resource,))
        budget = cur.fetchone()
        if budget is None:
            # Initialize
            cur.execute("INSERT INTO api_budget (resource, remaining, reserved, reset_at, updated_at) VALUES (?,?,?,?,?)",
                        (resource, 5000, 0, (datetime.utcnow() + timedelta(hours=1)).isoformat() + 'Z', now_iso()))
            budget = {'remaining': 5000, 'reserved': 0, 'secondary_limit_until': None}
        
        # Check secondary limit
        if budget['secondary_limit_until']:
            if budget['secondary_limit_until'] > now_iso():
                raise RuntimeError(f'Rate limited until {budget["secondary_limit_until"]}')
        
        # Check if we can reserve
        if budget['remaining'] - budget['reserved'] <= config.GH_RATE_LIMIT_FLOOR:
            raise RuntimeError('Rate limit budget exhausted')
        
        # Make reservation
        cur.execute("INSERT INTO reservations (reservation_id, resource, created_at, expires_at) VALUES (?,?,?,?)",
                    (reservation_id, resource, now_iso(), expires_at))
        cur.execute("UPDATE api_budget SET reserved = reserved + 1, updated_at = ? WHERE resource = ?",
                    (now_iso(), resource))
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        raise
    
    # Send request outside transaction
    url = path if path.startswith('http') else f'{GITHUB_API_BASE}{path}'
    headers = {
        'Authorization': f'token {config.GITHUB_TOKEN}' if config.GITHUB_TOKEN else '',
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'leakmon/1.0'
    }
    
    try:
        req = Request(url, headers=headers, method=method)
        resp = urlopen(req, timeout=30)
        data = resp.read()
        resp_headers = dict(resp.headers)
        status = resp.status
        try:
            result = json.loads(data) if data else {}
        except:
            result = {'raw': data.decode('utf-8', errors='ignore')}
        result['_status'] = status
        result['_headers'] = resp_headers
    except HTTPError as e:
        # Handle 403/429
        resp_headers = dict(e.headers) if e.headers else {}
        if e.code in (403, 429):
            retry_after = resp_headers.get('Retry-After')
            if retry_after:
                try:
                    wait = int(retry_after)
                except:
                    wait = 60
                limit_until = (datetime.utcnow() + timedelta(seconds=wait)).isoformat() + 'Z'
                conn2 = get_connection()
                cur2 = conn2.cursor()
                cur2.execute("UPDATE api_budget SET secondary_limit_until = ?, updated_at = ? WHERE resource = ?",
                             (limit_until, now_iso(), resource))
                conn2.commit()
                conn2.close()
        result = {'_error': True, '_status': e.code, '_headers': resp_headers}
    except Exception as e:
        result = {'_error': True, '_error_msg': str(e)}
    
    # Confirm
    conn3 = get_connection()
    cur3 = conn3.cursor()
    try:
        cur3.execute('BEGIN IMMEDIATE')
        cur3.execute("UPDATE reservations SET confirmed_at = ? WHERE reservation_id = ?", (now_iso(), reservation_id))
        cur3.execute("UPDATE api_budget SET reserved = MAX(0, reserved - 1), updated_at = ? WHERE resource = ?",
                     (now_iso(), resource))
        
        # Update budget from headers if present
        headers_resp = result.get('_headers', {})
        remaining = headers_resp.get('X-RateLimit-Remaining')
        reset = headers_resp.get('X-RateLimit-Reset')
        if remaining is not None and reset is not None:
            try:
                reset_int = int(reset)
                reset_iso = datetime.utcfromtimestamp(reset_int).isoformat() + 'Z'
                cur3.execute("SELECT reset_at FROM api_budget WHERE resource = ?", (resource,))
                current = cur3.fetchone()
                if current is None or current['reset_at'] is None or reset_iso >= current['reset_at']:
                    cur3.execute("UPDATE api_budget SET remaining = ?, reset_at = ?, updated_at = ? WHERE resource = ?",
                                 (int(remaining), reset_iso, now_iso(), resource))
            except Exception:
                pass
        
        conn3.commit()
    except Exception as e:
        conn3.rollback()
    finally:
        conn3.close()
    
    conn.close()
    return result
