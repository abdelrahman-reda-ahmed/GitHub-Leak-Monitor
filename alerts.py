#!/usr/bin/env python3
"""
alerts.py - Telegram sender + outbox worker
At-least-once delivery, not exactly-once
"""
import json
import time
from datetime import datetime, timedelta
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from config import config
from db import get_connection, now_iso


def send_telegram_alert(text: str) -> bool:
    if not config.TELEGRAM_BOT_TOKEN or not config.TELEGRAM_CHAT_ID:
        return False
    try:
        url = f'https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage'
        body = json.dumps({
            'chat_id': config.TELEGRAM_CHAT_ID,
            'text': text,
            'parse_mode': 'HTML',
            'disable_web_page_preview': True,
        }).encode()
        req = Request(url, data=body, headers={'Content-Type': 'application/json'}, method='POST')
        resp = urlopen(req, timeout=10)
        return resp.status == 200
    except Exception as e:
        print(f'Telegram send error: {e}')
        return False


def format_finding_alert(secret: dict, is_severity_bump: bool = False) -> str:
    emoji = {'low': '🟡', 'medium': '🟠', 'high': '🔴', 'critical': '🚨'}.get(secret.get('severity'), '⚠️')
    msg = f"{emoji} <b>LEAKMON</b>\n"
    msg += f"Type: {secret.get('secret_type')}\n"
    msg += f"Preview: {secret.get('masked_preview')}\n"
    msg += f"Severity: {secret.get('severity')}\n"
    if is_severity_bump:
        msg += f"Now seen in {secret.get('distinct_target_count', '?')} repos/domains\n"
    msg += f"Dashboard: http://127.0.0.1:{config.DASHBOARD_PORT}\n"
    return msg


def outbox_worker_once():
    """Process unsent outbox rows once"""
    conn = get_connection()
    try:
        cur = conn.cursor()
        # Get unsent, not retried too recently
        cur.execute("""SELECT * FROM alert_outbox 
                       WHERE sent_at IS NULL 
                       AND (last_attempt_at IS NULL OR last_attempt_at < ?)
                       AND delivery_attempts < ?
                       ORDER BY id LIMIT 10""",
                    ((datetime.utcnow() - timedelta(seconds=60)).isoformat() + 'Z',
                     config.ALERT_OUTBOX_MAX_ATTEMPTS))
        rows = cur.fetchall()
        for row in rows:
            try:
                payload = json.loads(row['payload'])
                text = format_finding_alert(payload, payload.get('is_severity_bump', False))
                ok = send_telegram_alert(text)
                if ok:
                    cur.execute("UPDATE alert_outbox SET sent_at = ? WHERE id = ?",
                                (now_iso(), row['id']))
                else:
                    cur.execute("""UPDATE alert_outbox 
                                   SET delivery_attempts = delivery_attempts + 1,
                                       last_attempt_at = ?, last_error = ?
                                   WHERE id = ?""",
                                (now_iso(), 'send_failed', row['id']))
                # Pace sends
                time.sleep(1.1)
            except Exception as e:
                cur.execute("""UPDATE alert_outbox 
                               SET delivery_attempts = delivery_attempts + 1,
                                   last_attempt_at = ?, last_error = ?
                               WHERE id = ?""",
                            (now_iso(), str(e)[:200], row['id']))
        conn.commit()
    finally:
        conn.close()


def outbox_worker_loop():
    """Continuous outbox worker loop"""
    while True:
        try:
            outbox_worker_once()
        except Exception as e:
            print(f'Outbox worker error: {e}')
        time.sleep(30)


def send_daily_digest():
    """Send daily digest via outbox"""
    conn = get_connection()
    try:
        cur = conn.cursor()
        since = (datetime.utcnow() - timedelta(days=1)).isoformat() + 'Z'
        cur.execute("SELECT severity, COUNT(*) as c FROM secrets WHERE first_seen_at > ? GROUP BY severity", (since,))
        counts = dict((r['severity'], r['c']) for r in cur.fetchall())
        msg = f"📊 <b>LEAKMON Daily Digest (24h)</b>\n"
        msg += f"Critical: {counts.get('critical',0)} | High: {counts.get('high',0)} | Medium: {counts.get('medium',0)} | Low: {counts.get('low',0)}\n"
        payload = json.dumps({'type': 'digest', 'text': msg})
        cur.execute("INSERT INTO alert_outbox (alert_type, payload, created_at) VALUES (?,?,?)",
                    ('digest', payload, now_iso()))
        conn.commit()
    finally:
        conn.close()


if __name__ == '__main__':
    outbox_worker_loop()
