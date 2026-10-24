#!/usr/bin/env python3
"""
db.py - SQLite schema + helper functions
"""
import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.expanduser('~/leakmon/leakmon.db')


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA busy_timeout=30000')
    return conn


def init_db():
    conn = get_connection()
    cur = conn.cursor()
    
    # secrets table
    cur.execute('''CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        secret_hash TEXT UNIQUE NOT NULL,
        secret_type TEXT NOT NULL,
        masked_preview TEXT NOT NULL,
        severity TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        occurrence_count INTEGER NOT NULL DEFAULT 0,
        distinct_target_count INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new','acknowledged','false_positive','confirmed','resolved'))
    )''')
    
    # exposures table
    cur.execute('''CREATE TABLE IF NOT EXISTS exposures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT NOT NULL,
        target TEXT NOT NULL,
        file_path TEXT NOT NULL,
        exposure_type TEXT NOT NULL,
        discovered_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'new',
        security_txt_url TEXT,
        bounty_program_url TEXT
    )''')
    
    # occurrences table
    cur.execute('''CREATE TABLE IF NOT EXISTS occurrences (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        secret_id INTEGER NOT NULL,
        source TEXT NOT NULL CHECK(source IN ('github','search')),
        target TEXT NOT NULL,
        file_path TEXT NOT NULL,
        commit_sha_or_url TEXT,
        encoding TEXT CHECK(encoding IS NULL OR encoding IN ('base64','base64url','hex','url','base32')),
        diff_status TEXT CHECK(diff_status IN ('added','removed','context')),
        exposure_state TEXT CHECK(exposure_state IN ('live','historical_only','unknown')),
        fingerprint TEXT UNIQUE NOT NULL,
        discovered_at TEXT NOT NULL,
        security_txt_url TEXT,
        bounty_program_url TEXT,
        FOREIGN KEY (secret_id) REFERENCES secrets(id)
    )''')
    
    # state table
    cur.execute('''CREATE TABLE IF NOT EXISTS state (
        component_name TEXT PRIMARY KEY,
        progress_key TEXT,
        progress_value TEXT,
        run_id TEXT,
        heartbeat_at TEXT,
        progress_at TEXT,
        component_state TEXT CHECK(component_state IN ('running','idle','rate_limited','crashed')),
        updated_at TEXT NOT NULL
    )''')
    
    # gh_archive_hours table
    cur.execute('''CREATE TABLE IF NOT EXISTS gh_archive_hours (
        hour_key TEXT PRIMARY KEY,
        status TEXT NOT NULL CHECK(status IN ('pending','processing','completed','completed_with_gaps')),
        started_at TEXT,
        completed_at TEXT,
        gap_reasons TEXT
    )''')
    
    # api_budget table
    cur.execute('''CREATE TABLE IF NOT EXISTS api_budget (
        resource TEXT PRIMARY KEY CHECK(resource IN ('core','search')),
        remaining INTEGER NOT NULL,
        reserved INTEGER NOT NULL DEFAULT 0,
        reset_at TEXT,
        secondary_limit_until TEXT,
        updated_at TEXT NOT NULL
    )''')
    
    # reservations table
    cur.execute('''CREATE TABLE IF NOT EXISTS reservations (
        reservation_id TEXT PRIMARY KEY,
        resource TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        confirmed_at TEXT
    )''')
    
    # alert_outbox table
    cur.execute('''CREATE TABLE IF NOT EXISTS alert_outbox (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_type TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        sent_at TEXT,
        delivery_attempts INTEGER NOT NULL DEFAULT 0,
        last_attempt_at TEXT,
        last_error TEXT
    )''')
    
    conn.commit()
    conn.close()
    print('Database initialized')


def now_iso():
    return datetime.utcnow().isoformat() + 'Z'


def build_fingerprint(secret_hash, source, target, file_path, commit_sha_or_url):
    """
    Fingerprinting: same secret appearing twice in same file+commit as ONE occurrence.
    This is an intentional design choice (not an oversight): a secret appearing on two
    lines of the same file in the same commit counts as ONE occurrence. A future
    enhancement could add line_number/diff_hunk_identifier to the fingerprint for
    finer granularity, but that is out of scope for this build.
    """
    parts = [secret_hash, source, target, file_path, commit_sha_or_url or ""]
    import hashlib
    encoded = "".join(f"{len(p)}:{p}" for p in parts)
    return hashlib.sha256(encoded.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Shared helpers used identically by collector.py, dorker.py, historical_scan.py
# (never duplicated across those modules)
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ['low', 'medium', 'high', 'critical']
BASE_SEVERITY = {
    'aws_access_key': 'high',
    'github_pat': 'high',
    'slack_token': 'high',
    'stripe_live': 'critical',
    'google_api_key': 'medium',
    'jwt': 'medium',
    'postgres': 'high',
    'mysql': 'high',
    'mongodb': 'high',
    'private_key': 'critical',
    'private_key_header': 'low',
    'high_entropy': 'medium',
}


def severity_for(secret_type):
    return BASE_SEVERITY.get(secret_type, 'medium')


def bump_severity(current, levels=1):
    try:
        idx = SEVERITY_ORDER.index(current)
    except ValueError:
        idx = 1
    idx = min(len(SEVERITY_ORDER) - 1, idx + levels)
    return SEVERITY_ORDER[idx]


def upsert_secret_finding(finding, source, target, commit_sha_or_url=None,
                          security_txt_url=None, bounty_program_url=None):
    """
    Shared upsert. One call per SecretFinding, single transaction.
    Returns (alert_payload_or_None, secret_id).
    Writes alert_outbox AFTER commit (never inside the transaction, never
    calls Telegram directly).
    """
    conn = get_connection()
    cur = conn.cursor()
    alert = None
    secret_id = None
    try:
        cur.execute('BEGIN IMMEDIATE')
        now = now_iso()
        cur.execute('SELECT * FROM secrets WHERE secret_hash = ?', (finding.secret_hash,))
        row = cur.fetchone()
        is_new = row is None
        old_severity = None
        old_distinct = 0
        if is_new:
            cur.execute(
                '''INSERT INTO secrets (secret_hash, secret_type, masked_preview, severity,
                        first_seen_at, last_seen_at, occurrence_count, distinct_target_count, status)
                   VALUES (?,?,?,?,?,?,0,0,'new')''',
                (finding.secret_hash, finding.secret_type, finding.masked_preview,
                 severity_for(finding.secret_type), now, now))
            secret_id = cur.lastrowid
        else:
            secret_id = row['id']
            old_severity = row['severity']
            old_distinct = row['distinct_target_count']

        fingerprint = build_fingerprint(
            finding.secret_hash, source, target, finding.file_path, commit_sha_or_url)
        cur.execute(
            '''INSERT OR IGNORE INTO occurrences
               (secret_id, source, target, file_path, commit_sha_or_url, encoding,
                diff_status, exposure_state, fingerprint, discovered_at,
                security_txt_url, bounty_program_url)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
            (secret_id, source, target, finding.file_path, commit_sha_or_url,
             finding.encoding, finding.diff_status, finding.exposure_state,
             fingerprint, now, security_txt_url, bounty_program_url))
        inserted = cur.rowcount > 0

        if inserted:
            # Recompute from occurrences directly (never increment a stored counter)
            cur.execute('SELECT COUNT(*) AS c FROM occurrences WHERE secret_id = ?', (secret_id,))
            occ_count = cur.fetchone()['c']
            cur.execute('SELECT COUNT(DISTINCT target) AS c FROM occurrences WHERE secret_id = ?', (secret_id,))
            distinct = cur.fetchone()['c']

            new_severity = old_severity if old_severity else severity_for(finding.secret_type)
            is_bump = False
            if distinct >= 2 and old_distinct < 2:
                new_severity = bump_severity(new_severity)
                is_bump = True
            if distinct >= 5 and old_distinct < 5:
                new_severity = bump_severity(new_severity)
                is_bump = True

            cur.execute(
                '''UPDATE secrets SET occurrence_count = ?, distinct_target_count = ?,
                       last_seen_at = ?, severity = ? WHERE id = ?''',
                (occ_count, distinct, now, new_severity, secret_id))
        conn.commit()

        if inserted and (is_new or is_bump):
            cur2 = conn.cursor()
            payload = json.dumps({
                'secret_hash': finding.secret_hash,
                'secret_type': finding.secret_type,
                'masked_preview': finding.masked_preview,
                'severity': new_severity if not is_new else severity_for(finding.secret_type),
                'distinct_target_count': distinct if not is_new else 1,
                'is_new': is_new,
                'is_severity_bump': (not is_new) and is_bump,
                'secret_id': secret_id,
            })
            cur2.execute(
                '''INSERT INTO alert_outbox (alert_type, payload, created_at)
                   VALUES (?,?,?)''',
                ('severity_bump' if (not is_new and is_bump) else 'new_secret', payload, now_iso()))
            conn.commit()
            alert = payload
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return alert, secret_id


def upsert_exposure(source, target, file_path, exposure_type,
                    security_txt_url=None, bounty_program_url=None):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute('BEGIN IMMEDIATE')
        cur.execute('SELECT id FROM exposures WHERE source=? AND target=? AND file_path=? AND exposure_type=?',
                    (source, target, file_path, exposure_type))
        if cur.fetchone() is None:
            cur.execute(
                '''INSERT INTO exposures (source, target, file_path, exposure_type,
                        discovered_at, status, security_txt_url, bounty_program_url)
                   VALUES (?,?,?,?,?, 'new', ?,?)''',
                (source, target, file_path, exposure_type, now_iso(),
                 security_txt_url, bounty_program_url))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def heartbeat(component_name, component_state='running', progress_key=None, progress_value=None,
              run_id=None, update_progress=False):
    """
    heartbeat_at every ~60s regardless of work; progress_at only on completed work.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        now = now_iso()
        cur.execute('SELECT component_name FROM state WHERE component_name = ?', (component_name,))
        exists = cur.fetchone() is not None
        if not exists:
            cur.execute(
                '''INSERT INTO state (component_name, progress_key, progress_value, run_id,
                        heartbeat_at, progress_at, component_state, updated_at)
                   VALUES (?,?,?,?,?,?,?,?)''',
                (component_name, progress_key, progress_value, run_id, now,
                 now if update_progress else None, component_state, now))
        else:
            if update_progress:
                cur.execute(
                    '''UPDATE state SET heartbeat_at=?, progress_at=?, component_state=?,
                           progress_key=COALESCE(?,progress_key),
                           progress_value=COALESCE(?,progress_value),
                           run_id=COALESCE(?,run_id), updated_at=? WHERE component_name=?''',
                    (now, now, component_state, progress_key, progress_value, run_id, now, component_name))
            else:
                cur.execute(
                    '''UPDATE state SET heartbeat_at=?, component_state=?, updated_at=?
                       WHERE component_name=?''',
                    (now, component_state, now, component_name))
        conn.commit()
    finally:
        conn.close()


def hour_start(hour_key):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT status FROM gh_archive_hours WHERE hour_key=?", (hour_key,))
        row = cur.fetchone()
        if row is None:
            cur.execute("INSERT INTO gh_archive_hours (hour_key, status, started_at) VALUES (?, 'processing', ?)",
                        (hour_key, now_iso()))
        elif row['status'] in ('pending', 'completed_with_gaps'):
            cur.execute("UPDATE gh_archive_hours SET status='processing', started_at=?, completed_at=NULL WHERE hour_key=?",
                        (now_iso(), hour_key))
        conn.commit()
    finally:
        conn.close()


def hour_finalize(hour_key, gap_reasons=None):
    """An hour is NEVER 'completed' if unresolved retryable gaps remain."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        reasons = [r for r in (gap_reasons or []) if r]
        if reasons:
            cur.execute("UPDATE gh_archive_hours SET status='completed_with_gaps', completed_at=?, gap_reasons=? WHERE hour_key=?",
                        (now_iso(), json.dumps(reasons), hour_key))
        else:
            cur.execute("UPDATE gh_archive_hours SET status='completed', completed_at=?, gap_reasons=NULL WHERE hour_key=?",
                        (now_iso(), hour_key))
        conn.commit()
    finally:
        conn.close()


if __name__ == '__main__':
    init_db()
