#!/usr/bin/env python3
"""
dashboard.py - Professional Leakmon Dashboard (stdlib only)
Binds to 127.0.0.1 only, Basic Auth, CSP headers
"""
import http.server
import html
import json
import os
import urllib.parse
from db import get_connection
from config import config

CSRF_TOKENS = {}


class LeakmonHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def _check_auth(self):
        auth = self.headers.get('Authorization')
        if not auth or not auth.startswith('Basic '):
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="Leakmon"')
            self.end_headers()
            return False
        import base64
        try:
            decoded = base64.b64decode(auth.split(' ')[1]).decode()
            user, passwd = decoded.split(':', 1)
            if user != config.DASHBOARD_USER or passwd != config.DASHBOARD_PASS:
                raise Exception
        except Exception:
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="Leakmon"')
            self.end_headers()
            return False
        return True

    def _send_headers(self, content_type='text/html'):
        self.send_response(200)
        self.send_header('Content-type', content_type)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
        self.end_headers()

    def _send_json(self, obj):
        data = json.dumps(obj).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not self._check_auth():
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        q = urllib.parse.parse_qs(parsed.query)

        if path == '/':
            self._send_headers()
            self.wfile.write(self._render_home().encode('utf-8'))
            return

        if path == '/api/stats':
            conn = get_connection()
            conn.row_factory = __import__('sqlite3').Row
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) as c FROM secrets")
            total_secrets = cur.fetchone()['c']
            cur.execute("SELECT COUNT(*) as c FROM secrets WHERE status='new'")
            new_secrets = cur.fetchone()['c']
            cur.execute("SELECT COUNT(*) as c FROM occurrences")
            total_occ = cur.fetchone()['c']
            cur.execute("SELECT COUNT(*) as c FROM alert_outbox WHERE sent_at IS NULL")
            pending_alerts = cur.fetchone()['c']
            cur.execute("SELECT COUNT(*) as c FROM gh_archive_hours WHERE status IN ('pending','processing')")
            pending_hours = cur.fetchone()['c']
            conn.close()
            self._send_json({
                "total_secrets": total_secrets,
                "new_secrets": new_secrets,
                "total_occurrences": total_occ,
                "pending_alerts": pending_alerts,
                "pending_gh_hours": pending_hours
            })
            return

        if path == '/api/secrets':
            conn = get_connection()
            conn.row_factory = __import__('sqlite3').Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM secrets ORDER BY severity DESC, first_seen_at DESC LIMIT 500")
            rows = cur.fetchall()
            out = [dict(x) for x in rows]
            conn.close()
            self._send_json(out)
            return

        if path == '/api/secret':
            sid = q.get('id', [''])[0]
            conn = get_connection()
            conn.row_factory = __import__('sqlite3').Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM secrets WHERE id=?", (sid,))
            sec = cur.fetchone()
            if not sec:
                conn.close()
                self.send_response(404)
                self.end_headers()
                return
            cur.execute("SELECT * FROM occurrences WHERE secret_id=? ORDER BY discovered_at DESC", (sid,))
            occ = [dict(x) for x in cur.fetchall()]
            conn.close()
            self._send_json({"secret": dict(sec), "occurrences": occ})
            return

        if path == '/secret':
            self._send_headers()
            self.wfile.write(self._render_detail().encode('utf-8'))
            return

        if path == '/coverage':
            self._send_headers()
            conn = get_connection()
            conn.row_factory = __import__('sqlite3').Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM gh_archive_hours ORDER BY hour_key DESC LIMIT 72")
            rows = cur.fetchall()
            html_out = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Leakmon • Coverage</title>
            <link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
            <style>:root{--bg:#0b1026;--panel:#10162b;--text:#e6e8ee;--sub:#9aa0c3;--border:#242a45;--ok:#22c55e;--warn:#f59e0b;--accent:#7aa2ff}*{box-sizing:border-box;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}body{margin:0;background:radial-gradient(1200px 800px at 80% -10%,#1a2247 0%,transparent 60%),var(--bg);color:var(--text);line-height:1.6}header{display:flex;align-items:center;justify-content:space-between;padding:18px 28px;border-bottom:1px solid var(--border);background:linear-gradient(180deg,rgba(122,162,255,.12),transparent)}nav a{color:var(--sub);text-decoration:none;margin-left:16px}nav a.active,nav a:hover{color:var(--text)}main{max-width:1100px;margin:0 auto;padding:26px 28px}h1{margin:0 0 10px;font-size:22px}.card{background:linear-gradient(180deg,rgba(255,255,255,.02),transparent);border:1px solid var(--border);border-radius:14px;overflow:hidden}table{width:100%;border-collapse:collapse}th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.12em;color:var(--sub);padding:14px 18px;border-bottom:1px solid var(--border)}td{padding:14px 18px;border-bottom:1px solid rgba(36,42,69,.8);font-size:14px}.pill{display:inline-flex;align-items:center;gap:6px;padding:6px 10px;border-radius:999px;border:1px solid var(--border);font-size:12px;color:var(--sub)}.pill.ok{color:var(--ok)}.pill.warn{color:var(--warn)}</style></head><body>
            <header><div><strong>Leakmon</strong> <span style="color:var(--sub)">• Coverage</span></div><nav><a href="/">Secrets</a><a class="active" href="/coverage">GH Archive</a></nav></header>
            <main><h1>GH Archive Hours</h1><p style="color:var(--sub);margin-top:-6px">Recent hours processed by the collector</p>
            <div class="card"><table><thead><tr><th>Hour Key</th><th>Status</th><th>Gap Reasons</th></tr></thead><tbody>'''
            for r in rows:
                status = html.escape(r['status'] or '')
                pill = 'ok' if status == 'completed' else ('warn' if 'gap' in status else '')
                html_out += f'<tr><td>{html.escape(r["hour_key"])}</td><td><span class="pill {pill}">{status}</span></td><td style="color:var(--sub)">{html.escape(r["gap_reasons"] or "-")}</td></tr>'
            html_out += '</tbody></table></div></main></body></html>'
            self.wfile.write(html_out.encode('utf-8'))
            conn.close()
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if not self._check_auth():
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

    def _render_home(self):
        return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Leakmon • Secrets</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>:root{--bg:#0b1026;--panel:#10162b;--text:#e6e8ee;--sub:#9aa0c3;--border:#242a45;--high:#f87171;--med:#f59e0b;--low:#22d3ee;--accent:#7aa2ff}*{box-sizing:border-box;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}body{margin:0;background:radial-gradient(1400px 900px at 70% -10%,#1f2a5a 0%,transparent 60%),var(--bg);color:var(--text);line-height:1.6}header{display:flex;align-items:center;justify-content:space-between;padding:18px 28px;border-bottom:1px solid var(--border);backdrop-filter:blur(12px)}nav a{color:var(--sub);text-decoration:none;margin-left:16px}nav a.active,nav a:hover{color:var(--text)}main{max-width:1200px;margin:0 auto;padding:28px}h1{margin:0;font-size:26px}.sub{color:var(--sub);margin-top:4px}.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:16px;margin:26px 0}.card-stat{position:relative;overflow:hidden;border:1px solid var(--border);border-radius:14px;padding:18px;background:radial-gradient(400px 160px at 50% -40%,rgba(122,162,255,.18),transparent),linear-gradient(180deg,rgba(255,255,255,.01),transparent)}.card-stat .label{color:var(--sub);font-size:13px}.card-stat .value{font-size:34px;font-weight:600;margin-top:6px}.table-wrap{border:1px solid var(--border);border-radius:16px;overflow:hidden;background:linear-gradient(180deg,rgba(255,255,255,.01),transparent);box-shadow:0 60px 80px -70px rgba(122,162,255,.8)}.toolbar{display:flex;align-items:center;justify-content:space-between;padding:18px 22px;border-bottom:1px solid var(--border)}.filters{display:flex;gap:10px;flex-wrap:wrap}.chip{border:1px solid var(--border);border-radius:999px;padding:8px 14px;font-size:13px;color:var(--sub);background:transparent;cursor:pointer}.chip.active{color:var(--text);border-color:rgba(122,162,255,.9)}table{width:100%;border-collapse:collapse}th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.12em;color:var(--sub);padding:14px 22px;border-bottom:1px solid var(--border)}td{padding:16px 22px;border-bottom:1px solid rgba(36,42,69,.9);vertical-align:top}tr:hover td{background:radial-gradient(600px 120px at 0% 0%,rgba(122,162,255,.08),transparent)}.type{font-weight:500}.preview{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--sub)}.sev{display:inline-flex;padding:6px 10px;border-radius:999px;border:1px solid var(--border);font-size:12px}.sev.high{color:var(--high);border-color:rgba(248,113,113,.6)}.sev.medium{color:var(--med);border-color:rgba(245,158,11,.6)}.sev.low{color:var(--low);border-color:rgba(34,211,238,.5)}.link{color:var(--accent);text-decoration:none}</style>
</head><body>
<header><div><strong>Leakmon</strong> <span class="sub">• Public GitHub Leak Monitor</span></div><nav><a class="active" href="/">Secrets</a><a href="/coverage">GH Archive</a></nav></header>
<main>
  <div><h1>Detected Secrets</h1><div class="sub">Pattern matches from public sources • Masked for safety</div></div>
  <div class="grid">
    <div class="card-stat"><div class="label">Total Secrets</div><div class="value" id="s-total">-</div></div>
    <div class="card-stat"><div class="label">New</div><div class="value" id="s-new">-</div></div>
    <div class="card-stat"><div class="label">Occurrences</div><div class="value" id="s-occ">-</div></div>
    <div class="card-stat"><div class="label">Pending Alerts</div><div class="value" id="s-alerts">-</div></div>
    <div class="card-stat"><div class="label">GH Hours Pending</div><div class="value" id="s-hours">-</div></div>
  </div>
  <div class="table-wrap">
    <div class="toolbar"><div><strong>Findings</strong><div class="sub">Click a row to see sources &amp; public links</div></div></div>
    <div style="overflow-x:auto"><table id="secrets-table"><thead><tr><th>Type</th><th>Preview</th><th>Severity</th><th>Status</th><th>Occurrences</th><th>Distinct Targets</th><th>First Seen</th><th>Last Seen</th></tr></thead><tbody></tbody></table></div>
  </div>
</main>
<script>
async function load(){
  const [s,r]=await Promise.all([fetch('/api/stats'),fetch('/api/secrets')]);
  const st=await s.json(), rows=await r.json();
  document.getElementById('s-total').textContent=st.total_secrets;
  document.getElementById('s-new').textContent=st.new_secrets;
  document.getElementById('s-occ').textContent=st.total_occurrences;
  document.getElementById('s-alerts').textContent=st.pending_alerts;
  document.getElementById('s-hours').textContent=st.pending_gh_hours;
  const tb=document.querySelector('#secrets-table tbody'); tb.innerHTML='';
  for(const x of rows){
    const tr=document.createElement('tr'); tr.style.cursor='pointer';
    tr.onclick=()=>{location.href='/secret?id='+x.id;};
    tr.innerHTML=`<td class="type">${escapeHtml(x.secret_type)}</td><td class="preview">${escapeHtml(x.masked_preview)}</td><td><span class="sev ${x.severity}">${x.severity}</span></td><td>${escapeHtml(x.status)}</td><td>${x.occurrence_count}</td><td>${x.distinct_target_count}</td><td class="sub">${x.first_seen_at.replace('T',' ').replace('Z',' UTC')}</td><td class="sub">${x.last_seen_at.replace('T',' ').replace('Z',' UTC')}</td>`;
    tb.appendChild(tr);
  }
}
function escapeHtml(t){return String(t).replace(/[&<>"']/g,m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]));}
load();
</script>
</body></html>'''

    def _render_detail(self):
        return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Leakmon • Finding</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>:root{--bg:#0b1026;--text:#e6e8ee;--sub:#9aa0c3;--border:#242a45;--accent:#7aa2ff}*{box-sizing:border-box;font-family:Inter,system-ui,sans-serif}body{margin:0;background:radial-gradient(1200px 800px at 80% -10%,#1a2247 0%,transparent 60%),var(--bg);color:var(--text)}header{display:flex;align-items:center;justify-content:space-between;padding:18px 28px;border-bottom:1px solid var(--border)}nav a{color:var(--sub);text-decoration:none}main{max-width:1100px;margin:0 auto;padding:26px 28px}.grid{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin:18px 0}.pill{border:1px solid var(--border);border-radius:12px;padding:14px}.pill .label{color:var(--sub);font-size:12px;text-transform:uppercase;letter-spacing:.12em}.pill .val{margin-top:6px;font-size:18px}.card{border:1px solid var(--border);border-radius:16px;overflow:hidden}table{width:100%;border-collapse:collapse}th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.12em;color:var(--sub);padding:14px 20px;border-bottom:1px solid var(--border)}td{padding:16px 20px;border-bottom:1px solid rgba(36,42,69,.9)}a{color:var(--accent);text-decoration:none}.mono{font-family:ui-monospace,monospace;color:var(--sub)}</style>
</head><body>
<header><div><strong>Leakmon</strong></div><nav><a href="/">← Back to secrets</a></nav></header>
<main>
  <a href="/" style="color:var(--sub);text-decoration:none">← All findings</a>
  <h1 id="title" style="margin:10px 0 0">Finding</h1>
  <div class="sub" id="sub"></div>
  <div class="grid" id="grid"></div>
  <h2 style="margin-top:26px">Occurrences</h2>
  <div class="sub">Public locations where this pattern was matched</div>
  <div class="card" style="margin-top:16px"><table><thead><tr><th>Source</th><th>Target / Public URL</th><th>Discovered</th><th>Exposure</th></tr></thead><tbody id="occ"></tbody></table></div>
</main>
<script>
const id=new URLSearchParams(location.search).get('id');
async function load(){
  const r=await fetch('/api/secret?id='+id); const j=await r.json(); const s=j.secret,o=j.occurrences;
  document.getElementById('title').textContent=s.secret_type+' • '+s.masked_preview;
  document.getElementById('sub').textContent='Severity: '+s.severity+' • Status: '+s.status;
  const g=document.getElementById('grid');
  g.innerHTML=`<div class="pill"><div class="label">Occurrences</div><div class="val">${s.occurrence_count}</div></div><div class="pill"><div class="label">Distinct Targets</div><div class="val">${s.distinct_target_count}</div></div><div class="pill"><div class="label">First Seen</div><div class="val mono">${s.first_seen_at.replace('T',' ').replace('Z','')}</div></div><div class="pill"><div class="label">Last Seen</div><div class="val mono">${s.last_seen_at.replace('T',' ').replace('Z','')}</div></div><div class="pill"><div class="label">Secret Hash</div><div class="val mono" style="font-size:12px">${s.secret_hash.slice(0,16)}…</div></div><div class="pill"><div class="label">Status</div><div class="val">${s.status}</div></div>`;
  const tb=document.getElementById('occ'); tb.innerHTML='';
  for(const x of o){
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${x.source}</td><td><a href="${x.target}" target="_blank" rel="noopener">${x.target}</a></td><td class="mono">${x.discovered_at.replace('T',' ').replace('Z','')}</td><td>${x.exposure_state}</td>`;
    tb.appendChild(tr);
  }
}
load();
</script>
</body></html>'''

def main():
    if not config.DASHBOARD_ALLOW_EXTERNAL:
        host = '127.0.0.1'
    else:
        raise RuntimeError('DASHBOARD_ALLOW_EXTERNAL requires explicit opt-in and HTTPS - not enabled')
    server = http.server.HTTPServer((host, config.DASHBOARD_PORT), LeakmonHandler)
    print(f'Dashboard running on http://{host}:{config.DASHBOARD_PORT}')
    server.serve_forever()


if __name__ == '__main__':
    main()
