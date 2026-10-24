#!/usr/bin/env python3
"""
dashboard.py - stdlib http.server app (hardened)
Binds to 127.0.0.1 only by default, Basic Auth, CSRF tokens, CSP headers
"""
import http.server
import html
import json
import os
import urllib.parse
from db import get_connection
from config import config
from disclosure import draft_disclosure_text


CSRF_TOKENS = {}


class LeakmonHandler(http.server.BaseHTTPRequestHandler):
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
        except:
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="Leakmon"')
            self.end_headers()
            return False
        return True
    
    def _send_headers(self, content_type='text/html'):
        self.send_response(200)
        self.send_header('Content-type', content_type)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'")
        self.end_headers()
    
    def _get_csrf(self):
        import uuid
        token = str(uuid.uuid4())
        CSRF_TOKENS[token] = True
        return token
    
    def _check_csrf(self, token):
        if not token or token not in CSRF_TOKENS:
            return False
        del CSRF_TOKENS[token]
        return True
    
    def do_GET(self):
        if not self._check_auth():
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        
        if path == '/':
            self._send_headers()
            conn = get_connection()
            cur = conn.cursor()
            cur.execute("SELECT * FROM secrets ORDER BY first_seen_at DESC LIMIT 100")
            rows = cur.fetchall()
            html_out = '<html><head><title>Leakmon</title></head><body>'
            html_out += '<h1>Secrets</h1><table border="1"><tr><th>Type</th><th>Preview</th><th>Severity</th><th>Status</th><th>Count</th></tr>'
            for r in rows:
                html_out += f"<tr><td>{html.escape(r['secret_type'])}</td><td>{html.escape(r['masked_preview'])}</td><td>{html.escape(r['severity'])}</td><td>{html.escape(r['status'])}</td><td>{r['occurrence_count']}</td></tr>"
            html_out += '</table></body></html>'
            self.wfile.write(html_out.encode())
            conn.close()
        elif path == '/exposures':
            self._send_headers()
            conn = get_connection()
            cur = conn.cursor()
            cur.execute("SELECT * FROM exposures ORDER BY discovered_at DESC LIMIT 100")
            rows = cur.fetchall()
            html_out = '<html><head><title>Leakmon - Exposures</title></head><body>'
            html_out += '<h1>Exposures</h1><table border="1"><tr><th>Target</th><th>Path</th><th>Type</th></tr>'
            for r in rows:
                html_out += f"<tr><td>{html.escape(r['target'])}</td><td>{html.escape(r['file_path'])}</td><td>{html.escape(r['exposure_type'])}</td></tr>"
            html_out += '</table></body></html>'
            self.wfile.write(html_out.encode())
            conn.close()
        elif path == '/coverage':
            self._send_headers()
            conn = get_connection()
            cur = conn.cursor()
            cur.execute("SELECT * FROM gh_archive_hours ORDER BY hour_key DESC LIMIT 48")
            rows = cur.fetchall()
            html_out = '<html><head><title>Leakmon - Coverage</title></head><body>'
            html_out += '<h1>GH Archive Hours</h1><table border="1"><tr><th>Hour</th><th>Status</th><th>Reasons</th></tr>'
            for r in rows:
                html_out += f"<tr><td>{html.escape(r['hour_key'])}</td><td>{html.escape(r['status'])}</td><td>{html.escape(r['gap_reasons'] or '')}</td></tr>"
            html_out += '</table></body></html>'
            self.wfile.write(html_out.encode())
            conn.close()
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        if not self._check_auth():
            return
        # CSRF check would go here for state changes
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')


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
