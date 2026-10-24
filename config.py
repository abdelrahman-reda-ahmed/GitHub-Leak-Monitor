#!/usr/bin/env python3
"""
config.py - loads all settings from env vars.
Defines the full env var interface early as required.
SECRET_HASH_KEY is loaded by reading ~/leakmon/.secret_hash_key directly (never regenerated).
"""
import os
import sys

LEAKMON_DIR = os.path.dirname(os.path.abspath(__file__))
SECRET_KEY_PATH = os.path.join(LEAKMON_DIR, '.secret_hash_key')

# Defaults
DEFAULTS = {
    'GH_RATE_LIMIT_FLOOR': '100',
    'SEARCH_PROVIDER': 'tavily',
    'DASHBOARD_PORT': '8787',
    'DASHBOARD_ALLOW_EXTERNAL': 'false',
    'GH_POLL_INTERVAL_SECONDS': '300',
    'DORK_INTERVAL_SECONDS': '900',
    'ENTROPY_THRESHOLD': '4.0',
    'SEARCH_MONTHLY_QUOTA': '1000',
    'SEARCH_DAILY_QUOTA': '100',
    'ENCODING_MAX_INPUT_BYTES': '5000000',
    'ENCODING_MAX_DECODED_BYTES': '1000000',
    'ENCODING_MAX_TOTAL_DECODED_BYTES': '5000000',
    'ALERT_OUTBOX_MAX_ATTEMPTS': '10',
}


def _get_env(name, default=None, required=False):
    val = os.environ.get(name)
    if val is None or val == '':
        if required:
            raise RuntimeError(f'Missing required environment variable: {name}')
        if default is not None:
            return default
        return None
    return val


def load_secret_hash_key():
    """Load secret hash key from file. Must exist - never generate."""
    if not os.path.exists(SECRET_KEY_PATH):
        print('FATAL: Run setup.py first — .secret_hash_key is missing', file=sys.stderr)
        sys.exit(1)
    try:
        with open(SECRET_KEY_PATH, 'rb') as f:
            key = f.read()
        if len(key) == 0:
            print('FATAL: .secret_hash_key is empty', file=sys.stderr)
            sys.exit(1)
        return key
    except Exception as e:
        print(f'FATAL: Failed to read .secret_hash_key: {e}', file=sys.stderr)
        sys.exit(1)


class Config:
    def __init__(self):
        # GitHub
        self.GITHUB_TOKEN = _get_env('GITHUB_TOKEN')
        
        # Rate limiting
        self.GH_RATE_LIMIT_FLOOR = int(_get_env('GH_RATE_LIMIT_FLOOR', DEFAULTS['GH_RATE_LIMIT_FLOOR']))
        
        # Search
        self.SEARCH_PROVIDER = _get_env('SEARCH_PROVIDER', DEFAULTS['SEARCH_PROVIDER'])
        self.TAVILY_API_KEY = _get_env('TAVILY_API_KEY')
        self.GOOGLE_API_KEY = _get_env('GOOGLE_API_KEY')
        self.GOOGLE_CX = _get_env('GOOGLE_CX')
        self.SEARCH_MONTHLY_QUOTA = int(_get_env('SEARCH_MONTHLY_QUOTA', DEFAULTS['SEARCH_MONTHLY_QUOTA']))
        self.SEARCH_DAILY_QUOTA = int(_get_env('SEARCH_DAILY_QUOTA', DEFAULTS['SEARCH_DAILY_QUOTA']))
        
        # Telegram
        self.TELEGRAM_BOT_TOKEN = _get_env('TELEGRAM_BOT_TOKEN')
        self.TELEGRAM_CHAT_ID = _get_env('TELEGRAM_CHAT_ID')
        
        # Dashboard
        self.DASHBOARD_USER = _get_env('DASHBOARD_USER')
        self.DASHBOARD_PASS = _get_env('DASHBOARD_PASS')
        self.DASHBOARD_PORT = int(_get_env('DASHBOARD_PORT', DEFAULTS['DASHBOARD_PORT']))
        self.DASHBOARD_ALLOW_EXTERNAL = _get_env('DASHBOARD_ALLOW_EXTERNAL', DEFAULTS['DASHBOARD_ALLOW_EXTERNAL']).lower() == 'true'
        
        # Intervals
        self.GH_POLL_INTERVAL_SECONDS = int(_get_env('GH_POLL_INTERVAL_SECONDS', DEFAULTS['GH_POLL_INTERVAL_SECONDS']))
        self.DORK_INTERVAL_SECONDS = int(_get_env('DORK_INTERVAL_SECONDS', DEFAULTS['DORK_INTERVAL_SECONDS']))
        
        # Scanner
        self.ENTROPY_THRESHOLD = float(_get_env('ENTROPY_THRESHOLD', DEFAULTS['ENTROPY_THRESHOLD']))
        
        # Encoding limits
        self.ENCODING_MAX_INPUT_BYTES = int(_get_env('ENCODING_MAX_INPUT_BYTES', DEFAULTS['ENCODING_MAX_INPUT_BYTES']))
        self.ENCODING_MAX_DECODED_BYTES = int(_get_env('ENCODING_MAX_DECODED_BYTES', DEFAULTS['ENCODING_MAX_DECODED_BYTES']))
        self.ENCODING_MAX_TOTAL_DECODED_BYTES = int(_get_env('ENCODING_MAX_TOTAL_DECODED_BYTES', DEFAULTS['ENCODING_MAX_TOTAL_DECODED_BYTES']))
        
        # Alerts
        self.ALERT_OUTBOX_MAX_ATTEMPTS = int(_get_env('ALERT_OUTBOX_MAX_ATTEMPTS', DEFAULTS['ALERT_OUTBOX_MAX_ATTEMPTS']))
        
        # Scope allowlist
        self.SCOPE_ALLOWLIST_ORGS = [x.strip() for x in (_get_env('SCOPE_ALLOWLIST_ORGS') or '').split(',') if x.strip()]
        self.SCOPE_ALLOWLIST_KEYWORDS = [x.strip() for x in (_get_env('SCOPE_ALLOWLIST_KEYWORDS') or '').split(',') if x.strip()]
        
        # Secret hash key
        self.SECRET_HASH_KEY = load_secret_hash_key()
        
        # Validate provider requirements
        if self.SEARCH_PROVIDER == 'tavily' and not self.TAVILY_API_KEY:
            raise RuntimeError('TAVILY_API_KEY required when SEARCH_PROVIDER=tavily')
        if self.SEARCH_PROVIDER == 'google_cse':
            print('WARNING: Google CSE is legacy bridge, closed to new signups, discontinued 2027-01-01', file=sys.stderr)
            if not (self.GOOGLE_API_KEY and self.GOOGLE_CX):
                raise RuntimeError('GOOGLE_API_KEY and GOOGLE_CX required when SEARCH_PROVIDER=google_cse')


# Global config instance
try:
    config = Config()
except SystemExit:
    raise
except Exception as e:
    print(f'FATAL: Configuration error: {e}', file=sys.stderr)
    sys.exit(1)
