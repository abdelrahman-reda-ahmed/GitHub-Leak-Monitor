# Public GitHub Leak Monitor

**AUTHORIZED SECURITY RESEARCH ONLY** - Detection and reporting, never exploitation.

## Setup (do this FIRST)

1. Create `.env` file in `~/leakmon/` with required variables (chmod 600)
2. **Run `python3 setup.py` FIRST** - generates `.secret_hash_key` atomically. This MUST be run before any service starts to avoid key-generation race conditions.
3. Initialize database: `python3 db.py`
4. Enable services or run manually

## Critical Constraints

- **Python 3 Standard Library only** - no pip packages ever
- **Never validate/test/use discovered credentials** - only pattern match and flag as "looks like a live-format"
- **Never store/display secrets in plaintext** - only HMAC-SHA256 hashes for deduplication
- **Never scrape search engine HTML** - only official JSON APIs
- **Never fetch from search results without safe_fetch.py** - SSRF/DNS-rebinding protection
- **Never auto-send reports** - all disclosure drafting is for manual copy/paste
- **Only public data** - GitHub public APIs, official search APIs
- **Minimum GitHub token privilege** - fine-grained PAT scoped to Public Repositories (read-only). Do NOT use classic `public_repo` scope
- **Zero ongoing cost** - use free tiers, track usage
- **Track rate limits** - primary AND secondary/abuse limits, coordinated across processes via SQLite

## Environment Variables

See `config.py` for full list. Required:
- `GITHUB_TOKEN` - fine-grained PAT (Public Repositories, read-only)
- `SEARCH_PROVIDER` - `tavily` (default) or `google_cse`
- `TAVILY_API_KEY` - free, no card required
- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` - for alerts
- `DASHBOARD_USER`, `DASHBOARD_PASS` - for Basic Auth

## GitHub PAT Setup
Create a fine-grained personal access token with:
- Repository access: Public Repositories (read-only)
- Permissions: Contents (Read-only)
Do NOT use classic tokens with `public_repo` scope.

## Tavily API
Get free API key at tavily.com (no credit card required). Default quota 1000 credits/month.
Credits tracked from `usage.credits` in responses. `search_depth` pinned to `basic`, `auto_parameters` disabled.

## Running Historical Scan
```bash
python3 historical_scan.py --repo owner/name --ref branch_or_tag
```
**Note:** This is a ref history scan, not a full-history scan. It only walks commits reachable from the specified ref. It does not enumerate all branches/tags or unreachable commits. Coverage is diff-based, not full filesystem snapshots.

## Running Tests
```bash
python3 -m unittest discover tests/
```

## Systemd Services
```bash
systemctl --user daemon-reload
systemctl --user enable --now leakmon-collector leakmon-dorker leakmon-dashboard
journalctl --user -u leakmon-collector -f
```

## Alert Delivery
Alerts go through the outbox (`alert_outbox` table). The outbox guarantees **at-least-once** delivery, not exactly-once (if Telegram receives the message but HTTP response is lost, retry will resend). Outbox worker retries with backoff, max attempts configurable.

## Ethical Constraints
This tool is for AUTHORIZED SECURITY RESEARCH only. Detection and reporting, never exploitation. Never validate credentials. Never store secrets in plaintext.
