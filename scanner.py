#!/usr/bin/env python3
"""
scanner.py - detection engine (regex + entropy + encoding + diff-aware)
"""
import re
import math
import base64
import binascii
import hashlib
import hmac
from dataclasses import dataclass
from typing import List, Tuple, Optional

# Will import config at runtime
try:
    from config import config
    ENTROPY_THRESHOLD = config.ENTROPY_THRESHOLD
    MAX_INPUT_BYTES = config.ENCODING_MAX_INPUT_BYTES
    MAX_DECODED_BYTES = config.ENCODING_MAX_DECODED_BYTES
    MAX_TOTAL_DECODED_BYTES = config.ENCODING_MAX_TOTAL_DECODED_BYTES
    SECRET_HASH_KEY = config.SECRET_HASH_KEY
except Exception:
    ENTROPY_THRESHOLD = 4.0
    MAX_INPUT_BYTES = 5_000_000
    MAX_DECODED_BYTES = 1_000_000
    MAX_TOTAL_DECODED_BYTES = 5_000_000
    SECRET_HASH_KEY = None


@dataclass
class SecretFinding:
    secret_type: str
    masked_preview: str
    secret_hash: str  # HMAC hash, raw value never attached
    encoding: Optional[str]
    diff_status: Optional[str]
    exposure_state: Optional[str]
    target: str
    file_path: str
    commit_sha_or_url: Optional[str]
    context_snippet: Optional[str]


@dataclass
class ExposureFinding:
    source: str
    target: str
    file_path: str
    exposure_type: str


# Direct regex patterns
PATTERNS = {
    'aws_access_key': re.compile(r'(AKIA[0-9A-Z]{16})'),
    'github_pat': re.compile(r'(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})'),
    'slack_token': re.compile(r'(xox[baprs]-[A-Za-z0-9-]+)'),
    'stripe_live': re.compile(r'(sk_live_[A-Za-z0-9]{24,})'),
    'google_api_key': re.compile(r'(AIza[0-9A-Za-z_-]{35})'),
    'jwt': re.compile(r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'),
    'postgres': re.compile(r'(postgres://[^:\s]+:[^@\s]+@[^\s]+)'),
    'mysql': re.compile(r'(mysql://[^:\s]+:[^@\s]+@[^\s]+)'),
    'mongodb': re.compile(r'(mongodb://[^:\s]+:[^@\s]+@[^\s]+)'),
}

PEM_HEADER = re.compile(r'-----BEGIN [A-Z]+ PRIVATE KEY-----')
PEM_FOOTER = re.compile(r'-----END [A-Z]+ PRIVATE KEY-----')


def compute_secret_hash(raw_value: str) -> str:
    """Compute HMAC-SHA256 hash. Raw value never stored."""
    if SECRET_HASH_KEY is None:
        raise RuntimeError('SECRET_HASH_KEY not loaded')
    return hmac.new(SECRET_HASH_KEY, raw_value.encode(), hashlib.sha256).hexdigest()


def mask_secret(value: str, secret_type: str = None) -> str:
    """
    Length-aware masking. For values <= 8 chars, never show first+last 4.
    Show only first 2 chars max, never reveal > 50% of total.
    """
    if not value:
        return '***'
    
    # Type-specific prefixes that are identifying
    if secret_type == 'aws_access_key' and value.startswith('AKIA'):
        return 'AKIA' + '*' * max(4, len(value) - 4)
    if secret_type == 'github_pat' and (value.startswith('ghp_') or value.startswith('github_pat_')):
        prefix = 'ghp_' if value.startswith('ghp_') else 'github_pat_'
        return prefix + '*' * max(4, len(value) - len(prefix))
    if secret_type == 'slack_token' and value.startswith('xox'):
        # Show prefix up to second dash
        parts = value.split('-')
        if len(parts) >= 2:
            prefix = '-'.join(parts[:2]) + '-'
            return prefix + '*' * max(4, len(value) - len(prefix))
    if secret_type == 'stripe_live' and value.startswith('sk_live_'):
        return 'sk_live_' + '*' * max(4, len(value) - 9)
    if secret_type == 'google_api_key' and value.startswith('AIza'):
        return 'AIza' + '*' * max(4, len(value) - 4)
    
    # General rules
    if len(value) <= 8:
        # Never reveal > 50%
        shown = len(value) // 2
        return value[:shown] + '*' * (len(value) - shown)
    else:
        # Show first 4 + last 4
        if len(value) <= 12:
            shown = min(2, len(value) // 2)
            return value[:shown] + '*' * (len(value) - shown * 2) + value[-shown:]
        return value[:4] + '*' * (len(value) - 8) + value[-4:]


def mask_connection_string(conn_str: str) -> str:
    """Mask each sensitive component separately - never expose full string"""
    try:
        # Simple parsing
        if '://' in conn_str:
            scheme_part, rest = conn_str.split('://', 1)
            if '@' in rest:
                user_pass, host_db = rest.split('@', 1)
                if ':' in user_pass:
                    user, passwd = user_pass.split(':', 1)
                    masked_user = mask_secret(user)
                    masked_pass = mask_secret(passwd)
                    return f"{scheme_part}://{masked_user}:{masked_pass}@{host_db}"
    except Exception:
        pass
    # Fallback - mask heavily
    return conn_str[:10] + '***MASKED***' + conn_str[-5:] if len(conn_str) > 15 else '***MASKED***'


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = data.count(chr(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy


def find_encoded_candidates(content: str) -> List[Tuple[str, str]]:
    """Detect encoded candidates with resource bounds"""
    candidates = []
    seen = set()
    
    # Base64/Base64url (20+ chars)
    for m in re.finditer(r'[A-Za-z0-9+/]{20,}={0,2}|[A-Za-z0-9_-]{20,}', content):
        s = m.group()
        if len(s) < 20 or len(set(s)) < 3:  # skip repeated
            continue
        h = hashlib.sha256(s.encode()).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        # Try to identify type
        if '-' in s or '_' in s:
            candidates.append((s, 'base64url'))
        else:
            candidates.append((s, 'base64'))
    
    # Hex (32+ chars)
    for m in re.finditer(r'\b[0-9a-fA-F]{32,}\b', content):
        s = m.group()
        if len(s) < 32 or len(set(s)) < 3:
            continue
        h = hashlib.sha256(s.encode()).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        candidates.append((s, 'hex'))
    
    # URL encoding
    for m in re.finditer(r'(%[0-9A-Fa-f]{2}){3,}', content):
        s = m.group()
        h = hashlib.sha256(s.encode()).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        candidates.append((s, 'url'))
    
    # Base32 (16+ chars)
    for m in re.finditer(r'\b[A-Z2-7]{16,}={0,6}\b', content):
        s = m.group()
        if len(s) < 16:
            continue
        h = hashlib.sha256(s.encode()).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        candidates.append((s, 'base32'))
    
    return candidates


def decode_candidate(s: str, enc_type: str) -> Optional[str]:
    """Decode candidate using only stdlib"""
    try:
        if enc_type == 'base64':
            # Add padding if needed
            padding = 4 - len(s) % 4
            if padding != 4:
                s_padded = s + '=' * padding
            else:
                s_padded = s
            decoded = base64.b64decode(s_padded)
        elif enc_type == 'base64url':
            decoded = base64.urlsafe_b64decode(s + '===')
        elif enc_type == 'hex':
            decoded = binascii.unhexlify(s)
        elif enc_type == 'url':
            from urllib.parse import unquote
            decoded = unquote(s).encode('latin-1')
        elif enc_type == 'base32':
            decoded = base64.b32decode(s)
        else:
            return None
        
        # Check size
        if len(decoded) > MAX_DECODED_BYTES:
            return None
        
        # Try to decode as text
        try:
            text = decoded.decode('utf-8')
        except:
            try:
                text = decoded.decode('latin-1')
            except:
                return None
        
        # Reject non-printable
        if any(ord(c) < 32 and c not in '\n\r\t' for c in text):
            return None
        
        return text
    except Exception:
        return None


def parse_diff(content: str) -> List[Tuple[str, str, str]]:
    """Parse diff, return (line_content, diff_status, line_number)"""
    results = []
    for line in content.split('\n'):
        if line.startswith('+') and not line.startswith('+++'):
            results.append((line[1:], 'added', line))
        elif line.startswith('-') and not line.startswith('---'):
            results.append((line[1:], 'removed', line))
        elif line.startswith(' '):
            results.append((line[1:], 'context', line))
    return results


def scan_content(content: str, filename: str = '', is_diff: bool = False) -> Tuple[List[SecretFinding], List[ExposureFinding]]:
    """Main scanning function"""
    secret_findings = []
    exposure_findings = []
    
    # Enforce input size cap
    if len(content.encode('utf-8', errors='ignore')) > MAX_INPUT_BYTES:
        content = content[:MAX_INPUT_BYTES]
    
    # Filename-based exposures
    exposure_patterns = [
        (r'\.env(\.|$)', '.env'),
        (r'id_rsa$', 'private_key_file'),
        (r'\.pem$', 'pem_file'),
        (r'\.git/config$', 'git_config'),
        (r'\.bak$', 'backup_file'),
        (r'wp-config\.php\.bak$', 'wp_config_backup'),
        (r'docker-compose\.yml$', 'docker_compose'),
        (r'credentials\.json$', 'credentials_file'),
    ]
    
    for pat, exp_type in exposure_patterns:
        if re.search(pat, filename):
            exposure_findings.append(ExposureFinding(
                source='filename',
                target='',
                file_path=filename,
                exposure_type=exp_type
            ))
    
    # Prepare content for scanning
    scan_items = []
    if is_diff:
        diff_items = parse_diff(content)
        for line_content, diff_status, raw_line in diff_items:
            scan_items.append((line_content, diff_status))
    else:
        scan_items.append((content, None))
    
    # Track seen secrets in this scan to avoid duplicates
    seen_hashes = set()
    total_decoded = 0
    
    for scan_text, diff_status in scan_items:
        # Direct pattern matching
        for stype, pattern in PATTERNS.items():
            for match in pattern.finditer(scan_text):
                raw_value = match.group(1)
                secret_hash = compute_secret_hash(raw_value)
                if secret_hash in seen_hashes:
                    continue
                seen_hashes.add(secret_hash)
                
                if stype in ['postgres', 'mysql', 'mongodb']:
                    masked = mask_connection_string(raw_value)
                else:
                    masked = mask_secret(raw_value, stype)
                
                # Get context snippet (masked)
                start = max(0, match.start() - 20)
                end = min(len(scan_text), match.end() + 20)
                snippet = scan_text[start:end]
                # Mask the secret in snippet
                snippet_masked = snippet.replace(raw_value, masked)
                
                secret_findings.append(SecretFinding(
                    secret_type=stype,
                    masked_preview=masked,
                    secret_hash=secret_hash,
                    encoding=None,
                    diff_status=diff_status,
                    exposure_state='live' if diff_status == 'added' else 'unknown',
                    target='',
                    file_path=filename,
                    commit_sha_or_url=None,
                    context_snippet=snippet_masked
                ))
        
        # PEM detection
        if PEM_HEADER.search(scan_text) and PEM_FOOTER.search(scan_text):
            # Try to extract block
            pem_match = re.search(r'(-----BEGIN [A-Z]+ PRIVATE KEY-----.*?-----END [A-Z]+ PRIVATE KEY-----)', scan_text, re.DOTALL)
            if pem_match:
                pem_block = pem_match.group(1)
                secret_hash = compute_secret_hash(pem_block)
                if secret_hash not in seen_hashes:
                    seen_hashes.add(secret_hash)
                    secret_findings.append(SecretFinding(
                        secret_type='private_key',
                        masked_preview='-----BEGIN PRIVATE KEY-----***MASKED***',
                        secret_hash=secret_hash,
                        encoding=None,
                        diff_status=diff_status,
                        exposure_state='live' if diff_status == 'added' else 'unknown',
                        target='',
                        file_path=filename,
                        commit_sha_or_url=None,
                        context_snippet='***MASKED PEM BLOCK***'
                    ))
        
        # Entropy check
        for m in re.finditer(r'(password|secret|token|api_key)\s*[:=]\s*[\'"]?([^\s\'"]{13,})[\'"]?', scan_text, re.I):
            val = m.group(2)
            if shannon_entropy(val) > ENTROPY_THRESHOLD:
                secret_hash = compute_secret_hash(val)
                if secret_hash not in seen_hashes:
                    seen_hashes.add(secret_hash)
                    masked = mask_secret(val)
                    start = max(0, m.start() - 10)
                    end = min(len(scan_text), m.end() + 10)
                    snippet = scan_text[start:end].replace(val, masked)
                    secret_findings.append(SecretFinding(
                        secret_type='high_entropy',
                        masked_preview=masked,
                        secret_hash=secret_hash,
                        encoding=None,
                        diff_status=diff_status,
                        exposure_state='live' if diff_status == 'added' else 'unknown',
                        target='',
                        file_path=filename,
                        commit_sha_or_url=None,
                        context_snippet=snippet
                    ))
        
        # Encoding detection
        candidates = find_encoded_candidates(scan_text)
        for cand_str, enc_type in candidates:
            if total_decoded > MAX_TOTAL_DECODED_BYTES:
                break
            decoded = decode_candidate(cand_str, enc_type)
            if not decoded:
                continue
            total_decoded += len(decoded.encode('utf-8'))
            if total_decoded > MAX_TOTAL_DECODED_BYTES:
                break
            # Re-run direct rules on decoded
            for stype, pattern in PATTERNS.items():
                for match in pattern.finditer(decoded):
                    raw_value = match.group(1)
                    secret_hash = compute_secret_hash(raw_value)
                    if secret_hash in seen_hashes:
                        continue
                    seen_hashes.add(secret_hash)
                    if stype in ['postgres', 'mysql', 'mongodb']:
                        masked = mask_connection_string(raw_value)
                    else:
                        masked = mask_secret(raw_value, stype)
                    secret_findings.append(SecretFinding(
                        secret_type=stype,
                        masked_preview=masked,
                        secret_hash=secret_hash,
                        encoding=enc_type,
                        diff_status=diff_status,
                        exposure_state='live' if diff_status == 'added' else 'unknown',
                        target='',
                        file_path=filename,
                        commit_sha_or_url=None,
                        context_snippet='***DECODED_AND_MASKED***'
                    ))
    
    return secret_findings, exposure_findings
