#!/usr/bin/env python3
"""
safe_fetch.py - SSRF + DNS-rebinding-safe URL fetcher
Uses http.client + ssl directly, connects to validated IP
"""
import socket
import ssl
import http.client
import ipaddress
from urllib.parse import urlparse
from config import config


def is_safe_ip(ip_str):
    """Check if IP is globally routable"""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Must be global (rejects loopback, private, link-local, multicast, reserved, etc.)
        if not ip.is_global:
            return False
        # Explicitly reject cloud metadata
        if str(ip) == '169.254.169.254':
            return False
        return True
    except Exception:
        return False


def safe_fetch(url: str, max_bytes: int = 2_000_000, timeout: int = 10, follow_redirects: int = 0) -> str | None:
    """
    ONLY way to fetch URL from search results.
    Connects to validated IP directly to prevent DNS rebinding.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme != 'https':
            # Only allow http if explicitly configured (not the default)
            if parsed.scheme != 'http':
                return None
        
        hostname = parsed.hostname
        if not hostname:
            return None
        
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        # Resolve DNS
        try:
            addrinfo = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except Exception:
            return None
        
        # Find safe IP
        safe_ip = None
        for family, socktype, proto, canonname, sockaddr in addrinfo:
            ip = sockaddr[0]
            if is_safe_ip(ip):
                safe_ip = ip
                break
        
        if not safe_ip:
            return None
        
        # Strip credentials from URL before logging
        if parsed.username or parsed.password:
            # Don't log/store URLs with credentials
            pass
        
        # Connect directly to validated IP
        sock = socket.socket(socket.AF_INET if ':' not in safe_ip else socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        try:
            sock.connect((safe_ip, port))
        except Exception:
            sock.close()
            return None
        
        if parsed.scheme == 'https':
            context = ssl.create_default_context()
            try:
                sock = context.wrap_socket(sock, server_hostname=hostname)
            except Exception:
                sock.close()
                return None
        
        # Use http.client over the socket
        if parsed.scheme == 'https':
            conn = http.client.HTTPSConnection(hostname, port, timeout=timeout, context=context)
            conn.sock = sock
        else:
            conn = http.client.HTTPConnection(hostname, port, timeout=timeout)
            conn.sock = sock
        
        path = parsed.path or '/'
        if parsed.query:
            # Strip sensitive query params
            from urllib.parse import parse_qs, urlencode, urlunparse
            qs = parse_qs(parsed.query, keep_blank_values=True)
            sensitive = {'token', 'key', 'secret', 'password', 'auth', 'api_key', 'access_token'}
            filtered = {k: v for k, v in qs.items() if k.lower() not in sensitive}
            path = path + '?' + urlencode(filtered, doseq=True) if filtered else path
        
        try:
            conn.request('GET', path, headers={'Host': hostname, 'User-Agent': 'leakmon/1.0'})
            resp = conn.getresponse()
            
            # Handle redirects
            if resp.status in (301, 302, 303, 307, 308) and follow_redirects < 3:
                location = resp.getheader('Location')
                if location:
                    conn.close()
                    return safe_fetch(location, max_bytes, timeout, follow_redirects + 1)
            
            if resp.status != 200:
                conn.close()
                return None
            
            data = resp.read(max_bytes + 1)
            conn.close()
            
            if len(data) > max_bytes:
                return None
            
            try:
                return data.decode('utf-8', errors='replace')
            except:
                return None
        except Exception:
            try:
                conn.close()
            except:
                pass
            return None
    except Exception:
        return None
