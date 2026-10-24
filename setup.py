#!/usr/bin/env python3
"""
setup.py - one-time atomic key generation (run BEFORE any service starts)
"""
import os
import sys

LEAKMON_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_PATH = os.path.join(LEAKMON_DIR, '.secret_hash_key')


def main():
    if os.path.exists(KEY_PATH):
        print('.secret_hash_key already exists (safe to re-run)')
        return
    
    # Ensure directory exists
    os.makedirs(LEAKMON_DIR, mode=0o700, exist_ok=True)
    
    # Generate 32 random bytes
    key = os.urandom(32)
    
    # Atomic write: temp file in same dir, chmod 600, rename
    import tempfile
    fd, tmp_path = tempfile.mkstemp(prefix='.secret_hash_key.tmp.', dir=LEAKMON_DIR)
    try:
        os.write(fd, key)
        os.close(fd)
        fd = None
        os.chmod(tmp_path, 0o600)
        os.rename(tmp_path, KEY_PATH)
        tmp_path = None
        print('Generated .secret_hash_key with secure permissions')
    finally:
        if fd is not None:
            os.close(fd)
        if tmp_path is not None and os.path.exists(tmp_path):
            os.unlink(tmp_path)


if __name__ == '__main__':
    main()
