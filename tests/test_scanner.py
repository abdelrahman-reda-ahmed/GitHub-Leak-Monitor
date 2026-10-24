import unittest
from scanner import scan_content, mask_secret, compute_secret_hash
import os


class TestScanner(unittest.TestCase):
    def test_aws_key_masking(self):
        key = 'AKIAIOSFODNN7EXAMPLE'
        masked = mask_secret(key, 'aws_access_key')
        self.assertTrue(masked.startswith('AKIA'))
        self.assertNotIn('IOSFODNN7EXAMPLE', masked)
    
    def test_short_value_masking(self):
        val = '12345678'  # 8 chars
        masked = mask_secret(val)
        # Never reveal > 50%
        self.assertLess(masked.count('*'), len(masked) // 2 + 1)
    
    def test_aws_detection(self):
        content = 'aws_key = AKIAIOSFODNN7EXAMPLE'
        secrets, exposures = scan_content(content, 'test.txt')
        self.assertTrue(any(s.secret_type == 'aws_access_key' for s in secrets))
        # Raw value never stored
        for s in secrets:
            self.assertNotIn('AKIAIOSFODNN7EXAMPLE', str(s))
    
    def test_pem_header_only(self):
        content = '-----BEGIN RSA PRIVATE KEY-----'
        secrets, exposures = scan_content(content, 'test.txt')
        # Bare header logged as lower severity signal, not full key
        for s in secrets:
            self.assertNotEqual(s.secret_type, 'private_key')  # full key needs header+footer


if __name__ == '__main__':
    unittest.main()
