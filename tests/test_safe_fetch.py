import unittest
from safe_fetch import is_safe_ip


class TestSafeFetch(unittest.TestCase):
    def test_reject_loopback(self):
        self.assertFalse(is_safe_ip('127.0.0.1'))
        self.assertFalse(is_safe_ip('::1'))
    
    def test_reject_private(self):
        self.assertFalse(is_safe_ip('10.0.0.1'))
        self.assertFalse(is_safe_ip('192.168.1.1'))
        self.assertFalse(is_safe_ip('172.16.0.1'))
    
    def test_reject_metadata(self):
        self.assertFalse(is_safe_ip('169.254.169.254'))
    
    def test_reject_link_local(self):
        self.assertFalse(is_safe_ip('169.254.1.1'))
        self.assertFalse(is_safe_ip('fe80::1'))


if __name__ == '__main__':
    unittest.main()
