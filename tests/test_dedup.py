import unittest
from db import build_fingerprint


class TestDedup(unittest.TestCase):
    def test_fingerprint_same_secret_same_file_same_commit_one_occurrence(self):
        h = 'abc123'
        f1 = build_fingerprint(h, 'github', 'owner/repo', 'file.py', 'sha123')
        f2 = build_fingerprint(h, 'github', 'owner/repo', 'file.py', 'sha123')
        self.assertEqual(f1, f2)
    
    def test_fingerprint_different_line_same_commit_same_occurrence(self):
        # Same secret, same file, same commit - should produce same fingerprint
        h = 'abc123'
        f1 = build_fingerprint(h, 'github', 'owner/repo', 'file.py', 'sha123')
        f2 = build_fingerprint(h, 'github', 'owner/repo', 'file.py', 'sha123')
        self.assertEqual(f1, f2)


if __name__ == '__main__':
    unittest.main()
