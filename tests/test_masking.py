import unittest
from scanner import mask_secret


class TestMasking(unittest.TestCase):
    def test_short_never_reveals_half(self):
        for val in ['1234567', '12345678']:
            masked = mask_secret(val)
            # Count non-asterisk chars
            visible = sum(1 for c in masked if c != '*')
            self.assertLessEqual(visible, len(val) / 2)
    
    def test_long_shows_prefix_suffix(self):
        val = 'AKIAIOSFODNN7EXAMPLE123'
        masked = mask_secret(val, 'aws_access_key')
        self.assertTrue(masked.startswith('AKIA'))


if __name__ == '__main__':
    unittest.main()
