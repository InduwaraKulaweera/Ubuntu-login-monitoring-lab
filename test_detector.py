import unittest
from detect_failed_logins import detect

def event(second, source='192.0.2.10', user='labuser'):
    return {'__REALTIME_TIMESTAMP': str((1700000000 + second) * 1000000),
            'MESSAGE': f'Failed password for {user} from {source} port 50000 ssh2'}

class DetectorTests(unittest.TestCase):
    def test_threshold(self):
        self.assertEqual(len(detect([event(x) for x in range(5)])), 1)

    def test_below_threshold(self):
        self.assertEqual(detect([event(x) for x in range(4)]), [])

    def test_expired_events(self):
        self.assertEqual(detect([event(x*301) for x in range(5)]), [])

    def test_separate_sources(self):
        self.assertEqual(detect([event(x, f'192.0.2.{x}') for x in range(5)]), [])

    def test_unordered_input(self):
        self.assertEqual(len(detect([event(x) for x in reversed(range(5))])), 1)

    def test_accepted_login_not_counted(self):
        self.assertEqual(detect([{'MESSAGE': 'Accepted password for labuser'}]*5), [])

    def test_ipv6(self):
        self.assertEqual(len(detect([event(x, '::1') for x in range(5)])), 1)

if __name__ == '__main__':
    unittest.main()
