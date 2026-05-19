import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import unittest
from parsers.auth_log_parser import parse_auth_log_line
from parsers.normalizer import normalize

class TestAuthLogParser(unittest.TestCase):

    def test_iso_failed_login(self):
        line = "2026-05-19T14:23:01.123456-04:00 kali sshd[1234]: Failed password for bob from 192.168.1.5 port 52341 ssh2"
        result = parse_auth_log_line(line)
        self.assertEqual(result["status"],     "failed")
        self.assertEqual(result["username"],   "bob")
        self.assertEqual(result["ip"],         "192.168.1.5")
        self.assertEqual(result["event_type"], "ssh_login")

    def test_iso_success_login(self):
        line = "2026-05-19T09:00:00.000000-04:00 kali sshd[5678]: Accepted password for alice from 10.0.0.1 port 44000 ssh2"
        result = parse_auth_log_line(line)
        self.assertEqual(result["status"],   "success")
        self.assertEqual(result["username"], "alice")
        self.assertEqual(result["ip"],       "10.0.0.1")

    def test_old_format_failed_login(self):
        line = "May 19 14:23:01 ubuntu sshd[9999]: Failed password for root from 10.0.0.5 port 22 ssh2"
        result = parse_auth_log_line(line)
        self.assertEqual(result["status"],   "failed")
        self.assertEqual(result["username"], "root")

    def test_invalid_user(self):
        line = "2026-05-19T14:23:01.000000-04:00 kali sshd[1111]: Failed password for invalid user fakeuser from 192.168.1.99 port 55000 ssh2"
        result = parse_auth_log_line(line)
        self.assertEqual(result["status"],   "failed")
        self.assertEqual(result["username"], "fakeuser")

    def test_empty_line(self):
        result = parse_auth_log_line("")
        self.assertEqual(result["event_type"], "unparsed")

    def test_malformed_line(self):
        result = parse_auth_log_line("!@#$%^&*()")
        self.assertIn("event_type", result)

    def test_root_risk_score(self):
        line = "2026-05-19T03:00:00.000000-04:00 kali sshd[2222]: Failed password for root from 1.2.3.4 port 22 ssh2"
        event = normalize(parse_auth_log_line(line))
        self.assertTrue(event["is_root"])
        self.assertGreaterEqual(event["risk_score"], 40)

if __name__ == "__main__":
    unittest.main(verbosity=2)
