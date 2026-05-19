# ingestion/ssh_collector.py
"""
Collect logs from a remote Linux host over SSH.
Requires: pip install paramiko
"""

import paramiko
import time
from streaming.producer import SIEMProducer

class SSHLogCollector:
    def __init__(self, host: str, username: str, key_path: str,
                 remote_log_path: str = "/var/log/auth.log"):
        self.host = host
        self.username = username
        self.key_path = key_path
        self.remote_log_path = remote_log_path
        self.producer = SIEMProducer()

    def collect(self):
        """SSH into remote host and tail the log file."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=self.host,
                username=self.username,
                key_filename=self.key_path
            )
            print(f"[SSHCollector] Connected to {self.host}")

            # Run tail -f on remote log file
            _, stdout, _ = client.exec_command(
                f"tail -f {self.remote_log_path}"
            )

            for line in stdout:
                line = line.strip()
                if line:
                    self.producer.send_raw_log(line)
                    print(f"[SSHCollector] {self.host}: {line[:80]}")

        except Exception as e:
            print(f"[SSHCollector] Error: {e}")
        finally:
            client.close()
