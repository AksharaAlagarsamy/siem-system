# ingestion/file_watcher.py
"""
Watches a log file (e.g., /var/log/auth.log) and tails new lines.
Sends each line to the Kafka producer.
"""

import time
import os
from streaming.producer import SIEMProducer
from config.settings import LOG_FILE_PATH

class FileWatcher:
    def __init__(self, filepath: str = LOG_FILE_PATH):
        self.filepath = filepath
        self.producer = SIEMProducer()

    def tail(self):
        """Continuously tail the log file and stream new lines."""
        print(f"[FileWatcher] Watching {self.filepath}")

        with open(self.filepath, "r") as f:
            # Start at end of file — only stream new lines
            f.seek(0, os.SEEK_END)

            while True:
                line = f.readline()
                if line:
                    line = line.strip()
                    if line:
                        # Send raw log line to Kafka
                        self.producer.send_raw_log(line)
                        print(f"[FileWatcher] Sent: {line[:80]}...")
                else:
                    time.sleep(0.1)  # Poll every 100ms


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
