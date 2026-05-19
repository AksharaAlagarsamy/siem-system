import time
import os
from pipeline import SIEMProducer
from config.settings import LOG_FILE_PATH

class FileWatcher:
    def __init__(self, filepath=LOG_FILE_PATH):
        self.filepath = filepath
        self.producer = SIEMProducer()

    def tail(self):
        print(f"[FileWatcher] Watching: {self.filepath}")
        if not os.path.exists(self.filepath):
            print(f"[FileWatcher] Creating: {self.filepath}")
            os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
            open(self.filepath, "w").close()
        try:
            with open(self.filepath, "r") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if line:
                        self.producer.send_raw_log(line.strip())
                        print(f"[FileWatcher] Queued: {line[:80].strip()}")
                    else:
                        time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[FileWatcher] Stopped.")
        except Exception as e:
            print(f"[FileWatcher] Error: {e}")
