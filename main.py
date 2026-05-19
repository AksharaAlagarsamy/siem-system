import argparse
import threading
import time
import os
from pipeline import SIEMConsumer, get_event_count
from ingestion.file_watcher import FileWatcher
from ingestion.log_simulator import LogSimulator

# Only watch auth.log — syslog has too much noise
LOG_FILES = [
    "/var/log/auth.log",
]

def run_consumer():
    SIEMConsumer().run()

def run_watcher(filepath):
    FileWatcher(filepath=filepath).tail()

def run_simulator():
    time.sleep(2)
    LogSimulator().run_full_scenario()

def status_reporter():
    while True:
        time.sleep(30)
        count = get_event_count()
        if count > 0:
            print(f"[Status] SSH events processed: {count}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--simulate", action="store_true")
    args = parser.parse_args()

    print("=" * 55)
    print("  SIEM System — Real-time Security Monitoring")
    print("  Dashboard : streamlit run dashboard.py")
    print("  API       : python webapp.py")
    print("=" * 55)

    threading.Thread(target=run_consumer,    daemon=True).start()
    threading.Thread(target=status_reporter, daemon=True).start()

    if args.simulate:
        threading.Thread(target=run_simulator, daemon=True).start()
        print("[Main] Simulator mode — test traffic in 2s...")
    else:
        for f in LOG_FILES:
            if os.path.exists(f):
                threading.Thread(target=run_watcher, args=(f,), daemon=True).start()
                print(f"[Main] Watching: {f}")
            else:
                open(f, "w").close()
                threading.Thread(target=run_watcher, args=(f,), daemon=True).start()
                print(f"[Main] Created and watching: {f}")

    print("[Main] Press Ctrl+C to stop.\n")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n[Main] Done. Events: {get_event_count()}")
