# main.py
"""
Orchestrates the full SIEM pipeline.

Usage:
  python main.py --mode ingest     # Start log ingestion (file watcher)
  python main.py --mode consume    # Start processing consumer
  python main.py --mode simulate   # Run test scenario
  python main.py --mode all        # Run everything (for dev)
"""

import argparse
import threading
from ingestion.file_watcher  import FileWatcher
from ingestion.log_simulator import LogSimulator
from streaming.consumer      import SIEMConsumer
from config.settings         import LOG_FILE_PATH


def run_ingestion():
    watcher = FileWatcher(filepath=LOG_FILE_PATH)
    watcher.tail()


def run_consumer():
    consumer = SIEMConsumer()
    consumer.run()


def run_simulation():
    sim = LogSimulator()
    sim.run_full_scenario()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lightweight SIEM System")
    parser.add_argument(
        "--mode",
        choices=["ingest", "consume", "simulate", "all"],
        default="all"
    )
    args = parser.parse_args()

    if args.mode == "ingest":
        run_ingestion()

    elif args.mode == "consume":
        run_consumer()

    elif args.mode == "simulate":
        run_simulation()

    elif args.mode == "all":
        # Run ingestion + consumer in parallel threads
        t_ingest  = threading.Thread(target=run_ingestion,  daemon=True)
        t_consume = threading.Thread(target=run_consumer,   daemon=True)

        t_ingest.start()
        t_consume.start()

        print("[Main] SIEM pipeline running. Press Ctrl+C to stop.")
        try:
            t_ingest.join()
            t_consume.join()
        except KeyboardInterrupt:
            print("\n[Main] Shutting down.")
