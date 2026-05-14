import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
import subprocess
from collections import defaultdict
import time

# -------------------------------
# REAL-TIME TCPDUMP COMMAND
# -------------------------------
command = ["sudo", "tcpdump", "-i", "eth0", "-nn", "-l"]

process = subprocess.Popen(
    command,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True
)

print("🚀 Real-Time AI SIEM Started...\n")

# -------------------------------
# STORE PACKETS PER SECOND
# -------------------------------
time_counts = defaultdict(int)

# -------------------------------
# LIVE PACKET MONITORING
# -------------------------------
for line in process.stdout:

    try:
        print(line.strip())

        # -------------------------------
        # EXTRACT TIMESTAMP (HH:MM:SS)
        # -------------------------------
        packet_time = line.split()[0].split(".")[0]

        # Increase packet count
        time_counts[packet_time] += 1

        # -------------------------------
        # CONVERT TO DATAFRAME
        # -------------------------------
        df = pd.DataFrame(
            list(time_counts.items()),
            columns=["time", "event_count"]
        )

        # -------------------------------
        # ANOMALY DETECTION
        # -------------------------------
        if len(df) > 5:

            model = IsolationForest(
                contamination=0.2,
                random_state=42
            )

            df["anomaly"] = model.fit_predict(
                df[["event_count"]]
            )

            # -------------------------------
            # OUTPUT
            # -------------------------------
            print("\n===== SIEM OUTPUT =====\n")
            print(df)

            # -------------------------------
            # ALERT SYSTEM
            # -------------------------------
            if -1 in df["anomaly"].values:
                print("\n⚠ ALERT: Suspicious network activity detected!\n")
            else:
                print("\n✅ Normal traffic\n")

            # -------------------------------
            # GRAPH
            # -------------------------------
            plt.clf()

            plt.plot(df["event_count"])

            plt.title("Network Traffic Activity")
            plt.xlabel("Time Index")
            plt.ylabel("Packet Count")

            plt.tight_layout()

            plt.savefig("output.png")

            print("📈 Graph saved as output.png")

            # -------------------------------
            # ANOMALY DETAILS
            # -------------------------------
            print("\n===== ANOMALY DETAILS =====\n")

            for i in range(len(df)):
                if df["anomaly"][i] == -1:
                    print(
                        f"🚨 Time {df['time'][i]} "
                        f"→ packets = {df['event_count'][i]}"
                    )

    except Exception as e:
        print("Error:", e)

    time.sleep(0.1)
