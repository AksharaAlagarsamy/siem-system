import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest

# -------------------------------
# STEP 1: READ TCPDUMP FILE
# -------------------------------
file_path = "traffic.log"

with open(file_path, "r") as f:
    lines = f.readlines()

# -------------------------------
# STEP 2: COUNT PACKETS PER SECOND
# -------------------------------
time_counts = {}

for line in lines:
    try:
        # Extract timestamp (HH:MM:SS)
        time = line.split()[0].split(".")[0]

        if time in time_counts:
            time_counts[time] += 1
        else:
            time_counts[time] = 1
    except:
        continue

# Convert to DataFrame
df = pd.DataFrame(list(time_counts.items()), columns=["time", "event_count"])

# -------------------------------
# STEP 3: ANOMALY DETECTION
# -------------------------------
model = IsolationForest(contamination=0.2, random_state=42)
df["anomaly"] = model.fit_predict(df[["event_count"]])

# -------------------------------
# STEP 4: OUTPUT
# -------------------------------
print("\n===== SIEM OUTPUT =====\n")
print(df)

# Alert
if -1 in df["anomaly"].values:
    print("\n⚠ ALERT: Suspicious network activity detected!\n")
else:
    print("\n✅ Normal traffic\n")

# -------------------------------
# STEP 5: GRAPH
# -------------------------------
plt.figure()
plt.plot(df["event_count"])
plt.title("Network Traffic Activity")
plt.xlabel("Time Index")
plt.ylabel("Packet Count")

plt.savefig("output.png")

print("📈 Graph saved as output.png")

# -------------------------------
# STEP 6: ANOMALY DETAILS
# -------------------------------
print("\n===== ANOMALY DETAILS =====\n")

for i in range(len(df)):
    if df["anomaly"][i] == -1:
        print(f"🚨 Time {df['time'][i]} → packets = {df['event_count'][i]}")
