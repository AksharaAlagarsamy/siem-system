import streamlit as st
import pandas as pd
import random

st.set_page_config(page_title="AI SIEM", layout="wide")

st.title("🔐 AI-Based SIEM Dashboard")

# -----------------------------
# METRICS
# -----------------------------
col1, col2, col3 = st.columns(3)

col1.metric("Packets Captured", random.randint(1000, 5000))
col2.metric("Suspicious IPs", random.randint(1, 10))
col3.metric("Alerts Generated", random.randint(5, 50))

# -----------------------------
# SAMPLE TRAFFIC DATA
# -----------------------------
data = pd.DataFrame({
    "Time": range(10),
    "Packets": [12, 25, 18, 40, 22, 60, 75, 30, 90, 120]
})

# -----------------------------
# LINE CHART
# -----------------------------
st.subheader("📈 Network Traffic")

st.line_chart(data.set_index("Time"))

# -----------------------------
# ALERT SECTION
# -----------------------------
st.subheader("🚨 Alerts")

st.error("Suspicious traffic detected from IP 192.168.1.5")

# -----------------------------
# TABLE OF IPS
# -----------------------------
st.subheader("🌐 Top Source IPs")

ip_data = pd.DataFrame({
    "IP Address": [
        "192.168.1.5",
        "10.0.0.7",
        "172.16.0.9"
    ],
    "Requests": [
        120,
        80,
        65
    ]
})

st.table(ip_data)
