import time
import requests
import pandas as pd
import streamlit as st

API_BASE     = "http://localhost:5000/api"
REFRESH_SECS = 5

st.set_page_config(page_title="SIEM Dashboard", page_icon="shield", layout="wide")

def fetch(endpoint):
    try:
        r = requests.get(f"{API_BASE}/{endpoint}", timeout=3)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        return None
    except Exception as e:
        st.warning(f"API error on /{endpoint}: {e}")
        return None

health = fetch("health")
if health is None:
    st.error("Cannot reach Flask API at localhost:5000. Make sure python webapp.py is running.")
    st.stop()

st.title("SIEM — Security Monitoring Dashboard")
st.caption(f"Live data · auto-refreshes every {REFRESH_SECS}s")

summary = fetch("summary") or {"total": 0, "success": 0, "failed": 0, "anomalies": 0}

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Events (24h)",  summary.get("total",     0))
c2.metric("Successful Logins",   summary.get("success",   0))
c3.metric("Failed Logins",       summary.get("failed",    0))
c4.metric("ML Anomalies",        summary.get("anomalies", 0))

st.divider()

col_left, col_right = st.columns([2, 1])

with col_left:
    st.subheader("Login Activity — Last 24 Hours")
    timeline = fetch("timeline")
    if timeline:
        df = pd.DataFrame(timeline)
        if not df.empty:
            st.line_chart(df.set_index("hour")[["total", "failed"]])
        else:
            st.info("No events yet.")
    else:
        st.warning("Timeline unavailable.")

with col_right:
    st.subheader("Top Source IPs")
    top_ips = fetch("top-ips")
    if top_ips:
        df = pd.DataFrame(top_ips)
        if not df.empty:
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No IP data yet.")
    else:
        st.warning("Top IPs unavailable.")

st.divider()

col_threats, col_alerts = st.columns([1, 2])

with col_threats:
    st.subheader("Detection Labels")
    threats = fetch("threats")
    if threats:
        df = pd.DataFrame(threats)
        if not df.empty:
            st.bar_chart(df.set_index("label")["count"])
        else:
            st.info("No detections yet.")
    else:
        st.warning("Threat data unavailable.")

with col_alerts:
    st.subheader("Recent Alerts")
    alerts = fetch("alerts")
    if alerts:
        df = pd.DataFrame(alerts)
        if not df.empty:
            cols = [c for c in ["timestamp","ip","username","severity","risk_score","labels"] if c in df.columns]
            st.dataframe(df[cols], use_container_width=True, hide_index=True)
        else:
            st.success("No alerts triggered yet.")
    else:
        st.warning("Alerts unavailable.")

st.divider()
st.subheader("High-Risk Events (score >= 60)")
high_risk = fetch("high-risk")
if high_risk:
    df = pd.DataFrame(high_risk)
    if not df.empty:
        cols = [c for c in ["timestamp","ip","username","status","risk_score","ml_score","labels"] if c in df.columns]
        st.dataframe(df[cols], use_container_width=True, hide_index=True)
    else:
        st.success("No high-risk events.")
else:
    st.warning("High-risk data unavailable.")

st.caption("SIEM Lightweight — Security Monitoring System")
time.sleep(REFRESH_SECS)
st.rerun()
