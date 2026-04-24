# 🔐 AI-Based SIEM System using Tcpdump & Machine Learning

## 📌 Overview

This project is a **Security Information and Event Management (SIEM)** system built using Python.
It analyzes real-time network traffic using `tcpdump` and applies **machine learning (Isolation Forest)** to detect anomalies and suspicious activity.

---

## 🚀 Features

* 📡 Capture network traffic using tcpdump
* 📊 Convert logs into structured data
* 🤖 Detect anomalies using Isolation Forest
* 🚨 Identify suspicious IP addresses
* 📈 Generate traffic visualization graphs
* ⚠ Alert system for abnormal behavior

---

## 🛠 Technologies Used

* Python
* Pandas
* Scikit-learn
* Matplotlib
* Tcpdump (Kali Linux)

---

## 📂 Project Structure

```
siem-system/
│── app.py              # Main SIEM script
│── traffic.log         # Captured network data (ignored in Git)
│── output.png          # Traffic graph
│── ip_traffic.png      # IP analysis graph
│── README.md           # Project documentation
```

---

## ⚙️ Installation

### 1. Clone Repository

```
git clone https://github.com/your-username/siem-system.git
cd siem-system
```

### 2. Create Virtual Environment

```
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```
pip install pandas matplotlib scikit-learn
```

---

## ▶️ Usage

### Step 1: Capture Network Traffic

```
sudo tcpdump -i eth0 -nn > traffic.log
```

Press `CTRL + C` after some time.

### Step 2: Run SIEM System

```
python app.py
```

---

## 📊 Output

* Displays anomaly detection results in terminal
* Identifies suspicious IP addresses
* Saves graphs:

  * `output.png`
  * `ip_traffic.png`

---

## 🧠 How It Works

1. Tcpdump captures live network packets
2. Logs are parsed into structured format
3. Packet counts & IP activity are analyzed
4. Isolation Forest detects anomalies
5. Alerts are generated for suspicious behavior

---

## 🚨 Example Alert

```
🚨 Suspicious IP: 172.20.10.6 → requests = 150
```

---

## 🔮 Future Enhancements

* Real-time monitoring (live SIEM)
* Automatic IP blocking using iptables
* Web dashboard (Flask / Streamlit)
* Email alert system
* Geo-location tracking of attackers

---

## 👩‍💻 Author

Developed as part of a cybersecurity & data science project.

---

## ⭐ Contribute

Feel free to fork and improve this project!

---
