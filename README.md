# Custom SIEM & Active Defense System 🛡️

A custom-built Security Information and Event Management (SIEM) system developed in Python. This project demonstrates real-time log monitoring, threat detection, IP geolocation tracking, active defense mechanisms, and a live web dashboard.

## 🌟 Key Features

*   **Real-Time Threat Detection**: Continuously monitors server logs to identify malicious activities using Regex-based rules.
    *   **SSH Brute Force Detection**: Detects repeated failed login attempts within a specific time window.
    *   **SQL Injection Detection**: Identifies malicious web requests containing SQL injection payloads `(UNION, OR, DROP, SELECT)`.
*   **Active Defense (Auto-Blocking)**: Automatically simulates blocking attacker IPs by writing mock `iptables` drop rules to a firewall configuration file.
*   **IP Geolocation Tracking**: Integrates with the `ip-api.com` API to trace the origin country and city of malicious/attacking IPs.
*   **Live Web Dashboard**: A Flask-based web interface that automatically fetches and displays real-time security alerts.
*   **Log Simulation Engine**: Includes a custom log generator script to simulate both normal network traffic and active attacks, making it easy to test the SIEM engine out-of-the-box.

## 🏗️ Architecture & Components

The project consists of three main Python scripts running concurrently:

1.  **`log_generator.py`**: Simulates a live server environment by generating randomized logs (Normal Web/SSH traffic, SQLi attacks, and SSH Brute Force sequences) and writing them to `server_logs.log`.
2.  **`siem_engine.py`**: The core detection engine. It continuously tails `server_logs.log`, applies detection rules, fetches geolocation data for attackers, simulates firewall blocks in `firewall_blocks.txt`, and saves formatted alerts to `alerts.json`.
3.  **`app.py`**: A lightweight Flask web application that serves the SOC dashboard (`templates/index.html`) and provides an API endpoint `(/api/alerts)` to stream alerts in real-time to the frontend.

## 🚀 Getting Started

### Prerequisites

*   Python 3.x installed on your system.
*   `Flask` library for the web dashboard.

### Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/vikrampawar64999/Custom-SIEM-Active-Defence-System.git
    cd Custom-SIEM-Active-Defence-System
    ```

2.  Install the required dependencies:
    ```bash
    pip install flask
    ```

### How to Run the Project

To see the SIEM system in action, you need to run all three components simultaneously in separate terminal windows.

**Terminal 1: Start the Log Generator**
This will start simulating normal and malicious traffic.
```bash
python log_generator.py
```

**Terminal 2: Start the SIEM Detection Engine**
This will begin analyzing the generated logs, detecting threats, and triggering active defenses.
```bash
python siem_engine.py
```

**Terminal 3: Start the Web Dashboard**
This will launch the Flask server to visualize the alerts.
```bash
python app.py
```

Once all scripts are running, open your web browser and navigate to:
👉 **http://127.0.0.1:5000** to view the live SOC Dashboard.

## ⚠️ Disclaimer

This project is designed **strictly for educational and demonstration purposes**. It is intended to showcase cybersecurity concepts such as log analysis and active defense in a controlled environment. Do not use this tool in a production environment without significant modifications and proper authorization.