import time
import re
import json
import os
import urllib.request
from collections import defaultdict
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "server_logs.log")
ALERTS_FILE = os.path.join(BASE_DIR, "alerts.json")
FIREWALL_FILE = os.path.join(BASE_DIR, "firewall_blocks.txt")

# --- SIEM Detection Rules (Regex) ---
SSH_FAILED_REGEX = re.compile(r"sshd\[\d+\]: Failed password for .* from (\d+\.\d+\.\d+\.\d+)")
WEB_SQLI_REGEX = re.compile(r"GET .*?(UNION|OR|DROP|SELECT).*? HTTP", re.IGNORECASE)

# --- Threat Tracking ---
failed_logins = defaultdict(list)
BRUTE_FORCE_THRESHOLD = 5
TIME_WINDOW = 60

def get_geolocation(ip):
    """Fetches Geolocation for an IP address using ip-api.com"""
    if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("172.") or ip == "127.0.0.1":
        return "Local Network (Internal)"
    try:
        url = f"http://ip-api.com/json/{ip}"
        # We spoof a User-Agent to ensure the API responds properly.
        req = urllib.request.Request(url, headers={'User-Agent': 'SIEM-Engine/1.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                return f"{data.get('country')}, {data.get('city')}"
    except Exception as e:
        pass
    return "Unknown Location"

def auto_block_ip(ip):
    """Simulates Active Defense by writing rules to a firewall config"""
    if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("172."):
        return "Ignored Local IP"
        
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Simulate an iptables drop rule
    rule = f"[{timestamp}] iptables -A INPUT -s {ip} -j DROP"
    with open(FIREWALL_FILE, "a") as f:
        f.write(rule + "\n")
    return "IP Blocked"

def save_alert(alert_data):
    # 🌟 FEATURE 1: Enrich data with IP Geolocation
    alert_data['location'] = get_geolocation(alert_data['ip'])
    
    # 🌟 FEATURE 2: Active Defense (Auto Block)
    alert_data['action_taken'] = auto_block_ip(alert_data['ip'])
    
    alerts = []
    if os.path.exists(ALERTS_FILE):
        try:
            with open(ALERTS_FILE, "r") as f:
                alerts = json.load(f)
        except json.JSONDecodeError:
            pass
            
    alerts.append(alert_data)
    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=4)
        
    print(f"\n\033[91m[🚨 ALERT] {alert_data['type']} from {alert_data['ip']} ({alert_data['location']})\033[0m")
    print(f"    -> Action: \033[92m{alert_data['action_taken']}\033[0m")

def process_log_line(line):
    # Rule 1: SSH Brute Force
    ssh_match = SSH_FAILED_REGEX.search(line)
    if ssh_match:
        ip = ssh_match.group(1)
        current_time = time.time()
        failed_logins[ip].append(current_time)
        # Clear out old attempts
        failed_logins[ip] = [t for t in failed_logins[ip] if current_time - t <= TIME_WINDOW]
        
        if len(failed_logins[ip]) >= BRUTE_FORCE_THRESHOLD:
            alert_data = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": ip,
                "type": "SSH Brute Force",
                "severity": "High",
                "details": f"{BRUTE_FORCE_THRESHOLD} failed logins within {TIME_WINDOW}s"
            }
            save_alert(alert_data)
            failed_logins[ip].clear() # Reset tracking for this IP
            
    # Rule 2: Web API SQL Injection
    if "GET" in line:
        sqli_match = WEB_SQLI_REGEX.search(line)
        if sqli_match:
            ip_match = re.search(r"^(\d+\.\d+\.\d+\.\d+)", line)
            ip = ip_match.group(1) if ip_match else "Unknown"
            
            alert_data = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": ip,
                "type": "Web SQL Injection",
                "severity": "Critical",
                "details": f"Malicious SQL Keyword: '{sqli_match.group(1).upper()}'"
            }
            save_alert(alert_data)

def main():
    print("==================================================")
    print("🧠 Custom SIEM - Engine Started with Active Defense 🛡️")
    print(f"[*] Monitoring: {LOG_FILE}")
    print("==================================================")
    
    while not os.path.exists(LOG_FILE):
        time.sleep(1)
        
    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            process_log_line(line)

if __name__ == "__main__":
    # Clear old alerts on startup
    with open(ALERTS_FILE, "w") as f:
        json.dump([], f)
    # Reset mock firewall log
    with open(FIREWALL_FILE, "w") as f:
        f.write("# SIEM Automated Firewall Rules\n")
    # Fix console color on Windows
    os.system('color')
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Engine stopped safely.")
