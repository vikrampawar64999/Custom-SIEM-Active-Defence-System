import time
import random
from datetime import datetime
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "server_logs.log")

# Internal normal IPs
IP_ADDRESSES = ["192.168.1.10", "10.0.0.5", "172.16.0.4", "8.8.8.8"]

# Real Public IPs from around the world to demonstrate Geolocation Tracking
MALICIOUS_IPS = [
    "45.33.32.156",  # USA
    "114.114.114.114", # China
    "77.88.55.242",  # Russia
    "85.214.132.117", # Germany
    "175.45.176.1"   # North Korea (Routed)
]

SQLI_PAYLOADS = [
    "1' OR '1'='1",
    "' UNION SELECT username, password FROM users--",
    "admin' --",
    "'; DROP TABLE users--"
]

def generate_ssh_log(ip, status="Failed"):
    dt = datetime.now().strftime("%b %d %H:%M:%S")
    return f"{dt} server1 sshd[1234]: {status} password for root from {ip} port {random.randint(10000, 60000)} ssh2\n"

def generate_web_log(ip, payload=None):
    dt = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0530")
    if payload:
        request = f"GET /login?username={payload} HTTP/1.1"
        status_code = 200 
    else:
        request = f"GET /index.html HTTP/1.1"
        status_code = 200
    
    return f'{ip} - - [{dt}] "{request}" {status_code} {random.randint(500, 2000)}\n'

def main():
    print("==================================================")
    print("🛡️  Advanced Custom SIEM - Log Generator 🛡️")
    print(f"[*] Writing fake logs to: {LOG_FILE}")
    print("==================================================")
    
    try:
        while True:
            with open(LOG_FILE, "a") as f:
                action = random.choices(
                    ["normal_ssh", "normal_web", "brute_force", "sqli"],
                    weights=[0.3, 0.4, 0.2, 0.1]
                )[0]

                if action == "normal_ssh":
                    f.write(generate_ssh_log(random.choice(IP_ADDRESSES), "Accepted"))
                elif action == "normal_web":
                    f.write(generate_web_log(random.choice(IP_ADDRESSES)))
                elif action == "brute_force":
                    attacker_ip = random.choice(MALICIOUS_IPS)
                    print(f"    [!] Simulating SSH Brute Force from {attacker_ip}...")
                    for _ in range(random.randint(5, 10)):
                        f.write(generate_ssh_log(attacker_ip, "Failed"))
                        time.sleep(0.1)
                elif action == "sqli":
                    attacker_ip = random.choice(MALICIOUS_IPS)
                    print(f"    [!] Simulating SQL Injection from {attacker_ip}...")
                    f.write(generate_web_log(attacker_ip, random.choice(SQLI_PAYLOADS)))
                
                f.flush()
            time.sleep(random.uniform(1.0, 3.0))
            
    except KeyboardInterrupt:
        print("\n[*] Log Generator stopped safely.")

if __name__ == "__main__":
    with open(LOG_FILE, "w") as f: f.write("")
    main()
