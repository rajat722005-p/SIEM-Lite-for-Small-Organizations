#!/usr/bin/env python3
"""
SIEM-Lite External Log Traffic & Attack Telemetry Shipper
Sends multi-source security events to SIEM-Lite REST API (http://localhost:8000/api/logs)
"""

import sys
import time
import json
import urllib.request

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    except Exception:
        pass

SERVER_URL = "http://localhost:8000/api/logs"

def send_log(log_payload):
    try:
        data = json.dumps(log_payload).encode('utf-8')
        req = urllib.request.Request(SERVER_URL, data=data, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=3) as response:
            res_data = response.read().decode('utf-8')
            print(f"[SENT] [{log_payload.get('severity', 'INFO')}] {log_payload['source']} -> {log_payload['message']}")
    except Exception as e:
        print(f"[ERROR] Failed to send log to SIEM API: {e}")

def run_simulation():
    print("=" * 64)
    print("🛡️  Starting External Log Stream to SIEM-Lite Collector...")
    print(f"Target API: {SERVER_URL}\n")
    print("=" * 64)

    logs = [
        {"source": "windows-server", "ip": "192.168.1.15", "user": "administrator", "severity": "INFO", "message": "Event ID 4624: Account successfully logged on (admin)"},
        {"source": "linux-server", "ip": "185.220.101.4", "user": "root", "severity": "WARN", "message": "Failed password for root from 185.220.101.4 port 45100 ssh2"},
        {"source": "linux-server", "ip": "185.220.101.4", "user": "root", "severity": "WARN", "message": "Failed password for root from 185.220.101.4 port 45101 ssh2"},
        {"source": "linux-server", "ip": "185.220.101.4", "user": "root", "severity": "WARN", "message": "Failed password for root from 185.220.101.4 port 45102 ssh2"},
        {"source": "linux-server", "ip": "185.220.101.4", "user": "root", "severity": "WARN", "message": "Failed password for root from 185.220.101.4 port 45103 ssh2"},
        {"source": "linux-server", "ip": "185.220.101.4", "user": "root", "severity": "WARN", "message": "Failed password for root from 185.220.101.4 port 45104 ssh2"},
        {"source": "web-application", "ip": "45.33.32.156", "user": "anonymous", "severity": "HIGH", "message": "GET /products?id=1' UNION SELECT username, password FROM users-- HTTP/1.1"},
        {"source": "firewall", "ip": "103.253.144.10", "user": "system", "severity": "WARN", "message": "Firewall connection dropped TCP 103.253.144.10 -> 192.168.1.1: port 3389 (SYN Scan)"},
        {"source": "web-application", "ip": "194.26.29.112", "user": "www-data", "severity": "CRITICAL", "message": "POST /uploads/shell.php?cmd=powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA= HTTP/1.1 200"},
        {"source": "windows-server", "ip": "192.168.1.15", "user": "SYSTEM", "severity": "CRITICAL", "message": "Windows Event 1102: The audit log was cleared by compromised user"}
    ]

    for log in logs:
        send_log(log)
        time.sleep(0.8)

    print("\n[+] Ingestion batch complete.")

if __name__ == '__main__':
    run_simulation()
