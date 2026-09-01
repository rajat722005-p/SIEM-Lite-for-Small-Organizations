#!/usr/bin/env python3
"""
SIEM-Lite Log File Tailer & Shipper Agent
Monitors and tails live log files (e.g. Nginx access.log, Apache error.log, Linux auth.log, custom app logs)
and streams lines in real-time to SIEM-Lite REST API.
"""

import os
import sys
import time
import json
import socket
import argparse
import urllib.request

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    except Exception:
        pass

SIEM_URL = os.environ.get("SIEM_URL", "http://localhost:8000")

def send_log(log_payload):
    try:
        data = json.dumps(log_payload).encode('utf-8')
        req = urllib.request.Request(
            f"{SIEM_URL}/api/logs",
            data=data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            print(f"[+] [TAIL SHIP] {log_payload['source']} -> {log_payload['message'][:80]}")
    except Exception as e:
        print(f"[!] Error sending log: {e}")

def tail_file(filepath, source_name="file-tailer"):
    if not os.path.exists(filepath):
        print(f"[!] Log file does not exist: {filepath}. Creating empty file to watch...")
        with open(filepath, 'a') as f:
            f.write(f"# SIEM Log Source Initialized: {filepath}\n")

    print(f"[+] Tailing log file: {filepath} (Source: {source_name})")
    with open(filepath, 'r') as f:
        # Seek to end of file
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            line = line.strip()
            if not line or line.startswith("#"):
                continue

            severity = "INFO"
            if any(w in line.lower() for w in ['error', 'warn', 'fail', 'denied', '403', '401', '500']):
                severity = "WARN"
            if any(w in line.lower() for w in ['crit', 'sql', 'union', 'select', 'drop', 'attack', 'inject']):
                severity = "HIGH"

            payload = {
                "source": source_name,
                "ip": socket.gethostbyname(socket.gethostname()),
                "user": "file-watcher",
                "severity": severity,
                "message": line,
                "raw": line
            }
            send_log(payload)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="SIEM-Lite Log File Tailer")
    parser.add_argument("--file", "-f", default="sample_app.log", help="Path to log file to tail")
    parser.add_argument("--source", "-s", default="web-application", help="Source identifier")
    args = parser.parse_args()

    try:
        tail_file(args.file, args.source)
    except KeyboardInterrupt:
        print("\nStopping file tailer...")
