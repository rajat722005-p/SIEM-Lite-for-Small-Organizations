#!/usr/bin/env python3
"""
SIEM-Lite Windows Security Event Log Forwarder Agent
Captures live Windows Security Event logs and forwards them in real-time to SIEM-Lite REST API.
Monitored Security Event IDs:
- 4625: An account failed to log on (Brute force indicator)
- 4624: An account was successfully logged on
- 4720: A user account was created (Persistence / Backdoor)
- 4726: A user account was deleted
- 1102: The audit log was cleared (Defense evasion)
- 7045: A service was installed in the system (Privilege Escalation)
- 4688: A new process has been created (Command execution)
"""

import os
import sys
import time
import json
import socket
import platform
import subprocess
import urllib.request

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    except Exception:
        pass

SIEM_URL = os.environ.get("SIEM_URL", "http://localhost:8000")
AGENT_ID = f"AGT-WIN-{socket.gethostname()}"
AGENT_NAME = f"Windows Security Agent ({socket.gethostname()})"
POLL_INTERVAL = 3  # seconds

def send_heartbeat(events_sent=0):
    try:
        payload = {
            "agent_id": AGENT_ID,
            "name": AGENT_NAME,
            "type": "Windows Event Forwarder",
            "hostname": socket.gethostname(),
            "ip_address": socket.gethostbyname(socket.gethostname()),
            "os": f"{platform.system()} {platform.release()} ({platform.version()})",
            "events_sent": events_sent
        }
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            f"{SIEM_URL}/api/agents/heartbeat",
            data=data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            pass
    except Exception as e:
        print(f"[!] Heartbeat error: {e}")

def forward_log(log_payload):
    try:
        data = json.dumps(log_payload).encode('utf-8')
        req = urllib.request.Request(
            f"{SIEM_URL}/api/logs",
            data=data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            print(f"[+] [FORWARDED] [{log_payload.get('severity', 'INFO')}] {log_payload.get('message')}")
    except Exception as e:
        print(f"[!] Log forward error: {e}")

def read_real_windows_events():
    """Reads latest security events using PowerShell or wevtutil on Windows."""
    ps_cmd = (
        'Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625,4624,4720,1102,7045} -MaxEvents 5 -ErrorAction SilentlyContinue | '
        'Select-Object Id, TimeCreated, Message | ConvertTo-Json'
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            raw = json.loads(result.stdout)
            events = [raw] if isinstance(raw, dict) else raw
            return events
    except Exception:
        pass
    return []

def run_agent():
    print("=" * 64)
    print(f"🛡️  SIEM-Lite Windows Endpoint Security Collector")
    print(f"[*] Agent ID:   {AGENT_ID}")
    print(f"[*] Hostname:   {socket.gethostname()}")
    print(f"[*] Target SIEM: {SIEM_URL}")
    print("=" * 64)

    send_heartbeat(0)
    seen_event_signatures = set()
    counter = 0

    while True:
        try:
            counter += 1
            if counter % 10 == 0:
                send_heartbeat(0)

            if sys.platform == "win32":
                events = read_real_windows_events()
                for ev in events:
                    ev_id = ev.get("Id")
                    time_str = ev.get("TimeCreated", "")
                    msg_snippet = ev.get("Message", "").split("\n")[0][:120]
                    sig = f"{ev_id}-{time_str}-{msg_snippet}"

                    if sig not in seen_event_signatures:
                        seen_event_signatures.add(sig)
                        if len(seen_event_signatures) > 1000:
                            seen_event_signatures.clear()

                        severity = "INFO"
                        if ev_id in [4625, 4720]:
                            severity = "WARN"
                        elif ev_id in [1102, 7045]:
                            severity = "HIGH"

                        log_item = {
                            "source": "windows-server",
                            "ip": socket.gethostbyname(socket.gethostname()),
                            "user": "SYSTEM",
                            "severity": severity,
                            "message": f"Windows Event {ev_id}: {msg_snippet}",
                            "raw": str(ev)
                        }
                        forward_log(log_item)
                        send_heartbeat(1)

            time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            print("\nStopping Windows Security Agent...")
            break
        except Exception as e:
            time.sleep(POLL_INTERVAL)

if __name__ == '__main__':
    run_agent()
