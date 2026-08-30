#!/usr/bin/env python3
"""
SIEM-Lite RFC 3164 / 5424 UDP Syslog Shipper & Simulator
Sends standard UDP Syslog datagrams to SIEM-Lite Syslog port (1514) to test hardware firewalls,
routers, switches, and Linux rsyslog integration.
"""

import os
import sys
import time
import socket
import datetime

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    except Exception:
        pass

SYSLOG_HOST = "127.0.0.1"
SYSLOG_PORT = 1514

SAMPLE_SYSLOGS = [
    "<34>1 {timestamp} firewall-01 pfSense 1234 - - DROP TCP 198.51.100.23:44910 -> 192.168.1.1:22 (SSH Brute Force Attempt)",
    "<34>1 {timestamp} firewall-01 pfSense 1234 - - DROP TCP 198.51.100.23:44911 -> 192.168.1.1:22 (SSH Brute Force Attempt)",
    "<34>1 {timestamp} firewall-01 pfSense 1234 - - DROP TCP 198.51.100.23:44912 -> 192.168.1.1:22 (SSH Brute Force Attempt)",
    "<34>1 {timestamp} firewall-01 pfSense 1234 - - DROP TCP 198.51.100.23:44913 -> 192.168.1.1:22 (SSH Brute Force Attempt)",
    "<34>1 {timestamp} firewall-01 pfSense 1234 - - DROP TCP 198.51.100.23:44914 -> 192.168.1.1:22 (SSH Brute Force Attempt)",
    "<86>1 {timestamp} webgw-02 nginx - - - GET /search?q=1%27%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1 500",
    "<13>1 {timestamp} linux-node-03 sudo - - - pam_unix(sudo:auth): authentication failure; logname=analyst uid=1001 euid=0",
    "<134>1 {timestamp} edge-router cisco 891 - - %SEC-6-IPACCESSLOGP: list 101 denied tcp 45.33.32.156(58210) -> 192.168.1.50(3389), 1 packet",
]

def send_syslog():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("=" * 64)
    print(f"📡 Sending Syslog UDP Packets to {SYSLOG_HOST}:{SYSLOG_PORT}")
    print("=" * 64)

    for template in SAMPLE_SYSLOGS:
        ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        msg = template.replace("{timestamp}", ts)
        sock.sendto(msg.encode('utf-8'), (SYSLOG_HOST, SYSLOG_PORT))
        print(f"[UDP SENT] {msg}")
        time.sleep(1)

    print("\n[+] Syslog batch transmission completed successfully.")

if __name__ == '__main__':
    send_syslog()
