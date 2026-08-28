#!/usr/bin/env python3
"""
SIEM-Lite Enterprise & Production-Ready Security Operations Server
Features:
- SQLite Persistent Storage (logs, alerts, rules, agents, blocked_ips)
- Multi-threaded REST Ingestion API (/api/logs)
- Real-Time Server-Sent Events (SSE) Streaming (/api/stream)
- Integrated RFC 3164 / 5424 UDP Syslog Server (Port 1514)
- Server-Side Stateful Threat Correlation Engine (24/7 Threat Detection)
- OS-Level Active Firewall Response (Windows Netsh / Linux UFW/iptables)
- Agent Fleet Heartbeat & Registration (/api/agents)
- Export Endpoints (JSON / CSV)
"""

import os
import sys
import json
import time
import socket
import sqlite3
import threading
import subprocess
import urllib.parse
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn

# Safe UTF-8 encoding on Windows console
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
        sys.stderr.reconfigure(encoding='utf-8', errors='backslashreplace')
    except Exception:
        pass

PORT = 8000
SYSLOG_UDP_PORT = 1514
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "siem_data.db")

# In-memory subscriber queues for Server-Sent Events (SSE)
SSE_CLIENTS = []
SSE_LOCK = threading.Lock()

# -----------------------------------------------------------------------------
# Database Setup & Persistence Engine
# -----------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    conn = get_db()
    cursor = conn.cursor()

    # Logs Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id TEXT UNIQUE,
            timestamp TEXT,
            source TEXT,
            ip TEXT,
            user TEXT,
            severity TEXT,
            message TEXT,
            raw TEXT
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(ip)")

    # Alerts / Incidents Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT UNIQUE,
            timestamp TEXT,
            rule_id TEXT,
            title TEXT,
            severity TEXT,
            category TEXT,
            attacker_ip TEXT,
            target_host TEXT,
            event_count INTEGER,
            details TEXT,
            mitigation TEXT,
            status TEXT DEFAULT 'OPEN'
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")

    # Correlation Rules Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            rule_id TEXT PRIMARY KEY,
            name TEXT,
            category TEXT,
            severity TEXT,
            enabled INTEGER DEFAULT 1,
            threshold INTEGER,
            time_window_sec INTEGER,
            pattern TEXT,
            description TEXT,
            mitigation TEXT
        )
    """)

    # Agents / Collectors Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            name TEXT,
            type TEXT,
            hostname TEXT,
            ip_address TEXT,
            os TEXT,
            status TEXT DEFAULT 'ONLINE',
            total_logs INTEGER DEFAULT 0,
            last_heartbeat TEXT
        )
    """)

    # Blocked IPs (Active Defense) Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            reason TEXT,
            blocked_at TEXT,
            blocked_by TEXT,
            firewall_rule_name TEXT
        )
    """)

    # Populate Default Production Rules if Empty
    cursor.execute("SELECT COUNT(*) FROM rules")
    if cursor.fetchone()[0] == 0:
        default_rules = [
            ('RULE-01', 'SSH / Windows Auth Brute Force', 'Credential Access', 'CRITICAL', 1, 5, 60,
             'failed password,authentication failure,invalid user,4625,failed logon',
             'Detects 5+ failed login attempts from single IP within 60 seconds.',
             'Block Attacker IP at Firewall & Reset User Password.'),
            ('RULE-02', 'Web SQL Injection (SQLi)', 'Web Attack', 'HIGH', 1, 1, 0,
             "' or 1=1,union select,select * from,drop table,sleep(,benchmark(,or '1'='1,admin'--",
             'Detects malicious SQL injection syntax patterns in HTTP queries or payloads.',
             'Enable WAF Rule, Sanitize Parameters & Block IP.'),
            ('RULE-03', 'Firewall Port Scan / Reconnaissance', 'Reconnaissance', 'HIGH', 1, 10, 30,
             'connection dropped,port scan,tcp block,rst sent,syn flood',
             'Detects single IP probing 10+ distinct ports within 30 seconds.',
             'Blacklist Attacker IP on Gateway Firewall.'),
            ('RULE-04', 'Directory Traversal & LFI / RFI', 'Web Attack', 'MEDIUM', 1, 1, 0,
             '../etc/passwd,..\\windows\\system32,php://filter,boot.ini,/proc/self/environ',
             'Detects path traversal and unauthorized system file access attempts.',
             'Block URI Path & Update Web Application Routing Rules.'),
            ('RULE-05', 'Unauthorized Privilege Escalation / Sudo', 'Privilege Escalation', 'HIGH', 1, 1, 0,
             'sudo: 3 incorrect password attempts,unauthorized root access,sudoers modified,mimikatz,privilege escalation',
             'Detects unauthorized sudo executions, shadow file access, or memory privilege dumping.',
             'Isolate Compromised Host & Audit User Account Permissions.'),
            ('RULE-06', 'Web Shell / Remote Command Execution', 'Execution', 'CRITICAL', 1, 1, 0,
             'cmd.exe,/bin/sh,/bin/bash,powershell -enc,whoami,curl http,wget http,c99shell,r57shell',
             'Detects command injection, interactive web shells, or encoded PowerShell commands.',
             'Terminate Malicious Process & Quarantine Host Interface.'),
            ('RULE-07', 'Windows Security Audit Log Cleared (Event 1102 / 104)', 'Defense Evasion', 'CRITICAL', 1, 1, 0,
             '1102,the audit log was cleared,104,log file was cleared,wevtutil cl',
             'Detects tampering with Windows Security / System Event Logs.',
             'Immediate Incident Response & Forensic Image Capture.'),
            ('RULE-08', 'Suspicious Account Creation / Persistence (Event 4720)', 'Persistence', 'HIGH', 1, 1, 0,
             '4720,a user account was created,useradd,net user /add',
             'Detects unexpected or unauthorized user account creation.',
             'Verify Account Authenticity & Disable Rogue Account.'),
            ('RULE-09', 'Malicious Vulnerability Scanner / Bot Traffic', 'Reconnaissance', 'MEDIUM', 1, 3, 10,
             'nikto,sqlmap,nmap scripting engine,dirbuster,gobuster,masscan,zgrab',
             'Detects automated cyber reconnaissance scanning tools.',
             'Block Scanner User-Agent & IP Subnet.'),
            ('RULE-10', 'Ransomware File Encryption Extension Pattern', 'Impact', 'CRITICAL', 1, 1, 0,
             '.locked,.crypto,.enc,.lockbit,.blackcat,.wannacry,mass file rename',
             'Detects known ransomware file extension patterns or bulk encryption attempts.',
             'Instantly Disconnect Network Cable & Initiate Ransomware Isolation.')
        ]
        cursor.executemany("""
            INSERT INTO rules (rule_id, name, category, severity, enabled, threshold, time_window_sec, pattern, description, mitigation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, default_rules)

    conn.commit()
    conn.close()

# -----------------------------------------------------------------------------
# Server-Side Stateful Threat Correlation Engine
# -----------------------------------------------------------------------------
class ServerCorrelationEngine:
    def __init__(self):
        self.ip_window = {}  # (rule_id, ip) -> list of timestamp floats
        self.port_window = {} # ip -> set of ports
        self.lock = threading.Lock()

    def evaluate(self, log_dict):
        alerts_generated = []
        now = time.time()
        msg = (log_dict.get("message", "") + " " + log_dict.get("raw", "")).lower()
        ip = log_dict.get("ip", "127.0.0.1")
        source = log_dict.get("source", "endpoint")

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM rules WHERE enabled = 1")
        active_rules = cursor.fetchall()

        with self.lock:
            for rule in active_rules:
                rule_id = rule["rule_id"]
                patterns = [p.strip().lower() for p in rule["pattern"].split(",") if p.strip()]
                matched_pattern = any(p in msg for p in patterns)

                if not matched_pattern:
                    continue

                threshold = rule["threshold"] or 1
                time_window = rule["time_window_sec"] or 0

                # Single-occurrence trigger (threshold <= 1)
                if threshold <= 1:
                    alert = self._create_alert(conn, rule, ip, source, 1, log_dict)
                    alerts_generated.append(alert)
                    continue

                # Multi-occurrence sliding window trigger (e.g. Brute force, Port scan)
                key = (rule_id, ip)
                timestamps = self.ip_window.get(key, [])
                # Filter out expired timestamps
                timestamps = [ts for ts in timestamps if now - ts <= time_window]
                timestamps.append(now)
                self.ip_window[key] = timestamps

                if len(timestamps) >= threshold:
                    # Reset window after triggering
                    self.ip_window[key] = []
                    alert = self._create_alert(conn, rule, ip, source, len(timestamps), log_dict)
                    alerts_generated.append(alert)

        conn.commit()
        conn.close()
        return alerts_generated

    def _create_alert(self, conn, rule, attacker_ip, target_host, count, log_dict):
        alert_id = f"ALT-{int(time.time()*1000)%1000000:06d}"
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        title = rule["name"]
        severity = rule["severity"]
        category = rule["category"]
        details = f"{rule['description']} Detected from {attacker_ip} targeting {target_host}. Event trigger: {log_dict.get('message')}"
        mitigation = rule["mitigation"]

        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts (alert_id, timestamp, rule_id, title, severity, category, attacker_ip, target_host, event_count, details, mitigation, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN')
        """, (alert_id, timestamp, rule["rule_id"], title, severity, category, attacker_ip, target_host, count, details, mitigation))

        alert_data = {
            "id": alert_id,
            "alert_id": alert_id,
            "timestamp": timestamp,
            "ruleId": rule["rule_id"],
            "title": title,
            "severity": severity,
            "category": category,
            "attackerIp": attacker_ip,
            "targetHost": target_host,
            "eventCount": count,
            "details": details,
            "mitigation": mitigation,
            "status": "OPEN",
            "log": log_dict
        }
        print(f"\n🚨 [SIEM ALERT TRIGGERED] [{severity}] {title} | Attacker: {attacker_ip} -> Target: {target_host}")
        return alert_data

CORRELATION_ENGINE = ServerCorrelationEngine()

# -----------------------------------------------------------------------------
# Active Defense / OS Firewall Automation
# -----------------------------------------------------------------------------
def block_ip_firewall(ip, reason="SIEM Incident Mitigation"):
    blocked_at = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    rule_name = f"SIEM_BLOCK_{ip.replace(':', '_').replace('.', '_')}"
    executed = False
    details = ""

    # Platform specific firewall execution
    if sys.platform == "win32":
        cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            executed = res.returncode == 0
            details = f"Windows Firewall rule '{rule_name}' applied. Output: {res.stdout.strip() or res.stderr.strip()}"
        except Exception as e:
            details = f"Windows Firewall execution notice: {e}"
    else:
        cmd = f"iptables -A INPUT -s {ip} -j DROP"
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            executed = res.returncode == 0
            details = f"Linux iptables DROP rule applied for {ip}."
        except Exception as e:
            details = f"Linux Firewall execution notice: {e}"

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at, blocked_by, firewall_rule_name)
        VALUES (?, ?, ?, ?, ?)
    """, (ip, reason, blocked_at, "SOC Analyst (SIEM-Lite)", rule_name))
    conn.commit()
    conn.close()

    print(f"[🛡️ ACTIVE DEFENSE] Blocked IP: {ip} | Rule: {rule_name} | {details}")
    return {"status": "success", "ip": ip, "rule_name": rule_name, "executed": executed, "details": details}

# -----------------------------------------------------------------------------
# Real-Time SSE Broadcasting
# -----------------------------------------------------------------------------
def broadcast_sse(event_type, data):
    payload = f"event: {event_type}\ndata: {json.dumps(data)}\n\n".encode('utf-8')
    with SSE_LOCK:
        dead_clients = []
        for client in SSE_CLIENTS:
            try:
                client.wfile.write(payload)
                client.wfile.flush()
            except Exception:
                dead_clients.append(client)
        for client in dead_clients:
            if client in SSE_CLIENTS:
                SSE_CLIENTS.remove(client)

# -----------------------------------------------------------------------------
# Core Ingestion Processing
# -----------------------------------------------------------------------------
def process_incoming_log(raw_dict):
    log_id = raw_dict.get("id") or f"LOG-{int(time.time()*1000)%10000000:07d}"
    timestamp = raw_dict.get("timestamp") or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    source = raw_dict.get("source") or "endpoint"
    ip = raw_dict.get("ip") or raw_dict.get("source_ip") or "192.168.1.100"
    user = raw_dict.get("user") or "system"
    severity = (raw_dict.get("severity") or "INFO").upper()
    message = raw_dict.get("message") or raw_dict.get("raw") or json.dumps(raw_dict)
    raw = raw_dict.get("raw") or message

    normalized = {
        "id": log_id,
        "log_id": log_id,
        "timestamp": timestamp,
        "source": source,
        "ip": ip,
        "user": user,
        "severity": severity,
        "message": message,
        "raw": raw
    }

    # Save to SQLite Database
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO logs (log_id, timestamp, source, ip, user, severity, message, raw)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (log_id, timestamp, source, ip, user, severity, message, raw))
    conn.commit()
    conn.close()

    # Evaluate Server-Side Threat Detection Rules
    alerts = CORRELATION_ENGINE.evaluate(normalized)

    # Broadcast to Connected Web SOC Dashboards
    broadcast_sse("log", normalized)
    for alert in alerts:
        broadcast_sse("alert", alert)

    return normalized, alerts

# -----------------------------------------------------------------------------
# UDP Syslog Listener (Port 1514 / RFC 3164 / 5424)
# -----------------------------------------------------------------------------
def syslog_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('0.0.0.0', SYSLOG_UDP_PORT))
        print(f"[+] Syslog UDP Ingestion Server listening on 0.0.0.0:{SYSLOG_UDP_PORT}")
    except Exception as e:
        print(f"[!] Warning: Could not bind UDP Syslog port {SYSLOG_UDP_PORT}: {e}")
        return

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            raw_msg = data.decode('utf-8', errors='ignore')
            ip = addr[0]

            # Parse Syslog format
            severity = "INFO"
            if any(w in raw_msg.lower() for w in ['fail', 'drop', 'denied', 'error', 'attack', 'invalid', 'warn']):
                severity = "WARN"
            if any(w in raw_msg.lower() for w in ['crit', 'alert', 'emerg', 'fatal', 'sql', 'injection']):
                severity = "HIGH"

            log_item = {
                "source": "syslog-network",
                "ip": ip,
                "user": "network-device",
                "severity": severity,
                "message": raw_msg.strip(),
                "raw": raw_msg
            }
            process_incoming_log(log_item)
        except Exception as e:
            time.sleep(0.1)

# -----------------------------------------------------------------------------
# HTTP Request Handler & REST API
# -----------------------------------------------------------------------------
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class SIEMRequestHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        # Clean console output
        pass

    def _send_json(self, status_code, data):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_POST(self):
        url_parts = urllib.parse.urlparse(self.path)
        path = url_parts.path

        # 1. Log Ingestion Endpoint
        if path == '/api/logs':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                body = json.loads(post_data.decode('utf-8'))
            except Exception:
                body = {"raw": post_data.decode('utf-8', errors='ignore'), "source": "raw-http"}

            ingested_logs = []
            generated_alerts = []

            if isinstance(body, list):
                for item in body:
                    norm, alerts = process_incoming_log(item)
                    ingested_logs.append(norm)
                    generated_alerts.extend(alerts)
            else:
                norm, alerts = process_incoming_log(body)
                ingested_logs.append(norm)
                generated_alerts.extend(alerts)

            self._send_json(200, {
                "status": "success",
                "ingested": len(ingested_logs),
                "alerts_triggered": len(generated_alerts)
            })
            return

        # 2. Agent Heartbeat / Registration Endpoint
        if path == '/api/agents/heartbeat':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                agent_data = json.loads(post_data.decode('utf-8'))
            except Exception:
                agent_data = {}

            agent_id = agent_data.get("agent_id") or f"AGT-{agent_data.get('hostname', 'unknown')}"
            name = agent_data.get("name") or agent_id
            agent_type = agent_data.get("type") or "Windows Collector"
            hostname = agent_data.get("hostname") or "localhost"
            ip_address = agent_data.get("ip_address") or self.client_address[0]
            agent_os = agent_data.get("os") or sys.platform
            now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO agents (agent_id, name, type, hostname, ip_address, os, status, total_logs, last_heartbeat)
                VALUES (?, ?, ?, ?, ?, ?, 'ONLINE', COALESCE((SELECT total_logs FROM agents WHERE agent_id = ?), 0) + ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    status = 'ONLINE',
                    ip_address = excluded.ip_address,
                    total_logs = agents.total_logs + excluded.total_logs,
                    last_heartbeat = excluded.last_heartbeat
            """, (agent_id, name, agent_type, hostname, ip_address, agent_os, agent_id, agent_data.get("events_sent", 1), now_iso))
            conn.commit()
            conn.close()

            self._send_json(200, {"status": "success", "agent_id": agent_id, "heartbeat": now_iso})
            return

        # 3. Active Defense / Firewall Block Endpoint
        if path == '/api/block-ip':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                payload = json.loads(post_data.decode('utf-8'))
            except Exception:
                payload = {}

            ip = payload.get("ip")
            reason = payload.get("reason", "Incident Triage Action")
            if not ip:
                self._send_json(400, {"status": "error", "message": "Missing 'ip' parameter"})
                return

            result = block_ip_firewall(ip, reason)
            self._send_json(200, result)
            return

        # 4. Update Alert Status Endpoint (/api/alerts/<id>/action)
        if path.startswith('/api/alerts/') and path.endswith('/action'):
            alert_id = path.split('/')[3]
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                payload = json.loads(post_data.decode('utf-8'))
            except Exception:
                payload = {}

            new_status = payload.get("status", "RESOLVED")
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("UPDATE alerts SET status = ? WHERE alert_id = ? OR id = ?", (new_status, alert_id, alert_id))
            conn.commit()
            conn.close()

            self._send_json(200, {"status": "success", "alert_id": alert_id, "new_status": new_status})
            return

        # 5. Add / Toggle Correlation Rule Endpoint
        if path == '/api/rules':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                rule_data = json.loads(post_data.decode('utf-8'))
            except Exception:
                rule_data = {}

            rule_id = rule_data.get("rule_id") or f"RULE-{int(time.time()*1000)%10000:04d}"
            name = rule_data.get("name", "Custom Rule")
            category = rule_data.get("category", "Custom Detection")
            severity = rule_data.get("severity", "HIGH")
            enabled = 1 if rule_data.get("enabled", True) else 0
            threshold = int(rule_data.get("threshold", 1))
            time_window = int(rule_data.get("time_window_sec", 60))
            pattern = rule_data.get("pattern", "")
            description = rule_data.get("description", "")
            mitigation = rule_data.get("mitigation", "Block Attacker IP")

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO rules (rule_id, name, category, severity, enabled, threshold, time_window_sec, pattern, description, mitigation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (rule_id, name, category, severity, enabled, threshold, time_window, pattern, description, mitigation))
            conn.commit()
            conn.close()

            self._send_json(200, {"status": "success", "rule_id": rule_id})
            return

        self.send_error(404, "Endpoint not found")

    def do_GET(self):
        url_parts = urllib.parse.urlparse(self.path)
        path = url_parts.path
        query = urllib.parse.parse_qs(url_parts.query)

        # 1. Server-Sent Events (SSE) Real-time Stream
        if path == '/api/stream':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            with SSE_LOCK:
                SSE_CLIENTS.append(self)

            # Send initial keepalive & status
            init_msg = f"event: connected\ndata: {json.dumps({'status': 'connected', 'timestamp': time.time()})}\n\n"
            self.wfile.write(init_msg.encode('utf-8'))
            self.wfile.flush()

            try:
                while True:
                    time.sleep(15)
                    # Ping keep-alive
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
            except Exception:
                pass
            finally:
                with SSE_LOCK:
                    if self in SSE_CLIENTS:
                        SSE_CLIENTS.remove(self)
            return

        # 2. Query Logs Endpoint
        if path == '/api/logs':
            limit = int(query.get('limit', ['200'])[0])
            offset = int(query.get('offset', ['0'])[0])
            search = query.get('search', [''])[0]
            source = query.get('source', ['ALL'])[0]
            severity = query.get('severity', ['ALL'])[0]

            sql = "SELECT * FROM logs WHERE 1=1"
            params = []

            if search:
                sql += " AND (message LIKE ? OR ip LIKE ? OR user LIKE ?)"
                search_param = f"%{search}%"
                params.extend([search_param, search_param, search_param])
            if source != 'ALL':
                sql += " AND source = ?"
                params.append(source)
            if severity != 'ALL':
                sql += " AND severity = ?"
                params.append(severity)

            sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(sql, params)
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()

            self._send_json(200, rows)
            return

        # 3. Query Alerts / Incidents Endpoint
        if path == '/api/alerts':
            status = query.get('status', ['ALL'])[0]
            sql = "SELECT * FROM alerts WHERE 1=1"
            params = []
            if status != 'ALL':
                sql += " AND status = ?"
                params.append(status)
            sql += " ORDER BY id DESC LIMIT 100"

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(sql, params)
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()

            # Map database columns to frontend camelCase expectations
            formatted = []
            for r in rows:
                formatted.append({
                    "id": r["alert_id"],
                    "alert_id": r["alert_id"],
                    "timestamp": r["timestamp"],
                    "ruleId": r["rule_id"],
                    "title": r["title"],
                    "severity": r["severity"],
                    "category": r["category"],
                    "attackerIp": r["attacker_ip"],
                    "targetHost": r["target_host"],
                    "eventCount": r["event_count"],
                    "details": r["details"],
                    "mitigation": r["mitigation"],
                    "status": r["status"]
                })

            self._send_json(200, formatted)
            return

        # 4. Query Rules Endpoint
        if path == '/api/rules':
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM rules ORDER BY rule_id ASC")
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            
            rules_formatted = []
            for r in rows:
                rules_formatted.append({
                    "id": r["rule_id"],
                    "name": r["name"],
                    "category": r["category"],
                    "severity": r["severity"],
                    "enabled": bool(r["enabled"]),
                    "threshold": r["threshold"],
                    "timeWindowSec": r["time_window_sec"],
                    "pattern": r["pattern"],
                    "description": r["description"],
                    "mitigation": r["mitigation"]
                })
            self._send_json(200, rules_formatted)
            return

        # 5. Query Agents Endpoint
        if path == '/api/agents':
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM agents ORDER BY last_heartbeat DESC")
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            self._send_json(200, rows)
            return

        # 6. Query Blocked IPs Endpoint
        if path == '/api/blocked-ips':
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM blocked_ips ORDER BY id DESC")
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            self._send_json(200, rows)
            return

        # 7. System Status & Health Metrics Endpoint
        if path == '/api/status':
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM logs")
            total_logs = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'OPEN'")
            open_alerts = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM agents")
            total_agents = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM blocked_ips")
            total_blocked = cursor.fetchone()[0]
            conn.close()

            status = {
                "status": "ONLINE",
                "version": "2.0.0-PROD",
                "collector": "SIEM-Lite Real-Time Collector & Correlation Engine",
                "database": "SQLite (Persistent)",
                "total_logs": total_logs,
                "total_alerts": total_alerts,
                "open_alerts": open_alerts,
                "active_agents": total_agents,
                "blocked_ips": total_blocked,
                "syslog_port": SYSLOG_UDP_PORT,
                "sse_clients": len(SSE_CLIENTS),
                "uptime_seconds": time.time()
            }
            self._send_json(200, status)
            return

        # 8. Data Export Endpoint (CSV / JSON)
        if path == '/api/export':
            export_format = query.get('format', ['json'])[0].lower()
            data_type = query.get('type', ['alerts'])[0].lower()

            conn = get_db()
            cursor = conn.cursor()
            if data_type == 'logs':
                cursor.execute("SELECT log_id, timestamp, source, ip, user, severity, message FROM logs ORDER BY id DESC LIMIT 5000")
            else:
                cursor.execute("SELECT alert_id, timestamp, rule_id, title, severity, category, attacker_ip, target_host, details, status FROM alerts ORDER BY id DESC")
            
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()

            if export_format == 'csv':
                if not rows:
                    csv_data = "No data available"
                else:
                    headers = list(rows[0].keys())
                    lines = [",".join(headers)]
                    for r in rows:
                        row_vals = [f'"{str(r[h]).replace(chr(34), chr(34)+chr(34))}"' for h in headers]
                        lines.append(",".join(row_vals))
                    csv_data = "\n".join(lines)

                self.send_response(200)
                self.send_header('Content-Type', 'text/csv')
                self.send_header('Content-Disposition', f'attachment; filename="siem_{data_type}_export.csv"')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(csv_data.encode('utf-8'))
                return
            else:
                self._send_json(200, rows)
                return

        # Static Frontend File Serving
        return super().do_GET()

def run_server():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(root_dir)

    # Initialize SQLite Database
    init_database()

    # Start Background Syslog UDP listener thread
    syslog_thread = threading.Thread(target=syslog_listener, daemon=True)
    syslog_thread.start()

    server = ThreadedHTTPServer(('0.0.0.0', PORT), SIEMRequestHandler)
    print("=" * 68)
    print("🛡️  SIEM-Lite Enterprise Security Operations & Ingestion Engine")
    print("=" * 68)
    print(f"[+] SOC Dashboard Web UI:      http://localhost:{PORT}")
    print(f"[+] REST Log Ingestion API:    http://localhost:{PORT}/api/logs")
    print(f"[+] Server-Sent Events (SSE):  http://localhost:{PORT}/api/stream")
    print(f"[+] Syslog UDP Listener:       0.0.0.0:{SYSLOG_UDP_PORT}")
    print(f"[+] Persistent SQLite Database: {DB_FILE}")
    print("=" * 68)
    print("[+] Status: ONLINE & Ready for real-world logs and attack telemetry.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping SIEM-Lite Server...")
        server.server_close()

if __name__ == '__main__':
    run_server()
