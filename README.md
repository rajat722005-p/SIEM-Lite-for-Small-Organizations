# SIEM-Lite for Small Organizations (Enterprise & Production Ready)

## 1. Project Overview

**SIEM-Lite** is a lightweight, real-world ready Security Information and Event Management (SIEM) and Security Operations Center (SOC) platform designed for small organizations, schools, clinics, and IT teams. It continuously collects security telemetry across Windows endpoints, Linux servers, edge firewalls/routers, and web applications, normalizes disparate log schemas, evaluates multi-vector threat detection rules 24/7 on the backend, persists events in a zero-configuration SQLite database, and presents live alerts and automated response actions via a modern browser-based SOC dashboard.

---

## 2. Key Capabilities & Production Features

- **Persistent Zero-Dependency Storage**: Built-in SQLite database (`server/siem_data.db`) storing logs, alerts, rules, agent fleet metadata, and firewall blocklists.
- **Multi-Source Ingestion Pipeline**:
  - **Integrated UDP Syslog Server (Port 1514 / RFC 3164 & 5424)** for firewalls, routers (pfSense, Cisco, MikroTik), switches, and Linux rsyslog.
  - **Native Windows Security Event Log Forwarder** (`collectors/windows_event_collector.py` & `collectors/windows_agent.ps1`) monitoring Event IDs `4625` (Failed Login), `4624` (Login Success), `4720` (User Created), `1102` (Audit Log Cleared), and `7045` (Service Installed).
  - **Universal Log File Tailer** (`collectors/file_tail_agent.py`) streaming Nginx `access.log`, Apache, or custom application logs.
  - **REST Ingestion API (`POST /api/logs`)** for webhooks, microservices, and cloud services.
- **Real-Time Streaming Engine**: Server-Sent Events (SSE) `/api/stream` streaming events directly to connected SOC dashboards with zero latency.
- **24/7 Backend Stateful Threat Correlation**: 10+ production rules mapping to the MITRE ATT&CK framework (SSH/Windows Brute Force, SQL Injection, Port Scanning, Path Traversal, Web Shell Execution, Audit Log Tampering, Rogue Account Creation, Vulnerability Scanners, Ransomware Detection).
- **Active Defense / 1-Click OS Firewall Blocking**: Block hostile IPs instantly via Windows Firewall (`netsh`) or Linux (`iptables`/`ufw`) directly from the SOC incident triage view.
- **Agent Fleet Management**: Real-time visibility into all connected collectors, heartbeats, and event ingestion rates.
- **Executive Audit & Compliance Reports**: Instant export of audited logs and incident histories in CSV and JSON formats with print-ready reports.
- **1-Click Windows Launcher**: Double-click `start_siem.bat` to boot the backend and launch the SOC dashboard in the browser automatically.

---

## 3. Architecture

```text
+---------------------------------------------------------------------------------------------------+
|                                          LOG SOURCES                                              |
|  [Windows Event Logs]   [Linux auth.log/syslog]   [Nginx/Apache]   [Firewall/Router Syslog UDP:1514] |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                                  SIEM-LITE BACKEND SERVER                                         |
|  - Multi-threaded HTTP REST Ingestion API (/api/logs)                                             |
|  - Integrated UDP Syslog Server (Port 1514)                                                       |
|  - SQLite Persistent Storage (logs, alerts, rules, agent heartbeats, blocked_ips)                |
|  - 24/7 Backend Stateful Correlation Engine (10+ real threat detection rules)                     |
|  - Server-Sent Events (SSE) Real-Time Stream (/api/stream)                                         |
|  - Active Defense / OS Firewall Automation (Windows Netsh / Linux UFW/iptables)                    |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                                   MODERN SOC DASHBOARD (FRONTEND)                                 |
|  - Real-Time Global Threat Meter & Telemetry Gauges                                               |
|  - Live SSE streaming log terminal with source & severity filters                                 |
|  - Incident Triage with 1-Click OS Firewall Blocking & Mitigation scripts                        |
|  - Agent Fleet & Collector Management View                                                        |
|  - Custom Correlation Rule Builder & Dynamic Manager                                              |
|  - Multi-Vector Cyber Attack Telemetry Console                                                    |
|  - Executive Audit Report Exporter (CSV, JSON, Print)                                             |
+---------------------------------------------------------------------------------------------------+
```

---

## 4. How to Run

### Quick Start (Windows 1-Click)
Double click `start_siem.bat` in the project root. It will:
1. Initialize the SQLite database.
2. Start the HTTP API server on `http://localhost:8000`.
3. Start the Syslog UDP listener on port `1514`.
4. Open the SOC Dashboard in your default browser.

### Manual Start (PowerShell / Terminal)
```powershell
python server/server.py
```
Open your browser at:
```text
http://localhost:8000
```

---

## 5. Deploying Real-World Collectors

### A. Windows Endpoints & Servers
Run the Python collector or native PowerShell script on any Windows machine:
```powershell
# Python Collector
python collectors/windows_event_collector.py

# Native PowerShell Collector
powershell -ExecutionPolicy Bypass -File .\collectors\windows_agent.ps1
```

### B. Linux & Hardware Routers / Firewalls (Syslog UDP)
Configure pfSense, Cisco, MikroTik, or Linux `/etc/rsyslog.conf` to forward to port `1514`:
```text
*.* @127.0.0.1:1514
```
To test Syslog forwarding locally:
```powershell
python collectors/syslog_forwarder.py
```

### C. Web Server & Application Log Tailer (Nginx / Apache)
```powershell
python collectors/file_tail_agent.py --file "C:\nginx\logs\access.log" --source "web-application"
```

### D. REST Ingestion API
Submit events directly from any application or script:
```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/logs -ContentType "application/json" -Body '{"source":"linux-server","ip":"185.220.101.4","user":"root","severity":"WARN","message":"Failed password for root from 185.220.101.4 port 45100 ssh2"}'
```

---

## 6. Threat Detection Rules

| Rule ID | Threat Rule | MITRE ATT&CK Category | Severity | Detection Condition |
| --- | --- | --- | --- | --- |
| `RULE-01` | SSH / Windows Auth Brute Force | Credential Access | **CRITICAL** | 5+ failed logins from same IP within 60 seconds |
| `RULE-02` | Web SQL Injection (SQLi) | Web Attack | **HIGH** | SQL injection syntax (`' OR 1=1`, `UNION SELECT`, `admin'--`) |
| `RULE-03` | Firewall Port Scan / Recon | Reconnaissance | **HIGH** | 10+ dropped ports probed by single IP within 30 seconds |
| `RULE-04` | Directory Traversal & LFI / RFI | Web Attack | **MEDIUM** | Traversal sequences (`../../etc/passwd`, `..\system32`) |
| `RULE-05` | Unauthorized Privilege Escalation | Privilege Escalation | **HIGH** | Unauthorized `sudo` attempts, shadow file tampering |
| `RULE-06` | Web Shell / Remote Command Execution | Execution | **CRITICAL** | Encoded PowerShell, `/bin/sh`, interactive shell scripts |
| `RULE-07` | Windows Audit Log Cleared | Defense Evasion | **CRITICAL** | Windows Event `1102` / `104` (Log cleared by attacker) |
| `RULE-08` | Rogue Account Creation | Persistence | **HIGH** | Windows Event `4720` (User account created) |
| `RULE-09` | Malicious Vulnerability Scanner | Reconnaissance | **MEDIUM** | Nikto, sqlmap, dirbuster user-agents / probing |
| `RULE-10` | Ransomware File Encryption | Impact | **CRITICAL** | Mass file rename to `.locked`, `.crypto` extensions |

---

## 7. REST API Endpoints

- `GET /api/status` - Health check, uptime, DB statistics, active agents, blocked IPs.
- `GET /api/stream` - Real-time Server-Sent Events (SSE) stream for live logs and alerts.
- `GET /api/logs` - Query historical logs (`limit`, `search`, `source`, `severity`).
- `POST /api/logs` - Ingest single log object or batch array of logs.
- `GET /api/alerts` - Query active and past security incidents.
- `POST /api/alerts/<id>/action` - Update alert status (`OPEN`, `BLOCKED`, `RESOLVED`).
- `POST /api/block-ip` - 1-Click active defense (triggers OS firewall rule).
- `GET /api/blocked-ips` - List active firewall blocks.
- `GET /api/agents` & `POST /api/agents/heartbeat` - Collector fleet registration & health monitoring.
- `GET /api/rules` & `POST /api/rules` - Query and add dynamic correlation rules.
- `GET /api/export` - Export logs or incidents to CSV / JSON format.
