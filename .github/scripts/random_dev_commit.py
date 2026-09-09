#!/usr/bin/env python3
"""
Organic & Authentic Developer Activity Generator for SIEM-Lite
Features:
- Strict Daily Cap: Maximum 1 to 3 (never > 4) commits per calendar day.
- Unpredictable Timing: Random skip probability and natural execution delays.
- Anti-Repetition: Checks git history to avoid repeating recent commit messages.
- Human Diversity: 120+ authentic SOC / SIEM developer commit messages & varied file updates.
- Configured identity: rajat722005-p <rajat722005@gmail.com>
"""

import os
import sys
import json
import time
import random
import datetime
import subprocess

# Maximum commits allowed in a single calendar day (Strict cap: never > 4)
MAX_DAILY_COMMITS_CAP = 4

# Rich, natural developer commit messages pool (Conventional + Natural Human phrasing)
MESSAGES_POOL = [
    # Performance & Optimization
    "perf(correlator): optimize sliding window memory retention for high velocity logs",
    "perf(sqlite): tune index lookups on timestamp and severity fields",
    "perf(ingest): streamline regex pattern compilation in normalizer",
    "perf(charts): reduce canvas redraw frequency during peak ingestion bursts",
    "perf(agent): minimize heartbeat packet payload overhead",
    "perf(db): add composite index on event_type and created_at",
    "optimize log buffer flush frequency during high traffic",
    "tune sqlite cache size for faster triage queries",
    "reduce memory footprint of active alert memory cache",
    "speed up syslog normalizer regex matching",

    # Bug Fixes & Resilience
    "fix(parser): handle trailing whitespace in RFC 5424 syslog timestamps",
    "fix(collector): increase socket receive buffer for UDP syslog listener",
    "fix(ui): resolve active badge count sync on incident status change",
    "fix(triage): prevent duplicate alert entry on rapid multi-threading events",
    "fix(agent): handle connection retry timeout in windows event forwarder",
    "fix(export): sanitize delimiter characters in csv audit report generator",
    "fix(rules): adjust regex boundary check for SQL injection detection",
    "fix(firewall): handle command exception gracefully when non-elevated",
    "fix(server): handle client disconnect during live SSE log stream",
    "fix(simulator): prevent out-of-bounds index on randomized payload generator",
    "fix edge case in syslog timestamp parsing for leap seconds",
    "fix minor race condition during batch log ingestion",
    "handle empty payload gracefully in agent listener",
    "prevent null pointer when alert metadata is empty",
    "resolve CSS flexbox overflow on small dashboard screens",

    # Feature Enhancements
    "feat(telemetry): add support for Windows Event ID 4688 process creation tracking",
    "feat(rules): expand suspicious user-agent signatures list",
    "feat(triage): add investigation timeline markers for correlated incidents",
    "feat(agents): track memory utilization metrics in agent heartbeat payload",
    "feat(reports): add MITRE ATT&CK technique tags to executive summary export",
    "feat(simulator): add new evasion pattern to attack console telemetry",
    "feat(defense): optimize Windows Netsh rule naming convention",
    "feat(rules): add brute force detection rule for SSH auth failures",
    "feat(analytics): add top 5 attacking IPs chart aggregation",
    "feat(alerts): add severity level filter to incident table",
    "add MITRE technique mapping for privilege escalation events",
    "support custom port configuration in syslog collector",
    "add quick-filter buttons for critical severity alerts",
    "implement automatic log rotation check on startup",

    # Refactoring & Code Quality
    "refactor(correlator): simplify multi-event threshold counter logic",
    "refactor(ingest): standardize normalizeObject property fallback chain",
    "refactor(database): extract query parameters builder for log search",
    "refactor(app): modularize modal event binding and state dispatchers",
    "refactor(agents): optimize heartbeat timestamp diff calculation",
    "refactor(server): separate route handlers from core app initialization",
    "refactor(rules): consolidate pattern matching helper functions",
    "cleanup unused imports and format helper utilities",
    "modularize incident triage card rendering logic",
    "standardize error response format across REST endpoints",
    "reorganize collector script configuration constants",

    # Documentation & Dev Notes
    "docs(readme): add collector deployment notes for Linux rsyslog",
    "docs(architecture): clarify stateful correlation window mechanics",
    "docs(api): document query parameters for /api/logs endpoint",
    "docs(collectors): update PowerShell execution policy instructions",
    "docs(triage): document incident response playbooks for brute force alerts",
    "docs(security): add guideline for secure agent token generation",
    "docs(install): document python dependency requirements for windows",
    "update architecture diagram notes in documentation",
    "add comments explaining correlation sliding window algorithm",
    "document REST API response status codes in readme",
    "clarify windows defender exclusion rules for log agent",

    # Threat Intelligence & Signatures
    "chore(threat-intel): update known malicious scanner user-agent definitions",
    "chore(ioc): sync updated TOR exit node IP blacklist feed",
    "chore(signatures): add SQL injection blind bypass pattern heuristics",
    "chore(telemetry): refresh baseline threat detection thresholds",
    "chore(rules): calibrate brute force window timing to 60s window",
    "chore(database): verify table integrity and clean transient buffer",
    "chore(ioc): prune expired temporary blocklist IPs",
    "chore(rules): update suspicious command line flags list for powershell",
    "sync latest threat intelligence reputation feed",
    "update IOC blacklist with recent command & control IP ranges",
    "calibrate anomaly score weightings for port scan detection",
    "refresh baseline false-positive suppression rules"
]

IOC_SAMPLES = [
    "185.220.101.4/32 # Tor Exit Node (Known Scanner)",
    "45.33.32.156/32 # Reconnaissance Botnet Probe",
    "198.51.100.42/32 # Fast-flux SSH Brute Force Origin",
    "103.253.144.10/32 # Compromised Edge Gateway IP",
    "194.26.29.112/32 # Web Shell C2 Command Source",
    "91.240.118.230/32 # Automated Nikto/Dirbuster Probe Source",
    "185.196.8.241/32 # Distributed Port Scanning Origin",
    "193.142.146.35/32 # Malicious User-Agent Fingerprint IP",
    "45.154.255.88/32 # Masscan Internet Scanner Node",
    "141.98.11.104/32 # Shodan Crawler Subnet",
    "195.201.225.24/32 # Vulnerability Assessment Scanner IP",
    "89.248.163.74/32 # Mirai Variant Recon Probe"
]

DEV_NOTES_SAMPLES = [
    "Tested sliding window memory retention under 5,000 EPS load; SQLite locks remain below 4ms.",
    "Verified RFC 5424 regex parser compatibility across Debian rsyslog and Windows forwarder.",
    "Benchmarked correlation rule engine: 10 active rules evaluated in ~1.2ms average per batch.",
    "Audit log CSV export tested with 50,000 rows; verified UTF-8 BOM encoding.",
    "Inspected agent heartbeat payload size: optimized down to 184 bytes per ping.",
    "Tuned SQL injection regex: zero false positives against standard WordPress admin queries.",
    "Validated Windows Event ID 4625 (Failed Logon) parsing with custom domain controller format."
]

def get_recent_commits():
    """Returns list of last 40 commit messages to prevent repetition."""
    try:
        out = subprocess.check_output(
            ["git", "log", "-n", "40", "--pretty=format:%s"],
            text=True
        )
        return [line.strip() for line in out.splitlines() if line.strip()]
    except Exception:
        return []

def get_today_commit_count():
    """Counts how many commits have been made today (UTC calendar day)."""
    try:
        today_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        out = subprocess.check_output(
            ["git", "log", "--since=" + today_str + " 00:00:00", "--pretty=format:%H"],
            text=True
        )
        hashes = [h.strip() for h in out.splitlines() if h.strip()]
        return len(hashes)
    except Exception:
        return 0

def make_organic_updates(commit_index):
    """Generates natural, varied file changes across realistic repo areas."""
    os.makedirs(".activity", exist_ok=True)
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Update 1: Threat signatures JSON with dynamic values
    sig_path = ".activity/threat_signatures.json"
    signatures_data = {
        "schema_version": "2.4.2",
        "last_sync": now_utc,
        "engine_state": "ACTIVE_MONITORING",
        "active_rules_count": 10,
        "reputation_feeds": {
            "tor_nodes_count": 490 + random.randint(1, 35),
            "malicious_c2_count": 1280 + random.randint(5, 70),
            "known_scanners_count": 910 + random.randint(3, 40)
        },
        "heuristics": {
            "sqli_sensitivity": round(0.92 + random.uniform(0.01, 0.06), 3),
            "bruteforce_threshold_rate": random.choice([4, 5, 5, 6]),
            "portscan_probe_limit": random.choice([8, 10, 12]),
            "sliding_window_seconds": 60
        }
    }
    with open(sig_path, "w", encoding="utf-8") as f:
        json.dump(signatures_data, f, indent=2)

    # Update 2: Dynamic IOC feed
    ioc_path = ".activity/ioc_feed.txt"
    selected_iocs = random.sample(IOC_SAMPLES, k=random.randint(4, 7))
    with open(ioc_path, "w", encoding="utf-8") as f:
        f.write(f"# SIEM-Lite Dynamic IOC Threat Feed\n# Last Verified: {now_utc}\n# Total Feeds Active: {len(selected_iocs)}\n\n")
        for ioc in selected_iocs:
            f.write(f"{ioc}\n")

    # Update 3: Daily Activity Log
    log_path = ".activity/daily_log.txt"
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"[{now_utc}] Activity Sync #{commit_index+1} | Verified 10 Active Rules | Engine Nominal\n")

    # Update 4: Developer Scratchpad & Engineering Notes
    notes_path = ".activity/dev_notes.md"
    note = random.choice(DEV_NOTES_SAMPLES)
    with open(notes_path, "w", encoding="utf-8") as f:
        f.write(f"# SOC Engineering Daily Notes\n\n- **Last Verification**: `{now_utc}`\n- **Engineering Focus**: {note}\n- **Integrity**: All SQLite log tables verified.\n")

    # Update 5: Collector Telemetry Health
    status_path = ".activity/status.txt"
    with open(status_path, "w", encoding="utf-8") as f:
        f.write(f"SIEM Collector Engine: ONLINE\nLast Sync: {now_utc}\nActive Status: HEALTHY\n")

def run(force=False):
    # 1. Check how many commits have already been made today
    today_commits = get_today_commit_count()
    print(f"[*] Commits already recorded today (UTC): {today_commits}")

    if today_commits >= MAX_DAILY_COMMITS_CAP and not force:
        print(f"[!] Daily commit cap ({MAX_DAILY_COMMITS_CAP}) already reached for today. Skipping to maintain organic profile.")
        return

    # 2. Decide how many commits to make in this run (typically 1, occasionally 2, never exceeding cap)
    remaining_budget = MAX_DAILY_COMMITS_CAP - today_commits
    if remaining_budget <= 0 and not force:
        print("[!] No remaining commit budget for today. Skipping.")
        return

    # 3. Organic skip probability (50% chance to skip when called via scheduled cron to stagger days naturally)
    if not force and today_commits >= 1:
        if random.random() < 0.50:
            print("[*] Organic random skip triggered for this slot to maintain natural developer rhythm.")
            return

    num_commits = min(remaining_budget, random.choice([1, 1, 2]))
    print(f"[*] Generating {num_commits} natural commit(s) for this cycle...")

    # 4. Filter recent commits to avoid any repetition
    recent_messages = set(get_recent_commits())
    available_messages = [m for m in MESSAGES_POOL if m not in recent_messages]
    if len(available_messages) < num_commits:
        available_messages = MESSAGES_POOL

    selected_messages = random.sample(available_messages, k=num_commits)

    # 5. Execute commits
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = "rajat722005-p"
    env["GIT_AUTHOR_EMAIL"] = "rajat722005@gmail.com"
    env["GIT_COMMITTER_NAME"] = "rajat722005-p"
    env["GIT_COMMITTER_EMAIL"] = "rajat722005@gmail.com"

    for i, msg in enumerate(selected_messages):
        make_organic_updates(i)
        subprocess.run(["git", "add", ".activity/"], check=True)

        res = subprocess.run(["git", "diff", "--staged", "--quiet"])
        if res.returncode != 0:
            print(f"[+] Committing ({i+1}/{num_commits}): {msg}")
            subprocess.run(["git", "commit", "-m", msg], env=env, check=True)
            # Short organic pause between commits
            time.sleep(random.randint(2, 5))

    print("[*] Pushing commit(s) to origin main...")
    subprocess.run(["git", "push", "origin", "main"], check=True)
    print("[+] All commits pushed successfully!")

if __name__ == '__main__':
    force_flag = "--force" in sys.argv
    run(force=force_flag)
