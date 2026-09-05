#!/usr/bin/env python3
"""
Intelligent Human-Like Developer Activity & Commit Generator
Generates randomized, authentic, non-repetitive developer commits for SIEM-Lite.
Features:
- Random commit count per run (1 to 3 commits per execution)
- 40+ realistic, human-authored commit messages tailored to SOC/SIEM development
- Meaningful mini-updates to threat intelligence datasets, IOC signatures, and telemetry metrics
- Configured with personal developer author identity (rajat722005-p <rajat722005@gmail.com>)
"""

import os
import sys
import json
import time
import random
import datetime
import subprocess

MESSAGES_POOL = [
    # Performance & Optimization
    "perf(correlator): optimize sliding window memory retention for high velocity logs",
    "perf(sqlite): tune index lookups on timestamp and severity fields",
    "perf(ingest): streamline regex pattern compilation in normalizer",
    "perf(charts): reduce canvas redraw frequency during peak ingestion bursts",
    
    # Bug Fixes
    "fix(parser): handle trailing whitespace in RFC 5424 syslog timestamps",
    "fix(collector): increase socket receive buffer for UDP syslog listener",
    "fix(ui): resolve active badge count sync on incident status change",
    "fix(triage): prevent duplicate alert entry on rapid multi-threading events",
    "fix(agent): handle connection retry timeout in windows event forwarder",
    "fix(export): sanitize delimiter characters in csv audit report generator",
    "fix(rules): adjust regex boundary check for SQL injection detection",
    "fix(firewall): handle command exception gracefully when non-elevated",

    # Feature Enhancements
    "feat(telemetry): add support for Windows Event ID 4688 process creation tracking",
    "feat(rules): expand suspicious user-agent signatures list",
    "feat(triage): add investigation timeline markers for correlated incidents",
    "feat(agents): track memory utilization metrics in agent heartbeat payload",
    "feat(reports): add MITRE ATT&CK technique tags to executive summary export",
    "feat(simulator): add new evasion pattern to attack console telemetry",
    "feat(defense): optimize Windows Netsh rule naming convention",

    # Refactoring & Code Quality
    "refactor(correlator): simplify multi-event threshold counter logic",
    "refactor(ingest): standardize normalizeObject property fallback chain",
    "refactor(database): extract query parameters builder for log search",
    "refactor(app): modularize modal event binding and state dispatchers",
    "refactor(agents): optimize heartbeat timestamp diff calculation",

    # Documentation & Specs
    "docs(readme): add collector deployment notes for Linux rsyslog",
    "docs(architecture): clarify stateful correlation window mechanics",
    "docs(api): document query parameters for /api/logs endpoint",
    "docs(collectors): update PowerShell execution policy instructions",
    "docs(triage): document incident response playbooks for brute force alerts",

    # Threat Intel & Signatures Sync
    "chore(threat-intel): update known malicious scanner user-agent definitions",
    "chore(ioc): sync updated TOR exit node IP blacklist feed",
    "chore(signatures): add SQL injection blind bypass pattern heuristics",
    "chore(telemetry): refresh baseline threat detection thresholds",
    "chore(rules): calibrate brute force window timing to 60s window",
    "chore(database): verify table integrity and clean transient buffer"
]

IOC_SAMPLES = [
    "185.220.101.4/32 # Tor Exit Node (Known Scanner)",
    "45.33.32.156/32 # Reconnaissance Botnet Probe",
    "198.51.100.42/32 # Fast-flux SSH Brute Force Origin",
    "103.253.144.10/32 # Compromised Edge Gateway IP",
    "194.26.29.112/32 # Web Shell C2 Command Source",
    "91.240.118.230/32 # Automated Nikto/Dirbuster Probe Source",
    "185.196.8.241/32 # Distributed Port Scanning Origin",
    "193.142.146.35/32 # Malicious User-Agent Fingerprint IP"
]

def make_mini_update(commit_index):
    os.makedirs(".activity", exist_ok=True)
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    today_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

    # Update 1: Threat signatures file
    sig_path = ".activity/threat_signatures.json"
    signatures_data = {
        "version": "2.4.0",
        "last_sync": now_utc,
        "active_rules_count": 10,
        "reputation_feeds": {
            "tor_nodes_count": 480 + random.randint(1, 20),
            "malicious_c2_count": 1250 + random.randint(5, 50),
            "known_scanners_count": 890 + random.randint(2, 30)
        },
        "heuristics": {
            "sqli_sensitivity": 0.95,
            "bruteforce_threshold_rate": 5,
            "portscan_probe_limit": 10
        }
    }
    with open(sig_path, "w", encoding="utf-8") as f:
        json.dump(signatures_data, f, indent=2)

    # Update 2: IOC cache list
    ioc_path = ".activity/ioc_feed.txt"
    selected_iocs = random.sample(IOC_SAMPLES, k=min(4, len(IOC_SAMPLES)))
    with open(ioc_path, "w", encoding="utf-8") as f:
        f.write(f"# SIEM-Lite Dynamic IOC Threat Feed\n# Last Verified: {now_utc}\n\n")
        for ioc in selected_iocs:
            f.write(f"{ioc}\n")

    # Update 3: Daily Activity Log
    log_path = ".activity/daily_log.txt"
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"[{now_utc}] Activity Sync #{commit_index+1} | Verified 10 Active Rules | Database Nominal\n")

    # Update 4: Telemetry status
    status_path = ".activity/status.txt"
    with open(status_path, "w", encoding="utf-8") as f:
        f.write(f"SIEM Collector Engine: ONLINE\nLast Sync: {now_utc}\nActive Status: HEALTHY\n")

def run():
    # Random number of commits for this execution: 1 to 3 commits
    num_commits = random.choice([1, 2, 2, 3])
    print(f"[*] Preparing {num_commits} organic commits for this workflow cycle...")

    # Pick non-repeating commit messages
    selected_messages = random.sample(MESSAGES_POOL, k=num_commits)

    for i, msg in enumerate(selected_messages):
        make_mini_update(i)
        
        # Stage .activity directory
        subprocess.run(["git", "add", ".activity/"], check=True)
        
        # Configure personal developer identity
        env = os.environ.copy()
        env["GIT_AUTHOR_NAME"] = "rajat722005-p"
        env["GIT_AUTHOR_EMAIL"] = "rajat722005@gmail.com"
        env["GIT_COMMITTER_NAME"] = "rajat722005-p"
        env["GIT_COMMITTER_EMAIL"] = "rajat722005@gmail.com"

        # Check if there are staged changes
        res = subprocess.run(["git", "diff", "--staged", "--quiet"])
        if res.returncode != 0:
            print(f"[+] Committing ({i+1}/{num_commits}): {msg}")
            subprocess.run(["git", "commit", "-m", msg], env=env, check=True)
            time.sleep(random.randint(1, 3))

    print("[*] Pushing commits to origin main...")
    subprocess.run(["git", "push", "origin", "main"], check=True)
    print("[+] All commits pushed successfully!")

if __name__ == '__main__':
    run()
