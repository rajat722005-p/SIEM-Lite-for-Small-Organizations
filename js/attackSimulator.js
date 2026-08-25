/**
 * SIEM-Lite Enterprise Cyber Attack Simulator Module
 * Generates realistic attack telemetry and pushes directly into the ingestion pipeline.
 */

class AttackSimulator {
  constructor(logIngestor) {
    this.logIngestor = logIngestor;
    this.isAutoTrafficEnabled = false;
    this.timer = null;

    // Known hostile threat actor IPs
    this.attackerIPs = [
      '185.220.101.4',
      '45.33.32.156',
      '198.51.100.42',
      '103.253.144.10',
      '194.26.29.112',
      '91.240.118.230'
    ];
  }

  startBackgroundTraffic(intervalMs = 3000) {
    if (this.isAutoTrafficEnabled) return;
    this.isAutoTrafficEnabled = true;

    this.timer = setInterval(() => {
      this.generateBenignLog();
    }, intervalMs);
  }

  stopBackgroundTraffic() {
    this.isAutoTrafficEnabled = false;
    if (this.timer) clearInterval(this.timer);
  }

  generateBenignLog() {
    const benignLogs = [
      { source: 'web-application', ip: '192.168.1.12', user: 'alice', severity: 'INFO', message: 'GET /index.html 200 OK (0.04s)' },
      { source: 'web-application', ip: '192.168.1.18', user: 'bob', severity: 'INFO', message: 'GET /api/v1/user/profile 200 OK' },
      { source: 'firewall', ip: '192.168.1.45', user: 'system', severity: 'INFO', message: 'Firewall ALLOW TCP 192.168.1.45:51240 -> 8.8.8.8:53' },
      { source: 'linux-server', ip: '192.168.1.5', user: 'charlie', severity: 'INFO', message: 'Accepted publickey for charlie from 192.168.1.5 port 44321 ssh2' },
      { source: 'windows-server', ip: '192.168.1.10', user: 'administrator', severity: 'INFO', message: 'Event ID 4624: An account was successfully logged on (User: admin)' },
      { source: 'syslog-network', ip: '172.16.0.1', user: 'gateway', severity: 'INFO', message: 'VLAN 10 Route health check: 0% packet loss' },
    ];

    const randomLog = benignLogs[Math.floor(Math.random() * benignLogs.length)];
    this.logIngestor.ingest(randomLog);
  }

  // Attack 1: SSH Brute Force
  simulateBruteForceAttack() {
    const attackerIp = this.attackerIPs[0];
    const targetUser = 'root';

    for (let i = 1; i <= 6; i++) {
      setTimeout(() => {
        this.logIngestor.ingest({
          source: 'linux-server',
          ip: attackerIp,
          user: targetUser,
          severity: 'WARN',
          message: `Failed password for ${targetUser} from ${attackerIp} port ${45000 + i} ssh2 [Attempt ${i}/6]`
        });
      }, i * 200);
    }
  }

  // Attack 2: SQL Injection
  simulateSqlInjectionAttack() {
    const attackerIp = this.attackerIPs[1];
    setTimeout(() => {
      this.logIngestor.ingest({
        source: 'web-application',
        ip: attackerIp,
        user: 'anonymous',
        severity: 'HIGH',
        message: `GET /api/products?id=1' UNION SELECT username, password FROM users-- HTTP/1.1 200`
      });
    }, 150);
  }

  // Attack 3: Firewall Port Scan
  simulatePortScanAttack() {
    const attackerIp = this.attackerIPs[2];
    for (let i = 1; i <= 12; i++) {
      setTimeout(() => {
        const port = [21, 22, 23, 80, 135, 139, 443, 445, 1433, 3306, 3389, 8080][i - 1];
        this.logIngestor.ingest({
          source: 'firewall',
          ip: attackerIp,
          user: 'system',
          severity: 'WARN',
          message: `Firewall connection dropped TCP ${attackerIp} -> 192.168.1.1: port ${port} (Port Scan Recon)`
        });
      }, i * 120);
    }
  }

  // Attack 4: Path Traversal
  simulatePathTraversalAttack() {
    const attackerIp = this.attackerIPs[3];
    setTimeout(() => {
      this.logIngestor.ingest({
        source: 'web-application',
        ip: attackerIp,
        user: 'anonymous',
        severity: 'WARN',
        message: `GET /download?file=../../../../etc/passwd HTTP/1.1 403 Forbidden`
      });
    }, 150);
  }

  // Attack 5: Privilege Escalation
  simulatePrivilegeEscalationAttack() {
    setTimeout(() => {
      this.logIngestor.ingest({
        source: 'linux-server',
        ip: '192.168.1.50',
        user: 'devuser',
        severity: 'WARN',
        message: `sudo: 3 incorrect password attempts ; TTY=pts/1 ; USER=root ; COMMAND=/bin/bash`
      });
    }, 150);
  }

  // Attack 6: Web Shell / Remote Command Execution
  simulateWebShellAttack() {
    const attackerIp = this.attackerIPs[4];
    setTimeout(() => {
      this.logIngestor.ingest({
        source: 'web-application',
        ip: attackerIp,
        user: 'www-data',
        severity: 'CRITICAL',
        message: `POST /uploads/shell.php?cmd=powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA= HTTP/1.1 200`
      });
    }, 150);
  }

  // Attack 7: Windows Security Audit Log Cleared
  simulateAuditLogCleared() {
    setTimeout(() => {
      this.logIngestor.ingest({
        source: 'windows-server',
        ip: '192.168.1.15',
        user: 'compromised_admin',
        severity: 'CRITICAL',
        message: `Windows Event 1102: The audit log was cleared by user compromised_admin`
      });
    }, 150);
  }

  // Attack 8: Windows Suspicious User Account Created
  simulateAccountCreated() {
    setTimeout(() => {
      this.logIngestor.ingest({
        source: 'windows-server',
        ip: '192.168.1.15',
        user: 'SYSTEM',
        severity: 'HIGH',
        message: `Windows Event 4720: A user account was created (Target: backdoor_admin, Creator: guest)`
      });
    }, 150);
  }

  // Attack 9: Vulnerability Scanner (Nikto / SQLmap)
  simulateVulnScanner() {
    const attackerIp = this.attackerIPs[5];
    for (let i = 1; i <= 4; i++) {
      setTimeout(() => {
        this.logIngestor.ingest({
          source: 'web-application',
          ip: attackerIp,
          user: 'bot',
          severity: 'WARN',
          message: `GET /admin.php HTTP/1.1 404 User-Agent: Mozilla/5.0 (Nikto/2.1.6 Vulnerability Scanner)`
        });
      }, i * 150);
    }
  }

  // Attack 10: Ransomware File Encryption
  simulateRansomwareActivity() {
    setTimeout(() => {
      this.logIngestor.ingest({
        source: 'endpoint',
        ip: '192.168.1.88',
        user: 'finance_workstation',
        severity: 'CRITICAL',
        message: `EDR Alert: Mass file rename activity detected. 450 documents modified to .locked extension.`
      });
    }, 150);
  }
}

window.AttackSimulator = AttackSimulator;
