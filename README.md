# StellerSight Priv-Audit

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-brightgreen.svg)](https://python.org)
[![Security Standard](https://img.shields.io/badge/compliance-CIS%20Linux%20%7C%20ISO%2027001%20%7C%20CERT--In-orange.svg)](#compliance-mappings)

**Zero-dependency Linux privilege boundary and host hardening auditor.**

Developed by **StellerSight Private Limited**, *Open-Source Security Engineering & Research*.

---

## Overview

**Priv-Audit** is a lightweight, zero-dependency security utility designed to rapidly audit Linux host privilege escalation vectors, sensitive file permissions, dangerous binaries, and identity boundary misconfigurations.

It evaluates host configurations against real-world offensive tradecraft (GTFOBins, PwnKit, sudoer bypasses) and institutional security standards (CIS Linux Benchmarks, ISO 27001 A.9, and CERT-In Directions).

```
   +-------------------------------------------------------------+
   |                  StellerSight Priv-Audit                     |
   +-------------------------------------------------------------+
         |                |                 |                |
   +-----v------+  +------v-------+  +------v------+  +------v------+
   |    SUID    |  |     Sudo     |  | Filesystem  |  | OpenSSH &   |
   |  GTFOBins  |  |  NOPASSWD &  |  | Permissions |  | Capabilities|
   | Escalation |  | Wildcards    |  | /etc/passwd |  | cap_setuid  |
   +------------+  +--------------+  +-------------+  +-------------+
```

---

## Core Capabilities

1. **SUID / SGID GTFOBins Auditing (`PA-SUID-001`):**
   * Scans system execution paths for SUID/SGID binaries.
   * Matches discovered binaries against GTFOBins exploit catalog (`bash`, `python`, `find`, `vim`, `cp`, `tar`, `nmap`, etc.) capable of instant root shell breakout.
2. **Sudoers Boundary & Env Inspection (`PA-SUDO-001`):**
   * Parses `/etc/sudoers` and `/etc/sudoers.d/*`.
   * Flags `NOPASSWD: ALL` and high-risk passwordless utility authorizations.
   * Flags dangerous environment passthroughs (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`) allowing dynamic shared library hijacking.
   * Detects wildcard command path specifications.
3. **Sensitive Filesystem Permissions (`PA-FS-001`):**
   * Audits mode and ownership of critical assets: `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`, `/etc/crontab`.
   * Flags world-writable system directories (`/etc/cron.*`, `/etc/systemd/system`, `/etc/profile.d`).
4. **Linux Extended Capabilities (`PA-CAP-001`):**
   * Inspects binary capabilities using `getcap`.
   * Flags dangerous capabilities (`cap_setuid`, `cap_sys_admin`, `cap_dac_override`, `cap_sys_ptrace`).
5. **OpenSSH Daemon Hardening (`PA-SSH-001`):**
   * Validates `/etc/ssh/sshd_config` for `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, and `MaxAuthTries`.
6. **Scheduled Task & Persistence Auditing (`PA-PERSIST-001`):**
   * Checks for world-writable user crontabs and scheduled cron scripts.

---

## Quick Start

### Single-File Direct Run (No Installation Required)

```bash
git clone https://github.com/stellersight/priv-audit.git
cd priv-audit
python3 priv-audit.py
```

### Installation via Pip

```bash
pip install stellersight-priv-audit
priv-audit
```

---

## Usage & CI/CD Integration

### Human-Readable Console Output
```bash
priv-audit
```

### Machine-Readable JSON (SIEM / Log Forwarders)
```bash
priv-audit --json > audit-results.json
```

### Formatted Markdown (for GitHub PRs & Audit Logs)
```bash
priv-audit --markdown -o host-audit-report.md
```

### DevSecOps / CI Pipeline Gate
Exit with return code `1` if any **CRITICAL** or **HIGH** severity finding exists:
```bash
priv-audit --exit-code
```

---

## Compliance Mappings

| Check ID | Title | CIS Linux Benchmark | ISO 27001 | CERT-In Cyber Directions |
| :--- | :--- | :--- | :--- | :--- |
| `PA-SUID-001` | Exploitable SUID/SGID Binaries | 1.1.20 | A.9.4.4 | Least Privilege Control |
| `PA-SUDO-NOPASSWD-ALL` | Unrestricted Passwordless Sudo | 5.3.7 | A.9.2.3 | Multi-Factor Root Access |
| `PA-SUDO-ENV` | Unsafe Linker Environment Sudo | 5.3.4 | A.9.4.2 | System Integrity |
| `PA-FS-PASSWD` | World-Writable /etc/passwd | 6.1.2 | A.9.4.1 | Host Tamper Resistance |
| `PA-SSH-ROOT` | SSH Root Login Permitted | 5.2.10 | A.9.4.2 | Remote Administration |
| `PA-CAP-CAP_SETUID` | Dangerous Binary Capabilities | 1.1.21 | A.9.4.4 | Privilege Separation |

---

## StellerSight Open-Source Security Suite

Priv-Audit is part of the **StellerSight Security Engineering Portfolio**:
* **[SUIT](https://www.drupal.org/project/suit):** Security & Unified Identity Toolkit (PIM, PAM, IAM for enterprise CMS).
* **[DPDP Compliance Toolkit](https://www.drupal.org/project/dpdp):** Verifiable consent ledger & Data Principal rights engine.
* **[Incident Reporting](https://www.drupal.org/project/incident_reporting):** CERT-In & ISO 27035 cyber incident management.
* **Priv-Audit:** Zero-dependency host hardening & privilege escalation auditing.

---

## License

Licensed under the **Apache License, Version 2.0**.
Copyright &copy; 2026 **StellerSight Private Limited**. All rights reserved.
