# StellerSight Priv-Audit

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-brightgreen.svg)](https://python.org)
[![Security Standard](https://img.shields.io/badge/compliance-CIS%20Linux%20%7C%20ISO%2027001%20%7C%20CERT--In-orange.svg)](#compliance-mappings)

**Zero-dependency Linux privilege boundary and host hardening auditor.**

Developed by **StellerSight Private Limited**, *Open-Source Security Engineering & Research*.

---

## Overview

**Priv-Audit** is a lightweight, zero-dependency security utility designed to rapidly audit Linux host privilege escalation vectors, sensitive file permissions, dangerous binaries, and identity boundary misconfigurations.

It evaluates host configurations against real-world offensive tradecraft (GTFOBins-listed SUID binaries, risky sudoers rules) and institutional security standards (CIS Linux Benchmarks, ISO 27001 A.9, and CERT-In Directions).

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

priv-audit is pre-release (0.1.0). Install it from StellerSight's signed package repository, which serves apt (Debian, Ubuntu), dnf/yum (RHEL, Rocky, AlmaLinux, Oracle Linux, Fedora, Amazon Linux 2023), zypper (openSUSE Tumbleweed), apk (Alpine) and pacman (Arch). Instructions and the signing-key fingerprint are at <https://stellersight.github.io/packages/>. For example, on Debian or Ubuntu:

```bash
curl -fsSL https://stellersight.github.io/packages/stellersight.gpg | sudo tee /usr/share/keyrings/stellersight.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/stellersight.gpg] https://stellersight.github.io/packages/deb stable main" | sudo tee /etc/apt/sources.list.d/stellersight.list
sudo apt update && sudo apt install priv-audit
sudo priv-audit                    # as root for a complete scan
```

Or run it from a checkout: `python3 priv-audit.py`. It is not on PyPI. It needs Python 3.8+ as `python3`, so RHEL 8 and openSUSE Leap 15 (Python 3.6) are not supported.

It has no dependencies beyond the Python 3.8+ standard library.

## Accuracy evidence

Accuracy is checked on clean Debian 12, Rocky Linux 9.3 and Alpine 3.20 images, and against seeded misconfigurations, with `sshd -T` as the reference for SSH settings. See [tests/fixtures/README.md](tests/fixtures/README.md) for the method, image digests and results. These results cover those images. They are not a claim of accuracy on every distribution.

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
```bash
priv-audit --exit-code              # fail on HIGH and above
priv-audit --exit-code --fail-on medium
```

| Exit code | Meaning |
| :--- | :--- |
| `0` | Scan complete, no finding at or above `--fail-on` |
| `1` | At least one finding at or above `--fail-on` |
| `2` | Scan incomplete, for example files unreadable without root, `getcap` missing, or `sshd -T` unavailable |
| `3` | A check failed with an unexpected error |

An incomplete scan is never reported as clean. Run as root for a complete result.

### What is and is not a finding
* Standard SUID binaries in system directories (`sudo`, `passwd`, `pkexec`, `unix_chkpwd` and similar) are expected and are not reported. This is a list of names and directories, not a query of the package manager, and it does not check for vulnerable versions (for example PwnKit in `pkexec`); use your distribution's security updates for that. Whether `sudo` grants too much is decided by the sudoers check, not by its file mode.
* The same binaries outside system directories are reported. Anything SUID in `/tmp`, `/var/tmp` or `/dev/shm` is CRITICAL; SGID-only files there are HIGH.
* File permissions are checked bit by bit against a per-file policy, so `/etc/shadow` at `0604` is reported even though `0604` is numerically below `0640`.
* SSH settings are read from `sshd -T`, the daemon's own effective configuration, when it is available. Otherwise the configuration is parsed with sshd's rules (first value wins, `Include` processed in place, `Match` blocks conditional), and the scan is marked incomplete.

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
