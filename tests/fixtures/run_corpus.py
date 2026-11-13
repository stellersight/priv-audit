# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 StellerSight Private Limited
"""priv-audit fixture corpus, run as root inside a disposable container.

A  clean image: no HIGH or CRITICAL finding (false-positive check)
B  SSH parser versus sshd -T on tricky configurations (differential oracle)
C  seeded misconfigurations: each must be detected (false-negative check)
D  unprivileged run: must report the scan incomplete (exit 2), never clean
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, "/opt/priv-audit")
from privaudit.checks.ssh import SSHD_CHECKS, SshCheck  # noqa: E402

AUDIT = ["python3", "-I", "/opt/priv-audit/priv-audit.py", "--json", "--exit-code"]
results = []


def check(name, cond, detail=""):
    results.append(cond)
    print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else f"\n      {detail}"))


def run_audit(as_user=None):
    cmd = AUDIT if as_user is None else ["su", "-s", "/bin/sh", as_user, "-c", " ".join(AUDIT)]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc.returncode, json.loads(proc.stdout)


def sev(report, *levels):
    return [f["check_id"] + ": " + f["title"] for f in report["findings"] if f["severity"] in levels]


def provenance():
    osr = dict(line.strip().split("=", 1) for line in open("/etc/os-release") if "=" in line)
    sshd = subprocess.run(["sshd", "-V"], stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    print(f"== {osr.get('PRETTY_NAME', '?').strip(chr(34))} | {(sshd.stderr or sshd.stdout).strip().splitlines()[0]}")


provenance()

# A. Clean image ------------------------------------------------------------
rc, rep = run_audit()
print(f"   clean findings: {[f['check_id'] for f in rep['findings']]} incomplete={rep['incomplete']}")
check("A clean image: no HIGH or CRITICAL findings", not sev(rep, "HIGH", "CRITICAL"), sev(rep, "HIGH", "CRITICAL"))
check("A clean image: --exit-code is not 1", rc != 1, f"rc={rc}")

# B. SSH differential oracle ------------------------------------------------
CASES = {
    "first value wins": "PermitRootLogin yes\nPermitRootLogin no\nPasswordAuthentication no\n",
    "key=value syntax": "PermitRootLogin=no\nPasswordAuthentication=yes\nMaxAuthTries=3\n",
    "include in place": "Include {dir}/drop.d/*.conf\nPermitRootLogin no\n",
    "match is conditional": "PermitRootLogin no\nX11Forwarding no\nMatch User backup\n    PermitRootLogin yes\n",
    "case-insensitive keywords": "permitrootlogin yes\nPERMITEMPTYPASSWORDS no\n",
}
ALIASES = {"without-password": "prohibit-password"}
checked_keys = {c[0].lower() for c in SSHD_CHECKS}
for name, text in CASES.items():
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "drop.d"))
    with open(os.path.join(d, "drop.d", "50-cloud.conf"), "w") as f:
        f.write("PermitRootLogin yes\nPasswordAuthentication yes\n")
    cfg = os.path.join(d, "sshd_config")
    with open(cfg, "w") as f:
        # HostKey goes first: sshd forbids it inside a Match block.
        f.write("HostKey /etc/ssh/ssh_host_ed25519_key\n" + text.format(dir=d))
    oracle = SshCheck(config_path=cfg)._effective_from_sshd()
    if oracle is None:
        check(f"B {name}: sshd -T available", False, "sshd -T failed")
        continue
    parsed = {}
    SshCheck(config_path=cfg, use_sshd=False)._parse_file(cfg, parsed, [], depth=0)
    mismatches = []
    for key in sorted(checked_keys & set(parsed)):
        mine = ALIASES.get(parsed[key][0].lower(), parsed[key][0].lower())
        theirs = ALIASES.get(oracle[key][0].lower(), oracle[key][0].lower())
        if mine != theirs:
            mismatches.append(f"{key}: parser={mine} sshd={theirs}")
    check(f"B {name}: parser agrees with sshd -T", not mismatches, mismatches)

# C. Seeded misconfigurations -----------------------------------------------
with open("/etc/ssh/sshd_config", "a") as f:
    f.write("\nPermitRootLogin yes\n")
shadow = "/etc/shadow"
os.chmod(shadow, 0o604)
os.makedirs("/tmp/x", exist_ok=True)
shutil.copy("/usr/bin/id", "/tmp/x/helper")
os.chmod("/tmp/x/helper", 0o4755)
with open("/etc/sudoers.d/zz-seeded", "w") as f:
    f.write("auditor ALL=(ALL) NOPASSWD: ALL\n")
os.chmod("/etc/sudoers.d/zz-seeded", 0o440)
py = os.path.realpath(shutil.which("python3"))
pycopy = "/usr/local/bin/py-seeded"
shutil.copy(py, pycopy)
subprocess.run(["setcap", "cap_setuid+ep", pycopy], check=True)

rc, rep = run_audit()
ids = {f["check_id"] for f in rep["findings"]}
for expected, what in [("PA-SSH-ROOT", "PermitRootLogin yes"), ("PA-FS-SHADOW", "world-readable /etc/shadow (0604)"),
                       ("PA-SUID-TMP", "SUID binary in /tmp"), ("PA-SUDO-NOPASSWD-ALL", "NOPASSWD: ALL"),
                       ("PA-CAP-CAP_SETUID", "cap_setuid on an interpreter")]:
    check(f"C detects {what}", expected in ids, sorted(ids))
check("C seeded host: --exit-code is 1", rc == 1, f"rc={rc}")

# D. Unprivileged run --------------------------------------------------------
rc, rep = run_audit(as_user="auditor")
check("D unprivileged run is reported incomplete (exit 2 or findings)", rc in (1, 2) and not rep["complete"], f"rc={rc} complete={rep['complete']}")
check("D unprivileged run never claims clean", rc != 0, f"rc={rc}")

passed = sum(results)
print(f"== {passed} passed, {len(results) - passed} failed")
sys.exit(0 if passed == len(results) else 1)
