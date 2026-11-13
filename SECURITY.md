# Security policy

Priv-Audit is a read-only auditor, usually run as root. A flaw in it can
mean a false "clean" report, or root reading something it should not.

## Reporting a vulnerability

Do not open a public issue for a security problem. Report it privately to
**security@stellersight.com** with the version or commit, the distribution,
and the steps to reproduce.

We acknowledge reports within three working days, aim to fix confirmed
vulnerabilities within 30 days, and credit reporters who wish to be named.
Please allow us to release a fix before disclosure.

## What is in scope

- Priv-Audit changing anything on the host.
- A scan that misses a condition it claims to check and still reports clean
  (exit 0) instead of incomplete (exit 2).
- Input on the host (file names, file contents, command output) that makes
  Priv-Audit execute code, follow a link it should not, or crash.

## What is not in scope

These are documented limits (see the README):

- Paths outside the fixed search directories.
- Sudo rules outside `/etc/sudoers` and `/etc/sudoers.d`, and SSH `Match`
  blocks, which are reported as gaps.
- Vulnerable package versions: Priv-Audit checks configuration, not versions.
