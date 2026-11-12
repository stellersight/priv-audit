# Fixture corpus

Accuracy checks on real distribution images. They are a complement to the unit tests, not a replacement: they catch what only a real system reveals.

```bash
docker build --build-arg BASE=debian:12-slim -f tests/fixtures/Dockerfile -t pa-fixture:debian .
docker run --rm pa-fixture:debian
```

Each run performs 15 checks:

| Phase | What it checks |
|---|---|
| A. Clean image | No HIGH or CRITICAL finding, and `--exit-code` does not fail (false-positive check) |
| B. SSH oracle | For five tricky configurations, the fallback parser's effective values equal `sshd -T`'s: first value wins, `Key=value`, `Include` in place, `Match` conditional, and case-insensitive keywords |
| C. Seeded host | Detects `PermitRootLogin yes`, `/etc/shadow` at `0604`, a SUID binary in `/tmp`, `NOPASSWD: ALL`, and `cap_setuid` on an interpreter. `--exit-code` returns 1 |
| D. Unprivileged | A non-root run is reported incomplete and never exits 0 |

## Results, 12 November 2026

| Image | Digest | OpenSSH | Result |
|---|---|---|---|
| debian:12-slim | `sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc` | 9.2 | 15/15 |
| rockylinux:9-minimal (9.3) | `sha256:305de618a5681ff75b1d608fd22b10f362867dff2f550a4f1d427d21cd7f42b4` | 9.9p1 | 15/15 |
| alpine:3.20 | `sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc` | 9.7p1 | 15/15 |

Kernel: 6.6.87.2-microsoft-standard-WSL2 (Docker Desktop). Containers share that kernel.

On clean images, the only remaining findings are real SSH hardening gaps: password authentication enabled, X11 forwarding, and `MaxAuthTries` above 4.

### Defects this corpus found

The first run on Rocky Linux failed phase A, and the cause was in priv-audit, not in the image:

- `newuidmap` and `newgidmap` ship with `cap_setuid` and `cap_setgid` on every RHEL-family host, for rootless containers. They were reported as CRITICAL and HIGH, so a stock host always failed the CI gate. These are now an expected-capability baseline, valid only in system directories and only with exactly those capabilities.
- `pam_timestamp_check`, a stock RHEL SUID binary, was reported as non-standard.
- On merged-`/usr` systems, the same file was reported twice, through `/sbin` and `/usr/sbin`. Findings are now de-duplicated by real path.
