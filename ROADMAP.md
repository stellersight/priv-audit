# Roadmap, November 2026 – November 2027

Priv-Audit is a focused, read-only auditor of Linux privilege boundaries. It
is not a vulnerability scanner or a compliance certification tool, and this
roadmap keeps it that way. The aim for the year is measured accuracy.

## Next three months

- **CI** on every push: unit tests and the fixture corpus on each supported
  distribution.
- **Release provenance.** Signed GitHub artifact attestations; reproducible
  package builds demonstrated.
- **Coverage.** Measured statement and branch coverage, published per release.

## Three to six months

- **SSH `Match` evaluation** with `sshd -T -C` for representative users,
  groups and addresses.
- **Effective sudo policy**: aliases, `@include` files and multi-line rules.
- **A larger corpus**: more distributions and seeded misconfigurations, with
  published false-positive and false-negative counts.

## Six to twelve months

- **Independent pilots** on hosts run by other organisations, reporting what
  the tool missed.
- **Upstream packaging** in Debian and Fedora/EPEL.
- **1.0.0**, once the above hold.

## Not planned

Exploitation, remediation that changes the host, and claims of certification
against CIS, ISO 27001 or CERT-In: findings are mapped to controls, nothing more.
