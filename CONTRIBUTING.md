# Contributing

Thank you for helping. Priv-Audit is usually run as root and its reports drive
security decisions, so every change is judged first by whether it could make an
incomplete or wrong scan read as clean.

## Before you start

- Security problems go to security@stellersight.com, never to a public issue
  (see [SECURITY.md](SECURITY.md)).
- For a new check or a change to severities or exit codes, open an issue first.
- Small fixes and tests can go straight to a pull request.

## Requirements for a change

- **Tests.** New checks come with unit tests in `tests/`, including a case the
  check must not flag, and, where possible, a seeded case in the fixture corpus
  (`tests/fixtures/`).
- **Report gaps.** Anything a check cannot read or evaluate marks the scan
  incomplete; it is never silently skipped.
- **Standard library only.** No runtime dependencies beyond Python 3.8+.
- **Documentation.** If what a check covers changes, update the README in the
  same pull request.
- **Style.** Follow the existing code: type hints, short functions, docstrings
  that say why. Run `python -m unittest discover -s tests` before pushing.

## Sign your work (DCO)

Every commit must carry a `Signed-off-by` line, certifying the
[Developer Certificate of Origin 1.1](https://developercertificate.org/):
that you wrote the change or otherwise have the right to submit it under the
project's licence (Apache-2.0).

```bash
git commit -s
```

## Review

A maintainer reviews every pull request. The aim is for changes to be reviewed
by someone other than their author before release.
