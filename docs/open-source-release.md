# Open Source Release Checklist

This checklist tracks the repository work required before making SPIDER public.
SPIDER is a dual-use penetration testing framework, so release readiness includes
ordinary open source hygiene and explicit controls for authorized-use security
research.

## Security and Scrubbing

- [ ] Run full-history secret scans with at least two scanners, such as Gitleaks
      and TruffleHog.
- [ ] Revoke and rotate every credential that appears in the repository, even if
      the value is later removed from history.
- [ ] Remove committed secrets, private configuration, customer data, private
      target data, and engagement artifacts from Git history with
      `git-filter-repo` or an equivalent tool.
- [ ] Search for PII, real target IP addresses, real target domains, customer
      names, screenshots, terminal transcripts, audit logs, and exploit output.
- [ ] Keep only sanitized examples such as `.env.example`; do not publish live
      `.env`, `*.local`, or `secrets.*` files.
- [ ] Enable GitHub secret scanning and push protection before public launch.
- [ ] Confirm GitHub Actions workflows never expose repository secrets to
      untrusted fork pull requests.

Suggested commands:

```bash
gitleaks git --verbose --redact --report-format sarif --report-path gitleaks.sarif .
trufflehog git file://. --results=verified,unknown
rg -n --hidden --glob '!/.git' 'password|passwd|secret|token|api[_-]?key|client_secret|PRIVATE_KEY'
```

## Licensing and Legal

- [x] Publish Apache-2.0 terms in `LICENSE`.
- [x] Declare Apache-2.0 package metadata in `pyproject.toml`.
- [x] Add `NOTICE` with project copyright information.
- [ ] Review dependency licenses before the repository is made public.
- [ ] Revisit temporary `pip-audit` ignores for transitive `diskcache` and dev-only
      `pytest` findings as soon as patched compatible releases are available.
- [ ] Decide whether DCO sign-off is required for all pull requests.
- [ ] Have counsel review export-control, liability, and dual-use positioning if
      the project will be promoted commercially or used by regulated customers.

## Documentation and Community

- [x] Keep the README focused on safe installation, quickstart, architecture,
      development, and disclaimer information.
- [x] Add `CONTRIBUTING.md` with development, testing, safety, and PR review
      expectations.
- [x] Add `CODE_OF_CONDUCT.md` for community behavior expectations.
- [x] Add `SECURITY.md` for private vulnerability reporting.
- [x] Add `ETHICAL_USE.md` for authorized-use boundaries.
- [x] Add issue templates that warn contributors not to disclose secrets, PII,
      real target data, or vulnerabilities publicly.
- [x] Add a pull request template with safety and testing checklists.

## Code Quality and CI/CD

- [x] Add pre-commit hooks for formatting, file hygiene, private-key detection,
      and secret scanning.
- [x] Add CI for Ruff linting, Ruff formatting, safety tests, tool tests, engine
      tests, and the non-integration test suite.
- [x] Add CodeQL static analysis.
- [x] Add dependency review for pull requests.
- [x] Add Gitleaks, pip-audit, and OpenSSF Scorecard security workflows.
- [ ] Pin third-party GitHub Actions to immutable SHAs before high-assurance
      releases.
- [ ] Configure release workflows with least-privilege permissions and trusted
      publishing if SPIDER is published to a package index.

## GitHub Repository Settings

Configure these in the GitHub UI before switching visibility to public:

- [ ] Protect the default branch and require pull requests before merge.
- [ ] Require status checks for CI, CodeQL, dependency review, and secret scans.
- [ ] Require code-owner review for safety-sensitive paths.
- [ ] Block force pushes and branch deletion on protected branches.
- [ ] Enable Dependabot alerts and security updates.
- [ ] Enable the dependency graph, code scanning, secret scanning, and push
      protection.
- [ ] Enable private vulnerability reporting.
- [ ] Enable Discussions for support and design questions.
- [ ] Audit collaborators, teams, deploy keys, webhooks, GitHub Apps,
      repository secrets, environments, and Pages settings.
- [ ] Set repository description, topics, homepage/docs link, and social preview.
