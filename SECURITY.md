# Security Policy

SPIDER is a dual-use security tool. Please report vulnerabilities responsibly and
avoid posting sensitive details in public issues, discussions, pull requests, or
comments.

## Supported Versions

Security fixes are provided for the default branch until the project publishes a
stable release policy.

## Reporting a Vulnerability

Use GitHub private vulnerability reporting if it is enabled for this repository.
If private reporting is not available, contact the maintainers using the private
security contact listed on the repository profile.

Please include:

- A concise vulnerability summary.
- Affected commit, version, or component.
- Reproduction steps using the local lab or sanitized fixtures only.
- Security impact and any known mitigations.
- Whether secrets, PII, or third-party target data may be involved.

Do not include:

- Real third-party targets, IP addresses, domains, credentials, tokens, or PII.
- Exploit logs from systems you do not own or lack written authorization to test.
- Public proof-of-concept payloads before maintainers coordinate disclosure.

## Response Expectations

Maintainers aim to acknowledge valid private reports within 7 calendar days and
will coordinate next steps, affected versions, remediation, and disclosure timing
with the reporter.

## Scope

In scope:

- Bypasses of SPIDER scope guard, sandbox, HITL, or audit controls.
- Unsafe tool execution or command construction.
- Secret leakage through logs, reports, CI, telemetry, or generated artifacts.
- Dependency or packaging issues that affect SPIDER users.

Out of scope:

- Reports requiring unauthorized access to third-party systems.
- Social engineering, physical attacks, or denial-of-service testing.
- Findings only affecting deliberately vulnerable lab targets without impact to
  SPIDER itself.

## Safe Harbor

Good-faith security research that follows this policy, avoids privacy violations,
and does not disrupt systems will be treated as authorized for the purpose of
coordinated vulnerability disclosure to the project maintainers.
