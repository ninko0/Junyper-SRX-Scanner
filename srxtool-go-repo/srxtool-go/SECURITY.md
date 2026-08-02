# Security Policy

## Scope

srxtool processes firewall configuration exports — files that describe the
structure of a network. Both the tool and its inputs deserve care.

The current deployment target is **localhost only, with no authentication**.
That is a deliberate, documented limitation, not a vulnerability in itself.
Reports along the lines of "the service has no login page" will be closed with
a pointer to this file.

## Reporting a vulnerability

Please report privately rather than opening a public issue:

- Use GitHub's **Report a vulnerability** button under the Security tab, or
- Contact the maintainer directly.

Include a description, reproduction steps, and the impact you believe it has.
A redacted proof-of-concept configuration is helpful — never send a real one.

Expect an acknowledgement within a few days. This is a small project; please
allow reasonable time for a fix before public disclosure.

## In scope

- Path traversal or any read outside a session directory
- Remote code execution, command injection, or template injection
- Crashes, hangs, or unbounded memory use triggered by a crafted
  configuration, hit-count export, or CSV
- Generated `set`/`delete` commands that do something other than what the tool
  reports — for example, a crafted object name that escapes into an unrelated
  configuration statement
- Session identifiers that are predictable or leak across sessions
- Container escape or privilege escalation from the shipped image

## Out of scope

- Missing authentication, missing TLS (see above — planned before any
  non-localhost deployment)
- Anything requiring the attacker to already have shell access on the host
- Findings from automated scanners without a demonstrated impact
- The security posture of the SRX configurations *analysed* by the tool — that
  is what the audit output is for

## Handling configurations

If you contribute a fixture or attach a configuration to an issue, redact it
first: addresses, hostnames, SNMP communities, policy and object names, and
anything identifying the organisation. Existing fixtures in
`testdata/fixtures/` use documentation ranges (RFC 5737) and are safe models
to follow.
