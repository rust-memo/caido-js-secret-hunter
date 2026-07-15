# Security policy

## Supported versions

Only the latest minor release receives security fixes.

| Version | Supported |
| --- | --- |
| 1.1.x | Yes |
| 1.0.x | No |

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose credentials, local data, or a user's authorized targets. Report it privately through GitHub Security Advisories for this repository.

Include the affected version, minimal reproduction steps, impact, and any suggested mitigation. Remove real credentials, session tokens, customer data, and information from systems you do not own.

## Security model

Raw detected values are not intentionally persisted. Automatic network fetching is disabled by default, restricted to Caido Scope at every redirect, and bounded. Forwarding `Cookie` or `Authorization` requires a second explicit opt-in and is allowed only for an exact same-origin request.

No detector can prove that a candidate is live or exploitable. Review and validate every result in an authorized environment.
