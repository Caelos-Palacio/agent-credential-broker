# Security policy

This is experimental software. No independent security audit or complete two-user production deployment has been demonstrated.

Do not send credentials, vault files, raw request/response payloads or private logs in issues or pull requests. Reproduce reports with synthetic fixtures. For sensitive vulnerability details, use GitHub private vulnerability reporting if enabled; otherwise open an issue containing only a high-level description and request a private channel before sharing details.

The supported security boundary is Linux local Unix IPC with a separately isolated custodian and agent identity. The client never receives provider credentials. The trusted custodian, operating system and provider remain within the trust boundary; this is not protection against a compromised root or custodian.

See [security limitations](docs/security.md) and [hardening](docs/hardening.md) before deployment. Installing the package alone does not establish that boundary.
