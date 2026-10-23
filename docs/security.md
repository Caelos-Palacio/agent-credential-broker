# Security of the experimental release

> Spanish original: [es/security.md](es/security.md)

The goal is deliberately narrow: **the agent calls predefined actions without ever receiving the credential bytes.** The custodian and the provider do use the secret (in memory and over TLS). There is no claim of absolute security, certification, resistance to root, or guaranteed zeroization in Python.

## Trust boundary

Trusted: the code and configuration, libraries, the OS, the GUI and the custodian process. Hostile: the agent and its input; a prompt injection may control its requests. The client identity comes from `SO_PEERCRED`, never from the JSON. The public actions cannot decrypt, read or export secrets, and cannot define a URL, auth headers, code or commands.

AES-256-GCM authenticates the header and the content. scrypt (n=32768, r=8, p=1) derives a 32-byte key from a fresh 16-byte salt; the nonce is a fresh 12 bytes. The format limits sizes, parameters and types before any expensive operation. This does not turn a weak password into a strong one, and it does not prevent guessing the password against a copy of the file. The PyCA [cryptography](https://cryptography.io/en/latest/) dependency is installed as a wheel pinned to 50.0.2; no custom cryptography was written.

Symlinks, hardlinks and insecure permissions on the vault are rejected. Atomic writes and detection of another instance prevent stale overwrites. Locking drops the Python references; internal copies, swap, core dumps and residual memory are outside the erasure guarantee. A production setup must add OS controls and avoid dumps.

## Action governance

The catalog belongs to the custodian. Each plan binds identity, action, exact inputs, destination and expiry. It is single-use, consumed before any remote access, and invalidated on lock or session change. Writes require explicit human approval in the GUI; another agent claiming approval is not enough. Per-session and per-credential budgets limit abuse, although authorized reads can still extract data or cost money.

The HTTPS connection pins public DNS, validates TLS, rejects metadata/private IPs and redirects, and ignores environment proxies. The maximum response is 128 KiB and the final projection is at most 4 KiB of explicitly allowed scalar fields. `outputSchema` is mandatory for every action: strings are limited to an enum or a simple anchored pattern with a bounded length, and free text is off by default. Literal, base64 and URL-encoded echoes of the credential are blocked; other encodings, fragments, third-party sensitive data and side channels need specific policies. The allow-list of fields matters more than any promise of universal redaction.

The server allows two concurrent clients, a 16 KiB frame, a 4 s read and one request per connection. An unauthorized peer receives a constant error. Error codes never embed the original exception, request or response. The total HTTPS deadline covers DNS, handshake, headers and body, and the transport aborts when it expires. DNS uses at most two bounded disposable processes: a timeout kills and reaps the child to release its slot. The cost of creating a process is measured in the benchmark; there is no connection pool and no DNS cache. A timeout does not prove that a remote action was cancelled.

## Verifiable limitations

- A laboratory with two distinct kernel identities in an ephemeral approved namespace exercised real `SO_PEERCRED` and the production constructor, with no bypass; authorized UID 1 passed and spoofed UID 0/2 were rejected. It has not been deployed with persistent users. Ordinary Unix fixtures keep the private constructor exception, separate from that laboratory; there is no remote/CLI/env bypass.
- The Tk GUI was rendered and reviewed in a temporary Xvfb and tested for create/unlock/save/lock, wrong password, tab order, and approve/reject/expiry. A virtual display does not prove the permissions or isolation of a production desktop.
- A Bubblewrap launcher with a clean environment and namespaces was tested with fictitious canaries, and a second laboratory passed with two real kernel UIDs inside an ephemeral namespace, but nothing has been deployed with persistent users; it does not configure users, ACLs, cgroups or desktop policy automatically. Another agent running under the custodian's UID can read its files and processes and automate its desktop, so that deployment is unsafe even though the API rejects the same UID.
- There is no independent audit, mlock, hardware-backed keys, OAuth, MFA, master-password rotation, recovery, attestation or tamper-proof log. Offline verification against a separate checkpoint exists; it neither installs nor guarantees an external witness. Write auditing fails closed before the network and reports an uncertain state if it fails afterwards; read auditing is best effort. Storage is bounded and holds no payloads for replay.
- A compromised root, kernel, provider or custodian, malicious software running as the same user, and effects already sent are out of scope. Encrypted storage does not replace account separation and a sandbox.

Tests use synthetic secrets only. No local vaults, user passwords or existing application credentials were inspected. The [primary research](research.md) (Spanish) explains precedents and differences.

## Separation from observability

Agent Observer is a separate project, but separate repositories do not create a security boundary. Running it under the custodian's UID and giving it arbitrary code would let it read the custodian's memory and files like any other process of that UID. To export audit data, a trusted component projects only the metadata schema to a receive-only destination; Observer and the agents must run under a lower identity with no access to the vault, the code or the custodian process. This release has no automatic deployment of that setup.

## Verified dependencies

On 16 October 2026 the public PyPI API reported no vulnerabilities for cryptography 50.0.2, cffi 2.1.1 and pycparser 3.11, and `pip check` found no incompatibilities. This does not prove the absence of unknown vulnerabilities and does not replace an audit. Only wheels were installed in the local venv. Packaging tools and the QA Xvfb are not runtime dependencies of the custodian.

[Reproducible demonstrations and limits](assurance.md) (Spanish) documents synthetic TLS, races, crash/restart, the seeded corpus and the hypotheses of each experiment. The final egress authorization point is after the audit; revoking afterwards does not recover data already delivered.
