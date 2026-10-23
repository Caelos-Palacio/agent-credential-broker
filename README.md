# Agent Credential Broker

**Let an AI coding agent call authenticated APIs without ever seeing the API key.**

English · [Español](README.es.md)

> **Status: experimental, not independently audited.** This is a working implementation, not a certified security product. The separation only holds when the agent runs under a different UID, with no access to the custodian's desktop, files or processes. Tests use fictitious credentials only. The GUI was rendered and reviewed in a private virtual display; the isolation of a production desktop is not validated. Read the [security model](docs/security.md) before putting any real secret near it.

![Animated demo: an agent asks the broker for a named action; the key stays in the broker and only {"id"} comes back.](docs/media/demo.gif)

<sub>Every terminal line in the demo is real output of the CLI against the real server, with a fake key and a stub provider. Regenerate: `python3 docs/media/capture.py` (from the project venv), then `python3 docs/media/demo.py` (needs Pillow and ffmpeg).</sub>

## Why

Coding agents run commands, read your files and follow instructions found in web pages and issues. If the API key is in their environment or a config file, a single prompt injection can read it. Password managers and browser profiles do not help: they hand the secret to whoever asks.

The broker inverts that. A local **custodian** process owns an encrypted vault and a catalog of actions you approved (method, exact HTTPS destination, input schema, response fields). The agent can only ask for those actions over a Unix socket. It never supplies a URL, header, code or command, and it never receives the secret. The custodian signs the request, calls the API, and returns only the fields you allowed.

It is independent of the agent, terminal, model provider and orchestration tool. Examples and integrations are optional.

## Quick start

Requires Linux and Python 3.12 or newer. The core and the audit work without a desktop; Tk is needed only for the human GUI.

```sh
git clone https://github.com/Caelos-Palacio/agent-credential-broker.git
cd agent-credential-broker
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.lock -r requirements-build.lock
.venv/bin/python -m pip install --no-deps --no-build-isolation .
.venv/bin/python -m unittest discover -s tests   # 102 tests; 2 GUI tests are skipped without Tk
.venv/bin/python -m credential_broker.cli gui    # the human custodian creates the vault here
```

In the GUI the custodian creates a vault in a new directory, stores a credential under an alias, chooses the agent UID, a socket and an action catalog, and starts the service. The [example catalog](examples/actions.json) uses fictitious endpoints and the alias `demo_key`; copy it to a trusted location, adjust the actions and set it to 0600 outside the agent's environment.

**Do not serve real secrets until you have deployed the separation described in [operations](docs/operations.md).** By design, an agent that shares the custodian's UID cannot use the service. The project never creates users, groups, services or sandbox configuration for you.

The agent side is four JSON operations over the socket:

```json
{"op":"capabilities"}
{"op":"plan","request":{"action":"read_account","input":{}}}
{"op":"execute","request":{"planId":"ID_RETURNED_BY_PLAN"}}
```

```sh
printf '%s\n' '{"op":"capabilities"}' | .venv/bin/python -m credential_broker.cli call --socket /trusted/path/broker.sock
```

The transport only exposes `status`, `capabilities`, `plan` and `execute`. There is no `getSecret`, unlock, export or remote storage. The private transport test lets a fixture inject an identity through a Python constructor; **no CLI flag, environment variable or agent parameter enables that bypass**, and production code must be unreachable for the agent's UID.

## Features

- **Encrypted vault.** AES-256-GCM with random salt and nonce, scrypt key derivation (PyCA `cryptography`, no home-made crypto). 0600 file, 0700 directory, atomic writes, symlink/hardlink rejection, stale-writer detection.
- **Human-only administration.** A native Tk GUI creates, unlocks, locks and stores credentials in hidden fields; it never shows or exports values. The master password never travels through arguments, environment variables or stdin.
- **Action catalog owned by the custodian.** Fixed method and HTTPS destination, strict input schema, allowed response fields with a strict `outputSchema`, and budgets. The agent contributes no URL, headers, code or commands.
- **Single-use plans.** 60 s TTL, kernel identity via `SO_PEERCRED`, invalidation on session change. Writes require the human to confirm the real method, destination and values in the GUI (25 s to answer).
- **Hardened transport.** Unix socket 0660, two concurrent requests, 16 KiB frames, 4 s read. Production rejects the custodian's own UID and UID 0 as the agent.
- **Safe egress.** Validated TLS, pinned public DNS, no redirects or proxies, no automatic retries of writes, constant error codes, projected results. Obvious credentials and some echoes are blocked; universal DLP is not promised.
- **Trusted per-task grants.** Kernel UID, actions, resources, expiry and a persistent quota. Production needs a grant file next to the catalog; see [hardening](docs/hardening.md).
- **Revocation.** Administrative revocation and credential versioning invalidate stale plans and results, including during delivery.
- **Isolation tooling.** A Bubblewrap launcher for the agent and a laboratory with two real kernel identities in an ephemeral namespace. There is no operational deployment with persistent users.
- **Metadata-only audit.** No requests, responses, aliases or secrets. Write attempts are persisted before the credential is used; two rotating files of about 256 KiB. Auto-lock after 5 minutes; the GUI and the server revoke plans when locking.
- **Observer export.** Offline export of audit metadata for [Agent Observer](https://github.com/Caelos-Palacio/agent-observer) with a strict schema (v1, or opt-in v2 with correlation and sequence) and persistent event IDs, plus `audit-checkpoint` / `audit-verify` for integrity against a separate reference. It exposes no vault access and adds no operation to the agent transport.

## Security model and limitations

- The custodian, the OS and the provider are inside the trust boundary. A compromised root, kernel, provider or custodian is out of scope, as are effects already sent to the provider.
- Hiding a key does not limit what the key can do. Create minimally scoped keys at the provider; the catalog narrows what the agent may ask for.
- **Not independently audited.** No hardware-backed keys, `mlock`, OAuth, MFA, master-password rotation, recovery or tamper-proof log.
- **Not validated:** a production deployment with persistent users, or a real X11/Wayland desktop. The earlier GUI QA used a private Xvfb and was not repeated in the last round.
- Python cannot guarantee zeroization of secrets in memory; swap and core dumps are outside the guarantee.
- Linux only. Isolation uses Linux kernel interfaces and Bubblewrap; equivalent support on macOS or Windows is not claimed.

### Evidence

The suite has 102 tests (100 passing and 2 GUI tests skipped in the recorded verification run): real TLS with synthetic certificates, 133 malformed frames and 136 provider outputs from a fixed seed, revocation races, and processes that die while persisting. [Semantic tests](docs/semantic-assurance.md) compare 288 traces against the real broker and cover twelve typed mutations; they found and fixed quota consumption of a new grant by old plans and plan reactivation when re-issuing an identical permission.

The [two-UID laboratory](docs/assurance.md) passed with real `SO_PEERCRED` and the production constructor, with no identity bypass: legitimate access, rejection of a spoofed UID, private files/memory/code and an IPC canary. It is not the same as production with persistent users. An optional [Solidity experiment](docs/solidity-assessment.md) runs 9 local EVM bytecode tests; it does not integrate any blockchain, deploy contracts or touch wallets, and it is not a formal SMT proof. See the [threat matrix, invariants and reproductions](docs/assurance.md).

Reproduce locally (this is exactly what CI runs):

```sh
.venv/bin/python scripts/assurance.py --all
.venv/bin/python -m compileall -q credential_broker
.venv/bin/python -m pip check
```

## Documentation

[Security and limits](docs/security.md) · [Operations](docs/operations.md) · [Governance, isolation, checkpoints and benchmarks](docs/hardening.md) · [Assurance](docs/assurance.md) · [Research and primary sources](docs/research.md). `assurance`, `semantic-assurance`, `solidity-assessment` and `research` are currently in Spanish. Vulnerability reports: see [SECURITY.md](SECURITY.md).

## Related projects

- [Agent Observer](https://github.com/Caelos-Palacio/agent-observer): imports this broker's audit export and reviews it, with no access to the vault.
- [Pi Session Workspace](https://github.com/Caelos-Palacio/pi-session-workspace): session navigation, checkpoints and a local mailbox for the Pi coding agent.

## License

[MIT](LICENSE)
