# Governance, isolation and verification

> Spanish original: [es/hardening.md](es/hardening.md)

## Per-task authority

The production service requires a `TaskGrant` and a `QuotaStore`; the fixtures' identity exception is not exposed in the CLI or API. The GUI reads a second trusted file: **the catalog path followed by `.grant.json`**, owned by the custodian, 0600 and link-free. Disabled example: [actions.json.grant.json](../examples/actions.json.grant.json). The custodian sets `expiresAt` as a future Unix UTC time, an administrative `taskId`, `maxUses` and the actions. Each action holds equality constraints per input field, for example `{"read_document":{"documentId":["approved-document"]}}`. An empty object allows every value valid under that action's schema; do not use it for resources that must be limited.

Identity is still the kernel UID; the agent supplies no taskId/model/principal. The plan fixes the grant, the inputs and the credential version, and re-checks them before and after using the credential. Agents that share a UID and socket share the grant: telling workers apart takes identities or channels from a trusted supervisor, not self-declared labels. The local permission also does not reduce the privileges of the key at the provider: the custodian must create minimal-scope keys there.

`quotas.json` stores only hashes and counters/timestamps, inside the custodian's 0700 directory. `flock`, atomic replacement and `fsync` of file/directory serialize concurrent attempts and keep quotas across restarts. Budget is consumed before accessing the credential and is not returned after a later rejection, failure or uncertain result. At most 128 grants, 64 credential hashes and 4096 active hourly marks are kept; full or corrupt storage denies. Do not delete the ledger to free space without an administrative review: that would reset budgets. Re-issuing a modified grant creates a new task budget but keeps the credential's hourly limit.

## Revocation

The trusted Python API `broker.revoke_credential(alias)` invalidates plans and removes the encrypted entry. It is not an agent operation. `Vault.put/remove` increment the local version: a direct replacement invalidates earlier plans and the result of callbacks that were using the previous version. The GUI keeps its stop-before-save rule.

There is no per-credential revocation in the GUI, no master-password rotation, no recovery, no temporary provider credentials and no remote revocation. A request already sent may have had effects; discarding its result does not undo them. No remote abort and no complete erasure of bytes in Python memory are promised.

## Agent launcher and laboratory

`python -m credential_broker.isolation --workspace WORK --socket SOCKET -- COMMAND` runs under the agent's UID, distinct from the custodian's. It rejects a socket of the same UID or root, and a missing Bubblewrap; it never degrades to running without a sandbox. It exposes `/usr`, libraries, minimal devices, a private `/proc`, its own `/tmp` and the workspace; it mounts only the socket as `/run/broker.sock`. It clears the environment and isolates namespaces, network, session and bus/desktop access. It disables core dumps and limits descriptors. It mounts no HOME, D-Bus, X11/Wayland or auxiliary custodian sockets.

This requires trusted installation/configuration: the agent must not be able to edit the launcher, code, catalog or dependencies, escape through another executor, or receive alternative access. It does not configure users/groups/cgroups/AppArmor automatically. It also provides no RAM/CPU/PID quota: the administrator must add one to the agent's environment. ACLs, socket mounting across UIDs, ptrace and desktop policies must be verified in the real deployment.

Reproducible test with fictitious canaries: `.venv/bin/python scripts/isolation-lab.py`. On the author's machine it returned PASS for an inaccessible external file, denied network and absence of desktop environment/session bus. The first attempt inside the outer sandbox returned 77; the authorized laboratory run outside that restriction passed. **`twoUidVerified:false`: no users were created and the complete two-real-UID deployment was not demonstrated.** That first laboratory keeps its limited report. The newer laboratory `scripts/two-uid-lab.py` did pass with distinct kernel identities and the production constructor, without the identity exception, with a fresh exec before generating keys and empty supplementary groups. Its `namespaceTwoUidVerified:true` does not mean a production deployment or proof of a real GUI. In the newer laboratory, 77 means the environment is unavailable and 1 a failed control, never passing evidence. See [assurance](assurance.md) (Spanish).

## Audit v2 and checkpoint

`audit-export --schema-version 2` adds `executionId`, `sequence`, `producerId`, `occurredAtUTC` and `observedAtUTC` to the v1 DTO. The execution identifier links intent and outcome; the counter and origin survive restarts through a private `audit-state.json`. The event and write times are host clock readings, not certified time. The sequence may have gaps if a persistence attempt fails; it is never recycled. Exporting v2 from old records lacking those fields fails rather than inventing them. Format v1 remains the default and adds no retroactive dates.

Commands for the custodian's trusted environment only; there is no endpoint for agents:

```sh
umask 077
.venv/bin/agent-credential-broker audit-export --directory DIR --schema-version 2 > EXPORT.jsonl
.venv/bin/agent-credential-broker audit-checkpoint --file EXPORT.jsonl > CHECKPOINT.json
.venv/bin/agent-credential-broker audit-verify --file EXPORT.jsonl --checkpoint CHECKPOINT.json
```

The reference must be transferred and kept outside the control of the custodian/agent, through a trusted human channel. Storing it next to the export under the same UID does not provide that boundary. The tool does not install an independent witness and does not automatically authenticate the origin of the reference.

Specification `sha256-chain-v1`: the initial digest is 32 zero bytes; for each validated JSON event, canonicalize with sorted keys, `,`/`:` separators and escaped ASCII; next digest = SHA256(previous digest + 8-byte big-endian length + canonical bytes). The checkpoint fixes the algorithm, the count and the final digest. It detects semantic changes, reordering or truncation against an intact reference; whitespace or JSON key order do not count as semantic changes. The reader is bounded to 2 MiB, regular files, no links, no group/other write; all DTOs are validated. It uses no signatures or new keys. A custodian/root that also controls the reference can regenerate it; this is not a tamper-proof audit and does not cover events that were never recorded.

## Dependencies and performance

`requirements.lock` pins hashes of official wheels for the three existing runtime dependencies, without updating versions. Download was verified with `pip --isolated download --require-hashes --no-deps -r requirements.lock` on Python 3.12 x86_64. `requirements-build.lock` likewise pins setuptools, wheel and packaging with hashes of official wheels. Install with `pip install --require-hashes -r requirements.lock -r requirements-build.lock`; build the local project with `pip install --no-deps --no-build-isolation .`, using the build tools of the trusted environment. The locks pin Python runtime and build dependencies; they do not pin the interpreter, system or compilers, so hermetic builds are not claimed. PyPI reported no vulnerabilities for those versions on 17 October 2026; that does not prove their absence.

DNS uses at most two disposable processes; a timeout kills and reaps the process, recovering its slot even if libc hangs. It inherits no environment or descriptors from the custodian. Each dispatch re-validates all IPs and pins one for TLS; there is no DNS cache or connection pool. The TLS context is shared while keeping certificate/hostname validation; CA changes require restarting the custodian.

Reproducible local microbenchmark: `.venv/bin/python scripts/benchmark.py`, fictitious data, no provider. Medians from the author's run (machine- and filesystem-dependent; run it to get your own numbers): creating a TLS context 27.38 ms versus reusing one 0.00010 ms; resolving `localhost` in a process 37.81 ms; durable audit event 14.35 ms; durable quota attempt 9.43 ms; peak RSS 34 MiB. The DNS process adds cost in exchange for availability; these figures do not show an overall improvement in HTTPS requests. Keep scrypt, pinning, durability and validation; do not weaken them to improve a benchmark.

## Interpreter and upgrades

Choose a compatible Python ≥ 3.12 installation; Tk is only needed for the GUI. Do not depend on a system alias that may change version after an upgrade. To rebuild, stop the broker, keep or rename **only `.venv`**, create another venv with the chosen interpreter, install `requirements.lock` and `requirements-build.lock` with `--require-hashes`, and the local project with `--no-deps --no-build-isolation`. Keep the vault, grants, quotas and audit in their private directory untouched. If the Python ABI changes, reinstall the appropriate wheels from the lock: do not copy compiled extensions between versions.

The library and the JSON protocol do not depend on Pi, Warp, Codex, a specific model or Agent Observer. The current isolation uses Linux kernel interfaces and Bubblewrap; equivalent security support on macOS or Windows is not claimed. `examples/` contains only fictitious destinations and credentials; adapting a provider does not require modifying the transport or granting arbitrary URLs to the agent.

## Revocation during delivery

The policy re-checks generation, grant, credential version and permission validity after the network and after the final audit. The return under the lock is the authorization point; the mutex is not held during I/O. A revoked result is not delivered; a write that was sent remains uncertain and is not retried. If `ok` was already audited, a `denied/uncertain` correction is appended with the same executionId. v2 consumers must interpret the highest sequence of each producer/execution while keeping the raw events.
