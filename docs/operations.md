# Operating the custodian

> Spanish original: [es/operations.md](es/operations.md)

This describes a setup that has **not** been applied to any machine yet. The project creates no users, groups or services.

## Required separation

1. The custodian runs the GUI on its trusted desktop. The agent runs under a different, unprivileged UID; it cannot edit the custodian's code, venv, catalog or vault. It must have no sudo, no inspection capabilities, no ptrace access and no broad groups.
2. An administrator configures a dedicated group shared only for IPC and a socket directory owned by the custodian, with no write access for group or others. Example permissions: directory 0750 with the dedicated group, socket 0660. The agent can traverse the directory and connect to the socket but cannot replace it. The custodian must belong to the GID selected in the GUI.
3. The vault stays in **another 0700 directory** of the custodian, out of the agent's reach. Do not place the socket inside that directory in a cross-UID deployment: its permissions would prevent connecting. The GUI's initial value is a staging path; change it to the configured IPC directory before serving.
4. The agent sandbox receives none of the custodian's HOME, DISPLAY, WAYLAND_DISPLAY, XAUTHORITY, session D-Bus, Docker/SSH/GPG sockets, config files or process access. Disable screen capture, accessibility and desktop automation from the agent, as well as any shell that could recover them. The password field's masking dots do not do this on their own.
5. The agent also cannot edit the package or use the private test constructor to change identity. There is no remote switch that relaxes these restrictions.

For stronger isolation, run the custodian on another trusted machine or VM with a restricted channel; this release only supports local Unix transport. Do not improvise network/TCP by putting a proxy in front: that needs a new identity model and review.

## Human input

Run `.venv/bin/python -m credential_broker.cli gui` as the custodian. Create a new vault or unlock one by typing the master password (minimum 12 UTF-8 bytes). Store the secret under an approved alias. The interface clears the fields after use and has no copy/export. Manual entry or pasting from a trusted human source is supported; the broker never reads the clipboard.

Prepare a 0600 JSON catalog outside the agent's reach. `examples/actions.json` is illustrative and connects to no real service. Each action fixes the method, the HTTPS URL on port 443, the alias, the schema and the response fields. Every action requires a strict `outputSchema`: types, required fields and limits; strings need an enum or a simple anchored pattern and a maximum length. Prefer bounded states/identifiers over free text. The only variable URL values allowed are encoded query placeholders; paths and hosts stay fixed. `auth` is `bearer` or `basic`; for Basic, the stored credential is `user:password`.

Saving credentials is blocked while the service is running: to replace one, lock/stop, unlock, save and restart. This invalidates plans prepared with the previous identity. Your own Python integration must keep the same rule; do not modify entries of the Vault object while an ActionBroker is active.

In the GUI, specify the agent UID, the dedicated GID, the socket path and the catalog, then start the service. The agent asks for capabilities, prepares a plan and executes its identifier. For a write, the GUI shows the real plan and the person authorizes once or rejects. With no answer within 25 s, it is rejected. Plans expire after 60 s and cannot be replayed, even after failures.

## Locking, stopping and recovery

Locking and stopping revoke plans and close the vault; closing the window does the same. The GUI and the server lock after five minutes of inactivity. An in-flight HTTPS request may have reached the provider before the lock; an operation already issued is not undone. After a write timeout, check the state through an authorized read action: do not retry blindly.

This version has no password recovery, automatic rotation, OAuth, hardware authentication, or per-credential revocation from the GUI. Locking the service prevents later use. Editing or deleting an entry needs a future administrative feature or a reviewed migration; do not use file access from the agent.

Back up only the encrypted vault, with 0600 permissions and the password kept through a separate human channel. Do not version vault files, catalogs containing personal data, or logs. The v1 format has fixed cryptographic parameters validated before key derivation.

## Audit and Observer

`audit.jsonl` contains only a random event identifier, the type `execute|intent|outcome`, a truncated hash of the action ID, the status `intent|ok|denied|uncertain` and a bounded duration. It does not contain the UID, alias, values, bodies, URLs or provider messages. It rotates to `audit.previous.jsonl` on reaching 256 KiB; the new file may exceed the threshold by one line. Before a write, the attempt must be persisted with `fsync` of the file and directory, including creation/rotation: on failure it returns `AUDIT_UNAVAILABLE` without touching the credential or the network. If logging after sending the write fails, it returns `OUTCOME_UNCERTAIN` with no response and no retry. Read auditing is best effort.

The vault does not depend on Observer. Exporting this metadata to Observer is a separate custodian step, never access to the vault directory. Do not read it from the agent's UID. Action-ID hashes help correlation but are not anonymity or a tamper-proof audit.

The custodian can run this in its trusted environment, outside the agent:

```sh
umask 077
.venv/bin/agent-credential-broker audit-export --directory /private/custodian/dir > /exchange/dir/broker-audit.jsonl
```

Prepare the exchange destination so that Observer can read only that exported file. The command configures no permissions or groups. Never share the custodian's private directory.

The exporter opens only `audit.previous.jsonl` and `audit.jsonl`, with no links or symlinked ancestors; it verifies owner, 0600 permissions, a single link, regular file type and a maximum size of 262656 bytes per file. It projects exact JSONL: `schemaVersion:1`, `source:"agent-credential-broker"`, `eventId`, `event`, `actionIdHash`, `status`, `durationMs`. It validates everything before emitting events; on error it prints a fixed code and exits 1, and that output must not be imported. The agent transport has no such operation.

New `eventId` values stay the same when copied and rotated, so imports can deduplicate. Old records without an identifier use a hash of device, inode, position and bytes: stable when the same file rotates, but not guaranteed when copied. There is no original execution time; Observer must distinguish its own import time. IDs and hashes give no cryptographic integrity against the custodian or root. The two-file window does not retain history indefinitely.

Optional integration with [Agent Observer](https://github.com/Caelos-Palacio/agent-observer), from its checkout and under its separate identity:

```sh
node /path/to/agent-observer/src/cli.mjs import-broker-audit --file /exchange/dir/broker-audit.jsonl --database /observer/dir/events.sqlite
node /path/to/agent-observer/src/cli.mjs review --source broker --database /observer/dir/events.sqlite
```

The full path was verified with three synthetic events: three imported, zero duplicates on repeat, two executions and one denial. No real vault was opened. Importing does not demonstrate isolation between UIDs and does not turn a local audit into tamper-proof evidence.
