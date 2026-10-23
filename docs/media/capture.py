"""Capture REAL broker output for the demo GIF.

Runs the real Unix-socket server and the real CLI client in a temporary
directory. Fixture identity (same UID) and a stub provider are used, exactly as
the test suite does; the credential is an obviously fake string and never
leaves the temp directory. Output: docs/media/capture.json
Usage: .venv/bin/python docs/media/capture.py
"""
import io, json, os, subprocess, sys, tempfile, threading
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from credential_broker.cli import main as cli_main
from credential_broker.host import AuditLog
from credential_broker.policy import ActionBroker
from credential_broker.server import BrokerServer
from credential_broker.vault import Vault

FAKE_KEY = b'sk-demo-FAKE-0000-not-a-real-key'
ACTION = json.loads((ROOT / 'examples/actions.json').read_text())[0]  # read_account
PROVIDER_BODY = json.dumps({'id': 'acct_8213', 'plan': 'demo', 'api_key_echo': FAKE_KEY.decode()}).encode()


def run_cli(argv, stdin=None):
    out = io.StringIO()
    old = sys.stdin
    if stdin is not None:
        sys.stdin = io.TextIOWrapper(io.BytesIO(stdin.encode()))
    try:
        with redirect_stdout(out):
            cli_main(argv)
    finally:
        sys.stdin = old
    return out.getvalue().strip()


with tempfile.TemporaryDirectory() as tmp:
    d = Path(tmp)
    os.chmod(d, 0o700)
    vault = Vault.create(d / 'credentials.vault', b'fake-password-only')
    vault.put('demo_key', FAKE_KEY)
    seen = {}
    def stub(**kw):
        seen['authorization_sent_to_provider'] = kw['headers']['Authorization'].startswith('Bearer sk-demo')
        return 200, PROVIDER_BODY
    broker = ActionBroker(vault, [ACTION], os.getuid(), executor=stub, audit=AuditLog(d))
    server = BrokerServer(d / 'broker.sock', broker, _test_allow_same_uid=True).start()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    sock = str(server.path)
    steps = []
    def agent(req):
        line = json.dumps(req, separators=(',', ':'))
        steps.append({'in': line, 'out': run_cli(['call', '--socket', sock], line + '\n')})
        return json.loads(steps[-1]['out'])
    agent({'op': 'capabilities'})
    plan = agent({'op': 'plan', 'request': {'action': 'read_account', 'input': {}}})['plan']
    agent({'op': 'execute', 'request': {'planId': plan['planId']}})
    server.close(); vault.lock()
    audit = run_cli(['audit-export', '--directory', str(d)])
    blob = json.dumps(steps) + audit
    assert FAKE_KEY.decode() not in blob, 'fake key leaked to agent side'
    assert seen['authorization_sent_to_provider']
    Path(ROOT / 'docs/media/capture.json').write_text(json.dumps(
        {'fakeKey': FAKE_KEY.decode(), 'steps': steps, 'audit': audit.splitlines(),
         'providerBody': PROVIDER_BODY.decode()}, indent=1) + '\n')
    print('ok', len(steps), 'steps,', len(audit.splitlines()), 'audit lines')
