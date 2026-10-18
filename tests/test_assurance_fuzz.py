import json
import os
from pathlib import Path
import random
import socket
import tempfile
import threading
import unittest

from credential_broker.policy import ActionBroker, PolicyError
from credential_broker.server import BrokerServer, MAX_MESSAGE
from test_policy import action, Vault


SEED = 0xA551


class FuzzAssuranceTests(unittest.TestCase):
    def test_seeded_malformed_frames_never_invoke_vault_or_provider(self):
        rng = random.Random(SEED)
        vault, calls = Vault(), []
        vault.lock = lambda: None  # Synthetic transport fixture has no resident keys.
        broker = ActionBroker(vault, [action()], os.getuid(), executor=lambda **_: calls.append(True))
        frames = [b'{"op":"status","op":"execute"}\n', b'{"op":NaN}\n', b'\xff\n',
                  b'x' * (MAX_MESSAGE + 1) + b'\n', b'{"op":"status"}\n{"op":"status"}\n']
        for _ in range(128):
            value = {'op': 'invalid_' + str(rng.getrandbits(32)), 'password': 'SYNTHETIC_FRAME_SENTINEL',
                     'request': rng.choice([None, [], True, rng.randrange(-1000, 1000), {'nested': [1, 2]}])}
            frames.append(json.dumps(value).encode() + b'\n')
        with tempfile.TemporaryDirectory() as directory:
            server = BrokerServer(Path(directory) / 'fixture.sock', broker, _test_allow_same_uid=True).start()
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            try:
                for frame in frames:
                    with socket.socket(socket.AF_UNIX) as conn:
                        conn.settimeout(2); conn.connect(str(server.path))
                        try:
                            conn.sendall(frame)
                            reply = conn.recv(MAX_MESSAGE)
                        except (BrokenPipeError, ConnectionResetError):
                            continue
                        self.assertNotIn(b'SYNTHETIC_FRAME_SENTINEL', reply)
                        self.assertFalse(json.loads(reply)['ok'])
                self.assertEqual(vault.calls, 0); self.assertEqual(calls, [])
                self.assertEqual(broker.plans, {})
            finally:
                server.close(); thread.join(2)

    def test_seeded_provider_output_is_closed_by_allowlist_not_redaction_guessing(self):
        rng = random.Random(SEED)
        values = [None, True, 1, {}, [], 'ready', 'ok', 'SYNTHETIC_OUTPUT_SENTINEL']
        values += [''.join(rng.choice('abcXYZ012_-') for _ in range(rng.randrange(0, 120))) for _ in range(128)]
        for value in values:
            body = json.dumps({'state': value, 'token': 'SYNTHETIC_OUTPUT_SENTINEL'}).encode()
            broker = ActionBroker(Vault(), [action()], 1000, executor=lambda **_: (200, body))
            plan = broker.plan(1000, {'action': 'status', 'input': {'q': 'safe'}})
            if type(value) is str and value in ('ready', 'ok'):
                result = broker.execute(1000, {'planId': plan['planId']})
                self.assertEqual(result, {'ok': True, 'output': {'state': value}})
                self.assertNotIn('SYNTHETIC_OUTPUT_SENTINEL', json.dumps(result))
            else:
                with self.assertRaises(PolicyError) as error:
                    broker.execute(1000, {'planId': plan['planId']})
                self.assertNotIn('SYNTHETIC_OUTPUT_SENTINEL', error.exception.code)


if __name__ == '__main__': unittest.main()
