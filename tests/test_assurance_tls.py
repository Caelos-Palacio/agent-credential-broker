import json
import os
from pathlib import Path
import ssl
import tempfile
import time
import unittest
from unittest.mock import patch

from assurance_support import TLSFixture
from credential_broker.executor import secure_request, TransportError
from credential_broker.host import AuditLog
from credential_broker.audit_export import export_audit
from credential_broker.governance import TaskGrant, QuotaStore
from credential_broker.policy import ActionBroker
from credential_broker.server import BrokerServer
from credential_broker.cli import call
from credential_broker.vault import Vault
from test_policy import action


class TLSAssuranceTests(unittest.TestCase):
    def request(self, path='/ok', **options):
        return secure_request(method='GET', url='https://fixture.example.test' + path,
                              headers={'Authorization': 'Bearer FAKE_PROVIDER_ONLY_KEY'}, body=None, **options)

    def test_real_tls_pins_dns_address_preserves_host_and_sni(self):
        with TLSFixture() as fixture:
            status, body = self.request()
            self.assertEqual(status, 200)
            self.assertEqual(fixture.connections, [(fixture.pinned_ip, 443)])
            self.assertEqual(fixture.lookup.call_count, 1)
            self.assertEqual(fixture.sni, [fixture.host])
            self.assertEqual(fixture.requests[0]['host'], fixture.host)
            self.assertEqual(fixture.requests[0]['authorization'], 'Bearer FAKE_PROVIDER_ONLY_KEY')

    def test_untrusted_or_wrong_hostname_certificate_never_receives_http_auth(self):
        for mode in ('untrusted', 'hostname'):
            with self.subTest(mode=mode), TLSFixture() as fixture:
                target = 'fixture.example.test' if mode == 'untrusted' else 'wrong.example.test'
                context = ssl.create_default_context() if mode == 'untrusted' else fixture.trust
                with patch('credential_broker.executor._tls_context', return_value=context):
                    with self.assertRaises(TransportError):
                        secure_request(method='GET', url='https://' + target + '/ok',
                                       headers={'Authorization': 'Bearer FAKE_PROVIDER_ONLY_KEY'}, body=None)
                self.assertEqual(fixture.requests, [])

    def test_redirect_is_not_followed_and_no_second_origin_receives_auth(self):
        with TLSFixture() as fixture:
            with self.assertRaises(TransportError) as error:
                self.request('/redirect')
            self.assertEqual(error.exception.code, 'UPSTREAM_REJECTED')
            self.assertEqual(len(fixture.connections), 1)
            self.assertEqual(len(fixture.requests), 1)

    def test_real_header_and_body_stalls_abort_within_deadline(self):
        for path in ('/stall-headers', '/stall-body'):
            with self.subTest(path=path), TLSFixture() as fixture:
                started = time.monotonic()
                with self.assertRaises(TransportError) as error:
                    self.request(path, timeout=.15)
                self.assertEqual(error.exception.code, 'UPSTREAM_TIMEOUT')
                self.assertLess(time.monotonic() - started, 1)
                self.assertEqual(len(fixture.requests), 1)

    def test_real_response_cap_and_production_private_ip_rejection(self):
        with TLSFixture() as fixture:
            with self.assertRaises(TransportError) as error:
                self.request('/oversized', max_bytes=128)
            self.assertEqual(error.exception.code, 'RESPONSE_TOO_LARGE')
            previous = len(fixture.connections)
            fixture.lookup.return_value = ['127.0.0.1']
            with self.assertRaises(TransportError) as error:
                self.request()
            self.assertEqual(error.exception.code, 'DESTINATION_DENIED')
            self.assertEqual(len(fixture.connections), previous)

    def test_unix_broker_vault_governance_audit_and_tls_project_only_safe_output(self):
        import threading
        with tempfile.TemporaryDirectory() as directory, TLSFixture() as fixture:
            root = Path(directory)
            vault = Vault.create(root / 'fake.vault', b'FAKE_MASTER_PASSWORD_ONLY')
            vault.put('fixture', b'FAKE_PROVIDER_ONLY_KEY')
            uid = os.getuid()
            grant = TaskGrant({'taskId': 'tls-assurance-fixture', 'expiresAt': int(time.time()) + 30,
                               'maxUses': 1, 'actions': {'status': {}}}, uid)
            broker = ActionBroker(vault, [action(url='https://fixture.example.test/ok')], uid,
                                  task_grant=grant, quota_store=QuotaStore(root), audit=AuditLog(root))
            server = BrokerServer(root / 'fake.sock', broker, _test_allow_same_uid=True).start()
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            try:
                plan = call(server.path, {'op': 'plan', 'request': {'action': 'status', 'input': {'q': 'safe'}}})['plan']
                output = call(server.path, {'op': 'execute', 'request': {'planId': plan['planId']}})
                self.assertEqual(output, {'ok': True, 'output': {'state': 'ready'}})
                audit = export_audit(root, schema_version=2)
                for visible in (json.dumps(plan), json.dumps(output), audit, (root / 'fake.vault').read_text()):
                    self.assertNotIn('FAKE_PROVIDER_ONLY_KEY', visible)
                self.assertEqual(fixture.requests[0]['authorization'], 'Bearer FAKE_PROVIDER_ONLY_KEY')
                replay = call(server.path, {'op': 'execute', 'request': {'planId': plan['planId']}})
                self.assertEqual(replay['error'], 'PLAN_INVALID')
                self.assertEqual(len(fixture.requests), 1)
            finally:
                server.close(); thread.join(2)


if __name__ == '__main__': unittest.main()
