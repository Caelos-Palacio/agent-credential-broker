import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from credential_broker.server import BrokerServer, ServerError
from credential_broker.cli import call
from credential_broker.policy import ActionBroker
from credential_broker.vault import Vault

ACTION = {'id':'read_account','credentialRef':'demo_key','method':'GET',
          'url':'https://example.com/account','inputSchema':{'type':'object','properties':{}},
          'effect':'read','responseFields':['id'],
          'outputSchema':{'type':'object','properties':{'id':{'type':'string','pattern':'^[0-9]{1,10}$','maxLength':10}},'required':['id'],'additionalProperties':False}}

class TransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.vault = Vault.create(self.directory/'credentials.vault', b'fake-password-only')
        self.vault.put('demo_key', b'fake-credential-only')
        self.broker = ActionBroker(self.vault, [ACTION], os.getuid(),
                                   executor=lambda **_: (200, b'{"id":"123","token":"hidden"}'))
        self.server = None
    def tearDown(self):
        if self.server:
            self.server.close()
        self.vault.lock()
        self.temp.cleanup()
    def start(self, broker=None, idle=300):
        self.server = BrokerServer(self.directory/'broker.sock', broker or self.broker,
                                   idle_seconds=idle, _test_allow_same_uid=True).start()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return str(self.server.path)
    def test_production_same_uid_is_rejected(self):
        with self.assertRaisesRegex(ServerError, 'SEPARATE_AGENT_UID_REQUIRED'):
            BrokerServer(self.directory/'a.sock', self.broker)
    def test_kernel_peer_rejected_even_if_payload_claims_uid(self):
        self.broker.allowed_uid = os.getuid()+1
        path = self.start()
        try:
            reply = call(path, {'op':'status','uid':os.getuid()+1})
        except (BrokenPipeError, ConnectionResetError):
            # Kernel identity can be refused before the peer sends its frame.
            pass
        else:
            self.assertEqual(reply['error'], 'PRINCIPAL_DENIED')
        self.assertEqual(self.broker.count, 0)
        self.assertEqual(self.broker.plans, {})
    def test_real_unix_plan_execute_and_replay(self):
        path = self.start()
        plan = call(path, {'op':'plan','request':{'action':'read_account','input':{}}})['plan']
        result = call(path, {'op':'execute','request':{'planId':plan['planId']}})
        self.assertEqual(result, {'ok':True,'output':{'id':'123'}})
        self.assertEqual(call(path, {'op':'execute','request':{'planId':plan['planId']}})['error'], 'PLAN_INVALID')
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o660)
    def test_write_requires_durable_intent_and_projects_result(self):
        from credential_broker.host import AuditLog
        action=dict(ACTION, method='POST', effect='write')
        self.broker=ActionBroker(self.vault,[action],os.getuid(),approve_host=lambda _:True,
            audit=AuditLog(self.directory),executor=lambda **_:(200,b'{"id":"456","debug":"fake-credential-only"}'))
        path=self.start()
        plan=call(path,{'op':'plan','request':{'action':'read_account','input':{}}})['plan']
        self.assertEqual(call(path,{'op':'execute','request':{'planId':plan['planId']}}),{'ok':True,'output':{'id':'456'}})
        events=[json.loads(line) for line in (self.directory/'audit.jsonl').read_text().splitlines()]
        self.assertEqual([e['event'] for e in events],['intent','outcome'])
        self.assertEqual([e['status'] for e in events],['intent','ok'])
        self.assertNotIn('fake-credential',json.dumps(events))
    def test_admin_and_secret_get_are_never_exposed(self):
        path = self.start()
        for op in ('getSecret','unlock','put','export','exec'):
            reply = call(path, {'op':op,'request':{}})
            self.assertEqual(reply['error'],'OPERATION_DENIED')
    def test_duplicate_json_and_oversize_rejected(self):
        path = self.start()
        for payload in (b'{"op":"status","op":"execute"}\n', b'x'*16385+b'\n'):
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                client.settimeout(2); client.connect(path); client.sendall(payload)
                self.assertFalse(json.loads(client.recv(4096))['ok'])
    def test_preexisting_socket_path_never_deleted(self):
        path = self.directory/'existing.sock'; path.write_text('keep')
        server = BrokerServer(path,self.broker,_test_allow_same_uid=True)
        with self.assertRaises(ServerError): server.start()
        self.assertEqual(path.read_text(),'keep')
    def test_close_revokes_and_locks(self):
        self.start(); self.server.close()
        with self.assertRaisesRegex(Exception,'vault_locked'):
            self.vault.list_aliases()
    def test_idle_auto_lock(self):
        self.start(idle=1); self.thread.join(3)
        self.assertFalse(self.thread.is_alive())
        with self.assertRaisesRegex(Exception,'vault_locked'):
            self.vault.list_aliases()

if __name__ == '__main__': unittest.main()
