import tempfile
import json
from pathlib import Path
import threading
import time
import unittest

from credential_broker.governance import TaskGrant, QuotaStore
from credential_broker.policy import ActionBroker, PolicyError
from test_policy import action, Vault


class RaceAssuranceTests(unittest.TestCase):
    def test_only_one_concurrent_redemption_can_reach_provider(self):
        entered, release = threading.Event(), threading.Event()
        calls, results = [], []
        def execute(**kwargs):
            calls.append(True); entered.set(); release.wait(2)
            return 200, b'{"state":"ready"}'
        vault = Vault()
        broker = ActionBroker(vault, [action()], 1000, executor=execute)
        plan = broker.plan(1000, {'action': 'status', 'input': {'q': 'safe'}})
        def redeem():
            try: results.append(broker.execute(1000, {'planId': plan['planId']}))
            except PolicyError as error: results.append(error.code)
        first = threading.Thread(target=redeem); first.start()
        self.assertTrue(entered.wait(1))
        second = threading.Thread(target=redeem); second.start(); second.join(1)
        release.set(); first.join(2)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertEqual(len(calls), 1)
        self.assertEqual(vault.calls, 1)
        self.assertIn('PLAN_INVALID', results)
        self.assertEqual(sum(isinstance(item, dict) for item in results), 1)

    def test_revoking_grant_during_intent_audit_prevents_secret_and_network(self):
        entered, release = threading.Event(), threading.Event()
        with tempfile.TemporaryDirectory() as directory:
            grant = TaskGrant({'taskId': 'race-fixture', 'expiresAt': int(time.time()) + 30,
                               'maxUses': 1, 'actions': {'status': {}}}, 1000)
            vault, calls, results = Vault(), [], []
            def audit(event):
                if event['event'] == 'intent': entered.set(); release.wait(2)
            broker = ActionBroker(vault, [action(method='POST', effect='write')], 1000,
                                  task_grant=grant, quota_store=QuotaStore(directory), audit=audit,
                                  approve_host=lambda _: True, executor=lambda **_: calls.append(True))
            plan = broker.plan(1000, {'action': 'status', 'input': {'q': 'safe'}})
            def redeem():
                try: results.append(broker.execute(1000, {'planId': plan['planId']}))
                except PolicyError as error: results.append(error.code)
            worker = threading.Thread(target=redeem); worker.start()
            self.assertTrue(entered.wait(1)); grant.revoke(); release.set(); worker.join(2)
            self.assertEqual(results, ['GRANT_EXPIRED'])
            self.assertEqual(vault.calls, 0); self.assertEqual(calls, [])
            self.assertEqual(broker.plans, {})

    def test_session_revocation_in_flight_discards_read_and_write_results(self):
        for write in (False, True):
            with self.subTest(write=write):
                entered, release = threading.Event(), threading.Event()
                calls, results = [], []
                def execute(**kwargs):
                    calls.append(True); entered.set(); release.wait(2)
                    return 200, b'{"state":"ready"}'
                broker = ActionBroker(Vault(), [action(method='POST' if write else 'GET',
                                                       effect='write' if write else 'read')], 1000,
                                      executor=execute, approve_host=lambda _: True, audit=lambda _: None)
                plan = broker.plan(1000, {'action': 'status', 'input': {'q': 'safe'}})
                def redeem():
                    try: results.append(broker.execute(1000, {'planId': plan['planId']}))
                    except PolicyError as error: results.append(error.code)
                worker = threading.Thread(target=redeem); worker.start()
                self.assertTrue(entered.wait(1)); broker.invalidate_session(); release.set(); worker.join(2)
                self.assertEqual(len(calls), 1)
                self.assertEqual(results, ['OUTCOME_UNCERTAIN' if write else 'AUTHORITY_REVOKED'])
                with self.assertRaises(PolicyError) as error:
                    broker.execute(1000, {'planId': plan['planId']})
                self.assertEqual(error.exception.code, 'PLAN_INVALID')

    def test_final_audit_window_rechecks_every_authority_and_corrects_outcome(self):
        from credential_broker.vault import Vault as RealVault
        for change in ('session', 'grant-replace', 'grant-revoke', 'credential-rotate'):
            for write in (False, True):
                with self.subTest(change=change, write=write), tempfile.TemporaryDirectory() as directory:
                    entered, release = threading.Event(), threading.Event()
                    events, calls, results = [], [], []
                    vault = RealVault.create(Path(directory) / 'fake.vault', b'FAKE_MASTER_PASSWORD_ONLY')
                    vault.put('fixture', b'FAKE_ORIGINAL_KEY_ONLY')
                    doc = {'taskId': 'audit-window-fixture', 'expiresAt': int(time.time()) + 30,
                           'maxUses': 1, 'actions': {'status': {'q': ['safe']}}}
                    grant = TaskGrant(doc, 1000)
                    def audit(event):
                        events.append(event)
                        if event['event'] == 'outcome' and event['status'] == 'ok':
                            entered.set(); release.wait(3)
                    def execute(**kwargs):
                        calls.append(True)
                        return 200, b'{"state":"ready"}'
                    broker = ActionBroker(vault, [action(method='POST' if write else 'GET',
                                                         effect='write' if write else 'read')], 1000,
                                          executor=execute, approve_host=lambda _: True, audit=audit,
                                          task_grant=grant, quota_store=QuotaStore(directory))
                    plan = broker.plan(1000, {'action': 'status', 'input': {'q': 'safe'}})
                    def redeem():
                        try: results.append(broker.execute(1000, {'planId': plan['planId']}))
                        except PolicyError as error: results.append(error.code)
                    worker = threading.Thread(target=redeem); worker.start()
                    try:
                        self.assertTrue(entered.wait(2))
                        if change == 'session': broker.invalidate_session()
                        elif change == 'grant-replace':
                            broker.task_grant = TaskGrant({**doc, 'taskId': 'replacement-fixture'}, 1000)
                        elif change == 'grant-revoke': grant.revoke()
                        else: vault.put('fixture', b'FAKE_REPLACEMENT_KEY_ONLY')
                    finally:
                        release.set(); worker.join(3)
                    expected = ('GRANT_EXPIRED' if change == 'grant-revoke' else
                                'CREDENTIAL_REVOKED' if change == 'credential-rotate' else 'AUTHORITY_REVOKED')
                    self.assertEqual(results, ['OUTCOME_UNCERTAIN' if write else expected])
                    self.assertEqual(events[-1]['status'], 'uncertain' if write else 'denied')
                    self.assertEqual(len({event['executionId'] for event in events}), 1)
                    self.assertEqual(len(calls), 1)
                    ledger = json.loads((Path(directory) / 'quotas.json').read_text())
                    self.assertEqual(ledger['grants'][grant.id], 1)
                    with self.assertRaises(PolicyError) as error:
                        broker.execute(1000, {'planId': plan['planId']})
                    self.assertEqual(error.exception.code, 'PLAN_INVALID')
                    vault.lock()


if __name__ == '__main__': unittest.main()
