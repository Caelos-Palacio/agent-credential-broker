import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock
from credential_broker.governance import TaskGrant, QuotaStore, GovernanceError
from credential_broker.policy import ActionBroker, PolicyError
from test_policy import action, Vault


def document(**changes):
    value = {'taskId': 'fixture-task', 'expiresAt': 2000, 'maxUses': 2,
             'actions': {'status': {'q': ['allowed']}}}
    value.update(changes)
    return value


class GovernanceTests(unittest.TestCase):
    def test_host_grant_rejects_resource_uid_expiry_and_revocation(self):
        grant = TaskGrant(document(), 1000, clock=lambda: 1000)
        grant.check(1000, 'status', {'q': 'allowed'})
        for uid, act, data in [(1001, 'status', {'q': 'allowed'}),
                               (1000, 'other', {}), (1000, 'status', {'q': 'other'})]:
            with self.assertRaises(GovernanceError):
                grant.check(uid, act, data)
        grant.revoke()
        with self.assertRaises(GovernanceError):
            grant.check(1000, 'status', {'q': 'allowed'})
        with self.assertRaises(GovernanceError):
            TaskGrant(document(expiresAt=999), 1000, clock=lambda: 1000).check(1000, 'status', {})

    def test_persistent_task_and_hourly_quotas_survive_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            grant = TaskGrant(document(), 1000, clock=lambda: 1000)
            QuotaStore(directory, clock=lambda: 1000).consume(grant, 'fake-ref', 5)
            QuotaStore(directory, clock=lambda: 1000).consume(grant, 'fake-ref', 5)
            with self.assertRaisesRegex(GovernanceError, 'PERSISTENT_QUOTA_EXCEEDED'):
                QuotaStore(directory, clock=lambda: 1000).consume(grant, 'fake-ref', 5)
            new_grant = TaskGrant(document(taskId='another'), 1000, clock=lambda: 1000)
            with self.assertRaisesRegex(GovernanceError, 'PERSISTENT_QUOTA_EXCEEDED'):
                QuotaStore(directory, clock=lambda: 1000).consume(new_grant, 'fake-ref', 2)
            self.assertNotIn('fake-ref', (Path(directory) / 'quotas.json').read_text())
            self.assertEqual((Path(directory) / 'quotas.json').stat().st_mode & 0o777, 0o600)

    def test_quota_corruption_permissions_and_symlink_fail_closed(self):
        for mode in ('invalid', 'permissions', 'symlink'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / 'quotas.json'
                if mode == 'symlink':
                    target.symlink_to(Path(directory) / 'vault')
                else:
                    target.write_text('{}')
                    target.chmod(0o644 if mode == 'permissions' else 0o600)
                with self.assertRaises(GovernanceError):
                    QuotaStore(directory).consume(TaskGrant(document(), 1000), 'fake', 2)

    def test_policy_does_not_accept_self_declared_task_and_rechecks_before_network(self):
        with tempfile.TemporaryDirectory() as directory:
            grant = TaskGrant(document(), 1000, clock=lambda: 1000)
            vault = Vault()
            execute = Mock(return_value=(200, b'{"state":"ready"}'))
            broker = ActionBroker(vault, [action()], 1000, executor=execute,
                                  task_grant=grant, quota_store=QuotaStore(directory))
            for request in ({'action': 'status', 'input': {'q': 'allowed'}, 'taskId': 'other'},
                            {'action': 'status', 'input': {'q': 'other'}}):
                with self.assertRaises(PolicyError):
                    broker.plan(1000, request)
            plan = broker.plan(1000, {'action': 'status', 'input': {'q': 'allowed'}})
            grant.revoke()
            with self.assertRaises(PolicyError):
                broker.execute(1000, {'planId': plan['planId']})
            execute.assert_not_called()
            self.assertEqual(vault.calls, 0)

    def test_concurrent_quota_consumption_has_no_lost_update(self):
        with tempfile.TemporaryDirectory() as directory:
            grant = TaskGrant(document(maxUses=1), 1000)
            results = []
            def consume():
                try:
                    QuotaStore(directory).consume(grant, 'fake', 5)
                    results.append(True)
                except GovernanceError:
                    results.append(False)
            threads = [threading.Thread(target=consume) for _ in range(4)]
            for thread in threads: thread.start()
            for thread in threads: thread.join(2)
            self.assertEqual(results.count(True), 1)

    def test_alias_rotation_invalidates_pending_plan_and_inflight_result(self):
        from credential_broker.vault import Vault as RealVault, VaultError
        with tempfile.TemporaryDirectory() as directory:
            vault = RealVault.create(Path(directory) / 'fixture.vault', b'fake-password-only')
            vault.put('fixture', b'fake-first-key')
            execute = Mock(return_value=(200, b'{"state":"ready"}'))
            broker = ActionBroker(vault, [action()], 1000, executor=execute)
            plan = broker.plan(1000, {'action': 'status', 'input': {'q': 'allowed'}})
            vault.put('fixture', b'fake-replacement-key')
            with self.assertRaises(PolicyError):
                broker.execute(1000, {'planId': plan['planId']})
            execute.assert_not_called()
            def rotate(_):
                vault.put('fixture', b'fake-third-key')
                return 'result-must-be-discarded'
            with self.assertRaisesRegex(VaultError, 'credential_changed'):
                vault.use('fixture', rotate)
            plan = broker.plan(1000, {'action': 'status', 'input': {'q': 'allowed'}})
            broker.revoke_credential('fixture')
            with self.assertRaises(PolicyError):
                broker.execute(1000, {'planId': plan['planId']})
            self.assertEqual(vault.list_aliases(), [])
            vault.lock()

    def test_uncertain_write_consumes_persistent_quota_without_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            grant = TaskGrant(document(maxUses=1), 1000, clock=lambda: 1000)
            execute = Mock(side_effect=TimeoutError())
            def broker():
                return ActionBroker(Vault(), [action(method='POST', effect='write', url='https://example.com/x')], 1000,
                                    executor=execute, approve_host=lambda _: True, audit=lambda _: None,
                                    task_grant=grant, quota_store=QuotaStore(directory))
            first = broker()
            plan = first.plan(1000, {'action': 'status', 'input': {'q': 'allowed'}})
            with self.assertRaises(PolicyError) as error:
                first.execute(1000, {'planId': plan['planId']})
            self.assertEqual(error.exception.code, 'OUTCOME_UNCERTAIN')
            second = broker()
            plan = second.plan(1000, {'action': 'status', 'input': {'q': 'allowed'}})
            with self.assertRaises(PolicyError) as error:
                second.execute(1000, {'planId': plan['planId']})
            self.assertEqual(error.exception.code, 'PERSISTENT_QUOTA_EXCEEDED')
            self.assertEqual(execute.call_count, 1)


if __name__ == '__main__':
    unittest.main()
