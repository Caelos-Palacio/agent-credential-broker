"""Public synthetic counterexamples and differential lifecycle exploration."""
import copy
import itertools
import json
from pathlib import Path
import tempfile
import unittest

from credential_broker.governance import QuotaStore, TaskGrant
from credential_broker.policy import ActionBroker, PolicyError
from lifecycle_spec import Observation, predict
from test_policy import Vault, action


class SemanticLifecycleTests(unittest.TestCase):
    def test_grant_document_is_an_inspection_snapshot_not_an_update_channel(self):
        document = {'taskId': 'snapshot-fixture', 'expiresAt': 200, 'maxUses': 1,
                    'actions': {'status': {'q': ['safe']}}}
        grant = TaskGrant(document, 1000, clock=lambda: 100)
        original_id = grant.id
        document['actions']['status']['q'].append('another')
        inspection = grant.document
        inspection['actions']['status']['q'].append('another')
        inspection['maxUses'] = 100
        self.assertEqual(grant.document['maxUses'], 1)
        self.assertEqual(grant.id, original_id)
        from credential_broker.governance import GovernanceError
        with self.assertRaises(GovernanceError):
            grant.check(1000, 'status', {'q': 'another'})
        grant.check(1000, 'status', {'q': 'safe'})

    def test_reissued_identical_document_does_not_resurrect_old_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            doc = {'taskId': 'reissue-fixture', 'expiresAt': 200, 'maxUses': 1, 'actions': {'status': {}}}
            grant = TaskGrant(doc, 1000, clock=lambda: 100)
            broker = ActionBroker(Vault(), [action()], 1000, task_grant=grant,
                                  quota_store=QuotaStore(directory),
                                  executor=lambda **_: (200, b'{"state":"ready"}'))
            request = {'action': 'status', 'input': {'q': 'safe'}}
            old = broker.plan(1000, request)
            grant.revoke()
            broker.task_grant = TaskGrant(doc, 1000, clock=lambda: 100)
            self.assertEqual(grant.id, broker.task_grant.id)  # Durable quota namespace stays stable.
            with self.assertRaises(PolicyError) as rejected:
                broker.execute(1000, {'planId': old['planId']})
            self.assertEqual(rejected.exception.code, 'GRANT_CHANGED')
            self.assertFalse((Path(directory) / 'quotas.json').exists())
            fresh = broker.plan(1000, request)
            self.assertTrue(broker.execute(1000, {'planId': fresh['planId']})['ok'])
            broker.task_grant = TaskGrant(doc, 1000, clock=lambda: 100)
            exhausted = broker.plan(1000, request)
            with self.assertRaises(PolicyError) as rejected:
                broker.execute(1000, {'planId': exhausted['planId']})
            self.assertEqual(rejected.exception.code, 'PERSISTENT_QUOTA_EXCEEDED')

    def test_replacement_at_reservation_never_charges_new_grant(self):
        with tempfile.TemporaryDirectory() as directory:
            doc = {'taskId': 'first', 'expiresAt': 200, 'maxUses': 1, 'actions': {'status': {}}}
            original = TaskGrant(doc, 1000, clock=lambda: 100)
            replacement = TaskGrant({**doc, 'taskId': 'second'}, 1000, clock=lambda: 100)
            store = QuotaStore(directory)
            seen = []
            class SwappingStore:
                def consume(self, snapshot, ref, limit):
                    # Boundary after validation but before durable reservation.
                    broker.task_grant = replacement
                    seen.append(snapshot.id)
                    store.consume(snapshot, ref, limit)
            vault = Vault()
            broker = ActionBroker(vault, [action()], 1000, task_grant=original,
                                  quota_store=SwappingStore(), audit=lambda _: None,
                                  executor=lambda **_: self.fail('old plan dispatched'))
            plan = broker.plan(1000, {'action': 'status', 'input': {'q': 'safe'}})
            with self.assertRaises(PolicyError):
                broker.execute(1000, {'planId': plan['planId']})
            self.assertEqual(seen, [original.id])
            self.assertEqual(json.loads((Path(directory) / 'quotas.json').read_text())['grants'], {original.id: 1})
            self.assertEqual(vault.calls, 0)

    def test_semantic_mutations_with_unchanged_action_id_are_not_authority(self):
        base = {'q': 'alpha', 'count': 2, 'unit': 'items', 'healthy': True, 'enabled': True}
        properties = {'q': {'type': 'string', 'maxLength': 20},
                      'count': {'type': 'integer', 'minimum': 1, 'maximum': 2},
                      'unit': {'type': 'string', 'enum': ['items', 'seconds']},
                      'healthy': {'type': 'boolean'}, 'enabled': {'type': 'boolean'}}
        mutations = {
            'actor': ('uid', 1001), 'target': ('credentialRef', 'another'),
            'scope': ('q', 'beta'), 'approval': ('approved', False),
            'unit': ('unit', 'seconds'), 'comparator': ('count', 3),
            'condition': ('healthy', False), 'negation': ('enabled', False),
            'exception': ('exceptions', [1001]), 'id_unchanged': ('q', 'beta'),
            'autoauthority_update': ('authority_update', {'allow': True}),
            'order': ('audit_fail', True),
        }
        for family in ('authorized', *mutations):
            with self.subTest(family=family), tempfile.TemporaryDirectory() as directory:
                request = {'action': 'status', 'input': copy.deepcopy(base)}
                uid, approved, audit_fail = 1000, True, False
                if family != 'authorized':
                    field, value = mutations[family]
                    if field == 'uid': uid = value
                    elif field == 'approved': approved = value
                    elif field == 'audit_fail': audit_fail = value
                    elif field in base: request['input'][field] = value
                    else: request[field] = value
                config = action(method='POST', effect='write', inputSchema={
                    'type': 'object', 'properties': properties, 'required': list(properties)})
                grant = TaskGrant({'taskId': 'semantic-fixture', 'expiresAt': 200, 'maxUses': 1,
                                   'actions': {'status': {key: [value] for key, value in base.items()}}},
                                  1000, clock=lambda: 100)
                calls, events = [], []
                vault = Vault()
                def audit(event):
                    if audit_fail: raise OSError('SYNTHETIC_AUDIT_FAILURE')
                    events.append(event['status'])
                def execute(**request):
                    calls.append(request)
                    return 200, b'{"state":"ready","authority_update":{"allow":true},"exceptions":[1001]}'
                broker = ActionBroker(vault, [config], 1000, task_grant=grant,
                                      quota_store=QuotaStore(directory), approve_host=lambda _: approved,
                                      executor=execute, audit=audit)
                result = None
                try:
                    plan = broker.plan(uid, request)
                    result = broker.execute(uid, {'planId': plan['planId']})
                except PolicyError:
                    pass
                if family == 'authorized':
                    self.assertEqual(result, {'ok': True, 'output': {'state': 'ready'}})
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(events, ['intent', 'ok'])
                else:
                    self.assertIsNone(result)
                    self.assertEqual(calls, [])
                    self.assertEqual(vault.calls, 0)

    def test_approval_review_and_request_cannot_rewrite_dispatch(self):
        captured = []
        def approve(review):
            review['destination'] = 'https://another.example.test/never'
            review['input']['q'] = 'another'
            return True
        broker = ActionBroker(Vault(), [action(method='POST', effect='write')], 1000,
                              approve_host=approve, audit=lambda _: None,
                              executor=lambda **request: (captured.append(request) or (200, b'{"state":"ready"}')))
        request = {'action': 'status', 'input': {'q': 'safe'}}
        plan = broker.plan(1000, request)
        request['input']['q'] = 'another'
        broker.execute(1000, {'planId': plan['planId']})
        self.assertEqual(captured[0]['url'], 'https://example.com/v1/status?q=safe')
        self.assertEqual(json.loads(captured[0]['body']), {'q': 'safe'})

    def test_finite_lifecycle_matches_real_broker(self):
        cases = successes = uncertain = 0
        changes = ('none', 'session', 'revoke', 'replace', 'reissue', 'version', 'plan_time', 'grant_time', 'audit')
        for write, approved, available in itertools.product((False, True), repeat=3):
            phases = ('before', 'upstream', 'outcome') + (('approval', 'intent') if write else ())
            for phase, change in itertools.product(phases, changes):
                with self.subTest(write=write, approved=approved, available=available, phase=phase, change=change):
                    actual = self.observe(write, approved, available, phase, change)
                    expected = predict(write, approved, available, phase, change)
                    self.assertEqual(actual, expected)
                    cases += 1; successes += actual.delivered; uncertain += actual.uncertain
        self.assertEqual(cases, 288)
        self.assertGreater(successes, 0)  # A deny-all implementation fails refinement.
        self.assertGreater(uncertain, 0)

    def observe(self, write, approved, available, phase, change):
        with tempfile.TemporaryDirectory(prefix='broker-semantic-fixture-') as directory:
            mono, wall = [0], [100]
            doc = {'taskId': 'synthetic-lifecycle', 'expiresAt': 200, 'maxUses': 1,
                   'actions': {'status': {'q': ['safe']}}}
            grant = TaskGrant(doc, 1000, clock=lambda: wall[0])
            quota = QuotaStore(directory, clock=lambda: wall[0])
            if not available:
                quota.consume(grant, 'fixture', 60)
            calls, events, trace = [], [], []
            audit_broken = [False]
            def at(barrier):
                if phase != barrier:
                    return
                if change == 'session': broker.invalidate_session()
                elif change == 'revoke': grant.revoke()
                elif change == 'replace':
                    broker.task_grant = TaskGrant({**doc, 'taskId': 'replacement'}, 1000, clock=lambda: wall[0])
                elif change == 'reissue':
                    grant.revoke()
                    broker.task_grant = TaskGrant(doc, 1000, clock=lambda: wall[0])
                elif change == 'version': broker.credential_versions['fixture'] = 1
                elif change == 'plan_time': mono[0] = 60
                elif change == 'grant_time': wall[0] = 200
                elif change == 'audit': audit_broken[0] = True
            def approval(review):
                at('approval')
                return approved
            def audit(event):
                at('intent' if event['event'] == 'intent' else 'outcome')
                if audit_broken[0]:
                    raise OSError('SYNTHETIC_AUDIT_FAILURE')
                events.append(event)
                trace.append('audit:' + event['status'])
            def upstream(**request):
                trace.append('dispatch')
                calls.append(True); at('upstream')
                return 200, b'{"state":"ready"}'
            broker = ActionBroker(Vault(), [action(method='POST' if write else 'GET',
                                                   effect='write' if write else 'read')], 1000,
                                  clock=lambda: mono[0], approve_host=approval, audit=audit,
                                  task_grant=grant, quota_store=quota, executor=upstream)
            plan = broker.plan(1000, {'action': 'status', 'input': {'q': 'safe'}})
            at('before')
            delivered, is_uncertain = False, False
            try:
                result = broker.execute(1000, {'planId': plan['planId']})
                self.assertEqual(result, {'ok': True, 'output': {'state': 'ready'}})
                delivered = True
            except PolicyError as error:
                is_uncertain = error.code == 'OUTCOME_UNCERTAIN'
            with self.assertRaises(PolicyError) as replay:
                broker.execute(1000, {'planId': plan['planId']})
            self.assertEqual(replay.exception.code, 'PLAN_INVALID')
            ledger = Path(directory) / 'quotas.json'
            total = sum(json.loads(ledger.read_text())['grants'].values()) if ledger.exists() else 0
            if write and calls:
                self.assertLess(trace.index('audit:intent'), trace.index('dispatch'))
            if delivered and write:
                self.assertLess(trace.index('dispatch'), trace.index('audit:ok'))
            if not audit_broken[0] and calls:
                self.assertEqual(events[-1]['status'], 'ok' if delivered else 'uncertain' if write else 'denied')
            return Observation(delivered, len(calls), total - (not available), is_uncertain)


if __name__ == '__main__':
    unittest.main()
