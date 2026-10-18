import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from credential_broker.governance import TaskGrant, QuotaStore, GovernanceError
from credential_broker.host import AuditLog
from credential_broker.audit_export import export_audit


CHILD = r'''
import json,os,sys
sys.path.insert(0,sys.argv[1])
from credential_broker.governance import TaskGrant,QuotaStore,GovernanceError
from credential_broker.host import AuditLog
directory,document,mode=sys.argv[2:]
grant=TaskGrant(json.loads(document),1000)
if mode=='audit':
 AuditLog(directory)({'event':'intent','actionIdHash':'a'*16,'status':'intent','durationMs':1})
 os._exit(74)
if mode=='after-replace':
 original=os.replace
 def replace(*args,**kwargs):
  original(*args,**kwargs)
  if args[1]=='quotas.json':os._exit(72)
 os.replace=replace
if mode=='fail-sync':
 def fail(*args):raise OSError('SYNTHETIC_STORAGE_FAULT')
 os.fsync=fail
try:QuotaStore(directory).consume(grant,'synthetic-ref',100)
except GovernanceError as error:sys.exit(3 if str(error)=='PERSISTENT_QUOTA_EXCEEDED' else 73)
os._exit(71 if mode=='after-commit' else 0)
'''


class CrashAssuranceTests(unittest.TestCase):
    def command(self, directory, document, mode):
        return [sys.executable, '-I', '-c', CHILD, str(Path(__file__).resolve().parents[1]),
                directory, json.dumps(document), mode]

    def grant(self, **changes):
        return {'taskId': 'crash-fixture', 'expiresAt': int(time.time()) + 30,
                'maxUses': 1, 'actions': {'fixture': {}}, **changes}

    def test_process_death_after_commit_or_replace_preserves_consumed_quota(self):
        for mode, expected in [('after-commit', 71), ('after-replace', 72)]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                doc = self.grant()
                result = subprocess.run(self.command(directory, doc, mode), capture_output=True, timeout=5)
                self.assertEqual(result.returncode, expected)
                with self.assertRaisesRegex(GovernanceError, 'PERSISTENT_QUOTA_EXCEEDED'):
                    QuotaStore(directory).consume(TaskGrant(doc, 1000), 'synthetic-ref', 100)

    def test_storage_failure_cannot_publish_quota_or_leave_temporary_files(self):
        with tempfile.TemporaryDirectory() as directory:
            doc = self.grant()
            result = subprocess.run(self.command(directory, doc, 'fail-sync'), capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 73)
            self.assertFalse((Path(directory) / 'quotas.json').exists())
            self.assertEqual(list(Path(directory).glob('.quota-*')), [])
            QuotaStore(directory).consume(TaskGrant(doc, 1000), 'synthetic-ref', 100)

    def test_independent_processes_cannot_overspend_shared_quota(self):
        with tempfile.TemporaryDirectory() as directory:
            doc = self.grant(maxUses=3)
            children = [subprocess.Popen(self.command(directory, doc, 'normal'), stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE) for _ in range(8)]
            try:
                for child in children: child.communicate(timeout=10)
                codes = [child.returncode for child in children]
                self.assertEqual(codes.count(0), 3)
                self.assertEqual(codes.count(3), 5)
            finally:
                for child in children:
                    if child.poll() is None: child.kill()
                    child.wait()

    def test_durable_audit_sequence_and_origin_survive_process_death(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(self.command(directory, self.grant(), 'audit'), capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 74)
            AuditLog(directory)({'event': 'outcome', 'actionIdHash': 'a'*16, 'status': 'uncertain', 'durationMs': 2})
            rows = [json.loads(line) for line in export_audit(directory, schema_version=2).splitlines()]
            self.assertEqual([row['sequence'] for row in rows], [1, 2])
            self.assertEqual(rows[0]['producerId'], rows[1]['producerId'])


if __name__ == '__main__': unittest.main()
