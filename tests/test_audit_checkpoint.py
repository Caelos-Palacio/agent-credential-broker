import json
from pathlib import Path
import tempfile
import unittest
from credential_broker.audit_checkpoint import checkpoint, verify
from credential_broker.audit_export import export_audit
from credential_broker.host import AuditLog


class CheckpointTests(unittest.TestCase):
    def test_detects_tampering_reorder_and_truncation_against_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            for status in ('ok', 'denied'):
                AuditLog(directory)({'event': 'outcome', 'actionIdHash': 'a' * 16, 'status': status, 'durationMs': 5})
            path, reference = Path(directory) / 'export.jsonl', Path(directory) / 'checkpoint.json'
            original = export_audit(directory, schema_version=2)
            path.write_text(original)
            path.chmod(0o600)
            reference.write_text(json.dumps(checkpoint(path)))
            reference.chmod(0o600)
            self.assertTrue(verify(path, reference))
            rows = original.splitlines()
            for changed in (original.replace('"durationMs":5', '"durationMs":6'),
                            '\n'.join(reversed(rows)) + '\n', rows[0] + '\n'):
                path.write_text(changed)
                self.assertFalse(verify(path, reference))

    def test_rejects_payloads_symlinks_and_writable_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'export'
            path.write_text('{"password":"FAKE_NEVER_PUBLISH"}\n')
            with self.assertRaises(Exception): checkpoint(path)
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaises(Exception): checkpoint(link)
            path.write_text('')
            path.chmod(0o600)
            reference = Path(directory) / 'checkpoint'
            reference.write_text(json.dumps(checkpoint(path)))
            reference.chmod(0o666)
            with self.assertRaises(Exception): verify(path, reference)


if __name__ == '__main__': unittest.main()
