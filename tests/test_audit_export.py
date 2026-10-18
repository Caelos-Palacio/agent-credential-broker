import contextlib
import io
import json
import os
import shutil
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from credential_broker.audit_export import AuditExportError, export_audit
from credential_broker.cli import main
from credential_broker.host import AuditLog


EVENT = {'event': 'intent', 'actionIdHash': 'a' * 16, 'status': 'intent', 'durationMs': 2}


class AuditExportTests(unittest.TestCase):
    def test_safe_metadata_cli_and_rotation_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            writer = AuditLog(directory)
            writer({**EVENT, 'password': 'FAKE_NOT_EXPORTED', 'body': 'FAKE_NOT_EXPORTED'})
            first = json.loads(export_audit(directory))
            self.assertEqual(set(first), {'schemaVersion', 'source', 'eventId', *EVENT})
            self.assertEqual(first['source'], 'agent-credential-broker')
            self.assertEqual(len(first['eventId']), 64)
            os.rename(Path(directory) / 'audit.jsonl', Path(directory) / 'audit.previous.jsonl')
            writer({**EVENT, 'event': 'outcome', 'status': 'ok'})
            rows = [json.loads(line) for line in export_audit(directory).splitlines()]
            self.assertEqual(rows[0]['eventId'], first['eventId'])
            self.assertNotEqual(rows[0]['eventId'], rows[1]['eventId'])
            with tempfile.TemporaryDirectory() as copy:
                for name in ('audit.previous.jsonl', 'audit.jsonl'):
                    shutil.copyfile(Path(directory) / name, Path(copy) / name)
                    (Path(copy) / name).chmod(0o600)
                self.assertEqual(export_audit(copy), export_audit(directory))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(['audit-export', '--directory', directory]), 0)
            self.assertNotIn('FAKE_NOT_EXPORTED', output.getvalue())
            self.assertEqual(len(output.getvalue().splitlines()), 2)

    def test_rejects_unsafe_file_types_permissions_and_links(self):
        for variant in ('symlink', 'hardlink', 'permissions', 'fifo', 'oversized'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'audit.jsonl'
                if variant == 'fifo':
                    os.mkfifo(path, 0o600)
                elif variant == 'symlink':
                    target = Path(directory) / 'vault.json'
                    target.write_text('FAKE_VAULT_NOT_READ')
                    path.symlink_to(target)
                else:
                    path.write_bytes(b'x' * 262657 if variant == 'oversized' else b'{}\n')
                    path.chmod(0o600)
                    if variant == 'hardlink':
                        os.link(path, Path(directory) / 'other')
                    if variant == 'permissions':
                        path.chmod(0o644)
                with self.assertRaises(AuditExportError):
                    export_audit(directory)

    def test_parent_symlink_rejected_by_reader_and_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / 'real'
            child = real / 'child'
            child.mkdir(parents=True, mode=0o700)
            alias = Path(directory) / 'alias'
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaises(AuditExportError):
                export_audit(alias / 'child')
            with self.assertRaises(OSError):
                AuditLog(alias / 'child')(EVENT)
            self.assertFalse((child / 'audit.jsonl').exists())

    def test_malformed_unknown_and_partial_records_fail_without_partial_stdout(self):
        invalid = [b'{"event":"intent","event":"execute"}\n', b'{}\n',
                   json.dumps({**EVENT, 'durationMs': True}).encode() + b'\n',
                   json.dumps({**EVENT, 'body': 'FAKE_SENSITIVE'}).encode() + b'\n',
                   json.dumps(EVENT).encode()]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'audit.jsonl'
            for raw in invalid:
                path.write_bytes(json.dumps(EVENT).encode() + b'\n' + raw)
                path.chmod(0o600)
                with self.assertRaises(AuditExportError):
                    export_audit(directory)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(main(['audit-export', '--directory', directory]), 1)
                self.assertEqual(json.loads(output.getvalue()), {'ok': False, 'error': 'CLIENT_FAILED'})

    def test_writer_fsyncs_data_then_directory_and_propagates_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            modes = []
            import stat
            def sync(fd):
                modes.append(stat.S_ISDIR(os.fstat(fd).st_mode))
                if modes[-1]:
                    raise OSError('FAKE_DIRECTORY_SYNC_FAILURE')
            with patch('credential_broker.host.os.fsync', side_effect=sync):
                with self.assertRaises(OSError):
                    AuditLog(directory)(EVENT)
            self.assertEqual(modes, [False, True])

    def test_empty_export_does_not_open_vault(self):
        with tempfile.TemporaryDirectory() as directory:
            vault = Path(directory) / 'vault.json'
            vault.write_text('FAKE_NEVER_READ')
            self.assertEqual(export_audit(directory), '')
            self.assertEqual(vault.read_text(), 'FAKE_NEVER_READ')

    def test_v2_sequence_producer_time_and_correlation_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            AuditLog(directory)({**EVENT, 'executionId': 'b' * 64})
            AuditLog(directory)({**EVENT, 'executionId': 'b' * 64, 'event': 'outcome', 'status': 'ok'})
            rows = [json.loads(line) for line in export_audit(directory, schema_version=2).splitlines()]
            self.assertEqual([row['sequence'] for row in rows], [1, 2])
            self.assertEqual(rows[0]['producerId'], rows[1]['producerId'])
            self.assertEqual(rows[0]['executionId'], rows[1]['executionId'])
            self.assertEqual(len(rows[0]), 12)
            self.assertEqual(rows[0]['schemaVersion'], 2)
            self.assertRegex(rows[0]['occurredAtUTC'], r'^\d{4}-\d{2}-\d{2}T.*Z$')
            self.assertEqual(len(json.loads(export_audit(directory).splitlines()[0])), 7)

    def test_v2_refuses_to_invent_timestamps_for_legacy_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'audit.jsonl'
            path.write_text(json.dumps(EVENT) + '\n')
            path.chmod(0o600)
            self.assertTrue(export_audit(directory))
            with self.assertRaises(AuditExportError):
                export_audit(directory, schema_version=2)

    def test_directory_sync_failure_blocks_credential_and_network(self):
        from unittest.mock import Mock
        from credential_broker.policy import ActionBroker, PolicyError
        from test_server import ACTION
        import stat
        with tempfile.TemporaryDirectory() as directory:
            vault, executor = Mock(), Mock()
            broker = ActionBroker(vault, [dict(ACTION, method='POST', effect='write')],
                                  1234, approve_host=lambda _: True,
                                  audit=AuditLog(directory), executor=executor)
            plan = broker.plan(1234, {'action': 'read_account', 'input': {}})
            def sync(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode):
                    raise OSError('FAKE_SYNC_FAILURE')
            with patch('credential_broker.host.os.fsync', side_effect=sync):
                with self.assertRaises(PolicyError) as error:
                    broker.execute(1234, {'planId': plan['planId']})
            self.assertEqual(error.exception.code, 'AUDIT_UNAVAILABLE')
            vault.use.assert_not_called()
            executor.assert_not_called()


if __name__ == '__main__':
    unittest.main()
