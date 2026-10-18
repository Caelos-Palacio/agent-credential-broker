import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from credential_broker.cli import main
from credential_broker.host import AuditLog, load_catalog
from credential_broker.server import ServerError

class CliTests(unittest.TestCase):
    def test_secret_argument_does_not_exist(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                main(['call','--socket','/tmp/missing','--password','fake'])
    def test_error_is_constant(self):
        data=io.TextIOWrapper(io.BytesIO(b'{"op":"status"}'))
        output=io.StringIO()
        with patch('sys.stdin', data), contextlib.redirect_stdout(output):
            self.assertEqual(main(['call','--socket','/not/a/path']),1)
        self.assertEqual(json.loads(output.getvalue()),{'ok':False,'error':'CLIENT_FAILED'})
    def test_invalid_arguments_never_echo_accidentally_supplied_secret(self):
        sentinel = 'FAKE_SENSITIVE_ARGUMENT_NEVER_ECHO'
        for args in ([sentinel], ['call', '--socket', '/tmp/missing', '--secret', sentinel],
                     ['gui', '--directory', '/tmp/fake', sentinel]):
            output = io.StringIO()
            with contextlib.redirect_stderr(output), self.assertRaises(SystemExit) as error:
                main(args)
            self.assertEqual(error.exception.code, 2)
            self.assertNotIn(sentinel, output.getvalue())
            self.assertEqual(json.loads(output.getvalue()), {'ok': False, 'error': 'INVALID_ARGUMENTS'})
    def test_catalog_private_owner_only(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'actions.json'; path.write_text('[]'); path.chmod(0o600)
            self.assertEqual(load_catalog(path),[])
            path.chmod(0o644)
            with self.assertRaises(ServerError): load_catalog(path)
    def test_audit_whitelist_rotation_and_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            audit=AuditLog(temp)
            event={'actionIdHash':'a'*16,'status':'ok','durationMs':10,
                   'password':'FAKE_DO_NOT_LOG','body':'FAKE_DO_NOT_LOG','uid':1000}
            audit(event)
            path=Path(temp)/'audit.jsonl'
            self.assertNotIn('FAKE',path.read_text())
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            path.write_bytes(b'x'*262144)
            audit(event)
            self.assertTrue((Path(temp)/'audit.previous.jsonl').exists())
            self.assertLess(path.stat().st_size,1024)
    def test_audit_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'target'; target.write_text('keep')
            (Path(temp)/'audit.jsonl').symlink_to(target)
            with self.assertRaises(ServerError): AuditLog(temp)({})
            self.assertEqual(target.read_text(),'keep')

if __name__ == '__main__': unittest.main()
