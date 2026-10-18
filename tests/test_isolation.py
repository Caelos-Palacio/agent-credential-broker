import contextlib
import io
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
from credential_broker.isolation import _command, main


class IsolationTests(unittest.TestCase):
    def test_profile_exposes_only_workspace_and_broker_socket(self):
        with patch('credential_broker.isolation.shutil.which', return_value='/usr/bin/bwrap'):
            args = _command('/tmp/work', '/tmp/private/broker.sock', ['/usr/bin/python3'])
        self.assertIn('--unshare-all', args)
        self.assertIn('--clearenv', args)
        self.assertIn('--new-session', args)
        self.assertIn('/run/broker.sock', args)
        self.assertNotIn('/run/user', args)
        self.assertNotIn('DISPLAY', args)
        self.assertNotIn(str(Path.home()), args)

    def test_missing_bwrap_never_falls_back_to_unsandboxed_command(self):
        with patch('credential_broker.isolation.shutil.which', return_value=None):
            with self.assertRaises(ValueError):
                _command('/tmp/work', None, ['true'])

    def test_launcher_rejects_same_uid_fixture_socket(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'broker.sock'
            with socket.socket(socket.AF_UNIX) as sock:
                sock.bind(str(path))
                path.chmod(0o660)
                output = io.StringIO()
                with contextlib.redirect_stderr(output):
                    self.assertEqual(main(['--workspace', directory, '--socket', str(path), '--', 'true']), 1)
                self.assertEqual(output.getvalue().strip(), '{"ok":false,"error":"ISOLATION_UNAVAILABLE"}')


if __name__ == '__main__':
    unittest.main()
