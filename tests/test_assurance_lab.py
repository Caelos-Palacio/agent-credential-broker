import contextlib
import io
import json
from pathlib import Path
import runpy
import subprocess
import unittest
from unittest.mock import patch


class LabClassificationTests(unittest.TestCase):
    def invoke(self, result):
        namespace = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'scripts/two-uid-lab.py'))
        output = io.StringIO()
        with patch('sys.argv', ['two-uid-lab.py']), patch('shutil.which', return_value='/usr/bin/unshare'), \
                patch('subprocess.run', return_value=result), contextlib.redirect_stdout(output):
            status = namespace['main']()
        return status, json.loads(output.getvalue())

    def test_unknown_child_crash_or_malformed_output_is_failure(self):
        status, report = self.invoke(subprocess.CompletedProcess([], 1, b'INVALID_SYNTHETIC_CHILD_OUTPUT',
                                                                 b'fixture child crash'))
        self.assertEqual(status, 1)
        self.assertTrue(report['failed'])
        self.assertNotIn('unsupported', report)

    def test_known_unshare_permission_denial_is_explicitly_unavailable(self):
        status, report = self.invoke(subprocess.CompletedProcess([], 1, b'',
                                    b'unshare: unshare failed: Operation not permitted\n'))
        self.assertEqual(status, 77)
        self.assertTrue(report['unsupported'])
        self.assertFalse(report['namespaceTwoUidVerified'])


if __name__ == '__main__': unittest.main()
