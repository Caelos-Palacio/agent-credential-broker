import subprocess
import sys
import unittest
from pathlib import Path


class HeadlessTests(unittest.TestCase):
    def test_host_and_client_do_not_import_tk_or_an_agent_sdk(self):
        code = '''import sys,importlib.abc
sys.path.insert(0,sys.argv[1])
class BlockGUI(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname=='tkinter' or fullname.startswith('tkinter.'):
   raise ImportError('GUI explicitly unavailable in fixture')
sys.meta_path.insert(0,BlockGUI())
import credential_broker.host,credential_broker.cli,credential_broker.policy
assert 'tkinter' not in sys.modules
print('HEADLESS_IMPORT_OK')
'''
        result = subprocess.run([sys.executable, '-I', '-c', code, str(Path(__file__).resolve().parents[1])],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), b'HEADLESS_IMPORT_OK')


if __name__ == '__main__':
    unittest.main()
