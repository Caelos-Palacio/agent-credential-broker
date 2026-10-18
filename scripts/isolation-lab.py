"""Temporary fake-data probe. Does not claim a two-UID production deployment."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from credential_broker.isolation import _command

with tempfile.TemporaryDirectory(prefix='broker-isolation-lab-') as directory:
    root = Path(directory)
    workspace = root / 'workspace'
    workspace.mkdir()
    sentinel = root / 'custodian-canary'
    sentinel.write_text('FAKE_CUSTODIAN_CANARY')
    probe = """import json,os,socket,sys
denied=False
try: open(sys.argv[1]).read()
except OSError: denied=True
network=False
try:
 s=socket.create_connection(('1.1.1.1',443),.1);s.close()
except OSError: network=True
env=not any(name in os.environ for name in ('DISPLAY','WAYLAND_DISPLAY','XAUTHORITY','DBUS_SESSION_BUS_ADDRESS'))
bus=not os.path.exists('/run/user') and not os.path.exists('/run/dbus')
print(json.dumps({'filesystemDenied':denied,'networkDenied':network,'desktopEnvironmentAbsent':env,'sessionBusAbsent':bus}))
sys.exit(0 if denied and network and env and bus else 1)
"""
    try:
        result = subprocess.run(_command(workspace, None, ['/usr/bin/python3', '-I', '-c', probe, str(sentinel)]),
                                capture_output=True, timeout=10, env={'PATH': '/usr/bin:/bin'})
        if result.returncode:
            print(json.dumps({'ok': False, 'lab': 'unavailable-or-controls-failed', 'twoUidVerified': False}))
            sys.exit(77)
        details = json.loads(result.stdout)
        print(json.dumps({'ok': True, 'controls': details, 'twoUidVerified': False}))
    except Exception:
        print(json.dumps({'ok': False, 'lab': 'unavailable', 'twoUidVerified': False}))
        sys.exit(77)
