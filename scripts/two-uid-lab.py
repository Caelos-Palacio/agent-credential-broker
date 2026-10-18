"""Real kernel identities inside an ephemeral user namespace, synthetic data only."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


CLIENT = r'''
import json,os,socket,sys
print('EXEC_READY',flush=True)
sys.stdin.readline()
sockpath,vault,canary,code,desktop,custodian_pid=sys.argv[1:]
def request(value):
 with socket.socket(socket.AF_UNIX) as conn:
  conn.settimeout(3);conn.connect(sockpath)
  try:conn.sendall(json.dumps(value).encode()+b'\n')
  except (BrokenPipeError,ConnectionResetError):return {'ok':False,'error':'PRINCIPAL_DENIED'}
  data=b''
  try:
   while b'\n' not in data and len(data)<16384:
    chunk=conn.recv(4096)
    if not chunk:break
    data+=chunk
  except ConnectionResetError:return {'ok':False,'error':'PRINCIPAL_DENIED'}
  return json.loads(data.split(b'\n')[0]) if data else {'ok':False,'error':'PRINCIPAL_DENIED'}
if os.getuid()!=1:
 result=request({'op':'status','uid':1})
 print(json.dumps({'uid':os.getuid(),'deniedSpoofedPrincipal':result.get('error')=='PRINCIPAL_DENIED'}),flush=True)
 sys.exit(0)
def denied(path,mode='rb'):
 try:
  with open(path,mode):pass
  return False
 except PermissionError:return True
vault_denied=denied(vault);canary_denied=denied(canary);code_denied=denied(code,'r+b')
memory_denied=denied('/proc/'+custodian_pid+'/mem')
desktop_denied=False
try:
 with socket.socket(socket.AF_UNIX) as conn:conn.connect(desktop)
except PermissionError:desktop_denied=True
plan=request({'op':'plan','request':{'action':'fixture_status','input':{}}})
output=request({'op':'execute','request':{'planId':plan['plan']['planId']}})
replay=request({'op':'execute','request':{'planId':plan['plan']['planId']}})
print(json.dumps({'uid':1,'supplementaryGroupsCleared':os.getgroups()==[],
 'vaultDenied':vault_denied,'secretCanaryDenied':canary_denied,'codeWriteDenied':code_denied,
 'custodianMemoryDenied':memory_denied,'desktopCanaryDenied':desktop_denied,
 'desktopEnvironmentAbsent':not any(k in os.environ for k in ('DISPLAY','WAYLAND_DISPLAY','XAUTHORITY','DBUS_SESSION_BUS_ADDRESS')),
 'legitimateOutput':output=={'ok':True,'output':{'state':'ready'}},'replayDenied':replay.get('error')=='PLAN_INVALID'}),flush=True)
'''


class UnsupportedLab(Exception):
    pass


def inside():
    mapping = [list(map(int, line.split())) for line in Path('/proc/self/uid_map').read_text().splitlines()]
    if os.getuid() != 0 or len(mapping) < 2 or mapping[0][0] != 0 or mapping[0][1] == 0:
        raise UnsupportedLab()
    try:
        os.setgroups([])
        os.setgid(1)
    except PermissionError:
        raise UnsupportedLab() from None
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import secrets
    import socket
    import threading
    import time
    from credential_broker.vault import Vault
    from credential_broker.policy import ActionBroker
    from credential_broker.server import BrokerServer
    from credential_broker.governance import TaskGrant, QuotaStore
    from credential_broker.host import AuditLog
    with tempfile.TemporaryDirectory(prefix='broker-two-uid-lab-') as directory:
        root = Path(directory); root.chmod(0o755)
        private, ipc, desktop = root / 'private', root / 'ipc', root / 'desktop'
        private.mkdir(0o700); ipc.mkdir(0o750); desktop.mkdir(0o700)
        canary, code, vault_path = private / 'canary', root / 'code-canary.py', private / 'fixture.vault'
        canary.write_text('SYNTHETIC_PRIVATE_CANARY'); canary.chmod(0o600)
        code.write_text('# synthetic custodian code canary\n'); code.chmod(0o644)
        desktop_socket = socket.socket(socket.AF_UNIX); desktop_socket.bind(str(desktop / 'session.sock'))
        children = []
        server = vault = None
        def spawn(uid):
            def drop():
                os.setgroups([]); os.setgid(1); os.setuid(uid)
            child = subprocess.Popen(['/usr/bin/python3', '-I', '-c', CLIENT, str(ipc / 'broker.sock'),
                                      str(vault_path), str(canary), str(code), str(desktop / 'session.sock'), str(os.getpid())],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, preexec_fn=drop, text=True)
            children.append(child)
            if child.stdout.readline().strip() != 'EXEC_READY':
                raise RuntimeError('AGENT_EXEC_FAILED')
            return child
        try:
            # Launch every client via fresh exec before generating/unlocking a key.
            clients = [spawn(uid) for uid in (1, 2, 0)]
            marker = ('FAKE_' + secrets.token_hex(32)).encode()
            vault = Vault.create(vault_path, b'SYNTHETIC_MASTER_PASSWORD_ONLY')
            vault.put('fixture', marker)
            calls = []
            def provider(**kwargs):
                calls.append(True)
                return 200, json.dumps({'state': 'ready', 'debug': marker.decode()}).encode()
            action = {'id': 'fixture_status', 'credentialRef': 'fixture', 'method': 'GET',
                      'url': 'https://fixture.example.test/status', 'effect': 'read',
                      'inputSchema': {'type': 'object', 'properties': {}, 'additionalProperties': False},
                      'responseFields': ['state'], 'outputSchema': {'type': 'object',
                       'properties': {'state': {'type': 'string', 'enum': ['ready'], 'maxLength': 5}},
                       'required': ['state'], 'additionalProperties': False}}
            grant = TaskGrant({'taskId': 'two-uid-fixture', 'expiresAt': int(time.time()) + 30,
                               'maxUses': 1, 'actions': {'fixture_status': {}}}, 1)
            broker = ActionBroker(vault, [action], 1, executor=provider, task_grant=grant,
                                  quota_store=QuotaStore(private), audit=AuditLog(private))
            server = BrokerServer(ipc / 'broker.sock', broker).start()  # Production constructor.
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            results = []
            for client in clients:
                output, _ = client.communicate('\n', timeout=5)
                if client.returncode or marker.decode() in output:
                    raise RuntimeError('AGENT_PROTOCOL_FAILED')
                results.append(json.loads(output))
            legitimate = results[0]
            verified = (all(value is True for key, value in legitimate.items() if key != 'uid')
                        and all(item['deniedSpoofedPrincipal'] for item in results[1:]) and len(calls) == 1)
            print(json.dumps({'ok': verified, 'namespaceTwoUidVerified': verified, 'productionIdentityBypass': False,
                              'legitimate': legitimate, 'unauthorizedPrincipalsDenied': 2,
                              'providerCalls': len(calls), 'productionDeploymentVerified': False}))
            return 0 if verified else 1
        finally:
            if server: server.close()
            elif vault: vault.lock()
            for child in children:
                if child.poll() is None: child.kill()
                child.wait()
            desktop_socket.close()


def main():
    if sys.argv[1:] == ['--inside']:
        return inside()
    executable = shutil.which('unshare')
    if not executable:
        print('{"ok":false,"unsupported":true,"namespaceTwoUidVerified":false}')
        return 77
    result = subprocess.run([executable, '--user', '--map-root-user', '--map-auto', '--fork', '--kill-child',
                             sys.executable, str(Path(__file__).resolve()), '--inside'],
                            capture_output=True, timeout=20, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
    try:
        report = json.loads(result.stdout)
    except Exception:
        # Only launcher diagnostics with a known environmental cause may skip.
        # A child crash, syntax error or malformed output must fail assurance.
        unsupported = result.returncode != 0 and any(result.stderr.startswith(prefix) for prefix in (
            b'unshare: unshare failed: Operation not permitted',
            b'unshare: failed to execute newuidmap: No such file or directory',
            b'unshare: failed to execute newgidmap: No such file or directory'))
        report = {'ok': False, 'unsupported' if unsupported else 'failed': True,
                  'namespaceTwoUidVerified': False}
    print(json.dumps(report))
    if result.returncode == 0 and report.get('ok'):
        return 0
    return 77 if report.get('unsupported') else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except UnsupportedLab:
        print('{"ok":false,"unsupported":true,"namespaceTwoUidVerified":false}')
        raise SystemExit(77)
    except Exception:
        print('{"ok":false,"failed":true,"namespaceTwoUidVerified":false}')
        raise SystemExit(1)
