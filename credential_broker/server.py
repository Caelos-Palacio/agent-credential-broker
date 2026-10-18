"""Linux-only bounded Unix transport; identity comes exclusively from the kernel."""
import json
import os
from pathlib import Path
import socket
import stat
import struct
import threading
import time

MAX_MESSAGE = 16384

class ServerError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _document(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError()
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


class BrokerServer:
    def __init__(self, path, broker, *, socket_group=None, idle_seconds=300,
                 _test_allow_same_uid=False):
        if not hasattr(socket, 'SO_PEERCRED'):
            raise ServerError('LINUX_REQUIRED')
        if type(broker.allowed_uid) is not int or broker.allowed_uid <= 0:
            raise ServerError('INVALID_AGENT_UID')
        if broker.allowed_uid == os.getuid() and not _test_allow_same_uid:
            raise ServerError('SEPARATE_AGENT_UID_REQUIRED')
        if not _test_allow_same_uid and (broker.task_grant is None or broker.quota_store is None):
            raise ServerError('HOST_GOVERNANCE_REQUIRED')
        self.path, self.broker = Path(path).absolute(), broker
        self.socket_group = socket_group
        self.idle_seconds = max(1, min(idle_seconds, 3600))
        self.last_active = time.monotonic()
        self.stopping = threading.Event()
        self.slots = threading.BoundedSemaphore(2)
        self.listener = None
        self.inode = None
        self.workers = set()
        self.mutex = threading.Lock()

    def start(self):
        # Parent directory is dedicated, trusted and not writable by the agent.
        parent = self.path.parent
        if parent != parent.resolve() or not parent.is_dir():
            raise ServerError('SOCKET_DIRECTORY_UNSAFE')
        info = parent.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise ServerError('SOCKET_DIRECTORY_UNSAFE')
        if self.socket_group is not None and self.socket_group not in os.getgroups() + [os.getgid()]:
            raise ServerError('SOCKET_GROUP_DENIED')
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            # Never unlink an existing path: it may belong to another process.
            listener.bind(str(self.path))
            self.inode = self.path.lstat().st_ino
            os.chmod(self.path, 0o660)
            if self.socket_group is not None:
                os.chown(self.path, -1, self.socket_group)
            listener.listen(8)
            listener.settimeout(0.25)
            self.listener = listener
        except Exception:
            listener.close()
            self._unlink()
            raise ServerError('SOCKET_START_FAILED') from None
        return self

    def _unlink(self):
        try:
            info = self.path.lstat()
            if self.inode == info.st_ino and stat.S_ISSOCK(info.st_mode):
                self.path.unlink()
        except FileNotFoundError:
            pass

    def serve_forever(self):
        if self.listener is None:
            self.start()
        while not self.stopping.is_set():
            if time.monotonic() - self.last_active > self.idle_seconds:
                self.lock()
                break
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self.slots.acquire(blocking=False):
                conn.close()
                continue
            worker = threading.Thread(target=self._client, args=(conn,), daemon=True)
            with self.mutex:
                self.workers.add(worker)
            worker.start()
        self.close()

    def _dispatch(self, uid, request):
        if not isinstance(request, dict) or set(request) - {'op', 'request'}:
            raise ServerError('INVALID_REQUEST')
        op = request.get('op')
        if op in ('status', 'capabilities'):
            if set(request) != {'op'}:
                raise ServerError('INVALID_REQUEST')
            if op == 'status':
                return {'ok': True, 'status': 'available', 'protocol': 'agent-credential-broker/1'}
            return {'ok': True, 'actions': self.broker.capabilities()}
        if set(request) != {'op', 'request'}:
            raise ServerError('INVALID_REQUEST')
        if op == 'plan':
            return {'ok': True, 'plan': self.broker.plan(uid, request['request'])}
        if op == 'execute':
            return self.broker.execute(uid, request['request'])
        raise ServerError('OPERATION_DENIED')

    def _client(self, conn):
        reply = {'ok': False, 'error': 'INVALID_REQUEST'}
        try:
            conn.settimeout(4)
            _, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != self.broker.allowed_uid:
                raise ServerError('PRINCIPAL_DENIED')
            data = bytearray()
            deadline = time.monotonic() + 4
            while b'\n' not in data:
                conn.settimeout(max(.001, deadline - time.monotonic()))
                chunk = conn.recv(min(4096, MAX_MESSAGE + 1 - len(data)))
                if not chunk:
                    raise ServerError('INVALID_REQUEST')
                data.extend(chunk)
                if len(data) > MAX_MESSAGE or time.monotonic() > deadline:
                    raise ServerError('REQUEST_TOO_LARGE')
            line, remainder = bytes(data).split(b'\n', 1)
            if remainder:
                raise ServerError('INVALID_REQUEST')
            request = _document(line)
            self.last_active = time.monotonic()
            reply = self._dispatch(uid, request)
        except Exception as exc:
            # Only stable codes from known exception classes cross the boundary.
            from .policy import PolicyError
            if isinstance(exc, (ServerError, PolicyError)):
                reply = {'ok': False, 'error': exc.code}
        finally:
            try:
                conn.settimeout(1)
                encoded = json.dumps(reply, allow_nan=False, separators=(',', ':')).encode() + b'\n'
                if len(encoded) > MAX_MESSAGE:
                    encoded = b'{"ok":false,"error":"RESPONSE_TOO_LARGE"}\n'
                conn.sendall(encoded)
            except Exception:
                pass
            conn.close()
            with self.mutex:
                self.workers.discard(threading.current_thread())
            self.slots.release()

    def lock(self):
        self.stopping.set()
        self.broker.invalidate_session()
        self.broker.vault.lock()
        self.stopping.set()

    def close(self):
        self.broker.invalidate_session()
        self.broker.vault.lock()
        self.stopping.set()
        if self.listener:
            self.listener.close()
        self._unlink()
