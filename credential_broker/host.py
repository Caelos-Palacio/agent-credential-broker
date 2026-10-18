"""Trusted host configuration and metadata audit, independent of GUI/tool clients."""
import datetime
import fcntl
import json
import os
from pathlib import Path
import secrets
import stat
import threading
from .audit_export import _directory
from .server import ServerError


def load_catalog(path, *, _grant=False):
    path = Path(path).absolute()
    if path.parent != path.parent.resolve():
        raise ServerError('CATALOG_UNSAFE')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_size > 65536):
            raise ServerError('CATALOG_UNSAFE')
        from .server import _document
        value = _document(os.read(fd, 65537))
        if (not _grant and (not isinstance(value, list) or len(value) > 64)) or (_grant and not isinstance(value, dict)):
            raise ServerError('CATALOG_INVALID')
        return value
    finally:
        os.close(fd)


class AuditLog:
    """Bounded metadata only. Never serialize requests, outputs or exception text."""
    def __init__(self, directory):
        self.directory = Path(directory)
        self.mutex = threading.Lock()

    def __call__(self, event):
        # The engine supplies fixed-code metadata; use an independent whitelist.
        payload = {'eventId': secrets.token_hex(32),
                   'event': event.get('event') if event.get('event') in ('execute','intent','outcome') else 'execute',
                   'actionIdHash': str(event.get('actionIdHash', ''))[:16],
                   'status': event.get('status') if event.get('status') in ('intent','ok','denied','uncertain') else 'denied',
                   'durationMs': min(60000, max(0, int(event.get('durationMs', 0))))}
        if not all(c in '0123456789abcdef' for c in payload['actionIdHash']):
            payload['actionIdHash'] = ''
        with self.mutex:
            directory = _directory(self.directory)
            try:
                fcntl.flock(directory, fcntl.LOCK_EX)
                state = self._state(directory)
                state['sequence'] += 1
                self._save_state(directory, state)
                observed = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
                execution_id = event.get('executionId')
                payload.update(executionId=execution_id if isinstance(execution_id, str) and len(execution_id) == 64
                               and all(char in '0123456789abcdef' for char in execution_id) else secrets.token_hex(32),
                               sequence=state['sequence'], producerId=state['producerId'],
                               occurredAtUTC=event.get('occurredAtUTC', observed), observedAtUTC=observed)
                from .audit_export import _metadata
                try:
                    _metadata(json.dumps(payload))
                except Exception:
                    raise ServerError('AUDIT_INVALID') from None
                line = json.dumps(payload, separators=(',', ':')).encode() + b'\n'
                info = os.fstat(directory)
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise ServerError('AUDIT_UNSAFE')
                try:
                    info = os.stat('audit.jsonl', dir_fd=directory, follow_symlinks=False)
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
                        raise ServerError('AUDIT_UNSAFE')
                    if info.st_size >= 262144:
                        os.replace('audit.jsonl', 'audit.previous.jsonl', src_dir_fd=directory, dst_dir_fd=directory)
                except FileNotFoundError:
                    pass
                fd = os.open('audit.jsonl', os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
                try:
                    opened = os.fstat(fd)
                    if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid()
                            or opened.st_nlink != 1 or stat.S_IMODE(opened.st_mode) != 0o600):
                        raise ServerError('AUDIT_UNSAFE')
                    view = memoryview(line)
                    while view:
                        view = view[os.write(fd, view):]
                    os.fsync(fd)
                finally:
                    os.close(fd)
                # Persist the filename as well as its bytes before allowing a write.
                os.fsync(directory)
            finally:
                os.close(directory)

    def _state(self, directory):
        try:
            fd = os.open('audit-state.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            return {'producerId': secrets.token_hex(16), 'sequence': 0}
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 256):
                raise ServerError('AUDIT_UNSAFE')
            from .server import _document
            value = _document(os.read(fd, 257))
            if (not isinstance(value, dict) or set(value) != {'producerId', 'sequence'}
                    or type(value['sequence']) is not int or not 0 <= value['sequence'] < 2**53 - 1
                    or not isinstance(value['producerId'], str) or len(value['producerId']) != 32
                    or any(c not in '0123456789abcdef' for c in value['producerId'])):
                raise ServerError('AUDIT_UNSAFE')
            return value
        finally:
            os.close(fd)

    def _save_state(self, directory, state):
        temporary = '.audit-' + secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            try:
                content = json.dumps(state, separators=(',', ':')).encode()
                view = memoryview(content)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(temporary, 'audit-state.json', src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
