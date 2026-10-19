"""Host-owned task authority and crash-durable attempt quotas; never agent APIs."""
import fcntl
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import time
from .audit_export import _directory


class GovernanceError(Exception):
    pass


class TaskGrant:
    def __init__(self, document, principal_uid, clock=time.time):
        try:
            if set(document) != {'taskId', 'expiresAt', 'maxUses', 'actions'}:
                raise ValueError()
            if (not isinstance(document['taskId'], str) or not 1 <= len(document['taskId']) <= 128
                    or type(document['expiresAt']) is not int
                    or type(document['maxUses']) is not int or not 1 <= document['maxUses'] <= 10000
                    or not isinstance(document['actions'], dict) or not 1 <= len(document['actions']) <= 64
                    or type(principal_uid) is not int or principal_uid <= 0):
                raise ValueError()
            for action, constraints in document['actions'].items():
                if not isinstance(action, str) or not isinstance(constraints, dict) or len(constraints) > 32:
                    raise ValueError()
                for name, values in constraints.items():
                    if (not isinstance(name, str) or not isinstance(values, list) or not 1 <= len(values) <= 64
                            or any(type(value) not in (str, int, bool) for value in values)
                            or any(isinstance(value, str) and len(value) > 1024 for value in values)):
                        raise ValueError()
            encoded = json.dumps(document, sort_keys=True, separators=(',', ':'), allow_nan=False)
            if len(encoded.encode()) > 65536:
                raise ValueError()
            self._document = json.loads(encoded)
            self.id = hashlib.sha256(str(principal_uid).encode() + b':' + encoded.encode()).hexdigest()
            self.uid, self.clock, self.revoked = principal_uid, clock, False
        except Exception:
            raise GovernanceError('GRANT_INVALID') from None

    @property
    def document(self):
        """Inspection snapshot; changing policy requires a new host grant."""
        return copy.deepcopy(self._document)

    def check(self, uid, action, value):
        if self.revoked or uid != self.uid or self.clock() >= self._document['expiresAt']:
            raise GovernanceError('GRANT_EXPIRED')
        rules = self._document['actions'].get(action)
        if rules is None:
            raise GovernanceError('GRANT_DENIED')
        for field, allowed in rules.items():
            if field not in value or not any(type(value[field]) is type(item) and value[field] == item for item in allowed):
                raise GovernanceError('RESOURCE_DENIED')

    def revoke(self):
        self.revoked = True


class QuotaStore:
    """Attempts survive restart. Corruption or exhausted storage denies requests."""
    def __init__(self, directory, clock=time.time):
        self.directory, self.clock = Path(directory), clock

    def consume(self, grant, credential_ref, hourly_limit):
        directory = _directory(self.directory)
        temporary = None
        try:
            fcntl.flock(directory, fcntl.LOCK_EX)
            try:
                fd = os.open('quotas.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            except FileNotFoundError:
                state = {'version': 1, 'grants': {}, 'credentials': {}}
            else:
                try:
                    info = os.fstat(fd)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1048576):
                        raise ValueError()
                    from .server import _document
                    state = _document(os.read(fd, 1048577))
                finally:
                    os.close(fd)
            if (not isinstance(state, dict) or set(state) != {'version', 'grants', 'credentials'}
                    or state['version'] != 1 or not isinstance(state['grants'], dict)
                    or not isinstance(state['credentials'], dict)):
                raise ValueError()
            now = self.clock()
            counts = state['grants']
            for key, count in counts.items():
                if not isinstance(key, str) or len(key) != 64 or type(count) is not int or not 0 <= count <= 10000:
                    raise ValueError()
            histories = state['credentials']
            for key, times in histories.items():
                if not isinstance(key, str) or len(key) != 64 or not isinstance(times, list):
                    raise ValueError()
                if any(type(t) not in (int, float) or not 0 <= t < 1e12 for t in times):
                    raise ValueError()
                histories[key] = [t for t in times if now - t < 3600]
            count = counts.get(grant.id, 0)
            ref = hashlib.sha256(credential_ref.encode()).hexdigest()
            times = histories.get(ref, [])
            if count >= grant.document['maxUses'] or len(times) >= hourly_limit:
                raise GovernanceError('PERSISTENT_QUOTA_EXCEEDED')
            counts[grant.id] = count + 1
            histories[ref] = times + [now]
            if len(counts) > 128 or len(histories) > 64 or sum(map(len, histories.values())) > 4096:
                raise GovernanceError('QUOTA_STORAGE_FULL')
            encoded = json.dumps(state, allow_nan=False, separators=(',', ':')).encode()
            if len(encoded) > 1048576:
                raise GovernanceError('QUOTA_STORAGE_FULL')
            temporary = '.quota-' + secrets.token_hex(16)
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            try:
                view = memoryview(encoded)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(temporary, 'quotas.json', src_dir_fd=directory, dst_dir_fd=directory)
            temporary = None
            os.fsync(directory)
        except GovernanceError:
            raise
        except Exception:
            raise GovernanceError('QUOTA_UNAVAILABLE') from None
        finally:
            if temporary:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
            os.close(directory)
