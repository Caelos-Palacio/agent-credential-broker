"""Custodian-only, bounded metadata export. Never opens a vault or serves an agent."""
import hashlib
import datetime
import json
import os
from pathlib import Path
import re
import stat


MAX_FILE = 262144 + 512
MAX_LINE = 512
FIELDS = {'event', 'actionIdHash', 'status', 'durationMs'}
V2_FIELDS = {'executionId', 'sequence', 'producerId', 'occurredAtUTC', 'observedAtUTC'}


class AuditExportError(Exception):
    pass


def _directory(path):
    """Traverse with dirfds so no parent component can be a symlink."""
    target = Path(path).absolute()
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in target.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise AuditExportError('AUDIT_UNSAFE')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _metadata(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise AuditExportError('AUDIT_INVALID')
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique)
    if (not isinstance(value, dict) or set(value) not in (FIELDS, FIELDS | {'eventId'}, FIELDS | {'eventId'} | V2_FIELDS)
            or value['event'] not in ('execute', 'intent', 'outcome')
            or value['status'] not in ('intent', 'ok', 'denied', 'uncertain')
            or not isinstance(value['actionIdHash'], str)
            or not re.fullmatch('[0-9a-f]{16}', value['actionIdHash'])
            or type(value['durationMs']) is not int
            or not 0 <= value['durationMs'] <= 60000):
        raise AuditExportError('AUDIT_INVALID')
    if 'eventId' in value and (not isinstance(value['eventId'], str)
                              or not re.fullmatch('[0-9a-f]{64}', value['eventId'])):
        raise AuditExportError('AUDIT_INVALID')
    if 'executionId' in value:
        if (not isinstance(value['executionId'], str) or not re.fullmatch('[0-9a-f]{64}', value['executionId'])
                or not isinstance(value['producerId'], str) or not re.fullmatch('[0-9a-f]{32}', value['producerId'])
                or type(value['sequence']) is not int or not 1 <= value['sequence'] <= 2**53 - 1):
            raise AuditExportError('AUDIT_INVALID')
        for field in ('occurredAtUTC', 'observedAtUTC'):
            if not isinstance(value[field], str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z', value[field]):
                raise AuditExportError('AUDIT_INVALID')
            datetime.datetime.fromisoformat(value[field].replace('Z', '+00:00'))
    return value


def export_audit(directory, *, schema_version=1):
    """Return validated JSONL before emitting anything; fail closed on any bad file.

    New event IDs survive copying and rotation. Legacy IDs follow an inode across
    rotation. Neither is cryptographic integrity or an execution timestamp.
    """
    rows = []
    try:
        if type(schema_version) is not int or schema_version not in (1, 2):
            raise AuditExportError('AUDIT_INVALID')
        root = _directory(directory)
        try:
            for name in ('audit.previous.jsonl', 'audit.jsonl'):
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
                except FileNotFoundError:
                    continue
                try:
                    info = os.fstat(fd)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                            or info.st_size > MAX_FILE):
                        raise AuditExportError('AUDIT_UNSAFE')
                    content = bytearray()
                    while len(content) < info.st_size:
                        chunk = os.read(fd, min(8192, info.st_size - len(content)))
                        if not chunk:
                            raise AuditExportError('AUDIT_CHANGED')
                        content.extend(chunk)
                    if content and not content.endswith(b'\n'):
                        raise AuditExportError('AUDIT_CHANGED')
                    offset = 0
                    for raw in content.splitlines(keepends=True):
                        if len(raw) > MAX_LINE:
                            raise AuditExportError('AUDIT_INVALID')
                        record = _metadata(raw)
                        extra = {key: record.pop(key) for key in V2_FIELDS if key in record}
                        if schema_version == 2 and len(extra) != len(V2_FIELDS):
                            raise AuditExportError('AUDIT_V2_REQUIRED')
                        identity = f'{info.st_dev}:{info.st_ino}:{offset}:'.encode() + raw
                        event_id = record.pop('eventId', hashlib.sha256(identity).hexdigest())
                        rows.append({'schemaVersion': schema_version, 'source': 'agent-credential-broker',
                                     'eventId': event_id, **record, **(extra if schema_version == 2 else {})})
                        offset += len(raw)
                finally:
                    os.close(fd)
        finally:
            os.close(root)
        return ''.join(json.dumps(row, separators=(',', ':')) + '\n' for row in rows)
    except Exception:
        raise AuditExportError('AUDIT_EXPORT_FAILED') from None
