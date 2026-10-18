"""Offline metadata integrity against a separately trusted snapshot checkpoint."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from .audit_export import FIELDS, V2_FIELDS, _metadata
from .server import _document

BASE = FIELDS | {'schemaVersion', 'source', 'eventId'}


def _read(path, maximum):
    target = Path(path).absolute()
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in target.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) & 0o022 or info.st_size > maximum):
                raise ValueError()
            result = bytearray()
            while len(result) < info.st_size:
                chunk = os.read(fd, min(8192, info.st_size - len(result)))
                if not chunk:
                    raise ValueError()
                result.extend(chunk)
            if os.fstat(fd).st_size != info.st_size:
                raise ValueError()
            return bytes(result)
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def checkpoint(path):
    content = _read(path, 2 * 1024 * 1024)
    if content and not content.endswith(b'\n'):
        raise ValueError()
    digest, count = bytes(32), 0
    for raw in content.splitlines():
        if len(raw) > 1024:
            raise ValueError()
        row = _document(raw)
        if (not isinstance(row, dict) or type(row.get('schemaVersion')) is not int
                or row['schemaVersion'] not in (1, 2) or row.get('source') != 'agent-credential-broker'
                or set(row) != (BASE | (V2_FIELDS if row['schemaVersion'] == 2 else set()))):
            raise ValueError()
        _metadata(json.dumps({key: value for key, value in row.items() if key not in ('schemaVersion', 'source')}))
        normalized = json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
        digest = hashlib.sha256(digest + len(normalized).to_bytes(8, 'big') + normalized).digest()
        count += 1
    return {'schemaVersion': 1, 'source': 'broker-audit-checkpoint', 'algorithm': 'sha256-chain-v1',
            'eventCount': count, 'finalDigest': digest.hex()}


def verify(path, reference):
    expected = _document(_read(reference, 512))
    if (not isinstance(expected, dict) or set(expected) != {'schemaVersion', 'source', 'algorithm', 'eventCount', 'finalDigest'}
            or type(expected['schemaVersion']) is not int or expected['schemaVersion'] != 1
            or expected['source'] != 'broker-audit-checkpoint' or expected['algorithm'] != 'sha256-chain-v1'
            or type(expected['eventCount']) is not int or not 0 <= expected['eventCount'] <= 30000
            or not isinstance(expected['finalDigest'], str) or not re.fullmatch('[0-9a-f]{64}', expected['finalDigest'])):
        raise ValueError()
    return checkpoint(path) == expected
