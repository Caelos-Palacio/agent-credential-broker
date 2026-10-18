"""Encrypted host-only storage. Never expose this object to an agent transport.

Callbacks run inside the trusted broker. Python cannot guarantee memory erasure;
locking drops references, but is not a substitute for process isolation.
"""

import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


MAX_FILE_BYTES = 1024 * 1024
MAX_SECRET_BYTES = 65536
_ALIAS = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_PARAMETERS = {"name": "scrypt", "n": 32768, "r": 8, "p": 1}


class VaultError(Exception):
    """Stable errors deliberately omit filesystem, input and crypto details."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _encode(value):
    return base64.b64encode(value).decode("ascii")


def _decode(value, length=None):
    if not isinstance(value, str):
        raise VaultError("vault_invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise VaultError("vault_invalid") from None
    if length is not None and len(decoded) != length:
        raise VaultError("vault_invalid")
    return decoded


def _derive(password, salt):
    if not isinstance(password, bytes) or not 12 <= len(password) <= 1024:
        raise VaultError("password_invalid")
    return Scrypt(salt=salt, length=32, n=32768, r=8, p=1).derive(password)


def _parent(path, create=False):
    """Walk with directory descriptors so symlink substitutions cannot redirect IO."""
    path = Path(os.path.abspath(os.fspath(path)))
    if path.name in ("", ".", ".."):
        raise VaultError("path_invalid")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        parts = path.parent.parts[1:]
        for index, component in enumerate(parts):
            final = index == len(parts) - 1
            try:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=descriptor)
            except FileNotFoundError:
                if not create or not final:
                    raise
                os.mkdir(component, mode=0o700, dir_fd=descriptor)
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise VaultError("directory_unsafe")
        return descriptor, path.name
    except BaseException:
        os.close(descriptor)
        raise


def _file_info(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
        raise VaultError("file_unsafe")
    if info.st_size > MAX_FILE_BYTES:
        raise VaultError("vault_too_large")


def _read(directory, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory)
    try:
        _file_info(os.fstat(descriptor))
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(65536, MAX_FILE_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_FILE_BYTES:
                raise VaultError("vault_too_large")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


class Vault:
    """Single-writer encrypted vault; credential references grant no authority."""

    def __init__(self, directory, name, key, salt, entries):
        self._directory = directory
        self._name = name
        self._key = key
        self._salt = salt
        self._entries = entries
        self._fingerprint = None
        self._epoch = 0
        self._versions = {}
        self._mutex = threading.RLock()

    @classmethod
    def create(cls, path, password):
        directory = None
        vault = None
        try:
            salt = secrets.token_bytes(16)
            key = _derive(password, salt)
            directory, name = _parent(path, create=True)
            try:
                os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise VaultError("vault_exists")
            vault = cls(directory, name, key, salt, {})
            vault._persist({}, exclusive=True)
            return vault
        except VaultError:
            if vault is not None:
                vault.lock()
            elif directory is not None:
                os.close(directory)
            raise
        except (OSError, ValueError, TypeError):
            if vault is not None:
                vault.lock()
            elif directory is not None:
                os.close(directory)
            raise VaultError("vault_io") from None

    @classmethod
    def unlock(cls, path, password):
        directory = None
        transferred = False
        try:
            directory, name = _parent(path)
            serialized = _read(directory, name)
            document = json.loads(serialized)
            if (not isinstance(document, dict) or set(document) != {"header", "ciphertext"}
                    or not isinstance(document["header"], dict)):
                raise VaultError("vault_invalid")
            header = document["header"]
            if (set(header) != {"version", "cipher", "kdf", "salt", "nonce"}
                    or type(header["version"]) is not int or header["version"] != 1
                    or header["cipher"] != "AES-256-GCM" or header["kdf"] != _PARAMETERS
                    or any(type(header["kdf"][field]) is not int for field in ("n", "r", "p"))):
                raise VaultError("vault_invalid")
            salt = _decode(header["salt"], 16)
            nonce = _decode(header["nonce"], 12)
            key = _derive(password, salt)
            plaintext = AESGCM(key).decrypt(nonce, _decode(document["ciphertext"]), _json(header))
            entries = json.loads(plaintext)
            if not isinstance(entries, dict) or len(entries) > 1024:
                raise VaultError("vault_invalid")
            for alias, value in entries.items():
                if not _ALIAS.fullmatch(alias) or not 1 <= len(_decode(value)) <= MAX_SECRET_BYTES:
                    raise VaultError("vault_invalid")
            vault = cls(directory, name, key, salt, entries)
            vault._fingerprint = hashlib.sha256(serialized).digest()
            transferred = True
            return vault
        except InvalidTag:
            raise VaultError("unlock_failed") from None
        except (OSError, ValueError, TypeError, RecursionError):
            raise VaultError("vault_invalid") from None
        finally:
            # A successful object owns the descriptor. Failed paths must close it.
            if directory is not None and not transferred:
                os.close(directory)

    def _check(self):
        if self._key is None:
            raise VaultError("vault_locked")

    def _persist(self, entries, exclusive=False):
        # Directory-level locking avoids a second lockfile and serializes host writers.
        try:
            fcntl.flock(self._directory, fcntl.LOCK_EX)
        except OSError:
            raise VaultError("vault_io") from None
        try:
            info = os.fstat(self._directory)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise VaultError("directory_unsafe")
            if not exclusive:
                current = hashlib.sha256(_read(self._directory, self._name)).digest()
                if current != self._fingerprint:
                    raise VaultError("vault_changed")
            self._persist_unlocked(entries, exclusive)
        except OSError:
            raise VaultError("vault_io") from None
        finally:
            fcntl.flock(self._directory, fcntl.LOCK_UN)

    def _persist_unlocked(self, entries, exclusive):
        nonce = secrets.token_bytes(12)
        header = {"version": 1, "cipher": "AES-256-GCM", "kdf": dict(_PARAMETERS),
                  "salt": _encode(self._salt), "nonce": _encode(nonce)}
        ciphertext = AESGCM(self._key).encrypt(nonce, _json(entries), _json(header))
        contents = _json({"header": header, "ciphertext": _encode(ciphertext)})
        if len(contents) > MAX_FILE_BYTES or len(entries) > 1024:
            raise VaultError("vault_too_large")
        temporary = ".vault-" + secrets.token_hex(16)
        descriptor = None
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=self._directory)
            view = memoryview(contents)
            while view:
                view = view[os.write(descriptor, view):]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            if exclusive:
                # Link publishes atomically without ever overwriting an existing vault.
                os.link(temporary, self._name, src_dir_fd=self._directory,
                        dst_dir_fd=self._directory, follow_symlinks=False)
                os.unlink(temporary, dir_fd=self._directory)
            else:
                _file_info(os.stat(self._name, dir_fd=self._directory, follow_symlinks=False))
                os.replace(temporary, self._name, src_dir_fd=self._directory,
                           dst_dir_fd=self._directory)
            os.fsync(self._directory)
            self._fingerprint = hashlib.sha256(contents).digest()
        except OSError:
            raise VaultError("vault_io") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=self._directory)
            except FileNotFoundError:
                pass

    def put(self, alias, secret):
        with self._mutex:
            self._check()
            if not isinstance(alias, str) or not _ALIAS.fullmatch(alias):
                raise VaultError("alias_invalid")
            if not isinstance(secret, bytes) or not 1 <= len(secret) <= MAX_SECRET_BYTES:
                raise VaultError("secret_invalid")
            entries = dict(self._entries)
            entries[alias] = _encode(secret)
            self._persist(entries)
            self._entries = entries
            self._versions[alias] = self._versions.get(alias, 0) + 1

    def list_aliases(self):
        with self._mutex:
            self._check()
            return sorted(self._entries)

    def version(self, alias):
        with self._mutex:
            self._check()
            if alias not in self._entries:
                raise VaultError('credential_missing')
            return self._versions.get(alias, 0)

    def use(self, alias, callback, *, expected_version=None):
        with self._mutex:
            self._check()
            if not isinstance(alias, str) or alias not in self._entries:
                raise VaultError("credential_missing")
            value = _decode(self._entries[alias])
            epoch = self._epoch
            version = self._versions.get(alias, 0)
            if expected_version is not None and version != expected_version:
                raise VaultError('credential_changed')
        # Never hold the lock across network IO: host lock/revoke stays responsive.
        # Callback is trusted host code, never agent-provided or dynamically loaded.
        result = callback(value)
        with self._mutex:
            self._check()
            if self._epoch != epoch:
                raise VaultError("vault_locked")
            if self._versions.get(alias, 0) != version:
                raise VaultError('credential_changed')
            return result

    def remove(self, alias):
        with self._mutex:
            self._check()
            if not isinstance(alias, str) or alias not in self._entries:
                raise VaultError("credential_missing")
            entries = dict(self._entries)
            del entries[alias]
            self._persist(entries)
            self._entries = entries
            self._versions[alias] = self._versions.get(alias, 0) + 1

    def lock(self):
        with self._mutex:
            self._epoch += 1
            self._key = None
            self._salt = None
            self._fingerprint = None
            self._entries.clear()
            if self._directory is not None:
                os.close(self._directory)
                self._directory = None

    def __del__(self):
        if getattr(self, "_directory", None) is not None:
            os.close(self._directory)
            self._directory = None
