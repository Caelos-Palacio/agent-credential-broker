import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from credential_broker.vault import MAX_FILE_BYTES, Vault, VaultError


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "private" / "vault.json"
        self.password = b"fixture master password only"
        self.vault = Vault.create(self.path, self.password)

    def tearDown(self):
        self.vault.lock()
        self.temporary.cleanup()

    def assert_code(self, code, operation):
        with self.assertRaises(VaultError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)

    def test_roundtrip_encrypted_and_host_callback(self):
        secret = b"FAKE_TEST_API_TOKEN_NEVER_REAL"
        self.vault.put("cred_fixture", secret)
        serialized = self.path.read_bytes()
        self.assertNotIn(secret, serialized)
        self.assertNotIn(b"cred_fixture", serialized)
        self.assertEqual(self.vault.list_aliases(), ["cred_fixture"])
        self.assertFalse(hasattr(self.vault, "get_secret"))
        self.vault.lock()
        self.vault = Vault.unlock(self.path, self.password)
        self.assertTrue(self.vault.use("cred_fixture", lambda value: value == secret))
        self.vault.remove("cred_fixture")
        self.assertEqual(self.vault.list_aliases(), [])

    def test_wrong_password_has_constant_error(self):
        self.assert_code("unlock_failed", lambda: Vault.unlock(self.path, b"wrong fixture password"))

    def test_ciphertext_and_header_tampering(self):
        original = self.path.read_bytes()
        document = json.loads(original)
        document["ciphertext"] = "AA" + document["ciphertext"][2:]
        self.path.write_text(json.dumps(document))
        self.assert_code("unlock_failed", lambda: Vault.unlock(self.path, self.password))
        self.path.write_bytes(original)
        document = json.loads(original)
        document["header"]["salt"] = "AA" + document["header"]["salt"][2:]
        self.path.write_text(json.dumps(document))
        self.assert_code("unlock_failed", lambda: Vault.unlock(self.path, self.password))

    def test_untrusted_kdf_cost_rejected_before_derivation(self):
        document = json.loads(self.path.read_bytes())
        document["header"]["kdf"]["n"] = 2 ** 50
        self.path.write_text(json.dumps(document))
        with patch("credential_broker.vault._derive") as derive:
            self.assert_code("vault_invalid", lambda: Vault.unlock(self.path, self.password))
            derive.assert_not_called()

    def test_permissions_and_atomic_failure_preserve_previous_state(self):
        self.assertEqual(self.path.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.vault.put("original", b"fixture_original")
        before = self.path.read_bytes()
        with patch("credential_broker.vault.os.replace", side_effect=OSError("hidden detail")):
            self.assert_code("vault_io", lambda: self.vault.put("new", b"fixture_new"))
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.vault.list_aliases(), ["original"])
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_file_symlink_and_parent_symlink_rejected(self):
        alias = self.path.parent / "alias"
        alias.symlink_to(self.path)
        self.assert_code("vault_invalid", lambda: Vault.unlock(alias, self.password))
        link = Path(self.temporary.name) / "linked"
        link.symlink_to(self.path.parent, target_is_directory=True)
        self.assert_code("vault_invalid", lambda: Vault.unlock(link / "vault.json", self.password))

    def test_hardlink_refused_for_read_and_write(self):
        os.link(self.path, self.path.parent / "second")
        self.assert_code("file_unsafe", lambda: Vault.unlock(self.path, self.password))
        self.assert_code("file_unsafe", lambda: self.vault.put("other", b"fixture_other"))

    def test_oversized_file_and_secret_rejected(self):
        self.assert_code("secret_invalid", lambda: self.vault.put("huge", b"x" * 65537))
        with self.path.open("r+b") as handle:
            handle.truncate(MAX_FILE_BYTES + 1)
        self.assert_code("vault_too_large", lambda: Vault.unlock(self.path, self.password))

    def test_lock_rejects_all_operations_and_is_idempotent(self):
        self.vault.lock()
        self.vault.lock()
        for action in (lambda: self.vault.put("a", b"fixture"), self.vault.list_aliases,
                       lambda: self.vault.use("a", lambda value: value),
                       lambda: self.vault.remove("a")):
            self.assert_code("vault_locked", action)

    def test_create_never_overwrites_existing_vault(self):
        before = self.path.read_bytes()
        self.assert_code("vault_exists", lambda: Vault.create(self.path, self.password))
        self.assertEqual(self.path.read_bytes(), before)

    def test_directory_and_file_permissions_fail_closed(self):
        self.path.chmod(0o644)
        self.assert_code("file_unsafe", lambda: Vault.unlock(self.path, self.password))
        self.path.chmod(0o600)
        self.path.parent.chmod(0o755)
        self.assert_code("directory_unsafe", lambda: Vault.unlock(self.path, self.password))
        self.path.parent.chmod(0o700)

    def test_stale_second_writer_cannot_erase_first_writer(self):
        other = Vault.unlock(self.path, self.password)
        try:
            self.vault.put("first", b"fixture_first")
            self.assert_code("vault_changed", lambda: other.put("second", b"fixture_second"))
            self.assertEqual(other.list_aliases(), [])
            self.assertEqual(self.vault.list_aliases(), ["first"])
        finally:
            other.lock()

    def test_lock_remains_responsive_during_use_and_discards_result(self):
        self.vault.put("active", b"fixture_active")
        entered, released, locked = threading.Event(), threading.Event(), threading.Event()
        outcome = []

        def callback(value):
            entered.set()
            released.wait(2)
            return "private_result"

        def use():
            try:
                outcome.append(self.vault.use("active", callback))
            except VaultError as error:
                outcome.append(error.code)

        worker = threading.Thread(target=use)
        worker.start()
        self.assertTrue(entered.wait(1))
        closer = threading.Thread(target=lambda: (self.vault.lock(), locked.set()))
        closer.start()
        try:
            self.assertTrue(locked.wait(1))
        finally:
            released.set()
            worker.join(2)
            closer.join(2)
        self.assertEqual(outcome, ["vault_locked"])


if __name__ == "__main__":
    unittest.main()
