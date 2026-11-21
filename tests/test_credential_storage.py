"""Bounded mountinfo interpretation, qualified self-bind, and stable-role validation."""
import copy
from pathlib import Path
import stat
import unittest
from unittest import mock

from orbis_sentinel import credential_storage as storage


class StorageViews(unittest.TestCase):
    BASE = (b'30 1 8:1 / / rw - ext4 /dev/device rw\n'
            b'33 30 0:2 / /proc rw - proc proc rw\n')
    PATH = Path('/var/lib/orbis state')
    EXPECTED = {'path': str(PATH), 'filesystem': 'ext4', 'uuid': 'a' * 32, 'handle': 'b' * 16,
                'owner': [0, 0, stat.S_IFDIR | 0o700], 'filesystemPath': str(PATH),
                'mountPoint': '/', 'mountRoot': '/'}

    def test_mount_view_looks_up_held_fd_and_parses_canonical_escaped_rows(self):
        alias = b'41 30 8:1 /var/lib/orbis\\040state /var/lib/orbis\\040state rw - ext4 /dev/device rw\n'
        observation = storage._view(self.BASE + alias, self.PATH, 41)
        self.assertEqual((observation.mount_id, observation.root, observation.point), (41, self.PATH, self.PATH))
        with self.assertRaises(storage.CredentialStorageError):
            storage._view(self.BASE + alias, self.PATH, 30)
        with self.assertRaises(storage.CredentialStorageError):
            storage._view(self.BASE + alias + alias.replace(b'41 ', b'42 ', 1), self.PATH, 41)

    def test_malformed_mount_and_unsupported_projections_reject(self):
        for changed in (self.BASE[:-1], self.BASE.replace(b'/ / rw', b'/ /../ rw'),
                        self.BASE.replace(b'/ / rw', b'/ /\\037 rw'), self.BASE + b'broken\n'):
            with self.subTest(changed=changed), self.assertRaises(storage.CredentialStorageError):
                storage._view(changed, self.PATH, 30)
        with self.assertRaises(storage.CredentialStorageError):
            storage._view(self.BASE, self.PATH, 9876)

    def test_same_handle_in_unqualified_bind_or_other_role_does_not_pass(self):
        qualified = {**self.EXPECTED, 'mountPoint': str(self.PATH), 'mountRoot': str(self.PATH)}
        with mock.patch.object(storage, 'observe', return_value=qualified), mock.patch.object(storage, 'in_recovery_unit', return_value=True):
            storage.verify_role('recovery', None, self.EXPECTED, recovery=True)
            for role, recovery in (('recovery', False), ('journal', True), ('namespace', True)):
                with self.subTest(role=role, recovery=recovery), self.assertRaises(storage.CredentialStorageError):
                    storage.verify_role(role, None, self.EXPECTED, recovery=recovery)
        for field, changed in (('uuid', 'c' * 32), ('handle', 'c' * 16), ('filesystemPath', '/bind-elsewhere')):
            counterfeit = {**qualified, field: changed}
            with mock.patch.object(storage, 'observe', return_value=counterfeit), mock.patch.object(storage, 'in_recovery_unit', return_value=True):
                with self.subTest(field=field), self.assertRaises(storage.CredentialStorageError):
                    storage.verify_role('recovery', None, self.EXPECTED, recovery=True)

    def test_bridge_roles_require_exact_scope_and_ext4_shape(self):
        value = {'schema': storage.BRIDGE_SCHEMA, 'installationId': '1' * 64, 'context': 'host',
                 'daemon': 'local', 'parentFloorSha256': '2' * 64, 'publicationOperation': '3' * 64,
                 'publicationSha256': '4' * 64, 'recoveryUnitSha256': '5' * 64,
                 'roles': {name: copy.deepcopy(self.EXPECTED) for name in storage.ROLES}}
        scope = {'installation': '1' * 64, 'context': 'host', 'daemon': 'local', 'previous': '2' * 64}
        storage.validate_bridge(value, **scope)
        for key, replacement in (('filesystem', 'tmpfs'), ('uuid', '0' * 32), ('owner', [0, 0, 0o700])):
            rejected = copy.deepcopy(value)
            rejected['roles']['journal'][key] = replacement
            with self.subTest(key=key), self.assertRaises(storage.CredentialStorageError):
                storage.validate_bridge(rejected, **scope)
        with self.assertRaises(storage.CredentialStorageError):
            storage.validate_bridge(value, **{**scope, 'daemon': 'different-daemon'})

    def test_bootstrap_bridge_cannot_be_used_as_an_ordinary_storage_upgrade(self):
        ordinary = {'schema': storage.BRIDGE_SCHEMA, 'installationId': '1' * 64, 'context': 'host',
                    'daemon': 'local', 'parentFloorSha256': '2' * 64, 'publicationOperation': '3' * 64,
                    'publicationSha256': '4' * 64, 'recoveryUnitSha256': '5' * 64,
                    'roles': {name: copy.deepcopy(self.EXPECTED) for name in storage.ROLES}}
        scope = {'installation': '1' * 64, 'context': 'host', 'daemon': 'local', 'previous': '2' * 64}
        bootstrap = {**ordinary, 'schema': storage.ACTIVATION_BRIDGE}
        storage.validate_bootstrap_bridge(bootstrap, **scope)
        with self.assertRaises(storage.CredentialStorageError):
            storage.validate_bridge(bootstrap, **scope)
        with self.assertRaises(storage.CredentialStorageError):
            storage.validate_bootstrap_bridge(ordinary, **scope)
        for changes in ({'publicationSha256': None}, {'released': True}, {'roles': {}}, {'schema': 'unknown'}):
            with self.subTest(changes=changes), self.assertRaises(storage.CredentialStorageError):
                storage.validate_bootstrap_bridge({**bootstrap, **changes}, **scope)
        with self.assertRaises(storage.CredentialStorageError):
            storage.validate_bootstrap_bridge(bootstrap, **{**scope, 'previous': '9' * 64})


if __name__ == '__main__':
    unittest.main()
