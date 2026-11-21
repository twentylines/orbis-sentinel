"""The recovery service is independently started from protected Root inputs."""
import configparser
from pathlib import Path
import unittest


class RecoveryServicePackagingTests(unittest.TestCase):
    def setUp(self):
        self.path=Path(__file__).resolve().parents[1]/'packaging/systemd/orbis-sentinel-recovery.service'
        self.unit=configparser.ConfigParser(interpolation=None,strict=False)
        self.unit.read(self.path)

    def test_independent_of_main_and_stable_across_current_selector_changes(self):
        body=self.path.read_text()
        for main_dependency in ('runtipi','orbis-host.service','Requires=','/current/'):
            self.assertNotIn(main_dependency,body)
        self.assertIn('docker.service',self.unit['Unit']['After'])
        self.assertEqual(self.unit['Service']['ExecStart'],'/usr/bin/python3 -I ${ORBIS_SENTINEL_RECOVERY_RUNTIME} --recovery-profile ${ORBIS_SENTINEL_RECOVERY_PROFILE}')
        self.assertEqual(self.unit['Service']['EnvironmentFile'],'/etc/orbis-sentinel/recovery.env')
        self.assertEqual(self.unit['Unit']['ConditionPathExists'],self.unit['Service']['EnvironmentFile'])

    def test_root_key_custody_and_only_recovery_store_writable(self):
        service=self.unit['Service']
        self.assertEqual(service['User'],'root');self.assertEqual(service['Group'],'root');self.assertEqual(service['UMask'],'0077')
        self.assertEqual(service['ProtectSystem'],'strict');self.assertEqual(service['ReadWritePaths'],'/var/lib/orbis-sentinel/recovery')
        self.assertEqual(service['NoNewPrivileges'],'yes');self.assertEqual(service['CapabilityBoundingSet'],'')
        self.assertEqual(service['PrivateDevices'],'yes');self.assertEqual(service['ProtectHome'],'yes')

    def test_loopback_network_and_control_group_children_bounded(self):
        service=self.unit['Service']
        self.assertEqual(service['IPAddressDeny'],'any');self.assertEqual(service['IPAddressAllow'],'localhost')
        self.assertEqual(service['KillMode'],'control-group');self.assertGreaterEqual(int(service['TimeoutStopSec'].removesuffix('s')),180)
        self.assertEqual(service['MemoryMax'],'256M');self.assertEqual(service['TasksMax'],'32')
        self.assertEqual(self.unit['Install']['WantedBy'],'multi-user.target')


if __name__=='__main__':unittest.main()
