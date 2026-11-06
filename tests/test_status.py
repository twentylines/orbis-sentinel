import unittest

from orbis_sentinel.contracts import PROTOCOL_VERSION
from orbis_sentinel.status import ComponentStatus, build_status


class StatusTests(unittest.TestCase):
    def test_normal_and_dev_versions_serialize_independently(self):
        result = build_status(
            ComponentStatus("1.2.3", "1.3.0", "healthy"),
            ComponentStatus("0.1.0-dev.1", None, "updating"),
        )
        self.assertEqual(result, {
            "schema": "orbis-sentinel.status.v1",
            "protocolVersion": PROTOCOL_VERSION,
            "components": {
                "orbis": {"installedVersion": "1.2.3", "availableVersion": "1.3.0", "state": "healthy"},
                "sentinel": {"installedVersion": "0.1.0-dev.1", "availableVersion": None, "state": "updating"},
            },
        })

    def test_unknown_and_offline_observations(self):
        self.assertEqual(build_status(ComponentStatus(None, None, "unknown"), ComponentStatus(None, None, "unavailable"))["components"]["orbis"], {
            "installedVersion": None, "availableVersion": None, "state": "unknown"
        })

    def test_rejects_invalid_states_types_and_versions(self):
        for args in ((None, None, "ready"), (1, None, "unknown"), (None, None, 1), ("1.2", None, "unknown"), ("1.2.3\n", None, "unknown"), ("1.2.3" * 30, None, "unknown")):
            with self.subTest(args=args), self.assertRaises((TypeError, ValueError)):
                ComponentStatus(*args)
        with self.assertRaises(TypeError):
            build_status(None, ComponentStatus(None, None, "unknown"))


if __name__ == "__main__":
    unittest.main()
