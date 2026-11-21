import os
from pathlib import Path
import tempfile
import threading
import unittest
from types import SimpleNamespace

from orbis_sentinel.telemetry import TelemetrySampler


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "net").mkdir()
        (self.root / "thermal_zone0").mkdir()
        self.now = 1.0
        self.write("stat", "cpu 10 0 10 80 0 0 0 0 0 0\n")
        self.write("meminfo", "MemTotal: 100 kB\nMemAvailable: 40 kB\n")
        self.net("eth0: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0")
        self.write("thermal_zone0/temp", "42000\n")
        self.sampler = TelemetrySampler(["/configured"], proc_root=self.root, thermal_root=self.root,
            monotonic=lambda: self.now, wall_time=lambda: 17.0, platform="linux", statvfs=lambda _: SimpleNamespace(
                f_blocks=100, f_bfree=30, f_bavail=20, f_frsize=4))

    def write(self, name, content):
        (self.root / name).write_text(content, encoding="ascii")

    def net(self, lines):
        self.write("net/dev", "Inter-| Receive | Transmit\n face |bytes packets |bytes packets\n" + lines + "\n")

    def rich_inputs(self):
        self.write("cpuinfo", "model name : Actual   CPU\ncpu MHz : 1200.0\ncpu MHz : 2400.0\n")
        self.write("uptime", "71.4 121.9\n")
        self.write("meminfo", "MemTotal: 100 kB\nMemAvailable: 40 kB\nSwapTotal: 20 kB\nSwapFree: 10 kB\n")
        self.write("stat", "cpu 10 0 10 80 0 0 0 0\ncpu9 5 0 5 40 0 0 0 0\ncpu2 5 0 5 40 0 0 0 0\n")

    def test_whole_host_group_shares_real_timestamp_and_measured_counter_sources(self):
        self.rich_inputs()
        self.sampler.wall_time = lambda: 17.0 + self.now
        self.assertIsNone(self.sampler.samples()[1])
        self.now = 2
        self.write("stat", "cpu 20 0 20 120 0 0 0 0\ncpu9 15 0 15 60 0 0 0 0\ncpu2 5 0 5 60 0 0 0 0\n")
        coarse, system = self.sampler.samples()
        self.assertEqual(system["sampledAt"], coarse["sampledAt"])
        self.assertEqual(system["sampledAt"], 19000)
        self.assertEqual(system["cpu"]["totalPercent"], coarse["cpuPercent"])
        self.assertAlmostEqual(system["cpu"]["totalPercent"], 100 / 3)
        self.assertEqual(system["cpu"]["perCorePercent"], [0, 50])
        self.assertEqual(system["cpu"]["model"], "Actual CPU")
        self.assertEqual(system["cpu"]["reportedClockGHz"], 1.8)
        self.assertEqual(system["cpu"]["uptimeSeconds"], 71.4)
        self.assertEqual(system["memory"], {"totalBytes": 102400, "availableBytes": 40960,
                                            "swapTotalBytes": 20480, "swapFreeBytes": 10240})
        self.assertEqual(coarse["memory"], {"totalBytes": 102400, "availableBytes": 40960})
        self.assertNotIn("cpu", coarse)
        system["cpu"]["perCorePercent"][0] = 100
        self.assertEqual(self.sampler.samples()[1]["cpu"]["perCorePercent"], [0, 50])

    def test_partial_or_discontinuous_group_never_reuses_last_rich_observation(self):
        self.rich_inputs()
        self.sampler.sample()
        self.now = 2
        self.write("stat", "cpu 20 0 20 120\ncpu9 15 0 15 60\ncpu3 5 0 5 60\n")
        self.assertIsNone(self.sampler.samples()[1])  # hotplug
        self.now = 3
        self.write("stat", "cpu 30 0 30 160\ncpu9 25 0 25 80\ncpu3 5 0 5 80\n")
        self.write("cpuinfo", "model name : Model with nominal 3.0GHz\n")
        coarse, system = self.sampler.samples()
        self.assertIsNotNone(coarse["cpuPercent"])
        self.assertIsNone(system)
        self.now = 40
        self.write("cpuinfo", "model name : Actual CPU\ncpu MHz : 2500.0\n")
        self.write("stat", "cpu 40 0 40 200\ncpu9 35 0 35 100\ncpu3 5 0 5 100\n")
        self.assertIsNone(self.sampler.samples()[1])  # elapsed out of bounds
        self.now = 41
        self.write("stat", "cpu 50 0 50 240\ncpu9 45 0 45 120\ncpu3 5 0 5 120\n")
        self.assertEqual(self.sampler.samples()[1]["cpu"]["reportedClockGHz"], 2.5)
        self.now = 42
        self.write("stat", "cpu 60 0 60 280\ncpu9 55 0 55 140\ncpu3 5 0 5 140\n")
        self.write("meminfo", "MemTotal: 100 kB\nMemAvailable: 40 kB\nSwapTotal: 5 kB\nSwapFree: 10 kB\n")
        self.assertIsNone(self.sampler.samples()[1])

    def test_initial_then_delta_and_cache_isolation(self):
        first = self.sampler.sample()
        self.assertIsNone(first["cpuPercent"])
        self.assertEqual(first["sampledAt"], 17000)
        self.assertIsNone(first["network"]["eth0"]["receiveBytesPerSecond"])
        self.assertEqual(first["memory"], {"totalBytes": 102400, "availableBytes": 40960})
        self.assertEqual(first["filesystems"]["/configured"]["availableBytes"], 80)
        self.assertEqual(first["thermal"], {"thermal_zone0": 42.0})
        first["memory"] = None
        self.write("stat", "cpu 20 0 20 160 0 0 0 0\n")
        self.net("eth0: 300 0 0 0 0 0 0 0 600 0 0 0 0 0 0 0")
        self.assertIsNotNone(self.sampler.sample()["memory"])
        self.now = 3
        second = self.sampler.sample()
        self.assertAlmostEqual(second["cpuPercent"], 20)
        self.assertEqual(second["network"]["eth0"]["receiveBytesPerSecond"], 100)
        self.assertEqual(second["network"]["eth0"]["transmitBytesPerSecond"], 200)
        self.assertIsNone(second["perAppCpu"])
        self.assertIsNone(second["gpu"])

    def test_invalid_reads_do_not_replace_baselines_and_reset_hotplug(self):
        self.sampler.sample()
        self.now = 2
        self.write("stat", "bad")
        self.net("broken")
        self.write("meminfo", "MemTotal: bad kB")
        bad = self.sampler.sample()
        self.assertIsNone(bad["cpuPercent"])
        self.assertIsNone(bad["network"])
        self.assertIsNone(bad["memory"])
        self.now = 3
        self.write("stat", "cpu 20 0 20 160 0 0 0 0")
        self.net("eth0: 300 0 0 0 0 0 0 0 600 0 0 0 0 0 0 0\nnew: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0")
        good = self.sampler.sample()
        self.assertEqual(good["network"]["eth0"]["receiveBytesPerSecond"], 100)
        self.assertIsNone(good["network"]["new"]["receiveBytesPerSecond"])
        self.now = 4
        self.write("stat", "cpu 1 0 1 8 0 0 0 0")
        self.net("eth0: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0")
        reset = self.sampler.sample()
        self.assertIsNone(reset["cpuPercent"])
        self.assertIsNone(reset["network"]["eth0"]["receiveBytesPerSecond"])

    def test_missing_oversize_and_non_linux(self):
        self.write("stat", "x" * (1024 * 1024 + 1))
        os.unlink(self.root / "net/dev")
        result = self.sampler.sample()
        self.assertIsNone(result["cpuPercent"])
        self.assertIsNone(result["network"])
        other = TelemetrySampler(platform="darwin").sample()
        self.assertIsNone(other["memory"])
        self.assertIsNone(other["thermal"])

    def test_shared_lock_and_clock_validation(self):
        results = []
        collections = []
        original = self.sampler.statvfs
        def counted(path):
            collections.append(path)
            return original(path)
        self.sampler.statvfs = counted
        threads = [threading.Thread(target=lambda: results.append(self.sampler.sample())) for _ in range(12)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(len(results), 12)
        self.assertEqual(collections, ["/configured"])
        self.assertTrue(all(result == results[0] for result in results))
        self.now = float("nan")
        with self.assertRaises(ValueError): self.sampler.sample()
        for interval in (0, -1, float("inf"), True):
            with self.assertRaises(ValueError): TelemetrySampler(interval=interval)

    def test_oversized_numeric_counters_are_unavailable_instead_of_overflowing(self):
        huge = "9" * 400
        self.sampler.sample()
        self.now = 2
        self.write("stat", "cpu " + " ".join([huge] * 8))
        self.write("meminfo", "MemTotal: " + huge + " kB\nMemAvailable: 1 kB\n")
        self.net("eth0: " + huge + " 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0")
        result = self.sampler.sample()
        self.assertIsNone(result["cpuPercent"])
        self.assertIsNone(result["memory"])
        self.assertIsNone(result["network"])
        self.assertEqual(result["sampledAt"], 17000)

    def test_configured_work_and_sample_timestamp_are_bounded(self):
        for paths in (["relative"], ["/a", "/a"], ["/a\x00b"], ["/" + str(i) for i in range(65)]):
            with self.assertRaises(ValueError): TelemetrySampler(paths)
        for interval in (0.01, 3601, 10 ** 400):
            with self.assertRaises(ValueError): TelemetrySampler(interval=interval)
        self.sampler.wall_time = lambda: float("inf")
        with self.assertRaises(ValueError): self.sampler.sample()


if __name__ == "__main__":
    unittest.main()
