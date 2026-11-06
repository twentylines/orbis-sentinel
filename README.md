# Orbis Sentinel

Orbis Sentinel is the independent maintenance and recovery companion for [Orbis](https://github.com/twentylines/orbis).

The current source provides a read-only local service, component version status, a private persistent job journal, and shared Linux telemetry sampling. Telemetry reports total-machine CPU use, memory, network traffic, configured filesystem capacity, and available thermal readings. Missing observations remain unavailable. A separate sampling process keeps slow hardware or filesystem reads out of API handlers. Expired samples are marked stale.

The job journal records work and progress. A privileged supervisor must separately authorize system operations and establish ownership before executing them. Interrupted claims remain pending for reconciliation.

This is pre-release software. The gateway, recovery interface, privileged lifecycle operations and OTA artifacts are not available yet. The local service does not replace the existing Orbis host daemon or make update and restore decisions.

## Local service

Linux and Python 3.10 or newer are required. No third-party Python packages are needed. Start the service with an existing private runtime directory owned by the service user:

```sh
python3 -I bin/orbis-sentinel --socket /run/orbis-sentinel/api.sock
```

The directory must be mode `0700`; existing socket paths are refused. Repeat `--disk-path /path` to monitor selected filesystems. The default is `/`. The service does not open a TCP port. Unix peer credentials restrict API access to root and the service user.

Four read-only GET endpoints are available under `/sentinel/api/v1`: `health`, `status`, `telemetry` and `progress`. Status reports the running Sentinel source version. Orbis health remains `unknown`; a responding Sentinel or a completed update record does not establish Orbis health. Telemetry responses include their observation age and an explicit ready, starting, stale or unavailable state. A failed sampler is restarted only after its owned process exits; repeated failures stop automatic restarts.

The optional `--observer-socket` connects to an enrolled, read-only host progress socket. Sentinel verifies its root owner, group, permissions, inode identity, connected server credentials and protocol capability. It reports the protected update's actual phase and download byte counts. Missing, invalid or expired observations become unavailable; progress never authorizes a recovery action or establishes that routing can return to Orbis.

## systemd

The units in `packaging/systemd` run the local service as an unprivileged dynamic user and retain a root-only socket across service restarts. They expect the source bundle at `/opt/orbis-sentinel/current`. Install both unit files under `/etc/systemd/system`, then enable both `orbis-sentinel.socket` and `orbis-sentinel.service` to keep the service running after boot. The systemd-created socket directory uses mode `0755`; this differs from the private directory required by standalone mode because systemd owns the socket and passes its listening descriptor to the service.

Keep the existing Orbis host service enabled. These units provide status and telemetry only; they do not enroll Orbis, expose a browser interface or grant privileged recovery access.

### Optional host progress bridge

The observer profile is separate from the base service. It requires a compatible Orbis host helper advertising `sentinel-observer.v1` on its existing private capability endpoint. Upgrade and verify that helper before enabling the profile; older helpers keep their existing upgrade path.

The profile files comprise `packaging/sysusers.d/orbis-sentinel-observer.conf`, `orbis-host-observer.socket` and the two service drop-in directories. The sysusers file creates the dedicated `orbis-observer` group. The host socket is root-owned with mode `0660` and this group; Sentinel keeps its dynamic user and uses the group as its primary group. The existing privileged `/run/orbis/host.sock` remains private and is never granted to Sentinel.

Enable the profile only during an idle, verified helper enrollment. Its socket descriptor is passed to the existing host daemon, which owns all privileged records and operations. The observer serves only a fixed capability and sanitized update progress. It cannot invoke update, restart, restore, routing cleanup or other mutation endpoints. Disabling the profile makes Sentinel's progress unavailable while its local service continues to run.

Licensed under the GNU General Public License v3. See [LICENSE](LICENSE).
