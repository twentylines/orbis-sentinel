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

Three read-only GET endpoints are available under `/sentinel/api/v1`: `health`, `status` and `telemetry`. Status reports the running Sentinel source version. Orbis remains `unknown` until an independent observer is connected; a responding Sentinel does not establish Orbis health. Telemetry responses include their observation age and an explicit ready, starting, stale or unavailable state. A failed sampler is restarted only after its owned process exits; repeated failures stop automatic restarts.

## systemd

The units in `packaging/systemd` run the local service as an unprivileged dynamic user and retain a root-only socket across service restarts. They expect the source bundle at `/opt/orbis-sentinel/current`. Install both unit files under `/etc/systemd/system`, then enable both `orbis-sentinel.socket` and `orbis-sentinel.service` to keep the service running after boot. The systemd-created socket directory uses mode `0755`; this differs from the private directory required by standalone mode because systemd owns the socket and passes its listening descriptor to the service.

Keep the existing Orbis host service enabled. These units provide status and telemetry only; they do not enroll Orbis, expose a browser interface or grant privileged recovery access.

Licensed under the GNU General Public License v3. See [LICENSE](LICENSE).
