# Orbis Sentinel

Orbis Sentinel is the independent maintenance and recovery companion for [Orbis](https://github.com/twentylines/orbis).

The current source package provides lifecycle contracts, component version status, a private persistent job journal, and shared Linux telemetry sampling. Telemetry reports total-machine CPU use, memory, network traffic, configured filesystem capacity, and available thermal readings. Missing observations remain unavailable.

The job journal records work and progress. A privileged supervisor must separately authorize system operations and establish ownership before executing them. Interrupted claims remain pending for reconciliation.

This is pre-release source. An installable companion service, recovery interface, and OTA artifacts are not published yet.

Licensed under the GNU General Public License v3. See [LICENSE](LICENSE).
