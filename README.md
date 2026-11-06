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

## Offline capture verification

The root-only `bin/orbis-sentinel-verify` command can verify an existing sealed Orbis core capture while the main Orbis container is unavailable. It uses a locally retained, independently approved recovery image containing the compatible publication worker. The image must be supplied by its immutable `sha256:` image ID; the command never downloads an image.

The command copies only the selected point's encrypted core, encrypted metadata, point record and master key into a private retained workspace. The verification container has no network, a read-only filesystem and input mount, no capabilities, and a separate writable staging directory. It authenticates the encrypted payload and retained image archives using the existing Orbis format. Dashboard previews are not verified by this command.

Run `python3 -I bin/orbis-sentinel-verify --help` for the operator arguments. The scratch directory must already exist, be root-owned mode `0700`, and have protected root-owned ancestors. The checkpoint expectation, owner and creation time must come from the protected supervisor's original capture records. An image ID pins bytes; the supervisor must separately establish that the retained image is trusted and compatible.

Success reports data verification only. It does not start Orbis, restore files, adopt a capture, release a maintenance hold or authorize recovery. Private workspace and container identity records remain for reconciliation. Exit status `2` means verifier cleanup is uncertain; do not repeat the operation until its retained identity record has been reviewed. This command is not yet connected to the recovery UI or capture completion service.

## Protected capture catalog

The `capture_catalog` library retains a capture reservation and its private decryption key before a separately authorized capture drains Orbis. It then publishes an immutable copy of the verified encrypted point, including its selected wallpaper and application icons. A compatible retained image must include the catalog verification worker. Neither reservation nor publication starts a capture or grants permission to change the host.

The catalog requires an existing root-owned `0700` directory on persistent storage, with protected root-owned ancestors. Its backing must be outside every Orbis reset and rollback boundary and must not be exposed through writable Orbis mounts. Reservation requires the trusted source directory; overlapping paths, underlying bind aliases and nested source mounts exposing catalog backing are refused before a key is written. This protects against accidental placement, not another process with host-root or Docker-daemon authority. Installer enrollment and supervisor authorization remain separate requirements.

Reservation and publication use durable atomic directory commits. After a successful commit, a repeated request observes the existing record; unfinished work remains available for inspection. Verification runs against a detached copy using the reserved key, so the original Orbis key directory is unnecessary. The published point contains no raw master key. Catalog listing reports recorded verification with current file-identity checks, avoiding archive reads on every refresh; export and restore must authenticate delivered bytes again.

This library is not yet connected to the local API, automatic capture scheduling, restore activation or the recovery interface. Its data state does not establish lifecycle completion, release maintenance holds or authorize replay after a supervisor restart.

### Host capture custody

`bin/orbis-sentinel-capture` provides a root-only descriptor handoff for an explicitly enrolled host helper. The helper pins the complete protected Sentinel Python bundle, reserves the original key before source draining, then retains the paused source's encrypted draft and selected assets before admitting a capture worker. Keys and draft directories cross the process boundary as read-only file descriptors. Requests contain bindings and paths, never raw key bytes. Capture storage must be separate from the installation, actual backup backing and the controller's writable directory mounts, including separately configured drives.

Drafts use the explicit `retained-unverified` state. Atomic staging and retries preserve the original reservation, preparation and source-hold bindings. Retaining a draft neither authenticates a complete snapshot nor authorizes shutdown, restart, restore, worker replay or maintenance-hold release. The launcher does not expose an HTTP endpoint. Existing installations without an enrolled profile retain their current capture path; enrollment is not yet automatic.

### Independent data publication

The separate `--publication-capability` and root-only `--publish` operation assemble a capture from its retained draft/key and an approved checkpoint descriptor. The host caller must first validate the protected original-source records and successful independent supervisor witness. Local image IDs are exported without pulling or loading images; restricted offline workers authenticate image archives, seal the capture, then independently verify its full encrypted contents and selected preview assets. No worker receives the Docker socket.

A persistent claim precedes external work. Incomplete or uncertain attempts require reconciliation; repeating the command does not repeat them. A successfully committed reply can be recovered by observing the same bound object. The exclusively owned sealed workspace is verified in place and adopted by directory rename, avoiding another full capture copy. Original retained drafts, keys and failure evidence remain private.

This publishes verified data while Orbis is unavailable. It does not complete the capture lifecycle, release holds, start services or restore data. Automatic workflow enrollment, lifecycle settlement, the recovery UI and real application restoration still need integration and verification.

### Publication image preflight

The separate `--image-check-capability` identifies an optional image-check protocol. An enrolled host can use `--check-publication-image` before creating a capture preparation. A restricted container checks the exact publication, sealing, catalog and image-inventory worker capabilities in the approved local image. It receives no host mounts, keys or network access. The image ID must already be independently approved; a capability response does not establish trust.

The new `--reserve-for-publication` operation repeats that check under the catalog lock before reading and retaining the supplied key descriptor. It returns both custody and image-check evidence, allowing a compatible supervisor to bind one publisher before draining the source. Missing workers, malformed replies and uncertain cleanup stop the new path. The original custody capability and `--reserve` operation remain unchanged for older callers and images. Neither image checks nor publisher selection release maintenance holds or authorize replay.

### Verified point transfer

The separate `--export-capability` and root-only `--export-file` operation let a compatible supervisor read one fixed file from a published capture. Requests bind the publication, preparation, source hold and successful terminal witness. Export checks the recorded object and file identities, hashes the delivered bytes, and checks the pinned catalog again. Raw keys and arbitrary paths cannot be exported.

Stdout contains only the requested file. Its bytes remain provisional until the process exits successfully; a receiver must discard incomplete or failed output. The Orbis host bridge also withholds the final chunk until Sentinel exits successfully and its protected publication records are rechecked. Transfers neither restore data nor release maintenance holds. Automatic capture handoff and recovery UI integration remain separate work.
