# Pinned publisher verifier

A new Linux installation can prepare its publisher-verification dependency with `bootstrap_verifier.py`. This is a separate step before `verify_release.py` or the managed activation installer. The bootstrap accepts only the reviewed official GitHub CLI 2.103.3 archive for Linux amd64 or arm64, using fixed archive, binary and licence hashes in trusted installer source. Unsupported systems and architectures fail closed.

The installer scripts themselves must already be trusted. A downloaded Sentinel archive cannot authenticate its own installer or choose its verifier pins. Obtain the official GitHub CLI archive using a trusted downloader; the bootstrap does not access the network or run the downloaded program.

Print the fixed download metadata for the current host:

```sh
python3 packaging/bootstrap_verifier.py --print-spec
```

Create a canonical cache directory first, owned by root for a system installation. Its ancestors must be root-owned or owned by the invoking user and must not be writable by other users. Then provide the downloaded archive and cache as absolute paths:

```sh
python3 packaging/bootstrap_verifier.py \
  --archive /path/to/downloaded-official-gh.tar.gz \
  --cache /path/to/trusted-verifier-cache
```

The command returns the prepared `verifier` path and `activated: false`. Pass that path as `--verifier` to the publisher consumer. Preparing the CLI does not validate a Sentinel package: the consumer must still verify the Sigstore bundle, publisher repository, workflow, branch, source revision and artifact digest.

The cache retains only the pinned executable, its licence and a deterministic receipt. It checks the archive before extraction, bounds expanded data and entries, rejects links and unsafe paths, validates the ELF architecture, and publishes a new cache directory without replacing an existing one. The executable is mode `0555`; the licence and receipt are mode `0444`. Every reuse rechecks the entire inventory, hashes, modes, ownership and path identities. A valid cache can be reused after its original download is removed.

Concurrent bootstraps use an exclusive protected lock. A changed cache, lock, parent directory or prepared directory fails closed. Failed staging directories are retained for review; rerunning does not repair or overwrite changed data. Do not remove a lock or cache merely to bypass a failure. Updating the pinned CLI requires a reviewed installer source change and renewed qualification on each supported architecture.

This step changes no Sentinel selectors, units, Orbis enrollment, running service or recovery authority. It is an installer dependency, not part of the Sentinel runtime archive.
