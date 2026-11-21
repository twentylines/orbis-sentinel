"""Build a reproducible Sentinel source release without installing or activating it."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import tempfile


MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FILES = 512
ENTRYPOINTS = ("orbis-sentinel", "orbis-sentinel-capture", "orbis-sentinel-verify")
RECOVERY_HTTPS_MEMBERS = {
    "src/orbis_sentinel/recovery_https_edge.py",
    "src/orbis_sentinel/recovery_https_install.py",
    "packaging/systemd/orbis-sentinel-recovery-https.socket",
    "packaging/systemd/orbis-sentinel-recovery-https.service",
}

RECOVERY_BACKEND_COMMAND = "--prepare-recovery-listener-backend"
RECOVERY_BACKEND_ENTRY = "src/orbis_sentinel/recovery_backend_tls.py"
RECOVERY_BACKEND_MEMBERS = RECOVERY_HTTPS_MEMBERS | {
    RECOVERY_BACKEND_ENTRY,
    "src/orbis_sentinel/recovery_listener_install.py",
    "src/orbis_sentinel/recovery_cli.py",
    "src/orbis_sentinel/recovery_runtime.py",
    "src/orbis_sentinel/recovery_gateway.py",
    "src/orbis_sentinel/recovery_worker_provision.py",
    "packaging/systemd/orbis-sentinel-recovery.service",
}

def advertises_recovery_https(tree: ast.AST) -> bool:
    return any(isinstance(node, ast.Constant) and node.value == "--recovery-https-edge" for node in ast.walk(tree))


def release_files(source: Path) -> list[Path]:
    source = source.resolve(strict=True)
    for name in ("bin", "src", "src/orbis_sentinel", "web", "packaging", "packaging/systemd", "packaging/sysusers.d"):
        if (source / name).is_symlink():
            raise ValueError("Linked release directories are not supported")
    files = [source / "LICENSE", *(source / "bin" / name for name in ENTRYPOINTS)]
    selections = (
        ("src/orbis_sentinel", {".py"}),
        ("web", {".html", ".css", ".js", ".json", ".svg", ".png", ".jpg", ".webp", ".woff2", ".ico"}),
        ("packaging/systemd", {".service", ".socket", ".conf"}),
        ("packaging/sysusers.d", {".conf"}),
    )
    for directory, suffixes in selections:
        base = source / directory
        if base.is_symlink() or not base.is_dir():
            raise ValueError(f"Missing or linked release directory: {directory}")
        for current, directories, names in os.walk(base, followlinks=False):
            for name in directories:
                if (Path(current) / name).is_symlink():
                    raise ValueError("Linked release directories are not supported")
            directories[:] = [name for name in directories if not name.startswith(".") and name != "__pycache__"]
            files.extend(Path(current) / name for name in names if not name.startswith(".") and Path(name).suffix in suffixes)
    files = sorted(set(files), key=lambda path: path.relative_to(source).as_posix())
    if len(files) > MAX_FILES:
        raise ValueError("Release contains too many files")
    required = ("src/orbis_sentinel/__init__.py", "packaging/systemd/orbis-sentinel.service", "packaging/systemd/orbis-sentinel.socket")
    if any(source / name not in files for name in required):
        raise ValueError("Release is missing its version or service contract")
    members = {path.relative_to(source).as_posix() for path in files}
    edge = members & RECOVERY_HTTPS_MEMBERS
    if edge and edge != RECOVERY_HTTPS_MEMBERS:
        raise ValueError("Release has an incomplete recovery HTTPS contract")
    if RECOVERY_BACKEND_ENTRY in members and not RECOVERY_BACKEND_MEMBERS <= members:
        raise ValueError("Release has an incomplete private recovery contract")
    return files


def read_release_file(path: Path) -> tuple[bytes, tuple[int, int, int, int]]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
            raise ValueError("Release entries must be bounded regular files")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(MAX_FILE_BYTES + 1)
        after = os.fstat(descriptor)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
        if len(data) != before.st_size or identity(before) != identity(after):
            raise ValueError("Release source changed while reading")
        return data, identity(after)
    finally:
        os.close(descriptor)


def component_version(data: bytes) -> str:
    tree = ast.parse(data)
    versions = [
        statement.value.value
        for statement in tree.body
        if isinstance(statement, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "__version__" for target in statement.targets)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    ]
    if len(versions) != 1 or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?", versions[0]):
        raise ValueError("Sentinel must declare one literal component version")
    return versions[0]


def build_release(source: Path, output: Path) -> dict[str, object]:
    source = source.resolve(strict=True)
    paths = release_files(source)
    payload: dict[str, bytes] = {}
    identities = {}
    total = 0
    for path in paths:
        relative = path.relative_to(source).as_posix()
        data, identity = read_release_file(path)
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ValueError("Release exceeds its size bound")
        if path.suffix == ".py" or relative.startswith("bin/"):
            tree = ast.parse(data, filename=relative, feature_version=(3, 10))
            if relative == "src/orbis_sentinel/runtime.py":
                if advertises_recovery_https(tree) and any(source/name not in paths for name in RECOVERY_HTTPS_MEMBERS):
                    raise ValueError("Release runtime requires the recovery HTTPS contract")
                if (any(isinstance(node,ast.Constant) and node.value == RECOVERY_BACKEND_COMMAND for node in ast.walk(tree))
                        and any(source/name not in paths for name in RECOVERY_BACKEND_MEMBERS)):
                    raise ValueError("Release runtime requires the private recovery contract")
        payload[relative] = data
        identities[path] = identity
    version = component_version(payload["src/orbis_sentinel/__init__.py"])
    manifest = {
        "format": 1,
        "component": "orbis-sentinel",
        "version": version,
        "python": ">=3.10",
        "files": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in payload.items()},
    }
    payload["release.json"] = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    output.mkdir(parents=True, exist_ok=True)
    artifact = output / f"orbis-sentinel-{version}.tar.gz"
    checksum = artifact.with_name(artifact.name + ".sha256")
    if artifact.exists() or artifact.is_symlink() or checksum.exists() or checksum.is_symlink():
        raise FileExistsError("Release output already exists")
    with tempfile.TemporaryDirectory(prefix=".sentinel-release-", dir=output) as temporary:
        staged = Path(temporary) / "release.tar.gz"
        with staged.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=6) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                directories = {parent.as_posix() for name in payload for parent in Path(name).parents if parent != Path(".")}
                for name in sorted(directories, key=lambda value: (value.count("/"), value)):
                    entry = tarfile.TarInfo(name)
                    entry.type = tarfile.DIRTYPE
                    entry.mode = 0o755
                    archive.addfile(entry)
                for name, data in sorted(payload.items()):
                    entry = tarfile.TarInfo(name)
                    entry.size = len(data)
                    entry.mode = 0o755 if name.startswith("bin/") else 0o644
                    archive.addfile(entry, io.BytesIO(data))
        if paths != release_files(source):
            raise ValueError("Release inventory changed during packaging")
        for path, expected in identities.items():
            data, current = read_release_file(path)
            if current != expected or data != payload[path.relative_to(source).as_posix()]:
                raise ValueError("Release source changed during packaging")
        digest = hashlib.sha256(staged.read_bytes()).hexdigest()
        os.link(staged, artifact)
        with checksum.open("x") as stream:
            stream.write(f"{digest}  {artifact.name}\n")
    return {"component": "orbis-sentinel", "version": version, "artifact": str(artifact), "sha256": digest, "files": len(paths)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    print(json.dumps(build_release(arguments.source, arguments.output), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
