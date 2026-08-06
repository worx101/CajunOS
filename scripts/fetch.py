#!/usr/bin/env python3
"""Update, synchronize, and validate CajunOS upstream source locks."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.parse import urlsplit


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = PROJECT_ROOT / "manifests" / "bootstrap.json"
DEFAULT_LOCK = PROJECT_ROOT / "locks" / "bootstrap.lock.json"
MANAGED_DIRECTORIES = (
    "upstream",
    "work",
    "sysroot",
    "tools",
    "cache",
    "artifacts",
    "logs",
)
OBJECT_ID = re.compile(r"^[0-9a-f]{40}$")


class SourceError(RuntimeError):
    pass


def command(
    argv: list[str], *, cwd: Path | None = None, capture: bool = False
) -> str:
    location = f" (in {cwd})" if cwd else ""
    print(f"+ {shlex.join(argv)}{location}", flush=True)
    result = subprocess.run(
        argv,
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    return result.stdout.strip() if capture else ""


def git(checkout: Path, *args: str, capture: bool = False) -> str:
    return command(["git", "-C", str(checkout), *args], capture=capture)


def normalized_url(value: str) -> str:
    return value.rstrip("/")


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise SourceError(f"expected a JSON object in {path}")
    return value


def file_sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_manifest(value: dict[str, Any]) -> list[dict[str, Any]]:
    if value.get("schema") != 1:
        raise SourceError("unsupported manifest schema")
    components = value.get("components")
    if not isinstance(components, list) or not components:
        raise SourceError("manifest has no components")
    seen: set[str] = set()
    for component in components:
        if not isinstance(component, dict):
            raise SourceError("component entries must be objects")
        name = component.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name):
            raise SourceError(f"unsafe component name: {name!r}")
        if name in seen:
            raise SourceError(f"duplicate component: {name}")
        seen.add(name)
        if component.get("vcs") != "git":
            raise SourceError(f"unsupported VCS for {name}")
        ref = component.get("ref")
        if not isinstance(ref, str) or not re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]+", ref):
            raise SourceError(f"invalid branch ref for {name}")
        depth = component.get("depth", 1)
        if not isinstance(depth, int) or depth < 1 or depth > 1000:
            raise SourceError(f"invalid fetch depth for {name}")
        repositories = component.get("repositories")
        if not isinstance(repositories, list) or not repositories:
            raise SourceError(f"missing repositories for {name}")
        for repository in repositories:
            if not isinstance(repository, str) or not repository:
                raise SourceError(f"invalid repository URL for {name}")
            parsed = urlsplit(repository)
            if parsed.scheme not in {"https", "git"} or not parsed.hostname:
                raise SourceError(f"unsupported repository URL for {name}: {repository}")
            if parsed.username or parsed.password:
                raise SourceError(f"credential-bearing repository URL for {name}")
        licenses = component.get("license_files")
        if not isinstance(licenses, list) or not licenses:
            raise SourceError(f"missing license paths for {name}")
        for license_path in licenses:
            if (
                not isinstance(license_path, str)
                or not license_path
                or license_path.startswith("/")
                or ".." in Path(license_path).parts
            ):
                raise SourceError(f"unsafe license path for {name}: {license_path!r}")
    return components


def validate_root(value: str) -> Path:
    requested = Path(value)
    if requested.is_symlink():
        raise SourceError(f"CajunOS root must not be a symlink: {requested}")
    root = requested.resolve()
    if root == Path("/") or root == Path.home().resolve() or not root.is_dir():
        raise SourceError(f"unsafe or missing CajunOS root: {root}")
    for name in MANAGED_DIRECTORIES:
        path = root / name
        if path.is_symlink():
            raise SourceError(f"managed path must not be a symlink: {path}")
        if path.exists() and not path.resolve().is_relative_to(root):
            raise SourceError(f"managed path escapes CajunOS root: {path}")
    return root


def canonical_materials(components: list[dict[str, Any]]) -> list[dict[str, str]]:
    return sorted(
        (
            {
                "name": item["name"],
                "canonical_repository": item["canonical_repository"],
                "ref": item["ref"],
                "commit": item["commit"],
                "tree": item["tree"],
            }
            for item in components
        ),
        key=lambda item: item["name"],
    )


def source_set_digest(components: list[dict[str, Any]]) -> str:
    normalized = json.dumps(
        canonical_materials(components), separators=(",", ":"), sort_keys=True
    ).encode()
    return "sha256:" + hashlib.sha256(normalized).hexdigest()


def validate_lock(
    manifest: dict[str, Any], manifest_path: Path, lock: dict[str, Any]
) -> list[dict[str, Any]]:
    manifest_components = validate_manifest(manifest)
    if lock.get("schema") != 1:
        raise SourceError("unsupported lock schema")
    expected_manifest_digest = "sha256:" + file_sha256(manifest_path)
    if lock.get("manifest_sha256") != expected_manifest_digest:
        raise SourceError("lock does not match the current manifest")
    locked_components = lock.get("components")
    if not isinstance(locked_components, list):
        raise SourceError("lock components must be an array")
    manifest_by_name = {item["name"]: item for item in manifest_components}
    locked_by_name: dict[str, dict[str, Any]] = {}
    for item in locked_components:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise SourceError("invalid locked component")
        name = item["name"]
        if name in locked_by_name:
            raise SourceError(f"duplicate locked component: {name}")
        locked_by_name[name] = item
    if set(locked_by_name) != set(manifest_by_name):
        raise SourceError("lock and manifest component sets differ")
    for name, item in locked_by_name.items():
        declared = manifest_by_name[name]
        if item.get("canonical_repository") != declared["repositories"][0]:
            raise SourceError(f"canonical repository mismatch for {name}")
        if item.get("repository") not in declared["repositories"]:
            raise SourceError(f"undeclared fetch repository for {name}")
        if item.get("ref") != declared["ref"]:
            raise SourceError(f"ref mismatch for {name}")
        if not OBJECT_ID.fullmatch(str(item.get("commit", ""))):
            raise SourceError(f"invalid commit for {name}")
        if not OBJECT_ID.fullmatch(str(item.get("tree", ""))):
            raise SourceError(f"invalid tree for {name}")
        authenticated = urlsplit(item["repository"]).scheme == "https"
        if item.get("transport_authenticated") is not authenticated:
            raise SourceError(f"transport authentication mismatch for {name}")
    expected_authentication = (
        "authenticated"
        if all(item["transport_authenticated"] for item in locked_components)
        else "contains-unauthenticated-transports"
    )
    if lock.get("source_authentication") != expected_authentication:
        raise SourceError("aggregate source-authentication status is incorrect")
    calculated = source_set_digest(locked_components)
    if lock.get("source_set_digest") != calculated:
        raise SourceError("source-set digest does not match locked materials")
    return manifest_components


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise SourceError(f"refusing to replace symlinked lockfile: {path}")
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = Path(stream.name)
    os.replace(temporary, path)
    path.chmod(0o644)


def safe_remove_temporary(path: Path, upstream: Path, name: str) -> None:
    resolved_parent = path.parent.resolve()
    if resolved_parent != upstream.resolve() or not path.name.startswith(f".{name}.tmp-"):
        raise SourceError(f"refusing to remove unexpected path: {path}")
    if path.is_symlink():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def repository_urls(component: dict[str, Any], allow_unauthenticated: bool) -> list[str]:
    values = []
    for url in component["repositories"]:
        if urlsplit(url).scheme == "https" or allow_unauthenticated:
            values.append(url)
    return values


def synchronization_urls(
    component: dict[str, Any], locked_repository: str
) -> list[str]:
    """Return declared transports no weaker than the one recorded in the lock."""
    locked_authenticated = urlsplit(locked_repository).scheme == "https"
    values = [locked_repository]
    for url in component["repositories"]:
        if url == locked_repository:
            continue
        if locked_authenticated and urlsplit(url).scheme != "https":
            continue
        values.append(url)
    return values


def retry_fetch_ref(
    checkout: Path,
    component: dict[str, Any],
    local_ref: str,
    retries: int,
    delay: float,
    allow_unauthenticated: bool,
) -> str:
    errors: list[str] = []
    for url in repository_urls(component, allow_unauthenticated):
        for attempt in range(1, retries + 1):
            subprocess.run(
                ["git", "-C", str(checkout), "update-ref", "-d", local_ref],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                git(
                    checkout,
                    "fetch",
                    "--depth",
                    str(component.get("depth", 1)),
                    "--no-tags",
                    url,
                    f"+{component['ref']}:{local_ref}",
                )
                return url
            except subprocess.CalledProcessError as error:
                errors.append(f"{url} attempt {attempt}: exit {error.returncode}")
                if attempt < retries:
                    time.sleep(delay * attempt)
    raise SourceError(
        f"unable to fetch {component['name']} branch tip: " + "; ".join(errors)
    )


def retry_fetch_commit(
    checkout: Path,
    component: dict[str, Any],
    commit: str,
    preferred_url: str,
    retries: int,
    delay: float,
) -> None:
    urls = synchronization_urls(component, preferred_url)
    errors: list[str] = []
    for url in urls:
        for attempt in range(1, retries + 1):
            try:
                git(checkout, "fetch", "--depth", str(component.get("depth", 1)), url, commit)
                return
            except subprocess.CalledProcessError as error:
                errors.append(f"{url} attempt {attempt}: exit {error.returncode}")
                if attempt < retries:
                    time.sleep(delay * attempt)

    # Servers may reject raw object-ID wants after a moving branch advances.
    # Deepen the explicit declared branch, then fall back to its complete
    # history so an older still-reachable locked commit remains reproducible.
    candidate_ref = f"refs/cajunos/sync/{component['name']}-{os.getpid()}"
    try:
        for url in urls:
            for depth in (50, 200, 1000, 5000):
                try:
                    git(
                        checkout,
                        "fetch",
                        "--depth",
                        str(depth),
                        "--no-tags",
                        url,
                        f"+{component['ref']}:{candidate_ref}",
                    )
                except subprocess.CalledProcessError as error:
                    errors.append(f"{url} depth {depth}: exit {error.returncode}")
                    continue
                if subprocess.run(
                    ["git", "-C", str(checkout), "cat-file", "-e", f"{commit}^{{commit}}"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                ).returncode == 0:
                    return

            full_fetch = ["fetch", "--no-tags"]
            if (checkout / ".git" / "shallow").exists():
                full_fetch.append("--unshallow")
            full_fetch.extend([url, f"+{component['ref']}:{candidate_ref}"])
            try:
                git(checkout, *full_fetch)
            except subprocess.CalledProcessError as error:
                errors.append(f"{url} full history: exit {error.returncode}")
                continue
            if subprocess.run(
                ["git", "-C", str(checkout), "cat-file", "-e", f"{commit}^{{commit}}"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode == 0:
                return
    finally:
        subprocess.run(
            ["git", "-C", str(checkout), "update-ref", "-d", candidate_ref],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    raise SourceError(
        f"unable to fetch locked commit for {component['name']}: " + "; ".join(errors)
    )


def require_clean_checkout(checkout: Path, component: dict[str, Any]) -> None:
    if checkout.is_symlink() or not (checkout / ".git").is_dir():
        raise SourceError(f"invalid checkout for {component['name']}: {checkout}")
    if git(checkout, "status", "--porcelain", capture=True):
        raise SourceError(f"refusing dirty checkout: {checkout}")
    origin = normalized_url(git(checkout, "remote", "get-url", "origin", capture=True))
    allowed = {normalized_url(url) for url in component["repositories"]}
    if origin not in allowed:
        raise SourceError(f"unexpected origin for {component['name']}: {origin}")


def verify_licenses(checkout: Path, component: dict[str, Any], commit: str) -> None:
    for license_path in component["license_files"]:
        try:
            git(checkout, "cat-file", "-e", f"{commit}:{license_path}")
        except subprocess.CalledProcessError as error:
            raise SourceError(
                f"missing declared license path for {component['name']}: {license_path}"
            ) from error


def locked_component(
    checkout: Path, component: dict[str, Any], repository: str, commit: str
) -> dict[str, Any]:
    tree = git(checkout, "rev-parse", f"{commit}^{{tree}}", capture=True)
    verify_licenses(checkout, component, commit)
    git(checkout, "update-ref", f"refs/cajunos/locks/{commit}", commit)
    return {
        "name": component["name"],
        "vcs": "git",
        "ref": component["ref"],
        "canonical_repository": component["repositories"][0],
        "repository": repository,
        "transport_authenticated": urlsplit(repository).scheme == "https",
        "commit": commit,
        "tree": tree,
        "commit_time": git(checkout, "show", "-s", "--format=%cI", commit, capture=True),
        "subject": git(checkout, "show", "-s", "--format=%s", commit, capture=True),
        "signature_status": git(
            checkout, "show", "-s", "--format=%G?", commit, capture=True
        ),
        "signer_fingerprint": git(
            checkout, "show", "-s", "--format=%GF", commit, capture=True
        ),
    }


def create_checkout(upstream: Path, component: dict[str, Any]) -> Path:
    name = component["name"]
    temporary = upstream / f".{name}.tmp-{os.getpid()}"
    safe_remove_temporary(temporary, upstream, name)
    command(["git", "init", "--quiet", str(temporary)])
    return temporary


def update_lock(args: argparse.Namespace) -> None:
    if os.geteuid() == 0:
        raise SourceError("refusing to update source locks as root")
    root = validate_root(args.root)
    manifest_path = args.manifest.resolve()
    manifest = load_json(manifest_path)
    components = validate_manifest(manifest)
    upstream = root / "upstream"
    upstream.mkdir(parents=True, exist_ok=True)
    process_lock_path = upstream / ".cajunos-source.lock"
    with process_lock_path.open("a+", encoding="utf-8") as process_lock:
        fcntl.flock(process_lock, fcntl.LOCK_EX)
        locked: list[dict[str, Any]] = []
        for component in components:
            name = component["name"]
            destination = upstream / name
            created = False
            if destination.exists():
                require_clean_checkout(destination, component)
                checkout = destination
            else:
                checkout = create_checkout(upstream, component)
                created = True
            candidate_ref = f"refs/cajunos/candidates/{name}-{os.getpid()}"
            try:
                selected_url = retry_fetch_ref(
                    checkout,
                    component,
                    candidate_ref,
                    args.retries,
                    args.retry_delay,
                    args.allow_unauthenticated,
                )
                commit = git(checkout, "rev-parse", candidate_ref, capture=True)
                git(checkout, "checkout", "--detach", commit)
                git(checkout, "fsck", "--connectivity-only")
                if created:
                    git(checkout, "remote", "add", "origin", selected_url)
                    checkout.rename(destination)
                    checkout = destination
                locked.append(locked_component(checkout, component, selected_url, commit))
            except Exception:
                if created:
                    safe_remove_temporary(checkout, upstream, name)
                raise
            finally:
                if checkout.exists():
                    subprocess.run(
                        ["git", "-C", str(checkout), "update-ref", "-d", candidate_ref],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )

        authentication = (
            "authenticated"
            if all(item["transport_authenticated"] for item in locked)
            else "contains-unauthenticated-transports"
        )
        lock = {
            "schema": 1,
            "selection": manifest["selection"],
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "manifest": str(manifest_path.relative_to(PROJECT_ROOT)),
            "manifest_sha256": "sha256:" + file_sha256(manifest_path),
            "source_set_digest": source_set_digest(locked),
            "source_authentication": authentication,
            "components": locked,
        }
        validate_lock(manifest, manifest_path, lock)
        atomic_json(args.lock.resolve(), lock)
        print(f"locked {len(locked)} components in {args.lock.resolve()}")


def sync_locked(args: argparse.Namespace) -> None:
    if os.geteuid() == 0:
        raise SourceError("refusing to synchronize sources as root")
    root = validate_root(args.root)
    manifest_path = args.manifest.resolve()
    manifest = load_json(manifest_path)
    lock = load_json(args.lock.resolve())
    components = validate_lock(manifest, manifest_path, lock)
    locked_by_name = {item["name"]: item for item in lock["components"]}
    upstream = root / "upstream"
    upstream.mkdir(parents=True, exist_ok=True)
    with (upstream / ".cajunos-source.lock").open("a+", encoding="utf-8") as process_lock:
        fcntl.flock(process_lock, fcntl.LOCK_EX)
        for component in components:
            name = component["name"]
            locked = locked_by_name[name]
            destination = upstream / name
            created = False
            if destination.exists():
                require_clean_checkout(destination, component)
                checkout = destination
            else:
                checkout = create_checkout(upstream, component)
                created = True
            try:
                exists = subprocess.run(
                    ["git", "-C", str(checkout), "cat-file", "-e", f"{locked['commit']}^{{commit}}"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                ).returncode == 0
                if not exists:
                    retry_fetch_commit(
                        checkout,
                        component,
                        locked["commit"],
                        locked["repository"],
                        args.retries,
                        args.retry_delay,
                    )
                git(checkout, "checkout", "--detach", locked["commit"])
                actual_tree = git(
                    checkout, "rev-parse", f"{locked['commit']}^{{tree}}", capture=True
                )
                if actual_tree != locked["tree"]:
                    raise SourceError(f"tree mismatch for {name}")
                verify_licenses(checkout, component, locked["commit"])
                git(
                    checkout,
                    "update-ref",
                    f"refs/cajunos/locks/{locked['commit']}",
                    locked["commit"],
                )
                git(checkout, "fsck", "--connectivity-only")
                if created:
                    git(checkout, "remote", "add", "origin", locked["repository"])
                    checkout.rename(destination)
            except Exception:
                if created:
                    safe_remove_temporary(checkout, upstream, name)
                raise
    validate_checkouts(root, manifest, lock)
    print(f"synchronized {len(components)} locked components")


def validate_checkouts(
    root: Path, manifest: dict[str, Any], lock: dict[str, Any]
) -> dict[str, Any]:
    components = validate_manifest(manifest)
    locked_by_name = {item["name"]: item for item in lock["components"]}
    results: list[dict[str, str]] = []
    for component in components:
        name = component["name"]
        locked = locked_by_name[name]
        checkout = root / "upstream" / name
        require_clean_checkout(checkout, component)
        head = git(checkout, "rev-parse", "HEAD", capture=True)
        tree = git(checkout, "rev-parse", "HEAD^{tree}", capture=True)
        if head != locked["commit"] or tree != locked["tree"]:
            raise SourceError(f"checkout does not match lock for {name}")
        verify_licenses(checkout, component, head)
        results.append({"name": name, "commit": head, "tree": tree})
    return {
        "valid": True,
        "source_set_digest": lock["source_set_digest"],
        "source_authentication": lock["source_authentication"],
        "components": results,
    }


def validate_command(args: argparse.Namespace) -> None:
    root = validate_root(args.root)
    manifest_path = args.manifest.resolve()
    manifest = load_json(manifest_path)
    lock = load_json(args.lock.resolve())
    validate_lock(manifest, manifest_path, lock)
    result = validate_checkouts(root, manifest, lock)
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            f"valid locked source set {result['source_set_digest']} "
            f"({result['source_authentication']})"
        )


def add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", default=os.environ.get("CAJUNOS_ROOT", "/srv/cajunos"))
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)

    update = subparsers.add_parser(
        "update-lock", help="resolve current upstream branch tips and replace the source lock"
    )
    add_common_options(update)
    update.add_argument("--retries", type=int, default=4)
    update.add_argument("--retry-delay", type=float, default=30.0)
    update.add_argument(
        "--allow-unauthenticated",
        action="store_true",
        help="allow declared git:// fallbacks and mark them in the lock",
    )
    update.set_defaults(function=update_lock)

    sync = subparsers.add_parser("sync", help="synchronize checkouts to the committed lock")
    add_common_options(sync)
    sync.add_argument("--retries", type=int, default=3)
    sync.add_argument("--retry-delay", type=float, default=30.0)
    sync.set_defaults(function=sync_locked)

    validate = subparsers.add_parser("validate", help="validate lock and local checkouts")
    add_common_options(validate)
    validate.add_argument("--json", action="store_true")
    validate.set_defaults(function=validate_command)
    return parser.parse_args()


def main() -> int:
    os.umask(0o022)
    args = parse_args()
    if hasattr(args, "retries") and (args.retries < 1 or args.retry_delay < 0):
        raise SourceError("retry values must be positive")
    args.function(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SourceError, subprocess.CalledProcessError, OSError, ValueError) as error:
        print(f"source operation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
