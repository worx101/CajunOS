#!/usr/bin/env bash
set -Eeuo pipefail
umask 022
export LC_ALL=C
export TZ=UTC
export PATH=/usr/bin:/bin

script_path=$(readlink -f -- "${BASH_SOURCE[0]}")

# Keep the filesystem attestation logic in this recipe so its bytes are bound
# into the build ID.  The deliberately narrow internal interface also lets the
# unit tests exercise the exact inventory and completed-receipt verifier used
# by the build without creating a second, unaudited implementation.
if [[ ${1:-} == --internal-python ]]; then
  shift
  exec python3 - "$@" <<'PY'
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def safe_symlink(root: Path, path: Path, relative: str, target: str) -> None:
    if not target or os.path.isabs(target):
        fail(f"unsafe absolute or empty symlink in snapshot: {relative} -> {target}")
    lexical = PurePosixPath(relative).parent / PurePosixPath(target)
    depth = 0
    for part in lexical.parts:
        if part in ("", "."):
            continue
        if part == "..":
            depth -= 1
        else:
            depth += 1
        if depth < 0:
            fail(f"escaping symlink in snapshot: {relative} -> {target}")
    try:
        resolved = (path.parent / target).resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (FileNotFoundError, RuntimeError, ValueError):
        fail(f"broken or escaping symlink in snapshot: {relative} -> {target}")


def tree_entries(root: Path) -> dict[str, dict[str, str]]:
    try:
        root_stat = root.lstat()
    except FileNotFoundError:
        fail(f"snapshot does not exist: {root}")
    if not stat.S_ISDIR(root_stat.st_mode):
        fail(f"snapshot is not a directory: {root}")
    entries: dict[str, dict[str, str]] = {
        ".": {"type": "directory", "mode": f"{stat.S_IMODE(root_stat.st_mode):04o}"}
    }

    def walk(directory: Path) -> None:
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda item: item.name)
        for child in children:
            path = Path(child.path)
            relative = path.relative_to(root).as_posix()
            metadata = child.stat(follow_symlinks=False)
            mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
            if child.is_symlink():
                target = os.readlink(path)
                safe_symlink(root, path, relative, target)
                entries[relative] = {
                    "type": "symlink",
                    "mode": mode,
                    "target": target,
                }
            elif child.is_dir(follow_symlinks=False):
                entries[relative] = {"type": "directory", "mode": mode}
                walk(path)
            elif child.is_file(follow_symlinks=False):
                if metadata.st_nlink != 1:
                    fail(f"multiply-linked regular file in snapshot: {relative}")
                entries[relative] = {
                    "type": "file",
                    "mode": mode,
                    "sha256": sha256(path),
                }
            else:
                fail(f"unsupported special file in snapshot: {relative}")
    walk(root)
    return entries


def dependency_tree_entries(
    root: Path, allowed_root: Path
) -> dict[str, dict[str, str]]:
    try:
        root_metadata = root.lstat()
        allowed_metadata = allowed_root.lstat()
    except FileNotFoundError as error:
        fail(f"dependency inventory path does not exist: {error.filename}")
    if not stat.S_ISDIR(root_metadata.st_mode):
        fail(f"dependency prefix is not a real directory: {root}")
    if not stat.S_ISDIR(allowed_metadata.st_mode):
        fail(f"dependency root is not a real directory: {allowed_root}")
    try:
        root.resolve(strict=True).relative_to(allowed_root.resolve(strict=True))
    except (FileNotFoundError, RuntimeError, ValueError):
        fail(f"dependency prefix escapes the managed dependency root: {root}")

    entries: dict[str, dict[str, str]] = {
        ".": {"type": "directory", "mode": f"{stat.S_IMODE(root_metadata.st_mode):04o}"}
    }
    hardlinks: dict[tuple[int, int], tuple[int, list[str]]] = {}

    def walk(directory: Path) -> None:
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda item: item.name)
        for child in children:
            path = Path(child.path)
            relative = path.relative_to(root).as_posix()
            metadata = child.stat(follow_symlinks=False)
            mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
            if child.is_symlink():
                target = os.readlink(path)
                if not target or os.path.isabs(target):
                    fail(f"unsafe dependency symlink: {relative} -> {target}")
                try:
                    resolved = (path.parent / target).resolve(strict=True)
                    resolved.relative_to(allowed_root.resolve(strict=True))
                except (FileNotFoundError, RuntimeError, ValueError):
                    fail(f"broken or escaping dependency symlink: {relative} -> {target}")
                entries[relative] = {
                    "type": "symlink",
                    "mode": mode,
                    "target": target,
                }
            elif child.is_dir(follow_symlinks=False):
                entries[relative] = {"type": "directory", "mode": mode}
                walk(path)
            elif child.is_file(follow_symlinks=False):
                if metadata.st_nlink != 1:
                    key = (metadata.st_dev, metadata.st_ino)
                    count, paths = hardlinks.setdefault(key, (metadata.st_nlink, []))
                    if count != metadata.st_nlink:
                        fail("dependency hardlink metadata changed while walking")
                    paths.append(relative)
                entries[relative] = {
                    "type": "file",
                    "mode": mode,
                    "sha256": sha256(path),
                }
            else:
                fail(f"unsupported dependency prefix entry: {relative}")
    walk(root)
    for link_count, paths in hardlinks.values():
        if len(paths) != link_count:
            fail("dependency hardlink escapes its attested prefix")
    return entries


def inventory(root: Path) -> dict[str, object]:
    entries = tree_entries(root)
    return {"digest": canonical_digest(entries), "entries": entries}


def walk_managed_directory(root: Path, relative: str, create: bool) -> None:
    path = PurePosixPath(relative)
    if path.is_absolute() or not path.parts or any(
        part in ("", ".", "..") for part in path.parts
    ):
        fail(f"unsafe managed directory path: {relative}")
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(root, flags)
    except OSError as error:
        fail(f"managed root is not a real directory: {root}: {error}")
    try:
        for part in path.parts:
            if create:
                try:
                    os.mkdir(part, 0o755, dir_fd=descriptor)
                except FileExistsError:
                    pass
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except OSError as error:
                fail(f"managed path is not a real directory: {relative}: {error}")
            os.close(descriptor)
            descriptor = child
    finally:
        os.close(descriptor)


def regular_hashes(root: Path) -> dict[str, str]:
    try:
        root_metadata = root.lstat()
    except FileNotFoundError:
        fail(f"attestation directory does not exist: {root}")
    if not stat.S_ISDIR(root_metadata.st_mode):
        fail(f"attestation path is not a real directory: {root}")
    hashes: dict[str, str] = {}
    for directory, names, filenames in os.walk(root, followlinks=False):
        names.sort()
        filenames.sort()
        directory_path = Path(directory)
        for name in names:
            path = directory_path / name
            metadata = path.lstat()
            if not stat.S_ISDIR(metadata.st_mode):
                fail(f"unsupported attestation directory entry: {path}")
        for name in filenames:
            path = directory_path / name
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                fail(f"unsupported attestation file: {path}")
            hashes[path.relative_to(root).as_posix()] = sha256(path)
    return hashes


def dotted(receipt: object, key: str) -> object:
    value = receipt
    for part in key.split("."):
        if not isinstance(value, dict) or part not in value:
            fail(f"completed receipt lacks {key}")
        value = value[part]
    return value


def require_pairs(arguments: list[str]) -> dict[str, str]:
    if len(arguments) % 2:
        fail("expected key/value pairs")
    return dict(zip(arguments[::2], arguments[1::2], strict=True))


if not sys.argv[1:]:
    fail("missing internal command")
command, *arguments = sys.argv[1:]

if command == "inventory":
    if len(arguments) != 1:
        fail("inventory requires ROOT")
    json.dump(inventory(Path(arguments[0])), sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
elif command == "dependency-inventory":
    if len(arguments) != 2:
        fail("dependency-inventory requires PREFIX MANAGED_ROOT")
    json.dump(
        dependency_tree_entries(Path(arguments[0]), Path(arguments[1])),
        sys.stdout,
        sort_keys=True,
    )
    sys.stdout.write("\n")
elif command == "compare":
    if len(arguments) != 3:
        fail("compare requires LEFT RIGHT OUTPUT")
    left = inventory(Path(arguments[0]))
    right = inventory(Path(arguments[1]))
    if left != right:
        fail("independent Linux header installations differ")
    output = Path(arguments[2])
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(left, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.replace(temporary, output)
    output.chmod(0o644)
elif command == "build-id":
    if len(arguments) < 3 or len(arguments[1:]) % 2:
        fail("build-id requires COMMIT and key/value pairs")
    commit = arguments[0]
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        fail("unsafe source commit for build ID")
    material = require_pairs(arguments[1:])
    digest = canonical_digest(material)
    print(f"linux-uapi-headers-{commit[:12]}-{digest[:16]}")
elif command in ("ensure-directories", "validate-directories"):
    if len(arguments) < 2:
        fail(f"{command} requires ROOT and one or more relative directories")
    root = Path(arguments[0])
    for relative in arguments[1:]:
        walk_managed_directory(root, relative, command == "ensure-directories")
elif command == "validate-completed":
    if len(arguments) < 4 or len(arguments[2:]) % 2:
        fail("validate-completed requires RECEIPT SNAPSHOT and key/value pairs")
    receipt_path = Path(arguments[0])
    snapshot = Path(arguments[1])
    expected = require_pairs(arguments[2:])
    with receipt_path.open(encoding="utf-8") as stream:
        receipt = json.load(stream)
    for key, expected_value in expected.items():
        actual = dotted(receipt, key)
        if str(actual) != expected_value:
            fail(f"completed receipt mismatch for {key}")
    actual_inventory = inventory(snapshot)
    if receipt.get("installed_entries") != actual_inventory["entries"]:
        fail("completed snapshot failed full inventory validation")
    expected_digest = f"sha256:{actual_inventory['digest']}"
    if receipt.get("result_snapshot_digest") != expected_digest:
        fail("completed snapshot digest does not match receipt")
    if receipt.get("sysroot_contract") != "immutable-snapshots-v1":
        fail("completed receipt has an unexpected sysroot contract")
    options_path = receipt_path.parent / "headers-install.options"
    try:
        options_metadata = options_path.lstat()
        options = options_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        fail("completed artifact lacks headers-install.options")
    if not stat.S_ISREG(options_metadata.st_mode) or options_metadata.st_nlink != 1:
        fail("headers-install.options is not a plain single-linked file")
    if not options or any(not value or "\0" in value or "\n" in value for value in options):
        fail("headers-install.options has invalid entries")
    if receipt.get("headers_install_options") != options:
        fail("completed receipt options differ from the recorded options file")
    options_material = b"".join(value.encode("utf-8") + b"\0" for value in options)
    actual_options_digest = hashlib.sha256(options_material).hexdigest()
    if receipt.get("options_digest") != actual_options_digest:
        fail("completed options digest is invalid")
    expected_reproducibility = {
        "independent_installations": 2,
        "inventory_schema": "paths-types-modes-sha256-symlink-targets-v1",
        "first_inventory_digest": expected_digest,
        "second_inventory_digest": expected_digest,
        "identical": True,
        "post_probe_inventory_digest": expected_digest,
    }
    if receipt.get("reproducibility") != expected_reproducibility:
        fail("completed reproducibility attestation is invalid")
    version_header = snapshot / "usr/include/linux/version.h"
    try:
        version_text = version_header.read_text(encoding="utf-8")
    except FileNotFoundError:
        fail("completed snapshot lacks linux/version.h")
    match = re.search(
        r"^#define LINUX_VERSION_CODE\s+(\d+)\s*$", version_text, re.MULTILINE
    )
    if not match:
        fail("completed linux/version.h lacks LINUX_VERSION_CODE")
    version_code = int(match.group(1))
    numeric_version = (
        f"{version_code >> 16}.{(version_code >> 8) & 255}.{version_code & 255}"
    )
    if receipt.get("kernel", {}).get("version_code") != version_code:
        fail("completed receipt kernel version code is invalid")
    if receipt.get("kernel", {}).get("numeric_version") != numeric_version:
        fail("completed receipt numeric kernel version is invalid")
    if receipt.get("license_sha256") != regular_hashes(receipt_path.parent / "licenses/linux"):
        fail("completed license attestation is invalid")
    probe_hashes = receipt.get("outputs", {}).get("probe_sha256")
    if probe_hashes != regular_hashes(receipt_path.parent / "probe"):
        fail("completed probe attestation is invalid")
    unifdef = receipt_path.parent / "host/unifdef"
    try:
        unifdef_metadata = unifdef.lstat()
    except FileNotFoundError:
        fail("completed artifact lacks the attested kernel unifdef")
    if (
        not stat.S_ISREG(unifdef_metadata.st_mode)
        or unifdef_metadata.st_nlink != 1
        or not os.access(unifdef, os.X_OK)
    ):
        fail("attested kernel unifdef is not a plain executable file")
    if receipt.get("host", {}).get("kernel_unifdef", {}).get("sha256") != sha256(unifdef):
        fail("completed kernel unifdef attestation is invalid")
elif command == "current-state":
    if len(arguments) != 2:
        fail("current-state requires SYSROOT BUILD_ID")
    sysroot = Path(arguments[0])
    build_id = arguments[1]
    snapshots = sysroot / "snapshots"
    current = sysroot / "current"
    usr = sysroot / "usr"
    for label, path in (("cohort sysroot", sysroot), ("snapshots root", snapshots)):
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            fail(f"{label} does not exist")
        if not stat.S_ISDIR(metadata.st_mode):
            fail(f"{label} is not a real directory")
    if usr.is_symlink():
        if os.readlink(usr) != "current/usr":
            fail("cohort usr symlink has an unexpected target")
    elif usr.exists():
        fail("cohort usr path is not the managed symlink")
    if not current.is_symlink():
        if current.exists():
            fail("cohort current path is not a symlink")
        print("missing")
    else:
        target = os.readlink(current)
        match = re.fullmatch(r"snapshots/([A-Za-z0-9][A-Za-z0-9._-]{0,127})", target)
        if not match:
            fail("cohort current symlink has an unsafe target")
        try:
            resolved = current.resolve(strict=True)
            resolved.relative_to(snapshots.resolve(strict=True))
        except (FileNotFoundError, RuntimeError, ValueError):
            fail("cohort current symlink is broken or escaping")
        print("this" if match.group(1) == build_id else f"other:{match.group(1)}")
else:
    fail(f"unknown internal command: {command}")
PY
fi

for variable in \
  CC CXX CPP CFLAGS CXXFLAGS CPPFLAGS LDFLAGS \
  LIBRARY_PATH CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH \
  PKG_CONFIG_PATH CONFIG_SITE LD_LIBRARY_PATH GCC_EXEC_PREFIX COMPILER_PATH; do
  unset "$variable"
done

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cajunos_root=${CAJUNOS_ROOT:-/srv/cajunos}
target=${CAJUNOS_TARGET:-x86_64-cajunos-linux-gnu}
arch=${CAJUNOS_LINUX_ARCH:-x86_64}
expected_user=${CAJUNOS_BUILD_USER:-cajunos}
requested_gcc_id=${CAJUNOS_GCC_BUILD_ID:-}
lock_file=$project_root/locks/bootstrap.lock.json
manifest_file=$project_root/manifests/bootstrap.json

if [[ $(id -u) -eq 0 || $(id -un) != "$expected_user" ]]; then
  echo "Run this build as the unprivileged $expected_user account" >&2
  exit 70
fi
if [[ $arch != x86_64 ]]; then
  echo "This stage currently supports only ARCH=x86_64" >&2
  exit 71
fi
for command in flock git install make python3 rsync sed sha256sum tar; do
  command -v "$command" >/dev/null || {
    echo "Missing required host command: $command" >&2
    exit 72
  }
done

# Validate once before opening the lock and again while holding it.  The source
# lock remains held through both header installations and final attestation.
"$project_root/scripts/fetch.py" validate --root "$cajunos_root" --json >/dev/null
cajunos_root=$(readlink -f -- "$cajunos_root")
exec 8>"$cajunos_root/upstream/.cajunos-source.lock"
if ! flock -n 8; then
  echo "Another CajunOS source operation or build owns the source lock" >&2
  exit 73
fi
"$project_root/scripts/fetch.py" validate --root "$cajunos_root"

linux_source_dir=$cajunos_root/upstream/linux

mapfile -t lock_values < <(python3 - "$lock_file" "$manifest_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    lock = json.load(stream)
with open(sys.argv[2], encoding="utf-8") as stream:
    manifest = json.load(stream)
print(lock["source_set_digest"])
print(lock["source_authentication"])
for wanted in ("linux", "gcc", "binutils"):
    for component in lock["components"]:
        if component["name"] == wanted:
            print(component["commit"])
            print(component["tree"])
            print(component["repository"])
            break
    else:
        raise SystemExit(f"{wanted} is absent from the bootstrap lock")
for component in manifest["components"]:
    if component["name"] == "linux":
        print(*component["license_files"], sep="\n")
        break
else:
    raise SystemExit("linux is absent from the bootstrap manifest")
PY
)
source_set_digest=${lock_values[0]}
source_authentication=${lock_values[1]}
locked_linux_commit=${lock_values[2]}
locked_linux_tree=${lock_values[3]}
linux_repository=${lock_values[4]}
locked_gcc_commit=${lock_values[5]}
locked_gcc_tree=${lock_values[6]}
gcc_repository=${lock_values[7]}
locked_binutils_commit=${lock_values[8]}
locked_binutils_tree=${lock_values[9]}
binutils_repository=${lock_values[10]}
license_paths=("${lock_values[@]:11}")

if [[ $source_authentication != authenticated ]]; then
  if [[ ${CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES:-} != 1 ]]; then
    echo "This source cohort contains recorded unauthenticated transports." >&2
    echo "Review locks/bootstrap.lock.json, then explicitly set" >&2
    echo "CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES=1 to accept that risk." >&2
    exit 74
  fi
  echo "WARNING: explicitly accepting the lock's recorded unauthenticated transports" >&2
fi

if [[ -n $(git -C "$project_root" status --porcelain) ]]; then
  echo "Refusing an official build from a dirty CajunOS orchestration checkout" >&2
  exit 75
fi
orchestration_commit=$(git -C "$project_root" rev-parse HEAD)
orchestration_tree=$(git -C "$project_root" rev-parse 'HEAD^{tree}')

jobs=${CAJUNOS_JOBS:-6}
if [[ ! $jobs =~ ^[1-9][0-9]*$ ]]; then
  echo "CAJUNOS_JOBS must be a positive integer" >&2
  exit 76
fi
export MAKEFLAGS="-j$jobs"
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git -C "$linux_source_dir" show -s --format=%ct "$locked_linux_commit")
expected_kernel_version=$(make -s -C "$linux_source_dir" kernelversion)
[[ $expected_kernel_version != *$'\n'* && -n $expected_kernel_version ]] || {
  echo "Unable to determine a single locked Linux kernel version" >&2
  exit 93
}

work_root=$cajunos_root/work/sysroot
tools_root=$cajunos_root/tools
artifacts_root=$cajunos_root/artifacts
logs_root=$cajunos_root/logs
cohort_id=${source_set_digest#sha256:}
cohort_id=${cohort_id:0:16}
sysroot=$cajunos_root/sysroot/$cohort_id
snapshots_root=$sysroot/snapshots

"$script_path" --internal-python ensure-directories "$cajunos_root" \
  work work/sysroot tools artifacts logs sysroot \
  "sysroot/$cohort_id" "sysroot/$cohort_id/snapshots"
exec 9>"$cajunos_root/work/.cajunos-build.lock"
if ! flock -n 9; then
  echo "Another CajunOS build owns $cajunos_root/work/.cajunos-build.lock" >&2
  exit 77
fi

resolve_dependencies() {
  python3 - \
    "$script_path" \
    "$artifacts_root" \
    "$tools_root" \
    "$requested_gcc_id" \
    "$source_set_digest" \
    "$source_authentication" \
    "$target" \
    "$sysroot" \
    "$locked_gcc_commit" \
    "$locked_gcc_tree" \
    "$gcc_repository" \
    "$locked_binutils_commit" \
    "$locked_binutils_tree" \
    "$binutils_repository" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

(
    script_value, artifacts_value, tools_value, requested, source_set_digest,
    source_authentication, target, sysroot, gcc_commit, gcc_tree,
    gcc_repository, binutils_commit, binutils_tree, binutils_repository,
) = sys.argv[1:]
script_path = Path(script_value)
artifacts_root = Path(artifacts_value)
tools_root = Path(tools_value)
try:
    tools_metadata = tools_root.lstat()
except FileNotFoundError:
    raise SystemExit("managed tools root does not exist")
if not stat.S_ISDIR(tools_metadata.st_mode):
    raise SystemExit("managed tools root is not a real directory")

def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def tree_entries(root: Path) -> dict[str, dict[str, str]]:
    result = subprocess.run(
        [
            script_path,
            "--internal-python",
            "dependency-inventory",
            root,
            tools_root,
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise SystemExit(
            result.stderr.strip() or "dependency inventory validation failed"
        )
    return json.loads(result.stdout)

if requested:
    if not re.fullmatch(r"gcc-stage1-[A-Za-z0-9._-]+", requested):
        raise SystemExit("unsafe CAJUNOS_GCC_BUILD_ID")
    receipt_paths = [artifacts_root / requested / "receipt.json"]
else:
    receipt_paths = sorted(artifacts_root.glob("gcc-stage1-*/receipt.json"))

candidates = []
for receipt_path in receipt_paths:
    if not receipt_path.is_file():
        continue
    with receipt_path.open(encoding="utf-8") as stream:
        receipt = json.load(stream)
    if (
        receipt.get("schema") == 1
        and receipt.get("component") == "gcc"
        and receipt.get("stage") == "stage1"
        and receipt.get("source_set_digest") == source_set_digest
        and receipt.get("source_authentication") == source_authentication
        and receipt.get("source_commit") == gcc_commit
        and receipt.get("source_tree") == gcc_tree
        and receipt.get("source_repository") == gcc_repository
        and receipt.get("target") == target
        and receipt.get("sysroot") == sysroot
        and receipt.get("sysroot_contract") == "empty-at-build"
    ):
        candidates.append((receipt_path, receipt))
if len(candidates) != 1:
    raise SystemExit(
        f"expected one matching GCC stage-one receipt, found {len(candidates)}; "
        "set CAJUNOS_GCC_BUILD_ID to disambiguate"
    )

gcc_receipt_path, gcc_receipt = candidates[0]
gcc_build_id = gcc_receipt.get("build_id")
if not isinstance(gcc_build_id, str) or gcc_receipt_path.parent.name != gcc_build_id:
    raise SystemExit("GCC receipt/build directory mismatch")
gcc_prefix = tools_root / gcc_build_id
if gcc_receipt.get("prefix") != str(gcc_prefix):
    raise SystemExit("GCC receipt prefix mismatch")
if gcc_receipt.get("installed_entries") != tree_entries(gcc_prefix):
    raise SystemExit("GCC dependency prefix failed full inventory validation")
gcc_driver = gcc_prefix / "bin" / f"{target}-gcc"
if not gcc_driver.is_file() or not os.access(gcc_driver, os.X_OK):
    raise SystemExit("GCC dependency lacks an executable cross compiler")
try:
    gcc_driver.resolve(strict=True).relative_to(gcc_prefix.resolve(strict=True))
except (FileNotFoundError, RuntimeError, ValueError):
    raise SystemExit("GCC driver resolves outside its dependency prefix")
dumpmachine = subprocess.run(
    [gcc_driver, "-dumpmachine"], check=True, text=True, stdout=subprocess.PIPE
).stdout.strip()
printed_sysroot = subprocess.run(
    [gcc_driver, "-print-sysroot"], check=True, text=True, stdout=subprocess.PIPE
).stdout.strip()
if dumpmachine != target or printed_sysroot != sysroot:
    raise SystemExit("GCC dependency target/sysroot contract changed")

dependency = gcc_receipt.get("dependencies", {}).get("binutils", {})
binutils_build_id = dependency.get("build_id")
if not isinstance(binutils_build_id, str) or not re.fullmatch(
    r"binutils-stage1-[A-Za-z0-9._-]+", binutils_build_id
):
    raise SystemExit("GCC receipt has an invalid Binutils build ID")
binutils_prefix = tools_root / binutils_build_id
binutils_receipt_path = artifacts_root / binutils_build_id / "receipt.json"
if dependency.get("prefix") != str(binutils_prefix):
    raise SystemExit("GCC receipt Binutils prefix mismatch")
if dependency.get("receipt") != str(binutils_receipt_path):
    raise SystemExit("GCC receipt Binutils receipt path mismatch")
if sha256(binutils_receipt_path) != dependency.get("receipt_sha256"):
    raise SystemExit("nested Binutils receipt hash mismatch")
with binutils_receipt_path.open(encoding="utf-8") as stream:
    binutils_receipt = json.load(stream)
if (
    binutils_receipt.get("schema") != 1
    or binutils_receipt.get("component") != "binutils"
    or binutils_receipt.get("stage") != "stage1"
    or binutils_receipt.get("build_id") != binutils_build_id
    or binutils_receipt.get("source_set_digest") != source_set_digest
    or binutils_receipt.get("source_authentication") != source_authentication
    or binutils_receipt.get("source_commit") != binutils_commit
    or binutils_receipt.get("source_tree") != binutils_tree
    or binutils_receipt.get("target") != target
    or binutils_receipt.get("prefix") != str(binutils_prefix)
):
    raise SystemExit("nested Binutils receipt provenance mismatch")
if binutils_receipt.get("installed_entries") != tree_entries(binutils_prefix):
    raise SystemExit("nested Binutils prefix failed full inventory validation")
for relative in (
    f"bin/{target}-as", f"bin/{target}-ld", f"bin/{target}-readelf",
    f"{target}/bin/as", f"{target}/bin/ld",
):
    path = binutils_prefix / relative
    if not path.is_file() or not os.access(path, os.X_OK):
        raise SystemExit(f"nested Binutils dependency lacks {relative}")
    try:
        path.resolve(strict=True).relative_to(binutils_prefix.resolve(strict=True))
    except (FileNotFoundError, RuntimeError, ValueError):
        raise SystemExit(f"nested Binutils tool resolves outside its prefix: {relative}")

for program in ("as", "ld"):
    output = subprocess.run(
        [gcc_driver, f"-print-prog-name={program}"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    if not output or "\n" in output or not Path(output).is_absolute():
        raise SystemExit(f"GCC returned an unsafe {program} program path")
    expected = binutils_prefix / "bin" / f"{target}-{program}"
    try:
        actual_resolved = Path(output).resolve(strict=True)
        expected_resolved = expected.resolve(strict=True)
    except (FileNotFoundError, RuntimeError):
        raise SystemExit(f"GCC returned a broken {program} program path")
    if actual_resolved != expected_resolved:
        raise SystemExit(
            f"GCC {program} binding does not match the attested Binutils prefix"
        )

values = (
    gcc_build_id,
    str(gcc_prefix),
    str(gcc_receipt_path),
    sha256(gcc_receipt_path),
    gcc_receipt.get("source_commit", ""),
    gcc_receipt.get("source_tree", ""),
    gcc_receipt.get("orchestration_commit", ""),
    gcc_receipt.get("orchestration_tree", ""),
    binutils_build_id,
    str(binutils_prefix),
    str(binutils_receipt_path),
    sha256(binutils_receipt_path),
    binutils_receipt.get("source_commit", ""),
    binutils_receipt.get("source_tree", ""),
    binutils_receipt.get("orchestration_commit", ""),
    binutils_receipt.get("orchestration_tree", ""),
)
if any(not isinstance(value, str) or "\n" in value for value in values):
    raise SystemExit("dependency receipt has invalid scalar metadata")
print(*values, sep="\n")
PY
}

if ! dependency_output=$(resolve_dependencies); then
  echo "GCC/Binutils dependency validation failed" >&2
  exit 78
fi
mapfile -t dependency_values <<<"$dependency_output"
if (( ${#dependency_values[@]} != 16 )); then
  echo "Dependency verifier returned incomplete metadata" >&2
  exit 79
fi
gcc_build_id=${dependency_values[0]}
gcc_prefix=${dependency_values[1]}
gcc_receipt=${dependency_values[2]}
gcc_receipt_sha256=${dependency_values[3]}
gcc_source_commit=${dependency_values[4]}
gcc_source_tree=${dependency_values[5]}
gcc_orchestration_commit=${dependency_values[6]}
gcc_orchestration_tree=${dependency_values[7]}
binutils_build_id=${dependency_values[8]}
binutils_prefix=${dependency_values[9]}
binutils_receipt=${dependency_values[10]}
binutils_receipt_sha256=${dependency_values[11]}
binutils_source_commit=${dependency_values[12]}
binutils_source_tree=${dependency_values[13]}
binutils_orchestration_commit=${dependency_values[14]}
binutils_orchestration_tree=${dependency_values[15]}

headers_options=(
  "make-target=headers_install"
  "ARCH=$arch"
  "HOSTCC=/usr/bin/gcc"
  "HOSTCXX=/usr/bin/g++"
  "installations=2"
  "inventory-schema=paths-types-modes-sha256-symlink-targets-v1"
  "sysroot-layout=snapshots-v1"
  "probe=freestanding-nostdinc-compile-only"
)
options_digest=$(printf '%s\0' "${headers_options[@]}" | sha256sum | awk '{print $1}')
recipe_sha256=$(sha256sum "$script_path" | awk '{print $1}')
empty_base_digest=sha256:$(printf 'cajunos-empty-sysroot-v1\n' | sha256sum | awk '{print $1}')
build_id=$("$script_path" --internal-python build-id "$locked_linux_commit" \
  source_set_digest "$source_set_digest" \
  source_authentication "$source_authentication" \
  source_commit "$locked_linux_commit" \
  source_tree "$locked_linux_tree" \
  target "$target" \
  arch "$arch" \
  orchestration_commit "$orchestration_commit" \
  orchestration_tree "$orchestration_tree" \
  recipe_sha256 "$recipe_sha256" \
  options_digest "$options_digest" \
  gcc_build_id "$gcc_build_id" \
  gcc_receipt_sha256 "$gcc_receipt_sha256" \
  binutils_build_id "$binutils_build_id" \
  binutils_receipt_sha256 "$binutils_receipt_sha256" \
  base_snapshot_digest "$empty_base_digest")

run_id=${CAJUNOS_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
if [[ ! $run_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "Unsafe CAJUNOS_RUN_ID: $run_id" >&2
  exit 80
fi

build_final=$work_root/$build_id
snapshot_final=$snapshots_root/$build_id
artifact_final=$artifacts_root/$build_id
receipt_final=$artifact_final/receipt.json
log_dir=$logs_root/$run_id
log_file=$log_dir/linux-uapi-headers.log
temporary_root=$work_root/.tmp-$build_id-$$
kbuild_a=$temporary_root/kbuild-a
kbuild_b=$temporary_root/kbuild-b
repro_snapshot=$temporary_root/repro-snapshot
snapshot_temporary=$snapshots_root/.tmp-$build_id-$$
artifact_temporary=$artifacts_root/.tmp-$build_id-$$

validate_completed() {
  "$script_path" --internal-python validate-completed \
    "$receipt_final" "$snapshot_final" \
    schema 1 \
    build_id "$build_id" \
    component linux \
    stage uapi-headers \
    source_commit "$locked_linux_commit" \
    source_tree "$locked_linux_tree" \
    source_repository "$linux_repository" \
    source_set_digest "$source_set_digest" \
    source_authentication "$source_authentication" \
    source_date_epoch "$SOURCE_DATE_EPOCH" \
    target "$target" \
    arch "$arch" \
    sysroot "$sysroot" \
    sysroot_contract immutable-snapshots-v1 \
    snapshot "$snapshot_final" \
    base_snapshot_digest "$empty_base_digest" \
    kernel.version "$expected_kernel_version" \
    orchestration_commit "$orchestration_commit" \
    orchestration_tree "$orchestration_tree" \
    recipe_sha256 "$recipe_sha256" \
    options_digest "$options_digest" \
    dependencies.gcc.build_id "$gcc_build_id" \
    dependencies.gcc.prefix "$gcc_prefix" \
    dependencies.gcc.receipt "$gcc_receipt" \
    dependencies.gcc.receipt_sha256 "$gcc_receipt_sha256" \
    dependencies.gcc.source_commit "$gcc_source_commit" \
    dependencies.gcc.source_tree "$gcc_source_tree" \
    dependencies.gcc.source_repository "$gcc_repository" \
    dependencies.gcc.orchestration_commit "$gcc_orchestration_commit" \
    dependencies.gcc.orchestration_tree "$gcc_orchestration_tree" \
    dependencies.binutils.build_id "$binutils_build_id" \
    dependencies.binutils.prefix "$binutils_prefix" \
    dependencies.binutils.receipt "$binutils_receipt" \
    dependencies.binutils.receipt_sha256 "$binutils_receipt_sha256" \
    dependencies.binutils.source_commit "$binutils_source_commit" \
    dependencies.binutils.source_tree "$binutils_source_tree" \
    dependencies.binutils.source_repository "$binutils_repository" \
    dependencies.binutils.orchestration_commit "$binutils_orchestration_commit" \
    dependencies.binutils.orchestration_tree "$binutils_orchestration_tree" \
    host.kernel_unifdef.path "$artifact_final/host/unifdef"
}

publish_usr_link() {
  local usr=$sysroot/usr
  local temporary_link=$sysroot/.usr-$$
  if [[ -L $usr ]]; then
    [[ $(readlink -- "$usr") == current/usr ]] || {
      echo "Refusing unexpected cohort usr symlink" >&2
      return 1
    }
    return 0
  fi
  [[ ! -e $usr ]] || {
    echo "Refusing unmanaged cohort usr path" >&2
    return 1
  }
  rm -f -- "$temporary_link"
  ln -s current/usr "$temporary_link"
  mv -T -- "$temporary_link" "$usr"
}

publish_current_link() {
  local temporary_link=$sysroot/.current-$$
  [[ ! -e $sysroot/current && ! -L $sysroot/current ]] || {
    echo "Refusing to replace an existing cohort current snapshot" >&2
    return 1
  }
  rm -f -- "$temporary_link"
  ln -s "snapshots/$build_id" "$temporary_link"
  mv -T -- "$temporary_link" "$sysroot/current"
}

if [[ -d $build_final && -d $snapshot_final && -f $receipt_final ]]; then
  validate_completed
  current_state=$("$script_path" --internal-python current-state "$sysroot" "$build_id")
  case $current_state in
    missing)
      publish_usr_link
      publish_current_link
      ;;
    this|other:*)
      publish_usr_link
      ;;
    *)
      echo "Unexpected cohort current state: $current_state" >&2
      exit 81
      ;;
  esac
  echo "CAJUNOS_LINUX_HEADERS_ALREADY_COMPLETE build_id=$build_id current=$current_state"
  exit 0
fi
if [[ -e $build_final || -e $snapshot_final || -e $artifact_final ]]; then
  echo "Refusing to reuse an incomplete published Linux header build: $build_id" >&2
  exit 82
fi
if [[ -e $temporary_root || -e $snapshot_temporary || -e $artifact_temporary || -e $log_dir ]]; then
  echo "Refusing colliding temporary or log path for run $run_id" >&2
  exit 83
fi

# This is the first sysroot mutation.  It must begin from the exact empty base;
# a later populated snapshot is never treated as an implicit predecessor.
if [[ -L $sysroot || ! -d $sysroot || -L $snapshots_root \
   || -n $(find "$sysroot" -mindepth 1 -maxdepth 1 ! -name snapshots -print -quit) \
   || ( -e $snapshots_root && ! -d $snapshots_root ) \
   || ( -d $snapshots_root && -n $(find "$snapshots_root" -mindepth 1 -print -quit) ) ]]; then
  echo "Linux UAPI headers require the cohort's explicit empty base sysroot" >&2
  exit 84
fi

build_succeeded=0
on_exit() {
  local status=$?
  if (( status != 0 || build_succeeded == 0 )); then
    if [[ -d $temporary_root ]]; then
      mv -- "$temporary_root" "$work_root/.failed-$build_id-$$"
    fi
    if [[ -d $snapshot_temporary ]]; then
      mv -- "$snapshot_temporary" "$work_root/.failed-snapshot-$build_id-$$"
    fi
    if [[ -d $artifact_temporary ]]; then
      mv -- "$artifact_temporary" "$artifacts_root/.failed-$build_id-$$"
    fi
    rmdir -- "$snapshots_root" 2>/dev/null || true
  fi
}
trap on_exit EXIT
"$script_path" --internal-python ensure-directories "$cajunos_root" \
  "work/sysroot/.tmp-$build_id-$$" \
  "work/sysroot/.tmp-$build_id-$$/kbuild-a" \
  "work/sysroot/.tmp-$build_id-$$/kbuild-b" \
  "work/sysroot/.tmp-$build_id-$$/repro-snapshot" \
  "sysroot/$cohort_id/snapshots/.tmp-$build_id-$$" \
  "artifacts/.tmp-$build_id-$$" \
  "logs/$run_id"
exec > >(tee "$log_file") 2>&1

echo "CajunOS Linux UAPI headers"
echo "build_id=$build_id"
echo "source=$locked_linux_commit"
echo "source_repository=$linux_repository"
echo "source_set=$source_set_digest"
echo "source_authentication=$source_authentication"
echo "orchestration=$orchestration_commit"
echo "recipe_sha256=$recipe_sha256"
echo "options_digest=$options_digest"
echo "gcc_build_id=$gcc_build_id"
echo "gcc_receipt_sha256=$gcc_receipt_sha256"
echo "binutils_build_id=$binutils_build_id"
echo "binutils_receipt_sha256=$binutils_receipt_sha256"
echo "target=$target"
echo "arch=$arch"
echo "sysroot=$sysroot"
echo "snapshot=$snapshot_final"
echo "makeflags=$MAKEFLAGS"
echo "source_date_epoch=$SOURCE_DATE_EPOCH"

printf '%s\n' "${headers_options[@]}" > "$artifact_temporary/headers-install.options"

make -C "$linux_source_dir" \
  O="$kbuild_a" \
  ARCH="$arch" \
  HOSTCC=/usr/bin/gcc \
  HOSTCXX=/usr/bin/g++ \
  INSTALL_HDR_PATH="$snapshot_temporary/usr" \
  -j"$jobs" \
  headers_install

make -C "$linux_source_dir" \
  O="$kbuild_b" \
  ARCH="$arch" \
  HOSTCC=/usr/bin/gcc \
  HOSTCXX=/usr/bin/g++ \
  INSTALL_HDR_PATH="$repro_snapshot/usr" \
  -j"$jobs" \
  headers_install

for relative in \
  usr/include/linux/version.h \
  usr/include/linux/types.h \
  usr/include/asm/unistd.h \
  usr/include/asm/unistd_64.h \
  usr/include/asm-generic/errno-base.h; do
  [[ -f $snapshot_temporary/$relative ]] || {
    echo "Installed Linux UAPI snapshot lacks $relative" >&2
    exit 85
  }
  [[ -f $repro_snapshot/$relative ]] || {
    echo "Independent Linux UAPI installation lacks $relative" >&2
    exit 86
  }
done

"$script_path" --internal-python compare \
  "$snapshot_temporary" "$repro_snapshot" "$artifact_temporary/inventory.json"
result_inventory_digest=$(python3 -c \
  'import json,sys; print("sha256:" + json.load(open(sys.argv[1], encoding="utf-8"))["digest"])' \
  "$artifact_temporary/inventory.json")

kernel_version=$(make -s -C "$linux_source_dir" kernelversion)
[[ $kernel_version != *$'\n'* && -n $kernel_version ]] || {
  echo "Unable to determine a single Linux kernel version" >&2
  exit 87
}
[[ $kernel_version == "$expected_kernel_version" ]] || {
  echo "Linux kernel version changed during header installation" >&2
  exit 94
}
printf '%s\n' "$kernel_version" > "$artifact_temporary/kernelversion.txt"

mapfile -t version_values < <(python3 - "$snapshot_temporary/usr/include/linux/version.h" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
match = re.search(r"^#define LINUX_VERSION_CODE\s+(\d+)\s*$", text, re.MULTILINE)
if not match:
    raise SystemExit("linux/version.h lacks LINUX_VERSION_CODE")
code = int(match.group(1))
print(code)
print(code >> 16)
print((code >> 8) & 255)
print(code & 255)
PY
)
linux_version_code=${version_values[0]}
linux_version_numeric=${version_values[1]}.${version_values[2]}.${version_values[3]}

probe_dir=$artifact_temporary/probe
mkdir -p "$probe_dir"
cat > "$probe_dir/linux-uapi.c" <<'EOF'
#include <linux/types.h>
#include <linux/version.h>
#include <asm/unistd.h>

_Static_assert(sizeof(__u64) == 8, "__u64 ABI");
_Static_assert(__NR_read == 0, "read syscall ABI");
_Static_assert(__NR_write == 1, "write syscall ABI");
_Static_assert(__NR_exit == 60, "exit syscall ABI");

int cajunos_linux_uapi_probe(__u64 value)
{
    return (int)value + LINUX_VERSION_CODE;
}
EOF
cross_gcc=$gcc_prefix/bin/$target-gcc
cross_readelf=$binutils_prefix/bin/$target-readelf
"$cross_gcc" \
  -std=c11 -Wall -Werror -ffreestanding -nostdinc \
  -isystem "$snapshot_temporary/usr/include" \
  -c "$probe_dir/linux-uapi.c" -o "$probe_dir/linux-uapi.o"
"$cross_readelf" -h "$probe_dir/linux-uapi.o" > "$probe_dir/linux-uapi.readelf-h"
grep -q 'Class:.*ELF64' "$probe_dir/linux-uapi.readelf-h"
grep -q 'Type:.*REL' "$probe_dir/linux-uapi.readelf-h"
grep -q 'Machine:.*Advanced Micro Devices X86-64' "$probe_dir/linux-uapi.readelf-h"

# Probes are read-only consumers of the snapshot.  Recompute and compare the
# complete inventory afterward so that this property is attested, not assumed.
"$script_path" --internal-python compare \
  "$snapshot_temporary" "$repro_snapshot" "$artifact_temporary/inventory-after-probe.json"
cmp -s "$artifact_temporary/inventory.json" "$artifact_temporary/inventory-after-probe.json" || {
  echo "Linux header snapshot changed while running probes" >&2
  exit 88
}

# Close both source and dependency TOCTOU windows immediately before creating
# the receipt and publishing immutable state.
"$project_root/scripts/fetch.py" validate --root "$cajunos_root"
if ! final_dependency_output=$(resolve_dependencies); then
  echo "GCC/Binutils dependency revalidation failed" >&2
  exit 89
fi
if [[ $final_dependency_output != "$dependency_output" ]]; then
  echo "Dependency provenance changed during Linux header installation" >&2
  exit 90
fi
if [[ -n $(git -C "$project_root" status --porcelain) \
   || $(git -C "$project_root" rev-parse HEAD) != "$orchestration_commit" \
   || $(git -C "$project_root" rev-parse 'HEAD^{tree}') != "$orchestration_tree" ]]; then
  echo "CajunOS orchestration changed during Linux header installation" >&2
  exit 91
fi

license_dir=$artifact_temporary/licenses/linux
mkdir -p "$license_dir"
git -C "$linux_source_dir" archive "$locked_linux_commit" -- "${license_paths[@]}" |
  tar -x -C "$license_dir"
mkdir -p "$artifact_temporary/host"
install -m 0755 "$kbuild_a/scripts/unifdef" "$artifact_temporary/host/unifdef"

python3 - \
  "$artifact_temporary/receipt.json" \
  "$artifact_temporary/inventory.json" \
  "$build_id" \
  "$locked_linux_commit" \
  "$locked_linux_tree" \
  "$linux_repository" \
  "$source_set_digest" \
  "$source_authentication" \
  "$SOURCE_DATE_EPOCH" \
  "$target" \
  "$arch" \
  "$sysroot" \
  "$snapshot_final" \
  "$empty_base_digest" \
  "$result_inventory_digest" \
  "$orchestration_commit" \
  "$orchestration_tree" \
  "$recipe_sha256" \
  "$options_digest" \
  "$artifact_temporary/headers-install.options" \
  "$gcc_build_id" \
  "$gcc_prefix" \
  "$gcc_receipt" \
  "$gcc_receipt_sha256" \
  "$gcc_source_commit" \
  "$gcc_source_tree" \
  "$gcc_repository" \
  "$gcc_orchestration_commit" \
  "$gcc_orchestration_tree" \
  "$binutils_build_id" \
  "$binutils_prefix" \
  "$binutils_receipt" \
  "$binutils_receipt_sha256" \
  "$binutils_source_commit" \
  "$binutils_source_tree" \
  "$binutils_repository" \
  "$binutils_orchestration_commit" \
  "$binutils_orchestration_tree" \
  "$kernel_version" \
  "$linux_version_code" \
  "$linux_version_numeric" \
  "$probe_dir" \
  "$license_dir" \
  "$log_file" \
  "$artifact_temporary/host/unifdef" \
  "$artifact_final/host/unifdef" <<'PY'
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

(
    output_value, inventory_value, build_id, source_commit, source_tree,
    source_repository, source_set_digest, source_authentication,
    source_date_epoch, target, arch, sysroot, snapshot, base_snapshot_digest,
    result_snapshot_digest, orchestration_commit, orchestration_tree,
    recipe_sha256, options_digest, options_value, gcc_build_id, gcc_prefix,
    gcc_receipt, gcc_receipt_sha256, gcc_source_commit, gcc_source_tree,
    gcc_source_repository, gcc_orchestration_commit, gcc_orchestration_tree,
    binutils_build_id, binutils_prefix, binutils_receipt,
    binutils_receipt_sha256, binutils_source_commit, binutils_source_tree,
    binutils_source_repository, binutils_orchestration_commit,
    binutils_orchestration_tree, kernel_version, linux_version_code,
    linux_version_numeric, probe_value, license_value, log_file,
    unifdef_value, published_unifdef_value,
) = sys.argv[1:]

output = Path(output_value)
probe_dir = Path(probe_value)
license_dir = Path(license_value)
unifdef = Path(unifdef_value)

def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def first_line(*argv: str) -> str:
    return subprocess.run(
        argv, check=True, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ).stdout.splitlines()[0]

with Path(inventory_value).open(encoding="utf-8") as stream:
    installed = json.load(stream)
with Path(options_value).open(encoding="utf-8") as stream:
    options = [line.rstrip("\n") for line in stream]

licenses = {
    path.relative_to(license_dir).as_posix(): sha256(path)
    for path in sorted(license_dir.rglob("*")) if path.is_file()
}
probe_hashes = {
    path.relative_to(probe_dir).as_posix(): sha256(path)
    for path in sorted(probe_dir.rglob("*")) if path.is_file()
}
packages = {}
for package in ("make", "gcc", "g++", "rsync", "sed"):
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Version}", package],
        check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    packages[package] = result.stdout if result.returncode == 0 else None

receipt = {
    "schema": 1,
    "build_id": build_id,
    "component": "linux",
    "stage": "uapi-headers",
    "source_commit": source_commit,
    "source_tree": source_tree,
    "source_repository": source_repository,
    "source_set_digest": source_set_digest,
    "source_authentication": source_authentication,
    "source_date_epoch": int(source_date_epoch),
    "target": target,
    "arch": arch,
    "kernel": {
        "version": kernel_version,
        "version_code": int(linux_version_code),
        "numeric_version": linux_version_numeric,
    },
    "sysroot": sysroot,
    "sysroot_contract": "immutable-snapshots-v1",
    "snapshot": snapshot,
    "base_snapshot_digest": base_snapshot_digest,
    "result_snapshot_digest": result_snapshot_digest,
    "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    "log": log_file,
    "orchestration_commit": orchestration_commit,
    "orchestration_tree": orchestration_tree,
    "recipe_sha256": recipe_sha256,
    "options_digest": options_digest,
    "headers_install_options": options,
    "reproducibility": {
        "independent_installations": 2,
        "inventory_schema": "paths-types-modes-sha256-symlink-targets-v1",
        "first_inventory_digest": result_snapshot_digest,
        "second_inventory_digest": result_snapshot_digest,
        "identical": True,
        "post_probe_inventory_digest": result_snapshot_digest,
    },
    "dependencies": {
        "gcc": {
            "build_id": gcc_build_id,
            "prefix": gcc_prefix,
            "receipt": gcc_receipt,
            "receipt_sha256": gcc_receipt_sha256,
            "source_commit": gcc_source_commit,
            "source_tree": gcc_source_tree,
            "source_repository": gcc_source_repository,
            "orchestration_commit": gcc_orchestration_commit,
            "orchestration_tree": gcc_orchestration_tree,
        },
        "binutils": {
            "build_id": binutils_build_id,
            "prefix": binutils_prefix,
            "receipt": binutils_receipt,
            "receipt_sha256": binutils_receipt_sha256,
            "source_commit": binutils_source_commit,
            "source_tree": binutils_source_tree,
            "source_repository": binutils_source_repository,
            "orchestration_commit": binutils_orchestration_commit,
            "orchestration_tree": binutils_orchestration_tree,
        },
    },
    "host": {
        "platform": platform.platform(),
        "make": first_line("/usr/bin/make", "--version"),
        "gcc": first_line("/usr/bin/gcc", "--version"),
        "g++": first_line("/usr/bin/g++", "--version"),
        "rsync": first_line("/usr/bin/rsync", "--version"),
        "sed": first_line("/usr/bin/sed", "--version"),
        "packages": packages,
        "kernel_unifdef": {
            "path": published_unifdef_value,
            "sha256": sha256(unifdef),
        },
    },
    "installed_entries": installed["entries"],
    "license_sha256": licenses,
    "outputs": {"probe_sha256": probe_hashes},
}

fd, temporary = tempfile.mkstemp(prefix=".receipt.", dir=output.parent, text=True)
with os.fdopen(fd, "w", encoding="utf-8") as stream:
    json.dump(receipt, stream, indent=2, sort_keys=True)
    stream.write("\n")
os.replace(temporary, output)
output.chmod(0o644)
PY

# Verify the just-created receipt before making any part of it immutable.
receipt_final=$artifact_temporary/receipt.json
snapshot_final_for_validation=$snapshot_temporary
"$script_path" --internal-python validate-completed \
  "$receipt_final" "$snapshot_final_for_validation" \
  schema 1 build_id "$build_id" component linux stage uapi-headers \
  source_commit "$locked_linux_commit" source_tree "$locked_linux_tree" \
  source_repository "$linux_repository" source_set_digest "$source_set_digest" \
  source_authentication "$source_authentication" source_date_epoch "$SOURCE_DATE_EPOCH" \
  target "$target" arch "$arch" sysroot "$sysroot" \
  sysroot_contract immutable-snapshots-v1 snapshot "$snapshot_final" \
  base_snapshot_digest "$empty_base_digest" \
  result_snapshot_digest "$result_inventory_digest" \
  kernel.version "$expected_kernel_version" \
  orchestration_commit "$orchestration_commit" orchestration_tree "$orchestration_tree" \
  recipe_sha256 "$recipe_sha256" options_digest "$options_digest" \
  dependencies.gcc.build_id "$gcc_build_id" \
  dependencies.gcc.prefix "$gcc_prefix" \
  dependencies.gcc.receipt "$gcc_receipt" \
  dependencies.gcc.receipt_sha256 "$gcc_receipt_sha256" \
  dependencies.gcc.source_commit "$gcc_source_commit" \
  dependencies.gcc.source_tree "$gcc_source_tree" \
  dependencies.gcc.source_repository "$gcc_repository" \
  dependencies.gcc.orchestration_commit "$gcc_orchestration_commit" \
  dependencies.gcc.orchestration_tree "$gcc_orchestration_tree" \
  dependencies.binutils.build_id "$binutils_build_id" \
  dependencies.binutils.prefix "$binutils_prefix" \
  dependencies.binutils.receipt "$binutils_receipt" \
  dependencies.binutils.receipt_sha256 "$binutils_receipt_sha256" \
  dependencies.binutils.source_commit "$binutils_source_commit" \
  dependencies.binutils.source_tree "$binutils_source_tree" \
  dependencies.binutils.source_repository "$binutils_repository" \
  dependencies.binutils.orchestration_commit "$binutils_orchestration_commit" \
  dependencies.binutils.orchestration_tree "$binutils_orchestration_tree" \
  host.kernel_unifdef.path "$artifact_final/host/unifdef"

# Publish immutable content before the mutable selector.  The `usr` link is a
# permanent indirection; `current` is advanced last and is never replaced by an
# idempotent rerun if a future stage has already advanced it.
"$script_path" --internal-python validate-directories "$cajunos_root" \
  work work/sysroot tools artifacts logs sysroot \
  "sysroot/$cohort_id" "sysroot/$cohort_id/snapshots" \
  "work/sysroot/.tmp-$build_id-$$" \
  "sysroot/$cohort_id/snapshots/.tmp-$build_id-$$" \
  "artifacts/.tmp-$build_id-$$"
mv -T -- "$snapshot_temporary" "$snapshot_final"
mv -T -- "$temporary_root" "$build_final"
mv -T -- "$artifact_temporary" "$artifact_final"
receipt_final=$artifact_final/receipt.json
publish_usr_link
publish_current_link

validate_completed
current_state=$("$script_path" --internal-python current-state "$sysroot" "$build_id")
[[ $current_state == this ]] || {
  echo "Published Linux header snapshot is not current" >&2
  exit 92
}

build_succeeded=1
trap - EXIT
echo "CAJUNOS_LINUX_HEADERS_OK build_id=$build_id snapshot=$snapshot_final"
