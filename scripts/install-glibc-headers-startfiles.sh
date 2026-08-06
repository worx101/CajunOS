#!/usr/bin/env bash
set -Eeuo pipefail
umask 022
export LC_ALL=C
export TZ=UTC
export PATH=/usr/bin:/bin

script_path=$(readlink -f -- "${BASH_SOURCE[0]}")
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
inventory_helper=$project_root/scripts/install-linux-headers.sh

# Reuse the frozen, reviewed filesystem walker for every inventory.  Both its
# bytes and this recipe's bytes are inputs to the build identity.
if [[ ${1:-} == --internal-python ]]; then
  shift
  internal_command=${1:-}
  case $internal_command in
    inventory|dependency-inventory|compare|ensure-directories|validate-directories)
      exec "$inventory_helper" --internal-python "$@"
      ;;
  esac
  exec python3 - "$script_path" "$inventory_helper" "$@" <<'PY'
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile


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


def helper_json(command: str, *arguments: object) -> object:
    result = subprocess.run(
        [str(helper), "--internal-python", command, *(str(v) for v in arguments)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        fail(result.stderr.strip() or f"inventory helper failed: {command}")
    return json.loads(result.stdout)


def inventory(root: Path) -> dict[str, object]:
    value = helper_json("inventory", root)
    if not isinstance(value, dict) or not isinstance(value.get("entries"), dict):
        fail("inventory helper returned invalid data")
    return value


def regular_hashes(root: Path) -> dict[str, str]:
    try:
        metadata = root.lstat()
    except FileNotFoundError:
        fail(f"attestation directory does not exist: {root}")
    if not stat.S_ISDIR(metadata.st_mode):
        fail(f"attestation path is not a real directory: {root}")
    hashes: dict[str, str] = {}
    for directory, names, filenames in os.walk(root, followlinks=False):
        names.sort()
        filenames.sort()
        directory_path = Path(directory)
        for name in names:
            child = directory_path / name
            if not stat.S_ISDIR(child.lstat().st_mode):
                fail(f"unsupported attestation directory entry: {child}")
        for name in filenames:
            child = directory_path / name
            child_metadata = child.lstat()
            if not stat.S_ISREG(child_metadata.st_mode) or child_metadata.st_nlink != 1:
                fail(f"unsupported attestation file: {child}")
            hashes[child.relative_to(root).as_posix()] = sha256(child)
    return hashes


def require_pairs(arguments: list[str]) -> dict[str, str]:
    if len(arguments) % 2:
        fail("expected key/value pairs")
    return dict(zip(arguments[::2], arguments[1::2], strict=True))


def dotted(value: object, key: str) -> object:
    for part in key.split("."):
        if not isinstance(value, dict) or part not in value:
            fail(f"completed receipt lacks {key}")
        value = value[part]
    return value


def derive_delta(base: dict[str, object], result: dict[str, object]) -> dict[str, object]:
    base_entries = base["entries"]
    result_entries = result["entries"]
    if not isinstance(base_entries, dict) or not isinstance(result_entries, dict):
        fail("invalid inventory entries")
    for path, metadata in base_entries.items():
        if result_entries.get(path) != metadata:
            fail(f"sealed base entry changed or disappeared: {path}")
    added = {path: metadata for path, metadata in result_entries.items() if path not in base_entries}
    required_crt = {"usr/lib/crt1.o", "usr/lib/crti.o", "usr/lib/crtn.o"}
    seen_crt = set()
    forbidden = re.compile(
        r"^(?:libc(?:\.so(?:\..*)?|\.a)|ld-linux[^/]*|libgcc[^/]*|"
        r"crtbegin[^/]*|crtend[^/]*)$"
    )
    for path, metadata in added.items():
        if path == ".":
            fail("result unexpectedly replaced its root")
        pure = PurePosixPath(path)
        basename = pure.name
        if forbidden.fullmatch(basename):
            fail(f"forbidden runtime artifact in bootstrap snapshot: {path}")
        allowed_header = path == "usr/include" or path.startswith("usr/include/")
        allowed_lib_dir = path == "usr/lib" and metadata.get("type") == "directory"
        allowed_crt = (
            path in required_crt
            and metadata.get("type") == "file"
            and metadata.get("mode") == "0644"
        )
        if not (allowed_header or allowed_lib_dir or allowed_crt):
            fail(f"unexpected glibc bootstrap addition: {path}")
        if allowed_crt:
            seen_crt.add(path)
    if seen_crt != required_crt:
        missing = sorted(required_crt - seen_crt)
        fail(f"glibc bootstrap snapshot lacks exact CRT set: {missing}")
    for path in result_entries:
        if forbidden.fullmatch(PurePosixPath(path).name):
            fail(f"forbidden runtime artifact in complete snapshot: {path}")
    return {
        "schema": "sealed-base-additions-v1",
        "base_digest": f"sha256:{base['digest']}",
        "result_digest": f"sha256:{result['digest']}",
        "added_entries": added,
        "added_entries_digest": f"sha256:{canonical_digest(added)}",
    }


def safe_selector(sysroot: Path) -> tuple[Path, str]:
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
    if not usr.is_symlink() or os.readlink(usr) != "current/usr":
        fail("cohort usr is not the managed current/usr symlink")
    if not current.is_symlink():
        fail("cohort current selector is not a symlink")
    target = os.readlink(current)
    match = re.fullmatch(r"snapshots/([A-Za-z0-9][A-Za-z0-9._-]{0,127})", target)
    if not match:
        fail("cohort current selector has an unsafe target")
    selected_snapshot = snapshots / match.group(1)
    try:
        selected_metadata = selected_snapshot.lstat()
    except FileNotFoundError:
        fail("cohort current selector names an absent snapshot")
    if not stat.S_ISDIR(selected_metadata.st_mode):
        fail("cohort current selector does not name a real snapshot directory")
    try:
        current.resolve(strict=True).relative_to(snapshots.resolve(strict=True))
        usr.resolve(strict=True).relative_to(selected_snapshot.resolve(strict=True))
    except (FileNotFoundError, RuntimeError, ValueError):
        fail("cohort current selector is broken or escaping")
    return current, match.group(1)


def require_descendant(sysroot: Path, selected: str, ancestor: str) -> None:
    if sysroot.parent.name != "sysroot":
        fail("cohort sysroot does not follow the managed root layout")
    artifacts = sysroot.parent.parent / "artifacts"
    cursor = selected
    seen = set()
    while cursor != ancestor:
        if cursor in seen or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", cursor):
            fail("selector ancestry is cyclic or unsafe")
        seen.add(cursor)
        receipt_path = artifacts / cursor / "receipt.json"
        try:
            metadata = receipt_path.lstat()
        except FileNotFoundError:
            fail("selector names an unproven later snapshot")
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            fail("later-stage ancestry receipt is not a plain file")
        with receipt_path.open(encoding="utf-8") as stream:
            receipt = json.load(stream)
        if (
            receipt.get("build_id") != cursor
            or receipt.get("sysroot") != str(sysroot)
            or receipt.get("snapshot") != str(sysroot / "snapshots" / cursor)
        ):
            fail("later-stage ancestry receipt has invalid identity")
        base = receipt.get("base_build_id")
        if not isinstance(base, str):
            fail("later-stage ancestry receipt lacks base_build_id")
        cursor = base


script = Path(sys.argv[1])
helper = Path(sys.argv[2])
if len(sys.argv) < 4:
    fail("missing internal command")
command, *arguments = sys.argv[3:]

if command == "build-id":
    if len(arguments) < 3 or len(arguments[1:]) % 2:
        fail("build-id requires COMMIT and key/value pairs")
    commit = arguments[0]
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        fail("unsafe source commit for build ID")
    print(
        f"glibc-headers-startfiles-{commit[:12]}-"
        f"{canonical_digest(require_pairs(arguments[1:]))[:16]}"
    )
elif command == "derived-delta":
    if len(arguments) != 3:
        fail("derived-delta requires BASE RESULT OUTPUT")
    delta = derive_delta(inventory(Path(arguments[0])), inventory(Path(arguments[1])))
    output = Path(arguments[2])
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(delta, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.replace(temporary, output)
    output.chmod(0o644)
elif command == "no-shared-inodes":
    if len(arguments) != 2:
        fail("no-shared-inodes requires BASE COPY")
    roots = [Path(value) for value in arguments]
    inode_sets = []
    for root in roots:
        seen = set()
        for directory, names, filenames in os.walk(root, followlinks=False):
            names.sort()
            filenames.sort()
            for name in filenames:
                path = Path(directory) / name
                metadata = path.lstat()
                if stat.S_ISREG(metadata.st_mode):
                    seen.add((metadata.st_dev, metadata.st_ino))
        inode_sets.append(seen)
    if inode_sets[0] & inode_sets[1]:
        fail("snapshot copy shares regular-file inodes with its sealed base")
elif command == "selector-state":
    if len(arguments) != 3:
        fail("selector-state requires SYSROOT BASE_BUILD_ID BUILD_ID")
    _, selected = safe_selector(Path(arguments[0]))
    if selected == arguments[2]:
        print("this")
    elif selected == arguments[1]:
        print("base")
    else:
        require_descendant(Path(arguments[0]), selected, arguments[2])
        print(f"later:{selected}")
elif command == "selector-transition":
    if len(arguments) != 3:
        fail("selector-transition requires SYSROOT BASE_BUILD_ID BUILD_ID")
    sysroot = Path(arguments[0])
    base_build_id, build_id = arguments[1:]
    current, selected = safe_selector(sysroot)
    result = sysroot / "snapshots" / build_id
    try:
        result_metadata = result.lstat()
    except FileNotFoundError:
        fail("result snapshot does not exist for selector transition")
    if not stat.S_ISDIR(result_metadata.st_mode):
        fail("result snapshot is not a real directory")
    if selected == build_id:
        print("this")
    elif selected != base_build_id:
        require_descendant(sysroot, selected, build_id)
        print(f"later:{selected}")
    else:
        temporary = sysroot / f".current-{os.getpid()}"
        try:
            os.symlink(f"snapshots/{build_id}", temporary)
            os.replace(temporary, current)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        _, selected_after = safe_selector(sysroot)
        if selected_after != build_id:
            fail("selector transition did not publish the requested snapshot")
        print("advanced")
elif command == "validate-completed":
    if len(arguments) < 5 or len(arguments[3:]) % 2:
        fail("validate-completed requires RECEIPT SNAPSHOT BASE and key/value pairs")
    receipt_path, snapshot, base = map(Path, arguments[:3])
    expected = require_pairs(arguments[3:])
    try:
        receipt_metadata = receipt_path.lstat()
    except FileNotFoundError:
        fail("completed receipt does not exist")
    if not stat.S_ISREG(receipt_metadata.st_mode) or receipt_metadata.st_nlink != 1:
        fail("completed receipt is not a plain single-linked file")
    with receipt_path.open(encoding="utf-8") as stream:
        receipt = json.load(stream)
    for key, expected_value in expected.items():
        if str(dotted(receipt, key)) != expected_value:
            fail(f"completed receipt mismatch for {key}")
    result_inventory = inventory(snapshot)
    base_inventory = inventory(base)
    if receipt.get("installed_entries") != result_inventory["entries"]:
        fail("completed snapshot failed full inventory validation")
    result_digest = f"sha256:{result_inventory['digest']}"
    base_digest = f"sha256:{base_inventory['digest']}"
    if receipt.get("result_snapshot_digest") != result_digest:
        fail("completed result snapshot digest is invalid")
    if receipt.get("base_snapshot_digest") != base_digest:
        fail("completed base snapshot digest is invalid")
    actual_delta = derive_delta(base_inventory, result_inventory)
    if receipt.get("delta") != actual_delta:
        fail("completed delta attestation is invalid")
    expected_repro = {
        "independent_installations": 2,
        "inventory_schema": "paths-types-modes-sha256-symlink-targets-v1",
        "first_inventory_digest": result_digest,
        "second_inventory_digest": result_digest,
        "identical": True,
        "base_unchanged_after_build": True,
        "post_probe_inventory_digest": result_digest,
    }
    if receipt.get("reproducibility") != expected_repro:
        fail("completed reproducibility attestation is invalid")
    if receipt.get("functional_libc") != "absent":
        fail("completed receipt makes an invalid functional-libc claim")
    options_path = receipt_path.parent / "configure.options"
    try:
        options_metadata = options_path.lstat()
    except FileNotFoundError:
        fail("completed artifact lacks configure.options")
    if not stat.S_ISREG(options_metadata.st_mode) or options_metadata.st_nlink != 1:
        fail("completed configure.options is not a plain single-linked file")
    options = options_path.read_text(encoding="utf-8").splitlines()
    if not options or receipt.get("configure_options") != options:
        fail("completed configure options are invalid")
    material = b"".join(value.encode() + b"\0" for value in options)
    if receipt.get("options_digest") != hashlib.sha256(material).hexdigest():
        fail("completed options digest is invalid")
    generated = {
        "gnu/lib-names.h": snapshot / "usr/include/gnu/lib-names.h",
        "gnu/lib-names-64.h": snapshot / "usr/include/gnu/lib-names-64.h",
        "gnu/stubs.h": snapshot / "usr/include/gnu/stubs.h",
        "gnu/stubs-64.h": snapshot / "usr/include/gnu/stubs-64.h",
    }
    for name, path in generated.items():
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o644:
            fail(f"completed generated header has invalid mode/type: {name}")
    selector = generated["gnu/stubs.h"].read_text(encoding="utf-8")
    if "<gnu/stubs-64.h>" not in selector or "<gnu/stubs-32.h>" not in selector or "<gnu/stubs-x32.h>" not in selector:
        fail("completed stubs selector lacks the upstream x86 ABI branches")
    if any(
        line.startswith("@")
        for line in generated["gnu/stubs-64.h"].read_text(encoding="utf-8").splitlines()
    ):
        fail("completed stubs-64 header retains template directives")
    if receipt.get("generated_header_sha256") != {name: sha256(path) for name, path in generated.items()}:
        fail("completed generated-header attestation is invalid")
    crt_hashes = {
        name: sha256(snapshot / "usr/lib" / name)
        for name in ("crt1.o", "crti.o", "crtn.o")
    }
    if receipt.get("crt_sha256") != crt_hashes:
        fail("completed CRT attestation is invalid")
    actual_licenses = inventory(receipt_path.parent / "licenses/glibc")
    if receipt.get("license_inventory") != actual_licenses:
        fail("completed license inventory attestation is invalid")
    license_sidecar = receipt_path.parent / "license-inventory.json"
    try:
        sidecar_metadata = license_sidecar.lstat()
    except FileNotFoundError:
        fail("completed artifact lacks license-inventory.json")
    if not stat.S_ISREG(sidecar_metadata.st_mode) or sidecar_metadata.st_nlink != 1:
        fail("completed license inventory sidecar is not a plain file")
    with license_sidecar.open(encoding="utf-8") as stream:
        if json.load(stream) != actual_licenses:
            fail("completed license inventory sidecar is invalid")
    if receipt.get("outputs", {}).get("probe_sha256") != regular_hashes(receipt_path.parent / "probe"):
        fail("completed probe attestation is invalid")
    if receipt.get("configuration_sha256") != regular_hashes(receipt_path.parent / "configuration"):
        fail("completed configuration attestation is invalid")
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

cajunos_root=${CAJUNOS_ROOT:-/srv/cajunos}
target=${CAJUNOS_TARGET:-x86_64-cajunos-linux-gnu}
arch=${CAJUNOS_LINUX_ARCH:-x86_64}
minimum_kernel=5.4
target_cflags='-O2 -g0 -march=x86-64-v2 -mtune=generic'
expected_user=${CAJUNOS_BUILD_USER:-cajunos}
requested_gcc_id=${CAJUNOS_GCC_BUILD_ID:-}
requested_linux_id=${CAJUNOS_LINUX_HEADERS_BUILD_ID:-}
lock_file=$project_root/locks/bootstrap.lock.json
manifest_file=$project_root/manifests/bootstrap.json

if [[ $(id -u) -eq 0 || $(id -un) != "$expected_user" ]]; then
  echo "Run this build as the unprivileged $expected_user account" >&2
  exit 100
fi
if [[ $arch != x86_64 || $target != x86_64-cajunos-linux-gnu ]]; then
  echo "This stage supports only x86_64-cajunos-linux-gnu / ARCH=x86_64" >&2
  exit 101
fi
for command in flock git install make python3 rsync sed sha256sum tar; do
  command -v "$command" >/dev/null || {
    echo "Missing required host command: $command" >&2
    exit 102
  }
done
[[ -x $inventory_helper ]] || {
  echo "Frozen Linux-header inventory helper is unavailable" >&2
  exit 103
}

"$project_root/scripts/fetch.py" validate --root "$cajunos_root" --json >/dev/null
cajunos_root=$(readlink -f -- "$cajunos_root")
exec 8>"$cajunos_root/upstream/.cajunos-source.lock"
if ! flock -n 8; then
  echo "Another CajunOS source operation or build owns the source lock" >&2
  exit 104
fi
"$project_root/scripts/fetch.py" validate --root "$cajunos_root"

glibc_source_dir=$cajunos_root/upstream/glibc
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
for wanted in ("glibc", "linux", "gcc", "binutils"):
    for component in lock["components"]:
        if component["name"] == wanted:
            print(component["commit"])
            print(component["tree"])
            print(component["repository"])
            break
    else:
        raise SystemExit(f"{wanted} is absent from the bootstrap lock")
for component in manifest["components"]:
    if component["name"] == "glibc":
        print(*component["license_files"], sep="\n")
        break
else:
    raise SystemExit("glibc is absent from the bootstrap manifest")
PY
)
source_set_digest=${lock_values[0]}
source_authentication=${lock_values[1]}
locked_glibc_commit=${lock_values[2]}
locked_glibc_tree=${lock_values[3]}
glibc_repository=${lock_values[4]}
locked_linux_commit=${lock_values[5]}
locked_linux_tree=${lock_values[6]}
linux_repository=${lock_values[7]}
locked_gcc_commit=${lock_values[8]}
locked_gcc_tree=${lock_values[9]}
gcc_repository=${lock_values[10]}
locked_binutils_commit=${lock_values[11]}
locked_binutils_tree=${lock_values[12]}
binutils_repository=${lock_values[13]}
license_paths=("${lock_values[@]:14}")

if [[ $locked_glibc_commit != 97f74c6781184a807faa3c0c02f6c5822a98b731 \
   || $locked_glibc_tree != d413e0e451f2f311d93af5b5b578bfd9b4523f3f ]]; then
  echo "This reviewed stage is frozen to glibc 97f74c678118" >&2
  exit 105
fi
if ! grep -Fxq '#define VERSION "2.44.9000"' "$glibc_source_dir/version.h"; then
  echo "Locked glibc no longer identifies as version 2.44.9000" >&2
  exit 106
fi
if [[ $source_authentication != authenticated ]]; then
  if [[ ${CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES:-} != 1 ]]; then
    echo "This source cohort contains recorded unauthenticated transports." >&2
    echo "Set CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES=1 after reviewing the lock." >&2
    exit 107
  fi
  echo "WARNING: explicitly accepting the lock's recorded unauthenticated transports" >&2
fi
if [[ -n $(git -C "$project_root" status --porcelain) ]]; then
  echo "Refusing an official build from a dirty CajunOS orchestration checkout" >&2
  exit 108
fi
orchestration_commit=$(git -C "$project_root" rev-parse HEAD)
orchestration_tree=$(git -C "$project_root" rev-parse 'HEAD^{tree}')

jobs=${CAJUNOS_JOBS:-6}
if [[ ! $jobs =~ ^[1-9][0-9]*$ ]]; then
  echo "CAJUNOS_JOBS must be a positive integer" >&2
  exit 109
fi
export MAKEFLAGS="-j$jobs"
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git -C "$glibc_source_dir" show -s --format=%ct "$locked_glibc_commit")
linux_source_date_epoch=$(git -C "$linux_source_dir" show -s --format=%ct "$locked_linux_commit")
expected_linux_kernel_version=$(make -s -C "$linux_source_dir" kernelversion)
[[ -n $expected_linux_kernel_version && $expected_linux_kernel_version != *$'\n'* ]] || {
  echo "Unable to determine the locked Linux kernel version" >&2
  exit 134
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
  exit 110
fi

resolve_chain() {
  python3 - \
    "$script_path" "$inventory_helper" "$artifacts_root" "$tools_root" \
    "$sysroot" "$snapshots_root" "$requested_linux_id" "$requested_gcc_id" \
    "$source_set_digest" "$source_authentication" "$target" "$arch" \
    "$linux_source_date_epoch" "$expected_linux_kernel_version" \
    "$locked_linux_commit" "$locked_linux_tree" "$linux_repository" \
    "$locked_gcc_commit" "$locked_gcc_tree" "$gcc_repository" \
    "$locked_binutils_commit" "$locked_binutils_tree" "$binutils_repository" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

(
    script_value, helper_value, artifacts_value, tools_value, sysroot_value,
    snapshots_value, requested_linux, requested_gcc, source_set_digest,
    source_authentication, target, arch, linux_source_date_epoch,
    linux_kernel_version, linux_commit, linux_tree, linux_repository,
    gcc_commit, gcc_tree, gcc_repository, binutils_commit,
    binutils_tree, binutils_repository,
) = sys.argv[1:]
script = Path(script_value)
helper = Path(helper_value)
artifacts = Path(artifacts_value)
tools = Path(tools_value)
sysroot = Path(sysroot_value)
snapshots = Path(snapshots_value)

def fail(message):
    raise SystemExit(message)

def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def orchestration_blob_sha256(receipt, relative):
    commit = receipt.get("orchestration_commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        fail("dependency receipt has an unsafe orchestration commit")
    result = subprocess.run(
        ["git", "-C", script.parent.parent, "show", f"{commit}:{relative}"],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode:
        fail(f"dependency recipe blob is unavailable: {relative}")
    return hashlib.sha256(result.stdout).hexdigest()

def helper_json(command, *arguments):
    result = subprocess.run(
        [helper, "--internal-python", command, *(str(v) for v in arguments)],
        check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode:
        fail(result.stderr.strip() or f"helper failed: {command}")
    return json.loads(result.stdout)

def dep_inventory(prefix):
    result = subprocess.run(
        [helper, "--internal-python", "dependency-inventory", prefix, tools],
        check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode:
        fail(result.stderr.strip() or "dependency inventory failed")
    return json.loads(result.stdout)

def require_plain_receipt(path):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail(f"dependency receipt is absent: {path}")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail(f"dependency receipt is not a plain single-linked file: {path}")

try:
    if not stat.S_ISDIR(tools.lstat().st_mode):
        fail("managed tools root is not a real directory")
    if not stat.S_ISDIR(sysroot.lstat().st_mode):
        fail("cohort sysroot is not a real directory")
    if not stat.S_ISDIR(snapshots.lstat().st_mode):
        fail("snapshot root is not a real directory")
except FileNotFoundError as error:
    fail(f"managed dependency path is absent: {error.filename}")

if requested_linux and not re.fullmatch(r"linux-uapi-headers-[A-Za-z0-9._-]+", requested_linux):
    fail("unsafe CAJUNOS_LINUX_HEADERS_BUILD_ID")
if requested_gcc and not re.fullmatch(r"gcc-stage1-[A-Za-z0-9._-]+", requested_gcc):
    fail("unsafe CAJUNOS_GCC_BUILD_ID")
linux_paths = (
    [artifacts / requested_linux / "receipt.json"] if requested_linux
    else sorted(artifacts.glob("linux-uapi-headers-*/receipt.json"))
)
linux_candidates = []
for receipt_path in linux_paths:
    try:
        require_plain_receipt(receipt_path)
    except SystemExit:
        if requested_linux:
            raise
        continue
    with receipt_path.open(encoding="utf-8") as stream:
        receipt = json.load(stream)
    if (
        receipt.get("schema") == 1
        and receipt.get("component") == "linux"
        and receipt.get("stage") == "uapi-headers"
        and receipt.get("source_set_digest") == source_set_digest
        and receipt.get("source_authentication") == source_authentication
        and receipt.get("source_commit") == linux_commit
        and receipt.get("source_tree") == linux_tree
        and receipt.get("source_repository") == linux_repository
        and receipt.get("target") == target
        and receipt.get("arch") == arch
        and receipt.get("sysroot") == str(sysroot)
    ):
        linux_candidates.append((receipt_path, receipt))
if len(linux_candidates) != 1:
    fail(f"expected one matching Linux UAPI receipt, found {len(linux_candidates)}")
linux_receipt_path, linux_receipt = linux_candidates[0]
linux_build_id = linux_receipt.get("build_id")
if (
    not isinstance(linux_build_id, str)
    or not re.fullmatch(r"linux-uapi-headers-[A-Za-z0-9._-]+", linux_build_id)
    or linux_receipt_path.parent.name != linux_build_id
):
    fail("Linux UAPI receipt/build directory mismatch")
linux_snapshot = snapshots / linux_build_id
if linux_receipt.get("snapshot") != str(linux_snapshot):
    fail("Linux UAPI receipt snapshot mismatch")
if linux_receipt.get("installed_entries") != helper_json("inventory", linux_snapshot)["entries"]:
    fail("Linux UAPI snapshot failed full inventory validation")
linux_digest = "sha256:" + helper_json("inventory", linux_snapshot)["digest"]
if linux_receipt.get("result_snapshot_digest") != linux_digest:
    fail("Linux UAPI snapshot digest mismatch")

gcc_dep = linux_receipt.get("dependencies", {}).get("gcc", {})
gcc_build_id = gcc_dep.get("build_id")
if not isinstance(gcc_build_id, str) or not re.fullmatch(r"gcc-stage1-[A-Za-z0-9._-]+", gcc_build_id):
    fail("Linux UAPI receipt has an unsafe GCC build ID")
if requested_gcc and gcc_build_id != requested_gcc:
    fail("Linux UAPI dependency does not match CAJUNOS_GCC_BUILD_ID")
gcc_receipt_path = artifacts / str(gcc_build_id) / "receipt.json"
gcc_prefix = tools / str(gcc_build_id)
require_plain_receipt(gcc_receipt_path)
if gcc_dep.get("receipt") != str(gcc_receipt_path) or gcc_dep.get("prefix") != str(gcc_prefix):
    fail("Linux UAPI GCC dependency paths are invalid")
if sha256(gcc_receipt_path) != gcc_dep.get("receipt_sha256"):
    fail("Linux UAPI GCC receipt hash mismatch")
with gcc_receipt_path.open(encoding="utf-8") as stream:
    gcc_receipt = json.load(stream)
if (
    gcc_receipt.get("schema") != 1 or gcc_receipt.get("component") != "gcc"
    or gcc_receipt.get("stage") != "stage1"
    or gcc_receipt.get("build_id") != gcc_build_id
    or gcc_receipt.get("source_set_digest") != source_set_digest
    or gcc_receipt.get("source_authentication") != source_authentication
    or gcc_receipt.get("source_commit") != gcc_commit
    or gcc_receipt.get("source_tree") != gcc_tree
    or gcc_receipt.get("source_repository") != gcc_repository
    or gcc_receipt.get("target") != target
    or gcc_receipt.get("prefix") != str(gcc_prefix)
    or gcc_receipt.get("sysroot") != str(sysroot)
    or gcc_receipt.get("sysroot_contract") != "empty-at-build"
    or gcc_receipt.get("target_contract") != {
        "architecture": "x86-64-v2",
        "fixincludes": "disabled-for-headerless-stage",
        "glibc_series": "2.44",
        "runtime": "intentionally absent",
        "threads": "single",
        "tuning": "generic",
    }
):
    fail("GCC dependency provenance mismatch")
if (
    gcc_dep.get("source_commit") != gcc_commit
    or gcc_dep.get("source_tree") != gcc_tree
    or gcc_dep.get("source_repository") != gcc_repository
    or gcc_dep.get("orchestration_commit") != gcc_receipt.get("orchestration_commit")
    or gcc_dep.get("orchestration_tree") != gcc_receipt.get("orchestration_tree")
):
    fail("Linux UAPI receipt does not exactly bind its GCC dependency")
if gcc_receipt.get("recipe_sha256") != orchestration_blob_sha256(
    gcc_receipt, "scripts/build-gcc-stage1.sh"
):
    fail("GCC receipt recipe hash differs from its orchestration blob")
if gcc_receipt.get("installed_entries") != dep_inventory(gcc_prefix):
    fail("GCC dependency prefix failed full inventory validation")
gcc_driver = gcc_prefix / "bin" / f"{target}-gcc"
if not gcc_driver.is_file() or not os.access(gcc_driver, os.X_OK):
    fail("GCC dependency lacks its executable driver")
if subprocess.run([gcc_driver, "-dumpmachine"], check=True, text=True, stdout=subprocess.PIPE).stdout.strip() != target:
    fail("GCC dependency target changed")
if subprocess.run([gcc_driver, "-print-sysroot"], check=True, text=True, stdout=subprocess.PIPE).stdout.strip() != str(sysroot):
    fail("GCC dependency sysroot changed")

binutils_dep = gcc_receipt.get("dependencies", {}).get("binutils", {})
binutils_build_id = binutils_dep.get("build_id")
if not isinstance(binutils_build_id, str) or not re.fullmatch(r"binutils-stage1-[A-Za-z0-9._-]+", binutils_build_id):
    fail("GCC receipt has an unsafe Binutils build ID")
binutils_receipt_path = artifacts / str(binutils_build_id) / "receipt.json"
binutils_prefix = tools / str(binutils_build_id)
require_plain_receipt(binutils_receipt_path)
if binutils_dep.get("receipt") != str(binutils_receipt_path) or binutils_dep.get("prefix") != str(binutils_prefix):
    fail("GCC Binutils dependency paths are invalid")
if sha256(binutils_receipt_path) != binutils_dep.get("receipt_sha256"):
    fail("nested Binutils receipt hash mismatch")
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
    fail("nested Binutils dependency provenance mismatch")
if binutils_receipt.get("installed_entries") != dep_inventory(binutils_prefix):
    fail("Binutils dependency prefix failed full inventory validation")
if binutils_receipt.get("recipe_sha256") != orchestration_blob_sha256(
    binutils_receipt, "scripts/build-binutils-stage1.sh"
):
    fail("Binutils receipt recipe hash differs from its orchestration blob")
linux_binutils_dep = linux_receipt.get("dependencies", {}).get("binutils", {})
if (
    linux_binutils_dep.get("build_id") != binutils_build_id
    or linux_binutils_dep.get("prefix") != str(binutils_prefix)
    or linux_binutils_dep.get("receipt") != str(binutils_receipt_path)
    or linux_binutils_dep.get("receipt_sha256") != sha256(binutils_receipt_path)
    or linux_binutils_dep.get("source_commit") != binutils_commit
    or linux_binutils_dep.get("source_tree") != binutils_tree
    or linux_binutils_dep.get("source_repository") != binutils_repository
    or linux_binutils_dep.get("orchestration_commit") != binutils_receipt.get("orchestration_commit")
    or linux_binutils_dep.get("orchestration_tree") != binutils_receipt.get("orchestration_tree")
):
    fail("Linux UAPI receipt does not exactly bind its Binutils dependency")

required_tools = (
    "ar", "as", "ld", "nm", "objcopy", "objdump", "ranlib", "readelf", "strip"
)
for program in required_tools:
    path = binutils_prefix / "bin" / f"{target}-{program}"
    if not path.is_file() or not os.access(path, os.X_OK):
        fail(f"Binutils dependency lacks {program}")
    try:
        path.resolve(strict=True).relative_to(binutils_prefix.resolve(strict=True))
    except (FileNotFoundError, RuntimeError, ValueError):
        fail(f"Binutils {program} resolves outside its prefix")
for program in ("as", "ld"):
    actual = subprocess.run(
        [gcc_driver, f"-print-prog-name={program}"], check=True, text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    expected = binutils_prefix / "bin" / f"{target}-{program}"
    if Path(actual).resolve(strict=True) != expected.resolve(strict=True):
        fail(f"GCC {program} binding differs from sealed Binutils")

# Exercise the Linux stage's own completed verifier, including its options,
# license, probe, and host-unifdef attestations.
validation = [
    helper, "--internal-python", "validate-completed",
    linux_receipt_path, linux_snapshot,
    "schema", "1", "build_id", linux_build_id, "component", "linux",
    "stage", "uapi-headers", "source_commit", linux_commit,
    "source_tree", linux_tree, "source_repository", linux_repository,
    "source_set_digest", source_set_digest,
    "source_authentication", source_authentication, "target", target,
    "arch", arch, "sysroot", str(sysroot), "snapshot", str(linux_snapshot),
    "source_date_epoch", linux_source_date_epoch,
    "base_snapshot_digest", "sha256:" + hashlib.sha256(
        b"cajunos-empty-sysroot-v1\n"
    ).hexdigest(),
    "kernel.version", linux_kernel_version,
    "result_snapshot_digest", linux_digest,
    "dependencies.gcc.build_id", str(gcc_build_id),
    "dependencies.gcc.receipt_sha256", sha256(gcc_receipt_path),
    "dependencies.binutils.build_id", str(binutils_build_id),
    "dependencies.binutils.receipt_sha256", sha256(binutils_receipt_path),
    "host.kernel_unifdef.path", str(linux_receipt_path.parent / "host/unifdef"),
]
result = subprocess.run(validation, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
if result.returncode:
    fail(result.stderr.strip() or "Linux UAPI completed validation failed")
if linux_receipt.get("recipe_sha256") != orchestration_blob_sha256(
    linux_receipt, "scripts/install-linux-headers.sh"
):
    fail("Linux UAPI receipt recipe hash differs from its orchestration blob")

values = (
    linux_build_id, str(linux_snapshot), str(linux_receipt_path),
    sha256(linux_receipt_path), linux_digest,
    linux_receipt.get("orchestration_commit", ""),
    linux_receipt.get("orchestration_tree", ""),
    linux_receipt.get("recipe_sha256", ""),
    str(gcc_build_id), str(gcc_prefix), str(gcc_receipt_path),
    sha256(gcc_receipt_path), gcc_receipt.get("orchestration_commit", ""),
    gcc_receipt.get("orchestration_tree", ""),
    str(binutils_build_id), str(binutils_prefix), str(binutils_receipt_path),
    sha256(binutils_receipt_path), binutils_receipt.get("orchestration_commit", ""),
    binutils_receipt.get("orchestration_tree", ""),
)
if any(not isinstance(value, str) or not value or "\n" in value for value in values):
    fail("dependency chain contains invalid scalar metadata")
print(*values, sep="\n")
PY
}

if ! chain_output=$(resolve_chain); then
  echo "Linux/GCC/Binutils dependency-chain validation failed" >&2
  exit 111
fi
mapfile -t chain_values <<<"$chain_output"
if (( ${#chain_values[@]} != 20 )); then
  echo "Dependency-chain verifier returned incomplete metadata" >&2
  exit 112
fi
linux_build_id=${chain_values[0]}
base_snapshot=${chain_values[1]}
linux_receipt=${chain_values[2]}
linux_receipt_sha256=${chain_values[3]}
base_snapshot_digest=${chain_values[4]}
linux_orchestration_commit=${chain_values[5]}
linux_orchestration_tree=${chain_values[6]}
linux_recipe_sha256=${chain_values[7]}
gcc_build_id=${chain_values[8]}
gcc_prefix=${chain_values[9]}
gcc_receipt=${chain_values[10]}
gcc_receipt_sha256=${chain_values[11]}
gcc_orchestration_commit=${chain_values[12]}
gcc_orchestration_tree=${chain_values[13]}
binutils_build_id=${chain_values[14]}
binutils_prefix=${chain_values[15]}
binutils_receipt=${chain_values[16]}
binutils_receipt_sha256=${chain_values[17]}
binutils_orchestration_commit=${chain_values[18]}
binutils_orchestration_tree=${chain_values[19]}
for dependency_pair in \
  "$linux_orchestration_commit:$linux_orchestration_tree" \
  "$gcc_orchestration_commit:$gcc_orchestration_tree" \
  "$binutils_orchestration_commit:$binutils_orchestration_tree"; do
  dependency_commit=${dependency_pair%%:*}
  dependency_tree=${dependency_pair#*:}
  if [[ $(git -C "$project_root" rev-parse "$dependency_commit^{tree}") != "$dependency_tree" ]]; then
    echo "Dependency orchestration commit/tree is unavailable or inconsistent" >&2
    exit 133
  fi
done

build_triplet=$("$glibc_source_dir/scripts/config.guess")
[[ -n $build_triplet && $build_triplet != "$target" && $build_triplet != *$'\n'* ]] || {
  echo "Unable to establish true build/host cross mode" >&2
  exit 113
}
cross_gcc=$gcc_prefix/bin/$target-gcc
cross_ar=$binutils_prefix/bin/$target-ar
cross_as=$binutils_prefix/bin/$target-as
cross_ld=$binutils_prefix/bin/$target-ld
cross_nm=$binutils_prefix/bin/$target-nm
cross_objcopy=$binutils_prefix/bin/$target-objcopy
cross_objdump=$binutils_prefix/bin/$target-objdump
cross_ranlib=$binutils_prefix/bin/$target-ranlib
cross_readelf=$binutils_prefix/bin/$target-readelf
cross_strip=$binutils_prefix/bin/$target-strip

configure_options=(
  "--prefix=/usr"
  "--build=$build_triplet"
  "--host=$target"
  "--with-binutils=$binutils_prefix/bin"
  "--with-headers=<candidate>/usr/include"
  "--enable-kernel=$minimum_kernel"
  "--disable-werror"
  "--disable-static-c++-tests"
  "--disable-static-c++-link-check"
  "--disable-build-nscd"
  "CC=$cross_gcc --sysroot=<candidate>"
  "CXX=false"
  "BUILD_CC=/usr/bin/gcc"
  "AR=$cross_ar"
  "AS=$cross_as"
  "LD=$cross_ld"
  "NM=$cross_nm"
  "OBJCOPY=$cross_objcopy"
  "OBJDUMP=$cross_objdump"
  "RANLIB=$cross_ranlib"
  "READELF=$cross_readelf"
  "STRIP=$cross_strip"
  "CFLAGS=$target_cflags"
  "libc_cv_slibdir=/usr/lib"
  "libc_cv_rtlddir=/usr/lib"
  "install-target=install-headers"
  "build-target=csu/subdir_lib"
  "stubs-selector=upstream-absolute-install-target"
  "stubs-64=sed-delete-template-directives"
  "lib-names-64=build-output-copy"
  "independent-builds=2"
  "sysroot-layout=immutable-snapshots-v1"
)
options_digest=$(printf '%s\0' "${configure_options[@]}" | sha256sum | awk '{print $1}')
recipe_sha256=$(sha256sum "$script_path" | awk '{print $1}')
helper_sha256=$(sha256sum "$inventory_helper" | awk '{print $1}')
stubs_prologue_sha256=$(sha256sum "$glibc_source_dir/include/stubs-prologue.h" | awk '{print $1}')
build_id=$("$script_path" --internal-python build-id "$locked_glibc_commit" \
  source_set_digest "$source_set_digest" \
  source_authentication "$source_authentication" \
  source_commit "$locked_glibc_commit" \
  source_tree "$locked_glibc_tree" \
  source_repository "$glibc_repository" \
  source_date_epoch "$SOURCE_DATE_EPOCH" \
  target "$target" arch "$arch" minimum_kernel "$minimum_kernel" \
  build_triplet "$build_triplet" \
  orchestration_commit "$orchestration_commit" \
  orchestration_tree "$orchestration_tree" \
  recipe_sha256 "$recipe_sha256" helper_sha256 "$helper_sha256" \
  stubs_prologue_sha256 "$stubs_prologue_sha256" \
  options_digest "$options_digest" \
  base_build_id "$linux_build_id" base_receipt_sha256 "$linux_receipt_sha256" \
  base_snapshot_digest "$base_snapshot_digest" \
  gcc_build_id "$gcc_build_id" gcc_receipt_sha256 "$gcc_receipt_sha256" \
  binutils_build_id "$binutils_build_id" \
  binutils_receipt_sha256 "$binutils_receipt_sha256")

run_id=${CAJUNOS_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
if [[ ! $run_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "Unsafe CAJUNOS_RUN_ID: $run_id" >&2
  exit 114
fi

build_final=$work_root/$build_id
snapshot_final=$snapshots_root/$build_id
artifact_final=$artifacts_root/$build_id
receipt_final=$artifact_final/receipt.json
log_dir=$logs_root/$run_id
log_file=$log_dir/glibc-headers-startfiles.log
temporary_root=$work_root/.tmp-$build_id-$$
build_a=$temporary_root/build-a
build_b=$temporary_root/build-b
candidate_b=$temporary_root/candidate-b
snapshot_temporary=$snapshots_root/.tmp-$build_id-$$
artifact_temporary=$artifacts_root/.tmp-$build_id-$$

validate_completed() {
  local receipt_path=${1:-$receipt_final}
  local actual_snapshot=${2:-$snapshot_final}
  "$script_path" --internal-python validate-completed \
    "$receipt_path" "$actual_snapshot" "$base_snapshot" \
    schema 1 build_id "$build_id" component glibc stage headers-startfiles \
    source_commit "$locked_glibc_commit" source_tree "$locked_glibc_tree" \
    source_repository "$glibc_repository" glibc_version 2.44.9000 \
    source_set_digest "$source_set_digest" \
    source_authentication "$source_authentication" \
    source_date_epoch "$SOURCE_DATE_EPOCH" target "$target" arch "$arch" \
    minimum_kernel "$minimum_kernel" build_triplet "$build_triplet" \
    target_cflags "$target_cflags" \
    sysroot "$sysroot" sysroot_contract immutable-snapshots-v1 \
    snapshot "$snapshot_final" base_build_id "$linux_build_id" \
    base_snapshot "$base_snapshot" base_snapshot_digest "$base_snapshot_digest" \
    orchestration_commit "$orchestration_commit" \
    orchestration_tree "$orchestration_tree" recipe_sha256 "$recipe_sha256" \
    inventory_helper_sha256 "$helper_sha256" options_digest "$options_digest" \
    generation.headers 'make install-headers install_root=<candidate>' \
    generation.csu 'make csu/subdir_lib' \
    generation.stubs_selector 'make -j1 install_root=<candidate> <candidate>/usr/include/gnu/stubs.h' \
    generation.stubs_64 "sed '/^@/d' glibc/include/stubs-prologue.h" \
    generation.stubs_prologue_sha256 "$stubs_prologue_sha256" \
    generation.lib_names_64 'install build/gnu/lib-names-64.h' \
    dependencies.linux.build_id "$linux_build_id" \
    dependencies.linux.receipt "$linux_receipt" \
    dependencies.linux.receipt_sha256 "$linux_receipt_sha256" \
    dependencies.linux.snapshot "$base_snapshot" \
    dependencies.linux.snapshot_digest "$base_snapshot_digest" \
    dependencies.linux.source_commit "$locked_linux_commit" \
    dependencies.linux.source_tree "$locked_linux_tree" \
    dependencies.linux.source_repository "$linux_repository" \
    dependencies.linux.orchestration_commit "$linux_orchestration_commit" \
    dependencies.linux.orchestration_tree "$linux_orchestration_tree" \
    dependencies.linux.recipe_sha256 "$linux_recipe_sha256" \
    dependencies.gcc.build_id "$gcc_build_id" \
    dependencies.gcc.prefix "$gcc_prefix" \
    dependencies.gcc.receipt "$gcc_receipt" \
    dependencies.gcc.receipt_sha256 "$gcc_receipt_sha256" \
    dependencies.gcc.source_commit "$locked_gcc_commit" \
    dependencies.gcc.source_tree "$locked_gcc_tree" \
    dependencies.gcc.source_repository "$gcc_repository" \
    dependencies.gcc.orchestration_commit "$gcc_orchestration_commit" \
    dependencies.gcc.orchestration_tree "$gcc_orchestration_tree" \
    dependencies.binutils.build_id "$binutils_build_id" \
    dependencies.binutils.prefix "$binutils_prefix" \
    dependencies.binutils.receipt "$binutils_receipt" \
    dependencies.binutils.receipt_sha256 "$binutils_receipt_sha256" \
    dependencies.binutils.source_commit "$locked_binutils_commit" \
    dependencies.binutils.source_tree "$locked_binutils_tree" \
    dependencies.binutils.source_repository "$binutils_repository" \
    dependencies.binutils.orchestration_commit "$binutils_orchestration_commit" \
    dependencies.binutils.orchestration_tree "$binutils_orchestration_tree" \
    functional_libc absent \
    probe_contract.header_compile freestanding-nostdinc-compile-only \
    probe_contract.header_search exact-candidate-include-only \
    probe_contract.crt_lookup exact-candidate-usr-lib \
    probe_contract.objects ELF64-REL-x86-64-noexecstack \
    probe_contract.executable_link not-attempted-or-claimed
}

if [[ -d $build_final && -d $snapshot_final && -f $receipt_final ]]; then
  validate_completed
  transition=$("$script_path" --internal-python selector-transition \
    "$sysroot" "$linux_build_id" "$build_id")
  echo "CAJUNOS_GLIBC_HEADERS_STARTFILES_ALREADY_COMPLETE build_id=$build_id selector=$transition"
  exit 0
fi
if [[ -e $build_final || -e $snapshot_final || -e $artifact_final ]]; then
  echo "Refusing to reuse an incomplete published glibc bootstrap build: $build_id" >&2
  exit 115
fi
if [[ -e $temporary_root || -e $snapshot_temporary || -e $artifact_temporary || -e $log_dir ]]; then
  echo "Refusing colliding temporary or log path for run $run_id" >&2
  exit 116
fi
selector_state=$("$script_path" --internal-python selector-state \
  "$sysroot" "$linux_build_id" "$build_id")
if [[ $selector_state != base ]]; then
  echo "Fresh glibc bootstrap requires current to name the sealed Linux base" >&2
  exit 117
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
  fi
}
trap on_exit EXIT
"$script_path" --internal-python ensure-directories "$cajunos_root" \
  "work/sysroot/.tmp-$build_id-$$" \
  "work/sysroot/.tmp-$build_id-$$/build-a" \
  "work/sysroot/.tmp-$build_id-$$/build-b" \
  "work/sysroot/.tmp-$build_id-$$/candidate-b" \
  "sysroot/$cohort_id/snapshots/.tmp-$build_id-$$" \
  "artifacts/.tmp-$build_id-$$" "logs/$run_id"
exec > >(tee "$log_file") 2>&1

echo "CajunOS glibc headers and startup objects"
echo "build_id=$build_id"
echo "source=$locked_glibc_commit"
echo "source_repository=$glibc_repository"
echo "source_set=$source_set_digest"
echo "source_authentication=$source_authentication"
echo "orchestration=$orchestration_commit"
echo "recipe_sha256=$recipe_sha256"
echo "inventory_helper_sha256=$helper_sha256"
echo "options_digest=$options_digest"
echo "base_build_id=$linux_build_id"
echo "base_snapshot_digest=$base_snapshot_digest"
echo "gcc_build_id=$gcc_build_id"
echo "binutils_build_id=$binutils_build_id"
echo "build=$build_triplet"
echo "host=$target"
echo "minimum_kernel=$minimum_kernel"
echo "sysroot=$sysroot"
echo "snapshot=$snapshot_final"
echo "source_date_epoch=$SOURCE_DATE_EPOCH"

printf '%s\n' "${configure_options[@]}" > "$artifact_temporary/configure.options"
"$script_path" --internal-python inventory "$base_snapshot" > "$artifact_temporary/base-before.json"

# These are ordinary byte copies: rsync -a does not preserve hard links unless
# -H is requested, and no clone/reflink option is used.  The inode audit below
# proves each candidate is physically independent of the sealed base.
rsync -a --delete "$base_snapshot/" "$snapshot_temporary/"
rsync -a --delete "$base_snapshot/" "$candidate_b/"
"$script_path" --internal-python compare \
  "$base_snapshot" "$snapshot_temporary" "$artifact_temporary/base-copy-a.json"
"$script_path" --internal-python compare \
  "$base_snapshot" "$candidate_b" "$artifact_temporary/base-copy-b.json"
"$script_path" --internal-python no-shared-inodes "$base_snapshot" "$snapshot_temporary"
"$script_path" --internal-python no-shared-inodes "$base_snapshot" "$candidate_b"

configure_and_stage() {
  local build_dir=$1
  local candidate=$2
  local candidate_cc="$cross_gcc --sysroot=$candidate"
  local configured_cc="$candidate_cc -B$binutils_prefix/bin/"
  [[ $("$cross_gcc" --sysroot="$candidate" -print-sysroot) == "$candidate" ]] || {
    echo "Cross GCC rejected the candidate sysroot override" >&2
    return 1
  }
  env \
    CC="$candidate_cc" \
    CXX=false \
    BUILD_CC=/usr/bin/gcc \
    AR="$cross_ar" \
    AS="$cross_as" \
    LD="$cross_ld" \
    NM="$cross_nm" \
    OBJCOPY="$cross_objcopy" \
    OBJDUMP="$cross_objdump" \
    RANLIB="$cross_ranlib" \
    READELF="$cross_readelf" \
    STRIP="$cross_strip" \
    CFLAGS="$target_cflags" \
    libc_cv_slibdir=/usr/lib \
    libc_cv_rtlddir=/usr/lib \
    "$glibc_source_dir/configure" \
      --prefix=/usr \
      --build="$build_triplet" \
      --host="$target" \
      --with-headers="$candidate/usr/include" \
      --with-binutils="$binutils_prefix/bin" \
      --enable-kernel="$minimum_kernel" \
      --disable-werror \
      --disable-static-c++-tests \
      --disable-static-c++-link-check \
      --disable-build-nscd

  grep -Fxq 'cross-compiling = yes' "$build_dir/config.make" || {
    echo "glibc configure did not enter true cross-compilation mode" >&2
    return 1
  }
  grep -Fxq "CC = $configured_cc" "$build_dir/config.make" || {
    echo "glibc configure did not retain the sealed cross compiler" >&2
    return 1
  }
  if ! grep -Fxq 'CXX = ' "$build_dir/config.make" \
     || ! grep -Fxq 'ac_cv_env_CXX_value=false' "$build_dir/config.log"; then
    echo "glibc configure unexpectedly enabled a C++ compiler" >&2
    return 1
  fi

  make -C "$build_dir" -j"$jobs" install-headers install_root="$candidate"
  make -C "$build_dir" -j1 install_root="$candidate" \
    "$candidate/usr/include/gnu/stubs.h"
  sed '/^@/d' "$glibc_source_dir/include/stubs-prologue.h" \
    > "$candidate/usr/include/gnu/stubs-64.h"
  chmod 0644 "$candidate/usr/include/gnu/stubs-64.h"

  make -C "$build_dir" -j"$jobs" csu/subdir_lib
  install -d -m 0755 "$candidate/usr/lib" "$candidate/usr/include/gnu"
  for crt in crt1.o crti.o crtn.o; do
    install -m 0644 "$build_dir/csu/$crt" "$candidate/usr/lib/$crt"
  done
  install -m 0644 "$build_dir/gnu/lib-names-64.h" \
    "$candidate/usr/include/gnu/lib-names-64.h"
}

(
  cd "$build_a"
  configure_and_stage "$build_a" "$snapshot_temporary"
)
(
  cd "$build_b"
  configure_and_stage "$build_b" "$candidate_b"
)

for candidate in "$snapshot_temporary" "$candidate_b"; do
  for relative in \
    usr/include/features.h \
    usr/include/stdint.h \
    usr/include/gnu/lib-names.h \
    usr/include/gnu/lib-names-64.h \
    usr/include/gnu/stubs.h \
    usr/include/gnu/stubs-64.h \
    usr/lib/crt1.o usr/lib/crti.o usr/lib/crtn.o; do
    [[ -f $candidate/$relative ]] || {
      echo "glibc bootstrap candidate lacks $relative" >&2
      exit 118
    }
  done
  for header in \
    usr/include/gnu/lib-names.h usr/include/gnu/lib-names-64.h \
    usr/include/gnu/stubs.h usr/include/gnu/stubs-64.h; do
    [[ $(stat -c %a "$candidate/$header") == 644 ]] || {
      echo "Generated glibc header has an unexpected mode: $header" >&2
      exit 119
    }
  done
  grep -Fq '# include <gnu/stubs-64.h>' "$candidate/usr/include/gnu/stubs.h"
  grep -Fq '# include <gnu/stubs-32.h>' "$candidate/usr/include/gnu/stubs.h"
  grep -Fq '# include <gnu/stubs-x32.h>' "$candidate/usr/include/gnu/stubs.h"
  if grep -q '^@' "$candidate/usr/include/gnu/stubs-64.h"; then
    echo "Generated stubs-64.h retains template directives" >&2
    exit 120
  fi
done

"$script_path" --internal-python derived-delta \
  "$base_snapshot" "$snapshot_temporary" "$artifact_temporary/delta-a.json"
"$script_path" --internal-python derived-delta \
  "$base_snapshot" "$candidate_b" "$artifact_temporary/delta-b.json"
cmp -s "$artifact_temporary/delta-a.json" "$artifact_temporary/delta-b.json" || {
  echo "Independent glibc bootstrap deltas differ" >&2
  exit 121
}
"$script_path" --internal-python compare \
  "$snapshot_temporary" "$candidate_b" "$artifact_temporary/inventory.json"
result_snapshot_digest=$(python3 -c \
  'import json,sys; print("sha256:" + json.load(open(sys.argv[1], encoding="utf-8"))["digest"])' \
  "$artifact_temporary/inventory.json")

# Confirm the immutable Linux base itself never changed during either build.
"$script_path" --internal-python inventory "$base_snapshot" > "$artifact_temporary/base-after.json"
cmp -s "$artifact_temporary/base-before.json" "$artifact_temporary/base-after.json" || {
  echo "Sealed Linux UAPI base changed during the glibc build" >&2
  exit 122
}

probe_dir=$artifact_temporary/probe
mkdir -p "$probe_dir"
cat > "$probe_dir/glibc-headers.c" <<'EOF'
#include <features.h>
#include <stdint.h>
#include <gnu/lib-names.h>
#include <gnu/stubs.h>
#include <linux/types.h>

_Static_assert(sizeof(uint64_t) == 8, "glibc uint64_t ABI");
_Static_assert(sizeof(__u64) == 8, "Linux __u64 ABI");

int cajunos_glibc_headers_probe(uint64_t left, __u64 right)
{
    return (int)(left + right);
}
EOF

"$cross_gcc" --sysroot="$snapshot_temporary" \
  -std=c11 -Wall -Werror -ffreestanding -nostdinc \
  -isystem "$snapshot_temporary/usr/include" \
  -E -v "$probe_dir/glibc-headers.c" -o "$probe_dir/glibc-headers.i" \
  2> "$probe_dir/header-search.txt"
python3 - "$probe_dir/header-search.txt" "$snapshot_temporary/usr/include" <<'PY'
import sys

lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
try:
    start = lines.index('#include <...> search starts here:') + 1
    end = lines.index('End of search list.', start)
except ValueError:
    raise SystemExit("compiler did not emit a parseable header search list")
paths = [line.strip() for line in lines[start:end] if line.strip()]
if paths != [sys.argv[2]]:
    raise SystemExit(f"host header search leak or unexpected search path: {paths}")
PY
"$cross_gcc" --sysroot="$snapshot_temporary" \
  -std=c11 -Wall -Werror -ffreestanding -nostdinc \
  -isystem "$snapshot_temporary/usr/include" \
  -c "$probe_dir/glibc-headers.c" -o "$probe_dir/glibc-headers.o"
"$cross_readelf" -h "$probe_dir/glibc-headers.o" > "$probe_dir/glibc-headers.readelf-h"
grep -q 'Class:.*ELF64' "$probe_dir/glibc-headers.readelf-h"
grep -q 'Type:.*REL' "$probe_dir/glibc-headers.readelf-h"
grep -q 'Machine:.*Advanced Micro Devices X86-64' "$probe_dir/glibc-headers.readelf-h"

: > "$probe_dir/crt-lookups.txt"
for crt in crt1.o crti.o crtn.o; do
  lookup=$("$cross_gcc" --sysroot="$snapshot_temporary" -print-file-name="$crt")
  expected=$snapshot_temporary/usr/lib/$crt
  [[ $(readlink -f -- "$lookup") == $(readlink -f -- "$expected") ]] || {
    echo "GCC did not resolve $crt from the candidate sysroot" >&2
    exit 123
  }
  printf '%s %s\n' "$crt" "$lookup" >> "$probe_dir/crt-lookups.txt"
  "$cross_readelf" -h "$expected" > "$probe_dir/$crt.readelf-h"
  "$cross_readelf" -SW "$expected" > "$probe_dir/$crt.readelf-SW"
  "$cross_readelf" -sW "$expected" > "$probe_dir/$crt.readelf-sW"
  grep -q 'Class:.*ELF64' "$probe_dir/$crt.readelf-h"
  grep -q 'Type:.*REL' "$probe_dir/$crt.readelf-h"
  grep -q 'Machine:.*Advanced Micro Devices X86-64' "$probe_dir/$crt.readelf-h"
  stack_line=$(grep '\.note.GNU-stack' "$probe_dir/$crt.readelf-SW")
  [[ -n $stack_line && $stack_line != *' X '* && $stack_line != *' AX '* ]] || {
    echo "$crt lacks a non-executable GNU-stack note" >&2
    exit 124
  }
done
grep -Eq '[[:space:]]_start$' "$probe_dir/crt1.o.readelf-sW"
for crt in crti.o crtn.o; do
  grep -q '[[:space:]]\.init[[:space:]]' "$probe_dir/$crt.readelf-SW"
  grep -q '[[:space:]]\.fini[[:space:]]' "$probe_dir/$crt.readelf-SW"
done
grep -Eq '[[:space:]]_init$' "$probe_dir/crti.o.readelf-sW"
grep -Eq '[[:space:]]_fini$' "$probe_dir/crti.o.readelf-sW"
printf '%s\n' 'compile-only; no executable link attempted or claimed' \
  > "$probe_dir/link-contract.txt"

"$script_path" --internal-python compare \
  "$snapshot_temporary" "$candidate_b" "$artifact_temporary/inventory-after-probe.json"
cmp -s "$artifact_temporary/inventory.json" "$artifact_temporary/inventory-after-probe.json" || {
  echo "glibc bootstrap snapshot changed while running probes" >&2
  exit 125
}

configuration_dir=$artifact_temporary/configuration
mkdir -p "$configuration_dir/build-a" "$configuration_dir/build-b"
for name in config.log config.status config.make; do
  install -m 0644 "$build_a/$name" "$configuration_dir/build-a/$name"
  install -m 0644 "$build_b/$name" "$configuration_dir/build-b/$name"
done
license_dir=$artifact_temporary/licenses/glibc
mkdir -p "$license_dir"
git -C "$glibc_source_dir" archive "$locked_glibc_commit" -- "${license_paths[@]}" |
  tar -x -C "$license_dir"
"$script_path" --internal-python inventory "$license_dir" \
  > "$artifact_temporary/license-inventory.json"

# Close every mutable-input window while both locks remain held.  This repeats
# full prefix inventories and receipt hashes, verifies the base byte-for-byte,
# and requires that the selector still names that base.
"$project_root/scripts/fetch.py" validate --root "$cajunos_root"
if ! final_chain_output=$(resolve_chain); then
  echo "Dependency-chain revalidation failed" >&2
  exit 126
fi
if [[ $final_chain_output != "$chain_output" ]]; then
  echo "Dependency provenance changed during the glibc bootstrap" >&2
  exit 127
fi
if [[ -n $(git -C "$project_root" status --porcelain) \
   || $(git -C "$project_root" rev-parse HEAD) != "$orchestration_commit" \
   || $(git -C "$project_root" rev-parse 'HEAD^{tree}') != "$orchestration_tree" ]]; then
  echo "CajunOS orchestration changed during the glibc bootstrap" >&2
  exit 128
fi
"$script_path" --internal-python inventory "$base_snapshot" > "$artifact_temporary/base-final.json"
cmp -s "$artifact_temporary/base-before.json" "$artifact_temporary/base-final.json" || {
  echo "Sealed Linux UAPI base changed before publication" >&2
  exit 129
}
selector_state=$("$script_path" --internal-python selector-state \
  "$sysroot" "$linux_build_id" "$build_id")
[[ $selector_state == base ]] || {
  echo "Cohort selector changed before glibc publication" >&2
  exit 130
}

python3 - \
  "$artifact_temporary/receipt.json" \
  "$artifact_temporary/inventory.json" \
  "$artifact_temporary/delta-a.json" \
  "$artifact_temporary/configure.options" \
  "$artifact_temporary/license-inventory.json" \
  "$build_id" "$locked_glibc_commit" "$locked_glibc_tree" \
  "$glibc_repository" "$source_set_digest" "$source_authentication" \
  "$SOURCE_DATE_EPOCH" "$target" "$arch" "$minimum_kernel" \
  "$build_triplet" "$target_cflags" "$sysroot" "$snapshot_final" \
  "$linux_build_id" "$base_snapshot" "$base_snapshot_digest" \
  "$result_snapshot_digest" "$orchestration_commit" "$orchestration_tree" \
  "$recipe_sha256" "$helper_sha256" "$options_digest" \
  "$linux_receipt" "$linux_receipt_sha256" "$locked_linux_commit" \
  "$locked_linux_tree" "$linux_repository" "$linux_orchestration_commit" \
  "$linux_orchestration_tree" "$linux_recipe_sha256" \
  "$gcc_build_id" "$gcc_prefix" "$gcc_receipt" "$gcc_receipt_sha256" \
  "$locked_gcc_commit" "$locked_gcc_tree" "$gcc_repository" \
  "$gcc_orchestration_commit" "$gcc_orchestration_tree" \
  "$binutils_build_id" "$binutils_prefix" "$binutils_receipt" \
  "$binutils_receipt_sha256" "$locked_binutils_commit" \
  "$locked_binutils_tree" "$binutils_repository" \
  "$binutils_orchestration_commit" "$binutils_orchestration_tree" \
  "$probe_dir" "$license_dir" "$configuration_dir" "$snapshot_temporary" \
  "$log_file" "$glibc_source_dir/include/stubs-prologue.h" <<'PY'
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
    output_value, inventory_value, delta_value, options_value,
    license_inventory_value, build_id,
    source_commit, source_tree, source_repository, source_set_digest,
    source_authentication, source_date_epoch, target, arch, minimum_kernel,
    build_triplet, target_cflags, sysroot, snapshot, linux_build_id,
    base_snapshot, base_snapshot_digest, result_snapshot_digest,
    orchestration_commit, orchestration_tree, recipe_sha256, helper_sha256,
    options_digest, linux_receipt, linux_receipt_sha256, linux_source_commit,
    linux_source_tree, linux_source_repository, linux_orchestration_commit,
    linux_orchestration_tree, linux_recipe_sha256, gcc_build_id, gcc_prefix,
    gcc_receipt, gcc_receipt_sha256, gcc_source_commit, gcc_source_tree,
    gcc_source_repository, gcc_orchestration_commit, gcc_orchestration_tree,
    binutils_build_id, binutils_prefix, binutils_receipt,
    binutils_receipt_sha256, binutils_source_commit, binutils_source_tree,
    binutils_source_repository, binutils_orchestration_commit,
    binutils_orchestration_tree, probe_value, license_value,
    configuration_value, candidate_value, log_file, stubs_prologue_value,
) = sys.argv[1:]

output = Path(output_value)
probe_dir = Path(probe_value)
license_dir = Path(license_value)
configuration_dir = Path(configuration_value)
candidate = Path(candidate_value)

def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def regular_hashes(root):
    root = Path(root)
    return {
        path.relative_to(root).as_posix(): sha256(path)
        for path in sorted(root.rglob("*")) if path.is_file()
    }

def first_line(*argv):
    return subprocess.run(
        argv, check=True, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ).stdout.splitlines()[0]

with Path(inventory_value).open(encoding="utf-8") as stream:
    installed = json.load(stream)
with Path(delta_value).open(encoding="utf-8") as stream:
    delta = json.load(stream)
with Path(options_value).open(encoding="utf-8") as stream:
    options = stream.read().splitlines()
with Path(license_inventory_value).open(encoding="utf-8") as stream:
    license_inventory = json.load(stream)

generated_paths = (
    "gnu/lib-names.h", "gnu/lib-names-64.h", "gnu/stubs.h", "gnu/stubs-64.h",
)
generated_hashes = {
    relative: sha256(candidate / "usr/include" / relative)
    for relative in generated_paths
}
crt_hashes = {
    name: sha256(candidate / "usr/lib" / name)
    for name in ("crt1.o", "crti.o", "crtn.o")
}
packages = {}
for package in ("make", "gcc", "rsync", "sed", "libc-bin"):
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Version}", package], check=False,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    packages[package] = result.stdout if result.returncode == 0 else None

receipt = {
    "schema": 1,
    "build_id": build_id,
    "component": "glibc",
    "stage": "headers-startfiles",
    "source_commit": source_commit,
    "source_tree": source_tree,
    "source_repository": source_repository,
    "glibc_version": "2.44.9000",
    "source_set_digest": source_set_digest,
    "source_authentication": source_authentication,
    "source_date_epoch": int(source_date_epoch),
    "target": target,
    "arch": arch,
    "minimum_kernel": minimum_kernel,
    "build_triplet": build_triplet,
    "target_cflags": target_cflags,
    "sysroot": sysroot,
    "sysroot_contract": "immutable-snapshots-v1",
    "snapshot": snapshot,
    "base_build_id": linux_build_id,
    "base_snapshot": base_snapshot,
    "base_snapshot_digest": base_snapshot_digest,
    "result_snapshot_digest": result_snapshot_digest,
    "functional_libc": "absent",
    "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    "log": log_file,
    "orchestration_commit": orchestration_commit,
    "orchestration_tree": orchestration_tree,
    "recipe_sha256": recipe_sha256,
    "inventory_helper_sha256": helper_sha256,
    "options_digest": options_digest,
    "configure_options": options,
    "generation": {
        "headers": "make install-headers install_root=<candidate>",
        "csu": "make csu/subdir_lib",
        "stubs_selector": "make -j1 install_root=<candidate> <candidate>/usr/include/gnu/stubs.h",
        "stubs_64": "sed '/^@/d' glibc/include/stubs-prologue.h",
        "stubs_prologue_sha256": sha256(stubs_prologue_value),
        "lib_names_64": "install build/gnu/lib-names-64.h",
    },
    "reproducibility": {
        "independent_installations": 2,
        "inventory_schema": "paths-types-modes-sha256-symlink-targets-v1",
        "first_inventory_digest": result_snapshot_digest,
        "second_inventory_digest": result_snapshot_digest,
        "identical": True,
        "base_unchanged_after_build": True,
        "post_probe_inventory_digest": result_snapshot_digest,
    },
    "dependencies": {
        "linux": {
            "build_id": linux_build_id, "receipt": linux_receipt,
            "receipt_sha256": linux_receipt_sha256, "snapshot": base_snapshot,
            "snapshot_digest": base_snapshot_digest,
            "source_commit": linux_source_commit, "source_tree": linux_source_tree,
            "source_repository": linux_source_repository,
            "orchestration_commit": linux_orchestration_commit,
            "orchestration_tree": linux_orchestration_tree,
            "recipe_sha256": linux_recipe_sha256,
        },
        "gcc": {
            "build_id": gcc_build_id, "prefix": gcc_prefix,
            "receipt": gcc_receipt, "receipt_sha256": gcc_receipt_sha256,
            "source_commit": gcc_source_commit, "source_tree": gcc_source_tree,
            "source_repository": gcc_source_repository,
            "orchestration_commit": gcc_orchestration_commit,
            "orchestration_tree": gcc_orchestration_tree,
        },
        "binutils": {
            "build_id": binutils_build_id, "prefix": binutils_prefix,
            "receipt": binutils_receipt,
            "receipt_sha256": binutils_receipt_sha256,
            "source_commit": binutils_source_commit,
            "source_tree": binutils_source_tree,
            "source_repository": binutils_source_repository,
            "orchestration_commit": binutils_orchestration_commit,
            "orchestration_tree": binutils_orchestration_tree,
        },
    },
    "delta": delta,
    "installed_entries": installed["entries"],
    "generated_header_sha256": generated_hashes,
    "crt_sha256": crt_hashes,
    "configuration_sha256": regular_hashes(configuration_dir),
    "license_inventory": license_inventory,
    "outputs": {"probe_sha256": regular_hashes(probe_dir)},
    "probe_contract": {
        "header_compile": "freestanding-nostdinc-compile-only",
        "header_search": "exact-candidate-include-only",
        "crt_lookup": "exact-candidate-usr-lib",
        "objects": "ELF64-REL-x86-64-noexecstack",
        "executable_link": "not-attempted-or-claimed",
    },
    "host": {
        "platform": platform.platform(),
        "make": first_line("/usr/bin/make", "--version"),
        "gcc": first_line("/usr/bin/gcc", "--version"),
        "rsync": first_line("/usr/bin/rsync", "--version"),
        "sed": first_line("/usr/bin/sed", "--version"),
        "packages": packages,
    },
}

fd, temporary = tempfile.mkstemp(prefix=".receipt.", dir=output.parent, text=True)
with os.fdopen(fd, "w", encoding="utf-8") as stream:
    json.dump(receipt, stream, indent=2, sort_keys=True)
    stream.write("\n")
os.replace(temporary, output)
output.chmod(0o644)
PY

validate_completed "$artifact_temporary/receipt.json" "$snapshot_temporary"

"$script_path" --internal-python validate-directories "$cajunos_root" \
  work work/sysroot tools artifacts logs sysroot \
  "sysroot/$cohort_id" "sysroot/$cohort_id/snapshots" \
  "work/sysroot/.tmp-$build_id-$$" \
  "sysroot/$cohort_id/snapshots/.tmp-$build_id-$$" \
  "artifacts/.tmp-$build_id-$$"
mv -T -- "$snapshot_temporary" "$snapshot_final"
mv -T -- "$temporary_root" "$build_final"
mv -T -- "$artifact_temporary" "$artifact_final"
transition=$("$script_path" --internal-python selector-transition \
  "$sysroot" "$linux_build_id" "$build_id")
[[ $transition == advanced ]] || {
  echo "Published glibc snapshot did not advance from its sealed base" >&2
  exit 131
}

validate_completed
selector_state=$("$script_path" --internal-python selector-state \
  "$sysroot" "$linux_build_id" "$build_id")
[[ $selector_state == this ]] || {
  echo "Published glibc bootstrap snapshot is not current" >&2
  exit 132
}

build_succeeded=1
trap - EXIT
echo "CAJUNOS_GLIBC_HEADERS_STARTFILES_OK build_id=$build_id snapshot=$snapshot_final"
