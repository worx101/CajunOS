#!/usr/bin/env bash
set -Eeuo pipefail
umask 022
export LC_ALL=C
export TZ=UTC
export PATH=/usr/bin:/bin

for variable in \
  CC CXX CPP CFLAGS CXXFLAGS CPPFLAGS LDFLAGS \
  LIBRARY_PATH CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH \
  PKG_CONFIG_PATH CONFIG_SITE LD_LIBRARY_PATH GCC_EXEC_PREFIX COMPILER_PATH; do
  unset "$variable"
done

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cajunos_root=${CAJUNOS_ROOT:-/srv/cajunos}
target=${CAJUNOS_TARGET:-x86_64-cajunos-linux-gnu}
expected_user=${CAJUNOS_BUILD_USER:-cajunos}
lock_file=$project_root/locks/bootstrap.lock.json
manifest_file=$project_root/manifests/bootstrap.json

if [[ $(id -u) -eq 0 || $(id -un) != "$expected_user" ]]; then
  echo "Run this build as the unprivileged $expected_user account" >&2
  exit 20
fi

# First validate the requested root before opening a lock beneath it. Then hold
# the source lock from the authoritative validation through final publication,
# preventing sync/update-lock from changing a checkout during compilation.
"$project_root/scripts/fetch.py" validate --root "$cajunos_root" --json >/dev/null
cajunos_root=$(readlink -f -- "$cajunos_root")
exec 8>"$cajunos_root/upstream/.cajunos-source.lock"
if ! flock -n 8; then
  echo "Another CajunOS source operation or build owns the source lock" >&2
  exit 31
fi

# This validates the manifest, its digest, the source-set digest, every locked
# commit/tree/origin, declared license paths, and all managed path boundaries.
"$project_root/scripts/fetch.py" validate --root "$cajunos_root"
source_dir=$cajunos_root/upstream/binutils

mapfile -t lock_values < <(python3 - "$lock_file" "$manifest_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    lock = json.load(stream)
with open(sys.argv[2], encoding="utf-8") as stream:
    manifest = json.load(stream)
print(lock["source_set_digest"])
print(lock["source_authentication"])
for component in lock["components"]:
    if component["name"] == "binutils":
        print(component["commit"])
        print(component["tree"])
        print(component["repository"])
        break
else:
    raise SystemExit("binutils is absent from the bootstrap lock")
for component in manifest["components"]:
    if component["name"] == "binutils":
        print(*component["license_files"], sep="\n")
        break
PY
)
source_set_digest=${lock_values[0]}
source_authentication=${lock_values[1]}
locked_commit=${lock_values[2]}
locked_tree=${lock_values[3]}
source_repository=${lock_values[4]}
license_paths=("${lock_values[@]:5}")

if [[ $source_authentication != authenticated ]]; then
  if [[ ${CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES:-} != 1 ]]; then
    echo "This source set contains recorded unauthenticated transports." >&2
    echo "Review locks/bootstrap.lock.json, then explicitly set" >&2
    echo "CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES=1 to accept that risk." >&2
    exit 30
  fi
  echo "WARNING: explicitly accepting the lock's recorded unauthenticated transports" >&2
fi

if [[ -n $(git -C "$project_root" status --porcelain) ]]; then
  echo "Refusing an official build from a dirty CajunOS orchestration checkout" >&2
  exit 21
fi
orchestration_commit=$(git -C "$project_root" rev-parse HEAD)
orchestration_tree=$(git -C "$project_root" rev-parse 'HEAD^{tree}')

canonical_target=$("$source_dir/config.sub" "$target")
if [[ $canonical_target != "$target" ]]; then
  echo "Unexpected canonical target: $canonical_target" >&2
  exit 22
fi
build_triplet=$("$source_dir/config.guess")

jobs=${CAJUNOS_JOBS:-6}
if [[ ! $jobs =~ ^[1-9][0-9]*$ ]]; then
  echo "CAJUNOS_JOBS must be a positive integer" >&2
  exit 23
fi
export MAKEFLAGS="-j$jobs"
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git -C "$source_dir" show -s --format=%ct "$locked_commit")

recipe_sha256=$(sha256sum "${BASH_SOURCE[0]}" | awk '{print $1}')
input_digest=$(printf '%s\n' \
  "$source_set_digest" \
  "$locked_commit" \
  "$locked_tree" \
  "$target" \
  "$orchestration_commit" \
  "$recipe_sha256" | sha256sum | awk '{print $1}')
build_id=binutils-stage1-${locked_commit:0:12}-${input_digest:0:16}
cohort_id=${source_set_digest#sha256:}
cohort_id=${cohort_id:0:16}

run_id=${CAJUNOS_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
if [[ ! $run_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "Unsafe CAJUNOS_RUN_ID: $run_id" >&2
  exit 24
fi

work_root=$cajunos_root/work/toolchain
tools_root=$cajunos_root/tools
artifacts_root=$cajunos_root/artifacts
logs_root=$cajunos_root/logs
sysroot=$cajunos_root/sysroot/$cohort_id
build_final=$work_root/$build_id
prefix_final=$tools_root/$build_id
artifact_final=$artifacts_root/$build_id
receipt_final=$artifact_final/receipt.json
log_dir=$logs_root/$run_id
log_file=$log_dir/binutils-stage1.log
temporary_root=$work_root/.tmp-$build_id-$$
build_temporary=$temporary_root/build
stage_root=$temporary_root/stage
prefix_staged=$stage_root$prefix_final
artifact_temporary=$artifacts_root/.tmp-$build_id-$$

mkdir -p "$work_root" "$tools_root" "$artifacts_root" "$logs_root" "$sysroot"
exec 9>"$cajunos_root/work/.cajunos-build.lock"
if ! flock -n 9; then
  echo "Another CajunOS build owns $cajunos_root/work/.cajunos-build.lock" >&2
  exit 25
fi

publish_current_link() {
  local temporary_link=$tools_root/.current-$$
  [[ $temporary_link == "$tools_root"/.current-* ]] || return 1
  rm -f -- "$temporary_link"
  ln -s "$build_id" "$temporary_link"
  mv -Tf -- "$temporary_link" "$tools_root/current"
}

if [[ -d $build_final && -d $prefix_final && -f $receipt_final ]]; then
  python3 - "$receipt_final" "$prefix_final" "$build_id" "$locked_commit" "$target" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

receipt_path, prefix_value, build_id, commit, target = sys.argv[1:]
prefix = Path(prefix_value)

def tree_entries(root: Path) -> dict[str, dict[str, str]]:
    root_mode = root.lstat().st_mode
    if not stat.S_ISDIR(root_mode):
        raise SystemExit(f"installed prefix is not a directory: {root}")
    entries: dict[str, dict[str, str]] = {
        ".": {"type": "directory", "mode": f"{stat.S_IMODE(root_mode):04o}"}
    }

    def walk(directory: Path) -> None:
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda item: item.name)
        for child in children:
            path = Path(child.path)
            relative = str(path.relative_to(root))
            item_mode = f"{stat.S_IMODE(child.stat(follow_symlinks=False).st_mode):04o}"
            if child.is_symlink():
                entries[relative] = {
                    "type": "symlink",
                    "mode": item_mode,
                    "target": os.readlink(path),
                }
            elif child.is_dir(follow_symlinks=False):
                entries[relative] = {"type": "directory", "mode": item_mode}
                walk(path)
            elif child.is_file(follow_symlinks=False):
                with path.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                entries[relative] = {
                    "type": "file",
                    "mode": item_mode,
                    "sha256": digest,
                }
            else:
                raise SystemExit(f"unsupported installed entry: {relative}")

    walk(root)
    return entries

with open(receipt_path, encoding="utf-8") as stream:
    receipt = json.load(stream)
if receipt["build_id"] != build_id or receipt["source_commit"] != commit or receipt["target"] != target:
    raise SystemExit("completed receipt does not match requested build")
expected_entries = receipt.get("installed_entries")
if not isinstance(expected_entries, dict):
    raise SystemExit("completed receipt lacks a full installed-tree inventory")
actual_entries = tree_entries(prefix)
if actual_entries != expected_entries:
    missing = sorted(set(expected_entries) - set(actual_entries))
    unexpected = sorted(set(actual_entries) - set(expected_entries))
    changed = sorted(
        key for key in set(expected_entries) & set(actual_entries)
        if expected_entries[key] != actual_entries[key]
    )
    raise SystemExit(
        "installed tree mismatch: "
        f"missing={missing}, unexpected={unexpected}, changed={changed}"
    )
PY
  publish_current_link
  echo "CAJUNOS_BINUTILS_STAGE1_ALREADY_COMPLETE build_id=$build_id"
  exit 0
fi
if [[ -e $build_final || -e $prefix_final || -e $artifact_final ]]; then
  echo "Refusing to reuse an incomplete published build: $build_id" >&2
  exit 26
fi
if [[ -e $temporary_root || -e $artifact_temporary || -e $log_dir ]]; then
  echo "Refusing colliding temporary or log path for run $run_id" >&2
  exit 27
fi

mkdir -p "$build_temporary" "$stage_root" "$artifact_temporary" "$log_dir"
build_succeeded=0
on_exit() {
  local status=$?
  if (( status != 0 || build_succeeded == 0 )); then
    if [[ -d $temporary_root ]]; then
      mv -- "$temporary_root" "$work_root/.failed-$build_id-$$"
    fi
    if [[ -d $artifact_temporary ]]; then
      mv -- "$artifact_temporary" "$artifacts_root/.failed-$build_id-$$"
    fi
  fi
}
trap on_exit EXIT
exec > >(tee "$log_file") 2>&1

echo "CajunOS Binutils stage 1"
echo "build_id=$build_id"
echo "source=$locked_commit"
echo "source_repository=$source_repository"
echo "source_set=$source_set_digest"
echo "source_authentication=$source_authentication"
echo "orchestration=$orchestration_commit"
echo "recipe_sha256=$recipe_sha256"
echo "build_triplet=$build_triplet"
echo "target=$target"
echo "sysroot=$sysroot"
echo "prefix=$prefix_final"
echo "makeflags=$MAKEFLAGS"
echo "source_date_epoch=$SOURCE_DATE_EPOCH"

(
  cd "$build_temporary"
  "$source_dir/configure" \
    --build="$build_triplet" \
    --host="$build_triplet" \
    --target="$target" \
    --prefix="$prefix_final" \
    --with-sysroot="$sysroot" \
    --disable-nls \
    --disable-werror \
    --disable-gdb \
    --disable-gdbserver \
    --disable-gprofng \
    --disable-libdecnumber \
    --disable-readline \
    --disable-sim \
    --disable-multilib \
    --enable-default-hash-style=gnu \
    --enable-new-dtags
)

make -C "$build_temporary"
make -j1 -C "$build_temporary" DESTDIR="$stage_root" install

assembler=$prefix_staged/bin/$target-as
linker=$prefix_staged/bin/$target-ld
readelf=$prefix_staged/bin/$target-readelf
for tool in "$assembler" "$linker" "$readelf"; do
  [[ -x $tool ]] || { echo "Missing staged cross-tool: $tool" >&2; exit 28; }
done

probe_dir=$artifact_temporary/probe
mkdir -p "$probe_dir"
cat > "$probe_dir/start.s" <<'EOF'
.global _start
.section .text
_start:
    xor %rdi, %rdi
    mov $60, %rax
    syscall
EOF
"$assembler" -o "$probe_dir/start.o" "$probe_dir/start.s"
"$linker" -o "$probe_dir/start" "$probe_dir/start.o"
file "$probe_dir/start"
"$readelf" -h "$probe_dir/start"
"$probe_dir/start"

license_dir=$artifact_temporary/licenses/binutils
mkdir -p "$license_dir"
git -C "$source_dir" archive "$locked_commit" -- "${license_paths[@]}" |
  tar -x -C "$license_dir"

python3 - \
  "$artifact_temporary/receipt.json" \
  "$build_id" \
  "$locked_commit" \
  "$locked_tree" \
  "$source_set_digest" \
  "$source_authentication" \
  "$target" \
  "$log_file" \
  "$prefix_final" \
  "$prefix_staged" \
  "$sysroot" \
  "$orchestration_commit" \
  "$orchestration_tree" \
  "$recipe_sha256" \
  "$probe_dir/start" \
  "$build_temporary/config.log" \
  "$license_dir" \
  "$SOURCE_DATE_EPOCH" <<'PY'
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import tempfile

(
    output,
    build_id,
    commit,
    tree,
    source_set_digest,
    source_authentication,
    target,
    log_file,
    prefix_final,
    prefix_staged_value,
    sysroot,
    orchestration_commit,
    orchestration_tree,
    recipe_sha256,
    probe_value,
    config_log_value,
    license_dir_value,
    source_date_epoch,
) = sys.argv[1:]

prefix_staged = Path(prefix_staged_value)
probe = Path(probe_value)
config_log = Path(config_log_value)
license_dir = Path(license_dir_value)

def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def first_line(*argv: str) -> str:
    return subprocess.run(
        argv, check=True, text=True, stdout=subprocess.PIPE
    ).stdout.splitlines()[0]

def tree_entries(root: Path) -> dict[str, dict[str, str]]:
    root_mode = root.lstat().st_mode
    if not stat.S_ISDIR(root_mode):
        raise SystemExit(f"installed prefix is not a directory: {root}")
    entries: dict[str, dict[str, str]] = {
        ".": {"type": "directory", "mode": f"{stat.S_IMODE(root_mode):04o}"}
    }

    def walk(directory: Path) -> None:
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda item: item.name)
        for child in children:
            path = Path(child.path)
            relative = str(path.relative_to(root))
            item_mode = f"{stat.S_IMODE(child.stat(follow_symlinks=False).st_mode):04o}"
            if child.is_symlink():
                entries[relative] = {
                    "type": "symlink",
                    "mode": item_mode,
                    "target": os.readlink(path),
                }
            elif child.is_dir(follow_symlinks=False):
                entries[relative] = {"type": "directory", "mode": item_mode}
                walk(path)
            elif child.is_file(follow_symlinks=False):
                entries[relative] = {
                    "type": "file",
                    "mode": item_mode,
                    "sha256": sha256(path),
                }
            else:
                raise SystemExit(f"unsupported installed entry: {relative}")

    walk(root)
    return entries

installed = tree_entries(prefix_staged)

licenses = {}
for path in sorted(license_dir.rglob("*")):
    if path.is_file():
        licenses[str(path.relative_to(license_dir))] = sha256(path)

packages = {}
for package in ("libgmp-dev", "libmpfr-dev", "libmpc-dev", "libisl-dev"):
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Version}", package],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    packages[package] = result.stdout if result.returncode == 0 else None

receipt = {
    "schema": 1,
    "build_id": build_id,
    "component": "binutils",
    "stage": "stage1",
    "source_commit": commit,
    "source_tree": tree,
    "source_set_digest": source_set_digest,
    "source_authentication": source_authentication,
    "source_date_epoch": int(source_date_epoch),
    "target": target,
    "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    "log": log_file,
    "prefix": prefix_final,
    "sysroot": sysroot,
    "orchestration_commit": orchestration_commit,
    "orchestration_tree": orchestration_tree,
    "recipe_sha256": recipe_sha256,
    "host": {
        "platform": platform.platform(),
        "gcc": first_line("gcc", "--version"),
        "make": first_line("make", "--version"),
        "packages": packages,
    },
    "installed_entries": installed,
    "license_sha256": licenses,
    "outputs": {
        "probe": "probe/start",
        "probe_sha256": sha256(probe),
        "config_log_sha256": sha256(config_log),
    },
}

output_path = Path(output)
fd, temporary = tempfile.mkstemp(prefix=".receipt.", dir=output_path.parent, text=True)
with os.fdopen(fd, "w", encoding="utf-8") as stream:
    json.dump(receipt, stream, indent=2, sort_keys=True)
    stream.write("\n")
os.replace(temporary, output_path)
output_path.chmod(0o644)
PY

mv -- "$prefix_staged" "$prefix_final"
mv -- "$build_temporary" "$build_final"
mv -- "$artifact_temporary" "$artifact_final"
publish_current_link

if [[ $temporary_root != "$work_root"/.tmp-$build_id-$$ ]]; then
  echo "Refusing to remove unexpected temporary path: $temporary_root" >&2
  exit 29
fi
rm -rf -- "$temporary_root"
build_succeeded=1
trap - EXIT
echo "CAJUNOS_BINUTILS_STAGE1_OK build_id=$build_id"
