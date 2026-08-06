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
requested_binutils_id=${CAJUNOS_BINUTILS_BUILD_ID:-}
lock_file=$project_root/locks/bootstrap.lock.json
manifest_file=$project_root/manifests/bootstrap.json

if [[ $(id -u) -eq 0 || $(id -un) != "$expected_user" ]]; then
  echo "Run this build as the unprivileged $expected_user account" >&2
  exit 40
fi

# Validate the requested root before opening a lock beneath it. The second
# validation is authoritative and occurs while the source lock is held.
"$project_root/scripts/fetch.py" validate --root "$cajunos_root" --json >/dev/null
cajunos_root=$(readlink -f -- "$cajunos_root")
exec 8>"$cajunos_root/upstream/.cajunos-source.lock"
if ! flock -n 8; then
  echo "Another CajunOS source operation or build owns the source lock" >&2
  exit 41
fi
"$project_root/scripts/fetch.py" validate --root "$cajunos_root"

source_dir=$cajunos_root/upstream/gcc
glibc_source_dir=$cajunos_root/upstream/glibc

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
    if component["name"] == "gcc":
        print(component["commit"])
        print(component["tree"])
        print(component["repository"])
        break
else:
    raise SystemExit("gcc is absent from the bootstrap lock")
for component in manifest["components"]:
    if component["name"] == "gcc":
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

mapfile -t locked_binutils_values < <(python3 - "$lock_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    lock = json.load(stream)
for component in lock["components"]:
    if component["name"] == "binutils":
        print(component["commit"])
        print(component["tree"])
        break
else:
    raise SystemExit("binutils is absent from the bootstrap lock")
PY
)
locked_binutils_commit=${locked_binutils_values[0]}
locked_binutils_tree=${locked_binutils_values[1]}

if [[ $source_authentication != authenticated ]]; then
  if [[ ${CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES:-} != 1 ]]; then
    echo "This source set contains recorded unauthenticated transports." >&2
    echo "Review locks/bootstrap.lock.json, then explicitly set" >&2
    echo "CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES=1 to accept that risk." >&2
    exit 42
  fi
  echo "WARNING: explicitly accepting the lock's recorded unauthenticated transports" >&2
fi

if [[ -n $(git -C "$project_root" status --porcelain) ]]; then
  echo "Refusing an official build from a dirty CajunOS orchestration checkout" >&2
  exit 43
fi
orchestration_commit=$(git -C "$project_root" rev-parse HEAD)
orchestration_tree=$(git -C "$project_root" rev-parse 'HEAD^{tree}')

canonical_target=$("$source_dir/config.sub" "$target")
if [[ $canonical_target != "$target" ]]; then
  echo "Unexpected canonical target: $canonical_target" >&2
  exit 44
fi
build_triplet=$("$source_dir/config.guess")

if ! grep -Eq '^#define VERSION "2\.44(\.|"$)' "$glibc_source_dir/version.h"; then
  echo "Locked glibc no longer matches the stage-one 2.44 ABI contract" >&2
  exit 45
fi
glibc_series=2.44

jobs=${CAJUNOS_JOBS:-6}
if [[ ! $jobs =~ ^[1-9][0-9]*$ ]]; then
  echo "CAJUNOS_JOBS must be a positive integer" >&2
  exit 46
fi
export MAKEFLAGS="-j$jobs"
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git -C "$source_dir" show -s --format=%ct "$locked_commit")

work_root=$cajunos_root/work/toolchain
tools_root=$cajunos_root/tools
artifacts_root=$cajunos_root/artifacts
logs_root=$cajunos_root/logs
cohort_id=${source_set_digest#sha256:}
cohort_id=${cohort_id:0:16}
sysroot=$cajunos_root/sysroot/$cohort_id

mkdir -p "$work_root" "$tools_root" "$artifacts_root" "$logs_root" "$sysroot"
exec 9>"$cajunos_root/work/.cajunos-build.lock"
if ! flock -n 9; then
  echo "Another CajunOS build owns $cajunos_root/work/.cajunos-build.lock" >&2
  exit 47
fi

# Find exactly one matching immutable Binutils stage-one receipt unless the
# caller supplies its build ID. The verifier recomputes the entire dependency
# prefix inventory, including modes and symlink targets.
mapfile -t binutils_values < <(python3 - \
  "$artifacts_root" \
  "$tools_root" \
  "$requested_binutils_id" \
  "$source_set_digest" \
  "$target" \
  "$locked_binutils_commit" \
  "$locked_binutils_tree" \
  "$source_authentication" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

artifacts_root = Path(sys.argv[1])
tools_root = Path(sys.argv[2])
requested = sys.argv[3]
source_set_digest = sys.argv[4]
target = sys.argv[5]
locked_commit = sys.argv[6]
locked_tree = sys.argv[7]
source_authentication = sys.argv[8]

def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def tree_entries(root: Path) -> dict[str, dict[str, str]]:
    root_mode = root.lstat().st_mode
    if not stat.S_ISDIR(root_mode):
        raise SystemExit(f"Binutils prefix is not a directory: {root}")
    entries: dict[str, dict[str, str]] = {
        ".": {"type": "directory", "mode": f"{stat.S_IMODE(root_mode):04o}"}
    }
    def walk(directory: Path) -> None:
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda item: item.name)
        for child in children:
            path = Path(child.path)
            relative = str(path.relative_to(root))
            mode = f"{stat.S_IMODE(child.stat(follow_symlinks=False).st_mode):04o}"
            if child.is_symlink():
                entries[relative] = {
                    "type": "symlink", "mode": mode, "target": os.readlink(path)
                }
            elif child.is_dir(follow_symlinks=False):
                entries[relative] = {"type": "directory", "mode": mode}
                walk(path)
            elif child.is_file(follow_symlinks=False):
                entries[relative] = {
                    "type": "file", "mode": mode, "sha256": sha256(path)
                }
            else:
                raise SystemExit(f"unsupported Binutils prefix entry: {relative}")
    walk(root)
    return entries

if requested:
    if not re.fullmatch(r"binutils-stage1-[A-Za-z0-9._-]+", requested):
        raise SystemExit("unsafe CAJUNOS_BINUTILS_BUILD_ID")
    paths = [artifacts_root / requested / "receipt.json"]
else:
    paths = sorted(artifacts_root.glob("binutils-stage1-*/receipt.json"))

candidates = []
for receipt_path in paths:
    if not receipt_path.is_file():
        continue
    with receipt_path.open(encoding="utf-8") as stream:
        receipt = json.load(stream)
    if (
        receipt.get("schema") == 1
        and receipt.get("component") == "binutils"
        and receipt.get("stage") == "stage1"
        and receipt.get("source_set_digest") == source_set_digest
        and receipt.get("source_authentication") == source_authentication
        and receipt.get("source_commit") == locked_commit
        and receipt.get("source_tree") == locked_tree
        and receipt.get("target") == target
    ):
        candidates.append((receipt_path, receipt))
if len(candidates) != 1:
    raise SystemExit(
        f"expected one matching Binutils stage-one receipt, found {len(candidates)}; "
        "set CAJUNOS_BINUTILS_BUILD_ID to disambiguate"
    )

receipt_path, receipt = candidates[0]
build_id = receipt.get("build_id")
if not isinstance(build_id, str) or receipt_path.parent.name != build_id:
    raise SystemExit("Binutils receipt/build directory mismatch")
prefix = tools_root / build_id
if receipt.get("prefix") != str(prefix):
    raise SystemExit("Binutils receipt prefix mismatch")
expected = receipt.get("installed_entries")
if not isinstance(expected, dict) or tree_entries(prefix) != expected:
    raise SystemExit("Binutils dependency prefix failed full inventory validation")
for relative in (
    f"bin/{target}-as",
    f"bin/{target}-ld",
    f"bin/{target}-readelf",
    f"{target}/bin/as",
    f"{target}/bin/ld",
):
    if not (prefix / relative).is_file():
        raise SystemExit(f"Binutils dependency lacks {relative}")

print(build_id)
print(prefix)
print(receipt_path)
print(sha256(receipt_path))
print(receipt.get("source_commit", ""))
print(receipt.get("source_tree", ""))
PY
)
binutils_build_id=${binutils_values[0]}
binutils_prefix=${binutils_values[1]}
binutils_receipt=${binutils_values[2]}
binutils_receipt_sha256=${binutils_values[3]}
binutils_source_commit=${binutils_values[4]}
binutils_source_tree=${binutils_values[5]}

configure_args=(
  "--build=$build_triplet"
  "--host=$build_triplet"
  "--target=$target"
  "--with-sysroot=$sysroot"
  "--with-native-system-header-dir=/usr/include"
  "--with-build-time-tools=$binutils_prefix/$target/bin"
  "--with-as=$binutils_prefix/bin/$target-as"
  "--with-ld=$binutils_prefix/bin/$target-ld"
  "--with-glibc-version=$glibc_series"
  "--with-arch=x86-64-v2"
  "--with-tune=generic"
  "--enable-languages=c"
  "--disable-bootstrap"
  "--disable-multilib"
  "--disable-shared"
  "--disable-threads"
  "--disable-nls"
  "--disable-werror"
  "--disable-lto"
  "--disable-fixincludes"
  "--without-headers"
  "--without-isl"
  "--without-zstd"
)
configure_digest=$(printf '%s\0' "${configure_args[@]}" | sha256sum | awk '{print $1}')
recipe_sha256=$(sha256sum "${BASH_SOURCE[0]}" | awk '{print $1}')
input_digest=$(printf '%s\n' \
  "$source_set_digest" \
  "$locked_commit" \
  "$locked_tree" \
  "$target" \
  "$orchestration_commit" \
  "$recipe_sha256" \
  "$configure_digest" \
  "$binutils_build_id" \
  "$binutils_receipt_sha256" | sha256sum | awk '{print $1}')
build_id=gcc-stage1-${locked_commit:0:12}-${input_digest:0:16}

run_id=${CAJUNOS_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
if [[ ! $run_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "Unsafe CAJUNOS_RUN_ID: $run_id" >&2
  exit 48
fi

build_final=$work_root/$build_id
prefix_final=$tools_root/$build_id
artifact_final=$artifacts_root/$build_id
receipt_final=$artifact_final/receipt.json
log_dir=$logs_root/$run_id
log_file=$log_dir/gcc-stage1.log
temporary_root=$work_root/.tmp-$build_id-$$
build_temporary=$temporary_root/build
stage_root=$temporary_root/stage
prefix_staged=$stage_root$prefix_final
artifact_temporary=$artifacts_root/.tmp-$build_id-$$

publish_current_link() {
  local temporary_link=$tools_root/.current-$$
  [[ $temporary_link == "$tools_root"/.current-* ]] || return 1
  rm -f -- "$temporary_link"
  ln -s "$build_id" "$temporary_link"
  mv -Tf -- "$temporary_link" "$tools_root/current"
}

if [[ -d $build_final && -d $prefix_final && -f $receipt_final ]]; then
  python3 - \
    "$receipt_final" \
    "$prefix_final" \
    "$build_id" \
    "$locked_commit" \
    "$locked_tree" \
    "$source_set_digest" \
    "$source_authentication" \
    "$source_repository" \
    "$target" \
    "$build_triplet" \
    "$sysroot" \
    "$orchestration_commit" \
    "$orchestration_tree" \
    "$recipe_sha256" \
    "$configure_digest" \
    "$binutils_build_id" \
    "$binutils_receipt_sha256" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

(
    receipt_path, prefix_value, build_id, commit, tree, source_set_digest,
    source_authentication, source_repository, target, build_triplet, sysroot,
    orchestration_commit, orchestration_tree, recipe_sha256, configure_digest,
    dependency_build_id, dependency_sha,
) = sys.argv[1:]
prefix = Path(prefix_value)

def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def tree_entries(root: Path) -> dict[str, dict[str, str]]:
    root_mode = root.lstat().st_mode
    if not stat.S_ISDIR(root_mode):
        raise SystemExit(f"installed prefix is not a directory: {root}")
    entries = {".": {"type": "directory", "mode": f"{stat.S_IMODE(root_mode):04o}"}}
    def walk(directory: Path) -> None:
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda item: item.name)
        for child in children:
            path = Path(child.path)
            relative = str(path.relative_to(root))
            mode = f"{stat.S_IMODE(child.stat(follow_symlinks=False).st_mode):04o}"
            if child.is_symlink():
                entries[relative] = {
                    "type": "symlink", "mode": mode, "target": os.readlink(path)
                }
            elif child.is_dir(follow_symlinks=False):
                entries[relative] = {"type": "directory", "mode": mode}
                walk(path)
            elif child.is_file(follow_symlinks=False):
                entries[relative] = {
                    "type": "file", "mode": mode, "sha256": sha256(path)
                }
            else:
                raise SystemExit(f"unsupported installed entry: {relative}")
    walk(root)
    return entries

with open(receipt_path, encoding="utf-8") as stream:
    receipt = json.load(stream)
if (
    receipt.get("schema") != 1
    or receipt.get("component") != "gcc"
    or receipt.get("stage") != "stage1"
    or receipt.get("build_id") != build_id
    or receipt.get("source_commit") != commit
    or receipt.get("source_tree") != tree
    or receipt.get("source_set_digest") != source_set_digest
    or receipt.get("source_authentication") != source_authentication
    or receipt.get("source_repository") != source_repository
    or receipt.get("target") != target
    or receipt.get("build_triplet") != build_triplet
    or receipt.get("prefix") != prefix_value
    or receipt.get("sysroot") != sysroot
    or receipt.get("sysroot_contract") != "empty-at-build"
    or receipt.get("target_contract", {}).get("fixincludes") != "disabled-for-headerless-stage"
    or receipt.get("orchestration_commit") != orchestration_commit
    or receipt.get("orchestration_tree") != orchestration_tree
    or receipt.get("recipe_sha256") != recipe_sha256
    or receipt.get("configure_digest") != configure_digest
    or receipt.get("dependencies", {}).get("binutils", {}).get("build_id") != dependency_build_id
    or receipt.get("dependencies", {}).get("binutils", {}).get("receipt_sha256") != dependency_sha
):
    raise SystemExit("completed GCC receipt does not match requested build")
expected = receipt.get("installed_entries")
if not isinstance(expected, dict) or tree_entries(prefix) != expected:
    raise SystemExit("completed GCC prefix failed full inventory validation")
PY
  publish_current_link
  echo "CAJUNOS_GCC_STAGE1_ALREADY_COMPLETE build_id=$build_id"
  exit 0
fi
if [[ -e $build_final || -e $prefix_final || -e $artifact_final ]]; then
  echo "Refusing to reuse an incomplete published build: $build_id" >&2
  exit 49
fi
if [[ -e $temporary_root || -e $artifact_temporary || -e $log_dir ]]; then
  echo "Refusing colliding temporary or log path for run $run_id" >&2
  exit 50
fi
if [[ -n $(find "$sysroot" -mindepth 1 -print -quit) ]]; then
  echo "GCC stage one requires an empty cohort sysroot" >&2
  exit 51
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

echo "CajunOS GCC stage 1"
echo "build_id=$build_id"
echo "source=$locked_commit"
echo "source_repository=$source_repository"
echo "source_set=$source_set_digest"
echo "source_authentication=$source_authentication"
echo "orchestration=$orchestration_commit"
echo "recipe_sha256=$recipe_sha256"
echo "configure_digest=$configure_digest"
echo "binutils_build_id=$binutils_build_id"
echo "binutils_receipt_sha256=$binutils_receipt_sha256"
echo "build_triplet=$build_triplet"
echo "target=$target"
echo "sysroot=$sysroot"
echo "prefix=$prefix_final"
echo "makeflags=$MAKEFLAGS"
echo "source_date_epoch=$SOURCE_DATE_EPOCH"

printf '%s\n' "${configure_args[@]}" > "$artifact_temporary/configure.args"
export PATH="$binutils_prefix/bin:/usr/bin:/bin"
(
  cd "$build_temporary"
  CONFIG_SHELL=/bin/bash "$source_dir/configure" \
    --prefix="$prefix_final" \
    "${configure_args[@]}"
)

make -j1 -C "$build_temporary" configure-gcc
if ! grep -Eq '^STMP_FIXINC[[:space:]]*=[[:space:]]*$' \
  "$build_temporary/gcc/Makefile"; then
  echo "Locked GCC did not honor --disable-fixincludes" >&2
  exit 64
fi
if ! grep -Fqx "TARGET_SYSTEM_ROOT = $sysroot" \
  "$build_temporary/gcc/Makefile"; then
  echo "Locked GCC configured an unexpected target sysroot" >&2
  exit 65
fi

make -C "$build_temporary" all-gcc
make -j1 -C "$build_temporary" DESTDIR="$stage_root" install-gcc

gcc_driver=$prefix_staged/bin/$target-gcc
[[ -x $gcc_driver ]] || { echo "Missing staged cross compiler: $gcc_driver" >&2; exit 52; }

# Compose the stage-one prefix with immutable relative links to its exact
# Binutils dependency. The prior prefix itself remains untouched.
for tool in addr2line ar as c++filt elfedit gprof ld ld.bfd nm objcopy objdump ranlib readelf size strings strip; do
  dependency=$binutils_prefix/bin/$target-$tool
  [[ -x $dependency ]] || { echo "Missing Binutils dependency: $dependency" >&2; exit 53; }
  destination=$prefix_staged/bin/$target-$tool
  [[ ! -e $destination && ! -L $destination ]] || {
    echo "Refusing composition collision: $destination" >&2
    exit 54
  }
  ln -s "../../$binutils_build_id/bin/$target-$tool" "$destination"
done

probe_dir=$artifact_temporary/probe
mkdir -p "$probe_dir"

dumpmachine=$($gcc_driver -dumpmachine)
[[ $dumpmachine == "$target" ]] || { echo "Unexpected GCC target: $dumpmachine" >&2; exit 55; }
printed_sysroot=$($gcc_driver -print-sysroot)
[[ $printed_sysroot == "$sysroot" ]] || {
  echo "Unexpected GCC sysroot: $printed_sysroot" >&2
  exit 56
}

cc1_path=$($gcc_driver -print-prog-name=cc1)
[[ -x $cc1_path && $cc1_path == "$prefix_staged"/* ]] || {
  echo "GCC did not resolve staged cc1: $cc1_path" >&2
  exit 57
}
for program in as ld; do
  resolved=$($gcc_driver -print-prog-name="$program")
  expected=$binutils_prefix/bin/$target-$program
  [[ $(readlink -f -- "$resolved") == $(readlink -f -- "$expected") ]] || {
    echo "GCC resolved unexpected $program: $resolved" >&2
    exit 58
  }
done

$gcc_driver -Q --help=target > "$probe_dir/target-options.txt"
grep -Eq -- '-march=.*x86-64-v2' "$probe_dir/target-options.txt"
grep -Eq -- '-mtune=.*generic' "$probe_dir/target-options.txt"

printf '\n' | $gcc_driver -E -v -x c - \
  > "$probe_dir/preprocessor.stdout" \
  2> "$probe_dir/preprocessor-search.txt"
if grep -Eq '^[[:space:]]+/usr/(local/)?include([[:space:]]|$)' "$probe_dir/preprocessor-search.txt"; then
  echo "Cross compiler leaked a host include directory" >&2
  exit 59
fi

cat > "$probe_dir/start.c" <<'EOF'
__attribute__((noreturn)) void _start(void)
{
    __asm__ volatile (
        "syscall"
        :
        : "a" (60L), "D" (0L)
        : "rcx", "r11", "memory");
    __builtin_unreachable();
}
EOF
$gcc_driver \
  -O2 -ffreestanding -fno-stack-protector -fno-pie -no-pie \
  -nostdlib -nostartfiles -nodefaultlibs -Wl,-e,_start \
  "$probe_dir/start.c" -o "$probe_dir/start"
"$binutils_prefix/bin/$target-readelf" -h "$probe_dir/start" > "$probe_dir/start.readelf-h"
"$binutils_prefix/bin/$target-readelf" -l "$probe_dir/start" > "$probe_dir/start.readelf-l"
"$binutils_prefix/bin/$target-readelf" -d "$probe_dir/start" > "$probe_dir/start.readelf-d"
grep -q 'Machine:.*Advanced Micro Devices X86-64' "$probe_dir/start.readelf-h"
if grep -Eq 'INTERP|DYNAMIC' "$probe_dir/start.readelf-l"; then
  echo "Freestanding GCC probe unexpectedly has a runtime loader" >&2
  exit 60
fi
"$probe_dir/start"

cat > "$probe_dir/popcount.c" <<'EOF'
unsigned cajunos_popcount(unsigned value)
{
    return __builtin_popcount(value);
}
EOF
$gcc_driver -O2 -S "$probe_dir/popcount.c" -o "$probe_dir/popcount.s"
grep -Eq '(^|[[:space:]])popcnt[lq]?[[:space:]]' "$probe_dir/popcount.s"

if find "$prefix_staged" -type f \( -name 'libgcc.a' -o -name 'libgcc_s.so*' -o -name 'crt*.o' \) -print -quit | grep -q .; then
  echo "GCC stage one unexpectedly installed a target runtime" >&2
  exit 61
fi
if [[ -n $(find "$sysroot" -mindepth 1 -print -quit) ]]; then
  echo "GCC stage one unexpectedly modified the cohort sysroot" >&2
  exit 62
fi
# Close the dependency time-of-check/time-of-use window before attesting to
# the GCC output. Both the receipt bytes and the complete immutable prefix must
# still be identical to the inputs used to derive this build ID.
python3 - \
  "$binutils_receipt" \
  "$binutils_prefix" \
  "$binutils_receipt_sha256" \
  "$binutils_build_id" \
  "$locked_binutils_commit" \
  "$locked_binutils_tree" \
  "$source_set_digest" \
  "$source_authentication" \
  "$target" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

(
    receipt_value, prefix_value, expected_receipt_sha, build_id, commit, tree,
    source_set_digest, source_authentication, target,
) = sys.argv[1:]
receipt_path = Path(receipt_value)
prefix = Path(prefix_value)

def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def tree_entries(root: Path) -> dict[str, dict[str, str]]:
    root_mode = root.lstat().st_mode
    if not stat.S_ISDIR(root_mode):
        raise SystemExit(f"Binutils prefix is not a directory: {root}")
    entries = {".": {"type": "directory", "mode": f"{stat.S_IMODE(root_mode):04o}"}}
    def walk(directory: Path) -> None:
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda item: item.name)
        for child in children:
            path = Path(child.path)
            relative = str(path.relative_to(root))
            mode = f"{stat.S_IMODE(child.stat(follow_symlinks=False).st_mode):04o}"
            if child.is_symlink():
                entries[relative] = {
                    "type": "symlink", "mode": mode, "target": os.readlink(path)
                }
            elif child.is_dir(follow_symlinks=False):
                entries[relative] = {"type": "directory", "mode": mode}
                walk(path)
            elif child.is_file(follow_symlinks=False):
                entries[relative] = {
                    "type": "file", "mode": mode, "sha256": sha256(path)
                }
            else:
                raise SystemExit(f"unsupported Binutils prefix entry: {relative}")
    walk(root)
    return entries

if sha256(receipt_path) != expected_receipt_sha:
    raise SystemExit("Binutils dependency receipt changed during GCC build")
with receipt_path.open(encoding="utf-8") as stream:
    receipt = json.load(stream)
if (
    receipt.get("schema") != 1
    or receipt.get("component") != "binutils"
    or receipt.get("stage") != "stage1"
    or receipt.get("build_id") != build_id
    or receipt.get("source_commit") != commit
    or receipt.get("source_tree") != tree
    or receipt.get("source_set_digest") != source_set_digest
    or receipt.get("source_authentication") != source_authentication
    or receipt.get("target") != target
    or receipt.get("prefix") != str(prefix)
):
    raise SystemExit("Binutils dependency provenance changed during GCC build")
expected_entries = receipt.get("installed_entries")
if not isinstance(expected_entries, dict) or tree_entries(prefix) != expected_entries:
    raise SystemExit("Binutils dependency prefix changed during GCC build")
PY

license_dir=$artifact_temporary/licenses/gcc
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
  "$source_repository" \
  "$target" \
  "$build_triplet" \
  "$log_file" \
  "$prefix_final" \
  "$prefix_staged" \
  "$sysroot" \
  "$orchestration_commit" \
  "$orchestration_tree" \
  "$recipe_sha256" \
  "$configure_digest" \
  "$artifact_temporary/configure.args" \
  "$binutils_build_id" \
  "$binutils_prefix" \
  "$binutils_receipt" \
  "$binutils_receipt_sha256" \
  "$binutils_source_commit" \
  "$binutils_source_tree" \
  "$glibc_series" \
  "$probe_dir" \
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
    output, build_id, commit, tree, source_set_digest, source_authentication,
    source_repository, target, build_triplet, log_file, prefix_final,
    prefix_staged_value, sysroot, orchestration_commit, orchestration_tree,
    recipe_sha256, configure_digest, configure_args_value, binutils_build_id,
    binutils_prefix, binutils_receipt, binutils_receipt_sha256,
    binutils_source_commit, binutils_source_tree, glibc_series, probe_dir_value,
    config_log_value, license_dir_value, source_date_epoch,
) = sys.argv[1:]

prefix_staged = Path(prefix_staged_value)
probe_dir = Path(probe_dir_value)
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
    entries = {".": {"type": "directory", "mode": f"{stat.S_IMODE(root_mode):04o}"}}
    def walk(directory: Path) -> None:
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda item: item.name)
        for child in children:
            path = Path(child.path)
            relative = str(path.relative_to(root))
            mode = f"{stat.S_IMODE(child.stat(follow_symlinks=False).st_mode):04o}"
            if child.is_symlink():
                entries[relative] = {
                    "type": "symlink", "mode": mode, "target": os.readlink(path)
                }
            elif child.is_dir(follow_symlinks=False):
                entries[relative] = {"type": "directory", "mode": mode}
                walk(path)
            elif child.is_file(follow_symlinks=False):
                entries[relative] = {
                    "type": "file", "mode": mode, "sha256": sha256(path)
                }
            else:
                raise SystemExit(f"unsupported installed entry: {relative}")
    walk(root)
    return entries

licenses = {
    str(path.relative_to(license_dir)): sha256(path)
    for path in sorted(license_dir.rglob("*")) if path.is_file()
}
probe_hashes = {
    str(path.relative_to(probe_dir)): sha256(path)
    for path in sorted(probe_dir.rglob("*")) if path.is_file()
}
with Path(configure_args_value).open(encoding="utf-8") as stream:
    configure_args = [line.rstrip("\n") for line in stream]

packages = {}
for package in ("libgmp-dev", "libmpfr-dev", "libmpc-dev", "bison", "flex", "texinfo"):
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Version}", package],
        check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    packages[package] = result.stdout if result.returncode == 0 else None

receipt = {
    "schema": 1,
    "build_id": build_id,
    "component": "gcc",
    "stage": "stage1",
    "source_commit": commit,
    "source_tree": tree,
    "source_repository": source_repository,
    "source_set_digest": source_set_digest,
    "source_authentication": source_authentication,
    "source_date_epoch": int(source_date_epoch),
    "target": target,
    "build_triplet": build_triplet,
    "target_contract": {
        "architecture": "x86-64-v2",
        "tuning": "generic",
        "glibc_series": glibc_series,
        "runtime": "intentionally absent",
        "threads": "single",
        "fixincludes": "disabled-for-headerless-stage",
    },
    "sysroot": sysroot,
    "sysroot_contract": "empty-at-build",
    "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    "log": log_file,
    "prefix": prefix_final,
    "orchestration_commit": orchestration_commit,
    "orchestration_tree": orchestration_tree,
    "recipe_sha256": recipe_sha256,
    "configure_digest": configure_digest,
    "configure_args": configure_args,
    "dependencies": {
        "binutils": {
            "build_id": binutils_build_id,
            "prefix": binutils_prefix,
            "receipt": binutils_receipt,
            "receipt_sha256": binutils_receipt_sha256,
            "source_commit": binutils_source_commit,
            "source_tree": binutils_source_tree,
        }
    },
    "host": {
        "platform": platform.platform(),
        "gcc": first_line("gcc", "--version"),
        "g++": first_line("g++", "--version"),
        "make": first_line("make", "--version"),
        "packages": packages,
    },
    "installed_entries": tree_entries(prefix_staged),
    "license_sha256": licenses,
    "outputs": {
        "config_log_sha256": sha256(config_log),
        "probe_sha256": probe_hashes,
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
  exit 63
fi
rm -rf -- "$temporary_root"
build_succeeded=1
trap - EXIT
echo "CAJUNOS_GCC_STAGE1_OK build_id=$build_id"
