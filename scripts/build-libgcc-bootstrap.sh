#!/usr/bin/env bash
set -Eeuo pipefail
umask 022
export LC_ALL=C
export TZ=UTC
export PATH=/usr/bin:/bin

script_path=$(readlink -f -- "${BASH_SOURCE[0]}")
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
inventory_helper=$project_root/scripts/install-linux-headers.sh

# Filesystem and selector logic is exposed for focused, forge-independent tests.
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
import shlex
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


def dependency_inventory(root: Path, tools_root: Path) -> dict[str, object]:
    entries = helper_json("dependency-inventory", root, tools_root)
    if not isinstance(entries, dict):
        fail("dependency inventory helper returned invalid data")
    return {"entries": entries, "digest": canonical_digest(entries)}


def regular_hashes(root: Path) -> dict[str, str]:
    try:
        metadata = root.lstat()
    except FileNotFoundError:
        fail(f"attestation directory does not exist: {root}")
    if not stat.S_ISDIR(metadata.st_mode):
        fail(f"attestation path is not a real directory: {root}")
    result: dict[str, str] = {}
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
            result[child.relative_to(root).as_posix()] = sha256(child)
    return result


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


def runtime_paths(target: str, version: str) -> set[str]:
    if target != "x86_64-cajunos-linux-gnu":
        fail("unsupported target in runtime delta")
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", version):
        fail("unsafe GCC version in runtime delta")
    root = f"lib/gcc/{target}/{version}"
    return {
        f"{root}/libgcc.a",
        f"{root}/include/unwind.h",
        f"{root}/include/gcov.h",
        f"{root}/crtbegin.o",
        f"{root}/crtbeginS.o",
        f"{root}/crtbeginT.o",
        f"{root}/crtend.o",
        f"{root}/crtendS.o",
        f"{root}/crtfastmath.o",
        f"{root}/crtprec32.o",
        f"{root}/crtprec64.o",
        f"{root}/crtprec80.o",
    }


def runtime_lookup_names() -> tuple[str, ...]:
    return (
        "libgcc.a",
        "crtbegin.o",
        "crtbeginS.o",
        "crtbeginT.o",
        "crtend.o",
        "crtendS.o",
        "crtfastmath.o",
        "crtprec32.o",
        "crtprec64.o",
        "crtprec80.o",
    )


def validate_runtime_lookups(runtime_root: Path, lookup_path: Path) -> None:
    if (
        not runtime_root.is_absolute()
        or str(runtime_root) != os.path.normpath(runtime_root)
    ):
        fail("unsafe runtime root for GCC lookup contract")
    try:
        runtime_metadata = runtime_root.lstat()
    except FileNotFoundError:
        fail("GCC lookup runtime root does not exist")
    if not stat.S_ISDIR(runtime_metadata.st_mode):
        fail("GCC lookup runtime root is not a real directory")
    try:
        lookup_metadata = lookup_path.lstat()
    except FileNotFoundError:
        fail("GCC runtime lookup attestation does not exist")
    if not stat.S_ISREG(lookup_metadata.st_mode) or lookup_metadata.st_nlink != 1:
        fail("GCC runtime lookup attestation is not a plain single-linked file")
    values: dict[str, str] = {}
    for line in lookup_path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            fail("GCC runtime lookup attestation is malformed")
        name, resolved = line.split("=", 1)
        if name in values:
            fail(f"GCC runtime lookup attestation repeats {name}")
        values[name] = resolved
    expected_names = runtime_lookup_names()
    if set(values) != set(expected_names) or len(values) != len(expected_names):
        fail("GCC runtime lookup attestation has unexpected entries")
    for name in expected_names:
        expected = runtime_root / name
        try:
            metadata = expected.lstat()
        except FileNotFoundError:
            fail(f"expected GCC runtime lookup is absent: {name}")
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o644
        ):
            fail(f"expected GCC runtime lookup is not a plain mode-0644 file: {name}")
        resolved = values[name]
        try:
            resolved_real = Path(resolved).resolve(strict=True)
            expected_real = expected.resolve(strict=True)
        except (FileNotFoundError, RuntimeError):
            fail(f"derived GCC resolved {name} through an invalid path: {resolved}")
        if (
            not os.path.isabs(resolved)
            or os.path.normpath(resolved) != str(expected)
            or resolved_real != expected_real
        ):
            fail(f"derived GCC resolved {name} outside its runtime prefix: {resolved}")


def derive_delta(
    base: dict[str, object], result: dict[str, object], target: str, version: str
) -> dict[str, object]:
    base_entries = base.get("entries")
    result_entries = result.get("entries")
    if not isinstance(base_entries, dict) or not isinstance(result_entries, dict):
        fail("invalid prefix inventories")
    for path, metadata in base_entries.items():
        if result_entries.get(path) != metadata:
            fail(f"sealed GCC prefix entry changed or disappeared: {path}")
    added = {
        path: metadata
        for path, metadata in result_entries.items()
        if path not in base_entries
    }
    expected = runtime_paths(target, version)
    if set(added) != expected:
        missing = sorted(expected - set(added))
        unexpected = sorted(set(added) - expected)
        fail(f"unexpected libgcc prefix delta: missing={missing}, unexpected={unexpected}")
    for path, metadata in added.items():
        if metadata != {
            "type": "file",
            "mode": "0644",
            "sha256": metadata.get("sha256"),
        } or not re.fullmatch(r"[0-9a-f]{64}", str(metadata.get("sha256", ""))):
            fail(f"bootstrap runtime is not a plain mode-0644 file: {path}")
    forbidden = re.compile(
        r"^(?:libgcc_s(?:\.so.*)?|libgcc_eh\.a|libgcov\.a|libunwind.*|"
        r"libc(?:\.so.*|\.a)|ld-linux.*|crt1\.o|crti\.o|crtn\.o)$"
    )
    for path in result_entries:
        if forbidden.fullmatch(PurePosixPath(path).name):
            fail(f"forbidden bootstrap runtime artifact: {path}")
    return {
        "schema": "sealed-tools-prefix-additions-v1",
        "base_digest": f"sha256:{base['digest']}",
        "result_digest": f"sha256:{result['digest']}",
        "added_entries": added,
        "added_entries_digest": f"sha256:{canonical_digest(added)}",
    }


def safe_current(tools_root: Path) -> tuple[Path, str]:
    current = tools_root / "current"
    try:
        root_metadata = tools_root.lstat()
    except FileNotFoundError:
        fail("tools root does not exist")
    if not stat.S_ISDIR(root_metadata.st_mode):
        fail("tools root is not a real directory")
    if not current.is_symlink():
        fail("tools/current is not a managed symlink")
    selected = os.readlink(current)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", selected):
        fail("tools/current has an unsafe target")
    prefix = tools_root / selected
    try:
        prefix_metadata = prefix.lstat()
    except FileNotFoundError:
        fail("tools/current names an absent prefix")
    if not stat.S_ISDIR(prefix_metadata.st_mode):
        fail("tools/current does not name a real prefix")
    try:
        current.resolve(strict=True).relative_to(tools_root.resolve(strict=True))
    except (FileNotFoundError, RuntimeError, ValueError):
        fail("tools/current is broken or escaping")
    return current, selected


def require_descendant(
    tools_root: Path, artifacts_root: Path, selected: str, ancestor: str
) -> None:
    cursor = selected
    seen: set[str] = set()
    while cursor != ancestor:
        if cursor in seen or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", cursor
        ):
            fail("tools selector ancestry is cyclic or unsafe")
        seen.add(cursor)
        receipt_path = artifacts_root / cursor / "receipt.json"
        try:
            metadata = receipt_path.lstat()
        except FileNotFoundError:
            fail("tools/current names an unproven later prefix")
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            fail("later tools receipt is not a plain single-linked file")
        with receipt_path.open(encoding="utf-8") as stream:
            receipt = json.load(stream)
        if (
            receipt.get("build_id") != cursor
            or receipt.get("prefix") != str(tools_root / cursor)
        ):
            fail("later tools receipt has invalid identity")
        parent = receipt.get("base_build_id")
        if not isinstance(parent, str):
            fail("later tools receipt lacks base_build_id")
        cursor = parent


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent, text=True
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.replace(temporary_name, path)
    path.chmod(0o644)


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
        f"libgcc-bootstrap-{commit[:12]}-"
        f"{canonical_digest(require_pairs(arguments[1:]))[:16]}"
    )
elif command == "derived-delta":
    if len(arguments) != 5:
        fail("derived-delta requires BASE RESULT TARGET VERSION OUTPUT")
    base, result = (dependency_inventory(Path(value), Path(arguments[2])) for value in arguments[:2])
    # The tools root is passed once, in argument 3, for both prefix walkers.
    delta = derive_delta(base, result, arguments[3], arguments[4])
    print(json.dumps(delta, indent=2, sort_keys=True))
elif command == "write-delta":
    if len(arguments) != 6:
        fail("write-delta requires BASE RESULT TOOLS TARGET VERSION OUTPUT")
    base = dependency_inventory(Path(arguments[0]), Path(arguments[2]))
    result = dependency_inventory(Path(arguments[1]), Path(arguments[2]))
    write_json(Path(arguments[5]), derive_delta(base, result, arguments[3], arguments[4]))
elif command == "no-shared-inodes":
    if len(arguments) != 2:
        fail("no-shared-inodes requires BASE COPY")
    inode_sets = []
    for root_value in arguments:
        seen = set()
        for directory, names, filenames in os.walk(root_value, followlinks=False):
            names.sort()
            filenames.sort()
            for name in filenames:
                path = Path(directory) / name
                metadata = path.lstat()
                if stat.S_ISREG(metadata.st_mode):
                    seen.add((metadata.st_dev, metadata.st_ino))
        inode_sets.append(seen)
    if inode_sets[0] & inode_sets[1]:
        fail("derived tools prefix shares regular-file inodes with its sealed base")
elif command == "runtime-lookups-contract":
    if len(arguments) != 2:
        fail("runtime-lookups-contract requires RUNTIME_ROOT LOOKUPS")
    validate_runtime_lookups(Path(arguments[0]), Path(arguments[1]))
elif command == "compare-json":
    if len(arguments) != 2:
        fail("compare-json requires LEFT RIGHT")
    with Path(arguments[0]).open(encoding="utf-8") as stream:
        left = json.load(stream)
    with Path(arguments[1]).open(encoding="utf-8") as stream:
        right = json.load(stream)
    if left != right:
        fail("JSON attestations differ")
elif command == "gcc-header-contract":
    if len(arguments) != 3:
        fail(
            "gcc-header-contract requires MAKEFILE TARGET_SYSROOT BUILD_SYSROOT"
        )
    makefile = Path(arguments[0])
    target_sysroot = arguments[1]
    build_sysroot = arguments[2]
    if not makefile.is_absolute() or str(makefile) != os.path.normpath(makefile):
        fail("unsafe generated GCC Makefile path")
    metadata = makefile.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail("generated GCC Makefile is not a plain single-linked file")
    for label, value in (
        ("target sysroot", target_sysroot),
        ("build sysroot", build_sysroot),
    ):
        if not value.startswith("/") or value != os.path.normpath(value):
            fail(f"unsafe {label} for GCC header contract")
    target = "__cajunos_print_gcc_header_contract"
    recipe = (
        f'{target}: ; @printf "%s\\n" '
        '"NATIVE=$(NATIVE_SYSTEM_HEADER_DIR)" '
        '"CROSS=$(CROSS_SYSTEM_HEADER_DIR)" '
        '"SYSTEM=$(SYSTEM_HEADER_DIR)" '
        '"BUILD=$(BUILD_SYSTEM_HEADER_DIR)" '
        '"ROOT=$(TARGET_SYSTEM_ROOT)" '
        '"SYSROOT_FLAGS=$(SYSROOT_CFLAGS_FOR_TARGET)" '
        '"INHIBIT=$(inhibit_libc)"'
    )
    result = subprocess.run(
        [
            "/usr/bin/make",
            "-s",
            "-C",
            str(makefile.parent),
            "-f",
            str(makefile),
            "--no-print-directory",
            "sysroot_headers_suffix=",
            f"--eval=.PHONY: {target}",
            f"--eval={recipe}",
            target,
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"},
    )
    if result.returncode:
        fail("could not evaluate generated GCC header contract")
    expected_lines = [
        "NATIVE=/usr/include",
        f"CROSS={target_sysroot}/usr/include",
        f"SYSTEM={build_sysroot}/usr/include",
        f"BUILD={build_sysroot}/usr/include",
        f"ROOT={target_sysroot}",
        f"SYSROOT_FLAGS=--sysroot={build_sysroot}",
        "INHIBIT=false",
    ]
    if result.stdout != "\n".join(expected_lines) + "\n":
        fail("generated GCC header contract does not match sealed sysroots")
elif command == "libgcc-make-contract":
    if len(arguments) != 3:
        fail(
            "libgcc-make-contract requires MAKEFILE GCC_OBJDIR BUILD_SYSROOT"
        )
    makefile = Path(arguments[0])
    gcc_objdir = arguments[1]
    build_sysroot = arguments[2]
    if not makefile.is_absolute() or str(makefile) != os.path.normpath(makefile):
        fail("unsafe generated libgcc Makefile path")
    metadata = makefile.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail("generated libgcc Makefile is not a plain single-linked file")
    for label, value in (
        ("GCC object directory", gcc_objdir),
        ("build sysroot", build_sysroot),
    ):
        if not value.startswith("/") or value != os.path.normpath(value):
            fail(f"unsafe {label} for libgcc Make contract")
    gcc_directory = Path(gcc_objdir)
    build_sysroot_directory = Path(build_sysroot)
    if not stat.S_ISDIR(gcc_directory.lstat().st_mode):
        fail("expected GCC object directory is not a real directory")
    if not stat.S_ISDIR(build_sysroot_directory.lstat().st_mode):
        fail("expected libgcc build sysroot is not a real directory")
    xgcc = gcc_directory / "xgcc"
    xgcc_metadata = xgcc.lstat()
    if (
        not stat.S_ISREG(xgcc_metadata.st_mode)
        or xgcc_metadata.st_nlink != 1
        or not (xgcc_metadata.st_mode & 0o111)
    ):
        fail("fresh cross compiler is not a plain executable file")
    libgcc_mvars = gcc_directory / "libgcc.mvars"
    mvars_metadata = libgcc_mvars.lstat()
    if not stat.S_ISREG(mvars_metadata.st_mode) or mvars_metadata.st_nlink != 1:
        fail("generated libgcc.mvars is not a plain single-linked file")
    inhibit_assignments = [
        line
        for line in libgcc_mvars.read_text(encoding="utf-8").splitlines()
        if re.match(r"^INHIBIT_LIBC_CFLAGS[ \t]*=", line)
    ]
    if len(inhibit_assignments) != 1 or not re.fullmatch(
        r"INHIBIT_LIBC_CFLAGS[ \t]*=[ \t]*", inhibit_assignments[0]
    ):
        fail("generated libgcc.mvars does not record functional-header mode")
    target = "__cajunos_print_libgcc_make_contract"
    recipe = (
        f'{target}: ; @printf "%s\\n" '
        '"SHARED=$(strip $(enable_shared))" '
        '"GCOV=$(strip $(enable_gcov))" '
        '"THREAD=$(strip $(thread_header))" '
        '"MULTIDIRS=$(strip $(MULTIDIRS))" '
        '"MULTISUBDIR=$(strip $(MULTISUBDIR))" '
        '"INHIBIT_FLAGS=$(strip $(INHIBIT_LIBC_CFLAGS))" '
        '"LIBGCC_FLAGS=$(strip $(LIBGCC2_CFLAGS))" '
        '"CRT_FLAGS=$(strip $(CRTSTUFF_CFLAGS) $(CRTSTUFF_T_CFLAGS))" '
        '"EXTRA_PARTS=$(strip $(EXTRA_PARTS))" '
        '"GCC_OBJDIR=$(abspath $(gcc_objdir))" '
        '"CC=$(strip $(CC))"'
    )
    result = subprocess.run(
        [
            "/usr/bin/make",
            "-s",
            "-C",
            str(makefile.parent),
            "-f",
            str(makefile),
            "--no-print-directory",
            f"--eval=.PHONY: {target}",
            f"--eval={recipe}",
            target,
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"},
    )
    if result.returncode or result.stderr:
        fail("could not cleanly evaluate generated libgcc Make contract")
    lines = result.stdout.splitlines()
    if len(lines) != 11 or any("=" not in line for line in lines):
        fail("generated libgcc Make contract has malformed output")
    values = dict(line.split("=", 1) for line in lines)
    expected_values = {
        "SHARED": "no",
        "GCOV": "no",
        "THREAD": "gthr-single.h",
        "MULTIDIRS": "",
        "MULTISUBDIR": "",
        "INHIBIT_FLAGS": "",
        "EXTRA_PARTS": (
            "crtbegin.o crtbeginS.o crtbeginT.o crtend.o crtendS.o "
            "crtprec32.o crtprec64.o crtprec80.o crtfastmath.o"
        ),
        "GCC_OBJDIR": gcc_objdir,
    }
    if {key: values.get(key) for key in expected_values} != expected_values:
        fail("generated libgcc Make contract has unsafe build modes")
    try:
        cc_tokens = shlex.split(values["CC"])
    except (KeyError, ValueError):
        fail("generated libgcc Make contract has an invalid compiler command")
    if not cc_tokens:
        fail("generated libgcc Make contract has an empty compiler command")

    def command_path(value: str) -> str:
        path = Path(value)
        if not path.is_absolute():
            path = makefile.parent / path
        return os.path.normpath(path)

    if command_path(cc_tokens[0]) != f"{gcc_objdir}/xgcc":
        fail("target libgcc is not configured with the fresh cross compiler")
    b_prefixes = [command_path(token[2:]) for token in cc_tokens if token.startswith("-B")]
    if gcc_objdir not in b_prefixes:
        fail("target libgcc compiler lacks its fresh GCC search prefix")
    sysroot_tokens = [token for token in cc_tokens if token.startswith("--sysroot=")]
    if sysroot_tokens != [f"--sysroot={build_sysroot}"]:
        fail("target libgcc compiler does not use the sealed build sysroot")
    if any("inhibit_libc" in token for token in cc_tokens):
        fail("target libgcc compiler unexpectedly inhibits libc")
    if (
        "inhibit_libc" in values["LIBGCC_FLAGS"]
        or "inhibit_libc" in values["CRT_FLAGS"]
    ):
        fail("target libgcc compile flags unexpectedly inhibit libc")
elif command == "selector-state":
    if len(arguments) != 4:
        fail("selector-state requires TOOLS ARTIFACTS BASE BUILD")
    _, selected = safe_current(Path(arguments[0]))
    if selected == arguments[3]:
        print("this")
    elif selected == arguments[2]:
        print("base")
    else:
        require_descendant(Path(arguments[0]), Path(arguments[1]), selected, arguments[3])
        print(f"later:{selected}")
elif command == "selector-transition":
    if len(arguments) != 4:
        fail("selector-transition requires TOOLS ARTIFACTS BASE BUILD")
    tools_root, artifacts_root = map(Path, arguments[:2])
    base_build_id, build_id = arguments[2:]
    current, selected = safe_current(tools_root)
    result = tools_root / build_id
    if not result.is_dir() or result.is_symlink():
        fail("result tools prefix does not exist as a real directory")
    if selected == build_id:
        print("this")
    elif selected != base_build_id:
        require_descendant(tools_root, artifacts_root, selected, build_id)
        print(f"later:{selected}")
    else:
        temporary = tools_root / f".current-{os.getpid()}"
        try:
            os.symlink(build_id, temporary)
            os.replace(temporary, current)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        _, selected_after = safe_current(tools_root)
        if selected_after != build_id:
            fail("tools selector transition did not publish requested prefix")
        print("advanced")
elif command == "validate-completed":
    if len(arguments) < 8 or len(arguments[6:]) % 2:
        fail("validate-completed requires RECEIPT PREFIX BASE TOOLS TARGET VERSION and pairs")
    receipt_path = Path(arguments[0])
    prefix = Path(arguments[1])
    base = Path(arguments[2])
    tools_root = Path(arguments[3])
    target, version = arguments[4:6]
    expected = require_pairs(arguments[6:])
    metadata = receipt_path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail("completed receipt is not a plain single-linked file")
    with receipt_path.open(encoding="utf-8") as stream:
        receipt = json.load(stream)
    for key, expected_value in expected.items():
        if str(dotted(receipt, key)) != expected_value:
            fail(f"completed receipt mismatch for {key}")
    base_inventory = dependency_inventory(base, tools_root)
    result_inventory = dependency_inventory(prefix, tools_root)
    delta = derive_delta(base_inventory, result_inventory, target, version)
    if receipt.get("installed_entries") != result_inventory["entries"]:
        fail("completed tools prefix failed full inventory validation")
    if receipt.get("result_prefix_digest") != f"sha256:{result_inventory['digest']}":
        fail("completed result prefix digest is invalid")
    if receipt.get("base_prefix_digest") != f"sha256:{base_inventory['digest']}":
        fail("completed base prefix digest is invalid")
    if receipt.get("delta") != delta:
        fail("completed libgcc delta attestation is invalid")
    expected_repro = {
        "independent_builds": 2,
        "inventory_schema": "paths-types-modes-sha256-symlink-targets-v1",
        "first_inventory_digest": f"sha256:{result_inventory['digest']}",
        "second_inventory_digest": f"sha256:{result_inventory['digest']}",
        "identical": True,
        "base_unchanged_after_build": True,
        "sysroot_unchanged_after_build": True,
        "post_probe_inventory_digest": f"sha256:{result_inventory['digest']}",
    }
    if receipt.get("reproducibility") != expected_repro:
        fail("completed reproducibility attestation is invalid")
    runtime_root = prefix / f"lib/gcc/{target}/{version}"
    actual_hashes = {
        path.relative_to(prefix).as_posix(): sha256(path)
        for relative in runtime_paths(target, version)
        for path in [prefix / relative]
    }
    if receipt.get("runtime_sha256") != actual_hashes:
        fail("completed runtime hash attestation is invalid")
    if receipt.get("outputs", {}).get("probe_sha256") != regular_hashes(receipt_path.parent / "probe"):
        fail("completed probe attestation is invalid")
    if receipt.get("outputs", {}).get("configuration_sha256") != regular_hashes(receipt_path.parent / "configuration"):
        fail("completed configuration attestation is invalid")
    if receipt.get("license_inventory") != inventory(receipt_path.parent / "licenses/gcc"):
        fail("completed license inventory is invalid")
    sysroot_snapshot = Path(str(receipt.get("sysroot_snapshot", "")))
    sysroot_inventory = inventory(sysroot_snapshot)
    if (
        receipt.get("sysroot_snapshot_digest") != f"sha256:{sysroot_inventory['digest']}"
        or receipt.get("outputs", {}).get("sysroot_inventory_digest")
        != f"sha256:{sysroot_inventory['digest']}"
    ):
        fail("completed sysroot snapshot attestation is invalid")
    configure_path = receipt_path.parent / "configure.args"
    configure_args = configure_path.read_text(encoding="utf-8").splitlines()
    if not configure_args or receipt.get("configure_args") != configure_args:
        fail("completed configure argument attestation is invalid")
    configure_material = b"".join(value.encode("utf-8") + b"\0" for value in configure_args)
    if receipt.get("configure_digest") != hashlib.sha256(configure_material).hexdigest():
        fail("completed configure digest is invalid")
    archive = runtime_root / "libgcc.a"
    members = subprocess.run(
        ["ar", "t", str(archive)], check=True, text=True, stdout=subprocess.PIPE
    ).stdout.splitlines()
    archive_receipt = receipt.get("archive")
    if (
        not members
        or not isinstance(archive_receipt, dict)
        or archive_receipt.get("sha256") != sha256(archive)
        or archive_receipt.get("members") != members
        or archive_receipt.get("members_digest")
        != hashlib.sha256("\n".join(members).encode("utf-8") + b"\n").hexdigest()
    ):
        fail("completed libgcc archive attestation is invalid")
    if runtime_root not in [path.parent for path in (prefix / item for item in runtime_paths(target, version))]:
        fail("invalid runtime layout")
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
target_cflags='-O2 -g0 -march=x86-64-v2 -mtune=generic'
expected_user=${CAJUNOS_BUILD_USER:-cajunos}
lock_file=$project_root/locks/bootstrap.lock.json
manifest_file=$project_root/manifests/bootstrap.json

if [[ $(id -u) -eq 0 || $(id -un) != "$expected_user" ]]; then
  echo "Run this build as the unprivileged $expected_user account" >&2
  exit 70
fi
if [[ $target != x86_64-cajunos-linux-gnu ]]; then
  echo "This stage supports only x86_64-cajunos-linux-gnu" >&2
  exit 71
fi
for command in ar flock git grep install make nm python3 readelf rsync sed sha256sum tar; do
  command -v "$command" >/dev/null || {
    echo "Missing required host command: $command" >&2
    exit 72
  }
done
[[ -x $inventory_helper ]] || {
  echo "Frozen filesystem inventory helper is unavailable" >&2
  exit 73
}

"$project_root/scripts/fetch.py" validate --root "$cajunos_root" --json >/dev/null
cajunos_root=$(readlink -f -- "$cajunos_root")
exec 8>"$cajunos_root/upstream/.cajunos-source.lock"
if ! flock -n 8; then
  echo "Another CajunOS source operation or build owns the source lock" >&2
  exit 74
fi
"$project_root/scripts/fetch.py" validate --root "$cajunos_root"

gcc_source_dir=$cajunos_root/upstream/gcc

mapfile -t lock_values < <(python3 - "$lock_file" "$manifest_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    lock = json.load(stream)
with open(sys.argv[2], encoding="utf-8") as stream:
    manifest = json.load(stream)
print(lock["source_set_digest"])
print(lock["source_authentication"])
for wanted in ("gcc", "binutils", "glibc", "linux"):
    component = next(
        (value for value in lock["components"] if value["name"] == wanted), None
    )
    if component is None:
        raise SystemExit(f"{wanted} is absent from the bootstrap lock")
    print(component["commit"])
    print(component["tree"])
    print(component["repository"])
gcc = next(
    (value for value in manifest["components"] if value["name"] == "gcc"), None
)
if gcc is None:
    raise SystemExit("gcc is absent from the bootstrap manifest")
print(*gcc["license_files"], sep="\n")
PY
)
source_set_digest=${lock_values[0]}
source_authentication=${lock_values[1]}
locked_gcc_commit=${lock_values[2]}
locked_gcc_tree=${lock_values[3]}
gcc_repository=${lock_values[4]}
locked_binutils_commit=${lock_values[5]}
locked_binutils_tree=${lock_values[6]}
binutils_repository=${lock_values[7]}
locked_glibc_commit=${lock_values[8]}
locked_glibc_tree=${lock_values[9]}
glibc_repository=${lock_values[10]}
locked_linux_commit=${lock_values[11]}
locked_linux_tree=${lock_values[12]}
linux_repository=${lock_values[13]}
license_paths=("${lock_values[@]:14}")

if [[ $source_authentication != authenticated ]]; then
  if [[ ${CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES:-} != 1 ]]; then
    echo "This source cohort contains recorded unauthenticated transports." >&2
    echo "Set CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES=1 after reviewing the lock." >&2
    exit 75
  fi
  echo "WARNING: explicitly accepting the lock's recorded unauthenticated transports" >&2
fi
if [[ -n $(git -C "$project_root" status --porcelain) ]]; then
  echo "Refusing an official build from a dirty CajunOS orchestration checkout" >&2
  exit 76
fi
orchestration_commit=$(git -C "$project_root" rev-parse HEAD)
orchestration_tree=$(git -C "$project_root" rev-parse 'HEAD^{tree}')

jobs=${CAJUNOS_JOBS:-6}
if [[ ! $jobs =~ ^[1-9][0-9]*$ ]]; then
  echo "CAJUNOS_JOBS must be a positive integer" >&2
  exit 77
fi
export MAKEFLAGS="-j$jobs"
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git -C "$gcc_source_dir" show -s --format=%ct "$locked_gcc_commit")
build_triplet=$("$gcc_source_dir/config.guess")

work_root=$cajunos_root/work/toolchain
tools_root=$cajunos_root/tools
artifacts_root=$cajunos_root/artifacts
logs_root=$cajunos_root/logs
cohort_id=${source_set_digest#sha256:}
cohort_id=${cohort_id:0:16}
sysroot=$cajunos_root/sysroot/$cohort_id

"$script_path" --internal-python ensure-directories "$cajunos_root" \
  work work/toolchain tools artifacts logs sysroot "sysroot/$cohort_id"

# Resolve the active glibc bootstrap snapshot and its complete sealed chain.
# The same resolver is rerun immediately before publication to close TOCTOU.
resolve_dependencies() {
python3 - \
  "$inventory_helper" \
  "$tools_root" \
  "$artifacts_root" \
  "$sysroot" \
  "$source_set_digest" \
  "$source_authentication" \
  "$target" \
  "$locked_gcc_commit" \
  "$locked_gcc_tree" \
  "$gcc_repository" \
  "$locked_binutils_commit" \
  "$locked_binutils_tree" \
  "$locked_glibc_commit" \
  "$locked_glibc_tree" \
  "$locked_linux_commit" \
  "$locked_linux_tree" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

(
    helper, tools_value, artifacts_value, sysroot_value, source_set_digest,
    source_authentication, target, gcc_commit, gcc_tree, gcc_repository,
    binutils_commit, binutils_tree, glibc_commit, glibc_tree, linux_commit,
    linux_tree,
) = sys.argv[1:]
tools = Path(tools_value)
artifacts = Path(artifacts_value)
sysroot = Path(sysroot_value)

def fail(message):
    raise SystemExit(message)

def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def load_plain(path, label):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail(f"{label} does not exist")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail(f"{label} is not a plain single-linked file")
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)

def helper_json(command, *args):
    result = subprocess.run(
        [helper, "--internal-python", command, *(str(value) for value in args)],
        check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode:
        fail(result.stderr.strip() or f"inventory helper failed: {command}")
    return json.loads(result.stdout)

def dependency_inventory(prefix):
    value = helper_json("dependency-inventory", prefix, tools)
    if not isinstance(value, dict):
        fail("invalid dependency inventory")
    return value

def snapshot_inventory(snapshot):
    value = helper_json("inventory", snapshot)
    if not isinstance(value, dict) or not isinstance(value.get("entries"), dict):
        fail("invalid snapshot inventory")
    return value

if not (sysroot / "usr").is_symlink() or os.readlink(sysroot / "usr") != "current/usr":
    fail("cohort sysroot has an invalid usr selector")
current = sysroot / "current"
if not current.is_symlink():
    fail("cohort sysroot lacks its current selector")
selected_target = os.readlink(current)
match = re.fullmatch(r"snapshots/([A-Za-z0-9][A-Za-z0-9._-]{0,127})", selected_target)
if not match:
    fail("cohort current selector is unsafe")
glibc_id = match.group(1)
glibc_snapshot = sysroot / "snapshots" / glibc_id
if not glibc_snapshot.is_dir() or glibc_snapshot.is_symlink():
    fail("active glibc snapshot is not a real directory")
glibc_receipt_path = artifacts / glibc_id / "receipt.json"
glibc_receipt = load_plain(glibc_receipt_path, "glibc receipt")
glibc_inventory = snapshot_inventory(glibc_snapshot)
if (
    glibc_receipt.get("schema") != 1
    or glibc_receipt.get("component") != "glibc"
    or glibc_receipt.get("stage") != "headers-startfiles"
    or glibc_receipt.get("build_id") != glibc_id
    or glibc_receipt.get("source_commit") != glibc_commit
    or glibc_receipt.get("source_tree") != glibc_tree
    or glibc_receipt.get("source_set_digest") != source_set_digest
    or glibc_receipt.get("source_authentication") != source_authentication
    or glibc_receipt.get("target") != target
    or glibc_receipt.get("sysroot") != str(sysroot)
    or glibc_receipt.get("snapshot") != str(glibc_snapshot)
    or glibc_receipt.get("functional_libc") != "absent"
    or glibc_receipt.get("installed_entries") != glibc_inventory["entries"]
    or glibc_receipt.get("result_snapshot_digest") != f"sha256:{glibc_inventory['digest']}"
):
    fail("active glibc bootstrap receipt or snapshot is invalid")

dependencies = glibc_receipt.get("dependencies")
if not isinstance(dependencies, dict):
    fail("glibc receipt lacks its dependency chain")

def dependency(name, component, stage, commit, tree):
    value = dependencies.get(name)
    if not isinstance(value, dict):
        fail(f"glibc receipt lacks {name} dependency")
    receipt_path = Path(str(value.get("receipt", "")))
    receipt = load_plain(receipt_path, f"{name} receipt")
    if sha256(receipt_path) != value.get("receipt_sha256"):
        fail(f"{name} dependency receipt hash is invalid")
    if (
        receipt.get("schema") != 1
        or receipt.get("component") != component
        or receipt.get("stage") != stage
        or receipt.get("build_id") != value.get("build_id")
        or receipt.get("source_commit") != commit
        or receipt.get("source_tree") != tree
        or receipt.get("source_set_digest") != source_set_digest
        or receipt.get("source_authentication") != source_authentication
        or receipt.get("target") != target
    ):
        fail(f"{name} dependency provenance is invalid")
    return value, receipt_path, receipt

gcc_value, gcc_receipt_path, gcc_receipt = dependency(
    "gcc", "gcc", "stage1", gcc_commit, gcc_tree
)
gcc_prefix = Path(str(gcc_value.get("prefix", "")))
if gcc_prefix != tools / str(gcc_value.get("build_id", "")):
    fail("GCC dependency prefix has invalid identity")
if gcc_receipt.get("source_repository") != gcc_repository:
    fail("GCC source repository provenance is invalid")
if gcc_receipt.get("prefix") != str(gcc_prefix) or gcc_receipt.get("sysroot") != str(sysroot):
    fail("GCC dependency prefix/sysroot contract is invalid")
if dependency_inventory(gcc_prefix) != gcc_receipt.get("installed_entries"):
    fail("GCC dependency prefix failed full inventory validation")

binutils_value, binutils_receipt_path, binutils_receipt = dependency(
    "binutils", "binutils", "stage1", binutils_commit, binutils_tree
)
binutils_prefix = Path(str(binutils_value.get("prefix", "")))
if binutils_prefix != tools / str(binutils_value.get("build_id", "")):
    fail("Binutils dependency prefix has invalid identity")
if binutils_receipt.get("prefix") != str(binutils_prefix):
    fail("Binutils dependency receipt has invalid prefix")
if dependency_inventory(binutils_prefix) != binutils_receipt.get("installed_entries"):
    fail("Binutils dependency prefix failed full inventory validation")
gcc_binutils = gcc_receipt.get("dependencies", {}).get("binutils", {})
if (
    gcc_binutils.get("build_id") != binutils_value.get("build_id")
    or gcc_binutils.get("receipt_sha256") != binutils_value.get("receipt_sha256")
):
    fail("GCC and glibc disagree about the sealed Binutils dependency")

linux_value, linux_receipt_path, linux_receipt = dependency(
    "linux", "linux", "uapi-headers", linux_commit, linux_tree
)
linux_snapshot = Path(str(linux_value.get("snapshot", "")))
linux_inventory = snapshot_inventory(linux_snapshot)
if (
    linux_receipt.get("snapshot") != str(linux_snapshot)
    or linux_receipt.get("installed_entries") != linux_inventory["entries"]
    or linux_receipt.get("result_snapshot_digest") != f"sha256:{linux_inventory['digest']}"
    or linux_value.get("snapshot_digest") != f"sha256:{linux_inventory['digest']}"
):
    fail("Linux dependency snapshot failed full inventory validation")

print(gcc_value["build_id"])
print(gcc_prefix)
print(gcc_receipt_path)
print(sha256(gcc_receipt_path))
print(binutils_value["build_id"])
print(binutils_prefix)
print(binutils_receipt_path)
print(sha256(binutils_receipt_path))
print(glibc_id)
print(glibc_snapshot)
print(glibc_receipt_path)
print(sha256(glibc_receipt_path))
print(f"sha256:{glibc_inventory['digest']}")
print(linux_value["build_id"])
print(linux_snapshot)
print(linux_receipt_path)
print(sha256(linux_receipt_path))
print(f"sha256:{linux_inventory['digest']}")
PY
}
mapfile -t dependency_values < <(resolve_dependencies)
gcc_build_id=${dependency_values[0]}
gcc_prefix=${dependency_values[1]}
gcc_receipt=${dependency_values[2]}
gcc_receipt_sha256=${dependency_values[3]}
binutils_build_id=${dependency_values[4]}
binutils_prefix=${dependency_values[5]}
binutils_receipt=${dependency_values[6]}
binutils_receipt_sha256=${dependency_values[7]}
glibc_build_id=${dependency_values[8]}
glibc_snapshot=${dependency_values[9]}
glibc_receipt=${dependency_values[10]}
glibc_receipt_sha256=${dependency_values[11]}
glibc_snapshot_digest=${dependency_values[12]}
linux_build_id=${dependency_values[13]}
linux_snapshot=${dependency_values[14]}
linux_receipt=${dependency_values[15]}
linux_receipt_sha256=${dependency_values[16]}
linux_snapshot_digest=${dependency_values[17]}

gcc_version=$("$gcc_prefix/bin/$target-gcc" -dumpfullversion)
if [[ ! $gcc_version =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
  echo "Sealed GCC reported an unsafe version: $gcc_version" >&2
  exit 78
fi

configure_args=(
  "--build=$build_triplet"
  "--host=$build_triplet"
  "--target=$target"
  "--with-sysroot=$sysroot"
  "--with-build-sysroot=$glibc_snapshot"
  "--with-native-system-header-dir=/usr/include"
  "--with-build-time-tools=$binutils_prefix/$target/bin"
  "--with-as=$binutils_prefix/bin/$target-as"
  "--with-ld=$binutils_prefix/bin/$target-ld"
  "--with-glibc-version=2.44"
  "--with-arch=x86-64-v2"
  "--with-tune=generic"
  "--enable-languages=c"
  "--disable-bootstrap"
  "--disable-multilib"
  "--disable-shared"
  "--disable-threads"
  "--disable-gcov"
  "--disable-nls"
  "--disable-werror"
  "--disable-lto"
  "--disable-fixincludes"
  "--without-isl"
  "--without-zstd"
)
configure_digest=$(printf '%s\0' "${configure_args[@]}" | sha256sum | awk '{print $1}')
recipe_sha256=$(sha256sum "$script_path" | awk '{print $1}')
inventory_helper_sha256=$(sha256sum "$inventory_helper" | awk '{print $1}')
base_inventory_digest=$("$script_path" --internal-python dependency-inventory \
  "$gcc_prefix" "$tools_root" | sha256sum | awk '{print $1}')
build_id=$("$script_path" --internal-python build-id "$locked_gcc_commit" \
  source_set_digest "$source_set_digest" \
  source_tree "$locked_gcc_tree" \
  orchestration_commit "$orchestration_commit" \
  orchestration_tree "$orchestration_tree" \
  recipe_sha256 "$recipe_sha256" \
  inventory_helper_sha256 "$inventory_helper_sha256" \
  configure_digest "$configure_digest" \
  target_cflags "$target_cflags" \
  libgcc2_debug_cflags -g0 \
  gcc_receipt_sha256 "$gcc_receipt_sha256" \
  binutils_receipt_sha256 "$binutils_receipt_sha256" \
  glibc_receipt_sha256 "$glibc_receipt_sha256" \
  linux_receipt_sha256 "$linux_receipt_sha256" \
  glibc_snapshot_digest "$glibc_snapshot_digest" \
  linux_snapshot_digest "$linux_snapshot_digest" \
  base_inventory_digest "$base_inventory_digest")

run_id=${CAJUNOS_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
if [[ ! $run_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "Unsafe CAJUNOS_RUN_ID: $run_id" >&2
  exit 79
fi

build_final=$work_root/$build_id
prefix_final=$tools_root/$build_id
artifact_final=$artifacts_root/$build_id
receipt_final=$artifact_final/receipt.json
log_dir=$logs_root/$run_id
log_file=$log_dir/libgcc-bootstrap.log
temporary_root=$work_root/.tmp-$build_id-$$
build_a=$temporary_root/build-a
build_b=$temporary_root/build-b
# Keep unpublished prefixes at final-prefix depth so relative dependency links
# resolve identically and the managed tools-root inventory guard can attest them.
candidate_a=$tools_root/.tmp-$build_id-a-$$
candidate_b=$tools_root/.tmp-$build_id-b-$$
overlay_a=$temporary_root/overlay-a
overlay_b=$temporary_root/overlay-b
artifact_temporary=$artifacts_root/.tmp-$build_id-$$
failed_root=$work_root/.failed-$build_id-$$
failed_artifact=$artifacts_root/.failed-$build_id-$$

exec 9>"$cajunos_root/work/.cajunos-build.lock"
if ! flock -n 9; then
  echo "Another CajunOS build owns the global build lock" >&2
  exit 80
fi

if [[ -d $build_final && ! -L $build_final \
   && -d $prefix_final && ! -L $prefix_final \
   && -d $artifact_final && ! -L $artifact_final \
   && -f $receipt_final && ! -L $receipt_final ]]; then
  "$script_path" --internal-python validate-completed \
    "$receipt_final" "$prefix_final" "$gcc_prefix" "$tools_root" \
    "$target" "$gcc_version" \
    schema 1 component gcc stage libgcc-bootstrap build_id "$build_id" \
    source_commit "$locked_gcc_commit" source_tree "$locked_gcc_tree" \
    source_set_digest "$source_set_digest" source_authentication "$source_authentication" \
    target "$target" build_triplet "$build_triplet" prefix "$prefix_final" \
    source_repository "$gcc_repository" gcc_version "$gcc_version" \
    target_cflags "$target_cflags" libgcc2_debug_cflags -g0 \
    base_prefix "$gcc_prefix" sysroot "$sysroot" \
    sysroot_snapshot "$glibc_snapshot" sysroot_snapshot_digest "$glibc_snapshot_digest" \
    sysroot_modified False runtime_contract.functional_libc absent \
    runtime_contract.shared_runtime absent runtime_contract.thread_model single \
    runtime_contract.multilib disabled runtime_contract.gcov_runtime absent \
    base_build_id "$gcc_build_id" orchestration_commit "$orchestration_commit" \
    orchestration_tree "$orchestration_tree" recipe_sha256 "$recipe_sha256" \
    dependencies.gcc.receipt_sha256 "$gcc_receipt_sha256" \
    dependencies.binutils.receipt_sha256 "$binutils_receipt_sha256" \
    dependencies.glibc.receipt_sha256 "$glibc_receipt_sha256" \
    dependencies.linux.receipt_sha256 "$linux_receipt_sha256"
  "$script_path" --internal-python selector-transition \
    "$tools_root" "$artifacts_root" "$gcc_build_id" "$build_id" >/dev/null
  echo "CAJUNOS_LIBGCC_BOOTSTRAP_ALREADY_COMPLETE build_id=$build_id"
  exit 0
fi

if [[ -e $build_final || -L $build_final \
   || -e $prefix_final || -L $prefix_final \
   || -e $artifact_final || -L $artifact_final ]]; then
  echo "Refusing to reuse an incomplete published build: $build_id" >&2
  exit 81
fi
if [[ -e $temporary_root || -L $temporary_root \
   || -e $candidate_a || -L $candidate_a \
   || -e $candidate_b || -L $candidate_b \
   || -e $artifact_temporary || -L $artifact_temporary \
   || -e $failed_root || -L $failed_root \
   || -e $failed_artifact || -L $failed_artifact \
   || -e $log_dir || -L $log_dir ]]; then
  echo "Refusing colliding temporary or log path for run $run_id" >&2
  exit 82
fi
selector_state=$("$script_path" --internal-python selector-state \
  "$tools_root" "$artifacts_root" "$gcc_build_id" "$build_id")
if [[ $selector_state != base ]]; then
  echo "Fresh libgcc build requires tools/current to select exact GCC base" >&2
  exit 83
fi

build_succeeded=0
on_exit() {
  local status=$?
  if (( status != 0 || build_succeeded == 0 )); then
    if [[ -d $temporary_root && ! -L $temporary_root ]]; then
      if [[ -e $candidate_a || -L $candidate_a ]]; then
        mv -T -- "$candidate_a" "$temporary_root/candidate-a"
      fi
      if [[ -e $candidate_b || -L $candidate_b ]]; then
        mv -T -- "$candidate_b" "$temporary_root/candidate-b"
      fi
      mv -T -- "$temporary_root" "$failed_root"
    elif [[ -e $temporary_root || -L $temporary_root \
         || -e $candidate_a || -L $candidate_a \
         || -e $candidate_b || -L $candidate_b ]]; then
      mkdir -- "$failed_root"
      if [[ -e $temporary_root || -L $temporary_root ]]; then
        mv -T -- "$temporary_root" "$failed_root/temporary-root-entry"
      fi
      if [[ -e $candidate_a || -L $candidate_a ]]; then
        mv -T -- "$candidate_a" "$failed_root/candidate-a"
      fi
      if [[ -e $candidate_b || -L $candidate_b ]]; then
        mv -T -- "$candidate_b" "$failed_root/candidate-b"
      fi
    fi
    if [[ -e $artifact_temporary || -L $artifact_temporary ]]; then
      mv -T -- "$artifact_temporary" "$failed_artifact"
    fi
  fi
}
trap on_exit EXIT
mkdir -p "$build_a" "$build_b" "$candidate_a" "$candidate_b" \
  "$overlay_a" "$overlay_b" "$artifact_temporary" "$log_dir"
exec > >(tee "$log_file") 2>&1

echo "CajunOS bootstrap libgcc"
echo "build_id=$build_id"
echo "source=$locked_gcc_commit"
echo "source_set=$source_set_digest"
echo "source_authentication=$source_authentication"
echo "orchestration=$orchestration_commit"
echo "base_gcc=$gcc_build_id"
echo "glibc_headers=$glibc_build_id"
echo "target=$target"
echo "prefix=$prefix_final"
echo "sysroot=$sysroot"
echo "makeflags=$MAKEFLAGS"

printf '%s\n' "${configure_args[@]}" > "$artifact_temporary/configure.args"
"$script_path" --internal-python dependency-inventory \
  "$gcc_prefix" "$tools_root" > "$artifact_temporary/base-before.json"
"$script_path" --internal-python inventory \
  "$glibc_snapshot" > "$artifact_temporary/sysroot-before.json"

export PATH="$binutils_prefix/bin:/usr/bin:/bin"

build_one() {
  local build=$1 candidate=$2 overlay=$3 label=$4
  CONFIG_SHELL=/bin/bash CC=/usr/bin/gcc CXX=/usr/bin/g++ \
    "$gcc_source_dir/configure" --prefix="$prefix_final" "${configure_args[@]}" \
    > "$artifact_temporary/$label.configure.stdout" 2>&1
  make -j1 -C "$build" configure-gcc
  grep -Eq '^STMP_FIXINC[[:space:]]*=[[:space:]]*$' "$build/gcc/Makefile" || {
    echo "Locked GCC did not honor --disable-fixincludes" >&2
    return 1
  }
  grep -Fqx "TARGET_SYSTEM_ROOT = $sysroot" "$build/gcc/Makefile" || {
    echo "Locked GCC configured an unexpected target sysroot" >&2
    return 1
  }
  "$script_path" --internal-python gcc-header-contract \
    "$build/gcc/Makefile" "$sysroot" "$glibc_snapshot" || {
    echo "Locked GCC configured an unexpected header/sysroot contract" >&2
    return 1
  }
  make -C "$build" all-gcc
  make -j1 -C "$build" configure-target-libgcc
  local libgcc_build=$build/$target/libgcc
  [[ -f $libgcc_build/Makefile ]] || {
    echo "Target libgcc configuration did not produce a Makefile" >&2
    return 1
  }
  "$script_path" --internal-python libgcc-make-contract \
    "$libgcc_build/Makefile" "$build/gcc" "$glibc_snapshot" || {
    echo "Target libgcc configured an unexpected Make contract" >&2
    return 1
  }
  make -C "$libgcc_build" \
    CFLAGS="$target_cflags" LIBGCC2_DEBUG_CFLAGS=-g0 all
  make -j1 -C "$libgcc_build" \
    CFLAGS="$target_cflags" LIBGCC2_DEBUG_CFLAGS=-g0 \
    DESTDIR="$overlay" install
  rsync -a -- "$gcc_prefix/" "$candidate/"
  "$script_path" --internal-python no-shared-inodes "$gcc_prefix" "$candidate"
  staged_prefix=$overlay$prefix_final
  [[ -d $staged_prefix ]] || {
    echo "Target libgcc install did not stage its configured prefix" >&2
    return 1
  }
  rsync -a -- "$staged_prefix/" "$candidate/"
  "$script_path" --internal-python write-delta \
    "$gcc_prefix" "$candidate" "$tools_root" "$target" "$gcc_version" \
    "$artifact_temporary/delta-$label.json"
  if grep -R -a -F -l -- "$build" \
    "$candidate/lib/gcc/$target/$gcc_version" | grep -q .; then
    echo "Published runtime contains its disposable build path" >&2
    return 1
  fi
}

(
  cd "$build_a"
  build_one "$build_a" "$candidate_a" "$overlay_a" a
)
(
  cd "$build_b"
  build_one "$build_b" "$candidate_b" "$overlay_b" b
)

"$script_path" --internal-python dependency-inventory \
  "$candidate_a" "$tools_root" > "$artifact_temporary/inventory-a.json"
"$script_path" --internal-python dependency-inventory \
  "$candidate_b" "$tools_root" > "$artifact_temporary/inventory-b.json"
"$script_path" --internal-python compare-json \
  "$artifact_temporary/inventory-a.json" "$artifact_temporary/inventory-b.json"
"$script_path" --internal-python compare-json \
  "$artifact_temporary/delta-a.json" "$artifact_temporary/delta-b.json"

probe_dir=$artifact_temporary/probe
configuration_dir=$artifact_temporary/configuration
license_dir=$artifact_temporary/licenses/gcc
mkdir -p "$probe_dir" "$configuration_dir" "$license_dir"
cp -- "$build_a/config.log" "$configuration_dir/build-a.config.log"
cp -- "$build_b/config.log" "$configuration_dir/build-b.config.log"
cp -- "$build_a/$target/libgcc/config.log" \
  "$configuration_dir/build-a.libgcc.config.log"
cp -- "$build_b/$target/libgcc/config.log" \
  "$configuration_dir/build-b.libgcc.config.log"

gcc_driver=$candidate_a/bin/$target-gcc
runtime_dir=$candidate_a/lib/gcc/$target/$gcc_version
[[ -x $gcc_driver ]] || { echo "Derived prefix lacks GCC driver" >&2; exit 84; }
[[ $($gcc_driver -dumpmachine) == "$target" ]] || {
  echo "Derived GCC reports unexpected target" >&2
  exit 85
}
[[ $($gcc_driver -print-sysroot) == "$sysroot" ]] || {
  echo "Derived GCC reports unexpected sysroot" >&2
  exit 86
}
[[ $($gcc_driver -print-multi-lib) == '.;' ]] || {
  echo "Derived GCC unexpectedly enables multilib" >&2
  exit 87
}
cc1_path=$($gcc_driver -print-prog-name=cc1)
[[ -x $cc1_path && $cc1_path == "$candidate_a"/* ]] || {
  echo "Derived GCC did not relocate cc1 into its own prefix" >&2
  exit 88
}
for program in as ld; do
  resolved=$($gcc_driver -print-prog-name="$program")
  expected=$binutils_prefix/bin/$target-$program
  [[ $(readlink -f -- "$resolved") == $(readlink -f -- "$expected") ]] || {
    echo "Derived GCC resolved unexpected $program: $resolved" >&2
    exit 89
  }
done

declare -a lookup_files=(
  libgcc.a crtbegin.o crtbeginS.o crtbeginT.o crtend.o crtendS.o
  crtfastmath.o crtprec32.o crtprec64.o crtprec80.o
)
{
  printf 'libgcc.a=%s\n' "$($gcc_driver -print-libgcc-file-name)"
  for name in "${lookup_files[@]:1}"; do
    printf '%s=%s\n' "$name" "$($gcc_driver -print-file-name="$name")"
  done
} > "$probe_dir/runtime-lookups.txt"
"$script_path" --internal-python runtime-lookups-contract \
  "$runtime_dir" "$probe_dir/runtime-lookups.txt" || exit 90

printf '#include <unwind.h>\n_Unwind_Reason_Code cajunos_unwind(void);\n' |
  "$gcc_driver" -std=c11 -Wall -Werror -ffreestanding -fsyntax-only -x c - \
    > "$probe_dir/unwind-compile.stdout" \
    2> "$probe_dir/unwind-compile.stderr"

"$binutils_prefix/bin/$target-ar" t "$runtime_dir/libgcc.a" \
  > "$probe_dir/libgcc.members"
[[ -s $probe_dir/libgcc.members ]] || {
  echo "Static libgcc archive has no members" >&2
  exit 91
}
"$binutils_prefix/bin/$target-nm" -A "$runtime_dir/libgcc.a" \
  > "$probe_dir/libgcc.nm"
grep -Eq '[[:space:]][TW][[:space:]]+__udivti3$' "$probe_dir/libgcc.nm" || {
  echo "Static libgcc lacks __udivti3" >&2
  exit 92
}
grep -Eq '[[:space:]][TW][[:space:]]+_Unwind_RaiseException$' \
  "$probe_dir/libgcc.nm" || {
  echo "Static libgcc lacks unwind implementation" >&2
  exit 93
}

declare -a crt_files=(
  crtbegin.o crtbeginS.o crtbeginT.o crtend.o crtendS.o
  crtfastmath.o crtprec32.o crtprec64.o crtprec80.o
)
for name in "${crt_files[@]}"; do
  "$binutils_prefix/bin/$target-readelf" -h "$runtime_dir/$name" \
    > "$probe_dir/$name.readelf-h"
  "$binutils_prefix/bin/$target-readelf" -SW "$runtime_dir/$name" \
    > "$probe_dir/$name.readelf-SW"
  grep -q 'Class:.*ELF64' "$probe_dir/$name.readelf-h"
  grep -q 'Type:.*REL' "$probe_dir/$name.readelf-h"
  grep -q 'Machine:.*Advanced Micro Devices X86-64' "$probe_dir/$name.readelf-h"
  if grep -E '\.note\.GNU-stack.*[[:space:]]X[[:space:]]' \
    "$probe_dir/$name.readelf-SW"; then
    echo "$name requests an executable stack" >&2
    exit 94
  fi
done

cat > "$probe_dir/start.c" <<'EOF'
typedef unsigned __int128 cajunos_u128;

static volatile cajunos_u128 numerator = ((cajunos_u128)1 << 100) + 0x12345;
static volatile cajunos_u128 denominator = ((cajunos_u128)1 << 67) + 3;

__attribute__((noreturn)) void _start(void)
{
    unsigned long quotient = (unsigned long)(numerator / denominator);
    long status = quotient == 0;
    __asm__ volatile (
        "syscall"
        :
        : "a" (60L), "D" (status)
        : "rcx", "r11", "memory");
    __builtin_unreachable();
}
EOF
"$gcc_driver" \
  -O2 -ffreestanding -fno-stack-protector -fno-pie -no-pie \
  -nostdlib -nostartfiles -nodefaultlibs -Wl,-e,_start \
  -Wl,-Map,"$probe_dir/start.map" \
  "$probe_dir/start.c" -lgcc -o "$probe_dir/start"
"$binutils_prefix/bin/$target-readelf" -h "$probe_dir/start" \
  > "$probe_dir/start.readelf-h"
"$binutils_prefix/bin/$target-readelf" -l "$probe_dir/start" \
  > "$probe_dir/start.readelf-l"
"$binutils_prefix/bin/$target-readelf" -d "$probe_dir/start" \
  > "$probe_dir/start.readelf-d"
"$binutils_prefix/bin/$target-nm" -u "$probe_dir/start" \
  > "$probe_dir/start.undefined"
[[ ! -s $probe_dir/start.undefined ]] || {
  echo "Freestanding libgcc probe retains undefined symbols" >&2
  exit 95
}
if grep -Eq 'INTERP|DYNAMIC' "$probe_dir/start.readelf-l"; then
  echo "Freestanding libgcc probe unexpectedly requires a loader" >&2
  exit 96
fi
grep -F "$runtime_dir/libgcc.a" "$probe_dir/start.map" >/dev/null || {
  echo "Link map does not name the derived libgcc archive" >&2
  exit 97
}
if grep -F "$gcc_prefix/lib/gcc/$target/$gcc_version/libgcc.a" \
  "$probe_dir/start.map"; then
  echo "Link map leaked the sealed headerless compiler prefix" >&2
  exit 98
fi
"$probe_dir/start"

"$script_path" --internal-python dependency-inventory \
  "$candidate_a" "$tools_root" > "$artifact_temporary/inventory-after-probe.json"
"$script_path" --internal-python compare-json \
  "$artifact_temporary/inventory-a.json" \
  "$artifact_temporary/inventory-after-probe.json"
"$script_path" --internal-python dependency-inventory \
  "$gcc_prefix" "$tools_root" > "$artifact_temporary/base-after.json"
"$script_path" --internal-python compare-json \
  "$artifact_temporary/base-before.json" "$artifact_temporary/base-after.json"
"$script_path" --internal-python inventory \
  "$glibc_snapshot" > "$artifact_temporary/sysroot-after.json"
"$script_path" --internal-python compare-json \
  "$artifact_temporary/sysroot-before.json" "$artifact_temporary/sysroot-after.json"

# Close source and receipt TOCTOU windows before publication.
"$project_root/scripts/fetch.py" validate --root "$cajunos_root"
if [[ -n $(git -C "$project_root" status --porcelain) \
   || $(git -C "$project_root" rev-parse HEAD) != "$orchestration_commit" \
   || $(git -C "$project_root" rev-parse 'HEAD^{tree}') != "$orchestration_tree" \
   || $(sha256sum "$script_path" | awk '{print $1}') != "$recipe_sha256" \
   || $(sha256sum "$inventory_helper" | awk '{print $1}') != "$inventory_helper_sha256" ]]; then
  echo "CajunOS orchestration or frozen helper changed during the build" >&2
  exit 99
fi
mapfile -t dependency_values_after < <(resolve_dependencies)
if (( ${#dependency_values_after[@]} != ${#dependency_values[@]} )); then
  echo "Sealed dependency chain changed length during the build" >&2
  exit 100
fi
for index in "${!dependency_values[@]}"; do
  if [[ ${dependency_values_after[index]} != "${dependency_values[index]}" ]]; then
    echo "Sealed dependency chain changed during the build" >&2
    exit 101
  fi
done
selector_state=$("$script_path" --internal-python selector-state \
  "$tools_root" "$artifacts_root" "$gcc_build_id" "$build_id")
if [[ $selector_state != base ]]; then
  echo "tools/current changed before libgcc publication" >&2
  exit 102
fi

git -C "$gcc_source_dir" archive "$locked_gcc_commit" -- "${license_paths[@]}" |
  tar -x -C "$license_dir"
"$script_path" --internal-python inventory "$license_dir" \
  > "$artifact_temporary/license-inventory.json"

python3 - \
  "$artifact_temporary/receipt.json" \
  "$artifact_temporary/inventory-a.json" \
  "$artifact_temporary/base-before.json" \
  "$artifact_temporary/delta-a.json" \
  "$artifact_temporary/sysroot-before.json" \
  "$artifact_temporary/license-inventory.json" \
  "$artifact_temporary/configure.args" \
  "$probe_dir" \
  "$configuration_dir" \
  "$build_id" \
  "$locked_gcc_commit" \
  "$locked_gcc_tree" \
  "$gcc_repository" \
  "$source_set_digest" \
  "$source_authentication" \
  "$SOURCE_DATE_EPOCH" \
  "$target" \
  "$build_triplet" \
  "$gcc_version" \
  "$target_cflags" \
  "$prefix_final" \
  "$gcc_prefix" \
  "$gcc_build_id" \
  "$sysroot" \
  "$glibc_snapshot" \
  "$glibc_snapshot_digest" \
  "$orchestration_commit" \
  "$orchestration_tree" \
  "$recipe_sha256" \
  "$inventory_helper_sha256" \
  "$configure_digest" \
  "$log_file" \
  "$gcc_receipt" "$gcc_receipt_sha256" \
  "$binutils_build_id" "$binutils_prefix" "$binutils_receipt" "$binutils_receipt_sha256" \
  "$glibc_build_id" "$glibc_receipt" "$glibc_receipt_sha256" \
  "$linux_build_id" "$linux_snapshot" "$linux_snapshot_digest" \
  "$linux_receipt" "$linux_receipt_sha256" \
  "$locked_binutils_commit" "$locked_binutils_tree" "$binutils_repository" \
  "$locked_glibc_commit" "$locked_glibc_tree" "$glibc_repository" \
  "$locked_linux_commit" "$locked_linux_tree" "$linux_repository" <<'PY'
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
    output_value, result_inventory_value, base_inventory_value, delta_value,
    sysroot_inventory_value, license_inventory_value, configure_args_value,
    probe_value, configuration_value, build_id, commit, tree, repository,
    source_set_digest, source_authentication, source_date_epoch, target,
    build_triplet, gcc_version, target_cflags, prefix, base_prefix,
    base_build_id, sysroot, glibc_snapshot, glibc_snapshot_digest,
    orchestration_commit, orchestration_tree, recipe_sha256,
    inventory_helper_sha256, configure_digest, log_file, gcc_receipt,
    gcc_receipt_sha256, binutils_build_id, binutils_prefix, binutils_receipt,
    binutils_receipt_sha256, glibc_build_id, glibc_receipt,
    glibc_receipt_sha256, linux_build_id, linux_snapshot, linux_snapshot_digest,
    linux_receipt, linux_receipt_sha256, binutils_commit, binutils_tree,
    binutils_repository,
    glibc_commit, glibc_tree, glibc_repository, linux_commit, linux_tree,
    linux_repository,
) = sys.argv[1:]

def load(path):
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream)

def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def regular_hashes(root_value):
    root = Path(root_value)
    return {
        path.relative_to(root).as_posix(): sha256(path)
        for path in sorted(root.rglob("*")) if path.is_file()
    }

def first_line(*argv):
    return subprocess.run(
        argv, check=True, text=True, stdout=subprocess.PIPE
    ).stdout.splitlines()[0]

result_entries = load(result_inventory_value)
base_entries = load(base_inventory_value)
delta = load(delta_value)
sysroot_inventory = load(sysroot_inventory_value)
license_inventory = load(license_inventory_value)
configure_args = Path(configure_args_value).read_text(encoding="utf-8").splitlines()
runtime_sha256 = {
    path: metadata["sha256"] for path, metadata in delta["added_entries"].items()
}
archive = Path(prefix) / f"lib/gcc/{target}/{gcc_version}/libgcc.a"
members = Path(probe_value, "libgcc.members").read_text(encoding="utf-8").splitlines()

packages = {}
for package in ("gcc", "g++", "make", "rsync", "binutils"):
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Version}", package], check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    packages[package] = result.stdout if result.returncode == 0 else None

receipt = {
    "schema": 1,
    "build_id": build_id,
    "component": "gcc",
    "stage": "libgcc-bootstrap",
    "source_commit": commit,
    "source_tree": tree,
    "source_repository": repository,
    "source_set_digest": source_set_digest,
    "source_authentication": source_authentication,
    "source_date_epoch": int(source_date_epoch),
    "target": target,
    "build_triplet": build_triplet,
    "gcc_version": gcc_version,
    "target_cflags": target_cflags,
    "libgcc2_debug_cflags": "-g0",
    "prefix": prefix,
    "base_prefix": base_prefix,
    "base_build_id": base_build_id,
    "sysroot": sysroot,
    "sysroot_snapshot": glibc_snapshot,
    "sysroot_snapshot_digest": glibc_snapshot_digest,
    "sysroot_modified": False,
    "runtime_contract": {
        "functional_libc": "absent",
        "shared_runtime": "absent",
        "thread_model": "single",
        "multilib": "disabled",
        "gcov_runtime": "absent",
        "unwind_implementation": "inside-static-libgcc",
    },
    "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    "log": log_file,
    "orchestration_commit": orchestration_commit,
    "orchestration_tree": orchestration_tree,
    "recipe_sha256": recipe_sha256,
    "inventory_helper_sha256": inventory_helper_sha256,
    "configure_digest": configure_digest,
    "configure_args": configure_args,
    "dependencies": {
        "gcc": {
            "build_id": base_build_id,
            "prefix": base_prefix,
            "receipt": gcc_receipt,
            "receipt_sha256": gcc_receipt_sha256,
            "source_commit": commit,
            "source_tree": tree,
        },
        "binutils": {
            "build_id": binutils_build_id,
            "prefix": binutils_prefix,
            "receipt": binutils_receipt,
            "receipt_sha256": binutils_receipt_sha256,
            "source_commit": binutils_commit,
            "source_tree": binutils_tree,
            "source_repository": binutils_repository,
        },
        "glibc": {
            "build_id": glibc_build_id,
            "snapshot": glibc_snapshot,
            "receipt": glibc_receipt,
            "receipt_sha256": glibc_receipt_sha256,
            "source_commit": glibc_commit,
            "source_tree": glibc_tree,
            "source_repository": glibc_repository,
            "functional_libc": "absent",
        },
        "linux": {
            "build_id": linux_build_id,
            "snapshot": linux_snapshot,
            "snapshot_digest": linux_snapshot_digest,
            "receipt": linux_receipt,
            "receipt_sha256": linux_receipt_sha256,
            "source_commit": linux_commit,
            "source_tree": linux_tree,
            "source_repository": linux_repository,
        },
    },
    "installed_entries": result_entries,
    "base_prefix_digest": f"sha256:{hashlib.sha256(json.dumps(base_entries, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}",
    "result_prefix_digest": f"sha256:{hashlib.sha256(json.dumps(result_entries, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}",
    "delta": delta,
    "runtime_sha256": runtime_sha256,
    "archive": {
        "path": str(archive),
        "sha256": runtime_sha256[f"lib/gcc/{target}/{gcc_version}/libgcc.a"],
        "members": members,
        "members_digest": hashlib.sha256(
            "\n".join(members).encode("utf-8") + b"\n"
        ).hexdigest(),
    },
    "reproducibility": {
        "independent_builds": 2,
        "inventory_schema": "paths-types-modes-sha256-symlink-targets-v1",
        "first_inventory_digest": f"sha256:{hashlib.sha256(json.dumps(result_entries, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}",
        "second_inventory_digest": f"sha256:{hashlib.sha256(json.dumps(result_entries, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}",
        "identical": True,
        "base_unchanged_after_build": True,
        "sysroot_unchanged_after_build": True,
        "post_probe_inventory_digest": f"sha256:{hashlib.sha256(json.dumps(result_entries, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}",
    },
    "license_inventory": license_inventory,
    "host": {
        "platform": platform.platform(),
        "gcc": first_line("gcc", "--version"),
        "make": first_line("make", "--version"),
        "rsync": first_line("rsync", "--version"),
        "packages": packages,
    },
    "outputs": {
        "probe_sha256": regular_hashes(probe_value),
        "configuration_sha256": regular_hashes(configuration_value),
        "sysroot_inventory_digest": f"sha256:{sysroot_inventory['digest']}",
    },
}

output = Path(output_value)
descriptor, temporary_name = tempfile.mkstemp(
    prefix=".receipt.", dir=output.parent, text=True
)
with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
    json.dump(receipt, stream, indent=2, sort_keys=True)
    stream.write("\n")
os.replace(temporary_name, output)
output.chmod(0o644)
PY

# Revalidate the exact candidate and its receipt before making anything public.
if [[ -n $(git -C "$project_root" status --porcelain) \
   || $(git -C "$project_root" rev-parse HEAD) != "$orchestration_commit" \
   || $(git -C "$project_root" rev-parse 'HEAD^{tree}') != "$orchestration_tree" \
   || $(sha256sum "$script_path" | awk '{print $1}') != "$recipe_sha256" \
   || $(sha256sum "$inventory_helper" | awk '{print $1}') != "$inventory_helper_sha256" ]]; then
  echo "CajunOS orchestration changed while writing the receipt" >&2
  exit 103
fi
"$script_path" --internal-python validate-completed \
  "$artifact_temporary/receipt.json" "$candidate_a" "$gcc_prefix" "$tools_root" \
  "$target" "$gcc_version" \
  schema 1 component gcc stage libgcc-bootstrap build_id "$build_id" \
  source_commit "$locked_gcc_commit" source_tree "$locked_gcc_tree" \
  source_set_digest "$source_set_digest" source_authentication "$source_authentication" \
  target "$target" build_triplet "$build_triplet" prefix "$prefix_final" \
  source_repository "$gcc_repository" gcc_version "$gcc_version" \
  target_cflags "$target_cflags" libgcc2_debug_cflags -g0 \
  base_prefix "$gcc_prefix" sysroot "$sysroot" \
  sysroot_snapshot "$glibc_snapshot" sysroot_snapshot_digest "$glibc_snapshot_digest" \
  sysroot_modified False runtime_contract.functional_libc absent \
  runtime_contract.shared_runtime absent runtime_contract.thread_model single \
  runtime_contract.multilib disabled runtime_contract.gcov_runtime absent \
  base_build_id "$gcc_build_id" orchestration_commit "$orchestration_commit" \
  orchestration_tree "$orchestration_tree" recipe_sha256 "$recipe_sha256" \
  dependencies.gcc.receipt_sha256 "$gcc_receipt_sha256" \
  dependencies.binutils.receipt_sha256 "$binutils_receipt_sha256" \
  dependencies.glibc.receipt_sha256 "$glibc_receipt_sha256" \
  dependencies.linux.receipt_sha256 "$linux_receipt_sha256"

# Validate managed roots and exact staging paths before irreversible publication.
"$script_path" --internal-python validate-directories "$cajunos_root" \
  work work/toolchain tools artifacts logs sysroot "sysroot/$cohort_id"
if [[ $candidate_a != "$tools_root/.tmp-$build_id-a-$$" \
   || $candidate_b != "$tools_root/.tmp-$build_id-b-$$" \
   || ! -d $candidate_a || -L $candidate_a \
   || ! -d $candidate_b || -L $candidate_b \
   || ! -d $temporary_root || -L $temporary_root \
   || ! -d $artifact_temporary || -L $artifact_temporary \
   || ! -f $artifact_temporary/receipt.json \
   || -L $artifact_temporary/receipt.json \
   || -e $prefix_final || -L $prefix_final \
   || -e $build_final || -L $build_final \
   || -e $artifact_final || -L $artifact_final ]]; then
  echo "CajunOS publication paths changed after validation" >&2
  exit 104
fi

# Publish immutable state first, then advance tools/current atomically last.
mv -T -- "$candidate_a" "$prefix_final"
rm -rf -- "$candidate_b" "$overlay_a" "$overlay_b"
mv -T -- "$temporary_root" "$build_final"
mv -T -- "$artifact_temporary" "$artifact_final"
"$script_path" --internal-python selector-transition \
  "$tools_root" "$artifacts_root" "$gcc_build_id" "$build_id" >/dev/null
build_succeeded=1
trap - EXIT
echo "CAJUNOS_LIBGCC_BOOTSTRAP_OK build_id=$build_id"
