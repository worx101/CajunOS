#!/usr/bin/env bash
set -Eeuo pipefail
umask 022
export LC_ALL=C
export TZ=UTC
export PATH=/usr/bin:/bin

script_path=$(readlink -f -- "${BASH_SOURCE[0]}")
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
inventory_helper=$project_root/scripts/install-linux-headers.sh
headers_helper=$project_root/scripts/install-glibc-headers-startfiles.sh
libgcc_helper=$project_root/scripts/build-libgcc-bootstrap.sh

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


def scan_installed_elf(root: Path) -> dict[str, object]:
    elf_files = []
    undefined_atomic = []
    forbidden_needed = []
    escaping_rpath = []
    executable_stack = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        with path.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                continue
        relative = path.relative_to(root).as_posix()
        header = subprocess.run(
            ["/usr/bin/readelf", "-hW", path], check=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
        if not re.search(r"Class:\s+ELF64", header) or not re.search(
            r"Machine:\s+Advanced Micro Devices X86-64", header
        ):
            fail(f"installed ELF has an unexpected target ABI: {relative}")
        symbols = subprocess.run(
            ["/usr/bin/readelf", "-sW", path], check=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
        for line in symbols.splitlines():
            if re.search(r"\bUND\b.*\b__atomic[A-Za-z0-9_]*", line):
                undefined_atomic.append(f"{relative}: {line.strip()}")
        dynamic = subprocess.run(
            ["/usr/bin/readelf", "-dW", path], check=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
        for needed in re.findall(r"\(NEEDED\).*Shared library: \[([^\]]+)\]", dynamic):
            if needed.startswith("libatomic") or needed.startswith("libgcc_s"):
                forbidden_needed.append(f"{relative}: {needed}")
        for tag, value in re.findall(
            r"\((RPATH|RUNPATH)\).*Library (?:rpath|runpath): \[([^\]]*)\]", dynamic
        ):
            if value:
                escaping_rpath.append(f"{relative}: {tag}={value}")
        program = subprocess.run(
            ["/usr/bin/readelf", "-lW", path], check=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
        for line in program.splitlines():
            if "GNU_STACK" in line and re.search(r"\bRWE\b", line):
                executable_stack.append(relative)
        elf_files.append({"path": relative, "sha256": sha256(path)})
    return {
        "schema": "cajunos-glibc-elf-scan-v1",
        "elf_files": elf_files,
        "undefined_atomic_symbols": undefined_atomic,
        "forbidden_needed": forbidden_needed,
        "escaping_rpath_runpath": escaping_rpath,
        "executable_stack": executable_stack,
    }


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
    deleted = sorted(set(base_entries) - set(result_entries))
    if deleted:
        fail(f"sealed base entries disappeared: {deleted}")
    replaced = {
        path: {"before": base_entries[path], "after": result_entries[path]}
        for path in base_entries
        if result_entries[path] != base_entries[path]
    }
    if set(replaced) != {"usr/include/gnu/stubs-64.h"}:
        fail(f"unexpected inherited-entry replacements: {sorted(replaced)}")
    replacement = replaced["usr/include/gnu/stubs-64.h"]
    for side in ("before", "after"):
        metadata = replacement[side]
        if (
            metadata.get("type") != "file"
            or metadata.get("mode") != "0644"
            or not re.fullmatch(r"[0-9a-f]{64}", str(metadata.get("sha256", "")))
        ):
            fail("stubs-64 replacement is not a plain mode-0644 file")
    if replacement["before"]["sha256"] == replacement["after"]["sha256"]:
        fail("stubs-64 replacement did not change content")

    added = {
        path: metadata
        for path, metadata in result_entries.items()
        if path not in base_entries
    }
    if not added:
        fail("complete glibc stage added no runtime")
    for path, metadata in result_entries.items():
        mode = metadata.get("mode")
        if isinstance(mode, str) and int(mode, 8) & 0o6000:
            fail(f"set-id output is forbidden: {path}")
    for path in added:
        top = path.split("/", 1)[0]
        if top not in {"usr", "etc", "var", "sbin", "lib64"}:
            fail(f"unexpected complete-glibc top-level addition: {path}")
        if top == "etc" and path not in {"etc", "etc/rpc"}:
            fail(f"unexpected complete-glibc configuration output: {path}")
        if top == "var" and path not in {"var", "var/db", "var/db/Makefile"}:
            fail(f"unexpected complete-glibc variable-state output: {path}")
        if top == "sbin" and path not in {"sbin", "sbin/ldconfig", "sbin/sln"}:
            fail(f"unexpected complete-glibc root-sbin output: {path}")
    if added.get("lib64") != {
        "type": "symlink", "mode": "0777", "target": "usr/lib"
    }:
        fail("snapshot lacks the exact merged-/usr lib64 alias")
    required = {
        "usr/lib/ld-linux-x86-64.so.2": ("file", "0755"),
        "usr/lib/libc.so.6": ("file", "0755"),
        "usr/lib/libc.so": ("file", "0644"),
        "usr/lib/libc.a": ("file", "0644"),
        "usr/lib/libc_nonshared.a": ("file", "0644"),
        "usr/bin/getconf": ("file", "0755"),
    }
    for path, (kind, mode) in required.items():
        metadata = result_entries.get(path, {})
        if metadata.get("type") != kind or metadata.get("mode") != mode:
            fail(f"required complete-glibc output has invalid metadata: {path}")
    loaders = {
        path for path in result_entries
        if re.fullmatch(r"ld-linux[^/]*\.so(?:\.[0-9]+)?", PurePosixPath(path).name)
    }
    if loaders != {"usr/lib/ld-linux-x86-64.so.2"}:
        fail(f"unexpected glibc loader set: {sorted(loaders)}")
    return {
        "schema": "sealed-base-transform-v1",
        "base_digest": f"sha256:{base['digest']}",
        "result_digest": f"sha256:{result['digest']}",
        "added_entries": added,
        "added_entries_digest": f"sha256:{canonical_digest(added)}",
        "replaced_entries": replaced,
        "replaced_entries_digest": f"sha256:{canonical_digest(replaced)}",
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
        f"glibc-complete-{commit[:12]}-"
        f"{canonical_digest(require_pairs(arguments[1:]))[:16]}"
    )
elif command == "elf-scan":
    if len(arguments) != 1:
        fail("elf-scan requires ROOT")
    print(json.dumps(scan_installed_elf(Path(arguments[0])), indent=2, sort_keys=True))
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
elif command == "selector-rollback":
    if len(arguments) != 3:
        fail("selector-rollback requires SYSROOT BASE_BUILD_ID BUILD_ID")
    sysroot = Path(arguments[0])
    base_build_id, build_id = arguments[1:]
    current, selected = safe_selector(sysroot)
    if selected == base_build_id:
        print("base")
    elif selected != build_id:
        fail("refusing to roll back a selector that no longer names this build")
    else:
        base = sysroot / "snapshots" / base_build_id
        try:
            base_metadata = base.lstat()
        except FileNotFoundError:
            fail("selector rollback base does not exist")
        if not stat.S_ISDIR(base_metadata.st_mode):
            fail("selector rollback base is not a real directory")
        temporary = sysroot / f".current-rollback-{os.getpid()}"
        try:
            os.symlink(f"snapshots/{base_build_id}", temporary)
            os.replace(temporary, current)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        _, selected_after = safe_selector(sysroot)
        if selected_after != base_build_id:
            fail("selector rollback did not restore the exact base")
        print("rolled-back")
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

    evidence_sha256 = {}
    evidence_directories = set()
    for path in sorted(receipt_path.parent.iterdir()):
        if path == receipt_path:
            continue
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            evidence_directories.add(path.name)
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or path.is_symlink()
        ):
            fail(f"unsupported root evidence entry: {path.name}")
        evidence_sha256[path.name] = sha256(path)
    if evidence_directories != {"configuration", "licenses", "probe"}:
        fail(f"unexpected root evidence directories: {sorted(evidence_directories)}")
    if receipt.get("evidence_sha256") != evidence_sha256:
        fail("completed root evidence sidecar attestation is invalid")

    result_inventory = inventory(snapshot)
    base_inventory = inventory(base)
    result_digest = f"sha256:{result_inventory['digest']}"
    base_digest = f"sha256:{base_inventory['digest']}"
    if receipt.get("installed_entries") != result_inventory["entries"]:
        fail("completed snapshot failed full inventory validation")
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
        "tools_unchanged_after_build": True,
        "post_probe_inventory_digest": result_digest,
    }
    if receipt.get("reproducibility") != expected_repro:
        fail("completed reproducibility attestation is invalid")
    if receipt.get("functional_libc") != "present":
        fail("completed receipt does not claim functional libc")
    forbidden_runtime = sorted(
        path.relative_to(snapshot).as_posix()
        for path in snapshot.rglob("*")
        if path.name.startswith(("libgcc_s.so", "libstdc++.so", "libatomic.so"))
    )
    if forbidden_runtime:
        fail(f"deferred shared runtime is unexpectedly present: {forbidden_runtime}")
    locale_archive = snapshot / "usr/lib/locale/locale-archive"
    if locale_archive.exists() or locale_archive.is_symlink():
        fail("deferred compiled locale archive is unexpectedly present")

    if not snapshot.joinpath("lib64").is_symlink() or os.readlink(snapshot / "lib64") != "usr/lib":
        fail("completed snapshot lacks exact lib64 -> usr/lib alias")
    cohort = Path(str(receipt.get("sysroot", "")))
    alias = cohort / "lib64"
    if not alias.is_symlink() or os.readlink(alias) != "current/usr/lib":
        fail("cohort lacks exact lib64 -> current/usr/lib alias")
    try:
        alias.resolve(strict=True).relative_to((cohort / "snapshots").resolve(strict=True))
    except (FileNotFoundError, RuntimeError, ValueError):
        fail("cohort lib64 alias is broken or escapes managed snapshots")

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

    stubs = snapshot / "usr/include/gnu/stubs-64.h"
    stubs_metadata = stubs.lstat()
    if (
        not stat.S_ISREG(stubs_metadata.st_mode)
        or stubs_metadata.st_nlink != 1
        or stat.S_IMODE(stubs_metadata.st_mode) != 0o644
    ):
        fail("completed stubs-64 header has invalid metadata")
    stub_names = sorted(
        match.group(1)
        for match in re.finditer(
            r"^#define[ \t]+(__stub_[A-Za-z0-9_]+)[ \t]*$",
            stubs.read_text(encoding="utf-8"), re.MULTILINE,
        )
    )
    expected_stubs = sorted((
        "__stub___compat_bdflush", "__stub_chflags", "__stub_fchflags",
        "__stub_gtty", "__stub_revoke", "__stub_setlogin",
        "__stub_sigreturn", "__stub_stty",
    ))
    if stub_names != expected_stubs:
        fail(f"completed stubs-64 macro set is invalid: {stub_names}")
    if receipt.get("stubs_64") != {
        "sha256": sha256(stubs), "stub_macros": expected_stubs
    }:
        fail("completed stubs-64 attestation is invalid")

    runtime_relatives = (
        "usr/lib/ld-linux-x86-64.so.2", "usr/lib/libc.so.6",
        "usr/lib/libc.so", "usr/lib/libc.a", "usr/lib/libc_nonshared.a",
        "usr/lib/libm.so.6", "usr/lib/libm.so", "usr/lib/libm.a",
        "usr/lib/libmvec.so.1", "usr/lib/libpthread.so.0",
        "usr/lib/Mcrt1.o", "usr/lib/Scrt1.o", "usr/lib/gcrt1.o",
        "usr/lib/grcrt1.o", "usr/lib/rcrt1.o",
    )
    runtime_hashes = {relative: sha256(snapshot / relative) for relative in runtime_relatives}
    if receipt.get("runtime_sha256") != runtime_hashes:
        fail("completed runtime hash attestation is invalid")
    libc_script = (snapshot / "usr/lib/libc.so").read_text(encoding="utf-8")
    compact_script = " ".join(libc_script.split())
    expected_script = (
        "/* GNU ld script Use the shared library, but some functions are only "
        "in the static library, so try that secondarily. */ "
        "OUTPUT_FORMAT(elf64-x86-64) "
        "GROUP ( /usr/lib/libc.so.6 /usr/lib/libc_nonshared.a "
        "AS_NEEDED ( /usr/lib/ld-linux-x86-64.so.2 ) )"
    )
    if compact_script != expected_script:
        fail("completed libc.so linker script has unexpected semantics")

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

    probe_root = receipt_path.parent / "probe"
    if receipt.get("outputs", {}).get("probe_sha256") != regular_hashes(probe_root):
        fail("completed probe attestation is invalid")
    configuration_root = receipt_path.parent / "configuration"
    configuration_hashes = regular_hashes(configuration_root)
    if receipt.get("configuration_sha256") != configuration_hashes:
        fail("completed configuration attestation is invalid")
    for relative in configuration_hashes:
        text = (configuration_root / relative).read_text(encoding="utf-8")
        if "/.tmp-" in text or "/work/" in text:
            fail(f"retained configuration contains a disposable path: {relative}")
    scan_path = probe_root / "installed-elf-scan.json"
    with scan_path.open(encoding="utf-8") as stream:
        scan = json.load(stream)
    if scan != scan_installed_elf(snapshot):
        fail("retained installed-ELF scan does not match the live snapshot")
    if (
        scan.get("schema") != "cajunos-glibc-elf-scan-v1"
        or not isinstance(scan.get("elf_files"), list)
        or len(scan["elf_files"]) < 300
        or scan.get("undefined_atomic_symbols") != []
        or scan.get("forbidden_needed") != []
        or scan.get("escaping_rpath_runpath") != []
        or scan.get("executable_stack") != []
    ):
        fail("completed installed-ELF scan is invalid")
    if receipt.get("outputs", {}).get("installed_elf_count") != len(scan["elf_files"]):
        fail("completed installed-ELF count is invalid")

    dynamic = probe_root / "dynamic"
    static_probe = probe_root / "static"
    for path in (dynamic, static_probe):
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o755
        ):
            fail(f"completed probe executable has unsafe metadata: {path.name}")
    readelf_l = subprocess.run(
        ["/usr/bin/readelf", "-lW", dynamic], check=True, text=True,
        stdout=subprocess.PIPE,
    ).stdout
    dynamic_h = subprocess.run(
        ["/usr/bin/readelf", "-hW", dynamic], check=True, text=True,
        stdout=subprocess.PIPE,
    ).stdout
    if not re.search(r"Type:\s+DYN\s", dynamic_h):
        fail("dynamic probe is not an ELF position-independent executable")
    if "[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]" not in readelf_l:
        fail("dynamic probe has the wrong program interpreter")
    static_l = subprocess.run(
        ["/usr/bin/readelf", "-lW", static_probe], check=True, text=True,
        stdout=subprocess.PIPE,
    ).stdout
    static_h = subprocess.run(
        ["/usr/bin/readelf", "-hW", static_probe], check=True, text=True,
        stdout=subprocess.PIPE,
    ).stdout
    if not re.search(r"Type:\s+EXEC\s", static_h):
        fail("static probe is not an ELF executable")
    if "Requesting program interpreter" in static_l:
        fail("static probe unexpectedly has a program interpreter")
    dynamic_d = subprocess.run(
        ["/usr/bin/readelf", "-dW", dynamic], check=True, text=True,
        stdout=subprocess.PIPE,
    ).stdout
    needed = re.findall(r"\(NEEDED\).*Shared library: \[([^\]]+)\]", dynamic_d)
    if needed != ["libc.so.6"]:
        fail(f"dynamic probe has an unexpected dependency set: {needed}")
    static_d = subprocess.run(
        ["/usr/bin/readelf", "-dW", static_probe], check=True, text=True,
        stdout=subprocess.PIPE,
    ).stdout
    if "(NEEDED)" in static_d:
        fail("static probe unexpectedly has a dynamic dependency")

    loader = snapshot / "lib64/ld-linux-x86-64.so.2"
    library_path = snapshot / "usr/lib"
    clean_env = {"LC_ALL": "C", "TZ": "UTC"}
    run = subprocess.run(
        [loader, "--inhibit-cache", "--library-path", library_path, dynamic],
        check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=clean_env,
    )
    if run.returncode or run.stdout != "glibc=2.44.9000 pthread=ok division=ok\n" or run.stderr:
        fail("dynamic probe no longer runs solely with the completed glibc")
    static_run = subprocess.run(
        [static_probe], check=False, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=clean_env,
    )
    if (
        static_run.returncode
        or static_run.stdout != "glibc=2.44.9000 static=ok division=ok\n"
        or static_run.stderr
    ):
        fail("static probe no longer runs")
    getconf = snapshot / "usr/bin/getconf"
    getconf_run = subprocess.run(
        [loader, "--inhibit-cache", "--library-path", library_path,
         getconf, "GNU_LIBC_VERSION"],
        check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=clean_env,
    )
    if getconf_run.returncode or getconf_run.stdout != "glibc 2.44.9000\n" or getconf_run.stderr:
        fail("installed getconf does not report the completed glibc")

    listing = subprocess.run(
        [loader, "--inhibit-cache", "--library-path", library_path,
         "--list", dynamic],
        check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=clean_env,
    )
    if listing.returncode or listing.stderr:
        fail("candidate loader listing failed")
    normalized_listing = re.sub(r" \(0x[0-9a-fA-F]+\)", "", listing.stdout)
    if normalized_listing != (probe_root / "loader.list").read_text(encoding="utf-8"):
        fail("retained loader listing does not match the live snapshot")
    for line in normalized_listing.splitlines():
        if "=>" in line and str(snapshot) not in line:
            fail(f"loader listing escaped the completed snapshot: {line}")
    libgcc_prefix = receipt.get("dependencies", {}).get("libgcc", {}).get("prefix")
    if not isinstance(libgcc_prefix, str):
        fail("completed receipt lacks its libgcc prefix")
    for map_name in ("dynamic.map", "static.map"):
        link_map = (probe_root / map_name).read_text(encoding="utf-8")
        if (
            str(snapshot) not in link_map
            or f"{libgcc_prefix}/lib/gcc/" not in link_map
            or "/.tmp-" in link_map
            or "/work/" in link_map
            or "/usr/lib/x86_64-linux-gnu" in link_map
        ):
            fail(f"{map_name} does not bind stable CajunOS inputs")
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
for command in \
  awk cmp cp dpkg-query env flock git grep install ln make mv python3 readelf readlink rsync \
  sed sha256sum sort stat tar tee unlink; do
  command -v "$command" >/dev/null || {
    echo "Missing required host command: $command" >&2
    exit 102
  }
done
for helper in "$inventory_helper" "$headers_helper" "$libgcc_helper"; do
  [[ -x $helper ]] || {
    echo "Required frozen dependency helper is unavailable: $helper" >&2
    exit 103
  }
done

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
linux_snapshot=$base_snapshot
linux_snapshot_digest=$base_snapshot_digest
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

resolve_runtime_chain() {
  python3 - \
    "$project_root" "$headers_helper" "$libgcc_helper" "$inventory_helper" \
    "$artifacts_root" "$tools_root" "$sysroot" "$snapshots_root" \
    "$source_set_digest" "$source_authentication" "$target" \
    "$locked_glibc_commit" "$locked_glibc_tree" "$glibc_repository" \
    "$linux_build_id" "$linux_receipt" "$linux_receipt_sha256" \
    "$locked_gcc_commit" "$locked_gcc_tree" "$gcc_repository" \
    "$gcc_build_id" "$gcc_prefix" "$gcc_receipt" "$gcc_receipt_sha256" \
    "$binutils_build_id" "$binutils_prefix" "$binutils_receipt" \
    "$binutils_receipt_sha256" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

(
    project_value, headers_helper_value, libgcc_helper_value,
    inventory_helper_value, artifacts_value, tools_value, sysroot_value,
    snapshots_value, source_set_digest, source_authentication, target,
    glibc_commit, glibc_tree, glibc_repository, linux_build_id,
    linux_receipt, linux_receipt_sha256, gcc_commit, gcc_tree, gcc_repository,
    gcc_build_id, gcc_prefix, gcc_receipt, gcc_receipt_sha256,
    binutils_build_id, binutils_prefix, binutils_receipt,
    binutils_receipt_sha256,
) = sys.argv[1:]
project = Path(project_value)
headers_helper = Path(headers_helper_value)
libgcc_helper = Path(libgcc_helper_value)
inventory_helper = Path(inventory_helper_value)
artifacts = Path(artifacts_value)
tools = Path(tools_value)
sysroot = Path(sysroot_value)
snapshots = Path(snapshots_value)

def fail(message):
    raise SystemExit(message)

def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def plain(path):
    try:
        metadata = Path(path).lstat()
    except FileNotFoundError:
        fail(f"required dependency is absent: {path}")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail(f"dependency is not a plain single-linked file: {path}")

def load(path):
    plain(path)
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream)

def recipe_hash(receipt, relative):
    commit = receipt.get("orchestration_commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        fail("dependency has an unsafe orchestration commit")
    result = subprocess.run(
        ["git", "-C", project, "show", f"{commit}:{relative}"],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode:
        fail(f"dependency recipe blob is unavailable: {relative}")
    return hashlib.sha256(result.stdout).hexdigest()

header_candidates = []
for receipt_path in sorted(artifacts.glob("glibc-headers-startfiles-*/receipt.json")):
    try:
        receipt = load(receipt_path)
    except (SystemExit, json.JSONDecodeError):
        continue
    if (
        receipt.get("schema") == 1
        and receipt.get("component") == "glibc"
        and receipt.get("stage") == "headers-startfiles"
        and receipt.get("source_set_digest") == source_set_digest
        and receipt.get("source_authentication") == source_authentication
        and receipt.get("source_commit") == glibc_commit
        and receipt.get("source_tree") == glibc_tree
        and receipt.get("source_repository") == glibc_repository
        and receipt.get("target") == target
        and receipt.get("sysroot") == str(sysroot)
        and receipt.get("base_build_id") == linux_build_id
        and receipt.get("dependencies", {}).get("linux", {}).get("receipt")
        == linux_receipt
        and receipt.get("dependencies", {}).get("linux", {}).get("receipt_sha256")
        == linux_receipt_sha256
    ):
        header_candidates.append((receipt_path, receipt))
if len(header_candidates) != 1:
    fail(f"expected one matching glibc headers receipt, found {len(header_candidates)}")
headers_receipt_path, headers_receipt = header_candidates[0]
headers_build_id = headers_receipt.get("build_id")
if (
    not isinstance(headers_build_id, str)
    or headers_receipt_path.parent.name != headers_build_id
    or not re.fullmatch(r"glibc-headers-startfiles-[A-Za-z0-9._-]+", headers_build_id)
):
    fail("glibc headers receipt/build directory mismatch")
headers_snapshot = snapshots / headers_build_id
linux_snapshot = snapshots / linux_build_id
if (
    headers_receipt.get("snapshot") != str(headers_snapshot)
    or headers_receipt.get("base_snapshot") != str(linux_snapshot)
    or headers_receipt.get("functional_libc") != "absent"
):
    fail("glibc headers receipt has an invalid snapshot contract")
validation = subprocess.run(
    [headers_helper, "--internal-python", "validate-completed",
     headers_receipt_path, headers_snapshot, linux_snapshot, "schema", "1"],
    check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
)
if validation.returncode:
    fail(validation.stderr.strip() or "glibc headers completed validation failed")
if headers_receipt.get("recipe_sha256") != recipe_hash(
    headers_receipt, "scripts/install-glibc-headers-startfiles.sh"
):
    fail("glibc headers recipe hash differs from its orchestration blob")

current = tools / "current"
if not current.is_symlink():
    fail("tools/current is not a managed symlink")
active_tools_id = os.readlink(current)
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", active_tools_id):
    fail("tools/current has an unsafe target")
try:
    current.resolve(strict=True).relative_to(tools.resolve(strict=True))
except (FileNotFoundError, RuntimeError, ValueError):
    fail("tools/current is broken or escaping")

cursor = active_tools_id
seen = set()
while True:
    if cursor in seen or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", cursor
    ):
        fail("tools ancestry is cyclic or unsafe")
    seen.add(cursor)
    cursor_prefix = tools / cursor
    try:
        metadata = cursor_prefix.lstat()
    except FileNotFoundError:
        fail("tools ancestry names an absent prefix")
    if not stat.S_ISDIR(metadata.st_mode):
        fail("tools ancestry does not name a real prefix")
    try:
        cursor_prefix.resolve(strict=True).relative_to(tools.resolve(strict=True))
    except (FileNotFoundError, RuntimeError, ValueError):
        fail("tools ancestry prefix is broken or escaping")
    cursor_receipt_path = artifacts / cursor / "receipt.json"
    cursor_receipt = load(cursor_receipt_path)
    if (
        cursor_receipt.get("schema") != 1
        or cursor_receipt.get("build_id") != cursor
        or cursor_receipt.get("prefix") != str(cursor_prefix)
        or cursor_receipt.get("source_set_digest") != source_set_digest
        or cursor_receipt.get("source_authentication") != source_authentication
        or cursor_receipt.get("target") != target
    ):
        fail("tools ancestry receipt has invalid identity")
    if (
        cursor_receipt.get("component") == "gcc"
        and cursor_receipt.get("stage") == "libgcc-bootstrap"
    ):
        break
    cursor = cursor_receipt.get("base_build_id")
    if not isinstance(cursor, str):
        fail("tools ancestry lacks a libgcc-bootstrap ancestor")

selected = cursor
libgcc_prefix = tools / selected
try:
    libgcc_prefix.resolve(strict=True).relative_to(tools.resolve(strict=True))
except (FileNotFoundError, RuntimeError, ValueError):
    fail("libgcc ancestor prefix is broken or escaping")
libgcc_receipt_path = cursor_receipt_path
libgcc_receipt = cursor_receipt
gcc_version = libgcc_receipt.get("gcc_version")
base_prefix = Path(str(libgcc_receipt.get("base_prefix", "")))
dependencies = libgcc_receipt.get("dependencies", {})
gcc_dependency = dependencies.get("gcc", {})
binutils_dependency = dependencies.get("binutils", {})
glibc_dependency = dependencies.get("glibc", {})
linux_dependency = dependencies.get("linux", {})
if (
    libgcc_receipt.get("schema") != 1
    or libgcc_receipt.get("component") != "gcc"
    or libgcc_receipt.get("stage") != "libgcc-bootstrap"
    or libgcc_receipt.get("build_id") != selected
    or libgcc_receipt.get("prefix") != str(libgcc_prefix)
    or libgcc_receipt.get("source_set_digest") != source_set_digest
    or libgcc_receipt.get("source_authentication") != source_authentication
    or libgcc_receipt.get("source_commit") != gcc_commit
    or libgcc_receipt.get("source_tree") != gcc_tree
    or libgcc_receipt.get("source_repository") != gcc_repository
    or libgcc_receipt.get("target") != target
    or libgcc_receipt.get("base_build_id") != gcc_build_id
    or base_prefix != Path(gcc_prefix)
    or libgcc_receipt.get("sysroot") != str(sysroot)
    or libgcc_receipt.get("sysroot_snapshot") != str(headers_snapshot)
    or libgcc_receipt.get("sysroot_snapshot_digest")
    != headers_receipt.get("result_snapshot_digest")
    or gcc_dependency.get("build_id") != gcc_build_id
    or gcc_dependency.get("prefix") != gcc_prefix
    or gcc_dependency.get("receipt") != gcc_receipt
    or gcc_dependency.get("receipt_sha256") != gcc_receipt_sha256
    or binutils_dependency.get("build_id") != binutils_build_id
    or binutils_dependency.get("prefix") != binutils_prefix
    or binutils_dependency.get("receipt") != binutils_receipt
    or binutils_dependency.get("receipt_sha256") != binutils_receipt_sha256
    or glibc_dependency.get("build_id") != headers_build_id
    or glibc_dependency.get("snapshot") != str(headers_snapshot)
    or glibc_dependency.get("receipt") != str(headers_receipt_path)
    or glibc_dependency.get("receipt_sha256") != sha256(headers_receipt_path)
    or linux_dependency.get("build_id") != linux_build_id
    or linux_dependency.get("receipt") != linux_receipt
    or linux_dependency.get("receipt_sha256") != linux_receipt_sha256
    or not isinstance(gcc_version, str)
    or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", gcc_version)
):
    fail("selected libgcc dependency provenance mismatch")
validation = subprocess.run(
    [libgcc_helper, "--internal-python", "validate-completed",
     libgcc_receipt_path, libgcc_prefix, base_prefix, tools, target,
     gcc_version, "schema", "1"],
    check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
)
if validation.returncode:
    fail(validation.stderr.strip() or "libgcc completed validation failed")
if libgcc_receipt.get("recipe_sha256") != recipe_hash(
    libgcc_receipt, "scripts/build-libgcc-bootstrap.sh"
):
    fail("libgcc recipe hash differs from its orchestration blob")

values = (
    headers_build_id, str(headers_snapshot), str(headers_receipt_path),
    sha256(headers_receipt_path), headers_receipt["result_snapshot_digest"],
    selected, str(libgcc_prefix), str(libgcc_receipt_path),
    sha256(libgcc_receipt_path), libgcc_receipt["result_prefix_digest"],
    gcc_version, libgcc_receipt.get("orchestration_commit", ""),
    libgcc_receipt.get("orchestration_tree", ""), active_tools_id,
)
if any(not isinstance(value, str) or not value or "\n" in value for value in values):
    fail("runtime dependency chain contains invalid scalar metadata")
print(*values, sep="\n")
PY
}

if ! runtime_chain_output=$(resolve_runtime_chain); then
  echo "glibc-headers/libgcc dependency-chain validation failed" >&2
  exit 135
fi
mapfile -t runtime_values <<<"$runtime_chain_output"
if (( ${#runtime_values[@]} != 14 )); then
  echo "Runtime dependency-chain verifier returned incomplete metadata" >&2
  exit 136
fi
glibc_headers_build_id=${runtime_values[0]}
base_snapshot=${runtime_values[1]}
glibc_headers_receipt=${runtime_values[2]}
glibc_headers_receipt_sha256=${runtime_values[3]}
base_snapshot_digest=${runtime_values[4]}
libgcc_build_id=${runtime_values[5]}
libgcc_prefix=${runtime_values[6]}
libgcc_receipt=${runtime_values[7]}
libgcc_receipt_sha256=${runtime_values[8]}
libgcc_prefix_digest=${runtime_values[9]}
gcc_version=${runtime_values[10]}
libgcc_orchestration_commit=${runtime_values[11]}
libgcc_orchestration_tree=${runtime_values[12]}
active_tools_id=${runtime_values[13]}
if [[ $(git -C "$project_root" rev-parse "$libgcc_orchestration_commit^{tree}") \
   != "$libgcc_orchestration_tree" ]]; then
  echo "libgcc orchestration commit/tree is unavailable or inconsistent" >&2
  exit 137
fi

build_triplet=$("$glibc_source_dir/scripts/config.guess")
[[ -n $build_triplet && $build_triplet != "$target" && $build_triplet != *$'\n'* ]] || {
  echo "Unable to establish true build/host cross mode" >&2
  exit 113
}
cross_gcc=$libgcc_prefix/bin/$target-gcc
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
  "CC=$cross_gcc --sysroot=<candidate> -fno-link-libatomic"
  "CXX=false"
  "CONFIG_SHELL=/bin/bash"
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
  "build-target=all"
  "install-target=install"
  "bootstrap-cycle-breaker=-fno-link-libatomic"
  "getconf-hardlinks=normalized-to-independent-copies"
  "snapshot-lib64-alias=usr/lib"
  "cohort-lib64-alias=current/usr/lib"
  "independent-builds=2"
  "sysroot-layout=immutable-snapshots-merged-usr-v1"
)
options_digest=$(printf '%s\0' "${configure_options[@]}" | sha256sum | awk '{print $1}')
recipe_sha256=$(sha256sum "$script_path" | awk '{print $1}')
helper_sha256=$(sha256sum "$inventory_helper" | awk '{print $1}')
headers_helper_sha256=$(sha256sum "$headers_helper" | awk '{print $1}')
libgcc_helper_sha256=$(sha256sum "$libgcc_helper" | awk '{print $1}')
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
  headers_helper_sha256 "$headers_helper_sha256" \
  libgcc_helper_sha256 "$libgcc_helper_sha256" \
  options_digest "$options_digest" \
  base_build_id "$glibc_headers_build_id" \
  base_receipt_sha256 "$glibc_headers_receipt_sha256" \
  base_snapshot_digest "$base_snapshot_digest" \
  libgcc_build_id "$libgcc_build_id" \
  libgcc_receipt_sha256 "$libgcc_receipt_sha256" \
  libgcc_prefix_digest "$libgcc_prefix_digest" \
  gcc_version "$gcc_version" \
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
log_file=$log_dir/glibc-complete.log
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
    schema 1 build_id "$build_id" component glibc stage complete \
    source_commit "$locked_glibc_commit" source_tree "$locked_glibc_tree" \
    source_repository "$glibc_repository" glibc_version 2.44.9000 \
    source_set_digest "$source_set_digest" \
    source_authentication "$source_authentication" \
    source_date_epoch "$SOURCE_DATE_EPOCH" target "$target" arch "$arch" \
    minimum_kernel "$minimum_kernel" build_triplet "$build_triplet" \
    target_cflags "$target_cflags" \
    sysroot "$sysroot" sysroot_contract immutable-snapshots-merged-usr-v1 \
    snapshot "$snapshot_final" base_build_id "$glibc_headers_build_id" \
    base_snapshot "$base_snapshot" base_snapshot_digest "$base_snapshot_digest" \
    orchestration_commit "$orchestration_commit" \
    orchestration_tree "$orchestration_tree" recipe_sha256 "$recipe_sha256" \
    inventory_helper_sha256 "$helper_sha256" \
    headers_helper_sha256 "$headers_helper_sha256" \
    libgcc_helper_sha256 "$libgcc_helper_sha256" \
    options_digest "$options_digest" \
    generation.build 'make -j<jobs> all' \
    generation.install 'make -j1 install_root=<candidate> install' \
    generation.cycle_breaker -fno-link-libatomic \
    generation.getconf_hardlinks independent-copies \
    runtime_layout.slibdir /usr/lib \
    runtime_layout.rtlddir /usr/lib \
    runtime_layout.snapshot_lib64_alias usr/lib \
    runtime_layout.cohort_lib64_alias current/usr/lib \
    dependencies.glibc_headers.build_id "$glibc_headers_build_id" \
    dependencies.glibc_headers.receipt "$glibc_headers_receipt" \
    dependencies.glibc_headers.receipt_sha256 "$glibc_headers_receipt_sha256" \
    dependencies.glibc_headers.snapshot "$base_snapshot" \
    dependencies.glibc_headers.snapshot_digest "$base_snapshot_digest" \
    dependencies.libgcc.build_id "$libgcc_build_id" \
    dependencies.libgcc.prefix "$libgcc_prefix" \
    dependencies.libgcc.prefix_digest "$libgcc_prefix_digest" \
    dependencies.libgcc.receipt "$libgcc_receipt" \
    dependencies.libgcc.receipt_sha256 "$libgcc_receipt_sha256" \
    dependencies.libgcc.gcc_version "$gcc_version" \
    dependencies.libgcc.orchestration_commit "$libgcc_orchestration_commit" \
    dependencies.libgcc.orchestration_tree "$libgcc_orchestration_tree" \
    dependencies.linux.build_id "$linux_build_id" \
    dependencies.linux.receipt "$linux_receipt" \
    dependencies.linux.receipt_sha256 "$linux_receipt_sha256" \
    dependencies.linux.snapshot "$linux_snapshot" \
    dependencies.linux.snapshot_digest "$linux_snapshot_digest" \
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
    functional_libc present \
    deferred_runtime.libgcc_s absent \
    deferred_runtime.libstdcxx absent \
    deferred_runtime.locale_archive absent \
    probe_contract.dynamic 'ELF64-PIE-PT_INTERP=/lib64/ld-linux-x86-64.so.2' \
    probe_contract.execution candidate-loader-inhibit-cache-library-path-only \
    probe_contract.static ELF64-static-no-PT_INTERP-no-DT_NEEDED \
    probe_contract.atomic_runtime no-undefined-or-needed-libatomic
}

ensure_cohort_lib64_alias() {
  local alias=$sysroot/lib64
  if [[ -L $alias ]]; then
    [[ $(readlink -- "$alias") == current/usr/lib ]] || {
      echo "Cohort lib64 alias has an unexpected target" >&2
      return 1
    }
    return 0
  fi
  [[ ! -e $alias ]] || {
    echo "Refusing to replace an unmanaged cohort lib64 path" >&2
    return 1
  }
  local temporary=$sysroot/.lib64-$$
  ln -s current/usr/lib "$temporary"
  mv -T -- "$temporary" "$alias"
  cohort_alias_created=1
}

validate_cohort_loader() {
  local artifacts=$1
  local probe=$artifacts/probe/dynamic
  local output
  [[ -L $sysroot/lib64 && $(readlink -- "$sysroot/lib64") == current/usr/lib ]] || {
    echo "Cohort lib64 alias is invalid" >&2
    return 1
  }
  [[ $(readlink -f -- "$sysroot/lib64/ld-linux-x86-64.so.2") \
     == $(readlink -f -- "$sysroot/usr/lib/ld-linux-x86-64.so.2") ]] || {
    echo "Cohort lib64 loader does not follow the current selector" >&2
    return 1
  }
  output=$(env -i LC_ALL=C TZ=UTC \
    "$sysroot/lib64/ld-linux-x86-64.so.2" \
    --inhibit-cache --library-path "$sysroot/usr/lib" "$probe") || return
  [[ $output == 'glibc=2.44.9000 pthread=ok division=ok' ]] || {
    echo "Cohort loader failed the retained dynamic probe" >&2
    return 1
  }
}

if [[ -d $build_final && ! -L $build_final \
   && -d $snapshot_final && ! -L $snapshot_final \
   && -d $artifact_final && ! -L $artifact_final \
   && -f $receipt_final && ! -L $receipt_final \
   && $(stat -c %h "$receipt_final") == 1 ]]; then
  cohort_alias_created=0
  idempotent_entry_state=$("$script_path" --internal-python selector-state \
    "$sysroot" "$glibc_headers_build_id" "$build_id")
  # Invoked indirectly by the EXIT trap below.
  # shellcheck disable=SC2317
  idempotent_on_exit() {
    local status=$?
    local safe_to_unlink=1
    if (( status != 0 )); then
      if [[ $idempotent_entry_state == base \
         && -L $sysroot/current \
         && $(readlink -- "$sysroot/current") == "snapshots/$build_id" ]]; then
        if ! "$script_path" --internal-python selector-rollback \
          "$sysroot" "$glibc_headers_build_id" "$build_id" >/dev/null; then
          safe_to_unlink=0
          echo "Failed to restore the sysroot selector after idempotent replay" >&2
        fi
      elif [[ $idempotent_entry_state == base \
           && ( ! -L $sysroot/current \
             || $(readlink -- "$sysroot/current") != "snapshots/$glibc_headers_build_id" ) ]]; then
        safe_to_unlink=0
      fi
      if (( safe_to_unlink == 1 && cohort_alias_created == 1 )) \
         && [[ -L $sysroot/lib64 \
            && $(readlink -- "$sysroot/lib64") == current/usr/lib ]]; then
        unlink -- "$sysroot/lib64"
      fi
    fi
    return "$status"
  }
  trap idempotent_on_exit EXIT
  ensure_cohort_lib64_alias
  validate_completed
  transition=$("$script_path" --internal-python selector-transition \
    "$sysroot" "$glibc_headers_build_id" "$build_id")
  validate_completed
  validate_cohort_loader "$artifact_final"
  trap - EXIT
  echo "CAJUNOS_GLIBC_COMPLETE_ALREADY_COMPLETE build_id=$build_id selector=$transition"
  exit 0
fi
if [[ -e $build_final || -L $build_final \
   || -e $snapshot_final || -L $snapshot_final \
   || -e $artifact_final || -L $artifact_final ]]; then
  echo "Refusing to reuse an incomplete published complete-glibc build: $build_id" >&2
  exit 115
fi
if [[ -e $temporary_root || -L $temporary_root \
   || -e $snapshot_temporary || -L $snapshot_temporary \
   || -e $artifact_temporary || -L $artifact_temporary \
   || -e $log_dir || -L $log_dir ]]; then
  echo "Refusing colliding temporary or log path for run $run_id" >&2
  exit 116
fi
selector_state=$("$script_path" --internal-python selector-state \
  "$sysroot" "$glibc_headers_build_id" "$build_id")
if [[ $selector_state != base ]]; then
  echo "Fresh complete glibc requires current to name its sealed headers base" >&2
  exit 117
fi
if [[ $active_tools_id != "$libgcc_build_id" ]]; then
  echo "Fresh complete glibc requires tools/current to name corrected bootstrap libgcc" >&2
  exit 138
fi

build_succeeded=0
build_established=0
snapshot_established=0
cohort_alias_created=0
on_exit() {
  local status=$?
  local safe_to_quarantine=1
  if (( status != 0 || build_succeeded == 0 )); then
    if [[ -L $sysroot/current \
       && $(readlink -- "$sysroot/current") == "snapshots/$build_id" ]]; then
      if ! "$script_path" --internal-python selector-rollback \
        "$sysroot" "$glibc_headers_build_id" "$build_id" >/dev/null; then
        safe_to_quarantine=0
        echo "Failed to restore the sysroot selector; preserving selected outputs" >&2
      fi
    elif [[ -L $sysroot/current \
         && $(readlink -- "$sysroot/current") != "snapshots/$glibc_headers_build_id" ]]; then
      safe_to_quarantine=0
      echo "Sysroot selector changed unexpectedly; preserving permanent outputs" >&2
    fi
    if [[ -d $temporary_root ]]; then
      mv -- "$temporary_root" "$work_root/.failed-$build_id-$$"
    fi
    if [[ -d $snapshot_temporary ]]; then
      mv -- "$snapshot_temporary" "$work_root/.failed-snapshot-$build_id-$$"
    fi
    if (( safe_to_quarantine == 1 && snapshot_established == 1 )) \
       && [[ -d $snapshot_final && ! -L $snapshot_final ]]; then
      mv -- "$snapshot_final" "$work_root/.failed-published-snapshot-$build_id-$$"
    fi
    if (( safe_to_quarantine == 1 && build_established == 1 )) \
       && [[ -d $build_final && ! -L $build_final ]]; then
      mv -- "$build_final" "$work_root/.failed-published-build-$build_id-$$"
    fi
    if [[ -d $artifact_temporary ]]; then
      mv -- "$artifact_temporary" "$artifacts_root/.failed-$build_id-$$"
    fi
    if (( safe_to_quarantine == 1 && cohort_alias_created == 1 )) \
       && [[ -L $sysroot/lib64 && $(readlink -- "$sysroot/lib64") == current/usr/lib ]]; then
      unlink -- "$sysroot/lib64"
    fi
    if (( safe_to_quarantine == 1 )) \
       && [[ -d $artifact_final && ! -L $artifact_final ]]; then
      mv -- "$artifact_final" "$artifacts_root/.failed-published-$build_id-$$"
    fi
  fi
  return "$status"
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

echo "CajunOS complete glibc and dynamic loader"
echo "build_id=$build_id"
echo "source=$locked_glibc_commit"
echo "source_repository=$glibc_repository"
echo "source_set=$source_set_digest"
echo "source_authentication=$source_authentication"
echo "orchestration=$orchestration_commit"
echo "recipe_sha256=$recipe_sha256"
echo "inventory_helper_sha256=$helper_sha256"
echo "headers_helper_sha256=$headers_helper_sha256"
echo "libgcc_helper_sha256=$libgcc_helper_sha256"
echo "options_digest=$options_digest"
echo "base_build_id=$glibc_headers_build_id"
echo "base_snapshot_digest=$base_snapshot_digest"
echo "libgcc_build_id=$libgcc_build_id"
echo "libgcc_prefix_digest=$libgcc_prefix_digest"
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
"$script_path" --internal-python dependency-inventory \
  "$libgcc_prefix" "$tools_root" > "$artifact_temporary/tools-before.json"

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

normalize_getconf_hardlinks() {
  local candidate=$1
  local paths=(
    "$candidate/usr/bin/getconf"
    "$candidate/usr/libexec/getconf/POSIX_V6_LP64_OFF64"
    "$candidate/usr/libexec/getconf/POSIX_V7_LP64_OFF64"
    "$candidate/usr/libexec/getconf/XBS5_LP64_OFF64"
  )
  local expected_identity=
  local expected_hash=
  local path identity hash
  for path in "${paths[@]}"; do
    [[ -f $path && ! -L $path && $(stat -c %a "$path") == 755 \
       && $(stat -c %h "$path") == 4 ]] || {
      echo "Unexpected upstream getconf hardlink metadata: $path" >&2
      return 1
    }
    identity=$(stat -c %d:%i "$path")
    hash=$(sha256sum "$path" | awk '{print $1}')
    if [[ -z $expected_identity ]]; then
      expected_identity=$identity
      expected_hash=$hash
    elif [[ $identity != "$expected_identity" || $hash != "$expected_hash" ]]; then
      echo "Upstream getconf hardlink group is inconsistent" >&2
      return 1
    fi
  done
  for path in "${paths[@]}"; do
    local temporary=$path.cajunos-copy-$$
    cp --reflink=never --preserve=mode,timestamps -- "$path" "$temporary"
    mv -T -- "$temporary" "$path"
  done
  for path in "${paths[@]}"; do
    [[ -f $path && ! -L $path && $(stat -c %a "$path") == 755 \
       && $(stat -c %h "$path") == 1 \
       && $(sha256sum "$path" | awk '{print $1}') == "$expected_hash" ]] || {
      echo "Normalized getconf copy failed its metadata contract: $path" >&2
      return 1
    }
  done
}

configure_and_stage() {
  local build_dir=$1
  local candidate=$2
  local candidate_cc="$cross_gcc --sysroot=$candidate -fno-link-libatomic"
  local configured_cc="$candidate_cc -B$binutils_prefix/bin/"
  [[ $("$cross_gcc" --sysroot="$candidate" -print-sysroot) == "$candidate" ]] || {
    echo "Cross GCC rejected the candidate sysroot override" >&2
    return 1
  }
  env \
    CONFIG_SHELL=/bin/bash \
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
    echo "glibc configure did not retain the sealed bootstrap compiler contract" >&2
    return 1
  }
  if ! grep -Fxq 'CXX = ' "$build_dir/config.make" \
     || ! grep -Fxq 'ac_cv_env_CXX_value=false' "$build_dir/config.log"; then
    echo "glibc configure unexpectedly enabled a C++ compiler" >&2
    return 1
  fi
  [[ $(grep -o -- '-B[^ ]*' "$build_dir/config.make" | sort -u | wc -l) -ge 1 ]] || {
    echo "glibc configure lacks its sealed Binutils search prefix" >&2
    return 1
  }

  make -C "$build_dir" -j"$jobs"
  make -C "$build_dir" -j1 install_root="$candidate" install
  normalize_getconf_hardlinks "$candidate"
  [[ ! -e $candidate/lib64 && ! -L $candidate/lib64 ]] || {
    echo "Complete glibc install unexpectedly created a root lib64 path" >&2
    return 1
  }
  ln -s usr/lib "$candidate/lib64"
}

(
  cd "$build_a"
  configure_and_stage "$build_a" "$snapshot_temporary"
)
(
  cd "$build_b"
  configure_and_stage "$build_b" "$candidate_b"
)

required_runtime=(
  usr/lib/ld-linux-x86-64.so.2
  usr/lib/libc.so.6 usr/lib/libc.so usr/lib/libc.a usr/lib/libc_nonshared.a
  usr/lib/libm.so.6 usr/lib/libm.so usr/lib/libm.a usr/lib/libmvec.so.1
  usr/lib/libpthread.so.0
  usr/lib/Mcrt1.o usr/lib/Scrt1.o usr/lib/gcrt1.o usr/lib/grcrt1.o usr/lib/rcrt1.o
  usr/bin/getconf sbin/ldconfig sbin/sln etc/rpc var/db/Makefile
)
expected_stub_macros=$'__stub___compat_bdflush\n__stub_chflags\n__stub_fchflags\n__stub_gtty\n__stub_revoke\n__stub_setlogin\n__stub_sigreturn\n__stub_stty'
for candidate in "$snapshot_temporary" "$candidate_b"; do
  [[ -L $candidate/lib64 && $(readlink -- "$candidate/lib64") == usr/lib ]] || {
    echo "Complete glibc candidate lacks exact lib64 -> usr/lib alias" >&2
    exit 118
  }
  for relative in "${required_runtime[@]}"; do
    [[ -f $candidate/$relative ]] || {
      echo "Complete glibc candidate lacks $relative" >&2
      exit 119
    }
  done
  actual_stub_macros=$(sed -n 's/^#define \(__stub_[A-Za-z0-9_]*\)[[:space:]]*$/\1/p' \
    "$candidate/usr/include/gnu/stubs-64.h" | sort)
  [[ $actual_stub_macros == "$expected_stub_macros" ]] || {
    echo "Complete glibc generated an unexpected stubs-64 macro set" >&2
    exit 120
  }
  for crt in crt1.o crti.o crtn.o; do
    cmp -s "$base_snapshot/usr/lib/$crt" "$candidate/usr/lib/$crt" || {
      echo "Complete glibc changed inherited $crt" >&2
      exit 121
    }
  done
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

# Confirm the immutable headers base and corrected libgcc prefix never changed.
"$script_path" --internal-python inventory "$base_snapshot" > "$artifact_temporary/base-after.json"
cmp -s "$artifact_temporary/base-before.json" "$artifact_temporary/base-after.json" || {
  echo "Sealed glibc headers base changed during the complete build" >&2
  exit 122
}
"$script_path" --internal-python dependency-inventory \
  "$libgcc_prefix" "$tools_root" > "$artifact_temporary/tools-after.json"
cmp -s "$artifact_temporary/tools-before.json" "$artifact_temporary/tools-after.json" || {
  echo "Sealed libgcc prefix changed during the complete glibc build" >&2
  exit 123
}

configuration_dir=$artifact_temporary/configuration
mkdir -p "$configuration_dir/build-a" "$configuration_dir/build-b"
for name in config.log config.make; do
  install -m 0644 "$build_a/$name" "$configuration_dir/build-a/$name"
  install -m 0644 "$build_b/$name" "$configuration_dir/build-b/$name"
done
python3 - \
  "$configuration_dir/build-a" "$build_a" "$snapshot_temporary" "$temporary_root" \
  "$configuration_dir/build-b" "$build_b" "$candidate_b" "$temporary_root" <<'PY'
from pathlib import Path
import sys

arguments = sys.argv[1:]
for offset in range(0, len(arguments), 4):
    evidence = Path(arguments[offset])
    build, candidate, temporary_root = arguments[offset + 1:offset + 4]
    replacements = (
        (candidate, "<CANDIDATE>"),
        (build, "<BUILD>"),
        (temporary_root, "<TEMPORARY_ROOT>"),
    )
    for path in sorted(evidence.iterdir()):
        text = path.read_text(encoding="utf-8")
        for original, normalized in replacements:
            text = text.replace(original, normalized)
        if "/.tmp-" in text or "/work/" in text:
            raise SystemExit(f"retained configuration contains a disposable path: {path}")
        path.write_text(text, encoding="utf-8")
        path.chmod(0o644)
PY
license_dir=$artifact_temporary/licenses/glibc
mkdir -p "$license_dir"
git -C "$glibc_source_dir" archive "$locked_glibc_commit" -- "${license_paths[@]}" |
  tar -x -C "$license_dir"
"$script_path" --internal-python inventory "$license_dir" \
  > "$artifact_temporary/license-inventory.json"

# Close every mutable-input window while both locks remain held.
"$project_root/scripts/fetch.py" validate --root "$cajunos_root"
if ! final_chain_output=$(resolve_chain); then
  echo "Dependency-chain revalidation failed" >&2
  exit 124
fi
if [[ $final_chain_output != "$chain_output" ]]; then
  echo "Linux/GCC/Binutils provenance changed during complete glibc" >&2
  exit 125
fi
if ! final_runtime_chain_output=$(resolve_runtime_chain); then
  echo "glibc-headers/libgcc dependency revalidation failed" >&2
  exit 126
fi
if [[ $final_runtime_chain_output != "$runtime_chain_output" ]]; then
  echo "Runtime dependency provenance changed during complete glibc" >&2
  exit 127
fi
if [[ -n $(git -C "$project_root" status --porcelain) \
   || $(git -C "$project_root" rev-parse HEAD) != "$orchestration_commit" \
   || $(git -C "$project_root" rev-parse 'HEAD^{tree}') != "$orchestration_tree" ]]; then
  echo "CajunOS orchestration changed during complete glibc" >&2
  exit 128
fi
"$script_path" --internal-python inventory "$base_snapshot" > "$artifact_temporary/base-final.json"
cmp -s "$artifact_temporary/base-before.json" "$artifact_temporary/base-final.json" || {
  echo "Sealed glibc headers base changed before publication" >&2
  exit 129
}
"$script_path" --internal-python dependency-inventory \
  "$libgcc_prefix" "$tools_root" > "$artifact_temporary/tools-final.json"
cmp -s "$artifact_temporary/tools-before.json" "$artifact_temporary/tools-final.json" || {
  echo "Sealed libgcc prefix changed before publication" >&2
  exit 130
}
selector_state=$("$script_path" --internal-python selector-state \
  "$sysroot" "$glibc_headers_build_id" "$build_id")
[[ $selector_state == base ]] || {
  echo "Cohort selector changed before complete-glibc publication" >&2
  exit 131
}

revalidate_publication_inputs() {
  local actual_chain actual_runtime actual_selector actual_hash
  "$project_root/scripts/fetch.py" validate --root "$cajunos_root" >/dev/null
  if ! actual_chain=$(resolve_chain) || [[ $actual_chain != "$chain_output" ]]; then
    echo "Linux/GCC/Binutils provenance changed before final publication" >&2
    return 1
  fi
  if ! actual_runtime=$(resolve_runtime_chain) \
     || [[ $actual_runtime != "$runtime_chain_output" ]]; then
    echo "glibc-headers/libgcc provenance changed before final publication" >&2
    return 1
  fi
  if [[ -n $(git -C "$project_root" status --porcelain) \
     || $(git -C "$project_root" rev-parse HEAD) != "$orchestration_commit" \
     || $(git -C "$project_root" rev-parse 'HEAD^{tree}') != "$orchestration_tree" ]]; then
    echo "CajunOS orchestration changed before final publication" >&2
    return 1
  fi
  for hash_pair in \
    "$script_path:$recipe_sha256" \
    "$inventory_helper:$helper_sha256" \
    "$headers_helper:$headers_helper_sha256" \
    "$libgcc_helper:$libgcc_helper_sha256"; do
    actual_hash=$(sha256sum "${hash_pair%%:*}" | awk '{print $1}')
    [[ $actual_hash == "${hash_pair#*:}" ]] || {
      echo "A frozen recipe/helper changed before final publication" >&2
      return 1
    }
  done
  cmp -s "$artifact_temporary/base-before.json" \
    <("$script_path" --internal-python inventory "$base_snapshot") || {
    echo "Sealed glibc headers base changed before final publication" >&2
    return 1
  }
  cmp -s "$artifact_temporary/tools-before.json" \
    <("$script_path" --internal-python dependency-inventory \
      "$libgcc_prefix" "$tools_root") || {
    echo "Sealed libgcc prefix changed before final publication" >&2
    return 1
  }
  actual_selector=$("$script_path" --internal-python selector-state \
    "$sysroot" "$glibc_headers_build_id" "$build_id")
  [[ $actual_selector == base \
     && -L $tools_root/current \
     && $(readlink -- "$tools_root/current") == "$active_tools_id" ]] || {
    echo "A managed selector changed before final publication" >&2
    return 1
  }
  [[ -d $temporary_root && ! -L $temporary_root \
     && -d $snapshot_final && ! -L $snapshot_final \
     && -d $artifact_temporary && ! -L $artifact_temporary \
     && ! -e $build_final && ! -L $build_final \
     && ! -e $artifact_final && ! -L $artifact_final ]] || {
    echo "Publication paths changed before final publication" >&2
    return 1
  }
}

# Establish the permanent, still-unselected snapshot before persistent probes.
# This keeps all retained path evidence stable while failures remain quarantinable.
"$script_path" --internal-python validate-directories "$cajunos_root" \
  work work/sysroot tools artifacts logs sysroot \
  "sysroot/$cohort_id" "sysroot/$cohort_id/snapshots" \
  "work/sysroot/.tmp-$build_id-$$" \
  "sysroot/$cohort_id/snapshots/.tmp-$build_id-$$" \
  "artifacts/.tmp-$build_id-$$"
mv -T -- "$snapshot_temporary" "$snapshot_final"
snapshot_established=1

probe_dir=$artifact_temporary/probe
mkdir -p "$probe_dir"
cat > "$probe_dir/dynamic.c" <<'EOF'
#define _GNU_SOURCE
#include <gnu/libc-version.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static _Thread_local unsigned int cajunos_tls;
static volatile unsigned __int128 dividend =
    (((unsigned __int128)UINT64_C(0xfedcba9876543210)) << 64)
    | UINT64_C(0x0123456789abcdef);
static volatile unsigned __int128 divisor = 97;

static void *worker(void *argument)
{
    cajunos_tls = *(const unsigned int *)argument;
    return cajunos_tls == 42 ? argument : NULL;
}

int main(void)
{
    unsigned int expected = 42;
    pthread_t thread;
    void *result = NULL;
    void *allocation = malloc(4096);
    if (allocation == NULL)
        return 10;
    free(allocation);
    if (pthread_create(&thread, NULL, worker, &expected) != 0)
        return 11;
    if (pthread_join(thread, &result) != 0 || result != &expected)
        return 12;
    unsigned __int128 quotient = dividend / divisor;
    unsigned __int128 remainder = dividend % divisor;
    if (quotient * divisor + remainder != dividend)
        return 13;
    printf("glibc=%s pthread=ok division=ok\n", gnu_get_libc_version());
    return 0;
}
EOF
cat > "$probe_dir/static.c" <<'EOF'
#include <gnu/libc-version.h>
#include <stdint.h>
#include <stdio.h>

static volatile unsigned __int128 dividend =
    (((unsigned __int128)UINT64_C(0xabcdef0123456789)) << 64)
    | UINT64_C(0x9876543210fedcba);
static volatile unsigned __int128 divisor = 89;

int main(void)
{
    unsigned __int128 quotient = dividend / divisor;
    unsigned __int128 remainder = dividend % divisor;
    if (quotient * divisor + remainder != dividend)
        return 20;
    printf("glibc=%s static=ok division=ok\n", gnu_get_libc_version());
    return 0;
}
EOF

(
  cd "$probe_dir"
  "$cross_gcc" --sysroot="$snapshot_final" -fno-link-libatomic \
    -std=c11 -O2 -g0 -fPIE -Wall -Wextra -Werror -pthread \
    -c dynamic.c -o dynamic.o
  "$cross_gcc" --sysroot="$snapshot_final" -fno-link-libatomic \
    -pie -pthread dynamic.o -Wl,-Map,dynamic.map -o dynamic
  chmod 0755 dynamic
  "$cross_readelf" -hW dynamic > dynamic.readelf-h
  "$cross_readelf" -lW dynamic > dynamic.readelf-l
  "$cross_readelf" -dW dynamic > dynamic.readelf-d
  grep -Eq 'Type:[[:space:]]+DYN[[:space:]]' dynamic.readelf-h
  grep -Fq '[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]' \
    dynamic.readelf-l
  "$snapshot_final/lib64/ld-linux-x86-64.so.2" \
    --inhibit-cache --library-path "$snapshot_final/usr/lib" ./dynamic \
    > dynamic.stdout
  grep -Fxq 'glibc=2.44.9000 pthread=ok division=ok' dynamic.stdout
  "$snapshot_final/lib64/ld-linux-x86-64.so.2" \
    --inhibit-cache --library-path "$snapshot_final/usr/lib" --list ./dynamic \
    | sed -E 's/ \(0x[0-9a-fA-F]+\)//g' > loader.list
  "$snapshot_final/lib64/ld-linux-x86-64.so.2" \
    --inhibit-cache --library-path "$snapshot_final/usr/lib" \
    "$snapshot_final/usr/bin/getconf" GNU_LIBC_VERSION > getconf.stdout
  grep -Fxq 'glibc 2.44.9000' getconf.stdout

  "$cross_gcc" --sysroot="$snapshot_final" -fno-link-libatomic \
    -std=c11 -O2 -g0 -fno-PIE -Wall -Wextra -Werror -c static.c -o static.o
  "$cross_gcc" --sysroot="$snapshot_final" -fno-link-libatomic \
    -static -no-pie static.o -Wl,-Map,static.map -o static
  chmod 0755 static
  "$cross_readelf" -hW static > static.readelf-h
  "$cross_readelf" -lW static > static.readelf-l
  "$cross_readelf" -dW static > static.readelf-d
  grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]' static.readelf-h
  if grep -q 'Requesting program interpreter' static.readelf-l; then
    echo "Static probe unexpectedly has a program interpreter" >&2
    exit 1
  fi
  if grep -q '(NEEDED)' static.readelf-d; then
    echo "Static probe unexpectedly has a dynamic dependency" >&2
    exit 1
  fi
  ./static > static.stdout
  grep -Fxq 'glibc=2.44.9000 static=ok division=ok' static.stdout
)

"$script_path" --internal-python elf-scan "$snapshot_final" \
  > "$probe_dir/installed-elf-scan.json"
python3 - "$probe_dir/installed-elf-scan.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    scan = json.load(stream)
if len(scan.get("elf_files", [])) < 300:
    raise SystemExit("complete glibc installed too few ELF outputs")
for key in (
    "undefined_atomic_symbols", "forbidden_needed",
    "escaping_rpath_runpath", "executable_stack",
):
    if scan.get(key) != []:
        raise SystemExit(f"installed ELF scan rejected {key}: {scan.get(key)}")
PY

"$script_path" --internal-python compare \
  "$snapshot_final" "$candidate_b" "$artifact_temporary/inventory-after-probe.json"
cmp -s "$artifact_temporary/inventory.json" "$artifact_temporary/inventory-after-probe.json" || {
  echo "Complete glibc snapshot changed while running probes" >&2
  exit 132
}

ensure_cohort_lib64_alias

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
  "$glibc_headers_build_id" "$base_snapshot" "$base_snapshot_digest" \
  "$result_snapshot_digest" "$orchestration_commit" "$orchestration_tree" \
  "$recipe_sha256" "$helper_sha256" "$headers_helper_sha256" \
  "$libgcc_helper_sha256" "$options_digest" \
  "$glibc_headers_receipt" "$glibc_headers_receipt_sha256" \
  "$libgcc_build_id" "$libgcc_prefix" "$libgcc_prefix_digest" "$gcc_version" \
  "$libgcc_receipt" "$libgcc_receipt_sha256" \
  "$libgcc_orchestration_commit" "$libgcc_orchestration_tree" \
  "$linux_build_id" "$linux_snapshot" "$linux_snapshot_digest" \
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
  "$probe_dir" "$license_dir" "$configuration_dir" "$snapshot_final" \
  "$log_file" <<'PY'
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
    license_inventory_value, build_id, source_commit, source_tree,
    source_repository, source_set_digest, source_authentication,
    source_date_epoch, target, arch, minimum_kernel, build_triplet,
    target_cflags, sysroot, snapshot, headers_build_id, base_snapshot,
    base_snapshot_digest, result_snapshot_digest, orchestration_commit,
    orchestration_tree, recipe_sha256, helper_sha256, headers_helper_sha256,
    libgcc_helper_sha256, options_digest, headers_receipt,
    headers_receipt_sha256, libgcc_build_id, libgcc_prefix,
    libgcc_prefix_digest, gcc_version, libgcc_receipt, libgcc_receipt_sha256,
    libgcc_orchestration_commit, libgcc_orchestration_tree, linux_build_id,
    linux_snapshot, linux_snapshot_digest, linux_receipt, linux_receipt_sha256,
    linux_source_commit, linux_source_tree, linux_source_repository,
    linux_orchestration_commit, linux_orchestration_tree, linux_recipe_sha256,
    gcc_build_id, gcc_prefix, gcc_receipt, gcc_receipt_sha256,
    gcc_source_commit, gcc_source_tree, gcc_source_repository,
    gcc_orchestration_commit, gcc_orchestration_tree, binutils_build_id,
    binutils_prefix, binutils_receipt, binutils_receipt_sha256,
    binutils_source_commit, binutils_source_tree, binutils_source_repository,
    binutils_orchestration_commit, binutils_orchestration_tree, probe_value,
    license_value, configuration_value, candidate_value, log_file,
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
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
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

stub_macros = sorted((
    "__stub___compat_bdflush", "__stub_chflags", "__stub_fchflags",
    "__stub_gtty", "__stub_revoke", "__stub_setlogin",
    "__stub_sigreturn", "__stub_stty",
))
runtime_relatives = (
    "usr/lib/ld-linux-x86-64.so.2", "usr/lib/libc.so.6",
    "usr/lib/libc.so", "usr/lib/libc.a", "usr/lib/libc_nonshared.a",
    "usr/lib/libm.so.6", "usr/lib/libm.so", "usr/lib/libm.a",
    "usr/lib/libmvec.so.1", "usr/lib/libpthread.so.0",
    "usr/lib/Mcrt1.o", "usr/lib/Scrt1.o", "usr/lib/gcrt1.o",
    "usr/lib/grcrt1.o", "usr/lib/rcrt1.o",
)
packages = {}
for package in ("make", "gcc", "rsync", "sed", "libc-bin"):
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=$" + "{Version}", package], check=False,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    packages[package] = result.stdout if result.returncode == 0 else None

evidence_sha256 = {}
for path in sorted(output.parent.iterdir()):
    if path == output or path.is_dir():
        continue
    metadata = path.lstat()
    if not path.is_file() or path.is_symlink() or metadata.st_nlink != 1:
        raise SystemExit(f"unsupported root evidence sidecar: {path}")
    evidence_sha256[path.name] = sha256(path)

receipt = {
    "schema": 1,
    "build_id": build_id,
    "component": "glibc",
    "stage": "complete",
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
    "sysroot_contract": "immutable-snapshots-merged-usr-v1",
    "snapshot": snapshot,
    "base_build_id": headers_build_id,
    "base_snapshot": base_snapshot,
    "base_snapshot_digest": base_snapshot_digest,
    "result_snapshot_digest": result_snapshot_digest,
    "functional_libc": "present",
    "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    "log": log_file,
    "orchestration_commit": orchestration_commit,
    "orchestration_tree": orchestration_tree,
    "recipe_sha256": recipe_sha256,
    "inventory_helper_sha256": helper_sha256,
    "headers_helper_sha256": headers_helper_sha256,
    "libgcc_helper_sha256": libgcc_helper_sha256,
    "options_digest": options_digest,
    "configure_options": options,
    "generation": {
        "build": "make -j<jobs> all",
        "install": "make -j1 install_root=<candidate> install",
        "cycle_breaker": "-fno-link-libatomic",
        "getconf_hardlinks": "independent-copies",
    },
    "runtime_layout": {
        "slibdir": "/usr/lib",
        "rtlddir": "/usr/lib",
        "snapshot_lib64_alias": "usr/lib",
        "cohort_lib64_alias": "current/usr/lib",
    },
    "reproducibility": {
        "independent_installations": 2,
        "inventory_schema": "paths-types-modes-sha256-symlink-targets-v1",
        "first_inventory_digest": result_snapshot_digest,
        "second_inventory_digest": result_snapshot_digest,
        "identical": True,
        "base_unchanged_after_build": True,
        "tools_unchanged_after_build": True,
        "post_probe_inventory_digest": result_snapshot_digest,
    },
    "dependencies": {
        "glibc_headers": {
            "build_id": headers_build_id, "receipt": headers_receipt,
            "receipt_sha256": headers_receipt_sha256,
            "snapshot": base_snapshot, "snapshot_digest": base_snapshot_digest,
        },
        "libgcc": {
            "build_id": libgcc_build_id, "prefix": libgcc_prefix,
            "prefix_digest": libgcc_prefix_digest, "gcc_version": gcc_version,
            "receipt": libgcc_receipt,
            "receipt_sha256": libgcc_receipt_sha256,
            "orchestration_commit": libgcc_orchestration_commit,
            "orchestration_tree": libgcc_orchestration_tree,
        },
        "linux": {
            "build_id": linux_build_id, "receipt": linux_receipt,
            "receipt_sha256": linux_receipt_sha256, "snapshot": linux_snapshot,
            "snapshot_digest": linux_snapshot_digest,
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
    "stubs_64": {
        "sha256": sha256(candidate / "usr/include/gnu/stubs-64.h"),
        "stub_macros": stub_macros,
    },
    "runtime_sha256": {
        relative: sha256(candidate / relative) for relative in runtime_relatives
    },
    "configuration_sha256": regular_hashes(configuration_dir),
    "evidence_sha256": evidence_sha256,
    "license_inventory": license_inventory,
    "outputs": {
        "probe_sha256": regular_hashes(probe_dir),
        "installed_elf_count": len(json.load(
            (probe_dir / "installed-elf-scan.json").open(encoding="utf-8")
        )["elf_files"]),
    },
    "probe_contract": {
        "dynamic": "ELF64-PIE-PT_INTERP=/lib64/ld-linux-x86-64.so.2",
        "execution": "candidate-loader-inhibit-cache-library-path-only",
        "static": "ELF64-static-no-PT_INTERP-no-DT_NEEDED",
        "atomic_runtime": "no-undefined-or-needed-libatomic",
    },
    "deferred_runtime": {
        "libgcc_s": "absent",
        "libstdcxx": "absent",
        "locale_archive": "absent",
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

validate_completed "$artifact_temporary/receipt.json" "$snapshot_final"
revalidate_publication_inputs

mv -T -- "$temporary_root" "$build_final"
build_established=1
mv -T -- "$artifact_temporary" "$artifact_final"
transition=$("$script_path" --internal-python selector-transition \
  "$sysroot" "$glibc_headers_build_id" "$build_id")
[[ $transition == advanced ]] || {
  echo "Published complete-glibc snapshot did not advance from its sealed base" >&2
  exit 133
}

validate_completed
validate_cohort_loader "$artifact_final"
selector_state=$("$script_path" --internal-python selector-state \
  "$sysroot" "$glibc_headers_build_id" "$build_id")
[[ $selector_state == this ]] || {
  echo "Published complete-glibc snapshot is not current" >&2
  exit 134
}
[[ -L $sysroot/lib64 && $(readlink -- "$sysroot/lib64") == current/usr/lib \
   && $(readlink -f -- "$sysroot/lib64/ld-linux-x86-64.so.2") \
      == $(readlink -f -- "$snapshot_final/usr/lib/ld-linux-x86-64.so.2") ]] || {
  echo "Published cohort loader alias is invalid" >&2
  exit 135
}
[[ $(readlink -- "$tools_root/current") == "$active_tools_id" ]] || {
  echo "Complete glibc unexpectedly changed tools/current" >&2
  exit 136
}

build_succeeded=1
trap - EXIT
echo "CAJUNOS_GLIBC_COMPLETE_OK build_id=$build_id snapshot=$snapshot_final"
