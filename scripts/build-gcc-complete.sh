#!/usr/bin/env bash
set -Eeuo pipefail
umask 022
export LC_ALL=C
export TZ=UTC
export PATH=/usr/bin:/bin

script_path=$(readlink -f -- "${BASH_SOURCE[0]}")
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
inventory_helper=$project_root/scripts/install-linux-headers.sh
libgcc_helper=$project_root/scripts/build-libgcc-bootstrap.sh
glibc_helper=$project_root/scripts/build-glibc-complete.sh

# Filesystem, generated-Makefile, probe, and selector contracts are exposed for
# forge-independent tests and for semantic replay of completed receipts.
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


TARGET = "x86_64-cajunos-linux-gnu"
LIBATOMIC_VERSION = "1.2.0"
LIBSTDCXX_VERSION = "6.0.37"


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
            if not stat.S_ISDIR(path.lstat().st_mode):
                fail(f"unsupported attestation directory entry: {path}")
        for name in filenames:
            path = directory_path / name
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                fail(f"unsupported attestation file: {path}")
            hashes[path.relative_to(root).as_posix()] = sha256(path)
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


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent, text=True
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(value)
    os.replace(temporary_name, path)
    path.chmod(0o644)


def regular_hardlinks(root: Path) -> list[Path]:
    try:
        root_metadata = root.lstat()
    except FileNotFoundError:
        fail("hardlink-contract root does not exist")
    if not stat.S_ISDIR(root_metadata.st_mode):
        fail("hardlink-contract root is not a real directory")
    found: list[Path] = []
    for directory, names, filenames in os.walk(root, followlinks=False):
        names.sort()
        filenames.sort()
        directory_path = Path(directory)
        for name in filenames:
            child = directory_path / name
            metadata = child.lstat()
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
                found.append(child)
    return found


def normalize_hardlinks(root: Path) -> int:
    # GCC installs its c++/g++ and gcc/gcc-VERSION aliases as hard links.
    # Break only the links that still have multiple names at the instant they
    # are visited. Atomic same-directory replacement preserves bytes and mode
    # while guaranteeing the sealed inventory's single-link invariant.
    changed = 0
    for path in regular_hardlinks(root):
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink == 1:
            continue
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.cajunos-unlink.", dir=path.parent
        )
        try:
            with path.open("rb") as source, os.fdopen(descriptor, "wb") as output:
                while block := source.read(1024 * 1024):
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary_name, stat.S_IMODE(metadata.st_mode))
            os.utime(
                temporary_name,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
                follow_symlinks=False,
            )
            os.replace(temporary_name, path)
            changed += 1
        finally:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
    remaining = regular_hardlinks(root)
    if remaining:
        fail(f"regular hardlinks remain after normalization: {remaining}")
    return changed


def normalize_modes(root: Path) -> dict[str, int]:
    try:
        root_metadata = root.lstat()
    except FileNotFoundError:
        fail("mode-normalization root does not exist")
    if not stat.S_ISDIR(root_metadata.st_mode):
        fail("mode-normalization root is not a real directory")
    changed = {"directories": 0, "files": 0}
    directories = [root]
    files: list[Path] = []
    for directory, names, filenames in os.walk(root, followlinks=False):
        names.sort()
        filenames.sort()
        directory_path = Path(directory)
        for name in names:
            child = directory_path / name
            metadata = child.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                directories.append(child)
            elif not stat.S_ISLNK(metadata.st_mode):
                fail(f"unsupported staged directory entry: {child}")
        for name in filenames:
            child = directory_path / name
            metadata = child.lstat()
            if stat.S_ISREG(metadata.st_mode):
                files.append(child)
            elif not stat.S_ISLNK(metadata.st_mode):
                fail(f"unsupported staged file entry: {child}")
    for directory in directories:
        if stat.S_IMODE(directory.lstat().st_mode) != 0o755:
            directory.chmod(0o755)
            changed["directories"] += 1
    for path in files:
        mode = stat.S_IMODE(path.lstat().st_mode)
        wanted = 0o755 if mode & 0o111 else 0o644
        if mode != wanted:
            path.chmod(wanted)
            changed["files"] += 1
    validate_modes(root)
    return changed


def validate_modes(root: Path) -> None:
    try:
        root_metadata = root.lstat()
    except FileNotFoundError:
        fail("mode-contract root does not exist")
    if not stat.S_ISDIR(root_metadata.st_mode):
        fail("mode-contract root is not a real directory")
    paths = [root, *sorted(root.rglob("*"))]
    for path in paths:
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            expected = {0o755}
        elif stat.S_ISREG(metadata.st_mode):
            expected = {0o644, 0o755}
        elif stat.S_ISLNK(metadata.st_mode):
            expected = {0o777}
        else:
            fail(f"mode-contract found an unsupported entry: {path}")
        if mode not in expected or (
            not stat.S_ISLNK(metadata.st_mode) and mode & 0o022
        ):
            fail(f"mode-contract found unsafe metadata: {path} mode={mode:04o}")


def validate_target_version(target: str, version: str) -> None:
    if target != TARGET:
        fail("unsupported target in complete GCC contract")
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", version):
        fail("unsafe GCC version in complete GCC contract")


def gcc_owned_path(path: str, target: str, version: str) -> bool:
    validate_target_version(target, version)
    pure = PurePosixPath(path)
    if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
        return False
    parts = pure.parts
    if not parts:
        return False
    if parts[0] == "bin" and len(parts) == 2:
        programs = {
            f"{target}-c++",
            f"{target}-cpp",
            f"{target}-g++",
            f"{target}-gcc",
            f"{target}-gcc-{version}",
            f"{target}-gcc-ar",
            f"{target}-gcc-nm",
            f"{target}-gcc-ranlib",
            f"{target}-gcov",
            f"{target}-gcov-dump",
            f"{target}-gcov-tool",
        }
        return parts[1] in programs
    for root in (
        ("lib", "gcc", target, version),
        ("libexec", "gcc", target, version),
    ):
        if parts[: len(root)] == root:
            return True
    if parts[0] == target:
        if len(parts) == 1:
            return True
        if parts[1] == "lib" and len(parts) == 2:
            return True
        if parts[1] == "lib64":
            return True
        include_root = (target, "include", "c++", version)
        if parts[: len(include_root)] == include_root:
            return True
        if parts in ((target, "include"), (target, "include", "c++")):
            return True
    if parts[0] == "share":
        if len(parts) >= 2 and (
            parts[1] in {"info", "man", "gdb"}
            or re.fullmatch(r"gcc-[0-9]+(?:\.[0-9]+){0,2}", parts[1])
        ):
            return True
    return False


def runtime_paths(target: str, version: str) -> dict[str, tuple[str, str | None]]:
    validate_target_version(target, version)
    gcc_root = f"lib/gcc/{target}/{version}"
    runtime_root = f"{target}/lib64"
    return {
        f"{gcc_root}/libgcc.a": ("file", None),
        f"{gcc_root}/libgcc_eh.a": ("file", None),
        f"{gcc_root}/libgcov.a": ("file", None),
        f"{runtime_root}/libgcc_s.so.1": ("file", None),
        f"{runtime_root}/libgcc_s.so": ("file", None),
        f"{runtime_root}/libgcc_s_asneeded.so": ("file", None),
        f"{runtime_root}/libatomic.a": ("file", None),
        f"{runtime_root}/libatomic.so.{LIBATOMIC_VERSION}": ("file", None),
        f"{runtime_root}/libatomic.so.1": (
            "symlink",
            f"libatomic.so.{LIBATOMIC_VERSION}",
        ),
        f"{runtime_root}/libatomic.so": (
            "symlink",
            f"libatomic.so.{LIBATOMIC_VERSION}",
        ),
        f"{runtime_root}/libatomic_asneeded.a": ("symlink", "libatomic.a"),
        f"{runtime_root}/libatomic_asneeded.so": ("file", None),
        f"{runtime_root}/libstdc++.a": ("file", None),
        f"{runtime_root}/libstdc++.so.{LIBSTDCXX_VERSION}": ("file", None),
        f"{runtime_root}/libstdc++.so.6": (
            "symlink",
            f"libstdc++.so.{LIBSTDCXX_VERSION}",
        ),
        f"{runtime_root}/libstdc++.so": (
            "symlink",
            f"libstdc++.so.{LIBSTDCXX_VERSION}",
        ),
        f"{runtime_root}/libstdc++exp.a": ("file", None),
        f"{runtime_root}/libstdc++fs.a": ("file", None),
        f"{runtime_root}/libsupc++.a": ("file", None),
    }


def required_programs(target: str, version: str) -> dict[str, tuple[str, str]]:
    return {
        f"bin/{target}-gcc": ("file", "0755"),
        f"bin/{target}-g++": ("file", "0755"),
        f"bin/{target}-c++": ("file", "0755"),
        f"libexec/gcc/{target}/{version}/cc1": ("file", "0755"),
        f"libexec/gcc/{target}/{version}/cc1plus": ("file", "0755"),
    }


def validate_runtime_topology(
    entries: dict[str, object], target: str, version: str
) -> None:
    for path, (kind, link_target) in runtime_paths(target, version).items():
        metadata = entries.get(path)
        if not isinstance(metadata, dict) or metadata.get("type") != kind:
            fail(f"required complete-GCC runtime has invalid type: {path}")
        if kind == "file":
            if (
                metadata.get("mode") not in {"0644", "0755"}
                or not re.fullmatch(r"[0-9a-f]{64}", str(metadata.get("sha256", "")))
            ):
                fail(f"required complete-GCC runtime has invalid metadata: {path}")
        elif metadata != {
            "type": "symlink",
            "mode": "0777",
            "target": link_target,
        }:
            fail(f"required complete-GCC runtime has invalid symlink: {path}")
    for path, (kind, mode) in required_programs(target, version).items():
        metadata = entries.get(path)
        if (
            not isinstance(metadata, dict)
            or metadata.get("type") != kind
            or metadata.get("mode") != mode
        ):
            fail(f"required complete-GCC program has invalid metadata: {path}")
    cxx_root = f"{target}/include/c++/{version}"
    if entries.get(cxx_root) != {"type": "directory", "mode": "0755"}:
        fail("complete GCC lacks its exact C++ include root")
    if any(path.endswith(".gch") or ".gch/" in path for path in entries):
        fail("complete GCC unexpectedly installed a precompiled header")
    forbidden = re.compile(
        r"^(?:libgomp|libitm|libasan|liblsan|libtsan|libubsan|"
        r"libquadmath|libssp|libvtv)(?:\.|_).*"
    )
    for path in entries:
        name = PurePosixPath(path).name
        if forbidden.match(name):
            fail(f"deferred target runtime is unexpectedly present: {path}")


def derive_delta(
    base: dict[str, object],
    result: dict[str, object],
    target: str,
    version: str,
) -> dict[str, object]:
    base_entries = base.get("entries")
    result_entries = result.get("entries")
    if not isinstance(base_entries, dict) or not isinstance(result_entries, dict):
        fail("invalid tools-prefix inventories")
    deleted = sorted(set(base_entries) - set(result_entries))
    if deleted:
        fail(f"sealed tools-prefix entries disappeared: {deleted}")
    replaced = {
        path: {"before": base_entries[path], "after": result_entries[path]}
        for path in base_entries
        if result_entries[path] != base_entries[path]
    }
    added = {
        path: metadata
        for path, metadata in result_entries.items()
        if path not in base_entries
    }
    if not replaced or not added:
        fail("complete GCC did not produce the required prefix transform")
    for path in (*replaced, *added):
        if not gcc_owned_path(path, target, version):
            fail(f"complete GCC changed an unowned prefix entry: {path}")
    for path, metadata in result_entries.items():
        if not isinstance(metadata, dict):
            fail(f"invalid complete-GCC inventory metadata: {path}")
        mode = metadata.get("mode")
        if isinstance(mode, str) and int(mode, 8) & 0o6000:
            fail(f"set-id complete-GCC output is forbidden: {path}")
        if metadata.get("type") == "directory" and mode != "0755":
            fail(f"complete-GCC directory mode is not sealed: {path}")
        if metadata.get("type") == "file" and mode not in {"0644", "0755"}:
            fail(f"complete-GCC file mode is not sealed: {path}")
        if metadata.get("type") == "symlink" and mode != "0777":
            fail(f"complete-GCC symlink mode is not sealed: {path}")
    validate_runtime_topology(result_entries, target, version)
    for path, metadata in base_entries.items():
        if path.startswith(f"bin/{target}-") and metadata.get("type") == "symlink":
            if result_entries.get(path) != metadata:
                fail(f"sealed Binutils link changed: {path}")
    return {
        "schema": "sealed-tools-prefix-transform-v1",
        "base_digest": f"sha256:{base['digest']}",
        "result_digest": f"sha256:{result['digest']}",
        "added_entries": added,
        "added_entries_digest": f"sha256:{canonical_digest(added)}",
        "replaced_entries": replaced,
        "replaced_entries_digest": f"sha256:{canonical_digest(replaced)}",
    }


def require_semantic_path(reported: str, expected: Path, label: str) -> None:
    if (
        not os.path.isabs(reported)
        or os.path.normpath(reported) != str(expected)
        or not expected.is_absolute()
    ):
        fail(f"{label} uses an unsafe path: {reported}")
    try:
        reported_real = Path(reported).resolve(strict=True)
        expected_real = expected.resolve(strict=True)
    except (OSError, RuntimeError):
        fail(f"{label} uses an invalid path: {reported}")
    if reported_real != expected_real:
        fail(f"{label} escapes its expected prefix: {reported}")


def lookup_paths(prefix: Path, target: str, version: str) -> dict[str, Path]:
    gcc_root = prefix / f"lib/gcc/{target}/{version}"
    runtime_root = prefix / f"{target}/lib64"
    values = {
        "libgcc.a": gcc_root / "libgcc.a",
        "libgcc_eh.a": gcc_root / "libgcc_eh.a",
        "libgcov.a": gcc_root / "libgcov.a",
        "libgcc_s.so": runtime_root / "libgcc_s.so",
        "libgcc_s.so.1": runtime_root / "libgcc_s.so.1",
        "libgcc_s_asneeded.so": runtime_root / "libgcc_s_asneeded.so",
        "libatomic.a": runtime_root / "libatomic.a",
        "libatomic.so": runtime_root / "libatomic.so",
        "libatomic.so.1": runtime_root / "libatomic.so.1",
        "libatomic_asneeded.a": runtime_root / "libatomic_asneeded.a",
        "libatomic_asneeded.so": runtime_root / "libatomic_asneeded.so",
        "libstdc++.a": runtime_root / "libstdc++.a",
        "libstdc++.so": runtime_root / "libstdc++.so",
        "libstdc++.so.6": runtime_root / "libstdc++.so.6",
        "libstdc++exp.a": runtime_root / "libstdc++exp.a",
        "libstdc++fs.a": runtime_root / "libstdc++fs.a",
        "libsupc++.a": runtime_root / "libsupc++.a",
    }
    for name in (
        "crtbegin.o",
        "crtbeginS.o",
        "crtbeginT.o",
        "crtend.o",
        "crtendS.o",
        "crtfastmath.o",
        "crtprec32.o",
        "crtprec64.o",
        "crtprec80.o",
    ):
        values[name] = gcc_root / name
    return values


def validate_runtime_lookups(
    prefix: Path, lookup_path: Path, target: str, version: str
) -> None:
    validate_target_version(target, version)
    if not prefix.is_absolute() or os.path.normpath(prefix) != str(prefix):
        fail("unsafe prefix for complete-GCC lookup contract")
    try:
        prefix_metadata = prefix.lstat()
        lookup_metadata = lookup_path.lstat()
    except FileNotFoundError:
        fail("complete-GCC lookup input does not exist")
    if not stat.S_ISDIR(prefix_metadata.st_mode):
        fail("complete-GCC lookup prefix is not a real directory")
    if (
        not stat.S_ISREG(lookup_metadata.st_mode)
        or lookup_metadata.st_nlink != 1
        or stat.S_IMODE(lookup_metadata.st_mode) != 0o644
    ):
        fail("runtime lookup evidence is not a plain mode-0644 file")
    values: dict[str, str] = {}
    for line in lookup_path.read_text(encoding="utf-8").splitlines():
        name, separator, value = line.partition("=")
        if not separator or not name or name in values:
            fail("runtime lookup evidence is malformed or duplicated")
        values[name] = value
    expected = lookup_paths(prefix, target, version)
    if set(values) != set(expected):
        fail(
            "runtime lookup evidence has unexpected entries: "
            f"missing={sorted(set(expected) - set(values))}, "
            f"unexpected={sorted(set(values) - set(expected))}"
        )
    gcc = prefix / "bin" / f"{target}-gcc"
    gxx = prefix / "bin" / f"{target}-g++"
    live = {}
    for name in expected:
        if name == "libgcc.a":
            live[name] = command_output([gcc, "-print-libgcc-file-name"]).strip()
        else:
            live[name] = command_output(
                [gxx, f"-print-file-name={name}"]
            ).strip()
    if values != live:
        fail("runtime lookup evidence differs from the live complete-GCC drivers")
    for name, expected_path in expected.items():
        try:
            metadata = expected_path.lstat()
        except FileNotFoundError:
            fail(f"expected complete-GCC lookup is absent: {name}")
        if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
            fail(f"expected complete-GCC lookup has an invalid type: {name}")
        require_semantic_path(
            values[name], expected_path, f"derived complete-GCC lookup for {name}"
        )


def scan_runtime_elf(prefix: Path, target: str, version: str) -> dict[str, object]:
    validate_target_version(target, version)
    runtime_root = prefix / f"{target}/lib64"
    gcc_root = prefix / f"lib/gcc/{target}/{version}"
    for root in (runtime_root, gcc_root):
        if not root.is_dir() or root.is_symlink():
            fail(f"runtime ELF root is not a real directory: {root}")
    elf_files = []
    rpath_runpath = []
    executable_stack = []
    disposable_paths = []
    sonames: dict[str, str] = {}
    needed: dict[str, list[str]] = {}
    for root in (runtime_root, gcc_root):
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            with path.open("rb") as stream:
                if stream.read(4) != b"\x7fELF":
                    continue
            relative = path.relative_to(prefix).as_posix()
            header = subprocess.run(
                ["/usr/bin/readelf", "-hW", path],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout
            if not re.search(r"Class:\s+ELF64", header) or not re.search(
                r"Machine:\s+Advanced Micro Devices X86-64", header
            ):
                fail(f"target runtime ELF has an unexpected ABI: {relative}")
            dynamic = subprocess.run(
                ["/usr/bin/readelf", "-dW", path],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout
            soname_match = re.search(
                r"\(SONAME\).*Library soname: \[([^\]]+)\]", dynamic
            )
            if soname_match:
                sonames[relative] = soname_match.group(1)
            needed[relative] = re.findall(
                r"\(NEEDED\).*Shared library: \[([^\]]+)\]", dynamic
            )
            for tag, value in re.findall(
                r"\((RPATH|RUNPATH)\).*Library (?:rpath|runpath): \[([^\]]*)\]",
                dynamic,
            ):
                if value:
                    rpath_runpath.append(f"{relative}: {tag}={value}")
            program = subprocess.run(
                ["/usr/bin/readelf", "-lW", path],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout
            if any(
                "GNU_STACK" in line and re.search(r"\bRWE\b", line)
                for line in program.splitlines()
            ):
                executable_stack.append(relative)
            strings = subprocess.run(
                ["/usr/bin/strings", "-a", path],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout
            bad = sorted(
                {
                    line
                    for line in strings.splitlines()
                    if "/.tmp-gcc-complete-" in line
                    or "/work/toolchain/.tmp-" in line
                }
            )
            if bad:
                disposable_paths.append({"path": relative, "values": bad})
            elf_files.append({"path": relative, "sha256": sha256(path)})
    expected_sonames = {
        f"{target}/lib64/libgcc_s.so.1": "libgcc_s.so.1",
        f"{target}/lib64/libatomic.so.{LIBATOMIC_VERSION}": "libatomic.so.1",
        f"{target}/lib64/libstdc++.so.{LIBSTDCXX_VERSION}": "libstdc++.so.6",
    }
    for path, soname in expected_sonames.items():
        if sonames.get(path) != soname:
            fail(f"complete-GCC shared runtime has the wrong SONAME: {path}")
    if rpath_runpath:
        fail(f"complete-GCC target runtime retains RPATH/RUNPATH: {rpath_runpath}")
    if executable_stack:
        fail(f"complete-GCC target runtime requests executable stack: {executable_stack}")
    if disposable_paths:
        fail("complete-GCC target runtime retains disposable build paths")
    return {
        "schema": "cajunos-gcc-complete-runtime-elf-scan-v1",
        "elf_files": elf_files,
        "sonames": sonames,
        "needed": needed,
        "rpath_runpath": rpath_runpath,
        "executable_stack": executable_stack,
        "disposable_paths": disposable_paths,
    }


def validate_link_map(map_path: Path, prefix: Path, snapshot: Path) -> None:
    for root, label in ((prefix, "prefix"), (snapshot, "snapshot")):
        if not root.is_absolute() or os.path.normpath(root) != str(root):
            fail(f"unsafe {label} for complete-GCC link-map contract")
        try:
            metadata = root.lstat()
        except FileNotFoundError:
            fail(f"link-map {label} does not exist")
        if not stat.S_ISDIR(metadata.st_mode):
            fail(f"link-map {label} is not a real directory")
    try:
        metadata = map_path.lstat()
    except FileNotFoundError:
        fail("complete-GCC link map does not exist")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o644
    ):
        fail("complete-GCC link map is not a plain mode-0644 file")
    contents = map_path.read_text(encoding="utf-8")
    if (
        "/.tmp-" in contents
        or "/work/" in contents
        or re.search(r"/tmp/cc[A-Za-z0-9]+", contents)
        or "/usr/lib/x86_64-linux-gnu" in contents
    ):
        fail(f"{map_path.name} retains a disposable or host path")
    normalized = contents.replace(f"{prefix}/bin/../", f"{prefix}/")
    if f"{prefix}/" not in normalized or f"{snapshot}/" not in normalized:
        fail(f"{map_path.name} does not bind both sealed runtime roots")
    allowed_real = (prefix.resolve(strict=True), snapshot.resolve(strict=True))
    path_pattern = re.compile(r"(?<![A-Za-z0-9_])(/[^\s()]+)")
    for match in path_pattern.finditer(contents):
        reported = match.group(1).rstrip(",")
        if reported == "/DISCARD/":
            continue
        normalized_path = Path(os.path.normpath(reported))
        try:
            resolved = Path(reported).resolve(strict=True)
        except (FileNotFoundError, OSError, RuntimeError):
            fail(f"{map_path.name} contains an invalid absolute input: {reported}")
        if not any(
            resolved == root or root in resolved.parents for root in allowed_real
        ):
            fail(f"{map_path.name} input escapes sealed roots: {reported}")
        if normalized_path.resolve(strict=True) != resolved:
            fail(f"{map_path.name} contains an unstable path: {reported}")


def validate_probe_paths(probe_root: Path, prefix: Path, snapshot: Path) -> None:
    try:
        root_metadata = probe_root.lstat()
    except FileNotFoundError:
        fail("complete-GCC probe directory does not exist")
    if not stat.S_ISDIR(root_metadata.st_mode):
        fail("complete-GCC probe path is not a real directory")
    for path in sorted(probe_root.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) not in {0o644, 0o755}
        ):
            fail(f"complete-GCC probe evidence has unsafe metadata: {path}")
        if path.suffix in {".map", ".txt", ".nm", ".search", ".list"}:
            text = path.read_text(encoding="utf-8")
            if (
                "/.tmp-" in text
                or "/work/" in text
                or re.search(r"/tmp/cc[A-Za-z0-9]+", text)
            ):
                fail(f"complete-GCC probe evidence retains a disposable path: {path}")
    validate_runtime_lookups(
        prefix,
        probe_root / "runtime-lookups.txt",
        TARGET,
        next(
            part
            for part in (prefix / "lib/gcc" / TARGET).iterdir()
            if part.is_dir() and re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", part.name)
        ).name,
    )
    for name in ("cxx-dynamic.map", "atomic-dynamic.map", "cxx-static.map"):
        validate_link_map(probe_root / name, prefix, snapshot)


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
        metadata = prefix.lstat()
    except FileNotFoundError:
        fail("tools/current names an absent prefix")
    if not stat.S_ISDIR(metadata.st_mode):
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


def evaluate_make(
    makefile: Path, variables: tuple[str, ...], assignments: tuple[str, ...] = ()
) -> dict[str, str]:
    if not makefile.is_absolute() or os.path.normpath(makefile) != str(makefile):
        fail("unsafe generated Makefile path")
    metadata = makefile.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail("generated Makefile is not a plain single-linked file")
    target = "__cajunos_print_complete_gcc_contract"
    fields = " ".join(f'"{name}=$(strip $({name}))"' for name in variables)
    recipe = f'{target}: ; @printf "%s\\n" {fields}'
    result = subprocess.run(
        [
            "/usr/bin/make",
            "-s",
            "-C",
            str(makefile.parent),
            "-f",
            str(makefile),
            "--no-print-directory",
            *assignments,
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
        fail(result.stderr.strip() or "could not evaluate generated Makefile")
    lines = result.stdout.splitlines()
    if len(lines) != len(variables) or any("=" not in line for line in lines):
        fail("generated Makefile contract produced malformed output")
    return dict(line.split("=", 1) for line in lines)


def validate_top_level_make(
    makefile: Path, target_sysroot: str, build_sysroot: str
) -> None:
    values = evaluate_make(
        makefile,
        (
            "TARGET_CONFIGDIRS",
            "CFLAGS",
            "CXXFLAGS",
            "CFLAGS_FOR_TARGET",
            "CXXFLAGS_FOR_TARGET",
            "XGCC_FLAGS_FOR_TARGET",
            "TOPLEVEL_CONFIGURE_ARGUMENTS",
            "MAKE",
            "LIBGCC2_DEBUG_CFLAGS",
        ),
        (
            "MAKE=/usr/bin/make LIBGCC2_DEBUG_CFLAGS=-g0",
            "LIBGCC2_DEBUG_CFLAGS=-g0",
        ),
    )
    if values["TARGET_CONFIGDIRS"] != "libgcc libatomic libstdc++-v3":
        fail("top-level GCC target library set is not exact")
    if values["CFLAGS"] != "-O2 -g0" or values["CXXFLAGS"] != "-O2 -g0":
        fail("top-level GCC host flags are not deterministic")
    target_flags = "-O2 -g0 -march=x86-64-v2 -mtune=generic"
    if values["CFLAGS_FOR_TARGET"] != target_flags:
        fail("top-level GCC target C flags are not exact")
    if values["CXXFLAGS_FOR_TARGET"] not in {
        target_flags,
        f"{target_flags} -D_GNU_SOURCE",
    }:
        fail("top-level GCC target C++ flags are not exact")
    if (
        values["MAKE"] != "/usr/bin/make LIBGCC2_DEBUG_CFLAGS=-g0"
        or values["LIBGCC2_DEBUG_CFLAGS"] != "-g0"
    ):
        fail("top-level GCC recursive make does not propagate deterministic libgcc flags")
    if f"--sysroot={build_sysroot}" not in values["XGCC_FLAGS_FOR_TARGET"]:
        fail("fresh GCC target compiler does not use sealed build sysroot")
    arguments = values["TOPLEVEL_CONFIGURE_ARGUMENTS"]
    required = (
        f"--with-sysroot={target_sysroot}",
        f"--with-build-sysroot={build_sysroot}",
        "--enable-languages=c,c++",
        "--disable-libstdcxx-pch",
        "--disable-libstdcxx-debug",
        "--disable-libstdcxx-debug-flags",
    )
    if any(value not in arguments for value in required):
        fail("top-level GCC configure arguments lack a required contract")


def validate_gcc_headers(
    makefile: Path, target_sysroot: str, build_sysroot: str
) -> None:
    values = evaluate_make(
        makefile,
        (
            "NATIVE_SYSTEM_HEADER_DIR",
            "CROSS_SYSTEM_HEADER_DIR",
            "SYSTEM_HEADER_DIR",
            "BUILD_SYSTEM_HEADER_DIR",
            "TARGET_SYSTEM_ROOT",
            "SYSROOT_CFLAGS_FOR_TARGET",
            "inhibit_libc",
            "STMP_FIXINC",
        ),
        ("sysroot_headers_suffix=",),
    )
    expected = {
        "NATIVE_SYSTEM_HEADER_DIR": "/usr/include",
        "CROSS_SYSTEM_HEADER_DIR": f"{target_sysroot}/usr/include",
        "SYSTEM_HEADER_DIR": f"{build_sysroot}/usr/include",
        "BUILD_SYSTEM_HEADER_DIR": f"{build_sysroot}/usr/include",
        "TARGET_SYSTEM_ROOT": target_sysroot,
        "SYSROOT_CFLAGS_FOR_TARGET": f"--sysroot={build_sysroot}",
        "inhibit_libc": "false",
        "STMP_FIXINC": "",
    }
    if values != expected:
        fail("generated GCC header/sysroot contract is invalid")


def compiler_tokens(value: str, makefile: Path) -> list[str]:
    try:
        tokens = shlex.split(value)
    except ValueError:
        fail("generated target Makefile has an invalid compiler command")
    if not tokens:
        fail("generated target Makefile has an empty compiler command")
    first = Path(tokens[0])
    if not first.is_absolute():
        first = makefile.parent / first
    tokens[0] = os.path.normpath(first)
    return tokens


def validate_target_make(
    kind: str,
    makefile: Path,
    gcc_objdir: str,
    prefix: str,
    target: str,
    build_sysroot: str,
) -> None:
    validate_target_version(target, "17.0.0")
    if kind == "libgcc":
        variables = (
            "enable_shared",
            "enable_gcov",
            "thread_header",
            "MULTIDIRS",
            "MULTISUBDIR",
            "MULTIOSDIR",
            "INHIBIT_LIBC_CFLAGS",
            "LIBGCC2_DEBUG_CFLAGS",
            "CC",
            "slibdir",
            "toolexeclibdir",
        )
    elif kind == "libatomic":
        variables = (
            "enable_shared",
            "MULTISUBDIR",
            "CC",
            "toolexecdir",
            "toolexeclibdir",
            "CFLAGS",
        )
    elif kind == "libstdcxx":
        variables = (
            "MULTISUBDIR",
            "CXX",
            "gxx_include_dir",
            "toolexecdir",
            "toolexeclibdir",
            "CXXFLAGS",
            "glibcxx_build_pch",
        )
    else:
        fail(f"unknown target Makefile contract: {kind}")
    assignments = (
        ("LIBGCC2_DEBUG_CFLAGS=-g0",)
        if kind == "libgcc"
        else ()
    )
    values = evaluate_make(makefile, variables, assignments)
    if values.get("MULTISUBDIR") != "":
        fail(f"{kind} unexpectedly enables a multilib subdirectory")
    compiler_key = "CXX" if kind == "libstdcxx" else "CC"
    tokens = compiler_tokens(values[compiler_key], makefile)
    if tokens[0] not in {
        f"{gcc_objdir}/xgcc",
        f"{gcc_objdir}/g++",
        f"{gcc_objdir}/xg++",
    }:
        fail(f"{kind} is not configured with the fresh cross compiler")
    if f"--sysroot={build_sysroot}" not in tokens:
        fail(f"{kind} compiler does not use the sealed build sysroot")
    if kind == "libgcc":
        if values["enable_shared"] != "yes" or values["enable_gcov"] != "yes":
            fail("final libgcc lacks shared or gcov mode")
        if values["thread_header"] != "gthr-posix.h":
            fail("final libgcc does not use POSIX threads")
        if values["INHIBIT_LIBC_CFLAGS"] or values["LIBGCC2_DEBUG_CFLAGS"] != "-g0":
            fail("final libgcc has unsafe inhibit/debug flags")
        if (
            not os.path.isabs(values["slibdir"])
            or os.path.normpath(values["slibdir"])
                != f"{prefix}/{target}/lib"
        ):
            fail("final libgcc shared library directory is invalid")
        if (
            not os.path.isabs(values["toolexeclibdir"])
            or os.path.normpath(values["toolexeclibdir"])
                != f"{prefix}/{target}/lib64"
        ):
            fail("final libgcc top-level install directory is invalid")
        if values["MULTIOSDIR"] != "../lib64":
            fail("final libgcc multios install mapping is invalid")
    elif kind == "libatomic":
        if values["enable_shared"] != "yes":
            fail("libatomic shared mode is disabled")
        if (
            not os.path.isabs(values["toolexeclibdir"])
            or os.path.normpath(values["toolexeclibdir"])
                != f"{prefix}/{target}/lib64"
        ):
            fail("libatomic install topology is invalid")
        if "-g" in shlex.split(values["CFLAGS"]):
            fail("libatomic target flags retain debug information")
    else:
        if values["gxx_include_dir"] != f"{prefix}/{target}/include/c++/17.0.0":
            fail("libstdc++ include topology is invalid")
        if (
            not os.path.isabs(values["toolexeclibdir"])
            or os.path.normpath(values["toolexeclibdir"])
                != f"{prefix}/{target}/lib64"
        ):
            fail("libstdc++ library topology is invalid")
        if values["glibcxx_build_pch"] not in {"", "no"}:
            fail("libstdc++ unexpectedly enables PCH")
        if "-g" in shlex.split(values["CXXFLAGS"]):
            fail("libstdc++ target flags retain debug information")


def validate_libgcc_debug_evidence(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail("libgcc debug-flag evidence does not exist")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail("libgcc debug-flag evidence is not a plain single-linked file")
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        fail("libgcc debug-flag evidence is empty")
    for line in lines:
        try:
            tokens = shlex.split(line)
        except ValueError:
            fail("libgcc debug-flag evidence has invalid shell syntax")
        positions = [index for index, token in enumerate(tokens) if token == "-DIN_LIBGCC2"]
        if not positions:
            fail("libgcc debug-flag evidence contains an unrelated line")
        for position in positions:
            if position == 0 or tokens[position - 1] != "-g0":
                fail("libgcc compile flags do not end in -g0 -DIN_LIBGCC2")
            if "-g" in tokens[:position]:
                fail("libgcc compile flags contain a late debug-enabling -g")


def command_output(arguments: list[object], *, stdin: str | None = None) -> str:
    result = subprocess.run(
        [str(value) for value in arguments],
        input=stdin,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"},
    )
    if result.returncode:
        fail(result.stderr.strip() or f"command failed: {arguments[0]}")
    return result.stdout


def driver_policy(
    prefix: Path, target: str, version: str, sysroot: Path, binutils: Path
) -> dict[str, str]:
    validate_target_version(target, version)
    gcc = prefix / "bin" / f"{target}-gcc"
    gxx = prefix / "bin" / f"{target}-g++"
    cxx = prefix / "bin" / f"{target}-c++"
    for driver in (gcc, gxx, cxx):
        if not driver.is_file() or not os.access(driver, os.X_OK):
            fail(f"complete-GCC driver is not executable: {driver}")
    if sha256(gxx) != sha256(cxx):
        fail("complete-GCC c++ alias differs from the normalized g++ driver")

    def one_line(driver: Path, option: str) -> str:
        output = command_output([driver, option]).splitlines()
        if len(output) != 1:
            fail(f"complete-GCC driver returned malformed {option} output")
        return output[0]

    def verbose_value(driver: Path, label: str) -> str:
        result = subprocess.run(
            [driver, "-v"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"},
        )
        if result.returncode:
            fail("complete-GCC driver -v failed")
        match = re.search(rf"^{re.escape(label)}:\s*(\S+)\s*$", result.stderr, re.M)
        if not match:
            fail(f"complete-GCC driver lacks {label}")
        return match.group(1)

    target_help = command_output(
        [
            gcc,
            "-Q",
            "--help=target",
            "-c",
            "-x",
            "c",
            "/dev/null",
            "-o",
            "/dev/null",
        ]
    )
    defaults = {}
    for option in ("march", "mtune"):
        match = re.search(rf"^\s*-{option}=\s+(\S+)\s*$", target_help, re.M)
        if not match:
            fail(f"complete GCC does not report its default -{option}")
        defaults[option] = match.group(1)
    values = {
        "gcc-dumpmachine": one_line(gcc, "-dumpmachine"),
        "gxx-dumpmachine": one_line(gxx, "-dumpmachine"),
        "cxx-dumpmachine": one_line(cxx, "-dumpmachine"),
        "gcc-sysroot": one_line(gcc, "-print-sysroot"),
        "gxx-sysroot": one_line(gxx, "-print-sysroot"),
        "gcc-multilib": one_line(gcc, "-print-multi-lib"),
        "gxx-multilib": one_line(gxx, "-print-multi-lib"),
        "gcc-fullversion": one_line(gcc, "-dumpfullversion"),
        "gxx-fullversion": one_line(gxx, "-dumpfullversion"),
        "cxx-fullversion": one_line(cxx, "-dumpfullversion"),
        "gcc-thread-model": verbose_value(gcc, "Thread model"),
        "gxx-thread-model": verbose_value(gxx, "Thread model"),
        "gcc-default-march": defaults["march"],
        "gcc-default-mtune": defaults["mtune"],
        "cc1": one_line(gcc, "-print-prog-name=cc1"),
        "cc1plus": one_line(gxx, "-print-prog-name=cc1plus"),
        "as": one_line(gcc, "-print-prog-name=as"),
        "ld": one_line(gcc, "-print-prog-name=ld"),
    }
    expected = {
        "gcc-dumpmachine": target,
        "gxx-dumpmachine": target,
        "cxx-dumpmachine": target,
        "gcc-sysroot": str(sysroot),
        "gxx-sysroot": str(sysroot),
        "gcc-multilib": ".;",
        "gxx-multilib": ".;",
        "gcc-fullversion": version,
        "gxx-fullversion": version,
        "cxx-fullversion": version,
        "gcc-thread-model": "posix",
        "gxx-thread-model": "posix",
        "gcc-default-march": "x86-64-v2",
        "gcc-default-mtune": "generic",
    }
    for key, wanted in expected.items():
        if values[key] != wanted:
            fail(f"complete-GCC driver policy mismatch for {key}")
    for key in ("cc1", "cc1plus"):
        path = Path(values[key])
        try:
            path.resolve(strict=True).relative_to(prefix.resolve(strict=True))
        except (FileNotFoundError, RuntimeError, ValueError):
            fail(f"complete-GCC driver {key} escapes its final prefix")
    for key in ("as", "ld"):
        expected_path = binutils / "bin" / f"{target}-{key}"
        try:
            if Path(values[key]).resolve(strict=True) != expected_path.resolve(
                strict=True
            ):
                fail(f"complete-GCC driver resolved unexpected {key}")
        except (FileNotFoundError, OSError, RuntimeError):
            fail(f"complete-GCC driver reported invalid {key}")
    return values


def validate_driver_policy(
    prefix: Path,
    evidence: Path,
    target: str,
    version: str,
    sysroot: Path,
    binutils: Path,
) -> None:
    values = {}
    for line in evidence.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or key in values:
            fail("driver-policy evidence is malformed")
        values[key] = value
    if values != driver_policy(prefix, target, version, sysroot, binutils):
        fail("driver-policy evidence does not match live complete GCC")


def cxx_header_search(
    prefix: Path, snapshot: Path, target: str, version: str
) -> str:
    gxx = prefix / "bin" / f"{target}-g++"
    result = subprocess.run(
        [gxx, f"--sysroot={snapshot}", "-std=c++23", "-E", "-x", "c++", "-v", "-"],
        input="",
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"},
    )
    if result.returncode:
        fail(result.stderr.strip() or "complete G++ header-search probe failed")
    match = re.search(
        r"(?ms)^#include <\.\.\.> search starts here:\n"
        r".*?^End of search list\.\n?",
        result.stderr,
    )
    if not match:
        fail("complete G++ did not report a C++ header search list")
    return match.group(0).rstrip("\n") + "\n"


def validate_cxx_header_search(
    evidence: Path,
    prefix: Path,
    snapshot: Path,
    base: Path,
    target: str,
    version: str,
) -> None:
    live = cxx_header_search(prefix, snapshot, target, version)
    if evidence.read_text(encoding="utf-8") != live:
        fail("persisted C++ header search does not match the live driver")
    lines = live.splitlines()
    entries = [line.strip() for line in lines[1:-1] if line.strip()]
    normalized = {os.path.normpath(value) for value in entries}
    expected = {
        str(prefix / f"{target}/include/c++/{version}"),
        str(prefix / f"{target}/include/c++/{version}/{target}"),
        str(prefix / f"{target}/include/c++/{version}/backward"),
        str(prefix / f"lib/gcc/{target}/{version}/include"),
        str(prefix / f"lib/gcc/{target}/{version}/include-fixed"),
        str(prefix / f"{target}/include"),
        str(snapshot / "usr/include"),
    }
    if normalized != expected or len(entries) != len(expected):
        fail("complete G++ has an unexpected C++ header search topology")
    allowed = (prefix.resolve(strict=True), snapshot.resolve(strict=True))
    base_real = base.resolve(strict=True)
    for value in entries:
        path = Path(value)
        if not path.is_absolute():
            fail("C++ header search contains a relative directory")
        try:
            resolved = path.resolve(strict=True)
        except (FileNotFoundError, OSError, RuntimeError):
            fail(f"C++ header search contains an absent directory: {value}")
        if any(resolved == root or root in resolved.parents for root in (base_real,)):
            fail("C++ header search falls back to bootstrap GCC")
        if not any(resolved == root or root in resolved.parents for root in allowed):
            fail(f"C++ header search escapes sealed roots: {value}")


def validate_loader_list(
    path: Path, prefix: Path, snapshot: Path, kind: str
) -> None:
    text = path.read_text(encoding="utf-8")
    if "/work/" in text or "/.tmp-" in text or "/usr/lib/x86_64-linux-gnu" in text:
        fail("loader-list evidence contains a disposable or host path")
    origins = {}
    for line in text.splitlines():
        match = re.match(r"^\s*(\S+)\s+=>\s+(/\S+)\s+\(", line)
        if match:
            name = match.group(1)
            if name in origins:
                fail(f"loader-list evidence duplicates {name}")
            origins[name] = Path(match.group(2))
    if kind == "cxx":
        required = {
            "libstdc++.so.6": prefix,
            "libgcc_s.so.1": prefix,
            "libc.so.6": snapshot,
            "libm.so.6": snapshot,
        }
    elif kind == "atomic":
        required = {"libatomic.so.1": prefix, "libc.so.6": snapshot}
    else:
        fail("unknown loader-list evidence kind")
    for name, root in required.items():
        path_value = origins.get(name)
        if path_value is None:
            fail(f"loader-list evidence lacks {name}")
        try:
            path_value.resolve(strict=True).relative_to(root.resolve(strict=True))
        except (FileNotFoundError, OSError, RuntimeError, ValueError):
            fail(f"loader-list {name} escapes its sealed origin")
    allowed = (prefix.resolve(strict=True), snapshot.resolve(strict=True))
    for name, path_value in origins.items():
        try:
            resolved = path_value.resolve(strict=True)
        except (FileNotFoundError, OSError, RuntimeError):
            fail(f"loader-list {name} has an invalid origin")
        if not any(
            resolved == root or root in resolved.parents for root in allowed
        ):
            fail(f"loader-list {name} resolves outside all sealed roots")
    loader_paths = re.findall(r"(/\S*ld-linux-x86-64\.so\.2)", text)
    if not loader_paths:
        fail("loader-list evidence lacks the sealed dynamic loader")
    if not any(
        snapshot.resolve(strict=True)
        in Path(value).resolve(strict=True).parents
        for value in loader_paths
        if Path(value).exists()
    ):
        fail("loader-list dynamic loader does not originate in the snapshot")


def live_loader_list(
    probe: Path, prefix: Path, snapshot: Path, name: str
) -> str:
    loader = snapshot / "lib64/ld-linux-x86-64.so.2"
    library_path = f"{prefix}/{TARGET}/lib64:{snapshot}/usr/lib"
    output = command_output(
        [
            loader,
            "--inhibit-cache",
            "--library-path",
            library_path,
            "--list",
            probe / name,
        ]
    )
    return re.sub(r"\(0x[0-9a-fA-F]+\)", "(<ADDR>)", output)


def write_loader_evidence(
    probe: Path, prefix: Path, snapshot: Path
) -> None:
    for name in ("cxx-dynamic", "atomic-dynamic"):
        write_text(
            probe / f"{name}.loader.list",
            live_loader_list(probe, prefix, snapshot, name),
        )


def validate_loader_evidence(
    probe: Path, prefix: Path, snapshot: Path
) -> None:
    for name, kind in (("cxx-dynamic", "cxx"), ("atomic-dynamic", "atomic")):
        path = probe / f"{name}.loader.list"
        if path.read_text(encoding="utf-8") != live_loader_list(
            probe, prefix, snapshot, name
        ):
            fail(f"{name} loader-list evidence differs from live resolution")
        validate_loader_list(path, prefix, snapshot, kind)


def archive_evidence(
    prefix: Path, binutils: Path, target: str, version: str
) -> dict[str, dict[str, str]]:
    ar = binutils / "bin" / f"{target}-ar"
    nm = binutils / "bin" / f"{target}-nm"
    archives = {
        "libgcc": prefix / f"lib/gcc/{target}/{version}/libgcc.a",
        "libgcc_eh": prefix / f"lib/gcc/{target}/{version}/libgcc_eh.a",
        "libatomic": prefix / f"{target}/lib64/libatomic.a",
        "libstdcxx": prefix / f"{target}/lib64/libstdc++.a",
        "libsupcxx": prefix / f"{target}/lib64/libsupc++.a",
    }
    required = {
        "libgcc": {"__udivti3"},
        "libgcc_eh": {"_Unwind_RaiseException"},
        "libatomic": {"__atomic_load_16", "__atomic_compare_exchange_16"},
        "libstdcxx": {"_ZSt4cout", "__cxa_throw"},
        "libsupcxx": {"__cxa_begin_catch", "__cxa_throw"},
    }
    result = {}
    for label, archive in archives.items():
        members = command_output([ar, "t", archive])
        if not members.splitlines() or any("/" in value for value in members.splitlines()):
            fail(f"{label} archive has invalid or empty member evidence")
        symbols = command_output([nm, "-A", "--defined-only", archive])
        matched = []
        seen = set()
        for line in symbols.splitlines():
            parts = line.rsplit(None, 1)
            if len(parts) == 2 and parts[1] in required[label]:
                matched.append(line)
                seen.add(parts[1])
        if seen != required[label]:
            fail(f"{label} archive lacks required complete-GCC symbols")
        result[label] = {
            "members": members,
            "symbols": "\n".join(matched) + "\n",
        }
    return result


def write_archive_evidence(
    prefix: Path, probe: Path, binutils: Path, target: str, version: str
) -> None:
    for label, values in archive_evidence(
        prefix, binutils, target, version
    ).items():
        for suffix, text_value in values.items():
            output = probe / f"{label}.{suffix if suffix == 'members' else 'required-symbols.nm'}"
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{output.name}.", dir=probe, text=True
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(text_value)
            os.replace(temporary_name, output)
            output.chmod(0o644)


def validate_archive_evidence(
    prefix: Path, probe: Path, binutils: Path, target: str, version: str
) -> None:
    for label, values in archive_evidence(
        prefix, binutils, target, version
    ).items():
        if (probe / f"{label}.members").read_text(encoding="utf-8") != values["members"]:
            fail(f"{label} archive member evidence differs from the live archive")
        if (probe / f"{label}.required-symbols.nm").read_text(
            encoding="utf-8"
        ) != values["symbols"]:
            fail(f"{label} symbol evidence differs from the live archive")


def normalize_configuration(
    root: Path, replacements: dict[str, tuple[str, ...]]
) -> None:
    for label in ("a", "b"):
        values = replacements[label]
        substitutions = (
            (values[0], "<BUILD>"),
            (values[1], "<CANDIDATE>"),
            (values[2], "<OVERLAY>"),
            (values[3], "<TEMPORARY_ROOT>"),
        )
        for path in sorted(root.glob(f"build-{label}.*.log")):
            text_value = path.read_text(encoding="utf-8")
            for original, normalized_value in substitutions:
                text_value = text_value.replace(original, normalized_value)
            text_value = re.sub(
                r"/tmp/cc[A-Za-z0-9]+\.o\b",
                "<CONFTST_OBJECT>",
                text_value,
            )
            path.write_text(text_value, encoding="utf-8")
            path.chmod(0o644)
    debug = root / "libgcc-debug-flags.txt"
    if debug.exists():
        text_value = debug.read_text(encoding="utf-8")
        for values in replacements.values():
            for original, normalized_value in (
                (values[0], "<BUILD>"),
                (values[1], "<CANDIDATE>"),
                (values[2], "<OVERLAY>"),
                (values[3], "<TEMPORARY_ROOT>"),
            ):
                text_value = text_value.replace(original, normalized_value)
        debug.write_text(text_value, encoding="utf-8")
        debug.chmod(0o644)
    validate_configuration(root)


def validate_configuration(root: Path) -> None:
    suffixes = (
        "config.log",
        "gcc.config.log",
        "libgcc.config.log",
        "libatomic.config.log",
        "libstdcxx.config.log",
    )
    for suffix in suffixes:
        left = (root / f"build-a.{suffix}").read_text(encoding="utf-8")
        right = (root / f"build-b.{suffix}").read_text(encoding="utf-8")
        if left != right:
            fail(f"independent normalized configuration differs: {suffix}")
        if (
            "/work/" in left
            or "/.tmp-" in left
            or re.search(r"/tmp/cc[A-Za-z0-9]+\.o\b", left)
        ):
            fail(f"normalized configuration retains a disposable path: {suffix}")
    debug = root / "libgcc-debug-flags.txt"
    if debug.exists():
        contents = debug.read_text(encoding="utf-8")
        if "/work/" in contents or "/.tmp-" in contents:
            fail("normalized libgcc compile evidence retains a disposable path")
        validate_libgcc_debug_evidence(debug)


def validate_probe_elf_semantics(probe: Path, prefix: Path, target: str) -> None:
    def readelf(*arguments: object) -> str:
        return command_output(["/usr/bin/readelf", *arguments])

    cxx_needed = set(re.findall(
        r"\(NEEDED\).*Shared library: \[([^\]]+)\]",
        readelf("-dW", probe / "cxx-dynamic"),
    ))
    if not {"libstdc++.so.6", "libgcc_s.so.1", "libc.so.6"}.issubset(cxx_needed):
        fail("live dynamic C++ probe lacks a required runtime")
    if "libatomic.so.1" in cxx_needed:
        fail("live ordinary C++ probe unexpectedly needs libatomic")
    atomic_needed = set(re.findall(
        r"\(NEEDED\).*Shared library: \[([^\]]+)\]",
        readelf("-dW", probe / "atomic-dynamic"),
    ))
    if not {"libatomic.so.1", "libc.so.6"}.issubset(atomic_needed):
        fail("live atomic probe lacks implicit libatomic linkage")
    static_dynamic = readelf("-dW", probe / "cxx-static")
    static_program = readelf("-lW", probe / "cxx-static")
    if "(NEEDED)" in static_dynamic or "INTERP" in static_program:
        fail("live static C++ probe requires a shared runtime or loader")
    undefined = command_output(
        ["/usr/bin/nm", "-u", probe / "cxx-static"]
    )
    if undefined.strip():
        fail("live static C++ probe retains undefined symbols")
    runtime = prefix / target / "lib64"
    versions = {
        "libstdc++.so.6": ("GLIBCXX_3.4.37", "CXXABI_1.3.17"),
        "libatomic.so.1": ("LIBATOMIC_1.2",),
        "libgcc_s.so.1": ("GCC_",),
    }
    for name, required in versions.items():
        output = readelf("--version-info", runtime / name)
        if any(value not in output for value in required):
            fail(f"live {name} lacks required symbol versions")


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
        f"gcc-complete-{commit[:12]}-"
        f"{canonical_digest(require_pairs(arguments[1:]))[:16]}"
    )
elif command == "derived-delta":
    if len(arguments) != 5:
        fail("derived-delta requires BASE RESULT TOOLS TARGET VERSION")
    base = dependency_inventory(Path(arguments[0]), Path(arguments[2]))
    result = dependency_inventory(Path(arguments[1]), Path(arguments[2]))
    print(
        json.dumps(
            derive_delta(base, result, arguments[3], arguments[4]),
            indent=2,
            sort_keys=True,
        )
    )
elif command == "write-delta":
    if len(arguments) != 6:
        fail("write-delta requires BASE RESULT TOOLS TARGET VERSION OUTPUT")
    base = dependency_inventory(Path(arguments[0]), Path(arguments[2]))
    result = dependency_inventory(Path(arguments[1]), Path(arguments[2]))
    write_json(
        Path(arguments[5]),
        derive_delta(base, result, arguments[3], arguments[4]),
    )
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
        fail("derived complete-GCC prefix shares regular-file inodes with its base")
elif command == "normalize-hardlinks":
    if len(arguments) != 1:
        fail("normalize-hardlinks requires ROOT")
    print(normalize_hardlinks(Path(arguments[0])))
elif command == "no-hardlinks":
    if len(arguments) != 1:
        fail("no-hardlinks requires ROOT")
    remaining = regular_hardlinks(Path(arguments[0]))
    if remaining:
        fail(f"regular hardlinks violate sealed inventory: {remaining}")
elif command == "normalize-modes":
    if len(arguments) != 1:
        fail("normalize-modes requires ROOT")
    print(json.dumps(normalize_modes(Path(arguments[0])), sort_keys=True))
elif command == "mode-contract":
    if len(arguments) != 1:
        fail("mode-contract requires ROOT")
    validate_modes(Path(arguments[0]))
elif command == "compare-json":
    if len(arguments) != 2:
        fail("compare-json requires LEFT RIGHT")
    with Path(arguments[0]).open(encoding="utf-8") as stream:
        left = json.load(stream)
    with Path(arguments[1]).open(encoding="utf-8") as stream:
        right = json.load(stream)
    if left != right:
        fail("JSON attestations differ")
elif command == "top-level-make-contract":
    if len(arguments) != 3:
        fail("top-level-make-contract requires MAKEFILE TARGET_SYSROOT BUILD_SYSROOT")
    validate_top_level_make(Path(arguments[0]), arguments[1], arguments[2])
elif command == "gcc-header-contract":
    if len(arguments) != 3:
        fail("gcc-header-contract requires MAKEFILE TARGET_SYSROOT BUILD_SYSROOT")
    validate_gcc_headers(Path(arguments[0]), arguments[1], arguments[2])
elif command in {"libgcc-make-contract", "libatomic-make-contract", "libstdcxx-make-contract"}:
    if len(arguments) != 5:
        fail(f"{command} requires MAKEFILE GCC_OBJDIR PREFIX TARGET BUILD_SYSROOT")
    kind = {
        "libgcc-make-contract": "libgcc",
        "libatomic-make-contract": "libatomic",
        "libstdcxx-make-contract": "libstdcxx",
    }[command]
    validate_target_make(
        kind,
        Path(arguments[0]),
        arguments[1],
        arguments[2],
        arguments[3],
        arguments[4],
    )
elif command == "libgcc-debug-flags-contract":
    if len(arguments) != 1:
        fail("libgcc-debug-flags-contract requires EVIDENCE")
    validate_libgcc_debug_evidence(Path(arguments[0]))
elif command == "write-driver-evidence":
    if len(arguments) != 6:
        fail("write-driver-evidence requires PREFIX EVIDENCE TARGET VERSION SYSROOT BINUTILS")
    values = driver_policy(
        Path(arguments[0]), arguments[2], arguments[3],
        Path(arguments[4]), Path(arguments[5])
    )
    write_text(
        Path(arguments[1]),
        "".join(f"{key}={value}\n" for key, value in values.items()),
    )
elif command == "driver-policy-contract":
    if len(arguments) != 6:
        fail("driver-policy-contract requires PREFIX EVIDENCE TARGET VERSION SYSROOT BINUTILS")
    validate_driver_policy(
        Path(arguments[0]), Path(arguments[1]), arguments[2], arguments[3],
        Path(arguments[4]), Path(arguments[5])
    )
elif command == "write-cxx-header-search":
    if len(arguments) != 5:
        fail("write-cxx-header-search requires EVIDENCE PREFIX SNAPSHOT TARGET VERSION")
    write_text(
        Path(arguments[0]),
        cxx_header_search(
            Path(arguments[1]), Path(arguments[2]), arguments[3], arguments[4]
        ),
    )
elif command == "cxx-header-search-contract":
    if len(arguments) != 6:
        fail("cxx-header-search-contract requires EVIDENCE PREFIX SNAPSHOT BASE TARGET VERSION")
    validate_cxx_header_search(
        Path(arguments[0]), Path(arguments[1]), Path(arguments[2]),
        Path(arguments[3]), arguments[4], arguments[5]
    )
elif command == "write-loader-evidence":
    if len(arguments) != 3:
        fail("write-loader-evidence requires PROBE PREFIX SNAPSHOT")
    write_loader_evidence(*(Path(value) for value in arguments))
elif command == "loader-evidence-contract":
    if len(arguments) != 3:
        fail("loader-evidence-contract requires PROBE PREFIX SNAPSHOT")
    validate_loader_evidence(*(Path(value) for value in arguments))
elif command == "write-archive-evidence":
    if len(arguments) != 5:
        fail("write-archive-evidence requires PREFIX PROBE BINUTILS TARGET VERSION")
    write_archive_evidence(
        Path(arguments[0]), Path(arguments[1]), Path(arguments[2]),
        arguments[3], arguments[4]
    )
elif command == "archive-evidence-contract":
    if len(arguments) != 5:
        fail("archive-evidence-contract requires PREFIX PROBE BINUTILS TARGET VERSION")
    validate_archive_evidence(
        Path(arguments[0]), Path(arguments[1]), Path(arguments[2]),
        arguments[3], arguments[4]
    )
elif command == "normalize-configuration":
    if len(arguments) != 8:
        fail(
            "normalize-configuration requires ROOT BUILD_A BUILD_B CANDIDATE_A "
            "CANDIDATE_B OVERLAY_A OVERLAY_B TEMPORARY_ROOT"
        )
    normalize_configuration(
        Path(arguments[0]),
        {
            "a": (arguments[1], arguments[3], arguments[5], arguments[7]),
            "b": (arguments[2], arguments[4], arguments[6], arguments[7]),
        },
    )
elif command == "configuration-contract":
    if len(arguments) != 1:
        fail("configuration-contract requires ROOT")
    validate_configuration(Path(arguments[0]))
elif command == "probe-elf-contract":
    if len(arguments) != 3:
        fail("probe-elf-contract requires PROBE PREFIX TARGET")
    validate_probe_elf_semantics(
        Path(arguments[0]), Path(arguments[1]), arguments[2]
    )
elif command == "runtime-lookups-contract":
    if len(arguments) != 4:
        fail("runtime-lookups-contract requires PREFIX LOOKUPS TARGET VERSION")
    validate_runtime_lookups(
        Path(arguments[0]), Path(arguments[1]), arguments[2], arguments[3]
    )
elif command == "runtime-elf-scan":
    if len(arguments) != 3:
        fail("runtime-elf-scan requires PREFIX TARGET VERSION")
    print(
        json.dumps(
            scan_runtime_elf(Path(arguments[0]), arguments[1], arguments[2]),
            indent=2,
            sort_keys=True,
        )
    )
elif command == "link-map-contract":
    if len(arguments) != 3:
        fail("link-map-contract requires MAP PREFIX SNAPSHOT")
    validate_link_map(*(Path(value) for value in arguments))
elif command == "probe-path-contract":
    if len(arguments) != 3:
        fail("probe-path-contract requires PROBE PREFIX SNAPSHOT")
    validate_probe_paths(*(Path(value) for value in arguments))
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
elif command == "selector-rollback":
    if len(arguments) != 4:
        fail("selector-rollback requires TOOLS ARTIFACTS BASE BUILD")
    tools_root, artifacts_root = map(Path, arguments[:2])
    base_build_id, build_id = arguments[2:]
    current, selected = safe_current(tools_root)
    if selected == base_build_id:
        print("base")
    elif selected != build_id:
        fail("refusing to roll back a tools selector that no longer names this build")
    else:
        base = tools_root / base_build_id
        if not base.is_dir() or base.is_symlink():
            fail("tools selector rollback base is not a real directory")
        temporary = tools_root / f".current-rollback-{os.getpid()}"
        try:
            os.symlink(base_build_id, temporary)
            os.replace(temporary, current)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        _, selected_after = safe_current(tools_root)
        if selected_after != base_build_id:
            fail("tools selector rollback did not restore the exact base")
        print("rolled-back")
elif command == "validate-completed":
    if len(arguments) < 8 or len(arguments[6:]) % 2:
        fail(
            "validate-completed requires RECEIPT PREFIX BASE TOOLS TARGET VERSION "
            "and key/value pairs"
        )
    receipt_path = Path(arguments[0])
    prefix = Path(arguments[1])
    base = Path(arguments[2])
    tools_root = Path(arguments[3])
    target, version = arguments[4:6]
    expected = require_pairs(arguments[6:])
    metadata = receipt_path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o644
    ):
        fail("completed receipt is not a plain mode-0644 single-linked file")
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
        fail("completed complete-GCC delta attestation is invalid")
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
    artifact = receipt_path.parent
    if receipt.get("outputs", {}).get("probe_sha256") != regular_hashes(
        artifact / "probe"
    ):
        fail("completed probe hash attestation is invalid")
    if receipt.get("outputs", {}).get("configuration_sha256") != regular_hashes(
        artifact / "configuration"
    ):
        fail("completed configuration hash attestation is invalid")
    configuration = artifact / "configuration"
    normalization = {
        "mode_policy": (
            "directories-0755-executable-regulars-0755-"
            "other-regulars-0644-symlinks-unchanged-v1"
        ),
        "hardlink_policy": "atomic-same-directory-single-link-v1",
        "build_a_modes": json.loads(
            (configuration / "build-a.normalized-modes.json").read_text(
                encoding="utf-8"
            )
        ),
        "build_b_modes": json.loads(
            (configuration / "build-b.normalized-modes.json").read_text(
                encoding="utf-8"
            )
        ),
        "build_a_hardlinks_broken": int(
            (configuration / "build-a.normalized-hardlinks.txt").read_text(
                encoding="utf-8"
            )
        ),
        "build_b_hardlinks_broken": int(
            (configuration / "build-b.normalized-hardlinks.txt").read_text(
                encoding="utf-8"
            )
        ),
    }
    if receipt.get("normalization") != normalization:
        fail("completed mode/hardlink normalization attestation is invalid")
    validate_modes(prefix)
    if regular_hardlinks(prefix):
        fail("completed prefix contains regular-file hardlinks")
    validate_libgcc_debug_evidence(
        configuration / "libgcc-debug-flags.txt"
    )
    validate_configuration(configuration)
    if receipt.get("license_inventory") != inventory(artifact / "licenses/gcc"):
        fail("completed GCC license inventory is invalid")
    configure_args = (artifact / "configure.args").read_text(
        encoding="utf-8"
    ).splitlines()
    if not configure_args or receipt.get("configure_args") != configure_args:
        fail("completed configure argument attestation is invalid")
    material = b"".join(value.encode("utf-8") + b"\0" for value in configure_args)
    if receipt.get("configure_digest") != hashlib.sha256(material).hexdigest():
        fail("completed configure digest is invalid")
    snapshot = Path(str(receipt.get("sysroot_snapshot", "")))
    snapshot_inventory = inventory(snapshot)
    if (
        receipt.get("sysroot_snapshot_digest")
        != f"sha256:{snapshot_inventory['digest']}"
        or receipt.get("outputs", {}).get("sysroot_inventory_digest")
        != f"sha256:{snapshot_inventory['digest']}"
    ):
        fail("completed sealed sysroot attestation is invalid")
    probe = artifact / "probe"
    binutils = Path(str(dotted(receipt, "dependencies.binutils.prefix")))
    validate_driver_policy(
        prefix,
        probe / "driver-identities.txt",
        target,
        version,
        Path(str(receipt.get("sysroot", ""))),
        binutils,
    )
    validate_cxx_header_search(
        probe / "cxx-header-search.search",
        prefix,
        snapshot,
        base,
        target,
        version,
    )
    validate_runtime_lookups(
        prefix, probe / "runtime-lookups.txt", target, version
    )
    for map_name in ("cxx-dynamic.map", "atomic-dynamic.map", "cxx-static.map"):
        validate_link_map(probe / map_name, prefix, snapshot)
    scan = scan_runtime_elf(prefix, target, version)
    with (probe / "runtime-elf-scan.json").open(encoding="utf-8") as stream:
        if json.load(stream) != scan:
            fail("completed runtime ELF scan does not match live prefix")
    if receipt.get("outputs", {}).get("runtime_elf_count") != len(
        scan["elf_files"]
    ):
        fail("completed runtime ELF count is invalid")
    validate_runtime_topology(result_inventory["entries"], target, version)
    runtime_hashes = {
        path: metadata["sha256"]
        for path, metadata in result_inventory["entries"].items()
        if path in runtime_paths(target, version)
        and metadata.get("type") == "file"
    }
    if receipt.get("runtime_sha256") != runtime_hashes:
        fail("completed runtime hash attestation is invalid")
    validate_loader_evidence(probe, prefix, snapshot)
    validate_archive_evidence(prefix, probe, binutils, target, version)
    validate_probe_elf_semantics(probe, prefix, target)
    validate_probe_paths(probe, prefix, snapshot)
    loader = snapshot / "lib64/ld-linux-x86-64.so.2"
    library_path = f"{prefix}/{target}/lib64:{snapshot}/usr/lib"
    executions = {
        "cxx-dynamic": "cxx=ok exception=ok thread=ok\n",
        "atomic-dynamic": "atomic=ok\n",
    }
    clean_env = {"LC_ALL": "C", "TZ": "UTC"}
    for name, output in executions.items():
        result = subprocess.run(
            [
                loader,
                "--inhibit-cache",
                "--library-path",
                library_path,
                probe / name,
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=clean_env,
        )
        if result.returncode or result.stdout != output or result.stderr:
            fail(f"completed {name} probe no longer runs with sealed runtimes")
    static_result = subprocess.run(
        [probe / "cxx-static"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=clean_env,
    )
    if (
        static_result.returncode
        or static_result.stdout != "cxx-static=ok exception=ok atomic=ok\n"
        or static_result.stderr
    ):
        fail("completed static C++ probe no longer runs")
else:
    fail(f"unknown internal command: {command}")
PY
fi

for variable in \
  CC CXX CPP CFLAGS CXXFLAGS CPPFLAGS LDFLAGS \
  CFLAGS_FOR_TARGET CXXFLAGS_FOR_TARGET LDFLAGS_FOR_TARGET \
  LIBRARY_PATH CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH \
  PKG_CONFIG_PATH CONFIG_SITE LD_LIBRARY_PATH GCC_EXEC_PREFIX COMPILER_PATH; do
  unset "$variable"
done

cajunos_root=${CAJUNOS_ROOT:-/srv/cajunos}
target=${CAJUNOS_TARGET:-x86_64-cajunos-linux-gnu}
expected_user=${CAJUNOS_BUILD_USER:-cajunos}
requested_glibc_build_id=${CAJUNOS_GLIBC_COMPLETE_BUILD_ID:-}
requested_libgcc_build_id=${CAJUNOS_LIBGCC_BUILD_ID:-}
host_cflags='-O2 -g0'
target_cflags='-O2 -g0 -march=x86-64-v2 -mtune=generic'
target_cxxflags=$target_cflags
# GCC's target libraries have an intentional bootstrap cycle through libatomic.
# These flags are build-only cycle breakers; they are never advertised as the
# public target ABI/optimization policy.
cycle_cflags="$target_cflags -fno-link-libatomic"
cycle_cxxflags="$target_cxxflags -fno-link-libatomic"
cycle_ldflags='-fno-link-libatomic'
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
for command in \
  ar awk cmp flock g++ gcc git grep install make nm python3 readelf \
  readlink rsync sed sha256sum strings tar tee; do
  command -v "$command" >/dev/null || {
    echo "Missing required host command: $command" >&2
    exit 72
  }
done
for helper in "$inventory_helper" "$libgcc_helper" "$glibc_helper"; do
  [[ -x $helper ]] || {
    echo "Frozen complete-GCC dependency helper is unavailable: $helper" >&2
    exit 73
  }
done

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
gcc_version=$(sed -n '1p' "$gcc_source_dir/gcc/BASE-VER")
if [[ ! $gcc_version =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
  echo "Locked GCC source reports an unsafe version: $gcc_version" >&2
  exit 78
fi

work_root=$cajunos_root/work/toolchain
tools_root=$cajunos_root/tools
artifacts_root=$cajunos_root/artifacts
logs_root=$cajunos_root/logs
cohort_id=${source_set_digest#sha256:}
cohort_id=${cohort_id:0:16}
sysroot=$cajunos_root/sysroot/$cohort_id

"$script_path" --internal-python ensure-directories "$cajunos_root" \
  work work/toolchain tools artifacts logs sysroot "sysroot/$cohort_id"

# Resolve one authoritative pair: the selected complete-glibc snapshot and the
# exact bootstrap-libgcc prefix recorded by that snapshot. Both dependency
# validators are replayed in full. The resolver is repeated immediately before
# publication to close source, receipt, selector, and filesystem TOCTOU windows.
resolve_dependencies() {
python3 - \
  "$inventory_helper" "$libgcc_helper" "$glibc_helper" \
  "$tools_root" "$artifacts_root" "$sysroot" \
  "$source_set_digest" "$source_authentication" "$target" "$gcc_version" \
  "$locked_gcc_commit" "$locked_gcc_tree" "$gcc_repository" \
  "$locked_binutils_commit" "$locked_binutils_tree" "$binutils_repository" \
  "$locked_glibc_commit" "$locked_glibc_tree" "$glibc_repository" \
  "$locked_linux_commit" "$locked_linux_tree" "$linux_repository" \
  "$requested_glibc_build_id" "$requested_libgcc_build_id" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

(
    inventory_helper, libgcc_helper, glibc_helper, tools_value,
    artifacts_value, sysroot_value, source_set_digest, source_authentication,
    target, gcc_version, gcc_commit, gcc_tree, gcc_repository,
    binutils_commit, binutils_tree, binutils_repository, glibc_commit,
    glibc_tree, glibc_repository, linux_commit, linux_tree, linux_repository,
    requested_glibc, requested_libgcc,
) = sys.argv[1:]
tools = Path(tools_value)
artifacts = Path(artifacts_value)
sysroot = Path(sysroot_value)
safe_id = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


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
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or path.is_symlink()
    ):
        fail(f"{label} is not a plain single-linked file")
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        fail(f"{label} does not contain an object")
    return value


def run_helper(helper, *arguments):
    result = subprocess.run(
        [helper, "--internal-python", *map(str, arguments)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"},
    )
    if result.returncode:
        fail(result.stderr.strip() or f"dependency helper failed: {helper}")


def helper_json(helper, *arguments):
    result = subprocess.run(
        [helper, "--internal-python", *map(str, arguments)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"},
    )
    if result.returncode:
        fail(result.stderr.strip() or f"dependency helper failed: {helper}")
    return json.loads(result.stdout)


def receipt_dependency(receipt, name):
    value = receipt.get("dependencies", {}).get(name)
    if not isinstance(value, dict):
        fail(f"complete glibc receipt lacks {name} dependency")
    return value


current = sysroot / "current"
if not current.is_symlink():
    fail("cohort sysroot lacks its managed current selector")
selected = os.readlink(current)
match = re.fullmatch(r"snapshots/([A-Za-z0-9][A-Za-z0-9._-]{0,127})", selected)
if not match:
    fail("cohort sysroot current selector is unsafe")
glibc_id = match.group(1)
if requested_glibc and requested_glibc != glibc_id:
    fail("requested complete-glibc build is not the active cohort snapshot")
snapshot = sysroot / "snapshots" / glibc_id
if not snapshot.is_dir() or snapshot.is_symlink():
    fail("selected complete-glibc snapshot is not a real directory")
glibc_receipt_path = artifacts / glibc_id / "receipt.json"
glibc_receipt = load_plain(glibc_receipt_path, "complete glibc receipt")
base_snapshot = Path(str(glibc_receipt.get("base_snapshot", "")))
run_helper(
    glibc_helper, "validate-completed", glibc_receipt_path, snapshot,
    base_snapshot, "schema", 1, "component", "glibc", "stage", "complete",
    "build_id", glibc_id, "source_commit", glibc_commit,
    "source_tree", glibc_tree, "source_repository", glibc_repository,
    "source_set_digest", source_set_digest,
    "source_authentication", source_authentication, "target", target,
    "snapshot", snapshot, "functional_libc", "present",
)

libgcc_value = receipt_dependency(glibc_receipt, "libgcc")
libgcc_id = str(libgcc_value.get("build_id", ""))
if not safe_id.fullmatch(libgcc_id):
    fail("complete glibc names an unsafe bootstrap-libgcc build")
if requested_libgcc and requested_libgcc != libgcc_id:
    fail("requested bootstrap-libgcc build disagrees with complete glibc")
libgcc_prefix = Path(str(libgcc_value.get("prefix", "")))
libgcc_receipt_path = Path(str(libgcc_value.get("receipt", "")))
libgcc_receipt = load_plain(libgcc_receipt_path, "bootstrap libgcc receipt")
if (
    libgcc_prefix != tools / libgcc_id
    or libgcc_receipt_path != artifacts / libgcc_id / "receipt.json"
    or sha256(libgcc_receipt_path) != libgcc_value.get("receipt_sha256")
    or libgcc_value.get("gcc_version") != gcc_version
    or libgcc_value.get("prefix_digest")
        != libgcc_receipt.get("result_prefix_digest")
    or libgcc_receipt.get("base_build_id")
        != libgcc_receipt.get("dependencies", {}).get("gcc", {}).get("build_id")
):
    fail("complete glibc bootstrap-libgcc binding is invalid")
libgcc_base = Path(str(libgcc_receipt.get("base_prefix", "")))
run_helper(
    libgcc_helper, "validate-completed", libgcc_receipt_path, libgcc_prefix,
    libgcc_base, tools, target, gcc_version, "schema", 1, "component", "gcc",
    "stage", "libgcc-bootstrap", "build_id", libgcc_id,
    "source_commit", gcc_commit, "source_tree", gcc_tree,
    "source_repository", gcc_repository, "source_set_digest",
    source_set_digest, "source_authentication", source_authentication,
    "target", target, "prefix", libgcc_prefix, "base_prefix", libgcc_base,
)

tools_current = tools / "current"
if not tools_current.is_symlink():
    fail("tools/current is not a managed symlink")
active_tools_id = os.readlink(tools_current)
if not safe_id.fullmatch(active_tools_id):
    fail("tools/current has an unsafe target")
cursor = active_tools_id
seen = set()
while cursor != libgcc_id:
    if cursor in seen:
        fail("tools/current ancestry is cyclic")
    seen.add(cursor)
    receipt = load_plain(artifacts / cursor / "receipt.json", "tools receipt")
    if receipt.get("build_id") != cursor:
        fail("tools/current ancestry has invalid receipt identity")
    cursor = receipt.get("base_build_id")
    if not isinstance(cursor, str) or not safe_id.fullmatch(cursor):
        fail("tools/current does not descend from complete glibc's libgcc")

gcc_value = receipt_dependency(glibc_receipt, "gcc")
binutils_value = receipt_dependency(glibc_receipt, "binutils")
linux_value = receipt_dependency(glibc_receipt, "linux")
for name, value, component, stage, commit, tree, repository in (
    ("gcc", gcc_value, "gcc", "stage1", gcc_commit, gcc_tree, gcc_repository),
    (
        "binutils", binutils_value, "binutils", "stage1", binutils_commit,
        binutils_tree, binutils_repository,
    ),
    (
        "linux", linux_value, "linux", "uapi-headers", linux_commit,
        linux_tree, linux_repository,
    ),
):
    path = Path(str(value.get("receipt", "")))
    receipt = load_plain(path, f"{name} receipt")
    if (
        path != artifacts / str(value.get("build_id", "")) / "receipt.json"
        or sha256(path) != value.get("receipt_sha256")
        or receipt.get("build_id") != value.get("build_id")
        or receipt.get("component") != component
        or receipt.get("stage") != stage
        or receipt.get("source_commit") != commit
        or receipt.get("source_tree") != tree
        or receipt.get("source_repository") != repository
        or receipt.get("source_set_digest") != source_set_digest
        or receipt.get("source_authentication") != source_authentication
        or receipt.get("target") != target
    ):
        fail(f"{name} dependency provenance is invalid")

libgcc_gcc = libgcc_receipt.get("dependencies", {}).get("gcc", {})
libgcc_binutils = libgcc_receipt.get("dependencies", {}).get("binutils", {})
if (
    libgcc_gcc.get("build_id") != gcc_value.get("build_id")
    or libgcc_gcc.get("receipt_sha256") != gcc_value.get("receipt_sha256")
    or libgcc_binutils.get("build_id") != binutils_value.get("build_id")
    or libgcc_binutils.get("receipt_sha256") != binutils_value.get("receipt_sha256")
):
    fail("complete glibc and bootstrap libgcc disagree on stage-one tools")
binutils_prefix = Path(str(binutils_value.get("prefix", "")))
gcc_prefix = Path(str(gcc_value.get("prefix", "")))
linux_snapshot = Path(str(linux_value.get("snapshot", "")))
if (
    binutils_prefix != tools / str(binutils_value.get("build_id", ""))
    or gcc_prefix != tools / str(gcc_value.get("build_id", ""))
):
    fail("stage-one tools have invalid prefix identity")
gcc_receipt = load_plain(Path(str(gcc_value["receipt"])), "GCC stage-one receipt")
binutils_receipt = load_plain(
    Path(str(binutils_value["receipt"])), "Binutils stage-one receipt"
)
if (
    helper_json(inventory_helper, "dependency-inventory", gcc_prefix, tools)
        != gcc_receipt.get("installed_entries")
    or helper_json(
        inventory_helper, "dependency-inventory", binutils_prefix, tools
    ) != binutils_receipt.get("installed_entries")
):
    fail("stage-one tools failed complete inventory replay")
linux_receipt = load_plain(Path(str(linux_value["receipt"])), "Linux receipt")
linux_inventory = helper_json(inventory_helper, "inventory", linux_snapshot)
if (
    linux_receipt.get("snapshot") != str(linux_snapshot)
    or linux_receipt.get("installed_entries") != linux_inventory.get("entries")
    or linux_receipt.get("result_snapshot_digest")
        != f"sha256:{linux_inventory.get('digest')}"
    or linux_value.get("snapshot_digest")
        != f"sha256:{linux_inventory.get('digest')}"
):
    fail("Linux UAPI snapshot failed complete inventory replay")

print(glibc_id)
print(snapshot)
print(glibc_receipt_path)
print(sha256(glibc_receipt_path))
print(glibc_receipt["result_snapshot_digest"])
print(libgcc_id)
print(libgcc_prefix)
print(libgcc_receipt_path)
print(sha256(libgcc_receipt_path))
print(libgcc_receipt["result_prefix_digest"])
print(libgcc_base)
print(active_tools_id)
print(gcc_value["build_id"])
print(gcc_prefix)
print(gcc_value["receipt"])
print(gcc_value["receipt_sha256"])
print(binutils_value["build_id"])
print(binutils_prefix)
print(binutils_value["receipt"])
print(binutils_value["receipt_sha256"])
print(linux_value["build_id"])
print(linux_snapshot)
print(linux_value["receipt"])
print(linux_value["receipt_sha256"])
print(linux_value["snapshot_digest"])
PY
}

mapfile -t dependency_values < <(resolve_dependencies)
if (( ${#dependency_values[@]} != 25 )); then
  echo "Authoritative GCC dependency resolver returned incomplete state" >&2
  exit 79
fi
glibc_build_id=${dependency_values[0]}
glibc_snapshot=${dependency_values[1]}
glibc_receipt=${dependency_values[2]}
glibc_receipt_sha256=${dependency_values[3]}
glibc_snapshot_digest=${dependency_values[4]}
libgcc_build_id=${dependency_values[5]}
libgcc_prefix=${dependency_values[6]}
libgcc_receipt=${dependency_values[7]}
libgcc_receipt_sha256=${dependency_values[8]}
libgcc_prefix_digest=${dependency_values[9]}
libgcc_base_prefix=${dependency_values[10]}
active_tools_build_id=${dependency_values[11]}
gcc_build_id=${dependency_values[12]}
gcc_prefix=${dependency_values[13]}
gcc_receipt=${dependency_values[14]}
gcc_receipt_sha256=${dependency_values[15]}
binutils_build_id=${dependency_values[16]}
binutils_prefix=${dependency_values[17]}
binutils_receipt=${dependency_values[18]}
binutils_receipt_sha256=${dependency_values[19]}
linux_build_id=${dependency_values[20]}
linux_snapshot=${dependency_values[21]}
linux_receipt=${dependency_values[22]}
linux_receipt_sha256=${dependency_values[23]}
linux_snapshot_digest=${dependency_values[24]}

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
  "--enable-languages=c,c++"
  "--disable-bootstrap"
  "--disable-multilib"
  "--enable-shared"
  "--enable-threads=posix"
  "--disable-nls"
  "--disable-werror"
  "--disable-lto"
  "--disable-fixincludes"
  "--without-isl"
  "--without-zstd"
  "--disable-libgomp"
  "--disable-libitm"
  "--disable-libsanitizer"
  "--disable-libquadmath"
  "--disable-libssp"
  "--disable-libvtv"
  "--disable-libstdcxx-pch"
  "--disable-libstdcxx-debug"
  "--disable-libstdcxx-debug-flags"
)
configure_digest=$(printf '%s\0' "${configure_args[@]}" | sha256sum | awk '{print $1}')
recipe_sha256=$(sha256sum "$script_path" | awk '{print $1}')
inventory_helper_sha256=$(sha256sum "$inventory_helper" | awk '{print $1}')
libgcc_helper_sha256=$(sha256sum "$libgcc_helper" | awk '{print $1}')
glibc_helper_sha256=$(sha256sum "$glibc_helper" | awk '{print $1}')
base_inventory_evidence_sha256=$(
  "$script_path" --internal-python dependency-inventory \
    "$libgcc_prefix" "$tools_root" | sha256sum | awk '{print $1}'
)
build_id=$("$script_path" --internal-python build-id "$locked_gcc_commit" \
  source_set_digest "$source_set_digest" \
  source_tree "$locked_gcc_tree" \
  orchestration_commit "$orchestration_commit" \
  orchestration_tree "$orchestration_tree" \
  recipe_sha256 "$recipe_sha256" \
  inventory_helper_sha256 "$inventory_helper_sha256" \
  libgcc_helper_sha256 "$libgcc_helper_sha256" \
  glibc_helper_sha256 "$glibc_helper_sha256" \
  configure_digest "$configure_digest" \
  public_target_cflags "$target_cflags" \
  public_target_cxxflags "$target_cxxflags" \
  cycle_cflags "$cycle_cflags" \
  cycle_cxxflags "$cycle_cxxflags" \
  cycle_ldflags "$cycle_ldflags" \
  libgcc2_debug_cflags -g0 \
  gcc_version "$gcc_version" \
  libgcc_receipt_sha256 "$libgcc_receipt_sha256" \
  gcc_receipt_sha256 "$gcc_receipt_sha256" \
  binutils_receipt_sha256 "$binutils_receipt_sha256" \
  glibc_receipt_sha256 "$glibc_receipt_sha256" \
  linux_receipt_sha256 "$linux_receipt_sha256" \
  glibc_snapshot_digest "$glibc_snapshot_digest" \
  linux_snapshot_digest "$linux_snapshot_digest" \
  base_inventory_evidence_sha256 "$base_inventory_evidence_sha256")

run_id=${CAJUNOS_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
if [[ ! $run_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "Unsafe CAJUNOS_RUN_ID: $run_id" >&2
  exit 80
fi

build_final=$work_root/$build_id
prefix_final=$tools_root/$build_id
artifact_final=$artifacts_root/$build_id
receipt_final=$artifact_final/receipt.json
log_dir=$logs_root/$run_id
log_file=$log_dir/gcc-complete.log
temporary_root=$work_root/.tmp-$build_id-$$
build_a=$temporary_root/build-a
build_b=$temporary_root/build-b
candidate_a=$tools_root/.tmp-$build_id-a-$$
candidate_b=$tools_root/.tmp-$build_id-b-$$
overlay_a=$temporary_root/overlay-a
overlay_b=$temporary_root/overlay-b
artifact_temporary=$artifacts_root/.tmp-$build_id-$$
failed_root=$work_root/.failed-$build_id-$$
failed_artifact=$artifacts_root/.failed-$build_id-$$

validate_complete() {
  local receipt_path=${1:-$receipt_final}
  local actual_prefix=${2:-$prefix_final}
  "$script_path" --internal-python validate-completed \
    "$receipt_path" "$actual_prefix" "$libgcc_prefix" "$tools_root" \
    "$target" "$gcc_version" \
    schema 1 component gcc stage complete build_id "$build_id" \
    source_commit "$locked_gcc_commit" source_tree "$locked_gcc_tree" \
    source_repository "$gcc_repository" \
    source_set_digest "$source_set_digest" \
    source_authentication "$source_authentication" \
    source_date_epoch "$SOURCE_DATE_EPOCH" target "$target" \
    build_triplet "$build_triplet" gcc_version "$gcc_version" \
    prefix "$prefix_final" base_prefix "$libgcc_prefix" \
    base_build_id "$libgcc_build_id" \
    sysroot "$sysroot" sysroot_snapshot "$glibc_snapshot" \
    sysroot_snapshot_digest "$glibc_snapshot_digest" sysroot_modified False \
    public_target_cflags "$target_cflags" \
    public_target_cxxflags "$target_cxxflags" \
    build_cycle_cflags "$cycle_cflags" \
    build_cycle_cxxflags "$cycle_cxxflags" \
    build_cycle_ldflags "$cycle_ldflags" \
    libgcc2_debug_cflags -g0 \
    runtime_contract.functional_libc present \
    runtime_contract.shared_libgcc present \
    runtime_contract.libatomic present \
    runtime_contract.libstdcxx present \
    runtime_contract.thread_model posix \
    runtime_contract.multilib disabled \
    runtime_contract.cxx_standard c++23 \
    orchestration_commit "$orchestration_commit" \
    orchestration_tree "$orchestration_tree" recipe_sha256 "$recipe_sha256" \
    inventory_helper_sha256 "$inventory_helper_sha256" \
    libgcc_helper_sha256 "$libgcc_helper_sha256" \
    glibc_helper_sha256 "$glibc_helper_sha256" \
    dependencies.libgcc.build_id "$libgcc_build_id" \
    dependencies.libgcc.prefix "$libgcc_prefix" \
    dependencies.libgcc.prefix_digest "$libgcc_prefix_digest" \
    dependencies.libgcc.receipt_sha256 "$libgcc_receipt_sha256" \
    dependencies.gcc.build_id "$gcc_build_id" \
    dependencies.gcc.prefix "$gcc_prefix" \
    dependencies.gcc.receipt_sha256 "$gcc_receipt_sha256" \
    dependencies.binutils.build_id "$binutils_build_id" \
    dependencies.binutils.prefix "$binutils_prefix" \
    dependencies.binutils.receipt_sha256 "$binutils_receipt_sha256" \
    dependencies.glibc.build_id "$glibc_build_id" \
    dependencies.glibc.snapshot "$glibc_snapshot" \
    dependencies.glibc.snapshot_digest "$glibc_snapshot_digest" \
    dependencies.glibc.receipt_sha256 "$glibc_receipt_sha256" \
    dependencies.linux.build_id "$linux_build_id" \
    dependencies.linux.snapshot "$linux_snapshot" \
    dependencies.linux.snapshot_digest "$linux_snapshot_digest" \
    dependencies.linux.receipt_sha256 "$linux_receipt_sha256"
}

exec 9>"$cajunos_root/work/.cajunos-build.lock"
if ! flock -n 9; then
  echo "Another CajunOS build owns the global build lock" >&2
  exit 81
fi

if [[ -d $build_final && ! -L $build_final \
   && -d $prefix_final && ! -L $prefix_final \
   && -d $artifact_final && ! -L $artifact_final \
   && -f $receipt_final && ! -L $receipt_final ]]; then
  validate_complete
  selector_result=$("$script_path" --internal-python selector-transition \
    "$tools_root" "$artifacts_root" "$libgcc_build_id" "$build_id")
  echo "CAJUNOS_GCC_COMPLETE_ALREADY_COMPLETE build_id=$build_id selector=$selector_result"
  exit 0
fi
if [[ -e $build_final || -L $build_final \
   || -e $prefix_final || -L $prefix_final \
   || -e $artifact_final || -L $artifact_final ]]; then
  echo "Refusing to reuse an incomplete published build: $build_id" >&2
  exit 82
fi
if [[ -e $temporary_root || -L $temporary_root \
   || -e $candidate_a || -L $candidate_a \
   || -e $candidate_b || -L $candidate_b \
   || -e $artifact_temporary || -L $artifact_temporary \
   || -e $failed_root || -L $failed_root \
   || -e $failed_artifact || -L $failed_artifact \
   || -e $log_dir || -L $log_dir ]]; then
  echo "Refusing colliding complete-GCC temporary or log path: $run_id" >&2
  exit 83
fi
selector_state=$("$script_path" --internal-python selector-state \
  "$tools_root" "$artifacts_root" "$libgcc_build_id" "$build_id")
if [[ $selector_state != base || $active_tools_build_id != "$libgcc_build_id" ]]; then
  echo "Fresh complete-GCC build requires tools/current to select exact bootstrap libgcc" >&2
  exit 84
fi

build_succeeded=0
on_exit() {
  local status=$?
  local safe_to_quarantine=1
  local live_selector_state=
  set +e
  if (( status != 0 || build_succeeded == 0 )); then
    live_selector_state=$("$script_path" --internal-python selector-state \
      "$tools_root" "$artifacts_root" "$libgcc_build_id" "$build_id" \
      2>/dev/null) || safe_to_quarantine=0
    case $live_selector_state in
      this)
        "$script_path" --internal-python selector-rollback \
          "$tools_root" "$artifacts_root" "$libgcc_build_id" "$build_id" \
          >/dev/null 2>&1 || safe_to_quarantine=0
        ;;
      base)
        ;;
      later:*|*)
        # A later consumer, corrupt selector, or unreadable selector makes the
        # published prefix potentially live. Preserve all state for recovery.
        safe_to_quarantine=0
        ;;
    esac
    if (( safe_to_quarantine == 1 )) \
       && [[ -e $temporary_root || -L $temporary_root \
          || -e $build_final || -L $build_final \
          || -e $candidate_a || -L $candidate_a \
          || -e $candidate_b || -L $candidate_b \
          || -e $prefix_final || -L $prefix_final ]]; then
      mkdir -- "$failed_root"
      if [[ -e $temporary_root || -L $temporary_root ]]; then
        mv -T -- "$temporary_root" "$failed_root/temporary-root-entry"
      fi
      if [[ -e $build_final || -L $build_final ]]; then
        mv -T -- "$build_final" "$failed_root/build-final-entry"
      fi
      if [[ -e $candidate_a || -L $candidate_a ]]; then
        mv -T -- "$candidate_a" "$failed_root/candidate-a"
      fi
      if [[ -e $candidate_b || -L $candidate_b ]]; then
        mv -T -- "$candidate_b" "$failed_root/candidate-b"
      fi
      if [[ -e $prefix_final || -L $prefix_final ]]; then
        mv -T -- "$prefix_final" "$failed_root/permanent-unselected-prefix"
      fi
    fi
    if (( safe_to_quarantine == 1 )) \
       && [[ -e $artifact_temporary || -L $artifact_temporary \
          || -e $artifact_final || -L $artifact_final ]]; then
      mkdir -- "$failed_artifact"
      if [[ -e $artifact_temporary || -L $artifact_temporary ]]; then
        mv -T -- "$artifact_temporary" "$failed_artifact/temporary-artifact-entry"
      fi
      if [[ -e $artifact_final || -L $artifact_final ]]; then
        mv -T -- "$artifact_final" "$failed_artifact/artifact-final-entry"
      fi
    fi
  fi
  trap - EXIT
  exit "$status"
}
trap on_exit EXIT

mkdir -p "$build_a" "$build_b" "$candidate_a" "$candidate_b" \
  "$overlay_a" "$overlay_b" "$artifact_temporary" "$log_dir"
exec > >(tee "$log_file") 2>&1

echo "CajunOS complete GCC/G++ cross-toolchain"
echo "build_id=$build_id"
echo "source=$locked_gcc_commit"
echo "source_set=$source_set_digest"
echo "source_authentication=$source_authentication"
echo "orchestration=$orchestration_commit"
echo "base_libgcc=$libgcc_build_id"
echo "complete_glibc=$glibc_build_id"
echo "target=$target"
echo "gcc_version=$gcc_version"
echo "prefix=$prefix_final"
echo "sysroot=$sysroot"
echo "sysroot_snapshot=$glibc_snapshot"
echo "public_target_cflags=$target_cflags"
echo "build_cycle_cflags=$cycle_cflags"
echo "build_cycle_ldflags=$cycle_ldflags"
echo "makeflags=$MAKEFLAGS"

printf '%s\n' "${configure_args[@]}" > "$artifact_temporary/configure.args"
"$script_path" --internal-python dependency-inventory \
  "$libgcc_prefix" "$tools_root" > "$artifact_temporary/base-before.json"
"$script_path" --internal-python inventory \
  "$glibc_snapshot" > "$artifact_temporary/sysroot-before.json"

export PATH="$binutils_prefix/bin:/usr/bin:/bin"
make_target_vars=(
  "CFLAGS_FOR_TARGET=$cycle_cflags"
  "CXXFLAGS_FOR_TARGET=$cycle_cxxflags"
  "LDFLAGS_FOR_TARGET=$cycle_ldflags"
  "LIBGCC2_DEBUG_CFLAGS=-g0"
  "MAKE=/usr/bin/make LIBGCC2_DEBUG_CFLAGS=-g0"
)

build_one() {
  local build=$1 candidate=$2 overlay=$3 label=$4
  (
    cd "$build"
    CONFIG_SHELL=/bin/bash \
      CC=/usr/bin/gcc CXX=/usr/bin/g++ \
      CFLAGS="$host_cflags" CXXFLAGS="$host_cflags" \
      CFLAGS_FOR_TARGET="$target_cflags" \
      CXXFLAGS_FOR_TARGET="$target_cxxflags" \
      LDFLAGS_FOR_TARGET= \
      "$gcc_source_dir/configure" --prefix="$prefix_final" "${configure_args[@]}"
  ) > "$artifact_temporary/$label.configure.stdout" 2>&1

  "$script_path" --internal-python top-level-make-contract \
    "$build/Makefile" "$sysroot" "$glibc_snapshot"

  # This is the authoritative, ordered complete compiler/runtime sequence.
  # All top-level make calls receive the exact same target/cycle contract.
  make -j1 -C "$build" "${make_target_vars[@]}" configure-gcc
  "$script_path" --internal-python gcc-header-contract \
    "$build/gcc/Makefile" "$sysroot" "$glibc_snapshot"
  make -C "$build" "${make_target_vars[@]}" all-gcc

  make -j1 -C "$build" "${make_target_vars[@]}" configure-target-libgcc
  "$script_path" --internal-python libgcc-make-contract \
    "$build/$target/libgcc/Makefile" "$build/gcc" "$prefix_final" \
    "$target" "$glibc_snapshot"
  make -C "$build" "${make_target_vars[@]}" all-target-libgcc

  make -j1 -C "$build" "${make_target_vars[@]}" configure-target-libatomic
  "$script_path" --internal-python libatomic-make-contract \
    "$build/$target/libatomic/Makefile" "$build/gcc" "$prefix_final" \
    "$target" "$glibc_snapshot"
  make -C "$build" "${make_target_vars[@]}" all-target-libatomic

  make -j1 -C "$build" "${make_target_vars[@]}" configure-target-libstdc++-v3
  "$script_path" --internal-python libstdcxx-make-contract \
    "$build/$target/libstdc++-v3/Makefile" "$build/gcc" "$prefix_final" \
    "$target" "$glibc_snapshot"
  make -C "$build" "${make_target_vars[@]}" all-target-libstdc++-v3

  make -j1 -C "$build" "${make_target_vars[@]}" \
    DESTDIR="$overlay" install-gcc
  make -j1 -C "$build" "${make_target_vars[@]}" \
    DESTDIR="$overlay" install-target-libgcc
  make -j1 -C "$build" "${make_target_vars[@]}" \
    DESTDIR="$overlay" install-target-libatomic
  make -j1 -C "$build" "${make_target_vars[@]}" \
    DESTDIR="$overlay" install-target-libstdc++-v3

  local staged_prefix=$overlay$prefix_final
  [[ -d $staged_prefix && ! -L $staged_prefix ]] || {
    echo "Complete GCC install did not stage its configured prefix" >&2
    return 1
  }
  "$script_path" --internal-python normalize-modes "$staged_prefix" \
    > "$artifact_temporary/$label.normalized-modes.json"
  "$script_path" --internal-python mode-contract "$staged_prefix"
  "$script_path" --internal-python normalize-hardlinks "$staged_prefix" \
    > "$artifact_temporary/$label.normalized-hardlinks.txt"
  "$script_path" --internal-python no-hardlinks "$staged_prefix"

  rsync -a -- "$libgcc_prefix/" "$candidate/"
  "$script_path" --internal-python no-shared-inodes \
    "$libgcc_prefix" "$candidate"
  rsync -a -- "$staged_prefix/" "$candidate/"
  "$script_path" --internal-python no-hardlinks "$candidate"
  "$script_path" --internal-python mode-contract "$candidate"
  "$script_path" --internal-python write-delta \
    "$libgcc_prefix" "$candidate" "$tools_root" "$target" "$gcc_version" \
    "$artifact_temporary/delta-$label.json"
  "$script_path" --internal-python runtime-elf-scan \
    "$candidate" "$target" "$gcc_version" \
    > "$artifact_temporary/runtime-elf-$label.json"

  if grep -R -a -F -l -- "$build" \
      "$candidate/lib/gcc/$target/$gcc_version" \
      "$candidate/libexec/gcc/$target/$gcc_version" \
      "$candidate/$target" | grep -q .; then
    echo "Complete GCC output retains its disposable $label build path" >&2
    return 1
  fi
}

build_one "$build_a" "$candidate_a" "$overlay_a" a
build_one "$build_b" "$candidate_b" "$overlay_b" b

"$script_path" --internal-python dependency-inventory \
  "$candidate_a" "$tools_root" > "$artifact_temporary/inventory-a.json"
"$script_path" --internal-python dependency-inventory \
  "$candidate_b" "$tools_root" > "$artifact_temporary/inventory-b.json"
"$script_path" --internal-python compare-json \
  "$artifact_temporary/inventory-a.json" "$artifact_temporary/inventory-b.json"
"$script_path" --internal-python compare-json \
  "$artifact_temporary/delta-a.json" "$artifact_temporary/delta-b.json"
"$script_path" --internal-python compare-json \
  "$artifact_temporary/runtime-elf-a.json" \
  "$artifact_temporary/runtime-elf-b.json"
cmp -s "$artifact_temporary/a.normalized-hardlinks.txt" \
  "$artifact_temporary/b.normalized-hardlinks.txt" || {
  echo "Independent GCC installations normalized different hardlink counts" >&2
  exit 85
}
cmp -s "$artifact_temporary/a.normalized-modes.json" \
  "$artifact_temporary/b.normalized-modes.json" || {
  echo "Independent GCC installations normalized different mode counts" >&2
  exit 85
}

configuration_dir=$artifact_temporary/configuration
probe_dir=$artifact_temporary/probe
license_dir=$artifact_temporary/licenses/gcc
mkdir -p "$configuration_dir" "$probe_dir" "$license_dir"
for label in a b; do
  build_variable=build_$label
  build=${!build_variable}
  cp -- "$build/config.log" "$configuration_dir/build-$label.config.log"
  cp -- "$build/gcc/config.log" \
    "$configuration_dir/build-$label.gcc.config.log"
  cp -- "$build/$target/libgcc/config.log" \
    "$configuration_dir/build-$label.libgcc.config.log"
  cp -- "$build/$target/libatomic/config.log" \
    "$configuration_dir/build-$label.libatomic.config.log"
  cp -- "$build/$target/libstdc++-v3/config.log" \
    "$configuration_dir/build-$label.libstdcxx.config.log"
done
grep -F -- '-DIN_LIBGCC2' "$log_file" \
  > "$configuration_dir/libgcc-debug-flags.txt"
"$script_path" --internal-python normalize-configuration \
  "$configuration_dir" "$build_a" "$build_b" \
  "$candidate_a" "$candidate_b" "$overlay_a" "$overlay_b" \
  "$temporary_root"
"$script_path" --internal-python configuration-contract "$configuration_dir"
"$script_path" --internal-python libgcc-debug-flags-contract \
  "$configuration_dir/libgcc-debug-flags.txt"
for label in a b; do
  cp -- "$artifact_temporary/$label.normalized-modes.json" \
    "$configuration_dir/build-$label.normalized-modes.json"
  cp -- "$artifact_temporary/$label.normalized-hardlinks.txt" \
    "$configuration_dir/build-$label.normalized-hardlinks.txt"
done

# Establish the final path while it remains permanently unselected. Every
# persistent probe therefore records the identity that the receipt publishes.
"$script_path" --internal-python validate-directories "$cajunos_root" \
  work work/toolchain tools artifacts logs sysroot "sysroot/$cohort_id"
if [[ $candidate_a != "$tools_root/.tmp-$build_id-a-$$" \
   || $candidate_b != "$tools_root/.tmp-$build_id-b-$$" \
   || ! -d $candidate_a || -L $candidate_a \
   || ! -d $candidate_b || -L $candidate_b \
   || -e $prefix_final || -L $prefix_final ]]; then
  echo "Complete-GCC permanent-prefix paths changed after validation" >&2
  exit 86
fi
mv -T -- "$candidate_a" "$prefix_final"
"$script_path" --internal-python no-hardlinks "$prefix_final"
"$script_path" --internal-python mode-contract "$prefix_final"

gcc_driver=$prefix_final/bin/$target-gcc
gxx_driver=$prefix_final/bin/$target-g++
[[ -x $gcc_driver && -x $gxx_driver ]] || {
  echo "Complete prefix lacks executable GCC/G++ cross drivers" >&2
  exit 87
}
"$script_path" --internal-python write-driver-evidence \
  "$prefix_final" "$probe_dir/driver-identities.txt" \
  "$target" "$gcc_version" "$sysroot" "$binutils_prefix"
"$script_path" --internal-python driver-policy-contract \
  "$prefix_final" "$probe_dir/driver-identities.txt" \
  "$target" "$gcc_version" "$sysroot" "$binutils_prefix"
grep -Fqx "gcc-dumpmachine=$target" "$probe_dir/driver-identities.txt"
grep -Fqx "gxx-dumpmachine=$target" "$probe_dir/driver-identities.txt"
grep -Fqx "gcc-sysroot=$sysroot" "$probe_dir/driver-identities.txt"
grep -Fqx "gxx-sysroot=$sysroot" "$probe_dir/driver-identities.txt"
grep -Fqx 'gcc-multilib=.;' "$probe_dir/driver-identities.txt"
grep -Fqx 'gxx-multilib=.;' "$probe_dir/driver-identities.txt"
cc1_path=$("$gcc_driver" -print-prog-name=cc1)
cc1plus_path=$("$gxx_driver" -print-prog-name=cc1plus)
[[ -x $cc1_path && $cc1_path == "$prefix_final"/* \
   && -x $cc1plus_path && $cc1plus_path == "$prefix_final"/* ]] || {
  echo "Complete drivers did not relocate cc1/cc1plus into their own prefix" >&2
  exit 88
}
for program in as ld; do
  resolved=$("$gcc_driver" -print-prog-name="$program")
  expected=$binutils_prefix/bin/$target-$program
  [[ $(readlink -f -- "$resolved") == "$(readlink -f -- "$expected")" ]] || {
    echo "Complete GCC resolved unexpected $program: $resolved" >&2
    exit 89
  }
done
"$script_path" --internal-python write-cxx-header-search \
  "$probe_dir/cxx-header-search.search" "$prefix_final" \
  "$glibc_snapshot" "$target" "$gcc_version"
"$script_path" --internal-python cxx-header-search-contract \
  "$probe_dir/cxx-header-search.search" "$prefix_final" \
  "$glibc_snapshot" "$libgcc_prefix" "$target" "$gcc_version"

declare -a runtime_lookup_files=(
  libgcc.a libgcc_eh.a libgcov.a
  libgcc_s.so libgcc_s.so.1 libgcc_s_asneeded.so
  libatomic.a libatomic.so libatomic.so.1
  libatomic_asneeded.a libatomic_asneeded.so
  libstdc++.a libstdc++.so libstdc++.so.6
  libstdc++exp.a libstdc++fs.a libsupc++.a
  crtbegin.o crtbeginS.o crtbeginT.o crtend.o crtendS.o
  crtfastmath.o crtprec32.o crtprec64.o crtprec80.o
)
{
  for name in "${runtime_lookup_files[@]}"; do
    if [[ $name == libgcc.a ]]; then
      value=$("$gcc_driver" -print-libgcc-file-name)
    else
      value=$("$gxx_driver" -print-file-name="$name")
    fi
    printf '%s=%s\n' "$name" "$value"
  done
} > "$probe_dir/runtime-lookups.txt"
"$script_path" --internal-python runtime-lookups-contract \
  "$prefix_final" "$probe_dir/runtime-lookups.txt" "$target" "$gcc_version"

cat > "$probe_dir/cxx-dynamic.cc" <<'EOF'
#include <atomic>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

struct base {
    virtual ~base() = default;
};
struct derived final : base {};
thread_local int cajunos_tls = 3;

int main()
{
    derived object;
    base* polymorphic = &object;
    const std::vector<std::string> values{"cajun", "os"};
    const std::filesystem::path path = "/cajun/../os";
    if (dynamic_cast<derived*>(polymorphic) == nullptr
        || values.at(1) != "os"
        || path.lexically_normal() != "/os"
        || cajunos_tls != 3)
        return 1;
    std::atomic<int> value{0};
    std::thread worker([&value] { value.store(7); });
    worker.join();
    if (value.load() != 7)
        return 1;
    try {
        throw std::runtime_error("cajunos");
    } catch (const std::runtime_error&) {
        std::cout << "cxx=ok exception=ok thread=ok\n";
    }
    return 0;
}
EOF

cat > "$probe_dir/atomic-dynamic.c" <<'EOF'
#include <stdatomic.h>
#include <stdio.h>

static _Atomic(unsigned __int128) atom;

int main(void)
{
    const unsigned __int128 expected =
        ((unsigned __int128)1 << 100) + 17;
    const unsigned __int128 replacement = expected + 1;
    atomic_store(&atom, expected);
    unsigned __int128 observed = atomic_load(&atom);
    if (observed != expected
        || !atomic_compare_exchange_strong(&atom, &observed, replacement)
        || atomic_load(&atom) != replacement)
        return 1;
    puts("atomic=ok");
    return 0;
}
EOF

cat > "$probe_dir/cxx-static.cc" <<'EOF'
#include <atomic>
#include <iostream>
#include <stdexcept>

int main()
{
    std::atomic<unsigned __int128> value{0};
    const unsigned __int128 expected =
        (static_cast<unsigned __int128>(1) << 100) + 17;
    value.store(expected);
    if (value.load() != expected)
        return 1;
    try {
        throw std::runtime_error("cajunos");
    } catch (const std::runtime_error&) {
        std::cout << "cxx-static=ok exception=ok atomic=ok\n";
    }
    return 0;
}
EOF

(
  cd "$probe_dir"
  "$gxx_driver" --sysroot="$glibc_snapshot" \
    -std=c++23 -O2 -Wall -Wextra -Werror -pthread \
    -c cxx-dynamic.cc -o cxx-dynamic.o
  "$gxx_driver" --sysroot="$glibc_snapshot" \
    -std=c++23 -O2 -pthread cxx-dynamic.o \
    -Wl,-Map,cxx-dynamic.map -o cxx-dynamic
  "$gcc_driver" --sysroot="$glibc_snapshot" \
    -std=c11 -O2 -Wall -Wextra -Werror \
    -c atomic-dynamic.c -o atomic-dynamic.o
  "$gcc_driver" --sysroot="$glibc_snapshot" \
    -std=c11 -O2 atomic-dynamic.o \
    -Wl,-Map,atomic-dynamic.map -o atomic-dynamic
  "$gxx_driver" --sysroot="$glibc_snapshot" \
    -std=c++23 -O2 -Wall -Wextra -Werror \
    -c cxx-static.cc -o cxx-static.o
  "$gxx_driver" --sysroot="$glibc_snapshot" \
    -std=c++23 -O2 -static cxx-static.o \
    -Wl,-Map,cxx-static.map -o cxx-static
)

for map_name in cxx-dynamic.map atomic-dynamic.map cxx-static.map; do
  "$script_path" --internal-python link-map-contract \
    "$probe_dir/$map_name" "$prefix_final" "$glibc_snapshot"
done
"$script_path" --internal-python probe-path-contract \
  "$probe_dir" "$prefix_final" "$glibc_snapshot"

"$binutils_prefix/bin/$target-readelf" -dW "$probe_dir/cxx-dynamic" \
  > "$probe_dir/cxx-dynamic.readelf-d"
"$binutils_prefix/bin/$target-readelf" -dW "$probe_dir/atomic-dynamic" \
  > "$probe_dir/atomic-dynamic.readelf-d"
"$binutils_prefix/bin/$target-readelf" -dW "$probe_dir/cxx-static" \
  > "$probe_dir/cxx-static.readelf-d"
"$binutils_prefix/bin/$target-readelf" -lW "$probe_dir/cxx-static" \
  > "$probe_dir/cxx-static.readelf-l"
grep -q 'Shared library: \[libstdc++\.so\.6\]' \
  "$probe_dir/cxx-dynamic.readelf-d"
grep -q 'Shared library: \[libgcc_s\.so\.1\]' \
  "$probe_dir/cxx-dynamic.readelf-d"
if grep -q 'Shared library: \[libatomic\.so\.1\]' \
    "$probe_dir/cxx-dynamic.readelf-d"; then
  echo "Ordinary dynamic C++ unexpectedly depends on libatomic" >&2
  exit 90
fi
grep -q 'Shared library: \[libatomic\.so\.1\]' \
  "$probe_dir/atomic-dynamic.readelf-d"
if grep -Eq 'NEEDED|INTERP' \
    "$probe_dir/cxx-static.readelf-d" "$probe_dir/cxx-static.readelf-l"; then
  echo "Static C++ probe unexpectedly requires a shared runtime or loader" >&2
  exit 90
fi
"$binutils_prefix/bin/$target-nm" -u "$probe_dir/cxx-static" \
  > "$probe_dir/cxx-static.undefined"
[[ ! -s $probe_dir/cxx-static.undefined ]] || {
  echo "Static C++ probe retains undefined symbols" >&2
  exit 90
}

runtime_dir=$prefix_final/$target/lib64
"$binutils_prefix/bin/$target-readelf" --version-info \
  "$runtime_dir/libstdc++.so.6" > "$probe_dir/libstdcxx.versions"
"$binutils_prefix/bin/$target-readelf" --version-info \
  "$runtime_dir/libatomic.so.1" > "$probe_dir/libatomic.versions"
"$binutils_prefix/bin/$target-readelf" --version-info \
  "$runtime_dir/libgcc_s.so.1" > "$probe_dir/libgcc-s.versions"
grep -q 'GLIBCXX_3\.4\.37' "$probe_dir/libstdcxx.versions"
grep -q 'CXXABI_1\.3\.17' "$probe_dir/libstdcxx.versions"
grep -q 'LIBATOMIC_1\.2' "$probe_dir/libatomic.versions"
grep -q 'GCC_' "$probe_dir/libgcc-s.versions"

"$script_path" --internal-python write-archive-evidence \
  "$prefix_final" "$probe_dir" "$binutils_prefix" "$target" "$gcc_version"
"$script_path" --internal-python archive-evidence-contract \
  "$prefix_final" "$probe_dir" "$binutils_prefix" "$target" "$gcc_version"
"$script_path" --internal-python write-loader-evidence \
  "$probe_dir" "$prefix_final" "$glibc_snapshot"
"$script_path" --internal-python loader-evidence-contract \
  "$probe_dir" "$prefix_final" "$glibc_snapshot"
"$script_path" --internal-python probe-elf-contract \
  "$probe_dir" "$prefix_final" "$target"

"$script_path" --internal-python runtime-elf-scan \
  "$prefix_final" "$target" "$gcc_version" \
  > "$probe_dir/runtime-elf-scan.json"

loader=$glibc_snapshot/lib64/ld-linux-x86-64.so.2
sealed_library_path=$prefix_final/$target/lib64:$glibc_snapshot/usr/lib
env -i LC_ALL=C TZ=UTC \
  "$loader" --inhibit-cache --library-path "$sealed_library_path" \
  "$probe_dir/cxx-dynamic" > "$probe_dir/cxx-dynamic.stdout" \
  2> "$probe_dir/cxx-dynamic.stderr"
env -i LC_ALL=C TZ=UTC \
  "$loader" --inhibit-cache --library-path "$sealed_library_path" \
  "$probe_dir/atomic-dynamic" > "$probe_dir/atomic-dynamic.stdout" \
  2> "$probe_dir/atomic-dynamic.stderr"
env -i LC_ALL=C TZ=UTC "$probe_dir/cxx-static" \
  > "$probe_dir/cxx-static.stdout" 2> "$probe_dir/cxx-static.stderr"
[[ $(<"$probe_dir/cxx-dynamic.stdout") == \
    'cxx=ok exception=ok thread=ok' \
   && ! -s $probe_dir/cxx-dynamic.stderr ]]
[[ $(<"$probe_dir/atomic-dynamic.stdout") == 'atomic=ok' \
   && ! -s $probe_dir/atomic-dynamic.stderr ]]
[[ $(<"$probe_dir/cxx-static.stdout") == \
    'cxx-static=ok exception=ok atomic=ok' \
   && ! -s $probe_dir/cxx-static.stderr ]]

"$script_path" --internal-python dependency-inventory \
  "$prefix_final" "$tools_root" \
  > "$artifact_temporary/inventory-after-probe.json"
"$script_path" --internal-python compare-json \
  "$artifact_temporary/inventory-a.json" \
  "$artifact_temporary/inventory-after-probe.json"
"$script_path" --internal-python dependency-inventory \
  "$libgcc_prefix" "$tools_root" > "$artifact_temporary/base-after.json"
"$script_path" --internal-python compare-json \
  "$artifact_temporary/base-before.json" "$artifact_temporary/base-after.json"
"$script_path" --internal-python inventory \
  "$glibc_snapshot" > "$artifact_temporary/sysroot-after.json"
"$script_path" --internal-python compare-json \
  "$artifact_temporary/sysroot-before.json" \
  "$artifact_temporary/sysroot-after.json"

# Close every mutable dependency and recipe window before the receipt is made.
"$project_root/scripts/fetch.py" validate --root "$cajunos_root"
if [[ -n $(git -C "$project_root" status --porcelain) \
   || $(git -C "$project_root" rev-parse HEAD) != "$orchestration_commit" \
   || $(git -C "$project_root" rev-parse 'HEAD^{tree}') != "$orchestration_tree" \
   || $(sha256sum "$script_path" | awk '{print $1}') != "$recipe_sha256" \
   || $(sha256sum "$inventory_helper" | awk '{print $1}') != "$inventory_helper_sha256" \
   || $(sha256sum "$libgcc_helper" | awk '{print $1}') != "$libgcc_helper_sha256" \
   || $(sha256sum "$glibc_helper" | awk '{print $1}') != "$glibc_helper_sha256" ]]; then
  echo "Complete-GCC orchestration or frozen helper changed during the build" >&2
  exit 91
fi
mapfile -t dependency_values_after < <(resolve_dependencies)
if (( ${#dependency_values_after[@]} != ${#dependency_values[@]} )); then
  echo "Authoritative complete-GCC dependency pair changed length" >&2
  exit 92
fi
for index in "${!dependency_values[@]}"; do
  if [[ ${dependency_values_after[index]} != "${dependency_values[index]}" ]]; then
    echo "Authoritative complete-GCC dependency pair changed during build" >&2
    exit 93
  fi
done
selector_state=$("$script_path" --internal-python selector-state \
  "$tools_root" "$artifacts_root" "$libgcc_build_id" "$build_id")
if [[ $selector_state != base ]]; then
  echo "tools/current changed before complete-GCC publication" >&2
  exit 94
fi

git -C "$gcc_source_dir" archive "$locked_gcc_commit" -- "${license_paths[@]}" |
  tar -x -C "$license_dir"
"$script_path" --internal-python inventory "$license_dir" \
  > "$artifact_temporary/license-inventory.json"
"$script_path" --internal-python probe-path-contract \
  "$probe_dir" "$prefix_final" "$glibc_snapshot"

python3 - \
  "$artifact_temporary/receipt.json" \
  "$artifact_temporary/inventory-a.json" \
  "$artifact_temporary/base-before.json" \
  "$artifact_temporary/delta-a.json" \
  "$artifact_temporary/sysroot-before.json" \
  "$artifact_temporary/license-inventory.json" \
  "$artifact_temporary/configure.args" \
  "$probe_dir" "$configuration_dir" \
  build_id "$build_id" \
  source_commit "$locked_gcc_commit" \
  source_tree "$locked_gcc_tree" \
  source_repository "$gcc_repository" \
  source_set_digest "$source_set_digest" \
  source_authentication "$source_authentication" \
  source_date_epoch "$SOURCE_DATE_EPOCH" \
  target "$target" build_triplet "$build_triplet" gcc_version "$gcc_version" \
  public_target_cflags "$target_cflags" \
  public_target_cxxflags "$target_cxxflags" \
  build_cycle_cflags "$cycle_cflags" \
  build_cycle_cxxflags "$cycle_cxxflags" \
  build_cycle_ldflags "$cycle_ldflags" \
  prefix "$prefix_final" base_prefix "$libgcc_prefix" \
  base_build_id "$libgcc_build_id" sysroot "$sysroot" \
  sysroot_snapshot "$glibc_snapshot" \
  sysroot_snapshot_digest "$glibc_snapshot_digest" \
  orchestration_commit "$orchestration_commit" \
  orchestration_tree "$orchestration_tree" \
  recipe_sha256 "$recipe_sha256" \
  inventory_helper_sha256 "$inventory_helper_sha256" \
  libgcc_helper_sha256 "$libgcc_helper_sha256" \
  glibc_helper_sha256 "$glibc_helper_sha256" \
  configure_digest "$configure_digest" log "$log_file" \
  libgcc_build_id "$libgcc_build_id" \
  libgcc_prefix "$libgcc_prefix" \
  libgcc_prefix_digest "$libgcc_prefix_digest" \
  libgcc_receipt "$libgcc_receipt" \
  libgcc_receipt_sha256 "$libgcc_receipt_sha256" \
  gcc_build_id "$gcc_build_id" gcc_prefix "$gcc_prefix" \
  gcc_receipt "$gcc_receipt" gcc_receipt_sha256 "$gcc_receipt_sha256" \
  binutils_build_id "$binutils_build_id" binutils_prefix "$binutils_prefix" \
  binutils_receipt "$binutils_receipt" \
  binutils_receipt_sha256 "$binutils_receipt_sha256" \
  glibc_build_id "$glibc_build_id" glibc_receipt "$glibc_receipt" \
  glibc_receipt_sha256 "$glibc_receipt_sha256" \
  linux_build_id "$linux_build_id" linux_snapshot "$linux_snapshot" \
  linux_receipt "$linux_receipt" \
  linux_receipt_sha256 "$linux_receipt_sha256" \
  linux_snapshot_digest "$linux_snapshot_digest" \
  binutils_source_commit "$locked_binutils_commit" \
  binutils_source_tree "$locked_binutils_tree" \
  binutils_source_repository "$binutils_repository" \
  glibc_source_commit "$locked_glibc_commit" \
  glibc_source_tree "$locked_glibc_tree" \
  glibc_source_repository "$glibc_repository" \
  linux_source_commit "$locked_linux_commit" \
  linux_source_tree "$locked_linux_tree" \
  linux_source_repository "$linux_repository" <<'PY'
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
    probe_value, configuration_value, *pair_values,
) = sys.argv[1:]
if len(pair_values) % 2:
    raise SystemExit("receipt generator requires key/value pairs")
p = dict(zip(pair_values[::2], pair_values[1::2], strict=True))


def load(path):
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream)


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical_digest(value):
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def regular_hashes(root_value):
    root = Path(root_value)
    result = {}
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        if path.is_dir() and not path.is_symlink():
            continue
        if (
            not path.is_file()
            or path.is_symlink()
            or metadata.st_nlink != 1
        ):
            raise SystemExit(f"unsupported receipt evidence: {path}")
        result[path.relative_to(root).as_posix()] = sha256(path)
    return result


def first_line(*arguments):
    return subprocess.run(
        arguments,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ).stdout.splitlines()[0]


result_entries = load(result_inventory_value)
base_entries = load(base_inventory_value)
delta = load(delta_value)
sysroot_inventory = load(sysroot_inventory_value)
license_inventory = load(license_inventory_value)
configure_args = Path(configure_args_value).read_text(
    encoding="utf-8"
).splitlines()
probe = Path(probe_value)
configuration = Path(configuration_value)
target = p["target"]
version = p["gcc_version"]
gcc_root = f"lib/gcc/{target}/{version}"
runtime_root = f"{target}/lib64"
runtime_files = {
    f"{gcc_root}/libgcc.a",
    f"{gcc_root}/libgcc_eh.a",
    f"{gcc_root}/libgcov.a",
    f"{runtime_root}/libgcc_s.so.1",
    f"{runtime_root}/libgcc_s.so",
    f"{runtime_root}/libgcc_s_asneeded.so",
    f"{runtime_root}/libatomic.a",
    f"{runtime_root}/libatomic.so.1.2.0",
    f"{runtime_root}/libatomic_asneeded.so",
    f"{runtime_root}/libstdc++.a",
    f"{runtime_root}/libstdc++.so.6.0.37",
    f"{runtime_root}/libstdc++exp.a",
    f"{runtime_root}/libstdc++fs.a",
    f"{runtime_root}/libsupc++.a",
}
runtime_sha256 = {}
for relative in sorted(runtime_files):
    metadata = result_entries.get(relative)
    if not isinstance(metadata, dict) or metadata.get("type") != "file":
        raise SystemExit(f"receipt runtime file is absent: {relative}")
    runtime_sha256[relative] = metadata["sha256"]
with (probe / "runtime-elf-scan.json").open(encoding="utf-8") as stream:
    runtime_elf_scan = json.load(stream)

normalization = {
    "mode_policy": (
        "directories-0755-executable-regulars-0755-"
        "other-regulars-0644-symlinks-unchanged-v1"
    ),
    "hardlink_policy": "atomic-same-directory-single-link-v1",
    "build_a_modes": load(configuration / "build-a.normalized-modes.json"),
    "build_b_modes": load(configuration / "build-b.normalized-modes.json"),
    "build_a_hardlinks_broken": int(
        (configuration / "build-a.normalized-hardlinks.txt").read_text()
    ),
    "build_b_hardlinks_broken": int(
        (configuration / "build-b.normalized-hardlinks.txt").read_text()
    ),
}

packages = {}
for package in ("gcc", "g++", "make", "rsync", "binutils"):
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Version}", package],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    packages[package] = result.stdout if result.returncode == 0 else None

result_digest = canonical_digest(result_entries)
base_digest = canonical_digest(base_entries)
receipt = {
    "schema": 1,
    "build_id": p["build_id"],
    "component": "gcc",
    "stage": "complete",
    "source_commit": p["source_commit"],
    "source_tree": p["source_tree"],
    "source_repository": p["source_repository"],
    "source_set_digest": p["source_set_digest"],
    "source_authentication": p["source_authentication"],
    "source_date_epoch": int(p["source_date_epoch"]),
    "target": target,
    "build_triplet": p["build_triplet"],
    "gcc_version": version,
    "public_target_cflags": p["public_target_cflags"],
    "public_target_cxxflags": p["public_target_cxxflags"],
    "build_cycle_cflags": p["build_cycle_cflags"],
    "build_cycle_cxxflags": p["build_cycle_cxxflags"],
    "build_cycle_ldflags": p["build_cycle_ldflags"],
    "libgcc2_debug_cflags": "-g0",
    "prefix": p["prefix"],
    "base_prefix": p["base_prefix"],
    "base_build_id": p["base_build_id"],
    "sysroot": p["sysroot"],
    "sysroot_snapshot": p["sysroot_snapshot"],
    "sysroot_snapshot_digest": p["sysroot_snapshot_digest"],
    "sysroot_modified": False,
    "runtime_contract": {
        "functional_libc": "present",
        "shared_libgcc": "present",
        "libatomic": "present",
        "libstdcxx": "present",
        "thread_model": "posix",
        "multilib": "disabled",
        "cxx_standard": "c++23",
    },
    "generation": {
        "target_configdirs": ["libgcc", "libatomic", "libstdc++-v3"],
        "build_targets": [
            "configure-gcc", "all-gcc", "configure-target-libgcc",
            "all-target-libgcc", "configure-target-libatomic",
            "all-target-libatomic", "configure-target-libstdc++-v3",
            "all-target-libstdc++-v3",
        ],
        "install_targets": [
            "install-gcc", "install-target-libgcc",
            "install-target-libatomic", "install-target-libstdc++-v3",
        ],
        "recursive_make_override": (
            "/usr/bin/make LIBGCC2_DEBUG_CFLAGS=-g0"
        ),
        "install": "make -j1 DESTDIR=<overlay> <ordered-target>",
        "overlay": "sealed-base-plus-normalized-DESTDIR-v1",
    },
    "normalization": normalization,
    "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    "log": p["log"],
    "orchestration_commit": p["orchestration_commit"],
    "orchestration_tree": p["orchestration_tree"],
    "recipe_sha256": p["recipe_sha256"],
    "inventory_helper_sha256": p["inventory_helper_sha256"],
    "libgcc_helper_sha256": p["libgcc_helper_sha256"],
    "glibc_helper_sha256": p["glibc_helper_sha256"],
    "configure_digest": p["configure_digest"],
    "configure_args": configure_args,
    "dependencies": {
        "libgcc": {
            "build_id": p["libgcc_build_id"],
            "prefix": p["libgcc_prefix"],
            "prefix_digest": p["libgcc_prefix_digest"],
            "receipt": p["libgcc_receipt"],
            "receipt_sha256": p["libgcc_receipt_sha256"],
            "gcc_version": version,
        },
        "gcc": {
            "build_id": p["gcc_build_id"],
            "prefix": p["gcc_prefix"],
            "receipt": p["gcc_receipt"],
            "receipt_sha256": p["gcc_receipt_sha256"],
            "source_commit": p["source_commit"],
            "source_tree": p["source_tree"],
            "source_repository": p["source_repository"],
        },
        "binutils": {
            "build_id": p["binutils_build_id"],
            "prefix": p["binutils_prefix"],
            "receipt": p["binutils_receipt"],
            "receipt_sha256": p["binutils_receipt_sha256"],
            "source_commit": p["binutils_source_commit"],
            "source_tree": p["binutils_source_tree"],
            "source_repository": p["binutils_source_repository"],
        },
        "glibc": {
            "build_id": p["glibc_build_id"],
            "snapshot": p["sysroot_snapshot"],
            "snapshot_digest": p["sysroot_snapshot_digest"],
            "receipt": p["glibc_receipt"],
            "receipt_sha256": p["glibc_receipt_sha256"],
            "source_commit": p["glibc_source_commit"],
            "source_tree": p["glibc_source_tree"],
            "source_repository": p["glibc_source_repository"],
            "functional_libc": "present",
        },
        "linux": {
            "build_id": p["linux_build_id"],
            "snapshot": p["linux_snapshot"],
            "snapshot_digest": p["linux_snapshot_digest"],
            "receipt": p["linux_receipt"],
            "receipt_sha256": p["linux_receipt_sha256"],
            "source_commit": p["linux_source_commit"],
            "source_tree": p["linux_source_tree"],
            "source_repository": p["linux_source_repository"],
        },
    },
    "installed_entries": result_entries,
    "base_prefix_digest": f"sha256:{base_digest}",
    "result_prefix_digest": f"sha256:{result_digest}",
    "delta": delta,
    "runtime_sha256": runtime_sha256,
    "reproducibility": {
        "independent_builds": 2,
        "inventory_schema": "paths-types-modes-sha256-symlink-targets-v1",
        "first_inventory_digest": f"sha256:{result_digest}",
        "second_inventory_digest": f"sha256:{result_digest}",
        "identical": True,
        "base_unchanged_after_build": True,
        "sysroot_unchanged_after_build": True,
        "post_probe_inventory_digest": f"sha256:{result_digest}",
    },
    "license_inventory": license_inventory,
    "host": {
        "platform": platform.platform(),
        "gcc": first_line("gcc", "--version"),
        "gxx": first_line("g++", "--version"),
        "make": first_line("make", "--version"),
        "rsync": first_line("rsync", "--version"),
        "packages": packages,
    },
    "outputs": {
        "probe_sha256": regular_hashes(probe),
        "configuration_sha256": regular_hashes(configuration),
        "sysroot_inventory_digest": f"sha256:{sysroot_inventory['digest']}",
        "runtime_elf_count": len(runtime_elf_scan["elf_files"]),
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

# Revalidate the exact permanent-but-unselected candidate and receipt. This is
# the final semantic gate before any selector can move.
if [[ -n $(git -C "$project_root" status --porcelain) \
   || $(git -C "$project_root" rev-parse HEAD) != "$orchestration_commit" \
   || $(git -C "$project_root" rev-parse 'HEAD^{tree}') != "$orchestration_tree" \
   || $(sha256sum "$script_path" | awk '{print $1}') != "$recipe_sha256" \
   || $(sha256sum "$inventory_helper" | awk '{print $1}') != "$inventory_helper_sha256" \
   || $(sha256sum "$libgcc_helper" | awk '{print $1}') != "$libgcc_helper_sha256" \
   || $(sha256sum "$glibc_helper" | awk '{print $1}') != "$glibc_helper_sha256" ]]; then
  echo "Complete-GCC orchestration changed while writing its receipt" >&2
  exit 95
fi
mapfile -t dependency_values_final < <(resolve_dependencies)
if (( ${#dependency_values_final[@]} != ${#dependency_values[@]} )); then
  echo "Authoritative complete-GCC dependency pair changed length" >&2
  exit 96
fi
for index in "${!dependency_values[@]}"; do
  [[ ${dependency_values_final[index]} == "${dependency_values[index]}" ]] || {
    echo "Authoritative complete-GCC dependency pair changed before publication" >&2
    exit 97
  }
done
validate_complete "$artifact_temporary/receipt.json" "$prefix_final"
selector_state=$("$script_path" --internal-python selector-state \
  "$tools_root" "$artifacts_root" "$libgcc_build_id" "$build_id")
if [[ $selector_state != base ]]; then
  echo "tools/current changed during complete-GCC final validation" >&2
  exit 98
fi

"$script_path" --internal-python validate-directories "$cajunos_root" \
  work work/toolchain tools artifacts logs sysroot "sysroot/$cohort_id"
if [[ $candidate_a != "$tools_root/.tmp-$build_id-a-$$" \
   || $candidate_b != "$tools_root/.tmp-$build_id-b-$$" \
   || -e $candidate_a || -L $candidate_a \
   || ! -d $candidate_b || -L $candidate_b \
   || ! -d $prefix_final || -L $prefix_final \
   || ! -d $temporary_root || -L $temporary_root \
   || ! -d $artifact_temporary || -L $artifact_temporary \
   || ! -f $artifact_temporary/receipt.json \
   || -L $artifact_temporary/receipt.json \
   || -e $build_final || -L $build_final \
   || -e $artifact_final || -L $artifact_final ]]; then
  echo "Complete-GCC publication paths changed after validation" >&2
  exit 99
fi

# Only reproducibility duplicates are discarded. Immutable build/artifact state
# is published first; tools/current advances atomically and last.
rm -rf -- "$candidate_b" "$overlay_a" "$overlay_b"
mv -T -- "$temporary_root" "$build_final"
mv -T -- "$artifact_temporary" "$artifact_final"
validate_complete "$receipt_final" "$prefix_final"
selector_result=$("$script_path" --internal-python selector-transition \
  "$tools_root" "$artifacts_root" "$libgcc_build_id" "$build_id")
validate_complete "$receipt_final" "$prefix_final"
selector_state=$("$script_path" --internal-python selector-state \
  "$tools_root" "$artifacts_root" "$libgcc_build_id" "$build_id")
if [[ $selector_state != this ]]; then
  echo "Published complete-GCC prefix is not selected" >&2
  exit 100
fi

build_succeeded=1
trap - EXIT
echo "CAJUNOS_GCC_COMPLETE_OK build_id=$build_id prefix=$prefix_final"
