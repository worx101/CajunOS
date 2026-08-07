#!/usr/bin/env bash
set -Eeuo pipefail
umask 022
export LC_ALL=C
export TZ=UTC
export PATH=/usr/bin:/bin

script_path=$(readlink -f -- "${BASH_SOURCE[0]}")
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
inventory_helper=$project_root/scripts/install-linux-headers.sh
gcc_helper=$project_root/scripts/build-gcc-complete.sh
libgcc_helper=$project_root/scripts/build-libgcc-bootstrap.sh
glibc_helper=$project_root/scripts/build-glibc-complete.sh

# Pure validators are intentionally available without a forge.  Unit tests use
# these entry points with byte-level fixtures; completed-build replay uses the
# same code against the published evidence.
if [[ ${1:-} == --internal-python ]]; then
  shift
  command_name=${1:-}
  shift || true
  case $command_name in
    inventory|ensure-directories|validate-directories)
      exec "$inventory_helper" --internal-python "$command_name" "$@"
      ;;
  esac
  exec python3 - "$command_name" "$@" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


command, *arguments = sys.argv[1:]
TARGET = "x86_64-cajunos-linux-gnu"


def fail(message):
    raise SystemExit(message)


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical_digest(value):
    data = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def load_json(path):
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream)


def write_text(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value if isinstance(value, bytes) else value.encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        path.chmod(0o644)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def regular_hashes(root):
    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        fail(f"hash root is not a real directory: {root}")
    values = {}
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        relative = path.relative_to(root).as_posix()
        if stat.S_ISDIR(metadata.st_mode):
            if path.is_symlink():
                fail(f"hash tree contains a symlinked directory: {relative}")
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            fail(f"hash tree contains an unsupported entry: {relative}")
        values[relative] = sha256(path)
    return values


def plain_inventory(root, include_root=True):
    root = Path(root)
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or root.is_symlink():
        fail("inventory root is not a real directory")
    entries = {}
    if include_root:
        entries["."] = {"type": "directory", "mode": f"{stat.S_IMODE(metadata.st_mode):04o}"}
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        relative = path.relative_to(root).as_posix()
        if stat.S_ISDIR(metadata.st_mode) and not path.is_symlink():
            entries[relative] = {"type": "directory", "mode": f"{stat.S_IMODE(metadata.st_mode):04o}"}
        elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            entries[relative] = {
                "type": "file", "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                "sha256": sha256(path),
            }
        else:
            fail(f"unsupported plain inventory entry: {relative}")
    return {"entries": entries, "digest": canonical_digest(entries)}


def parse_config(path):
    values = {}
    for number, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if raw.startswith("CONFIG_") and "=" in raw:
            key, value = raw.split("=", 1)
        else:
            match = re.fullmatch(r"# (CONFIG_[A-Z0-9_]+) is not set", raw)
            if not match:
                continue
            key, value = match.group(1), "n"
        if key in values:
            fail(f"duplicate kernel configuration key on line {number}: {key}")
        values[key] = value
    return values


def validate_config(path):
    values = parse_config(path)
    required_y = {
        "CONFIG_64BIT", "CONFIG_X86_64", "CONFIG_MMU", "CONFIG_PRINTK",
        "CONFIG_BUG", "CONFIG_TTY", "CONFIG_SERIAL_8250",
        "CONFIG_SERIAL_8250_CONSOLE", "CONFIG_SERIAL_CORE",
        "CONFIG_SERIAL_CORE_CONSOLE", "CONFIG_SERIAL_EARLYCON",
        "CONFIG_BLK_DEV_INITRD", "CONFIG_BINFMT_ELF", "CONFIG_DEVTMPFS",
        "CONFIG_DEVTMPFS_MOUNT", "CONFIG_MULTIUSER", "CONFIG_POSIX_TIMERS",
        "CONFIG_FUTEX", "CONFIG_RSEQ", "CONFIG_PROC_FS", "CONFIG_SYSFS",
        "CONFIG_SHMEM", "CONFIG_TMPFS", "CONFIG_CC_OPTIMIZE_FOR_SIZE",
        "CONFIG_KERNEL_GZIP", "CONFIG_SLUB", "CONFIG_SLUB_TINY",
        "CONFIG_DEBUG_INFO_NONE", "CONFIG_LTO_NONE",
        "CONFIG_RANDSTRUCT_NONE", "CONFIG_INIT_STACK_ALL_ZERO",
    }
    forbidden = {
        "CONFIG_MODULES", "CONFIG_SMP", "CONFIG_RANDOMIZE_BASE",
        "CONFIG_RANDSTRUCT", "CONFIG_GCC_PLUGINS", "CONFIG_WERROR",
        "CONFIG_DEBUG_INFO", "CONFIG_DEBUG_INFO_BTF", "CONFIG_EFI",
        "CONFIG_ACPI", "CONFIG_PCI", "CONFIG_BLOCK", "CONFIG_NET",
        "CONFIG_USB_SUPPORT", "CONFIG_DRM", "CONFIG_SOUND", "CONFIG_RUST",
        "CONFIG_CPU_MITIGATIONS", "CONFIG_RELOCATABLE",
        "CONFIG_RANDOMIZE_MEMORY", "CONFIG_RANDOMIZE_KSTACK_OFFSET",
        "CONFIG_STACKPROTECTOR", "CONFIG_FORTIFY_SOURCE",
        "CONFIG_HARDENED_USERCOPY", "CONFIG_SECURITY",
    }
    for key in sorted(required_y):
        if values.get(key) != "y":
            fail(f"required kernel configuration is not enabled: {key}")
    for key in sorted(forbidden):
        if values.get(key, "n") != "n":
            fail(f"forbidden kernel configuration is enabled: {key}")
    expected = {
        "CONFIG_LOCALVERSION": '"-cajunos"',
        "CONFIG_LOCALVERSION_AUTO": "n",
        "CONFIG_BUILD_SALT": '""',
        "CONFIG_SERIAL_8250_NR_UARTS": "1",
        "CONFIG_SERIAL_8250_RUNTIME_UARTS": "1",
        "CONFIG_INITRAMFS_SOURCE": '""',
    }
    for key, wanted in expected.items():
        if values.get(key) != wanted:
            fail(f"kernel configuration mismatch for {key}")
    modules = sorted(key for key, value in values.items() if value == "m")
    if modules:
        fail(f"kernel configuration contains modules: {', '.join(modules)}")
    enabled_decompressors = sorted(
        key for key, value in values.items() if key.startswith("CONFIG_RD_") and value != "n"
    )
    if enabled_decompressors:
        fail(f"kernel config enables initramfs decompressors: {enabled_decompressors}")
    print(json.dumps({"keys": len(values), "modules": 0}, sort_keys=True))


def parse_newc(path):
    data = Path(path).read_bytes()
    if not data or len(data) % 512:
        fail("initramfs archive is empty")
    offset = 0
    entries = []
    trailer_seen = False
    while offset < len(data):
        if len(data) - offset < 110:
            fail("truncated newc header")
        header = data[offset:offset + 110]
        if header[:6] != b"070701":
            fail("initramfs is not an uncompressed SVR4 newc archive")
        try:
            fields = [int(header[6 + i * 8:14 + i * 8], 16) for i in range(13)]
        except ValueError:
            fail("invalid hexadecimal field in newc header")
        (
            ino, mode, uid, gid, nlink, mtime, size, devmajor, devminor,
            rdevmajor, rdevminor, namesize, check,
        ) = fields
        if namesize < 1:
            fail("newc entry has an empty name field")
        offset += 110
        end_name = offset + namesize
        if end_name > len(data) or data[end_name - 1] != 0:
            fail("truncated or unterminated newc name")
        name_bytes = data[offset:end_name - 1]
        try:
            name = name_bytes.decode("ascii")
        except UnicodeDecodeError:
            fail("newc entry name is not ASCII")
        if not name or name.startswith("/") or ".." in Path(name).parts:
            fail(f"unsafe newc entry name: {name!r}")
        aligned_name = (end_name + 3) & ~3
        if any(data[end_name:aligned_name]):
            fail(f"nonzero newc name alignment padding: {name}")
        offset = aligned_name
        end_data = offset + size
        if end_data > len(data):
            fail(f"truncated newc payload: {name}")
        payload = data[offset:end_data]
        aligned_data = (end_data + 3) & ~3
        if any(data[end_data:aligned_data]):
            fail(f"nonzero newc data alignment padding: {name}")
        offset = aligned_data
        if name == "TRAILER!!!":
            trailer_shape = (
                mode, uid, gid, nlink, mtime, devmajor, devminor,
                rdevmajor, rdevminor, check,
            )
            expected_trailer = (0, 0, 0, 1, 0, 0, 0, 0, 0, 0)
            if size or ino or trailer_seen or trailer_shape != expected_trailer:
                fail("invalid or duplicate newc trailer")
            trailer_seen = True
            if any(data[offset:]):
                fail("nonzero bytes follow the newc trailer")
            if len(data) != ((offset + 511) // 512) * 512:
                fail("newc archive has noncanonical terminal zero padding")
            break
        if trailer_seen:
            fail("newc entry follows its trailer")
        entries.append({
            "name": name, "ino": ino, "mode": mode, "uid": uid,
            "gid": gid, "nlink": nlink, "mtime": mtime, "size": size,
            "devmajor": devmajor, "devminor": devminor,
            "rdevmajor": rdevmajor, "rdevminor": rdevminor,
            "check": check, "sha256": hashlib.sha256(payload).hexdigest(),
        })
    if not trailer_seen:
        fail("newc archive lacks TRAILER!!!")
    return entries


def validate_newc(path, init_path=None):
    entries = parse_newc(path)
    by_name = {entry["name"]: entry for entry in entries}
    expected_names = {"dev", "dev/console", "dev/null", "proc", "sys", "run", "init"}
    expected_order = ["dev", "dev/console", "dev/null", "proc", "sys", "run", "init"]
    if len(by_name) != len(entries) or set(by_name) != expected_names or [e["name"] for e in entries] != expected_order:
        fail("newc archive does not have the exact first-boot topology")
    if len({entry["ino"] for entry in entries}) != len(entries):
        fail("newc archive contains duplicate inode identities")
    if [entry["ino"] for entry in entries] != list(range(721, 728)):
        fail("newc archive has unexpected locked generator inode sequence")
    for name, wanted_mode in (
        ("dev", 0o755), ("proc", 0o555), ("sys", 0o555), ("run", 0o755)
    ):
        entry = by_name[name]
        if stat.S_IFMT(entry["mode"]) != stat.S_IFDIR or stat.S_IMODE(entry["mode"]) != wanted_mode:
            fail(f"newc directory has wrong type or mode: {name}")
        if entry["size"] != 0:
            fail(f"newc directory has data: {name}")
        if entry["rdevmajor"] or entry["rdevminor"]:
            fail(f"newc directory has a device identity: {name}")
    for name, mode, major, minor in (
        ("dev/console", 0o600, 5, 1), ("dev/null", 0o666, 1, 3)
    ):
        entry = by_name[name]
        if (
            stat.S_IFMT(entry["mode"]) != stat.S_IFCHR
            or stat.S_IMODE(entry["mode"]) != mode
            or (entry["rdevmajor"], entry["rdevminor"]) != (major, minor)
            or entry["size"] != 0
        ):
            fail(f"newc device contract failed: {name}")
    init = by_name["init"]
    if (
        stat.S_IFMT(init["mode"]) != stat.S_IFREG
        or stat.S_IMODE(init["mode"]) != 0o755
        or init["size"] == 0
        or init["rdevmajor"] or init["rdevminor"]
    ):
        fail("newc /init has wrong type, mode, or size")
    for entry in entries:
        if entry["uid"] != 0 or entry["gid"] != 0:
            fail(f"newc entry is not root-owned: {entry['name']}")
        if entry["mtime"] != 1785943083:
            fail(f"newc entry has wrong locked epoch: {entry['name']}")
        if entry["check"] != 0:
            fail(f"newc entry has a nonzero checksum field: {entry['name']}")
        wanted_links = 2 if stat.S_IFMT(entry["mode"]) == stat.S_IFDIR else 1
        if entry["nlink"] != wanted_links:
            fail(f"newc entry has wrong link count: {entry['name']}")
    if any((entry["devmajor"], entry["devminor"]) != (3, 1) for entry in entries):
        fail("newc entries have unexpected locked generator device identity")
    if init_path is not None and init["sha256"] != sha256(init_path):
        fail("newc /init payload does not match the sealed init executable")
    result = {"entries": entries, "digest": canonical_digest(entries)}
    print(json.dumps(result, indent=2, sort_keys=True))


def normalized_serial(path):
    data = Path(path).read_bytes()
    if b"\x00" in data or b"\x1b" in data:
        fail("serial transcript contains NUL or terminal escape bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        fail("serial transcript is not UTF-8")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def validate_serial(kind, path, release, build_id, output=None):
    if kind not in {"positive", "negative"}:
        fail("serial validation kind must be positive or negative")
    text = normalized_serial(path)
    lines = text.splitlines()
    if re.search(r"(^|[\[ ])(?:Kernel panic|Oops:|BUG:)", text, re.MULTILINE | re.IGNORECASE):
        fail("serial transcript contains a kernel failure")
    begin = "CAJUNOS_KERNEL_FIRST_BOOT_BEGIN"
    success = [
        begin,
        "CAJUNOS_KERNEL_FIRST_BOOT_PID1_OK",
        f"CAJUNOS_KERNEL_FIRST_BOOT_UNAME {release}",
        f"CAJUNOS_KERNEL_FIRST_BOOT_BUILD_ID {build_id}",
        "CAJUNOS_KERNEL_FIRST_BOOT_PROC_OK",
        "CAJUNOS_KERNEL_FIRST_BOOT_CMDLINE_OK",
        "CAJUNOS_KERNEL_FIRST_BOOT_OK",
    ]
    if kind == "positive":
        positions = []
        for marker in success:
            if lines.count(marker) != 1:
                fail(f"positive serial marker is missing or non-unique: {marker}")
            positions.append(lines.index(marker))
        if positions != sorted(positions):
            fail("positive serial markers are out of order")
        if any(line.startswith("CAJUNOS_KERNEL_FIRST_BOOT_FAIL ") for line in lines):
            fail("positive serial transcript contains a failure marker")
    else:
        prefix = success[:5]
        positions = []
        for marker in prefix:
            if lines.count(marker) != 1:
                fail(f"negative serial identity marker is missing or non-unique: {marker}")
            positions.append(lines.index(marker))
        if positions != sorted(positions):
            fail("negative serial identity markers are out of order")
        failures = [line for line in lines if line.startswith("CAJUNOS_KERNEL_FIRST_BOOT_FAIL ")]
        if failures != ["CAJUNOS_KERNEL_FIRST_BOOT_FAIL cmdline-token"]:
            fail("negative serial transcript lacks the exact fail-closed marker")
        if positions[-1] >= lines.index(failures[0]):
            fail("negative failure marker precedes completed identity evidence")
        for marker in success[5:]:
            if marker in lines:
                fail(f"negative serial transcript contains a success marker: {marker}")
    allowed = set(success)
    allowed.add("CAJUNOS_KERNEL_FIRST_BOOT_FAIL cmdline-token")
    unknown = [
        line for line in lines
        if line.startswith("CAJUNOS_KERNEL_FIRST_BOOT_") and line not in allowed
    ]
    if unknown:
        fail(f"serial transcript contains unknown first-boot markers: {unknown}")
    if output is not None:
        write_text(output, text)
    print(json.dumps({"kind": kind, "lines": len(lines)}, sort_keys=True))


def validate_init(path, readelf, nm, map_path, prefix, snapshot, binutils):
    path = Path(path)
    map_path = Path(map_path)
    prefix = Path(prefix)
    snapshot = Path(snapshot)
    binutils = Path(binutils)
    for value, mode, label in ((path, 0o755, "/init"), (map_path, 0o644, "link map")):
        try:
            metadata = value.lstat()
        except FileNotFoundError:
            fail(f"{label} does not exist")
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != mode:
            fail(f"{label} is not a plain mode-{mode:04o} single-linked file")
    for root, label in ((prefix, "tools prefix"), (snapshot, "glibc snapshot")):
        if not root.is_absolute() or os.path.normpath(root) != str(root):
            fail(f"unsafe exact {label}")
        if not root.is_dir() or root.is_symlink():
            fail(f"{label} is not a real directory")
    for tool, name in ((Path(readelf), f"{TARGET}-readelf"), (Path(nm), f"{TARGET}-nm")):
        expected = binutils / "bin" / name
        try:
            metadata = tool.lstat()
        except FileNotFoundError:
            fail(f"pinned ELF tool does not exist: {tool}")
        if tool != expected or not stat.S_ISREG(metadata.st_mode) or not os.access(tool, os.X_OK):
            fail(f"ELF validator is not the receipt-pinned Binutils tool: {tool}")
        try:
            tool.resolve(strict=True).relative_to(binutils.resolve(strict=True))
        except (FileNotFoundError, RuntimeError, ValueError):
            fail(f"pinned ELF tool escapes Binutils prefix: {tool}")
    header = subprocess.run(
        [readelf, "-hW", path], check=True, text=True,
        stdout=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    ).stdout
    program = subprocess.run(
        [readelf, "-lW", path], check=True, text=True,
        stdout=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    ).stdout
    dynamic = subprocess.run(
        [readelf, "-dW", path], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    ).stdout
    undefined = subprocess.run(
        [nm, "-u", path], check=True, text=True, stdout=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    ).stdout
    if (
        not re.search(r"Class:\s+ELF64", header)
        or not re.search(r"Data:\s+2's complement, little endian", header)
        or not re.search(r"Type:\s+EXEC ", header)
        or not re.search(r"Machine:\s+Advanced Micro Devices X86-64", header)
    ):
        fail("/init is not ELF64 x86-64")
    stack = next((line for line in program.splitlines() if "GNU_STACK" in line), "")
    if (
        "INTERP" in program or "NEEDED" in dynamic or "RPATH" in dynamic
        or "RUNPATH" in dynamic or undefined.strip() or not stack
        or re.search(r"\bRWE\b", stack)
    ):
        fail("/init is not fully static and resolved")
    map_text = map_path.read_text(encoding="utf-8", errors="strict")
    forbidden = (
        "/tmp/", "/work/", "/.tmp-", "/usr/lib/x86_64-linux-gnu",
        str(prefix.parent / "current"), str(snapshot.parent.parent / "current"),
    )
    if any(value in map_text for value in forbidden):
        fail("/init link map contains a disposable or selector path")
    normalized_text = map_text.replace(f"{prefix}/bin/../", f"{prefix}/")
    if f"{prefix}/" not in normalized_text or f"{snapshot}/" not in normalized_text:
        fail("/init link map does not bind both exact sealed roots")
    relative_loads = []
    for match in re.finditer(r"(?m)^\s*LOAD\s+(\S+)", map_text):
        reported = match.group(1)
        if not reported.startswith("/"):
            relative_loads.append(reported)
    if relative_loads != ["init.o"]:
        fail(f"/init link map relative inputs are not exact: {relative_loads}")
    allowed_lexical = (prefix, snapshot)
    allowed_real = (prefix.resolve(strict=True), snapshot.resolve(strict=True))
    absolute = set(re.findall(r"(?<![A-Za-z0-9_.-])(/[^\s()]+)", map_text))
    for value in absolute:
        reported = value.rstrip(",:")
        if reported == "/DISCARD/":
            continue
        lexical = Path(os.path.normpath(reported.replace(f"{prefix}/bin/../", f"{prefix}/")))
        if not any(lexical == root or root in lexical.parents for root in allowed_lexical):
            fail(f"/init link map is not lexically confined: {reported}")
        try:
            resolved = Path(reported).resolve(strict=True)
        except (FileNotFoundError, OSError, RuntimeError):
            fail(f"/init link map names an invalid absolute input: {value}")
        if not any(resolved == root or root in resolved.parents for root in allowed_real):
            fail(f"/init link map escaped sealed inputs: {value}")
    print(json.dumps({"sha256": sha256(path), "absolute_inputs": len(absolute)}, sort_keys=True))


if command == "validate-config":
    if len(arguments) != 1:
        fail("validate-config requires CONFIG")
    validate_config(arguments[0])
elif command == "validate-newc":
    if len(arguments) not in (1, 2):
        fail("validate-newc requires ARCHIVE [INIT]")
    validate_newc(*arguments)
elif command == "validate-serial":
    if len(arguments) not in (4, 5):
        fail("validate-serial requires KIND LOG RELEASE BUILD_ID [NORMALIZED]")
    validate_serial(*arguments)
elif command == "validate-init":
    if len(arguments) != 7:
        fail("validate-init requires INIT READELF NM MAP PREFIX SNAPSHOT BINUTILS")
    validate_init(*arguments)
elif command == "regular-hashes":
    if len(arguments) != 1:
        fail("regular-hashes requires ROOT")
    print(json.dumps(regular_hashes(arguments[0]), indent=2, sort_keys=True))
elif command == "compare-json":
    if len(arguments) != 2:
        fail("compare-json requires FIRST SECOND")
    if load_json(arguments[0]) != load_json(arguments[1]):
        fail("JSON evidence differs")
elif command == "validate-receipt":
    if len(arguments) < 2 or len(arguments[2:]) % 2:
        fail("validate-receipt requires RECEIPT ARTIFACT and key/value pairs")
    receipt_path, artifact = map(Path, arguments[:2])
    artifact_metadata = artifact.lstat()
    if not stat.S_ISDIR(artifact_metadata.st_mode) or artifact.is_symlink():
        fail("first-boot artifact root is not a real directory")
    metadata = receipt_path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o644:
        fail("first-boot receipt is not a plain mode-0644 single-linked file")
    receipt = load_json(receipt_path)
    root_entries = {path.name for path in artifact.iterdir()}
    if root_entries != {"boot", "configuration", "probe", "licenses", "receipt.json"}:
        fail("first-boot artifact has unexpected root topology")
    expected = dict(zip(arguments[2::2], arguments[3::2], strict=True))
    for key, wanted in expected.items():
        value = receipt
        for part in key.split("."):
            if not isinstance(value, dict) or part not in value:
                fail(f"first-boot receipt lacks {key}")
            value = value[part]
        if str(value) != wanted:
            fail(f"first-boot receipt mismatch for {key}")
    actual_hashes = {
        name: regular_hashes(artifact / name)
        for name in ("boot", "configuration", "probe", "licenses")
    }
    if receipt.get("outputs", {}).get("subtree_sha256") != actual_hashes:
        fail("first-boot receipt output hashes are invalid")
    first = load_json(artifact / "configuration/inventory-a.json")
    second = load_json(artifact / "configuration/inventory-b.json")
    include_root = isinstance(first.get("entries"), dict) and "." in first["entries"]
    live = plain_inventory(artifact / "boot", include_root=include_root)
    if first != second or live != first or receipt.get("reproducibility", {}).get("inventory") != first:
        fail("first-boot reproducibility inventory is invalid")
    for kind in ("positive", "negative"):
        raw = artifact / f"probe/{kind}.serial.raw"
        normalized = artifact / f"probe/{kind}.serial.normalized"
        if normalized.read_text(encoding="utf-8") != normalized_serial(raw):
            fail(f"stored {kind} normalized serial transcript is invalid")
elif command == "build-id":
    if len(arguments) < 1 or len(arguments[1:]) % 2:
        fail("build-id requires COMMIT and key/value pairs")
    commit = arguments[0]
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        fail("build-id source commit is unsafe")
    fields = dict(zip(arguments[1::2], arguments[2::2], strict=True))
    print(f"kernel-first-boot-{commit[:12]}-{canonical_digest(fields)[:16]}")
else:
    fail(f"unknown internal command: {command}")
PY
fi

for variable in \
  CC CXX CPP CFLAGS CXXFLAGS CPPFLAGS LDFLAGS \
  CFLAGS_FOR_TARGET CXXFLAGS_FOR_TARGET LDFLAGS_FOR_TARGET \
  LIBRARY_PATH CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH \
  PKG_CONFIG_PATH CONFIG_SITE LD_LIBRARY_PATH GCC_EXEC_PREFIX COMPILER_PATH \
  MAKEFLAGS MFLAGS KCONFIG_CONFIG ARCH CROSS_COMPILE HOSTCC HOSTCXX \
  HOSTCFLAGS HOSTCXXFLAGS HOSTLDFLAGS KBUILD_OUTPUT KBUILD_ABS_SRCTREE \
  KBUILD_BUILD_USER KBUILD_BUILD_HOST KBUILD_BUILD_VERSION \
  KBUILD_BUILD_TIMESTAMP KCONFIG_NOTIMESTAMP KCPPFLAGS KCFLAGS KAFLAGS \
  KRUSTFLAGS CFLAGS_KERNEL AFLAGS_KERNEL LDFLAGS_vmlinux LLVM LLVM_IAS \
  SUBARCH KBUILD_CFLAGS KBUILD_AFLAGS KBUILD_CPPFLAGS KBUILD_LDFLAGS \
  QEMU_AUDIO_DRV QEMU_AUDIO_TIMER_PERIOD QEMU_PATH QEMU_DATA_DIR; do
  unset "$variable"
done

cajunos_root=${CAJUNOS_ROOT:-/srv/cajunos}
target=${CAJUNOS_TARGET:-x86_64-cajunos-linux-gnu}
expected_user=${CAJUNOS_BUILD_USER:-cajunos}
requested_gcc_build_id=${CAJUNOS_GCC_COMPLETE_BUILD_ID:-}
requested_glibc_build_id=${CAJUNOS_GLIBC_COMPLETE_BUILD_ID:-}
config_source=$project_root/configs/x86_64-first-boot.config
init_source=$project_root/initramfs/first-boot-init.c
lock_file=$project_root/locks/bootstrap.lock.json
manifest_file=$project_root/manifests/bootstrap.json
kernel_kcflags='-Wno-constant-logical-operand'
kernel_prefix_map_template='-ffile-prefix-map=<linux-source>=/usr/src/linux -fmacro-prefix-map=<linux-source>=/usr/src/linux -ffile-prefix-map=<kernel-build>=/usr/src/linux-build -fmacro-prefix-map=<kernel-build>=/usr/src/linux-build'
init_cflags='-std=c11 -O2 -g0 -march=x86-64-v2 -mtune=generic -ffunction-sections -fdata-sections -fno-ident -fno-pie'
init_ldflags='-static -static-libgcc -no-pie -Wl,--gc-sections -Wl,--build-id=none -Wl,-z,noexecstack'
qemu_machine=pc-q35-10.0
qemu_cpu=Nehalem-v1
qemu_timeout=${CAJUNOS_QEMU_TIMEOUT:-60}

if [[ $(id -u) -eq 0 || $(id -un) != "$expected_user" ]]; then
  echo "Run this build as the unprivileged $expected_user account" >&2
  exit 70
fi
if [[ $target != x86_64-cajunos-linux-gnu ]]; then
  echo "This stage supports only x86_64-cajunos-linux-gnu" >&2
  exit 71
fi
if [[ ! $qemu_timeout =~ ^[1-9][0-9]*$ || $qemu_timeout -gt 600 ]]; then
  echo "CAJUNOS_QEMU_TIMEOUT must be an integer from 1 through 600" >&2
  exit 72
fi
for required_command in \
  awk cmp cp find flock git grep install make python3 qemu-system-x86_64 \
  readlink sha256sum tar tee timeout; do
  command -v "$required_command" >/dev/null || {
    echo "Missing required host command: $required_command" >&2
    exit 73
  }
done
for required_file in \
  "$inventory_helper" "$gcc_helper" "$libgcc_helper" "$glibc_helper" \
  "$config_source" "$init_source"; do
  [[ -f $required_file && ! -L $required_file ]] || {
    echo "Required frozen first-boot input is unavailable: $required_file" >&2
    exit 74
  }
done
[[ -x $inventory_helper && -x $gcc_helper && -x $libgcc_helper \
   && -x $glibc_helper ]] || {
  echo "A frozen dependency helper is not executable" >&2
  exit 74
}

"$project_root/scripts/fetch.py" validate --root "$cajunos_root" --json >/dev/null
cajunos_root=$(readlink -f -- "$cajunos_root")
exec 8>"$cajunos_root/upstream/.cajunos-source.lock"
if ! flock -n 8; then
  echo "Another CajunOS source operation or build owns the source lock" >&2
  exit 75
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
for wanted in ("linux", "gcc", "binutils", "glibc"):
    component = next(value for value in lock["components"] if value["name"] == wanted)
    print(component["commit"])
    print(component["tree"])
    print(component["repository"])
linux = next(value for value in manifest["components"] if value["name"] == "linux")
print(*linux["license_files"], sep="\n")
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
locked_glibc_commit=${lock_values[11]}
locked_glibc_tree=${lock_values[12]}
glibc_repository=${lock_values[13]}
license_paths=("${lock_values[@]:14}")

if [[ $source_authentication != authenticated ]]; then
  if [[ ${CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES:-} != 1 ]]; then
    echo "This source cohort contains recorded unauthenticated transports." >&2
    echo "Set CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES=1 after reviewing the lock." >&2
    exit 76
  fi
  echo "WARNING: explicitly accepting the lock's recorded unauthenticated transports" >&2
fi
if [[ -n $(git -C "$project_root" status --porcelain) ]]; then
  echo "Refusing an official build from a dirty CajunOS orchestration checkout" >&2
  exit 77
fi
orchestration_commit=$(git -C "$project_root" rev-parse HEAD)
orchestration_tree=$(git -C "$project_root" rev-parse 'HEAD^{tree}')
jobs=${CAJUNOS_JOBS:-6}
if [[ ! $jobs =~ ^[1-9][0-9]*$ ]]; then
  echo "CAJUNOS_JOBS must be a positive integer" >&2
  exit 78
fi
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git -C "$linux_source_dir" show -s --format=%ct "$locked_linux_commit")
kernel_version=$(make -s -C "$linux_source_dir" kernelversion)
if [[ ! $kernel_version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?$ ]]; then
  echo "Locked Linux reports an unsafe version: $kernel_version" >&2
  exit 79
fi

cohort_id=${source_set_digest#sha256:}
cohort_id=${cohort_id:0:16}
tools_root=$cajunos_root/tools
artifacts_root=$cajunos_root/artifacts
sysroot=$cajunos_root/sysroot/$cohort_id
work_root=$cajunos_root/work/kernel
logs_root=$cajunos_root/logs
"$script_path" --internal-python ensure-directories "$cajunos_root" \
  work work/kernel tools artifacts logs sysroot "sysroot/$cohort_id"

# Resolve and fully replay the exact active final-GCC/complete-glibc pair.  The
# final GCC receipt already binds the nested stage-one GCC, Binutils, Linux UAPI
# and bootstrap-libgcc chain; this resolver cross-checks that chain against the
# active glibc receipt and replays the Linux UAPI receipt directly as well.
resolve_dependencies() {
python3 - \
  "$inventory_helper" "$gcc_helper" "$libgcc_helper" "$glibc_helper" \
  "$tools_root" "$artifacts_root" "$sysroot" "$target" \
  "$source_set_digest" "$source_authentication" \
  "$locked_linux_commit" "$locked_linux_tree" "$linux_repository" \
  "$locked_gcc_commit" "$locked_gcc_tree" "$gcc_repository" \
  "$locked_glibc_commit" "$locked_glibc_tree" "$glibc_repository" \
  "$locked_binutils_commit" "$locked_binutils_tree" "$binutils_repository" \
  "$requested_gcc_build_id" "$requested_glibc_build_id" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

(
    inventory_helper, gcc_helper, libgcc_helper, glibc_helper, tools_value, artifacts_value,
    sysroot_value, target, source_set, source_auth, linux_commit, linux_tree,
    linux_repo, gcc_commit, gcc_tree, gcc_repo, glibc_commit, glibc_tree,
    glibc_repo, binutils_commit, binutils_tree, binutils_repo, requested_gcc,
    requested_glibc,
) = sys.argv[1:]
tools, artifacts, sysroot = map(Path, (tools_value, artifacts_value, sysroot_value))
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
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or path.is_symlink():
        fail(f"{label} is not a plain single-linked file")
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        fail(f"{label} is not a JSON object")
    return value


def run_helper(helper, *args):
    result = subprocess.run(
        [helper, "--internal-python", *map(str, args)], check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"},
    )
    if result.returncode:
        fail(result.stderr.strip() or f"dependency replay failed: {helper}")


def helper_json(helper, *args):
    result = subprocess.run(
        [helper, "--internal-python", *map(str, args)], check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"},
    )
    if result.returncode:
        fail(result.stderr.strip() or f"dependency inventory failed: {helper}")
    return json.loads(result.stdout)


def selected_id(link, pattern, label):
    if not link.is_symlink():
        fail(f"{label} is not a managed symlink")
    value = os.readlink(link)
    match = re.fullmatch(pattern, value)
    if not match:
        fail(f"{label} has an unsafe target")
    return match.group(1)


tools_id = selected_id(tools / "current", r"([A-Za-z0-9][A-Za-z0-9._-]{0,127})", "tools/current")
if requested_gcc and requested_gcc != tools_id:
    fail("requested complete GCC is not the exact active tools prefix")
tools_prefix = tools / tools_id
tools_receipt_path = artifacts / tools_id / "receipt.json"
tools_receipt = load_plain(tools_receipt_path, "complete GCC receipt")
if (
    tools_receipt.get("schema") != 1
    or tools_receipt.get("component") != "gcc"
    or tools_receipt.get("stage") != "complete"
    or tools_receipt.get("build_id") != tools_id
    or tools_receipt.get("source_commit") != gcc_commit
    or tools_receipt.get("source_tree") != gcc_tree
    or tools_receipt.get("source_repository") != gcc_repo
    or tools_receipt.get("source_set_digest") != source_set
    or tools_receipt.get("source_authentication") != source_auth
    or tools_receipt.get("target") != target
    or tools_receipt.get("prefix") != str(tools_prefix)
):
    fail("active tools receipt is not the locked complete GCC")
gcc_version = str(tools_receipt.get("gcc_version", ""))
base_prefix = Path(str(tools_receipt.get("base_prefix", "")))
run_helper(
    gcc_helper, "validate-completed", tools_receipt_path, tools_prefix,
    base_prefix, tools, target, gcc_version,
    "schema", 1, "component", "gcc", "stage", "complete",
    "build_id", tools_id, "source_commit", gcc_commit, "source_tree",
    gcc_tree, "source_repository", gcc_repo, "source_set_digest",
    source_set, "source_authentication", source_auth, "target", target,
    "prefix", tools_prefix, "base_prefix", base_prefix,
)

dependencies = tools_receipt.get("dependencies", {})
libgcc_value = dependencies.get("libgcc", {})
libgcc_id = str(libgcc_value.get("build_id", ""))
libgcc_prefix = Path(str(libgcc_value.get("prefix", "")))
libgcc_receipt_path = Path(str(libgcc_value.get("receipt", "")))
if (
    not safe_id.fullmatch(libgcc_id)
    or libgcc_prefix != base_prefix
    or libgcc_prefix != tools / libgcc_id
    or libgcc_receipt_path != artifacts / libgcc_id / "receipt.json"
    or sha256(libgcc_receipt_path) != libgcc_value.get("receipt_sha256")
    or libgcc_value.get("gcc_version") != gcc_version
):
    fail("complete GCC has an invalid bootstrap-libgcc dependency")
libgcc_receipt = load_plain(libgcc_receipt_path, "bootstrap libgcc receipt")
libgcc_base = Path(str(libgcc_receipt.get("base_prefix", "")))
if (
    libgcc_value.get("prefix_digest") != libgcc_receipt.get("result_prefix_digest")
    or libgcc_receipt.get("gcc_version") != gcc_version
    or libgcc_receipt.get("source_commit") != gcc_commit
    or libgcc_receipt.get("source_tree") != gcc_tree
    or libgcc_receipt.get("source_repository") != gcc_repo
):
    fail("bootstrap libgcc wrapper disagrees with its receipt")
run_helper(
    libgcc_helper, "validate-completed", libgcc_receipt_path, libgcc_prefix,
    libgcc_base, tools, target, gcc_version, "schema", 1, "component", "gcc",
    "stage", "libgcc-bootstrap", "build_id", libgcc_id, "source_commit",
    gcc_commit, "source_tree", gcc_tree, "source_repository", gcc_repo,
    "source_set_digest", source_set, "source_authentication", source_auth,
    "target", target, "prefix", libgcc_prefix, "base_prefix", libgcc_base,
)

stage1_gcc_value = dependencies.get("gcc", {})
stage1_gcc_id = str(stage1_gcc_value.get("build_id", ""))
stage1_gcc_prefix = Path(str(stage1_gcc_value.get("prefix", "")))
stage1_gcc_receipt_path = Path(str(stage1_gcc_value.get("receipt", "")))
if (
    not safe_id.fullmatch(stage1_gcc_id)
    or stage1_gcc_prefix != tools / stage1_gcc_id
    or stage1_gcc_receipt_path != artifacts / stage1_gcc_id / "receipt.json"
    or sha256(stage1_gcc_receipt_path) != stage1_gcc_value.get("receipt_sha256")
    or stage1_gcc_value.get("source_commit") != gcc_commit
    or stage1_gcc_value.get("source_tree") != gcc_tree
    or stage1_gcc_value.get("source_repository") != gcc_repo
):
    fail("complete GCC has an invalid stage-one GCC dependency")
stage1_gcc_receipt = load_plain(stage1_gcc_receipt_path, "stage-one GCC receipt")
if (
    stage1_gcc_receipt.get("schema") != 1
    or stage1_gcc_receipt.get("component") != "gcc"
    or stage1_gcc_receipt.get("stage") != "stage1"
    or stage1_gcc_receipt.get("build_id") != stage1_gcc_id
    or stage1_gcc_receipt.get("source_set_digest") != source_set
    or stage1_gcc_receipt.get("source_authentication") != source_auth
    or stage1_gcc_receipt.get("source_commit") != gcc_commit
    or stage1_gcc_receipt.get("source_tree") != gcc_tree
    or stage1_gcc_receipt.get("source_repository") != gcc_repo
    or stage1_gcc_receipt.get("target") != target
    or stage1_gcc_receipt.get("prefix") != str(stage1_gcc_prefix)
    or helper_json(inventory_helper, "dependency-inventory", stage1_gcc_prefix, tools)
        != stage1_gcc_receipt.get("installed_entries")
):
    fail("stage-one GCC failed receipt and live-inventory replay")
if (
    libgcc_base != stage1_gcc_prefix
    or libgcc_receipt.get("base_prefix") != str(stage1_gcc_prefix)
    or libgcc_receipt.get("base_build_id") != stage1_gcc_id
    or libgcc_receipt.get("dependencies", {}).get("gcc", {}).get("receipt_sha256")
        != stage1_gcc_value.get("receipt_sha256")
):
    fail("bootstrap libgcc and complete GCC disagree on stage-one GCC")

glibc_id = selected_id(
    sysroot / "current",
    r"snapshots/([A-Za-z0-9][A-Za-z0-9._-]{0,127})",
    "cohort sysroot current",
)
if requested_glibc and requested_glibc != glibc_id:
    fail("requested complete glibc is not the exact active cohort snapshot")
snapshot = sysroot / "snapshots" / glibc_id
glibc_receipt_path = artifacts / glibc_id / "receipt.json"
glibc_receipt = load_plain(glibc_receipt_path, "complete glibc receipt")
base_snapshot = Path(str(glibc_receipt.get("base_snapshot", "")))
run_helper(
    glibc_helper, "validate-completed", glibc_receipt_path, snapshot,
    base_snapshot, "schema", 1, "component", "glibc", "stage", "complete",
    "build_id", glibc_id, "source_commit", glibc_commit, "source_tree",
    glibc_tree, "source_repository", glibc_repo, "source_set_digest",
    source_set, "source_authentication", source_auth, "target", target,
    "snapshot", snapshot, "functional_libc", "present",
)
if tools_receipt.get("sysroot_snapshot") != str(snapshot):
    fail("complete GCC was not built against the active complete glibc snapshot")
gcc_glibc = tools_receipt.get("dependencies", {}).get("glibc", {})
if (
    gcc_glibc.get("build_id") != glibc_id
    or gcc_glibc.get("snapshot") != str(snapshot)
    or gcc_glibc.get("receipt_sha256") != sha256(glibc_receipt_path)
    or gcc_glibc.get("snapshot_digest") != glibc_receipt.get("result_snapshot_digest")
):
    fail("complete GCC and complete glibc dependency bindings disagree")

linux_value = tools_receipt.get("dependencies", {}).get("linux", {})
linux_id = str(linux_value.get("build_id", ""))
linux_snapshot = Path(str(linux_value.get("snapshot", "")))
linux_receipt_path = Path(str(linux_value.get("receipt", "")))
if (
    not safe_id.fullmatch(linux_id)
    or linux_snapshot != sysroot / "snapshots" / linux_id
    or linux_receipt_path != artifacts / linux_id / "receipt.json"
    or sha256(linux_receipt_path) != linux_value.get("receipt_sha256")
):
    fail("complete GCC has an invalid Linux UAPI dependency")
run_helper(
    inventory_helper, "validate-completed", linux_receipt_path,
    linux_snapshot, "schema", 1, "component", "linux", "stage",
    "uapi-headers", "build_id", linux_id, "source_commit", linux_commit,
    "source_tree", linux_tree, "source_repository", linux_repo,
    "source_set_digest", source_set, "source_authentication", source_auth,
    "target", target, "snapshot", linux_snapshot,
)
linux_receipt = load_plain(linux_receipt_path, "Linux UAPI receipt")
if (
    linux_value.get("snapshot_digest") != linux_receipt.get("result_snapshot_digest")
    or linux_receipt.get("snapshot") != str(linux_snapshot)
):
    fail("Linux UAPI wrapper disagrees with its fully replayed receipt")

binutils_value = dependencies.get("binutils", {})
binutils_id = str(binutils_value.get("build_id", ""))
binutils_prefix = Path(str(binutils_value.get("prefix", "")))
binutils_receipt_path = Path(str(binutils_value.get("receipt", "")))
if (
    not safe_id.fullmatch(binutils_id)
    or binutils_prefix != tools / binutils_id
    or binutils_receipt_path != artifacts / binutils_id / "receipt.json"
    or sha256(binutils_receipt_path) != binutils_value.get("receipt_sha256")
    or binutils_value.get("source_commit") != binutils_commit
    or binutils_value.get("source_tree") != binutils_tree
    or binutils_value.get("source_repository") != binutils_repo
):
    fail("complete GCC has an invalid locked Binutils dependency")
binutils_receipt = load_plain(binutils_receipt_path, "stage-one Binutils receipt")
if (
    binutils_receipt.get("schema") != 1
    or binutils_receipt.get("component") != "binutils"
    or binutils_receipt.get("stage") != "stage1"
    or binutils_receipt.get("build_id") != binutils_id
    or binutils_receipt.get("source_commit") != binutils_commit
    or binutils_receipt.get("source_tree") != binutils_tree
    or binutils_receipt.get("source_repository") is not None
    or binutils_receipt.get("source_set_digest") != source_set
    or binutils_receipt.get("source_authentication") != source_auth
    or binutils_receipt.get("target") != target
    or binutils_receipt.get("prefix") != str(binutils_prefix)
    or helper_json(inventory_helper, "dependency-inventory", binutils_prefix, tools)
        != binutils_receipt.get("installed_entries")
    or libgcc_receipt.get("dependencies", {}).get("binutils", {}).get("receipt_sha256")
        != binutils_value.get("receipt_sha256")
):
    fail("stage-one Binutils failed nested receipt and live-inventory replay")

for name, value in (("gcc", stage1_gcc_value), ("binutils", binutils_value), ("linux", linux_value), ("libgcc", libgcc_value)):
    nested = glibc_receipt.get("dependencies", {}).get(name, {})
    if (
        nested.get("build_id") != value.get("build_id")
        or nested.get("receipt_sha256") != value.get("receipt_sha256")
    ):
        fail(f"complete glibc and complete GCC disagree on nested {name}")

print(tools_id)
print(tools_prefix)
print(tools_receipt_path)
print(sha256(tools_receipt_path))
print(tools_receipt["result_prefix_digest"])
print(gcc_version)
print(glibc_id)
print(snapshot)
print(glibc_receipt_path)
print(sha256(glibc_receipt_path))
print(glibc_receipt["result_snapshot_digest"])
print(binutils_id)
print(binutils_prefix)
print(binutils_receipt_path)
print(sha256(binutils_receipt_path))
print(linux_id)
print(linux_snapshot)
print(linux_receipt_path)
print(sha256(linux_receipt_path))
print(linux_value["snapshot_digest"])
print(libgcc_id)
print(libgcc_prefix)
print(libgcc_receipt_path)
print(sha256(libgcc_receipt_path))
print(stage1_gcc_id)
print(stage1_gcc_prefix)
print(stage1_gcc_receipt_path)
print(sha256(stage1_gcc_receipt_path))
PY
}

mapfile -t dependency_values < <(resolve_dependencies)
if (( ${#dependency_values[@]} != 28 )); then
  echo "Authoritative kernel dependency resolver returned incomplete state" >&2
  exit 80
fi
gcc_build_id=${dependency_values[0]}
gcc_prefix=${dependency_values[1]}
gcc_receipt=${dependency_values[2]}
gcc_receipt_sha256=${dependency_values[3]}
gcc_prefix_digest=${dependency_values[4]}
gcc_version=${dependency_values[5]}
glibc_build_id=${dependency_values[6]}
glibc_snapshot=${dependency_values[7]}
glibc_receipt=${dependency_values[8]}
glibc_receipt_sha256=${dependency_values[9]}
glibc_snapshot_digest=${dependency_values[10]}
binutils_build_id=${dependency_values[11]}
binutils_prefix=${dependency_values[12]}
binutils_receipt=${dependency_values[13]}
binutils_receipt_sha256=${dependency_values[14]}
linux_uapi_build_id=${dependency_values[15]}
linux_uapi_snapshot=${dependency_values[16]}
linux_uapi_receipt=${dependency_values[17]}
linux_uapi_receipt_sha256=${dependency_values[18]}
linux_uapi_snapshot_digest=${dependency_values[19]}
libgcc_build_id=${dependency_values[20]}
libgcc_prefix=${dependency_values[21]}
libgcc_receipt=${dependency_values[22]}
libgcc_receipt_sha256=${dependency_values[23]}
stage1_gcc_build_id=${dependency_values[24]}
stage1_gcc_prefix=${dependency_values[25]}
stage1_gcc_receipt=${dependency_values[26]}
stage1_gcc_receipt_sha256=${dependency_values[27]}
initial_tools_selector=$(readlink -- "$tools_root/current")
initial_sysroot_selector=$(readlink -- "$sysroot/current")

recipe_sha256=$(sha256sum "$script_path" | awk '{print $1}')
inventory_helper_sha256=$(sha256sum "$inventory_helper" | awk '{print $1}')
gcc_helper_sha256=$(sha256sum "$gcc_helper" | awk '{print $1}')
libgcc_helper_sha256=$(sha256sum "$libgcc_helper" | awk '{print $1}')
glibc_helper_sha256=$(sha256sum "$glibc_helper" | awk '{print $1}')
config_sha256=$(sha256sum "$config_source" | awk '{print $1}')
init_source_sha256=$(sha256sum "$init_source" | awk '{print $1}')
qemu_path=$(readlink -f -- "$(command -v qemu-system-x86_64)")
qemu_sha256=$(sha256sum "$qemu_path" | awk '{print $1}')
qemu_version=$("$qemu_path" --version | sed -n '1p')
qemu_bios=/usr/share/seabios/bios-256k.bin
qemu_linuxboot=/usr/share/qemu/linuxboot_dma.bin
qemu_kvmvapic=/usr/share/qemu/kvmvapic.bin
for qemu_input in "$qemu_bios" "$qemu_linuxboot" "$qemu_kvmvapic"; do
  [[ -f $qemu_input && ! -L $qemu_input ]] || {
    echo "Pinned QEMU guest-visible input is not a real file: $qemu_input" >&2
    exit 82
  }
done
qemu_bios_sha256=$(sha256sum "$qemu_bios" | awk '{print $1}')
qemu_linuxboot_sha256=$(sha256sum "$qemu_linuxboot" | awk '{print $1}')
qemu_kvmvapic_sha256=$(sha256sum "$qemu_kvmvapic" | awk '{print $1}')
host_cc=/usr/bin/gcc
host_cxx=/usr/bin/g++
host_cc_resolved=$(readlink -f -- "$host_cc")
host_cxx_resolved=$(readlink -f -- "$host_cxx")
for host_tool in "$host_cc_resolved" "$host_cxx_resolved"; do
  [[ -f $host_tool && ! -L $host_tool && -x $host_tool ]] || {
    echo "Pinned kernel host compiler is not a real executable: $host_tool" >&2
    exit 82
  }
done
host_cc_sha256=$(sha256sum "$host_cc_resolved" | awk '{print $1}')
host_cxx_sha256=$(sha256sum "$host_cxx_resolved" | awk '{print $1}')
host_cc_version=$("$host_cc" --version | sed -n '1p')
host_cxx_version=$("$host_cxx" --version | sed -n '1p')
qemu_args=(
  -no-user-config -nodefaults
  -machine "$qemu_machine,accel=tcg"
  -cpu "$qemu_cpu"
  -bios "$qemu_bios"
  -m 256M -smp 1
  -display none -monitor none -nic none
  -chardev stdio,id=serial0,signal=off,mux=off
  -device isa-serial,chardev=serial0,iobase=0x3f8,irq=4
  -no-reboot
)
positive_cmdline='console=ttyS0,115200 earlycon=uart8250,io,0x3f8,115200n8 rdinit=/init panic=-1 cajunos.first_boot=1'
negative_cmdline='console=ttyS0,115200 earlycon=uart8250,io,0x3f8,115200n8 rdinit=/init panic=-1 cajunos.first_boot=0'
contract_digest=$(
  printf '%s\0' \
    "$kernel_kcflags" "$kernel_prefix_map_template" \
    "$init_cflags" "$init_ldflags" \
    "$qemu_path" "$qemu_sha256" "$qemu_version" \
    "$qemu_bios" "$qemu_bios_sha256" \
    "$qemu_linuxboot" "$qemu_linuxboot_sha256" \
    "$qemu_kvmvapic" "$qemu_kvmvapic_sha256" \
    "$host_cc" "$host_cc_resolved" "$host_cc_sha256" "$host_cc_version" \
    "$host_cxx" "$host_cxx_resolved" "$host_cxx_sha256" "$host_cxx_version" \
    "${qemu_args[@]}" "$positive_cmdline" "$negative_cmdline" |
    sha256sum | awk '{print $1}'
)
build_id=$("$script_path" --internal-python build-id "$locked_linux_commit" \
  source_set_digest "$source_set_digest" \
  source_tree "$locked_linux_tree" \
  orchestration_commit "$orchestration_commit" \
  orchestration_tree "$orchestration_tree" \
  recipe_sha256 "$recipe_sha256" \
  inventory_helper_sha256 "$inventory_helper_sha256" \
  gcc_helper_sha256 "$gcc_helper_sha256" \
  libgcc_helper_sha256 "$libgcc_helper_sha256" \
  glibc_helper_sha256 "$glibc_helper_sha256" \
  config_sha256 "$config_sha256" init_source_sha256 "$init_source_sha256" \
  gcc_receipt_sha256 "$gcc_receipt_sha256" \
  libgcc_receipt_sha256 "$libgcc_receipt_sha256" \
  stage1_gcc_receipt_sha256 "$stage1_gcc_receipt_sha256" \
  glibc_receipt_sha256 "$glibc_receipt_sha256" \
  linux_uapi_receipt_sha256 "$linux_uapi_receipt_sha256" \
  binutils_receipt_sha256 "$binutils_receipt_sha256" \
  gcc_prefix_digest "$gcc_prefix_digest" \
  glibc_snapshot_digest "$glibc_snapshot_digest" \
  contract_digest "$contract_digest")
expected_release=$kernel_version-cajunos+

run_id=${CAJUNOS_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
if [[ ! $run_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "Unsafe CAJUNOS_RUN_ID: $run_id" >&2
  exit 81
fi
build_final=$work_root/$build_id
artifact_final=$artifacts_root/$build_id
receipt_final=$artifact_final/receipt.json
log_dir=$logs_root/$run_id
log_file=$log_dir/kernel-first-boot.log
temporary_root=$work_root/.tmp-$build_id-$$
build_a=$temporary_root/build-a
build_b=$temporary_root/build-b
candidate_a=$temporary_root/candidate-a
candidate_b=$temporary_root/candidate-b
artifact_temporary=$artifacts_root/.tmp-$build_id-$$
failed_root=$work_root/.failed-$build_id-$$
failed_artifact=$artifacts_root/.failed-$build_id-$$
gcc_driver=$gcc_prefix/bin/$target-gcc
readelf_driver=$binutils_prefix/bin/$target-readelf
nm_driver=$binutils_prefix/bin/$target-nm

[[ -x $gcc_driver && -x $readelf_driver && -x $nm_driver ]] || {
  echo "Sealed complete toolchain lacks required compiler or ELF tools" >&2
  exit 82
}
"$script_path" --internal-python validate-config "$config_source" >/dev/null

validate_mutable_inputs() {
  "$project_root/scripts/fetch.py" validate --root "$cajunos_root" >/dev/null
  [[ -f $qemu_path && ! -L $qemu_path \
     && -f $qemu_bios && ! -L $qemu_bios \
     && -f $qemu_linuxboot && ! -L $qemu_linuxboot \
     && -f $qemu_kvmvapic && ! -L $qemu_kvmvapic \
     && -f $host_cc_resolved && ! -L $host_cc_resolved \
     && -f $host_cxx_resolved && ! -L $host_cxx_resolved \
     && -z $(git -C "$project_root" status --porcelain) \
     && $(git -C "$project_root" rev-parse HEAD) == "$orchestration_commit" \
     && $(git -C "$project_root" rev-parse 'HEAD^{tree}') == "$orchestration_tree" \
     && $(sha256sum "$script_path" | awk '{print $1}') == "$recipe_sha256" \
     && $(sha256sum "$inventory_helper" | awk '{print $1}') == "$inventory_helper_sha256" \
     && $(sha256sum "$gcc_helper" | awk '{print $1}') == "$gcc_helper_sha256" \
     && $(sha256sum "$libgcc_helper" | awk '{print $1}') == "$libgcc_helper_sha256" \
     && $(sha256sum "$glibc_helper" | awk '{print $1}') == "$glibc_helper_sha256" \
     && $(sha256sum "$config_source" | awk '{print $1}') == "$config_sha256" \
     && $(sha256sum "$init_source" | awk '{print $1}') == "$init_source_sha256" \
     && $(sha256sum "$qemu_path" | awk '{print $1}') == "$qemu_sha256" \
     && $("$qemu_path" --version | sed -n '1p') == "$qemu_version" \
     && $(sha256sum "$qemu_bios" | awk '{print $1}') == "$qemu_bios_sha256" \
     && $(sha256sum "$qemu_linuxboot" | awk '{print $1}') == "$qemu_linuxboot_sha256" \
     && $(sha256sum "$qemu_kvmvapic" | awk '{print $1}') == "$qemu_kvmvapic_sha256" \
     && $(readlink -f -- "$host_cc") == "$host_cc_resolved" \
     && $(readlink -f -- "$host_cxx") == "$host_cxx_resolved" \
     && $(sha256sum "$host_cc_resolved" | awk '{print $1}') == "$host_cc_sha256" \
     && $(sha256sum "$host_cxx_resolved" | awk '{print $1}') == "$host_cxx_sha256" \
     && $("$host_cc" --version | sed -n '1p') == "$host_cc_version" \
     && $("$host_cxx" --version | sed -n '1p') == "$host_cxx_version" ]]
}

run_qemu() {
  local kind=$1 boot_root=$2 raw_log=$3 normalized_log=$4
  local cmdline=$positive_cmdline
  [[ $kind == positive ]] || cmdline=$negative_cmdline
  env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC \
    /usr/bin/timeout --signal=TERM --kill-after=5 "$qemu_timeout" \
    "$qemu_path" "${qemu_args[@]}" \
      -kernel "$boot_root/bzImage" \
      -initrd "$boot_root/initramfs.cpio" \
      -append "$cmdline" </dev/null >"$raw_log" 2>&1
  "$script_path" --internal-python validate-serial \
    "$kind" "$raw_log" "$expected_release" "$build_id" "$normalized_log"
}

validate_complete() {
  [[ $(readlink -- "$tools_root/current") == "$initial_tools_selector" \
     && $(readlink -- "$sysroot/current") == "$initial_sysroot_selector" ]] || {
    echo "Managed selector changed before completed first-boot replay" >&2
    return 1
  }
  validate_mutable_inputs || {
    echo "Completed first-boot mutable input closure failed" >&2
    return 1
  }
  "$script_path" --internal-python validate-receipt \
    "$receipt_final" "$artifact_final" \
    schema 1 component linux stage first-boot build_id "$build_id" \
    source_commit "$locked_linux_commit" source_tree "$locked_linux_tree" \
    source_repository "$linux_repository" source_set_digest "$source_set_digest" \
    source_authentication "$source_authentication" \
    source_date_epoch "$SOURCE_DATE_EPOCH" target "$target" \
    kernel.version "$kernel_version" kernel.release "$expected_release" \
    diagnostic_only True deployable False \
    security_contract.cpu_mitigations disabled \
    security_contract.kaslr disabled \
    security_contract.stack_protector disabled \
    security_contract.fortify_source disabled \
    security_contract.security_framework disabled \
    security_contract.init_stack_all_zero enabled \
    orchestration_commit "$orchestration_commit" \
    orchestration_tree "$orchestration_tree" recipe_sha256 "$recipe_sha256" \
    inventory_helper_sha256 "$inventory_helper_sha256" \
    gcc_helper_sha256 "$gcc_helper_sha256" \
    libgcc_helper_sha256 "$libgcc_helper_sha256" \
    glibc_helper_sha256 "$glibc_helper_sha256" \
    config_sha256 "$config_sha256" init_source_sha256 "$init_source_sha256" \
    build_contract.independent_builds 2 \
    build_contract.kernel_kcflags "$kernel_kcflags" \
    build_contract.kernel_prefix_map_template "$kernel_prefix_map_template" \
    build_contract.init_cflags "$init_cflags" \
    build_contract.init_ldflags "$init_ldflags" \
    build_contract.contract_digest "$contract_digest" \
    build_contract.initramfs_format raw-svr4-newc \
    build_contract.initramfs_epoch "$SOURCE_DATE_EPOCH" \
    dependencies.gcc.build_id "$gcc_build_id" \
    dependencies.gcc.prefix "$gcc_prefix" \
    dependencies.gcc.prefix_digest "$gcc_prefix_digest" \
    dependencies.gcc.receipt "$gcc_receipt" \
    dependencies.gcc.receipt_sha256 "$gcc_receipt_sha256" \
    dependencies.libgcc.build_id "$libgcc_build_id" \
    dependencies.libgcc.prefix "$libgcc_prefix" \
    dependencies.libgcc.receipt "$libgcc_receipt" \
    dependencies.libgcc.receipt_sha256 "$libgcc_receipt_sha256" \
    dependencies.stage1_gcc.build_id "$stage1_gcc_build_id" \
    dependencies.stage1_gcc.prefix "$stage1_gcc_prefix" \
    dependencies.stage1_gcc.receipt "$stage1_gcc_receipt" \
    dependencies.stage1_gcc.receipt_sha256 "$stage1_gcc_receipt_sha256" \
    dependencies.glibc.build_id "$glibc_build_id" \
    dependencies.glibc.snapshot "$glibc_snapshot" \
    dependencies.glibc.snapshot_digest "$glibc_snapshot_digest" \
    dependencies.glibc.receipt "$glibc_receipt" \
    dependencies.glibc.receipt_sha256 "$glibc_receipt_sha256" \
    dependencies.binutils.build_id "$binutils_build_id" \
    dependencies.binutils.prefix "$binutils_prefix" \
    dependencies.binutils.receipt "$binutils_receipt" \
    dependencies.binutils.receipt_sha256 "$binutils_receipt_sha256" \
    dependencies.linux_uapi.build_id "$linux_uapi_build_id" \
    dependencies.linux_uapi.snapshot "$linux_uapi_snapshot" \
    dependencies.linux_uapi.snapshot_digest "$linux_uapi_snapshot_digest" \
    dependencies.linux_uapi.receipt "$linux_uapi_receipt" \
    dependencies.linux_uapi.receipt_sha256 "$linux_uapi_receipt_sha256" \
    qemu.path "$qemu_path" qemu.sha256 "$qemu_sha256" \
    qemu.version "$qemu_version" qemu.machine "$qemu_machine" \
    qemu.accelerator tcg qemu.cpu "$qemu_cpu" \
    qemu.firmware.bios.path "$qemu_bios" \
    qemu.firmware.bios.sha256 "$qemu_bios_sha256" \
    qemu.firmware.linuxboot_dma.path "$qemu_linuxboot" \
    qemu.firmware.linuxboot_dma.sha256 "$qemu_linuxboot_sha256" \
    qemu.firmware.kvmvapic.path "$qemu_kvmvapic" \
    qemu.firmware.kvmvapic.sha256 "$qemu_kvmvapic_sha256" \
    qemu.positive_cmdline "$positive_cmdline" \
    qemu.negative_cmdline "$negative_cmdline" \
    qemu.diskless True qemu.network False \
    reproducibility.independent_builds 2 \
    reproducibility.inventory_schema \
      paths-types-modes-sha256-symlink-targets-v1 \
    reproducibility.identical True reproducibility.gcc_unchanged True \
    reproducibility.glibc_unchanged True \
    host.kernel_cc.path "$host_cc" \
    host.kernel_cc.resolved_path "$host_cc_resolved" \
    host.kernel_cc.sha256 "$host_cc_sha256" \
    host.kernel_cc.version "$host_cc_version" \
    host.kernel_cxx.path "$host_cxx" \
    host.kernel_cxx.resolved_path "$host_cxx_resolved" \
    host.kernel_cxx.sha256 "$host_cxx_sha256" \
    host.kernel_cxx.version "$host_cxx_version" \
    selectors_modified False
  cmp -s "$artifact_final/boot/config" "$config_source" || {
    echo "Completed first-boot kernel config differs from frozen config" >&2
    return 1
  }
  "$script_path" --internal-python validate-config \
    "$artifact_final/boot/config" >/dev/null
  "$script_path" --internal-python validate-newc \
    "$artifact_final/boot/initramfs.cpio" "$artifact_final/boot/init" >/dev/null
  "$script_path" --internal-python validate-init \
    "$artifact_final/boot/init" "$readelf_driver" "$nm_driver" \
    "$artifact_final/boot/init.map" "$gcc_prefix" "$glibc_snapshot" \
    "$binutils_prefix" >/dev/null
  "$script_path" --internal-python validate-serial positive \
    "$artifact_final/probe/positive.serial.raw" "$expected_release" "$build_id" >/dev/null
  "$script_path" --internal-python validate-serial negative \
    "$artifact_final/probe/negative.serial.raw" "$expected_release" "$build_id" >/dev/null
  local replay_root=$work_root/.replay-$build_id-$$
  [[ ! -e $replay_root && ! -L $replay_root ]] || return 1
  mkdir -- "$replay_root"
  if ! (
    set -Eeuo pipefail
    for label in a b; do
      [[ -d $build_final/candidate-$label \
         && ! -L $build_final/candidate-$label ]]
      "$script_path" --internal-python inventory \
        "$build_final/candidate-$label" > "$replay_root/inventory-$label.json"
      "$script_path" --internal-python compare-json \
        "$artifact_final/configuration/inventory-$label.json" \
        "$replay_root/inventory-$label.json"
    done
    run_qemu positive "$artifact_final/boot" \
      "$replay_root/positive.raw" "$replay_root/positive.normalized" >/dev/null
    run_qemu negative "$artifact_final/boot" \
      "$replay_root/negative.raw" "$replay_root/negative.normalized" >/dev/null
    "$inventory_helper" --internal-python dependency-inventory \
      "$gcc_prefix" "$tools_root" > "$replay_root/gcc.json"
    "$inventory_helper" --internal-python inventory "$glibc_snapshot" \
      > "$replay_root/glibc.json"
    "$script_path" --internal-python compare-json \
      "$artifact_final/configuration/gcc-before.json" "$replay_root/gcc.json"
    "$script_path" --internal-python compare-json \
      "$artifact_final/configuration/glibc-before.json" "$replay_root/glibc.json"
    mapfile -t completed_dependencies < <(resolve_dependencies)
    [[ ${completed_dependencies[*]} == "${dependency_values[*]}" ]]
  ); then
    mv -T -- "$replay_root" "$work_root/.failed-replay-$build_id-$$"
    return 1
  fi
  rm -rf -- "$replay_root"
  validate_mutable_inputs || {
    echo "Completed first-boot mutable inputs changed during replay" >&2
    return 1
  }
  [[ $(readlink -- "$tools_root/current") == "$initial_tools_selector" \
     && $(readlink -- "$sysroot/current") == "$initial_sysroot_selector" ]] || {
    echo "Managed selector changed during completed first-boot replay" >&2
    return 1
  }
}

exec 9>"$cajunos_root/work/.cajunos-build.lock"
if ! flock -n 9; then
  echo "Another CajunOS build owns the global build lock" >&2
  exit 83
fi

if [[ -d $build_final && ! -L $build_final \
   && -d $artifact_final && ! -L $artifact_final \
   && -f $receipt_final && ! -L $receipt_final ]]; then
  mapfile -t replay_dependencies < <(resolve_dependencies)
  [[ ${replay_dependencies[*]} == "${dependency_values[*]}" ]] || {
    echo "Completed first-boot dependency pair is no longer exact-active" >&2
    exit 84
  }
  validate_complete
  echo "CAJUNOS_KERNEL_FIRST_BOOT_ALREADY_COMPLETE build_id=$build_id"
  exit 0
fi
if [[ -e $build_final || -L $build_final \
   || -e $artifact_final || -L $artifact_final ]]; then
  echo "Refusing to reuse an incomplete published kernel build: $build_id" >&2
  exit 85
fi
if [[ -e $temporary_root || -L $temporary_root \
   || -e $artifact_temporary || -L $artifact_temporary \
   || -e $failed_root || -L $failed_root \
   || -e $failed_artifact || -L $failed_artifact \
   || -e $log_dir || -L $log_dir ]]; then
  echo "Refusing colliding kernel temporary or log path: $run_id" >&2
  exit 86
fi

build_succeeded=0
on_exit() {
  local status=$?
  set +e
  if (( status != 0 || build_succeeded == 0 )); then
    if [[ -e $temporary_root || -L $temporary_root \
       || -e $build_final || -L $build_final ]]; then
      mkdir -- "$failed_root"
      [[ ! -e $temporary_root && ! -L $temporary_root ]] \
        || mv -T -- "$temporary_root" "$failed_root/temporary-root-entry"
      [[ ! -e $build_final && ! -L $build_final ]] \
        || mv -T -- "$build_final" "$failed_root/build-final-entry"
    fi
    if [[ -e $artifact_temporary || -L $artifact_temporary \
       || -e $artifact_final || -L $artifact_final ]]; then
      mkdir -- "$failed_artifact"
      [[ ! -e $artifact_temporary && ! -L $artifact_temporary ]] \
        || mv -T -- "$artifact_temporary" "$failed_artifact/temporary-artifact-entry"
      [[ ! -e $artifact_final && ! -L $artifact_final ]] \
        || mv -T -- "$artifact_final" "$failed_artifact/artifact-final-entry"
    fi
  fi
  trap - EXIT
  exit "$status"
}
trap on_exit EXIT

mkdir -p "$build_a" "$build_b" "$candidate_a" "$candidate_b" \
  "$artifact_temporary/boot" "$artifact_temporary/configuration" \
  "$artifact_temporary/probe" "$artifact_temporary/licenses" "$log_dir"
exec > >(tee "$log_file") 2>&1

echo "CajunOS diagnostic kernel plus minimal initramfs first boot"
echo "build_id=$build_id"
echo "linux_source=$locked_linux_commit"
echo "source_set=$source_set_digest"
echo "source_authentication=$source_authentication"
echo "orchestration=$orchestration_commit"
echo "complete_gcc=$gcc_build_id"
echo "complete_glibc=$glibc_build_id"
echo "kernel_release=$expected_release"
echo "qemu=$qemu_version"
echo "qemu_machine=$qemu_machine"
echo "qemu_cpu=$qemu_cpu"
echo "diagnostic_only=true"

"$inventory_helper" --internal-python dependency-inventory \
  "$gcc_prefix" "$tools_root" > "$artifact_temporary/configuration/gcc-before.json"
"$inventory_helper" --internal-python inventory "$glibc_snapshot" \
  > "$artifact_temporary/configuration/glibc-before.json"

export PATH="$gcc_prefix/bin:$binutils_prefix/bin:/usr/bin:/bin"
export KBUILD_BUILD_USER=cajunos
export KBUILD_BUILD_HOST=cajunos-forge
export KBUILD_BUILD_VERSION=1
export KBUILD_BUILD_TIMESTAMP
KBUILD_BUILD_TIMESTAMP=$(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%d %H:%M:%S +0000')
export KCONFIG_NOTIMESTAMP=1

build_one() {
  local build=$1 candidate=$2 label=$3
  local prefix_flags="-ffile-prefix-map=$linux_source_dir=/usr/src/linux -fmacro-prefix-map=$linux_source_dir=/usr/src/linux -ffile-prefix-map=$build=/usr/src/linux-build -fmacro-prefix-map=$build=/usr/src/linux-build"
  local effective_kcflags="$kernel_kcflags $prefix_flags"
  cp -- "$config_source" "$build/.config"
  "$script_path" --internal-python validate-config "$build/.config" \
    > "$artifact_temporary/configuration/$label.config-contract.json"
  env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    KBUILD_BUILD_USER="$KBUILD_BUILD_USER" \
    KBUILD_BUILD_HOST="$KBUILD_BUILD_HOST" \
    KBUILD_BUILD_VERSION="$KBUILD_BUILD_VERSION" \
    KBUILD_BUILD_TIMESTAMP="$KBUILD_BUILD_TIMESTAMP" KCONFIG_NOTIMESTAMP=1 \
    /usr/bin/make -s -C "$linux_source_dir" O="$build" ARCH=x86_64 \
    CROSS_COMPILE="$gcc_prefix/bin/$target-" \
    HOSTCC="$host_cc" HOSTCXX="$host_cxx" \
    KCONFIG_CONFIG="$build/.config" \
    KCFLAGS="$effective_kcflags" KAFLAGS="$prefix_flags" olddefconfig
  cmp -s "$build/.config" "$config_source" || {
    echo "Locked kernel config changed during $label olddefconfig" >&2
    return 1
  }
  env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    KBUILD_BUILD_USER="$KBUILD_BUILD_USER" \
    KBUILD_BUILD_HOST="$KBUILD_BUILD_HOST" \
    KBUILD_BUILD_VERSION="$KBUILD_BUILD_VERSION" \
    KBUILD_BUILD_TIMESTAMP="$KBUILD_BUILD_TIMESTAMP" KCONFIG_NOTIMESTAMP=1 \
    /usr/bin/make -C "$linux_source_dir" O="$build" ARCH=x86_64 \
    CROSS_COMPILE="$gcc_prefix/bin/$target-" \
    HOSTCC="$host_cc" HOSTCXX="$host_cxx" \
    KCONFIG_CONFIG="$build/.config" \
    KCFLAGS="$effective_kcflags" KAFLAGS="$prefix_flags" \
    -j"$jobs" bzImage vmlinux usr_gen_init_cpio
  cmp -s "$build/.config" "$config_source" || {
    echo "Locked kernel config changed during $label build" >&2
    return 1
  }
  local release
  release=$(env -i PATH="$PATH" LC_ALL=C TZ=UTC \
    SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    KBUILD_BUILD_USER="$KBUILD_BUILD_USER" \
    KBUILD_BUILD_HOST="$KBUILD_BUILD_HOST" \
    KBUILD_BUILD_VERSION="$KBUILD_BUILD_VERSION" \
    KBUILD_BUILD_TIMESTAMP="$KBUILD_BUILD_TIMESTAMP" KCONFIG_NOTIMESTAMP=1 \
    /usr/bin/make -s -C "$linux_source_dir" O="$build" ARCH=x86_64 \
    CROSS_COMPILE="$gcc_prefix/bin/$target-" \
    HOSTCC="$host_cc" HOSTCXX="$host_cxx" \
    KCONFIG_CONFIG="$build/.config" kernelrelease)
  [[ $release == "$expected_release" ]] || {
    echo "Independent kernel $label has unexpected release: $release" >&2
    return 1
  }
  "$readelf_driver" -hW "$build/vmlinux" \
    > "$artifact_temporary/configuration/$label.vmlinux.readelf-h"
  grep -Eq 'Class:[[:space:]]+ELF64' \
    "$artifact_temporary/configuration/$label.vmlinux.readelf-h"
  grep -Eq 'Type:[[:space:]]+EXEC ' \
    "$artifact_temporary/configuration/$label.vmlinux.readelf-h"
  grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64' \
    "$artifact_temporary/configuration/$label.vmlinux.readelf-h"
  for forbidden_path in "$linux_source_dir" "$build" "$temporary_root"; do
    if grep -a -F -q -- "$forbidden_path" "$build/vmlinux"; then
      echo "Kernel $label vmlinux retains disposable path: $forbidden_path" >&2
      return 1
    fi
  done
  printf '%s %s\n' "$kernel_kcflags" "$kernel_prefix_map_template" \
    > "$artifact_temporary/configuration/$label.kernel.kcflags"
  printf '%s\n' "$kernel_prefix_map_template" \
    > "$artifact_temporary/configuration/$label.kernel.kaflags"

  cp -- "$build/arch/x86/boot/bzImage" "$candidate/bzImage"
  cp -- "$build/vmlinux" "$candidate/vmlinux"
  cp -- "$build/System.map" "$candidate/System.map"
  cp -- "$build/.config" "$candidate/config"
  cp -- "$init_source" "$candidate/first-boot-init.c"
  printf '%s\n' "$release" > "$candidate/kernelrelease.txt"
  "$gcc_driver" --version > "$candidate/compiler.txt"

  (
    cd "$candidate"
    local_prefix_flags="-ffile-prefix-map=$project_root=/usr/src/cajunos -fmacro-prefix-map=$project_root=/usr/src/cajunos"
    printf '%s\n' \
      "$gcc_driver --sysroot=$glibc_snapshot $init_cflags $local_prefix_flags -DCAJUNOS_EXPECTED_RELEASE=\"$expected_release\" -DCAJUNOS_BUILD_ID=\"$build_id\" -c first-boot-init.c -o init.o" \
      > init.compile.command
    # shellcheck disable=SC2086
    env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
      "$gcc_driver" --sysroot="$glibc_snapshot" $init_cflags \
      $local_prefix_flags \
      -DCAJUNOS_EXPECTED_RELEASE="\"$expected_release\"" \
      -DCAJUNOS_BUILD_ID="\"$build_id\"" \
      -c first-boot-init.c -o init.o
    chmod 0644 init.o
    printf '%s\n' \
      "$gcc_driver --sysroot=$glibc_snapshot $init_ldflags init.o -Wl,-Map=init.map -o init" \
      > init.link.command
    # shellcheck disable=SC2086
    env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
      "$gcc_driver" --sysroot="$glibc_snapshot" $init_ldflags init.o \
      -Wl,-Map=init.map -o init
    chmod 0755 init
    printf '%s\n' \
      'dir /dev 0755 0 0' \
      'nod /dev/console 0600 0 0 c 5 1' \
      'nod /dev/null 0666 0 0 c 1 3' \
      'dir /proc 0555 0 0' \
      'dir /sys 0555 0 0' \
      'dir /run 0755 0 0' \
      'file /init init 0755 0 0' > initramfs.list
    "$build/usr/gen_init_cpio" -t "$SOURCE_DATE_EPOCH" \
      -o initramfs.cpio initramfs.list
  )
  chmod 0644 "$candidate"/{first-boot-init.c,init.compile.command,init.link.command,init.map,initramfs.list,initramfs.cpio,config,kernelrelease.txt,compiler.txt,System.map}
  "$script_path" --internal-python validate-init \
    "$candidate/init" "$readelf_driver" "$nm_driver" "$candidate/init.map" \
    "$gcc_prefix" "$glibc_snapshot" "$binutils_prefix" \
    > "$artifact_temporary/configuration/$label.init-contract.json"
  "$script_path" --internal-python validate-newc "$candidate/initramfs.cpio" \
    "$candidate/init" \
    > "$artifact_temporary/configuration/$label.newc-inventory.json"
  "$script_path" --internal-python inventory "$candidate" \
    > "$artifact_temporary/configuration/inventory-$label.json"
}

copy_flat_license_bundle() {
  local source=$1 destination=$2 entry resolved name count=0
  [[ -d $source && ! -L $source && -d $destination \
     && ! -L $destination ]] || return 1
  while IFS= read -r -d '' entry; do
    name=${entry##*/}
    [[ $name =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ && -f $entry ]] || return 1
    resolved=$(readlink -f -- "$entry")
    [[ $resolved == "$source/"* && -f $resolved && ! -L $resolved ]] \
      || return 1
    install -m 0644 -- "$entry" "$destination/$name"
    ((count += 1))
  done < <(find -P "$source" -mindepth 1 -maxdepth 1 -print0)
  (( count > 0 ))
}

build_one "$build_a" "$candidate_a" a
build_one "$build_b" "$candidate_b" b
"$script_path" --internal-python compare-json \
  "$artifact_temporary/configuration/inventory-a.json" \
  "$artifact_temporary/configuration/inventory-b.json"
"$script_path" --internal-python compare-json \
  "$artifact_temporary/configuration/a.newc-inventory.json" \
  "$artifact_temporary/configuration/b.newc-inventory.json"
"$script_path" --internal-python compare-json \
  "$artifact_temporary/configuration/a.config-contract.json" \
  "$artifact_temporary/configuration/b.config-contract.json"
"$script_path" --internal-python compare-json \
  "$artifact_temporary/configuration/a.init-contract.json" \
  "$artifact_temporary/configuration/b.init-contract.json"
cmp -s "$artifact_temporary/configuration/a.vmlinux.readelf-h" \
  "$artifact_temporary/configuration/b.vmlinux.readelf-h"
cmp -s "$candidate_a/config" "$candidate_b/config"
cmp -s "$candidate_a/bzImage" "$candidate_b/bzImage"
cmp -s "$candidate_a/vmlinux" "$candidate_b/vmlinux"
cmp -s "$candidate_a/System.map" "$candidate_b/System.map"
cmp -s "$candidate_a/init" "$candidate_b/init"
cmp -s "$candidate_a/init.o" "$candidate_b/init.o"
cmp -s "$candidate_a/initramfs.cpio" "$candidate_b/initramfs.cpio"
cmp -s "$artifact_temporary/configuration/a.kernel.kcflags" \
  "$artifact_temporary/configuration/b.kernel.kcflags"
cmp -s "$artifact_temporary/configuration/a.kernel.kaflags" \
  "$artifact_temporary/configuration/b.kernel.kaflags"

cp -a -- "$candidate_a/." "$artifact_temporary/boot/"
git -C "$linux_source_dir" archive "$locked_linux_commit" -- "${license_paths[@]}" |
  tar -x -C "$artifact_temporary/licenses"
mkdir -p "$artifact_temporary/licenses/gcc" "$artifact_temporary/licenses/glibc"
copy_flat_license_bundle "$artifacts_root/$gcc_build_id/licenses/gcc" \
  "$artifact_temporary/licenses/gcc"
copy_flat_license_bundle "$artifacts_root/$glibc_build_id/licenses/glibc" \
  "$artifact_temporary/licenses/glibc"

{
  printf '%q' "$qemu_path"
  printf ' %q' "${qemu_args[@]}"
  printf ' -kernel <boot>/bzImage -initrd <boot>/initramfs.cpio -append %q\n' \
    "$positive_cmdline"
  printf '%q' "$qemu_path"
  printf ' %q' "${qemu_args[@]}"
  printf ' -kernel <boot>/bzImage -initrd <boot>/initramfs.cpio -append %q\n' \
    "$negative_cmdline"
} > "$artifact_temporary/configuration/qemu.commands"
printf '%s\n' "$qemu_version" > "$artifact_temporary/configuration/qemu.version"
printf '%s\n' "$kernel_kcflags" > "$artifact_temporary/configuration/kernel.kcflags"
printf '%s\n' "$kernel_prefix_map_template" \
  > "$artifact_temporary/configuration/kernel.prefix-map-template"
printf '%s\n' "$init_cflags" > "$artifact_temporary/configuration/init.cflags"
printf '%s\n' "$init_ldflags" > "$artifact_temporary/configuration/init.ldflags"

# Revalidate immutable inputs before establishing any final path.
validate_mutable_inputs || {
  echo "Kernel mutable-input closure failed before permanent probes" >&2
  exit 87
}
"$project_root/scripts/fetch.py" validate --root "$cajunos_root"
if [[ -n $(git -C "$project_root" status --porcelain) \
   || $(git -C "$project_root" rev-parse HEAD) != "$orchestration_commit" \
   || $(git -C "$project_root" rev-parse 'HEAD^{tree}') != "$orchestration_tree" \
   || $(sha256sum "$script_path" | awk '{print $1}') != "$recipe_sha256" \
   || $(sha256sum "$inventory_helper" | awk '{print $1}') != "$inventory_helper_sha256" \
   || $(sha256sum "$gcc_helper" | awk '{print $1}') != "$gcc_helper_sha256" \
   || $(sha256sum "$libgcc_helper" | awk '{print $1}') != "$libgcc_helper_sha256" \
   || $(sha256sum "$glibc_helper" | awk '{print $1}') != "$glibc_helper_sha256" \
   || $(sha256sum "$config_source" | awk '{print $1}') != "$config_sha256" \
   || $(sha256sum "$init_source" | awk '{print $1}') != "$init_source_sha256" ]]; then
  echo "Kernel orchestration or frozen input changed during build" >&2
  exit 87
fi
mapfile -t dependency_values_after < <(resolve_dependencies)
if [[ ${dependency_values_after[*]} != "${dependency_values[*]}" ]]; then
  echo "Authoritative kernel dependency pair changed during build" >&2
  exit 88
fi
"$inventory_helper" --internal-python dependency-inventory \
  "$gcc_prefix" "$tools_root" > "$artifact_temporary/configuration/gcc-after.json"
"$inventory_helper" --internal-python inventory "$glibc_snapshot" \
  > "$artifact_temporary/configuration/glibc-after.json"
"$script_path" --internal-python compare-json \
  "$artifact_temporary/configuration/gcc-before.json" \
  "$artifact_temporary/configuration/gcc-after.json"
"$script_path" --internal-python compare-json \
  "$artifact_temporary/configuration/glibc-before.json" \
  "$artifact_temporary/configuration/glibc-after.json"
[[ $(readlink -- "$tools_root/current") == "$initial_tools_selector" \
   && $(readlink -- "$sysroot/current") == "$initial_sysroot_selector" ]] || {
  echo "A managed selector changed before kernel publication" >&2
  exit 89
}

"$script_path" --internal-python validate-directories "$cajunos_root" \
  work work/kernel tools artifacts logs sysroot "sysroot/$cohort_id"
if [[ ! -d $temporary_root || -L $temporary_root \
   || ! -d $artifact_temporary || -L $artifact_temporary \
   || -e $build_final || -L $build_final \
   || -e $artifact_final || -L $artifact_final ]]; then
  echo "Kernel publication paths changed before permanent probes" >&2
  exit 90
fi
mv -T -- "$temporary_root" "$build_final"
mv -T -- "$artifact_temporary" "$artifact_final"

run_qemu positive "$artifact_final/boot" \
  "$artifact_final/probe/positive.serial.raw" \
  "$artifact_final/probe/positive.serial.normalized" \
  > "$artifact_final/probe/positive.validation.json"
run_qemu negative "$artifact_final/boot" \
  "$artifact_final/probe/negative.serial.raw" \
  "$artifact_final/probe/negative.serial.normalized" \
  > "$artifact_final/probe/negative.validation.json"

# Semantic probes must not mutate any sealed dependency or published boot bit.
"$inventory_helper" --internal-python dependency-inventory \
  "$gcc_prefix" "$tools_root" > "$artifact_final/configuration/gcc-post-probe.json"
"$inventory_helper" --internal-python inventory "$glibc_snapshot" \
  > "$artifact_final/configuration/glibc-post-probe.json"
"$script_path" --internal-python compare-json \
  "$artifact_final/configuration/gcc-before.json" \
  "$artifact_final/configuration/gcc-post-probe.json"
"$script_path" --internal-python compare-json \
  "$artifact_final/configuration/glibc-before.json" \
  "$artifact_final/configuration/glibc-post-probe.json"

validate_mutable_inputs || {
  echo "Kernel mutable-input closure failed before receipt" >&2
  exit 91
}
mapfile -t dependency_values_receipt < <(resolve_dependencies)
if [[ ${dependency_values_receipt[*]} != "${dependency_values[*]}" ]]; then
  echo "Authoritative kernel dependency pair changed before receipt" >&2
  exit 91
fi
[[ $(readlink -- "$tools_root/current") == "$gcc_build_id" \
   && $(readlink -- "$sysroot/current") == "snapshots/$glibc_build_id" ]] || {
  echo "A managed selector changed during kernel probes" >&2
  exit 92
}

python3 - \
  "$receipt_final" "$artifact_final" \
  build_id "$build_id" source_commit "$locked_linux_commit" \
  source_tree "$locked_linux_tree" source_repository "$linux_repository" \
  source_set_digest "$source_set_digest" \
  source_authentication "$source_authentication" \
  source_date_epoch "$SOURCE_DATE_EPOCH" target "$target" \
  kernel_version "$kernel_version" expected_release "$expected_release" \
  orchestration_commit "$orchestration_commit" \
  orchestration_tree "$orchestration_tree" recipe_sha256 "$recipe_sha256" \
  inventory_helper_sha256 "$inventory_helper_sha256" \
  gcc_helper_sha256 "$gcc_helper_sha256" \
  libgcc_helper_sha256 "$libgcc_helper_sha256" \
  glibc_helper_sha256 "$glibc_helper_sha256" \
  config_sha256 "$config_sha256" init_source_sha256 "$init_source_sha256" \
  kernel_kcflags "$kernel_kcflags" \
  kernel_prefix_map_template "$kernel_prefix_map_template" \
  init_cflags "$init_cflags" \
  init_ldflags "$init_ldflags" contract_digest "$contract_digest" \
  gcc_build_id "$gcc_build_id" gcc_prefix "$gcc_prefix" \
  gcc_prefix_digest "$gcc_prefix_digest" gcc_receipt "$gcc_receipt" \
  gcc_receipt_sha256 "$gcc_receipt_sha256" \
  libgcc_build_id "$libgcc_build_id" libgcc_prefix "$libgcc_prefix" \
  libgcc_receipt "$libgcc_receipt" \
  libgcc_receipt_sha256 "$libgcc_receipt_sha256" \
  stage1_gcc_build_id "$stage1_gcc_build_id" \
  stage1_gcc_prefix "$stage1_gcc_prefix" \
  stage1_gcc_receipt "$stage1_gcc_receipt" \
  stage1_gcc_receipt_sha256 "$stage1_gcc_receipt_sha256" \
  glibc_build_id "$glibc_build_id" glibc_snapshot "$glibc_snapshot" \
  glibc_snapshot_digest "$glibc_snapshot_digest" \
  glibc_receipt "$glibc_receipt" glibc_receipt_sha256 "$glibc_receipt_sha256" \
  binutils_build_id "$binutils_build_id" binutils_prefix "$binutils_prefix" \
  binutils_receipt "$binutils_receipt" \
  binutils_receipt_sha256 "$binutils_receipt_sha256" \
  linux_uapi_build_id "$linux_uapi_build_id" \
  linux_uapi_snapshot "$linux_uapi_snapshot" \
  linux_uapi_snapshot_digest "$linux_uapi_snapshot_digest" \
  linux_uapi_receipt "$linux_uapi_receipt" \
  linux_uapi_receipt_sha256 "$linux_uapi_receipt_sha256" \
  qemu_path "$qemu_path" qemu_sha256 "$qemu_sha256" \
  qemu_bios "$qemu_bios" qemu_bios_sha256 "$qemu_bios_sha256" \
  qemu_linuxboot "$qemu_linuxboot" \
  qemu_linuxboot_sha256 "$qemu_linuxboot_sha256" \
  qemu_kvmvapic "$qemu_kvmvapic" \
  qemu_kvmvapic_sha256 "$qemu_kvmvapic_sha256" \
  qemu_version "$qemu_version" qemu_machine "$qemu_machine" \
  qemu_cpu "$qemu_cpu" positive_cmdline "$positive_cmdline" \
  negative_cmdline "$negative_cmdline" \
  host_cc "$host_cc" host_cc_sha256 "$host_cc_sha256" \
  host_cc_resolved "$host_cc_resolved" \
  host_cc_version "$host_cc_version" host_cxx "$host_cxx" \
  host_cxx_resolved "$host_cxx_resolved" \
  host_cxx_sha256 "$host_cxx_sha256" host_cxx_version "$host_cxx_version" \
  log "$log_file" <<'PY'
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

receipt_path = Path(sys.argv[1])
artifact = Path(sys.argv[2])
pairs = sys.argv[3:]
if len(pairs) % 2:
    raise SystemExit("receipt generator requires key/value pairs")
p = dict(zip(pairs[::2], pairs[1::2], strict=True))


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def regular_hashes(root):
    result = {}
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            if path.is_symlink():
                raise SystemExit(f"symlinked evidence directory: {path}")
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise SystemExit(f"unsupported receipt evidence: {path}")
        result[path.relative_to(root).as_posix()] = sha256(path)
    return result


def load(path):
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream)


subtree_hashes = {
    name: regular_hashes(artifact / name)
    for name in ("boot", "configuration", "probe", "licenses")
}
inventory = load(artifact / "configuration/inventory-a.json")
if inventory != load(artifact / "configuration/inventory-b.json"):
    raise SystemExit("independent first-boot inventories differ at receipt time")

packages = {}
for package in (
    "qemu-system-x86", "qemu-system-data", "seabios",
    "gcc", "g++", "make", "binutils",
):
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Version}", package], check=False,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    packages[package] = result.stdout if result.returncode == 0 else None

receipt = {
    "schema": 1,
    "build_id": p["build_id"],
    "component": "linux",
    "stage": "first-boot",
    "source_commit": p["source_commit"],
    "source_tree": p["source_tree"],
    "source_repository": p["source_repository"],
    "source_set_digest": p["source_set_digest"],
    "source_authentication": p["source_authentication"],
    "source_date_epoch": int(p["source_date_epoch"]),
    "target": p["target"],
    "kernel": {"version": p["kernel_version"], "release": p["expected_release"]},
    "diagnostic_only": True,
    "deployable": False,
    "security_contract": {
        "cpu_mitigations": "disabled",
        "kaslr": "disabled",
        "stack_protector": "disabled",
        "fortify_source": "disabled",
        "security_framework": "disabled",
        "init_stack_all_zero": "enabled",
    },
    "orchestration_commit": p["orchestration_commit"],
    "orchestration_tree": p["orchestration_tree"],
    "recipe_sha256": p["recipe_sha256"],
    "inventory_helper_sha256": p["inventory_helper_sha256"],
    "gcc_helper_sha256": p["gcc_helper_sha256"],
    "libgcc_helper_sha256": p["libgcc_helper_sha256"],
    "glibc_helper_sha256": p["glibc_helper_sha256"],
    "config_sha256": p["config_sha256"],
    "init_source_sha256": p["init_source_sha256"],
    "build_contract": {
        "independent_builds": 2,
        "kernel_kcflags": p["kernel_kcflags"],
        "kernel_prefix_map_template": p["kernel_prefix_map_template"],
        "init_cflags": p["init_cflags"],
        "init_ldflags": p["init_ldflags"],
        "contract_digest": p["contract_digest"],
        "initramfs_format": "raw-svr4-newc",
        "initramfs_epoch": int(p["source_date_epoch"]),
    },
    "qemu": {
        "path": p["qemu_path"], "sha256": p["qemu_sha256"],
        "version": p["qemu_version"], "machine": p["qemu_machine"],
        "accelerator": "tcg", "cpu": p["qemu_cpu"],
        "positive_cmdline": p["positive_cmdline"],
        "negative_cmdline": p["negative_cmdline"],
        "firmware": {
            "bios": {"path": p["qemu_bios"], "sha256": p["qemu_bios_sha256"]},
            "linuxboot_dma": {
                "path": p["qemu_linuxboot"],
                "sha256": p["qemu_linuxboot_sha256"],
            },
            "kvmvapic": {
                "path": p["qemu_kvmvapic"],
                "sha256": p["qemu_kvmvapic_sha256"],
            },
        },
        "diskless": True, "network": False,
    },
    "dependencies": {
        "gcc": {
            "build_id": p["gcc_build_id"], "prefix": p["gcc_prefix"],
            "prefix_digest": p["gcc_prefix_digest"],
            "receipt": p["gcc_receipt"],
            "receipt_sha256": p["gcc_receipt_sha256"],
        },
        "libgcc": {
            "build_id": p["libgcc_build_id"], "prefix": p["libgcc_prefix"],
            "receipt": p["libgcc_receipt"],
            "receipt_sha256": p["libgcc_receipt_sha256"],
        },
        "stage1_gcc": {
            "build_id": p["stage1_gcc_build_id"],
            "prefix": p["stage1_gcc_prefix"],
            "receipt": p["stage1_gcc_receipt"],
            "receipt_sha256": p["stage1_gcc_receipt_sha256"],
        },
        "glibc": {
            "build_id": p["glibc_build_id"], "snapshot": p["glibc_snapshot"],
            "snapshot_digest": p["glibc_snapshot_digest"],
            "receipt": p["glibc_receipt"],
            "receipt_sha256": p["glibc_receipt_sha256"],
        },
        "binutils": {
            "build_id": p["binutils_build_id"], "prefix": p["binutils_prefix"],
            "receipt": p["binutils_receipt"],
            "receipt_sha256": p["binutils_receipt_sha256"],
        },
        "linux_uapi": {
            "build_id": p["linux_uapi_build_id"],
            "snapshot": p["linux_uapi_snapshot"],
            "snapshot_digest": p["linux_uapi_snapshot_digest"],
            "receipt": p["linux_uapi_receipt"],
            "receipt_sha256": p["linux_uapi_receipt_sha256"],
        },
    },
    "selectors_modified": False,
    "reproducibility": {
        "independent_builds": 2,
        "inventory_schema": "paths-types-modes-sha256-symlink-targets-v1",
        "inventory": inventory,
        "identical": True,
        "gcc_unchanged": True,
        "glibc_unchanged": True,
    },
    "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    "log": p["log"],
    "host": {
        "platform": platform.platform(),
        "qemu": p["qemu_version"],
        "kernel_cc": {
            "path": p["host_cc"], "sha256": p["host_cc_sha256"],
            "resolved_path": p["host_cc_resolved"],
            "version": p["host_cc_version"],
        },
        "kernel_cxx": {
            "path": p["host_cxx"], "sha256": p["host_cxx_sha256"],
            "resolved_path": p["host_cxx_resolved"],
            "version": p["host_cxx_version"],
        },
        "packages": packages,
    },
    "outputs": {"subtree_sha256": subtree_hashes},
}
descriptor, temporary = tempfile.mkstemp(
    prefix=".receipt.", dir=receipt_path.parent, text=True
)
with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
    json.dump(receipt, stream, indent=2, sort_keys=True)
    stream.write("\n")
os.replace(temporary, receipt_path)
receipt_path.chmod(0o644)
PY

# Close the last mutable-input window, then replay the complete receipt and
# both boots from the permanent paths.  No tool or sysroot selector is moved.
validate_mutable_inputs || {
  echo "Kernel mutable-input closure failed after receipt" >&2
  exit 93
}
mapfile -t dependency_values_final < <(resolve_dependencies)
if [[ ${dependency_values_final[*]} != "${dependency_values[*]}" ]]; then
  echo "Authoritative kernel dependency pair changed after receipt" >&2
  exit 93
fi
validate_complete
validate_mutable_inputs || {
  echo "Kernel mutable inputs changed during completed replay" >&2
  exit 94
}
[[ $(readlink -- "$tools_root/current") == "$gcc_build_id" \
   && $(readlink -- "$sysroot/current") == "snapshots/$glibc_build_id" ]] || {
  echo "Kernel stage modified or raced a managed selector" >&2
  exit 94
}

build_succeeded=1
trap - EXIT
echo "CAJUNOS_KERNEL_FIRST_BOOT_OK build_id=$build_id artifact=$artifact_final"
