#!/usr/bin/env bash
set -Eeuo pipefail
umask 022
export LC_ALL=C
export TZ=UTC
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

script_path=$(readlink -f -- "${BASH_SOURCE[0]}")
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

# These validators are deliberately usable without the forge.  Static tests
# exercise the same parsers used before publication and during replay.
if [[ ${1:-} == --internal-python ]]; then
  shift
  command_name=${1:-}
  shift || true
  exec python3 - "$command_name" "$@" <<'PY'
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tempfile
import uuid


command, *arguments = sys.argv[1:]


def fail(message):
    raise SystemExit(message)


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical_digest(value):
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_json(path):
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream)


def atomic_text(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        path.chmod(0o644)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def parse_kconfig(path):
    values = {}
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
        else:
            match = re.fullmatch(r"# (CONFIG_[A-Z0-9_]+) is not set", line)
            if not match:
                continue
            key, value = match.group(1), "n"
        if key in values:
            fail(f"duplicate Kconfig symbol on line {number}: {key}")
        values[key] = value
    return values


def merge_kconfig(base_path, fragment_path):
    base_path = Path(base_path)
    fragment_path = Path(fragment_path)
    fragment = parse_kconfig(fragment_path)
    if not fragment:
        fail("Kconfig fragment is empty")
    symbol_line = re.compile(r"(?:CONFIG_[A-Z0-9_]+=|# CONFIG_[A-Z0-9_]+ is not set)")
    output = []
    for line in base_path.read_text(encoding="utf-8").splitlines():
        key = None
        if line.startswith("CONFIG_") and "=" in line:
            key = line.split("=", 1)[0]
        else:
            match = re.fullmatch(r"# (CONFIG_[A-Z0-9_]+) is not set", line)
            if match:
                key = match.group(1)
        if key not in fragment:
            output.append(line)
    output.append("")
    output.append(f"# Locked CajunOS fragment: {fragment_path.name}")
    for raw in fragment_path.read_text(encoding="utf-8").splitlines():
        if raw.startswith("CONFIG_") or raw.startswith("# CONFIG_"):
            output.append(raw)
    atomic_text(base_path, "\n".join(output) + "\n")


def require_config(path, required_y, required_n, expected):
    values = parse_kconfig(path)
    for key in sorted(required_y):
        if values.get(key) != "y":
            fail(f"required configuration is not enabled: {key}")
    for key in sorted(required_n):
        if values.get(key, "n") != "n":
            fail(f"forbidden configuration is enabled: {key}")
    for key, wanted in sorted(expected.items()):
        if values.get(key) != wanted:
            fail(f"configuration mismatch for {key}: {values.get(key)!r}")
    return values


def validate_kernel_config(path):
    required_y = {
        "CONFIG_64BIT", "CONFIG_X86_64", "CONFIG_SMP", "CONFIG_ACPI",
        "CONFIG_PCI", "CONFIG_PCI_MSI", "CONFIG_EFI_PARTITION",
        "CONFIG_BLOCK", "CONFIG_SCSI", "CONFIG_BLK_DEV_SD",
        "CONFIG_VIRTIO", "CONFIG_VIRTIO_PCI", "CONFIG_VIRTIO_BLK",
        "CONFIG_SCSI_VIRTIO", "CONFIG_NET", "CONFIG_PACKET", "CONFIG_UNIX",
        "CONFIG_INET", "CONFIG_NETDEVICES", "CONFIG_VIRTIO_NET",
        "CONFIG_EXT4_FS", "CONFIG_DEVTMPFS", "CONFIG_DEVTMPFS_MOUNT",
        "CONFIG_PROC_FS", "CONFIG_SYSFS", "CONFIG_TMPFS", "CONFIG_TTY",
        "CONFIG_SERIAL_8250", "CONFIG_SERIAL_8250_CONSOLE",
        "CONFIG_SERIAL_8250_PCI", "CONFIG_SERIAL_EARLYCON",
        "CONFIG_BINFMT_ELF", "CONFIG_BINFMT_SCRIPT", "CONFIG_MULTIUSER",
        "CONFIG_RANDOMIZE_BASE", "CONFIG_RELOCATABLE", "CONFIG_STACKPROTECTOR",
        "CONFIG_STACKPROTECTOR_STRONG", "CONFIG_FORTIFY_SOURCE",
        "CONFIG_HARDENED_USERCOPY", "CONFIG_SECURITY",
        "CONFIG_CPU_MITIGATIONS", "CONFIG_INIT_STACK_ALL_ZERO",
        "CONFIG_DEBUG_INFO_NONE", "CONFIG_LTO_NONE",
    }
    required_n = {
        "CONFIG_MODULES", "CONFIG_WERROR", "CONFIG_EFI", "CONFIG_DEBUG_INFO",
        "CONFIG_LTO", "CONFIG_VT",
    }
    expected = {
        "CONFIG_LOCALVERSION": '"-cajunos"',
        "CONFIG_LOCALVERSION_AUTO": "n",
        "CONFIG_BUILD_SALT": '""',
        "CONFIG_SERIAL_8250_NR_UARTS": "4",
        "CONFIG_SERIAL_8250_RUNTIME_UARTS": "4",
    }
    values = require_config(path, required_y, required_n, expected)
    modules = sorted(key for key, value in values.items() if value == "m")
    if modules:
        fail(f"base-system kernel contains modules: {', '.join(modules)}")
    print(json.dumps({"keys": len(values), "modules": 0}, sort_keys=True))


def validate_busybox_config(path):
    required_y = {
        "CONFIG_STATIC", "CONFIG_INSTALL_APPLET_SYMLINKS", "CONFIG_ASH", "CONFIG_SH_IS_ASH", "CONFIG_INIT",
        "CONFIG_FEATURE_USE_INITTAB", "CONFIG_GETTY", "CONFIG_LOGIN",
        "CONFIG_HALT", "CONFIG_MOUNT", "CONFIG_UMOUNT", "CONFIG_MDEV",
        "CONFIG_HOSTNAME", "CONFIG_IP", "CONFIG_FEATURE_IP_ADDRESS",
        "CONFIG_FEATURE_IP_LINK", "CONFIG_FEATURE_IP_ROUTE", "CONFIG_UDHCPC",
        "CONFIG_CAT", "CONFIG_ECHO", "CONFIG_GREP", "CONFIG_MKDIR",
        "CONFIG_UNAME", "CONFIG_WC", "CONFIG_AWK", "CONFIG_TAR",
    }
    required_n = {
        "CONFIG_TC", "CONFIG_UDHCPC6", "CONFIG_FEATURE_MOUNT_HELPERS",
        "CONFIG_FEATURE_MOUNT_CIFS", "CONFIG_FEATURE_SUID",
        "CONFIG_INSTALL_APPLET_HARDLINKS", "CONFIG_INSTALL_APPLET_SCRIPT_WRAPPERS",
        "CONFIG_INSTALL_APPLET_DONT",
    }
    expected = {
        "CONFIG_UDHCPC_DEFAULT_SCRIPT": '"/etc/udhcpc/default.script"',
        "CONFIG_CROSS_COMPILER_PREFIX": '""',
        "CONFIG_SYSROOT": '""',
    }
    values = require_config(path, required_y, required_n, expected)
    print(json.dumps({"keys": len(values), "tc": "disabled"}, sort_keys=True))


def deterministic_tree_entries(root, root_metadata):
    def reject_extended_metadata(path, relative):
        try:
            attributes = os.listxattr(path, follow_symlinks=False)
        except OSError as error:
            fail(f"tree extended-metadata scan failed at {relative}: {error}")
        if attributes:
            fail(
                f"tree contains extended metadata at {relative}: "
                + ", ".join(sorted(attributes))
            )

    def recurse(directory, relative, directory_metadata):
        mode = stat.S_IMODE(directory_metadata.st_mode)
        readable_and_searchable = any(
            mode & permissions == permissions
            for permissions in (0o500, 0o050, 0o005)
        )
        if not readable_and_searchable:
            fail(f"tree contains an unreadable directory: {relative}")
        try:
            children = []
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    child_relative = (
                        entry.name if relative == "." else f"{relative}/{entry.name}"
                    )
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except OSError as error:
                        fail(f"tree stat failed at {child_relative}: {error}")
                    reject_extended_metadata(entry.path, child_relative)
                    children.append((entry.name, Path(entry.path), metadata, child_relative))
        except OSError as error:
            fail(f"tree scan failed at {relative}: {error}")
        for _name, path, metadata, child_relative in sorted(
            children, key=lambda item: item[0]
        ):
            yield path, metadata, child_relative
            if stat.S_ISDIR(metadata.st_mode):
                yield from recurse(path, child_relative, metadata)

    reject_extended_metadata(root, ".")
    yield from recurse(root, ".", root_metadata)


def inventory(root):
    root = Path(root)
    root_metadata = root.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode) or root.is_symlink():
        fail(f"inventory root is not a real directory: {root}")
    entries = {
        ".": {
            "type": "directory",
            "mode": f"{stat.S_IMODE(root_metadata.st_mode):04o}",
        }
    }
    for path, metadata, relative in deterministic_tree_entries(root, root_metadata):
        if stat.S_ISDIR(metadata.st_mode) and not path.is_symlink():
            entries[relative] = {
                "type": "directory", "mode": f"{stat.S_IMODE(metadata.st_mode):04o}"
            }
        elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            entries[relative] = {
                "type": "file", "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                "size": metadata.st_size, "sha256": sha256(path),
            }
        elif stat.S_ISLNK(metadata.st_mode) and metadata.st_nlink == 1:
            target = os.readlink(path)
            if target.startswith("/"):
                fail(f"inventory contains an escaping symlink: {relative} -> {target}")
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(root.resolve(strict=True))
            except (FileNotFoundError, OSError, RuntimeError, ValueError):
                fail(f"inventory contains a broken or escaping symlink: {relative} -> {target}")
            entries[relative] = {
                "type": "symlink", "mode": "0777", "target": target,
            }
        else:
            fail(f"inventory contains an unsupported or hard-linked entry: {relative}")
    return {"entries": entries, "digest": canonical_digest(entries)}


OVERLAY_EXECUTABLES = {
    "etc/init.d/rcS",
    "etc/init.d/rcK",
    "etc/udhcpc/default.script",
}
OVERLAY_REQUIRED_MODES = {
    **{relative: "0755" for relative in OVERLAY_EXECUTABLES},
    "etc/shadow": "0600",
}


def safe_internal_symlink(path, root, relative):
    target = os.readlink(path)
    if target.startswith("/"):
        fail(f"tree contains an absolute symlink: {relative} -> {target}")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (FileNotFoundError, OSError, RuntimeError, ValueError):
        fail(f"tree contains a broken or escaping symlink: {relative} -> {target}")
    return target


def reject_unsafe_checkout_mode(metadata, relative):
    mode = stat.S_IMODE(metadata.st_mode)
    if stat.S_ISDIR(metadata.st_mode):
        if mode & 0o4000:
            fail(f"tree contains a set-user-ID directory: {relative}")
    elif mode & 0o6000:
        fail(f"tree contains a set-id entry: {relative}")
    if mode & 0o002:
        fail(f"tree contains a world-writable checkout entry: {relative}")


def canonical_overlay_inventory(root):
    root = Path(root)
    root_metadata = root.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode) or root.is_symlink():
        fail("overlay root is not a real directory")
    reject_unsafe_checkout_mode(root_metadata, ".")
    entries = {".": {"type": "directory", "mode": "0755"}}
    for path, metadata, relative in deterministic_tree_entries(root, root_metadata):
        if stat.S_ISDIR(metadata.st_mode) and not path.is_symlink():
            reject_unsafe_checkout_mode(metadata, relative)
            entries[relative] = {"type": "directory", "mode": "0755"}
        elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            reject_unsafe_checkout_mode(metadata, relative)
            executable = bool(stat.S_IMODE(metadata.st_mode) & 0o111)
            if executable != (relative in OVERLAY_EXECUTABLES):
                fail(f"overlay executable-bit contract failed: {relative}")
            mode = "0755" if executable else ("0600" if relative == "etc/shadow" else "0644")
            entries[relative] = {
                "type": "file", "mode": mode, "size": metadata.st_size,
                "sha256": sha256(path),
            }
        elif stat.S_ISLNK(metadata.st_mode) and metadata.st_nlink == 1:
            entries[relative] = {
                "type": "symlink", "mode": "0777",
                "target": safe_internal_symlink(path, root, relative),
            }
        else:
            fail(f"overlay contains an unsupported or hard-linked entry: {relative}")
    invalid_required = []
    for relative, mode in sorted(OVERLAY_REQUIRED_MODES.items()):
        entry = entries.get(relative)
        if entry is None:
            invalid_required.append(f"{relative}=missing")
        elif entry.get("type") != "file" or entry.get("mode") != mode:
            invalid_required.append(
                f"{relative}={entry.get('type')}:{entry.get('mode')}"
            )
    if invalid_required:
        fail("overlay required-file contract failed: " + ", ".join(invalid_required))
    return {"entries": entries, "digest": canonical_digest(entries)}


def canonicalize_root(root):
    root = Path(root)
    root_metadata = root.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode) or root.is_symlink():
        fail("root tree is not a real directory")
    reject_unsafe_checkout_mode(root_metadata, ".")
    directories = [root]
    files = []
    for path, metadata, relative in deterministic_tree_entries(root, root_metadata):
        if stat.S_ISDIR(metadata.st_mode) and not path.is_symlink():
            reject_unsafe_checkout_mode(metadata, relative)
            directories.append(path)
        elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            reject_unsafe_checkout_mode(metadata, relative)
            files.append(path)
        elif stat.S_ISLNK(metadata.st_mode) and metadata.st_nlink == 1:
            safe_internal_symlink(path, root, relative)
        else:
            fail(f"root tree contains an unsupported or hard-linked entry: {relative}")
    for path in directories:
        path.chmod(0o755)
    for path in files:
        path.chmod(0o644)
    required_modes = {
        "bin/busybox": 0o755,
        "etc/init.d/rcS": 0o755,
        "etc/init.d/rcK": 0o755,
        "etc/udhcpc/default.script": 0o755,
        "etc/shadow": 0o600,
        "root": 0o700,
        "tmp": 0o1777,
    }
    for relative, mode in required_modes.items():
        path = root / relative
        metadata = path.lstat()
        if relative in {"root", "tmp"}:
            if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
                fail(f"canonical root path is not a directory: {relative}")
        elif not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            fail(f"canonical root path is not a plain file: {relative}")
        path.chmod(mode)
    print(json.dumps(inventory(root), indent=2, sort_keys=True))


def validate_gpt(path, disk_guid, bios_guid, root_guid, root_first):
    path = Path(path)
    sector = 512
    size = path.stat().st_size
    if size < 16 * 1024 * 1024 or size % sector:
        fail("disk image has unsafe size or sector alignment")
    sectors = size // sector
    with path.open("rb") as stream:
        def read_at(offset, length):
            stream.seek(offset)
            value = stream.read(length)
            if len(value) != length:
                fail("disk image is truncated")
            return value

        mbr = read_at(0, sector)
        primary = read_at(sector, sector)
        backup = read_at((sectors - 1) * sector, sector)
    if mbr[510:512] != b"\x55\xaa" or mbr[446 + 4] != 0xEE:
        fail("disk image lacks the exact protective MBR")
    protective_start, protective_count = struct.unpack_from("<II", mbr, 446 + 8)
    if protective_start != 1 or protective_count != min(sectors - 1, 0xFFFFFFFF):
        fail("protective MBR start or size is invalid")
    if any(mbr[462:510]):
        fail("protective MBR contains additional partition entries")

    def parse_header(header, label, current_lba, backup_lba, entries_lba):
        if header[:8] != b"EFI PART":
            fail(f"disk image lacks its {label} GPT header")
        revision, header_size, header_crc, reserved = struct.unpack_from("<IIII", header, 8)
        if revision != 0x00010000 or header_size != 92 or reserved != 0:
            fail(f"{label} GPT revision, size, or reserved field is invalid")
        checked = bytearray(header[:header_size])
        struct.pack_into("<I", checked, 16, 0)
        if binascii.crc32(checked) & 0xFFFFFFFF != header_crc:
            fail(f"{label} GPT header checksum is invalid")
        actual_current, actual_backup, first_usable, last_usable = struct.unpack_from(
            "<QQQQ", header, 24
        )
        if (
            actual_current != current_lba or actual_backup != backup_lba
            or first_usable != 34 or last_usable != sectors - 34
        ):
            fail(f"{label} GPT LBA contract is invalid")
        if str(uuid.UUID(bytes_le=header[56:72])) != str(uuid.UUID(disk_guid)):
            fail(f"{label} GPT disk GUID mismatch")
        actual_entries, count, entry_size, entries_crc = struct.unpack_from("<QIII", header, 72)
        if actual_entries != entries_lba or count != 128 or entry_size != 128:
            fail(f"{label} GPT entry-array geometry is invalid")
        if any(header[92:]):
            fail(f"{label} GPT header has nonzero trailing bytes")
        return entries_crc

    primary_crc = parse_header(primary, "primary", 1, sectors - 1, 2)
    backup_entries_lba = sectors - 33
    backup_crc = parse_header(
        backup, "backup", sectors - 1, 1, backup_entries_lba
    )
    with path.open("rb") as stream:
        stream.seek(2 * sector)
        entries = stream.read(128 * 128)
        stream.seek(backup_entries_lba * sector)
        backup_entries = stream.read(128 * 128)
    if len(entries) != 128 * 128 or len(backup_entries) != 128 * 128:
        fail("GPT entry array is truncated")
    entries_digest = binascii.crc32(entries) & 0xFFFFFFFF
    if entries_digest != primary_crc or entries_digest != backup_crc:
        fail("GPT entry-array checksum is invalid")
    if entries != backup_entries:
        fail("primary and backup GPT entry arrays differ")
    wanted = (
        ("21686148-6449-6e6f-744e-656564454649", bios_guid, 2048, 4095, "BIOS-BOOT"),
        ("0fc63daf-8483-4772-8e79-3d69d8477de4", root_guid, int(root_first), sectors - 34, "CAJUNOS-ROOT"),
    )
    entry_size = 128
    parsed = []
    for index, (type_guid, unique_guid, first, last, name) in enumerate(wanted):
        entry = entries[index * entry_size:(index + 1) * entry_size]
        actual_type = str(uuid.UUID(bytes_le=entry[:16]))
        actual_unique = str(uuid.UUID(bytes_le=entry[16:32]))
        actual_first, actual_last = struct.unpack_from("<QQ", entry, 32)
        attributes = struct.unpack_from("<Q", entry, 48)[0]
        actual_name = entry[56:128].decode("utf-16-le").rstrip("\0")
        if actual_type != type_guid or actual_unique != str(uuid.UUID(unique_guid)):
            fail(f"GPT partition {index + 1} GUID contract failed")
        if actual_first != first or actual_last != last:
            fail(f"GPT partition {index + 1} sector contract failed")
        if attributes != 0 or actual_name != name:
            fail(f"GPT partition {index + 1} attributes or name contract failed")
        parsed.append({"number": index + 1, "first": actual_first, "last": actual_last})
    if any(entries[2 * 128:]):
        fail("GPT contains unexpected additional partition entries")
    print(json.dumps({"disk_guid": str(uuid.UUID(disk_guid)), "partitions": parsed}, sort_keys=True))


def install_grub_raw(image_path, boot_path, core_path, core_lba, maximum_sectors):
    """Install source-built GRUB using the fixed, attested GPT embedding area.

    This is the fixed-layout subset of GRUB's util/setup.c.  It avoids a loop
    device, mounting the filesystem, or asking grub-bios-setup to infer a host
    root device.  Every patched offset is part of the i386-pc diskboot ABI and
    is asserted before writing.
    """
    image_path = Path(image_path)
    boot = bytearray(Path(boot_path).read_bytes())
    core = bytearray(Path(core_path).read_bytes())
    core_lba = int(core_lba)
    maximum_sectors = int(maximum_sectors)
    if len(boot) != 512 or boot[:3] != b"\xeb\x63\x90" or boot[510:] != b"\x55\xaa":
        fail("GRUB boot.img does not match the i386-pc boot-sector ABI")
    if len(core) < 1024 or core[:2] != b"RV":
        fail("GRUB core.img lacks the i386-pc diskboot signature")
    sectors = (len(core) + 511) // 512
    if sectors < 2 or sectors > maximum_sectors:
        fail("GRUB core.img does not fit the locked BIOS Boot partition")
    start, count, segment = struct.unpack_from("<QHH", core, 500)
    if start not in (0, 2) or count not in (0, sectors - 1) or segment != 0x0820:
        fail("GRUB core.img has an unexpected initial blocklist contract")
    # One entry loads every sector after diskboot.img; the preceding twelve
    # zero bytes terminate the backwards-scanned blocklist exactly.
    core[488:500] = b"\0" * 12
    struct.pack_into("<QHH", core, 500, core_lba + 1, sectors - 1, segment)
    core.extend(b"\0" * (sectors * 512 - len(core)))
    with image_path.open("r+b") as stream:
        old_mbr = stream.read(512)
        if len(old_mbr) != 512 or old_mbr[510:] != b"\x55\xaa" or old_mbr[450] != 0xEE:
            fail("raw image lacks its protective GPT MBR before GRUB install")
        # Preserve the BPB-shaped compatibility region, disk signature, and
        # complete protective partition table from the deterministic GPT.
        boot[0x03:0x5A] = old_mbr[0x03:0x5A]
        boot[0x1B8:0x1FE] = old_mbr[0x1B8:0x1FE]
        struct.pack_into("<Q", boot, 0x5C, core_lba)
        boot[0x64] = 0xFF
        stream.seek(0)
        stream.write(boot)
        stream.seek(core_lba * 512)
        stream.write(core)
        stream.flush()
        os.fsync(stream.fileno())
    result = {
        "boot_sha256": hashlib.sha256(boot).hexdigest(),
        "core_sha256": hashlib.sha256(core).hexdigest(),
        "core_lba": core_lba,
        "core_sectors": sectors,
        "blocklist_start": core_lba + 1,
        "blocklist_length": sectors - 1,
        "load_segment": segment,
    }
    print(json.dumps(result, indent=2, sort_keys=True))


def validate_ext4(path, filesystem_uuid, hash_seed):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        fail("ext4 image is not a plain file")
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}
    header = subprocess.run(
        ["/usr/sbin/dumpe2fs", "-h", path], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
    ).stdout
    fields = {}
    for line in header.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()
    if fields.get("Filesystem UUID") != str(uuid.UUID(filesystem_uuid)):
        fail("ext4 filesystem UUID is not locked")
    if fields.get("Directory Hash Seed") != str(uuid.UUID(hash_seed)):
        fail("ext4 directory hash seed is not locked")
    features = set(fields.get("Filesystem features", "").split())
    if "has_journal" in features or "extents" not in features:
        fail("ext4 feature contract is invalid")
    for guest_path in ("/etc/inittab", "/bin/busybox", "/boot/grub/grub.cfg"):
        output = subprocess.run(
            ["/usr/sbin/debugfs", "-R", f"stat {guest_path}", path],
            check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment,
        ).stdout
        if not re.search(r"User:\s+0\s+Group:\s+0(?:\s|$)", output):
            fail(f"ext4 payload is not root-owned: {guest_path}")
    print(json.dumps({"filesystem_uuid": fields["Filesystem UUID"],
                      "hash_seed": fields["Directory Hash Seed"]}, sort_keys=True))


def normalized_serial(path):
    data = Path(path).read_bytes()
    if b"\x00" in data or b"\x1b" in data:
        fail("serial transcript contains terminal control bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        fail("serial transcript is not UTF-8")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def validate_serial(kind, path, release, build_id, output=None):
    if kind not in {"positive", "negative"}:
        fail("serial kind must be positive or negative")
    text = normalized_serial(path)
    lines = text.splitlines()
    if re.search(r"(^|[\[ ])(?:Kernel panic|Oops:|BUG:)", text, re.I | re.M):
        fail("serial transcript contains a kernel failure")
    begin = "CAJUNOS_BASE_SYSTEM_BEGIN"
    success = [
        begin,
        f"CAJUNOS_BASE_SYSTEM_BUILD_ID {build_id}",
        "CAJUNOS_BASE_SYSTEM_ROOT_OK",
        "CAJUNOS_BASE_SYSTEM_NETWORK_OK",
        f"CAJUNOS_BASE_SYSTEM_UNAME {release}",
        "CAJUNOS_BASE_SYSTEM_OK",
    ]
    if kind == "positive":
        positions = []
        for marker in success:
            if lines.count(marker) != 1:
                fail(f"positive serial marker missing or non-unique: {marker}")
            positions.append(lines.index(marker))
        if positions != sorted(positions):
            fail("positive serial markers are out of order")
        if any(line.startswith("CAJUNOS_BASE_SYSTEM_FAIL ") for line in lines):
            fail("positive serial contains a failure marker")
    else:
        if lines.count(begin) != 1:
            fail("negative serial lacks its unique begin marker")
        failures = [line for line in lines if line.startswith("CAJUNOS_BASE_SYSTEM_FAIL ")]
        if failures != ["CAJUNOS_BASE_SYSTEM_FAIL cmdline-token"]:
            fail("negative serial lacks exact fail-closed cmdline marker")
        if lines.index(begin) >= lines.index(failures[0]):
            fail("negative failure marker precedes begin marker")
        if any(marker in lines for marker in success[1:]):
            fail("negative serial contains success identity or completion")
    if output is not None:
        atomic_text(output, text)
    print(json.dumps({"kind": kind, "lines": len(lines)}, sort_keys=True))


def dotted(value, key):
    for part in key.split("."):
        if not isinstance(value, dict) or part not in value:
            fail(f"receipt lacks required field: {key}")
        value = value[part]
    return value


def validate_receipt(receipt_path, artifact_path, build_id, *pairs):
    if not pairs or len(pairs) % 2:
        fail("validate-receipt requires exact key/value contract pairs")
    receipt_path = Path(receipt_path)
    artifact = Path(artifact_path)
    metadata = receipt_path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o644
    ):
        fail("base-system receipt is not a plain mode-0644 single-linked file")
    artifact_metadata = artifact.lstat()
    if not stat.S_ISDIR(artifact_metadata.st_mode) or artifact.is_symlink():
        fail("base-system artifact root is not a real directory")
    receipt = load_json(receipt_path)
    expected = dict(zip(pairs[::2], pairs[1::2], strict=True))
    if len(expected) != len(pairs) // 2:
        fail("validate-receipt contains duplicate expected keys")
    topologies = {
        "": {
            "schema", "component", "stage", "build_id", "deployable",
            "diagnostic_only", "target", "source_date_epoch", "source_sets",
            "sources", "orchestration", "dependencies", "kernel", "bootloader",
            "filesystem", "disk", "network", "security_contract", "qemu",
            "build_contract", "reproducibility", "outputs",
        },
        "source_sets": {"bootstrap", "base_system"},
        "source_sets.bootstrap": {"digest", "authentication"},
        "source_sets.base_system": {"digest", "authentication"},
        "sources": {"linux", "busybox", "grub", "gnulib"},
        "sources.linux": {"commit", "tree", "repository"},
        "sources.busybox": {"commit", "tree", "repository"},
        "sources.grub": {"commit", "tree", "repository"},
        "sources.gnulib": {"commit", "tree", "repository", "purpose"},
        "orchestration": {
            "commit", "tree", "recipe_sha256", "gcc_helper_sha256",
            "glibc_helper_sha256", "kernel_fragment_sha256",
            "busybox_fragment_sha256", "overlay_digest",
        },
        "dependencies": {"gcc", "glibc"},
        "dependencies.gcc": {"build_id", "prefix", "receipt", "receipt_sha256"},
        "dependencies.glibc": {"build_id", "snapshot", "receipt", "receipt_sha256"},
        "kernel": {"version", "release", "modules", "root_selector"},
        "bootloader": {"name", "platform", "firmware", "installer", "host_grub_used"},
        "filesystem": {"type", "bytes", "uuid", "journal"},
        "disk": {"format", "bytes", "guid", "bios_boot_partuuid", "root_partuuid"},
        "network": {"driver", "interface", "configuration"},
        "security_contract": {
            "cpu_mitigations", "kaslr", "stack_protector", "fortify_source",
            "hardened_usercopy", "root_password", "ssh",
        },
        "qemu": {
            "path", "sha256", "machine", "accelerator", "cpu", "firmware",
            "positive_boot", "negative_boot", "positive_cmdline", "negative_cmdline",
        },
        "qemu.firmware": {"path", "sha256"},
        "build_contract": {
            "independent_builds", "kernel_kcflags",
            "busybox_install_arch_and_cross_compile_preserved", "busybox_tc",
            "host_contract_sha256", "rootfs_population", "rootfs_hash_seed_locked",
        },
        "reproducibility": {
            "independent_builds", "kernel_identical", "busybox_identical",
            "rootfs_ext4_identical", "gpt_disk_identical", "selectors_modified",
            "rootfs_inventory",
        },
        "reproducibility.rootfs_inventory": {"entries", "digest"},
        "outputs": {"subtree_inventories"},
        "outputs.subtree_inventories": {"boot", "configuration", "licenses", "probe"},
    }
    for key, keys in topologies.items():
        value = receipt if not key else dotted(receipt, key)
        if not isinstance(value, dict) or set(value) != keys:
            fail(f"base-system receipt topology mismatch at {key or '<root>'}")
    bool_paths = {
        "deployable", "diagnostic_only", "kernel.modules",
        "bootloader.host_grub_used", "filesystem.journal",
        "build_contract.busybox_install_arch_and_cross_compile_preserved",
        "build_contract.rootfs_hash_seed_locked", "reproducibility.kernel_identical",
        "reproducibility.busybox_identical", "reproducibility.rootfs_ext4_identical",
        "reproducibility.gpt_disk_identical", "reproducibility.selectors_modified",
    }
    int_paths = {
        "schema", "source_date_epoch", "filesystem.bytes", "disk.bytes",
        "build_contract.independent_builds", "reproducibility.independent_builds",
    }
    for key in bool_paths:
        if type(dotted(receipt, key)) is not bool:
            fail(f"base-system receipt boolean has wrong type: {key}")
    for key in int_paths:
        if type(dotted(receipt, key)) is not int:
            fail(f"base-system receipt integer has wrong type: {key}")
    for key, wanted in expected.items():
        if str(dotted(receipt, key)) != wanted:
            fail(f"base-system receipt mismatch for {key}")
    if receipt.get("schema") != 1 or receipt.get("stage") != "base-system-image":
        fail("base-system receipt identity is invalid")
    if receipt.get("build_id") != build_id:
        fail("base-system receipt build ID is invalid")
    root_names = {path.name for path in artifact.iterdir()}
    if root_names != {"boot", "configuration", "licenses", "probe", "receipt.json"}:
        fail("base-system artifact has unexpected root topology")
    live = {
        name: inventory(artifact / name)
        for name in ("boot", "configuration", "licenses", "probe")
    }
    if receipt.get("outputs", {}).get("subtree_inventories") != live:
        fail("base-system receipt does not bind its artifact subtrees")
    first = load_json(artifact / "configuration/rootfs-a.json")
    second = load_json(artifact / "configuration/rootfs-b.json")
    if first != second or receipt.get("reproducibility", {}).get("rootfs_inventory") != first:
        fail("base-system root filesystem reproducibility record is invalid")
    for kind in ("positive", "negative"):
        raw = artifact / f"probe/{kind}.serial.raw"
        normalized = artifact / f"probe/{kind}.serial.normalized"
        if normalized.read_text(encoding="utf-8") != normalized_serial(raw):
            fail(f"stored {kind} serial normalization is invalid")
    print(json.dumps({"build_id": build_id, "valid": True}, sort_keys=True))


if command == "merge-kconfig":
    if len(arguments) != 2:
        fail("merge-kconfig requires CONFIG FRAGMENT")
    merge_kconfig(*arguments)
elif command == "validate-kernel-config":
    if len(arguments) != 1:
        fail("validate-kernel-config requires CONFIG")
    validate_kernel_config(arguments[0])
elif command == "validate-busybox-config":
    if len(arguments) != 1:
        fail("validate-busybox-config requires CONFIG")
    validate_busybox_config(arguments[0])
elif command == "inventory":
    if len(arguments) != 1:
        fail("inventory requires ROOT")
    print(json.dumps(inventory(arguments[0]), indent=2, sort_keys=True))
elif command == "overlay-inventory":
    if len(arguments) != 1:
        fail("overlay-inventory requires ROOT")
    print(json.dumps(canonical_overlay_inventory(arguments[0]), indent=2, sort_keys=True))
elif command == "canonicalize-root":
    if len(arguments) != 1:
        fail("canonicalize-root requires ROOT")
    canonicalize_root(arguments[0])
elif command == "compare-json":
    if len(arguments) != 2:
        fail("compare-json requires FIRST SECOND")
    if load_json(arguments[0]) != load_json(arguments[1]):
        fail("JSON evidence differs")
elif command == "validate-gpt":
    if len(arguments) != 5:
        fail("validate-gpt requires IMAGE DISK_GUID BIOS_GUID ROOT_GUID ROOT_FIRST")
    validate_gpt(*arguments)
elif command == "install-grub-raw":
    if len(arguments) != 5:
        fail("install-grub-raw requires IMAGE BOOT CORE CORE_LBA MAX_SECTORS")
    install_grub_raw(*arguments)
elif command == "validate-ext4":
    if len(arguments) != 3:
        fail("validate-ext4 requires IMAGE UUID HASH_SEED")
    validate_ext4(*arguments)
elif command == "validate-serial":
    if len(arguments) not in (4, 5):
        fail("validate-serial requires KIND LOG RELEASE BUILD_ID [NORMALIZED]")
    validate_serial(*arguments)
elif command == "validate-receipt":
    if len(arguments) < 5 or len(arguments[3:]) % 2:
        fail("validate-receipt requires RECEIPT ARTIFACT BUILD_ID and key/value pairs")
    validate_receipt(*arguments)
elif command == "build-id":
    if len(arguments) < 1 or len(arguments[1:]) % 2:
        fail("build-id requires LINUX_COMMIT and key/value pairs")
    commit = arguments[0]
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        fail("unsafe Linux commit for build ID")
    fields = dict(zip(arguments[1::2], arguments[2::2], strict=True))
    print(f"base-system-{commit[:12]}-{canonical_digest(fields)[:16]}")
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
  GNULIB_SRCDIR QEMU_AUDIO_DRV QEMU_PATH QEMU_DATA_DIR; do
  unset "$variable"
done

cajunos_root=${CAJUNOS_ROOT:-/srv/cajunos}
target=${CAJUNOS_TARGET:-x86_64-cajunos-linux-gnu}
expected_user=${CAJUNOS_BUILD_USER:-cajunos}
jobs=${CAJUNOS_JOBS:-6}
qemu_timeout=${CAJUNOS_QEMU_TIMEOUT:-90}
bootstrap_manifest=$project_root/manifests/bootstrap.json
bootstrap_lock=$project_root/locks/bootstrap.lock.json
system_manifest=$project_root/manifests/base-system.json
system_lock=$project_root/locks/base-system.lock.json
gcc_helper=$project_root/scripts/build-gcc-complete.sh
glibc_helper=$project_root/scripts/build-glibc-complete.sh
kernel_fragment=$project_root/configs/x86_64-base-system.fragment
busybox_fragment=$project_root/configs/busybox-base-system.fragment
overlay=$project_root/rootfs/base-system
kernel_kcflags='-Wno-constant-logical-operand'
disk_bytes=$((1024 * 1024 * 1024))
rootfs_bytes=$((768 * 1024 * 1024))
disk_guid=6f53d7c2-4ed5-4e54-9a50-d9430b70f101
bios_guid=813e4ae2-9e5f-4f2e-a37f-6e3b570ba101
root_guid=bbf9a847-17bc-4665-8af2-5ed2017ca102
root_uuid=7a1a6d79-2db5-47b7-87f4-7dbdd9595102
root_first_sector=4096
qemu_machine=pc-q35-10.0
qemu_cpu=Nehalem-v1

if [[ $(id -u) -eq 0 || $(id -un) != "$expected_user" ]]; then
  echo "Run this build as the unprivileged $expected_user account" >&2
  exit 70
fi
if [[ $target != x86_64-cajunos-linux-gnu ]]; then
  echo "This stage supports only x86_64-cajunos-linux-gnu" >&2
  exit 71
fi
if [[ ! $jobs =~ ^[1-9][0-9]*$ || ! $qemu_timeout =~ ^[1-9][0-9]*$ ]]; then
  echo "CAJUNOS_JOBS and CAJUNOS_QEMU_TIMEOUT must be positive integers" >&2
  exit 72
fi
for command_name in \
  aclocal ar as autoconf autoheader automake autopoint autoreconf awk bash bc bison chown \
  cmp cp dd debugfs dumpe2fs fakeroot find flex flock g++ gcc gettext git grep \
  help2man install ld libtoolize m4 make mke2fs nm objcopy openssl patch perl pkg-config \
  python3 qemu-system-x86_64 ranlib readelf readlink sed sha256sum sh sgdisk \
  stat tar timeout touch truncate; do
  command -v "$command_name" >/dev/null || {
    echo "Missing required host command: $command_name" >&2
    exit 73
  }
done
for frozen in \
  "$bootstrap_manifest" "$bootstrap_lock" "$system_manifest" "$system_lock" \
  "$kernel_fragment" "$busybox_fragment" "$overlay" "$gcc_helper" "$glibc_helper"; do
  [[ -e $frozen && ! -L $frozen ]] || {
    echo "Missing or symlinked frozen base-system input: $frozen" >&2
    exit 74
  }
done

"$project_root/scripts/fetch.py" validate --root "$cajunos_root" --json >/dev/null
"$project_root/scripts/fetch.py" validate --root "$cajunos_root" \
  --manifest "$system_manifest" --lock "$system_lock" --json >/dev/null
cajunos_root=$(readlink -f -- "$cajunos_root")
exec 8>"$cajunos_root/upstream/.cajunos-source.lock"
flock -n 8 || {
  echo "Another source operation or build owns the source lock" >&2
  exit 75
}
"$project_root/scripts/fetch.py" validate --root "$cajunos_root" >/dev/null
"$project_root/scripts/fetch.py" validate --root "$cajunos_root" \
  --manifest "$system_manifest" --lock "$system_lock" >/dev/null

if [[ -n $(git -C "$project_root" status --porcelain) ]]; then
  echo "Refusing an official build from a dirty orchestration checkout" >&2
  exit 76
fi

upstream=$cajunos_root/upstream
linux_source=$upstream/linux
busybox_source=$upstream/busybox
grub_source=$upstream/grub
gnulib_source=$upstream/gnulib
tools_root=$cajunos_root/tools
sysroot_root=$cajunos_root/sysroot
work_root=$cajunos_root/work
artifacts_root=$cajunos_root/artifacts
logs_root=$cajunos_root/logs
for path in "$linux_source" "$busybox_source" "$grub_source" "$gnulib_source"; do
  [[ -d $path && ! -L $path ]] || {
    echo "Locked source checkout is unavailable: $path" >&2
    exit 77
  }
done

mapfile -t lock_values < <(python3 - "$bootstrap_lock" "$system_lock" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    bootstrap = json.load(stream)
with open(sys.argv[2], encoding="utf-8") as stream:
    system = json.load(stream)
print(bootstrap["source_set_digest"])
print(bootstrap["source_authentication"])
for name in ("linux", "gcc", "glibc", "binutils"):
    item = next(value for value in bootstrap["components"] if value["name"] == name)
    print(item["commit"]); print(item["tree"]); print(item["repository"])
print(system["source_set_digest"])
print(system["source_authentication"])
for name in ("busybox", "grub", "gnulib"):
    item = next(value for value in system["components"] if value["name"] == name)
    print(item["commit"]); print(item["tree"]); print(item["repository"])
PY
)
bootstrap_digest=${lock_values[0]}
bootstrap_auth=${lock_values[1]}
linux_commit=${lock_values[2]}
linux_tree=${lock_values[3]}
linux_repository=${lock_values[4]}
gcc_commit=${lock_values[5]}
gcc_tree=${lock_values[6]}
gcc_repository=${lock_values[7]}
glibc_commit=${lock_values[8]}
glibc_tree=${lock_values[9]}
glibc_repository=${lock_values[10]}
binutils_commit=${lock_values[11]}
binutils_tree=${lock_values[12]}
binutils_repository=${lock_values[13]}
system_digest=${lock_values[14]}
system_auth=${lock_values[15]}
busybox_commit=${lock_values[16]}
busybox_tree=${lock_values[17]}
busybox_repository=${lock_values[18]}
grub_commit=${lock_values[19]}
grub_tree=${lock_values[20]}
grub_repository=${lock_values[21]}
gnulib_commit=${lock_values[22]}
gnulib_tree=${lock_values[23]}
gnulib_repository=${lock_values[24]}

if [[ $bootstrap_auth != authenticated \
   && ${CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES:-} != 1 ]]; then
  echo "Bootstrap cohort contains recorded unauthenticated transports" >&2
  echo "Set CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES=1 after reviewing the lock" >&2
  exit 78
fi
[[ $system_auth == authenticated ]] || {
  echo "Base-system sources must use authenticated transports" >&2
  exit 78
}

# GRUB's bootstrap.conf names this exact Gnulib revision.  Keeping it in the
# separate system lock prevents bootstrap from making an undeclared network
# fetch while leaving the sealed four-component bootstrap cohort untouched.
declared_gnulib=$(sed -n 's/^GNULIB_REVISION=\([0-9a-f]\{40\}\)$/\1/p' \
  "$grub_source/bootstrap.conf")
[[ $declared_gnulib == "$gnulib_commit" ]] || {
  echo "Locked Gnulib does not match GRUB bootstrap.conf" >&2
  exit 79
}

orchestration_commit=$(git -C "$project_root" rev-parse HEAD)
orchestration_tree=$(git -C "$project_root" rev-parse 'HEAD^{tree}')
SOURCE_DATE_EPOCH=$(git -C "$linux_source" show -s --format=%ct "$linux_commit")
export SOURCE_DATE_EPOCH
kernel_version=$(make -s -C "$linux_source" kernelversion)
kernel_release=$kernel_version-cajunos+
build_timestamp=$(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%d %H:%M:%S +0000')

tools_prefix=$(readlink -f -- "$tools_root/current")
cohort_id=${bootstrap_digest#sha256:}
cohort_id=${cohort_id:0:16}
sysroot_selector=$sysroot_root/$cohort_id/current
glibc_snapshot=$(readlink -f -- "$sysroot_selector")
for path in "$tools_prefix" "$glibc_snapshot"; do
  [[ -d $path && ! -L $path ]] || {
    echo "Selected immutable dependency is unavailable: $path" >&2
    exit 80
  }
done
gcc_driver_reported=$tools_prefix/bin/$target-gcc
strip_driver_reported=$tools_prefix/bin/$target-strip
readelf_driver_reported=$tools_prefix/bin/$target-readelf
for tool in "$gcc_driver_reported" "$strip_driver_reported" "$readelf_driver_reported"; do
  resolved=$(readlink -f -- "$tool")
  [[ -x $tool && $resolved == "$tools_root/"* && -f $resolved && ! -L $resolved \
     && $(stat -c %h "$resolved") == 1 ]] || {
    echo "Selected toolchain executable escapes its sealed tools roots: $tool" >&2
    exit 80
  }
done
gcc_driver=$(readlink -f -- "$gcc_driver_reported")
strip_driver=$(readlink -f -- "$strip_driver_reported")
readelf_driver=$(readlink -f -- "$readelf_driver_reported")
busybox_extra_cflags="--sysroot=$glibc_snapshot -march=x86-64-v2 -mtune=generic -fdebug-prefix-map=$cajunos_root=/usr/src/cajunos"
busybox_extra_ldflags="--sysroot=$glibc_snapshot -static"
tools_build_id=$(basename -- "$tools_prefix")
glibc_build_id=$(basename -- "$glibc_snapshot")
tools_receipt=$artifacts_root/$tools_build_id/receipt.json
glibc_receipt=$artifacts_root/$glibc_build_id/receipt.json
tools_licenses=$artifacts_root/$tools_build_id/licenses
glibc_licenses=$artifacts_root/$glibc_build_id/licenses
for receipt in "$tools_receipt" "$glibc_receipt"; do
  [[ -f $receipt && ! -L $receipt ]] || {
    echo "Selected dependency receipt is unavailable: $receipt" >&2
    exit 80
  }
done
for license_root in "$tools_licenses" "$glibc_licenses"; do
  [[ -d $license_root && ! -L $license_root ]] || {
    echo "Selected dependency license bundle is unavailable: $license_root" >&2
    exit 80
  }
done
mapfile -t dependency_receipt_values < <(python3 - "$tools_receipt" "$glibc_receipt" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    gcc = json.load(stream)
with open(sys.argv[2], encoding="utf-8") as stream:
    glibc = json.load(stream)
print(gcc.get("base_prefix", ""))
print(gcc.get("gcc_version", ""))
print(gcc.get("sysroot_snapshot", ""))
print(glibc.get("base_snapshot", ""))
PY
)
gcc_base_prefix=${dependency_receipt_values[0]}
gcc_version=${dependency_receipt_values[1]}
gcc_receipt_sysroot=${dependency_receipt_values[2]}
glibc_base_snapshot=${dependency_receipt_values[3]}
[[ $gcc_base_prefix == "$tools_root/"* \
   && -d $gcc_base_prefix && ! -L $gcc_base_prefix ]] || {
  echo "GCC receipt base is not confined to the sealed tools root" >&2
  exit 80
}
[[ $glibc_base_snapshot == "$sysroot_root/$cohort_id/snapshots/"* \
   && -d $glibc_base_snapshot && ! -L $glibc_base_snapshot ]] || {
  echo "glibc receipt base is not confined to the sealed cohort snapshots" >&2
  exit 80
}
[[ $gcc_receipt_sysroot == "$glibc_snapshot" ]] || {
  echo "Selected complete GCC is not bound to the active complete glibc snapshot" >&2
  exit 80
}
gcc_helper_sha256=$(sha256sum "$gcc_helper" | awk '{print $1}')
glibc_helper_sha256=$(sha256sum "$glibc_helper" | awk '{print $1}')
validate_live_dependencies() {
  "$gcc_helper" --internal-python validate-completed \
    "$tools_receipt" "$tools_prefix" "$gcc_base_prefix" "$tools_root" \
    "$target" "$gcc_version" \
    schema 1 component gcc stage complete build_id "$tools_build_id" \
    source_commit "$gcc_commit" source_tree "$gcc_tree" \
    source_repository "$gcc_repository" source_set_digest "$bootstrap_digest" \
    source_authentication "$bootstrap_auth" target "$target" \
    prefix "$tools_prefix" sysroot_snapshot "$glibc_snapshot" >/dev/null
  "$glibc_helper" --internal-python validate-completed \
    "$glibc_receipt" "$glibc_snapshot" "$glibc_base_snapshot" \
    schema 1 component glibc stage complete build_id "$glibc_build_id" \
    source_commit "$glibc_commit" source_tree "$glibc_tree" \
    source_repository "$glibc_repository" source_set_digest "$bootstrap_digest" \
    source_authentication "$bootstrap_auth" target "$target" \
    snapshot "$glibc_snapshot" >/dev/null
}
validate_live_dependencies

initial_tools_selector=$(readlink -- "$tools_root/current")
initial_sysroot_selector=$(readlink -- "$sysroot_selector")
recipe_sha256=$(sha256sum "$script_path" | awk '{print $1}')
kernel_fragment_sha256=$(sha256sum "$kernel_fragment" | awk '{print $1}')
busybox_fragment_sha256=$(sha256sum "$busybox_fragment" | awk '{print $1}')
overlay_inventory=$("$script_path" --internal-python overlay-inventory "$overlay")
overlay_digest=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["digest"])' <<<"$overlay_inventory")
tools_receipt_sha256=$(sha256sum "$tools_receipt" | awk '{print $1}')
glibc_receipt_sha256=$(sha256sum "$glibc_receipt" | awk '{print $1}')

qemu_path=$(readlink -f -- "$(command -v qemu-system-x86_64)")
qemu_bios=/usr/share/seabios/bios-256k.bin
[[ -f $qemu_bios && ! -L $qemu_bios ]] || {
  echo "Pinned SeaBIOS input is unavailable" >&2
  exit 82
}
qemu_sha256=$(sha256sum "$qemu_path" | awk '{print $1}')
qemu_bios_sha256=$(sha256sum "$qemu_bios" | awk '{print $1}')
host_tool_names=(
  aclocal ar as autoconf autoheader automake autopoint autoreconf awk bash bc bison chown
  cmp cp dd debugfs dumpe2fs fakeroot find flex flock g++ gcc gettext git grep
  help2man install ld libtoolize m4 make mke2fs nm objcopy openssl patch perl pkg-config
  python3 qemu-system-x86_64 ranlib readelf readlink sed sha256sum sh sgdisk
  stat tar timeout touch truncate
)
calculate_host_contract() {
  {
    local tool_name reported resolved
    for tool_name in "${host_tool_names[@]}"; do
      reported=$(command -v "$tool_name")
      resolved=$(readlink -f -- "$reported")
      [[ -f $resolved && ! -L $resolved && -x $resolved ]] || return 1
      printf '%s\0%s\0%s\0%s\0' "$tool_name" "$reported" "$resolved" \
        "$(sha256sum "$resolved" | awk '{print $1}')"
    done
    printf '%s\0%s\0' "$qemu_bios" "$(sha256sum "$qemu_bios" | awk '{print $1}')"
    printf '%s\0%s\0%s\0%s\0%s\0%s\0' \
      "$disk_bytes" "$rootfs_bytes" "$disk_guid" "$bios_guid" "$root_guid" "$root_uuid"
    printf '%s\0%s\0%s\0%s\0' "$qemu_machine" "$qemu_cpu" "$kernel_kcflags" "$root_first_sector"
  } | sha256sum | awk '{print $1}'
}
host_contract_sha256=$(calculate_host_contract)
build_id=$("$script_path" --internal-python build-id "$linux_commit" \
  bootstrap_digest "$bootstrap_digest" system_digest "$system_digest" \
  orchestration_commit "$orchestration_commit" orchestration_tree "$orchestration_tree" \
  recipe_sha256 "$recipe_sha256" kernel_fragment_sha256 "$kernel_fragment_sha256" \
  gcc_helper_sha256 "$gcc_helper_sha256" glibc_helper_sha256 "$glibc_helper_sha256" \
  busybox_fragment_sha256 "$busybox_fragment_sha256" overlay_digest "$overlay_digest" \
  busybox_extra_cflags "$busybox_extra_cflags" \
  busybox_extra_ldflags "$busybox_extra_ldflags" \
  tools_receipt_sha256 "$tools_receipt_sha256" \
  glibc_receipt_sha256 "$glibc_receipt_sha256" \
  host_contract_sha256 "$host_contract_sha256")

run_id=${CAJUNOS_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
[[ $run_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || {
  echo "Unsafe CAJUNOS_RUN_ID: $run_id" >&2
  exit 81
}
build_final=$work_root/$build_id
artifact_final=$artifacts_root/$build_id
receipt_final=$artifact_final/receipt.json
temporary_root=$work_root/.tmp-$build_id-$$
artifact_temporary=$artifacts_root/.tmp-$build_id-$$
failed_root=$work_root/.failed-$build_id-$$
failed_artifact=$artifacts_root/.failed-$build_id-$$
log_dir=$logs_root/$run_id
log_file=$log_dir/base-system-image.log

positive_cmdline="root=PARTUUID=$root_guid rw rootwait console=ttyS0,115200 earlycon=uart8250,io,0x3f8,115200n8 panic=-1 cajunos.base_system=1"
negative_cmdline="root=PARTUUID=$root_guid rw rootwait console=ttyS0,115200 earlycon=uart8250,io,0x3f8,115200n8 panic=-1 cajunos.base_system=0"

validate_inputs() {
  "$project_root/scripts/fetch.py" validate --root "$cajunos_root" --json >/dev/null
  "$project_root/scripts/fetch.py" validate --root "$cajunos_root" \
    --manifest "$system_manifest" --lock "$system_lock" --json >/dev/null
  if ! [[ -z $(git -C "$project_root" status --porcelain) \
     && -f $qemu_bios && ! -L $qemu_bios \
     && $(git -C "$project_root" rev-parse HEAD) == "$orchestration_commit" \
     && $(git -C "$project_root" rev-parse 'HEAD^{tree}') == "$orchestration_tree" \
     && $(sha256sum "$script_path" | awk '{print $1}') == "$recipe_sha256" \
     && $(sha256sum "$gcc_helper" | awk '{print $1}') == "$gcc_helper_sha256" \
     && $(sha256sum "$glibc_helper" | awk '{print $1}') == "$glibc_helper_sha256" \
     && $(sha256sum "$kernel_fragment" | awk '{print $1}') == "$kernel_fragment_sha256" \
     && $(sha256sum "$busybox_fragment" | awk '{print $1}') == "$busybox_fragment_sha256" \
     && $(sha256sum "$tools_receipt" | awk '{print $1}') == "$tools_receipt_sha256" \
     && $(sha256sum "$glibc_receipt" | awk '{print $1}') == "$glibc_receipt_sha256" \
     && $(calculate_host_contract) == "$host_contract_sha256" \
     && $(readlink -- "$tools_root/current") == "$initial_tools_selector" \
     && $(readlink -- "$sysroot_selector") == "$initial_sysroot_selector" ]]; then
    return 1
  fi
  validate_live_dependencies
}

qemu_common=(
  -no-user-config -nodefaults
  -machine "$qemu_machine,accel=tcg"
  -cpu "$qemu_cpu" -m 512M -smp 2
  -bios "$qemu_bios"
  -display none -monitor none
  -chardev stdio,id=serial0,signal=off,mux=off
  -device isa-serial,chardev=serial0,iobase=0x3f8,irq=4
  -netdev user,id=net0
  -device virtio-net-pci,netdev=net0
  -no-reboot
)

run_qemu() {
  local kind=$1 boot_dir=$2 raw=$3 normalized=$4
  local cmdline=$negative_cmdline
  local extra=()
  local disk_before disk_after
  if [[ $kind == positive ]]; then
    # Positive evidence exercises the actual GPT/BIOS/GRUB path.  Negative
    # evidence direct-loads the same kernel against the same root partition so
    # only the fail-closed init token changes.
    extra=()
  else
    extra=(-kernel "$boot_dir/bzImage" -append "$cmdline")
  fi
  disk_before=$(sha256sum "$boot_dir/disk.raw" | awk '{print $1}')
  set +e
  env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C TZ=UTC \
    timeout --signal=TERM --kill-after=5 "$qemu_timeout" \
    "$qemu_path" "${qemu_common[@]}" \
      -drive "file=$boot_dir/disk.raw,format=raw,if=none,id=disk0,snapshot=on" \
      -device virtio-blk-pci,drive=disk0 \
      "${extra[@]}" </dev/null >"$raw" 2>&1
  local status=$?
  set -e
  if [[ $status -ne 0 && $status -ne 124 ]]; then
    echo "QEMU $kind probe exited unexpectedly: $status" >&2
    return 1
  fi
  disk_after=$(sha256sum "$boot_dir/disk.raw" | awk '{print $1}')
  [[ $disk_after == "$disk_before" ]] || {
    echo "QEMU $kind probe mutated the sealed raw disk" >&2
    return 1
  }
  "$script_path" --internal-python validate-serial \
    "$kind" "$raw" "$kernel_release" "$build_id" "$normalized" >/dev/null
}

validate_receipt_contract() {
  local receipt=$1 artifact=$2
  "$script_path" --internal-python validate-receipt \
    "$receipt" "$artifact" "$build_id" \
    schema 1 component system-image stage base-system-image build_id "$build_id" \
    deployable True diagnostic_only False target "$target" \
    source_date_epoch "$SOURCE_DATE_EPOCH" \
    source_sets.bootstrap.digest "$bootstrap_digest" \
    source_sets.bootstrap.authentication "$bootstrap_auth" \
    source_sets.base_system.digest "$system_digest" \
    source_sets.base_system.authentication "$system_auth" \
    sources.linux.commit "$linux_commit" sources.linux.tree "$linux_tree" \
    sources.linux.repository "$linux_repository" \
    sources.busybox.commit "$busybox_commit" sources.busybox.tree "$busybox_tree" \
    sources.busybox.repository "$busybox_repository" \
    sources.grub.commit "$grub_commit" sources.grub.tree "$grub_tree" \
    sources.grub.repository "$grub_repository" \
    sources.gnulib.commit "$gnulib_commit" sources.gnulib.tree "$gnulib_tree" \
    sources.gnulib.repository "$gnulib_repository" \
    sources.gnulib.purpose 'GRUB bootstrap.conf input' \
    orchestration.commit "$orchestration_commit" orchestration.tree "$orchestration_tree" \
    orchestration.recipe_sha256 "$recipe_sha256" \
    orchestration.gcc_helper_sha256 "$gcc_helper_sha256" \
    orchestration.glibc_helper_sha256 "$glibc_helper_sha256" \
    orchestration.kernel_fragment_sha256 "$kernel_fragment_sha256" \
    orchestration.busybox_fragment_sha256 "$busybox_fragment_sha256" \
    orchestration.overlay_digest "$overlay_digest" \
    dependencies.gcc.build_id "$tools_build_id" dependencies.gcc.prefix "$tools_prefix" \
    dependencies.gcc.receipt "$tools_receipt" \
    dependencies.gcc.receipt_sha256 "$tools_receipt_sha256" \
    dependencies.glibc.build_id "$glibc_build_id" \
    dependencies.glibc.snapshot "$glibc_snapshot" \
    dependencies.glibc.receipt "$glibc_receipt" \
    dependencies.glibc.receipt_sha256 "$glibc_receipt_sha256" \
    kernel.version "$kernel_version" kernel.release "$kernel_release" \
    kernel.modules False kernel.root_selector PARTUUID \
    bootloader.name GRUB bootloader.platform i386-pc bootloader.firmware SeaBIOS \
    bootloader.installer source-built-grub-mkimage-and-fixed-layout-setup.c-subset \
    bootloader.host_grub_used False \
    filesystem.type ext4 filesystem.bytes "$rootfs_bytes" filesystem.uuid "$root_uuid" \
    filesystem.journal False disk.format raw-gpt-bios disk.bytes "$disk_bytes" \
    disk.guid "$disk_guid" disk.bios_boot_partuuid "$bios_guid" \
    disk.root_partuuid "$root_guid" \
    network.driver virtio-net network.interface eth0 \
    network.configuration udhcpc-dhcpv4 \
    security_contract.cpu_mitigations enabled security_contract.kaslr enabled \
    security_contract.stack_protector strong security_contract.fortify_source enabled \
    security_contract.hardened_usercopy enabled security_contract.root_password locked \
    security_contract.ssh deferred-to-stage-9b \
    qemu.path "$qemu_path" qemu.sha256 "$qemu_sha256" \
    qemu.machine "$qemu_machine" qemu.accelerator tcg qemu.cpu "$qemu_cpu" \
    qemu.firmware.path "$qemu_bios" qemu.firmware.sha256 "$qemu_bios_sha256" \
    qemu.positive_boot disk-only-gpt-bios-grub \
    qemu.negative_boot direct-kernel-same-gpt-root \
    qemu.positive_cmdline "$positive_cmdline" qemu.negative_cmdline "$negative_cmdline" \
    build_contract.independent_builds 2 \
    build_contract.kernel_kcflags "$kernel_kcflags" \
    build_contract.busybox_install_arch_and_cross_compile_preserved True \
    build_contract.busybox_tc disabled-for-linux-7.2-uapi-compatibility \
    build_contract.host_contract_sha256 "$host_contract_sha256" \
    build_contract.rootfs_population fakeroot-mke2fs-d \
    build_contract.rootfs_hash_seed_locked True \
    reproducibility.independent_builds 2 reproducibility.kernel_identical True \
    reproducibility.busybox_identical True reproducibility.rootfs_ext4_identical True \
    reproducibility.gpt_disk_identical True reproducibility.selectors_modified False
}

validate_candidate() {
  local artifact=$1 build=$2
  cmp -- "$build/bzImage-a" "$build/bzImage-b"
  cmp -- "$build/kernel-a.config" "$build/kernel-b.config"
  cmp -- "$build/busybox-install-a/bin/busybox" \
    "$build/busybox-install-b/bin/busybox"
  cmp -- "$build/busybox-a.config" "$build/busybox-b.config"
  cmp -- "$build/root-a.ext4" "$build/root-b.ext4"
  cmp -- "$build/disk-a.raw" "$build/disk-b.raw"
  cmp -- "$artifact/boot/bzImage" "$build/bzImage-a"
  cmp -- "$artifact/boot/disk.raw" "$build/disk-a.raw"
  cmp -- "$artifact/boot/kernel.config" "$build/kernel-a.config"
  cmp -- "$artifact/boot/busybox.config" "$build/busybox-a.config"
  cmp -- "$artifact/boot/grub.cfg" "$build/root-a/boot/grub/grub.cfg"
  validate_receipt_contract "$artifact/receipt.json" "$artifact" >/dev/null
  "$script_path" --internal-python validate-kernel-config \
    "$artifact/boot/kernel.config" >/dev/null
  "$script_path" --internal-python validate-busybox-config \
    "$artifact/boot/busybox.config" >/dev/null
  "$script_path" --internal-python validate-gpt \
    "$artifact/boot/disk.raw" "$disk_guid" "$bios_guid" \
    "$root_guid" "$root_first_sector" >/dev/null
  "$script_path" --internal-python inventory "$build/root-a" \
    >"$build/replay-root-a.json"
  "$script_path" --internal-python inventory "$build/root-b" \
    >"$build/replay-root-b.json"
  "$script_path" --internal-python compare-json \
    "$artifact/configuration/rootfs-a.json" "$build/replay-root-a.json"
  "$script_path" --internal-python compare-json \
    "$artifact/configuration/rootfs-b.json" "$build/replay-root-b.json"
  rm -- "$build/replay-root-a.json" "$build/replay-root-b.json"
  "$script_path" --internal-python validate-serial positive \
    "$artifact/probe/positive.serial.raw" "$kernel_release" "$build_id" >/dev/null
  "$script_path" --internal-python validate-serial negative \
    "$artifact/probe/negative.serial.raw" "$kernel_release" "$build_id" >/dev/null
}

validate_complete() {
  validate_inputs || return 1
  validate_candidate "$artifact_final" "$build_final"
  local replay=$work_root/.replay-$build_id-$$
  mkdir -- "$replay"
  if ! (
    set -Eeuo pipefail
    "$script_path" --internal-python inventory "$build_final/root-a" >"$replay/root-a.json"
    "$script_path" --internal-python inventory "$build_final/root-b" >"$replay/root-b.json"
    "$script_path" --internal-python compare-json \
      "$artifact_final/configuration/rootfs-a.json" "$replay/root-a.json"
    "$script_path" --internal-python compare-json \
      "$artifact_final/configuration/rootfs-b.json" "$replay/root-b.json"
    run_qemu positive "$artifact_final/boot" \
      "$replay/positive.raw" "$replay/positive.normalized"
    run_qemu negative "$artifact_final/boot" \
      "$replay/negative.raw" "$replay/negative.normalized"
  ); then
    mv -T -- "$replay" "$work_root/.failed-replay-$build_id-$$"
    return 1
  fi
  rm -rf -- "$replay"
  validate_inputs
}

exec 9>"$work_root/.cajunos-build.lock"
flock -n 9 || {
  echo "Another CajunOS build owns the global build lock" >&2
  exit 83
}

if [[ -d $build_final && ! -L $build_final \
   && -d $artifact_final && ! -L $artifact_final \
   && -f $receipt_final && ! -L $receipt_final ]]; then
  validate_complete
  echo "CAJUNOS_BASE_SYSTEM_ALREADY_COMPLETE build_id=$build_id"
  exit 0
fi
if [[ -e $build_final || -L $build_final || -e $artifact_final || -L $artifact_final ]]; then
  echo "Refusing incomplete or structurally invalid prior base-system result" >&2
  exit 84
fi
for candidate_path in \
  "$temporary_root" "$artifact_temporary" "$failed_root" "$failed_artifact"; do
  [[ ! -e $candidate_path && ! -L $candidate_path ]] || {
    echo "Refusing colliding base-system work or quarantine path: $candidate_path" >&2
    exit 84
  }
done

mkdir -p -- "$log_dir"
exec > >(tee -a "$log_file") 2>&1
echo "build_id=$build_id"
echo "linux_source=$linux_commit"
echo "base_system_sources=$system_digest"
echo "source_date_epoch=$SOURCE_DATE_EPOCH"

published=0
cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  if [[ $status -ne 0 ]]; then
    if [[ -d $temporary_root && ! -L $temporary_root ]]; then
      mv -T -- "$temporary_root" "$failed_root"
      echo "Quarantined failed work at $failed_root" >&2
    fi
    if [[ -d $artifact_temporary && ! -L $artifact_temporary ]]; then
      mv -T -- "$artifact_temporary" "$failed_artifact"
      echo "Quarantined failed artifact at $failed_artifact" >&2
    fi
    if [[ $published == 1 ]]; then
      if [[ -d $build_final && ! -L $build_final ]]; then
        mv -T -- "$build_final" "$failed_root"
        echo "Quarantined failed published work at $failed_root" >&2
      fi
      if [[ -d $artifact_final && ! -L $artifact_final ]]; then
        mv -T -- "$artifact_final" "$failed_artifact"
        echo "Quarantined failed published artifact at $failed_artifact" >&2
      fi
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

mkdir -- "$temporary_root" "$artifact_temporary"

build_kernel() {
  local label=$1
  local build=$temporary_root/kernel-$label
  mkdir -- "$build"
  env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    make -s -C "$linux_source" O="$build" ARCH=x86_64 \
      CROSS_COMPILE="$tools_prefix/bin/$target-" x86_64_defconfig
  "$script_path" --internal-python merge-kconfig "$build/.config" "$kernel_fragment"
  env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    make -s -C "$linux_source" O="$build" ARCH=x86_64 \
      CROSS_COMPILE="$tools_prefix/bin/$target-" olddefconfig
  "$script_path" --internal-python validate-kernel-config "$build/.config" >/dev/null
  env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    KBUILD_BUILD_USER=cajunos KBUILD_BUILD_HOST=forge KBUILD_BUILD_VERSION=1 \
    KBUILD_BUILD_TIMESTAMP="$build_timestamp" KCONFIG_NOTIMESTAMP=1 \
    KCFLAGS="$kernel_kcflags -ffile-prefix-map=$linux_source=/usr/src/linux -fmacro-prefix-map=$linux_source=/usr/src/linux -ffile-prefix-map=$build=/usr/src/linux-build -fmacro-prefix-map=$build=/usr/src/linux-build" \
    make -C "$linux_source" O="$build" ARCH=x86_64 \
      CROSS_COMPILE="$tools_prefix/bin/$target-" -j"$jobs" bzImage
  cp -- "$build/arch/x86/boot/bzImage" "$temporary_root/bzImage-$label"
  cp -- "$build/.config" "$temporary_root/kernel-$label.config"
  chmod 0644 "$temporary_root/bzImage-$label" "$temporary_root/kernel-$label.config"
}

build_busybox() {
  local label=$1
  local build=$temporary_root/busybox-$label
  local install_root=$temporary_root/busybox-install-$label
  mkdir -- "$build" "$install_root"
  env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    make -s -C "$busybox_source" O="$build" ARCH=x86_64 \
      CROSS_COMPILE="$tools_prefix/bin/$target-" allnoconfig
  "$script_path" --internal-python merge-kconfig "$build/.config" "$busybox_fragment"
  env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    make -s -C "$busybox_source" O="$build" ARCH=x86_64 \
      CROSS_COMPILE="$tools_prefix/bin/$target-" olddefconfig
  "$script_path" --internal-python validate-busybox-config "$build/.config" >/dev/null
  env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    KBUILD_BUILD_TIMESTAMP="$build_timestamp" \
    make -C "$busybox_source" O="$build" ARCH=x86_64 \
      CROSS_COMPILE="$tools_prefix/bin/$target-" \
      EXTRA_CFLAGS="$busybox_extra_cflags" \
      EXTRA_LDFLAGS="$busybox_extra_ldflags" -j"$jobs" busybox
  "$strip_driver" --strip-all "$build/busybox"
  # ARCH and CROSS_COMPILE are mandatory here too.  Omitting them makes
  # upstream's install dependency silently rebuild BusyBox with the host GCC.
  env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    make -s -C "$busybox_source" O="$build" ARCH=x86_64 \
      CROSS_COMPILE="$tools_prefix/bin/$target-" \
      EXTRA_CFLAGS="$busybox_extra_cflags" \
      EXTRA_LDFLAGS="$busybox_extra_ldflags" \
      CONFIG_PREFIX="$install_root" install
  "$readelf_driver" -hW "$install_root/bin/busybox" | grep -q 'Machine:.*Advanced Micro Devices X86-64'
  if "$readelf_driver" -dW "$install_root/bin/busybox" 2>/dev/null | grep -q NEEDED; then
    echo "BusyBox is not static" >&2
    return 1
  fi
  cp -- "$build/.config" "$temporary_root/busybox-$label.config"
  chmod 0644 "$temporary_root/busybox-$label.config"
}

build_grub() {
  local label=$1
  local source_copy=$temporary_root/grub-source-$label
  local build=$temporary_root/grub-build-$label
  local prefix=$temporary_root/grub-install-$label
  mkdir -- "$source_copy" "$build" "$prefix"
  git -C "$grub_source" archive "$grub_commit" | tar -x -C "$source_copy"
  find "$source_copy" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  (
    cd "$source_copy"
    env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
      GNULIB_SRCDIR="$gnulib_source" ./bootstrap
  )
  (
    cd "$build"
    env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
      "$source_copy/configure" \
        --prefix="$prefix" --target=i386 --with-platform=pc \
        --disable-werror --disable-nls --disable-device-mapper \
        --disable-grub-mount --disable-grub-mkfont
    env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
      make -j"$jobs"
    env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
      make install
  )
  [[ -x $prefix/bin/grub-mkimage \
     && -f $prefix/lib/grub/i386-pc/boot.img ]] || {
    echo "Source-built GRUB lacks required PC BIOS tools" >&2
    return 1
  }
}

make_root() {
  local label=$1
  local root=$temporary_root/root-$label
  mkdir -- "$root"
  cp -a -- "$temporary_root/busybox-install-$label/." "$root/"
  cp -a -- "$overlay/." "$root/"
  install -d -m 0755 \
    "$root/boot/grub" "$root/dev" "$root/proc" "$root/sys" "$root/run" \
    "$root/root" "$root/tmp" "$root/var" "$root/usr" "$root/usr/bin" \
    "$root/usr/sbin"
  install -m 0644 "$temporary_root/bzImage-$label" "$root/boot/vmlinuz-$kernel_release"
  printf '%s\n' "$build_id" >"$root/etc/cajunos-build-id"
  printf '%s\n' "$root_guid" >"$root/etc/cajunos-root-partuuid"
  cat >"$root/boot/grub/grub.cfg" <<EOF
serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1
terminal_input serial
terminal_output serial
set timeout=0
set default=0
search --no-floppy --fs-uuid --set=root $root_uuid
menuentry 'CajunOS base system' {
    linux /boot/vmlinuz-$kernel_release $positive_cmdline
}
EOF
  "$script_path" --internal-python canonicalize-root "$root" \
    >"$temporary_root/root-$label.json"
  find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
}

make_ext4() {
  local label=$1
  local root=$temporary_root/root-$label
  local image=$temporary_root/root-$label.ext4
  find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  truncate -s "$rootfs_bytes" "$image"
  fakeroot -- sh -ceu '
    chown -R 0:0 "$1"
    E2FSPROGS_FAKE_TIME="$2" /usr/sbin/mke2fs \
      -q -t ext4 -b 4096 -I 256 -m 0 -L CAJUNOS_ROOT -U "$3" \
      -E lazy_itable_init=0,root_owner=0:0,hash_seed=4a696d42-6f75-4769-8f73-43616a756e21 \
      -O "^has_journal,^resize_inode,^orphan_file,^metadata_csum_seed" \
      -d "$1" "$4"
  ' sh "$root" "$SOURCE_DATE_EPOCH" "$root_uuid" "$image"
  chmod 0644 "$image"
  "$script_path" --internal-python validate-ext4 "$image" "$root_uuid" \
    4a696d42-6f75-4769-8f73-43616a756e21 >/dev/null
}

make_disk() {
  local label=$1
  local disk=$temporary_root/disk-$label.raw
  local grub_prefix=$temporary_root/grub-install-$label
  local setup=$temporary_root/grub-setup-$label
  truncate -s "$disk_bytes" "$disk"
  /usr/sbin/sgdisk --zap-all --clear --set-alignment=1 \
    --disk-guid="$disk_guid" \
    --new=1:2048:4095 --typecode=1:ef02 --change-name=1:BIOS-BOOT \
    --partition-guid=1:"$bios_guid" \
    --new=2:"$root_first_sector":0 --typecode=2:8300 --change-name=2:CAJUNOS-ROOT \
    --partition-guid=2:"$root_guid" "$disk" >/dev/null
  dd if="$temporary_root/root-$label.ext4" of="$disk" bs=512 \
    seek="$root_first_sector" conv=notrunc status=none
  mkdir -- "$setup"
  cp -- "$grub_prefix/lib/grub/i386-pc/boot.img" "$setup/boot.img"
  cat >"$setup/early.cfg" <<EOF
search --no-floppy --fs-uuid --set=root $root_uuid
set prefix=(\$root)/boot/grub
configfile \$prefix/grub.cfg
EOF
  "$grub_prefix/bin/grub-mkimage" \
    --format=i386-pc --directory="$grub_prefix/lib/grub/i386-pc" \
    --prefix=/boot/grub --config="$setup/early.cfg" --output="$setup/core.img" \
    biosdisk part_gpt ext2 normal configfile linux search search_fs_uuid serial terminal
  "$script_path" --internal-python install-grub-raw \
    "$disk" "$setup/boot.img" "$setup/core.img" 2048 2048 \
    >"$setup/install.json"
  chmod 0644 "$disk"
  "$script_path" --internal-python validate-gpt \
    "$disk" "$disk_guid" "$bios_guid" "$root_guid" "$root_first_sector" >/dev/null
}

build_kernel a
build_kernel b
cmp -- "$temporary_root/bzImage-a" "$temporary_root/bzImage-b"
cmp -- "$temporary_root/kernel-a.config" "$temporary_root/kernel-b.config"
build_busybox a
build_busybox b
cmp -- "$temporary_root/busybox-install-a/bin/busybox" \
  "$temporary_root/busybox-install-b/bin/busybox"
cmp -- "$temporary_root/busybox-a.config" "$temporary_root/busybox-b.config"
build_grub a
build_grub b
make_root a
make_root b
"$script_path" --internal-python compare-json \
  "$temporary_root/root-a.json" "$temporary_root/root-b.json"
make_ext4 a
make_ext4 b
cmp -- "$temporary_root/root-a.ext4" "$temporary_root/root-b.ext4"
make_disk a
make_disk b
cmp -- "$temporary_root/disk-a.raw" "$temporary_root/disk-b.raw"

mkdir -p -- \
  "$artifact_temporary/boot" "$artifact_temporary/configuration" \
  "$artifact_temporary/licenses/bootstrap" "$artifact_temporary/licenses/system" \
  "$artifact_temporary/licenses/dependencies/gcc" \
  "$artifact_temporary/licenses/dependencies/glibc" \
  "$artifact_temporary/probe"
install -m 0644 "$temporary_root/bzImage-a" "$artifact_temporary/boot/bzImage"
install -m 0644 "$temporary_root/disk-a.raw" "$artifact_temporary/boot/disk.raw"
install -m 0644 "$temporary_root/kernel-a.config" "$artifact_temporary/boot/kernel.config"
install -m 0644 "$temporary_root/busybox-a.config" "$artifact_temporary/boot/busybox.config"
install -m 0644 "$temporary_root/root-a/boot/grub/grub.cfg" "$artifact_temporary/boot/grub.cfg"
install -m 0644 "$temporary_root/root-a.json" "$artifact_temporary/configuration/rootfs-a.json"
install -m 0644 "$temporary_root/root-b.json" "$artifact_temporary/configuration/rootfs-b.json"
printf '%s\n' "$overlay_inventory" >"$artifact_temporary/configuration/overlay.json"
git -C "$linux_source" archive "$linux_commit" -- COPYING LICENSES | \
  tar -x -C "$artifact_temporary/licenses/bootstrap"
git -C "$busybox_source" archive "$busybox_commit" -- LICENSE | \
  tar -x -C "$artifact_temporary/licenses/system"
mkdir -- "$artifact_temporary/licenses/system/grub" "$artifact_temporary/licenses/system/gnulib"
git -C "$grub_source" archive "$grub_commit" -- COPYING | \
  tar -x -C "$artifact_temporary/licenses/system/grub"
git -C "$gnulib_source" archive "$gnulib_commit" -- COPYING | \
  tar -x -C "$artifact_temporary/licenses/system/gnulib"
cp -a -- "$tools_licenses/." "$artifact_temporary/licenses/dependencies/gcc/"
cp -a -- "$glibc_licenses/." "$artifact_temporary/licenses/dependencies/glibc/"

run_qemu positive "$artifact_temporary/boot" \
  "$artifact_temporary/probe/positive.serial.raw" \
  "$artifact_temporary/probe/positive.serial.normalized"
run_qemu negative "$artifact_temporary/boot" \
  "$artifact_temporary/probe/negative.serial.raw" \
  "$artifact_temporary/probe/negative.serial.normalized"

export CAJUNOS_BASE_SYSTEM_SCRIPT=$script_path
export CAJUNOS_BASE_SYSTEM_RECEIPT
export CAJUNOS_RECEIPT_BOOTSTRAP_DIGEST=$bootstrap_digest
export CAJUNOS_RECEIPT_BOOTSTRAP_AUTH=$bootstrap_auth
export CAJUNOS_RECEIPT_SYSTEM_DIGEST=$system_digest
export CAJUNOS_RECEIPT_SYSTEM_AUTH=$system_auth
export CAJUNOS_RECEIPT_LINUX_COMMIT=$linux_commit
export CAJUNOS_RECEIPT_LINUX_TREE=$linux_tree
export CAJUNOS_RECEIPT_LINUX_REPOSITORY=$linux_repository
export CAJUNOS_RECEIPT_BUSYBOX_COMMIT=$busybox_commit
export CAJUNOS_RECEIPT_BUSYBOX_TREE=$busybox_tree
export CAJUNOS_RECEIPT_BUSYBOX_REPOSITORY=$busybox_repository
export CAJUNOS_RECEIPT_GRUB_COMMIT=$grub_commit
export CAJUNOS_RECEIPT_GRUB_TREE=$grub_tree
export CAJUNOS_RECEIPT_GRUB_REPOSITORY=$grub_repository
export CAJUNOS_RECEIPT_GNULIB_COMMIT=$gnulib_commit
export CAJUNOS_RECEIPT_GNULIB_TREE=$gnulib_tree
export CAJUNOS_RECEIPT_GNULIB_REPOSITORY=$gnulib_repository
export CAJUNOS_RECEIPT_ORCHESTRATION_COMMIT=$orchestration_commit
export CAJUNOS_RECEIPT_ORCHESTRATION_TREE=$orchestration_tree
export CAJUNOS_RECEIPT_RECIPE_SHA256=$recipe_sha256
export CAJUNOS_RECEIPT_GCC_HELPER_SHA256=$gcc_helper_sha256
export CAJUNOS_RECEIPT_GLIBC_HELPER_SHA256=$glibc_helper_sha256
export CAJUNOS_RECEIPT_KERNEL_FRAGMENT_SHA256=$kernel_fragment_sha256
export CAJUNOS_RECEIPT_BUSYBOX_FRAGMENT_SHA256=$busybox_fragment_sha256
export CAJUNOS_RECEIPT_OVERLAY_DIGEST=$overlay_digest
export CAJUNOS_RECEIPT_TOOLS_ID=$tools_build_id
export CAJUNOS_RECEIPT_TOOLS_PREFIX=$tools_prefix
export CAJUNOS_RECEIPT_TOOLS_RECEIPT=$tools_receipt
export CAJUNOS_RECEIPT_TOOLS_RECEIPT_SHA256=$tools_receipt_sha256
export CAJUNOS_RECEIPT_GLIBC_ID=$glibc_build_id
export CAJUNOS_RECEIPT_GLIBC_SNAPSHOT=$glibc_snapshot
export CAJUNOS_RECEIPT_GLIBC_RECEIPT=$glibc_receipt
export CAJUNOS_RECEIPT_GLIBC_RECEIPT_SHA256=$glibc_receipt_sha256
export CAJUNOS_RECEIPT_SOURCE_EPOCH=$SOURCE_DATE_EPOCH
export CAJUNOS_RECEIPT_KERNEL_VERSION=$kernel_version
export CAJUNOS_RECEIPT_KERNEL_RELEASE=$kernel_release
export CAJUNOS_RECEIPT_DISK_BYTES=$disk_bytes
export CAJUNOS_RECEIPT_ROOTFS_BYTES=$rootfs_bytes
export CAJUNOS_RECEIPT_DISK_GUID=$disk_guid
export CAJUNOS_RECEIPT_BIOS_GUID=$bios_guid
export CAJUNOS_RECEIPT_ROOT_GUID=$root_guid
export CAJUNOS_RECEIPT_ROOT_UUID=$root_uuid
export CAJUNOS_RECEIPT_HOST_CONTRACT=$host_contract_sha256
export CAJUNOS_RECEIPT_QEMU_PATH=$qemu_path
export CAJUNOS_RECEIPT_QEMU_SHA256=$qemu_sha256
export CAJUNOS_RECEIPT_QEMU_BIOS=$qemu_bios
export CAJUNOS_RECEIPT_QEMU_BIOS_SHA256=$qemu_bios_sha256
export CAJUNOS_RECEIPT_POSITIVE_CMDLINE=$positive_cmdline
export CAJUNOS_RECEIPT_NEGATIVE_CMDLINE=$negative_cmdline
CAJUNOS_BASE_SYSTEM_RECEIPT=$(python3 - <<'PY'
import json, os
e = os.environ
value = {
    "schema": 1,
    "component": "system-image",
    "stage": "base-system-image",
    "deployable": True,
    "diagnostic_only": False,
    "target": "x86_64-cajunos-linux-gnu",
    "source_date_epoch": int(e["CAJUNOS_RECEIPT_SOURCE_EPOCH"]),
    "source_sets": {
        "bootstrap": {
            "digest": e["CAJUNOS_RECEIPT_BOOTSTRAP_DIGEST"],
            "authentication": e["CAJUNOS_RECEIPT_BOOTSTRAP_AUTH"],
        },
        "base_system": {
            "digest": e["CAJUNOS_RECEIPT_SYSTEM_DIGEST"],
            "authentication": e["CAJUNOS_RECEIPT_SYSTEM_AUTH"],
        },
    },
    "sources": {
        "linux": {
            "commit": e["CAJUNOS_RECEIPT_LINUX_COMMIT"],
            "tree": e["CAJUNOS_RECEIPT_LINUX_TREE"],
            "repository": e["CAJUNOS_RECEIPT_LINUX_REPOSITORY"],
        },
        "busybox": {
            "commit": e["CAJUNOS_RECEIPT_BUSYBOX_COMMIT"],
            "tree": e["CAJUNOS_RECEIPT_BUSYBOX_TREE"],
            "repository": e["CAJUNOS_RECEIPT_BUSYBOX_REPOSITORY"],
        },
        "grub": {
            "commit": e["CAJUNOS_RECEIPT_GRUB_COMMIT"],
            "tree": e["CAJUNOS_RECEIPT_GRUB_TREE"],
            "repository": e["CAJUNOS_RECEIPT_GRUB_REPOSITORY"],
        },
        "gnulib": {
            "commit": e["CAJUNOS_RECEIPT_GNULIB_COMMIT"],
            "tree": e["CAJUNOS_RECEIPT_GNULIB_TREE"],
            "repository": e["CAJUNOS_RECEIPT_GNULIB_REPOSITORY"],
            "purpose": "GRUB bootstrap.conf input",
        },
    },
    "orchestration": {
        "commit": e["CAJUNOS_RECEIPT_ORCHESTRATION_COMMIT"],
        "tree": e["CAJUNOS_RECEIPT_ORCHESTRATION_TREE"],
        "recipe_sha256": e["CAJUNOS_RECEIPT_RECIPE_SHA256"],
        "gcc_helper_sha256": e["CAJUNOS_RECEIPT_GCC_HELPER_SHA256"],
        "glibc_helper_sha256": e["CAJUNOS_RECEIPT_GLIBC_HELPER_SHA256"],
        "kernel_fragment_sha256": e["CAJUNOS_RECEIPT_KERNEL_FRAGMENT_SHA256"],
        "busybox_fragment_sha256": e["CAJUNOS_RECEIPT_BUSYBOX_FRAGMENT_SHA256"],
        "overlay_digest": e["CAJUNOS_RECEIPT_OVERLAY_DIGEST"],
    },
    "dependencies": {
        "gcc": {
            "build_id": e["CAJUNOS_RECEIPT_TOOLS_ID"],
            "prefix": e["CAJUNOS_RECEIPT_TOOLS_PREFIX"],
            "receipt": e["CAJUNOS_RECEIPT_TOOLS_RECEIPT"],
            "receipt_sha256": e["CAJUNOS_RECEIPT_TOOLS_RECEIPT_SHA256"],
        },
        "glibc": {
            "build_id": e["CAJUNOS_RECEIPT_GLIBC_ID"],
            "snapshot": e["CAJUNOS_RECEIPT_GLIBC_SNAPSHOT"],
            "receipt": e["CAJUNOS_RECEIPT_GLIBC_RECEIPT"],
            "receipt_sha256": e["CAJUNOS_RECEIPT_GLIBC_RECEIPT_SHA256"],
        },
    },
    "kernel": {
        "version": e["CAJUNOS_RECEIPT_KERNEL_VERSION"],
        "release": e["CAJUNOS_RECEIPT_KERNEL_RELEASE"],
        "modules": False,
        "root_selector": "PARTUUID",
    },
    "bootloader": {
        "name": "GRUB",
        "platform": "i386-pc",
        "firmware": "SeaBIOS",
        "installer": "source-built-grub-mkimage-and-fixed-layout-setup.c-subset",
        "host_grub_used": False,
    },
    "filesystem": {
        "type": "ext4",
        "bytes": int(e["CAJUNOS_RECEIPT_ROOTFS_BYTES"]),
        "uuid": e["CAJUNOS_RECEIPT_ROOT_UUID"],
        "journal": False,
    },
    "disk": {
        "format": "raw-gpt-bios",
        "bytes": int(e["CAJUNOS_RECEIPT_DISK_BYTES"]),
        "guid": e["CAJUNOS_RECEIPT_DISK_GUID"],
        "bios_boot_partuuid": e["CAJUNOS_RECEIPT_BIOS_GUID"],
        "root_partuuid": e["CAJUNOS_RECEIPT_ROOT_GUID"],
    },
    "network": {
        "driver": "virtio-net",
        "interface": "eth0",
        "configuration": "udhcpc-dhcpv4",
    },
    "security_contract": {
        "cpu_mitigations": "enabled",
        "kaslr": "enabled",
        "stack_protector": "strong",
        "fortify_source": "enabled",
        "hardened_usercopy": "enabled",
        "root_password": "locked",
        "ssh": "deferred-to-stage-9b",
    },
    "qemu": {
        "path": e["CAJUNOS_RECEIPT_QEMU_PATH"],
        "sha256": e["CAJUNOS_RECEIPT_QEMU_SHA256"],
        "machine": "pc-q35-10.0",
        "accelerator": "tcg",
        "cpu": "Nehalem-v1",
        "firmware": {
            "path": e["CAJUNOS_RECEIPT_QEMU_BIOS"],
            "sha256": e["CAJUNOS_RECEIPT_QEMU_BIOS_SHA256"],
        },
        "positive_boot": "disk-only-gpt-bios-grub",
        "negative_boot": "direct-kernel-same-gpt-root",
        "positive_cmdline": e["CAJUNOS_RECEIPT_POSITIVE_CMDLINE"],
        "negative_cmdline": e["CAJUNOS_RECEIPT_NEGATIVE_CMDLINE"],
    },
    "build_contract": {
        "independent_builds": 2,
        "kernel_kcflags": "-Wno-constant-logical-operand",
        "busybox_install_arch_and_cross_compile_preserved": True,
        "busybox_tc": "disabled-for-linux-7.2-uapi-compatibility",
        "host_contract_sha256": e["CAJUNOS_RECEIPT_HOST_CONTRACT"],
        "rootfs_population": "fakeroot-mke2fs-d",
        "rootfs_hash_seed_locked": True,
    },
    "reproducibility": {
        "independent_builds": 2,
        "kernel_identical": True,
        "busybox_identical": True,
        "rootfs_ext4_identical": True,
        "gpt_disk_identical": True,
        "selectors_modified": False,
    },
}
print(json.dumps(value, sort_keys=True))
PY
)

python3 - "$artifact_temporary" "$build_id" <<'PY'
import hashlib, json, os
from pathlib import Path
import subprocess, sys

artifact = Path(sys.argv[1])
build_id = sys.argv[2]
script = Path(os.environ["CAJUNOS_BASE_SYSTEM_SCRIPT"])

def inventory(path):
    return json.loads(subprocess.run(
        [script, "--internal-python", "inventory", path], check=True,
        text=True, stdout=subprocess.PIPE,
    ).stdout)

receipt = json.loads(os.environ["CAJUNOS_BASE_SYSTEM_RECEIPT"])
receipt["build_id"] = build_id
receipt["outputs"] = {
    "subtree_inventories": {
        name: inventory(artifact / name)
        for name in ("boot", "configuration", "licenses", "probe")
    }
}
with (artifact / "configuration/rootfs-a.json").open(encoding="utf-8") as stream:
    rootfs_inventory = json.load(stream)
receipt["reproducibility"]["rootfs_inventory"] = rootfs_inventory
with (artifact / "receipt.json").open("w", encoding="utf-8", newline="\n") as stream:
    json.dump(receipt, stream, indent=2, sort_keys=True)
    stream.write("\n")
(artifact / "receipt.json").chmod(0o644)
PY

validate_inputs
validate_candidate "$artifact_temporary" "$temporary_root"
published=1
mv -T -- "$temporary_root" "$build_final"
mv -T -- "$artifact_temporary" "$artifact_final"
validate_complete
published=0
trap - EXIT INT TERM HUP
echo "CAJUNOS_BASE_SYSTEM_COMPLETE build_id=$build_id"
