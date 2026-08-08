#!/usr/bin/env bash
set -Eeuo pipefail
umask 022
export LC_ALL=C
export TZ=UTC
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

for inherited_name in ${!E2FSPROGS_@} ${!MKE2FS_@}; do
  unset "$inherited_name"
done
unset inherited_name
unset E2FSCK_TIME SOURCE_DATE_EPOCH

script_path=$(readlink -f -- "${BASH_SOURCE[0]}")

if [[ ${1:-} == --internal-python ]]; then
  shift
  command_name=${1:-}
  shift || true
  exec python3 - "$command_name" "$@" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import uuid
import zlib

command, *arguments = sys.argv[1:]

SECTOR = 512
SOURCE_DISK_BYTES = 16 * 1024**3
DEPLOYED_OS_BYTES = 64 * 1024**3
BUILD_DISK_BYTES = 256 * 1024**3
ROOT_FIRST_SECTOR = 4096
GPT_TAIL_SECTORS = 33
BUILD_PARTITION_SECTORS = BUILD_DISK_BYTES // SECTOR - ROOT_FIRST_SECTOR - GPT_TAIL_SECTORS
BUILD_FILESYSTEM_BLOCKS = BUILD_PARTITION_SECTORS // 8
BUILD_STATFS_BLOCKS = 66776076
DEPLOYED_ROOT_SECTORS = DEPLOYED_OS_BYTES // SECTOR - ROOT_FIRST_SECTOR - GPT_TAIL_SECTORS
DEPLOYED_ROOT_BLOCKS = DEPLOYED_ROOT_SECTORS // 8
LINUX_FILESYSTEM_GUID = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4")
BIOS_BOOT_GUID = uuid.UUID("21686148-6449-6e6f-744e-656564454649")


def fail(message):
    raise SystemExit(message)


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical_uuid(value, name):
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        fail(f"{name} is not a UUID")
    if str(parsed) != value:
        fail(f"{name} is not a canonical lowercase UUID")
    return parsed


def plain_file(path, name, size=None, mode=None):
    path = Path(path)
    try:
        metadata = path.lstat()
    except OSError:
        fail(f"{name} is absent")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail(f"{name} is not one plain file")
    if mode is not None and stat.S_IMODE(metadata.st_mode) != mode:
        fail(f"{name} has the wrong mode")
    if size is not None and metadata.st_size != size:
        fail(f"{name} has the wrong size")
    return path


def load_object(path, name):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        fail(f"{name} is not valid UTF-8 JSON")
    if not isinstance(value, dict):
        fail(f"{name} is not a JSON object")
    return value


def exact_keys(value, expected, name):
    if not isinstance(value, dict) or set(value) != set(expected):
        fail(f"{name} topology differs")


def validate_hex(value, name):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        fail(f"{name} is not a lowercase SHA-256")
    return value


def validate_secure_output_parent(path):
    raw = os.fspath(path)
    if not os.path.isabs(raw) or os.path.normpath(raw) != raw:
        fail("deployment output path is not canonical and absolute")
    if os.path.lexists(raw):
        fail("deployment output already exists")
    current = Path(raw).parent
    chain = []
    while True:
        chain.append(current)
        if current == current.parent:
            break
        current = current.parent
    for component in reversed(chain):
        try:
            metadata = component.lstat()
        except OSError:
            fail("deployment output ancestor is absent")
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            fail(
                "deployment output ancestors must be real root-owned "
                "directories with no group/other write access"
            )
    return raw


def validate_private_directory(path):
    raw = os.fspath(path)
    if not os.path.isabs(raw) or os.path.normpath(raw) != raw:
        fail("internal private directory is not canonical and absolute")
    directory = Path(raw)
    try:
        metadata = directory.lstat()
    except OSError:
        fail("internal private directory is absent")
    effective_uid = os.geteuid()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != effective_uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        fail(
            "internal private directory must be real, owned by the "
            "effective UID, and mode 0700"
        )
    current = directory.parent
    while True:
        try:
            metadata = current.lstat()
        except OSError:
            fail("internal private directory ancestor is absent")
        mode = stat.S_IMODE(metadata.st_mode)
        if not stat.S_ISDIR(metadata.st_mode):
            fail("internal private directory ancestor is not a real directory")
        if metadata.st_uid not in {0, effective_uid}:
            fail("internal private directory ancestor has an unsafe owner")
        if mode & 0o022 and not (
            metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX
        ):
            fail(
                "writable internal private directory ancestors must be "
                "root-owned sticky directories"
            )
        if current == current.parent:
            break
        current = current.parent
    return raw


def validate_private_output(path):
    raw = os.fspath(path)
    if not os.path.isabs(raw) or os.path.normpath(raw) != raw:
        fail("internal output is not canonical and absolute")
    output = Path(raw)
    validate_private_directory(output.parent)
    if os.path.lexists(raw):
        fail("internal output already exists")
    return raw


def validate_private_sentinel(path, directory):
    raw = os.fspath(path)
    if not os.path.isabs(raw) or os.path.normpath(raw) != raw:
        fail("internal sentinel is not canonical and absolute")
    protected = Path(validate_private_directory(directory))
    sentinel = Path(raw)
    if sentinel.parent != protected:
        fail("internal sentinel is outside the protected directory")
    try:
        metadata = sentinel.lstat()
    except OSError:
        fail("internal sentinel is absent")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        fail(
            "internal sentinel must be one effective-UID-owned plain "
            "mode-0600 file"
        )
    return raw


def read_header(stream, lba, sectors):
    stream.seek(lba * SECTOR)
    raw = stream.read(SECTOR)
    if len(raw) != SECTOR or raw[:8] != b"EFI PART":
        fail("GPT header is absent")
    revision, header_size, header_crc = struct.unpack_from("<III", raw, 8)
    if revision != 0x00010000 or header_size != 92:
        fail("GPT header ABI differs")
    checked = bytearray(raw[:header_size])
    struct.pack_into("<I", checked, 16, 0)
    if zlib.crc32(checked) & 0xFFFFFFFF != header_crc:
        fail("GPT header checksum differs")
    current, backup, first_usable, last_usable = struct.unpack_from("<QQQQ", raw, 24)
    disk_guid = uuid.UUID(bytes_le=raw[56:72])
    entries_lba, count, entry_size, entries_crc = struct.unpack_from("<QIII", raw, 72)
    expected_alternate = sectors - 1 if lba == 1 else 1
    if (
        current != lba or backup != expected_alternate
        or first_usable != 34 or last_usable != sectors - 34
        or count != 128 or entry_size != 128
    ):
        fail("GPT geometry differs")
    stream.seek(entries_lba * SECTOR)
    entries = stream.read(count * entry_size)
    if len(entries) != count * entry_size:
        fail("GPT entry array is truncated")
    if zlib.crc32(entries) & 0xFFFFFFFF != entries_crc:
        fail("GPT entry-array checksum differs")
    return {
        "disk_guid": disk_guid, "entries": entries,
        "entries_lba": entries_lba, "first_usable": first_usable,
        "last_usable": last_usable,
    }


def parse_entries(raw):
    entries = []
    for index in range(128):
        entry = raw[index * 128:(index + 1) * 128]
        if entry == bytes(128):
            continue
        try:
            name = entry[56:128].decode("utf-16-le").rstrip("\0")
        except UnicodeDecodeError:
            fail("GPT partition name is invalid UTF-16")
        entries.append({
            "number": index + 1,
            "type_guid": uuid.UUID(bytes_le=entry[:16]),
            "partuuid": uuid.UUID(bytes_le=entry[16:32]),
            "first": struct.unpack_from("<Q", entry, 32)[0],
            "last": struct.unpack_from("<Q", entry, 40)[0],
            "attributes": struct.unpack_from("<Q", entry, 48)[0],
            "name": name,
        })
    return entries


def validate_gpt(path, expected_bytes):
    path = plain_file(path, "raw disk", expected_bytes)
    sectors = expected_bytes // SECTOR
    with path.open("rb") as stream:
        mbr = stream.read(SECTOR)
        protective = mbr[446:462]
        if (
            len(mbr) != SECTOR or mbr[510:512] != b"\x55\xaa"
            or len(protective) != 16 or protective[0] != 0
            or protective[4] != 0xEE
            or struct.unpack_from("<I", protective, 8)[0] != 1
            or struct.unpack_from("<I", protective, 12)[0]
            != min(sectors - 1, 0xFFFFFFFF)
            or mbr[462:510] != bytes(48)
        ):
            fail("protective GPT MBR differs")
        primary = read_header(stream, 1, sectors)
        backup = read_header(stream, sectors - 1, sectors)
        if (
            primary["disk_guid"] != backup["disk_guid"]
            or primary["entries"] != backup["entries"]
            or primary["entries_lba"] != 2
            or backup["entries_lba"] != sectors - 33
        ):
            fail("primary and backup GPT metadata differ")
    return primary["disk_guid"], parse_entries(primary["entries"])


def ext_superblock(path, partition_first):
    with Path(path).open("rb") as stream:
        stream.seek(partition_first * SECTOR + 1024)
        raw = stream.read(1024)
    if len(raw) != 1024 or struct.unpack_from("<H", raw, 56)[0] != 0xEF53:
        fail("ext filesystem superblock is absent")
    blocks_lo = struct.unpack_from("<I", raw, 4)[0]
    inodes = struct.unpack_from("<I", raw, 0)[0]
    blocks_hi = struct.unpack_from("<I", raw, 336)[0]
    incompat = struct.unpack_from("<I", raw, 96)[0]
    blocks = blocks_lo | ((blocks_hi << 32) if incompat & 0x80 else 0)
    block_size = 1024 << struct.unpack_from("<I", raw, 24)[0]
    filesystem_uuid = str(uuid.UUID(bytes=raw[104:120]))
    hash_seed = str(uuid.UUID(bytes=raw[236:252]))
    label = raw[120:136].split(b"\0", 1)[0].decode("ascii")
    compat = struct.unpack_from("<I", raw, 92)[0]
    ro_compat = struct.unpack_from("<I", raw, 100)[0]
    state = struct.unpack_from("<H", raw, 58)[0]
    errors = struct.unpack_from("<H", raw, 60)[0]
    inode_size = struct.unpack_from("<H", raw, 88)[0]
    mount_time = struct.unpack_from("<I", raw, 44)[0]
    write_time = struct.unpack_from("<I", raw, 48)[0]
    last_check = struct.unpack_from("<I", raw, 64)[0]
    creation_time = struct.unpack_from("<I", raw, 264)[0]
    return {
        "blocks": blocks, "block_size": block_size, "inodes": inodes,
        "uuid": filesystem_uuid, "hash_seed": hash_seed,
        "label": label, "journal": bool(compat & 0x4),
        "inode_size": inode_size, "compat": compat,
        "incompat": incompat, "ro_compat": ro_compat, "errors": errors,
        "mount_time": mount_time, "write_time": write_time,
        "last_check": last_check, "creation_time": creation_time,
        "ext4": bool(incompat & 0x40) and bool(incompat & 0x80)
        and bool(ro_compat & 0x400),
        "clean": state == 1 and not bool(incompat & 0x4),
    }


def validate_ext_times(path, epoch):
    try:
        epoch = int(epoch)
    except (TypeError, ValueError):
        fail("filesystem epoch is invalid")
    filesystem = ext_superblock(path, 0)
    actual = {
        key: filesystem[key]
        for key in ("mount_time", "write_time", "last_check", "creation_time")
    }
    expected = {
        "mount_time": 0, "write_time": epoch,
        "last_check": epoch, "creation_time": epoch,
    }
    if actual != expected:
        fail("normalized ext superblock times differ")
    return actual


def validate_build_disk(path, disk_guid, partuuid, fs_uuid, epoch):
    try:
        epoch = int(epoch)
    except (TypeError, ValueError):
        fail("build filesystem epoch is invalid")
    if epoch <= 0 or epoch > 0x7FFFFFFF:
        fail("build filesystem epoch is outside the locked range")
    expected_disk_guid = canonical_uuid(disk_guid, "build disk GUID")
    expected_partuuid = canonical_uuid(partuuid, "build PARTUUID")
    expected_fs_uuid = canonical_uuid(fs_uuid, "build filesystem UUID")
    actual_disk_guid, entries = validate_gpt(path, BUILD_DISK_BYTES)
    if actual_disk_guid != expected_disk_guid or len(entries) != 1:
        fail("build-disk GPT identity or topology differs")
    entry = entries[0]
    if entry != {
        "number": 1, "type_guid": LINUX_FILESYSTEM_GUID,
        "partuuid": expected_partuuid, "first": ROOT_FIRST_SECTOR,
        "last": BUILD_DISK_BYTES // SECTOR - 34,
        "attributes": 0, "name": "CAJUNOS-BUILD",
    }:
        fail("build-disk partition contract differs")
    filesystem = ext_superblock(path, ROOT_FIRST_SECTOR)
    if filesystem != {
        "blocks": BUILD_FILESYSTEM_BLOCKS, "block_size": 4096,
        "inodes": 1048576,
        "uuid": str(expected_fs_uuid), "label": "CAJUNOS_BUILD",
        "hash_seed": str(expected_fs_uuid),
        "journal": True, "inode_size": 256,
        "compat": 0x2C, "incompat": 0x2C2, "ro_compat": 0x46B,
        "errors": 2, "ext4": True, "clean": True,
        "mount_time": 0, "write_time": epoch,
        "last_check": epoch, "creation_time": epoch,
    }:
        fail("build-disk ext4 contract differs")
    return {
        "disk_bytes": BUILD_DISK_BYTES,
        "disk_guid": str(actual_disk_guid),
        "partition": {
            "number": 1, "first_sector": ROOT_FIRST_SECTOR,
            "sectors": BUILD_PARTITION_SECTORS,
            "partuuid": str(expected_partuuid), "gpt_name": "CAJUNOS-BUILD",
        },
        "filesystem": {
            "type": "ext4", "label": "CAJUNOS_BUILD",
            "uuid": str(expected_fs_uuid), "block_size": 4096,
            "blocks": BUILD_FILESYSTEM_BLOCKS, "inodes": 1048576,
            "directory_hash_seed": str(expected_fs_uuid),
            "epoch": epoch,
        },
    }


def deployment_contract(
    source_build_id, disk_guid, partuuid, fs_uuid, source_contract
):
    if not re.fullmatch(r"native-developer-[A-Za-z0-9._-]+", source_build_id):
        fail("source build ID is invalid")
    build_identifiers = (
        canonical_uuid(disk_guid, "build disk GUID"),
        canonical_uuid(partuuid, "build PARTUUID"),
        canonical_uuid(fs_uuid, "build filesystem UUID"),
    )
    if any(identifier.int == 0 for identifier in build_identifiers):
        fail("deployment UUIDs must not be nil")
    if len(set(build_identifiers)) != len(build_identifiers):
        fail("deployment UUIDs must be pairwise distinct")
    if not isinstance(source_contract, dict):
        fail("source contract is not an object")
    source_identifiers = {
        canonical_uuid(source_contract.get(key), f"source {key}")
        for key in (
            "disk_guid", "bios_partuuid", "root_partuuid", "root_uuid"
        )
    }
    if set(build_identifiers) & source_identifiers:
        fail("deployment UUID collides with a pristine source identity")
    filesystem_epoch = source_contract.get("source_date_epoch")
    if (
        not isinstance(filesystem_epoch, int)
        or filesystem_epoch <= 0
        or filesystem_epoch > 0x7FFFFFFF
    ):
        fail("source filesystem epoch is outside the locked range")
    disk_guid, partuuid, fs_uuid = map(str, build_identifiers)
    identity = {
        "schema": 1,
        "source_build_id": source_build_id,
        "build_disk_guid": disk_guid,
        "build_partuuid": partuuid,
        "build_filesystem_uuid": fs_uuid,
        "build_disk_bytes": BUILD_DISK_BYTES,
        "partition_first_sector": ROOT_FIRST_SECTOR,
        "partition_sectors": BUILD_PARTITION_SECTORS,
        "filesystem_type": "ext4",
        "filesystem_label": "CAJUNOS_BUILD",
        "filesystem_block_size": 4096,
        "filesystem_blocks": BUILD_FILESYSTEM_BLOCKS,
        "filesystem_statfs_blocks": BUILD_STATFS_BLOCKS,
        "filesystem_inodes": 1048576,
        "filesystem_epoch": filesystem_epoch,
        "identities_pairwise_distinct": True,
        "source_identity_collision": False,
        "offline_disk_guid_validation": True,
        "runtime_disk_guid_validation": False,
        "runtime_identity_validation": [
            "partition-partuuid", "filesystem-uuid", "filesystem-type",
            "filesystem-label", "partition-sectors", "filesystem-capacity",
            "sentinel-sha256",
        ],
        "fstab_entry": (
            f"PARTUUID={partuuid} /build ext4 rw,nosuid,nodev 0 2"
        ),
    }
    encoded = json.dumps(
        identity, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    deployment_id = "native-developer-deployment-" + hashlib.sha256(
        encoded
    ).hexdigest()[:24]
    sentinel = "".join((
        "CAJUNOS_NATIVE_DEVELOPER_BUILD_VOLUME_V1\n",
        f"deployment_id={deployment_id}\n",
        f"source_build_id={source_build_id}\n",
        f"build_disk_guid={disk_guid}\n",
        f"build_partuuid={partuuid}\n",
        f"build_filesystem_uuid={fs_uuid}\n",
        f"build_disk_bytes={BUILD_DISK_BYTES}\n",
        f"partition_first_sector={ROOT_FIRST_SECTOR}\n",
        f"partition_sectors={BUILD_PARTITION_SECTORS}\n",
        "filesystem_type=ext4\n",
        "filesystem_label=CAJUNOS_BUILD\n",
        "filesystem_block_size=4096\n",
        f"filesystem_blocks={BUILD_FILESYSTEM_BLOCKS}\n",
        f"filesystem_statfs_blocks={BUILD_STATFS_BLOCKS}\n",
        "filesystem_inodes=1048576\n",
        f"filesystem_epoch={filesystem_epoch}\n",
    ))
    return {
        **identity,
        "deployment_id": deployment_id,
        "sentinel": sentinel,
        "sentinel_sha256": hashlib.sha256(sentinel.encode("ascii")).hexdigest(),
    }


def validate_source(
    receipt_path, disk_path, helper_sha256=None, trusted_receipt_sha256=None
):
    receipt_path = plain_file(receipt_path, "Stage 9B receipt", mode=0o644)
    disk_path = plain_file(
        disk_path, "Stage 9B pristine disk", SOURCE_DISK_BYTES, mode=0o644
    )
    receipt = load_object(receipt_path, "Stage 9B receipt")
    if helper_sha256 is not None or trusted_receipt_sha256 is not None:
        validate_hex(helper_sha256, "deployment helper hash")
        validate_hex(trusted_receipt_sha256, "trusted Stage 9B receipt hash")
        if sha256(receipt_path) != trusted_receipt_sha256:
            fail("Stage 9B receipt differs from its trusted hash")
        if receipt.get("orchestration", {}).get(
            "deployment_helper_sha256"
        ) != helper_sha256:
            fail("Stage 9B receipt does not bind this deployment helper")
    if (
        receipt.get("schema") != 1
        or receipt.get("stage") != "native-developer-seed"
        or receipt.get("deployable") is not True
        or receipt.get("disk", {}).get("format") != "raw-gpt-bios"
        or receipt.get("disk", {}).get("bytes") != SOURCE_DISK_BYTES
        or receipt.get("filesystem", {}).get("type") != "ext4"
        or receipt.get("filesystem", {}).get("bytes") != 12 * 1024**3
        or receipt.get("filesystem", {}).get("journal") is not True
        or receipt.get("template_contract", {}).get("source")
        != "pristine-never-booted-stage9b-artifact-only"
        or not re.fullmatch(
            r"native-developer-[A-Za-z0-9._-]+", receipt.get("build_id", "")
        )
        or not isinstance(receipt.get("source_date_epoch"), int)
        or receipt["source_date_epoch"] <= 0
    ):
        fail("input receipt is not a pristine Stage 9B contract")
    disk_hash = sha256(disk_path)
    if receipt["disk"].get("sha256") != disk_hash:
        fail("pristine Stage 9B disk hash differs from its receipt")
    disk_guid, entries = validate_gpt(disk_path, SOURCE_DISK_BYTES)
    if len(entries) != 2:
        fail("pristine Stage 9B GPT topology differs")
    expected = (
        (1, BIOS_BOOT_GUID, receipt["disk"]["bios_boot_partuuid"], 2048, 4095, "BIOS-BOOT"),
        (2, LINUX_FILESYSTEM_GUID, receipt["disk"]["root_partuuid"], ROOT_FIRST_SECTOR,
         SOURCE_DISK_BYTES // SECTOR - 34, "CAJUNOS-ROOT"),
    )
    for entry, contract in zip(entries, expected, strict=True):
        number, type_guid, partuuid, first, last, name = contract
        if entry != {
            "number": number, "type_guid": type_guid,
            "partuuid": canonical_uuid(partuuid, f"partition {number} GUID"),
            "first": first, "last": last, "attributes": 0, "name": name,
        }:
            fail("pristine Stage 9B partition contract differs")
    if str(disk_guid) != receipt["disk"]["guid"]:
        fail("pristine Stage 9B disk GUID differs")
    filesystem = ext_superblock(disk_path, ROOT_FIRST_SECTOR)
    if (
        filesystem["blocks"] * filesystem["block_size"] != 12 * 1024**3
        or filesystem["block_size"] != 4096
        or filesystem["uuid"] != receipt["filesystem"]["uuid"]
        or filesystem["label"] != "CAJUNOS_ROOT"
        or filesystem["hash_seed"] != receipt["filesystem"]["directory_hash_seed"]
        or filesystem["inode_size"] != 256
        or filesystem["compat"] != 0x2C
        or filesystem["incompat"] != 0x2C2
        or filesystem["ro_compat"] != 0x46B
        or filesystem["errors"] != 1 or not filesystem["ext4"]
        or not filesystem["journal"] or not filesystem["clean"]
        or filesystem["mount_time"] != 0
        or filesystem["creation_time"] != receipt["source_date_epoch"]
    ):
        fail("pristine Stage 9B root filesystem differs")
    return {
        "build_id": receipt["build_id"], "source_sha256": disk_hash,
        "source_date_epoch": receipt["source_date_epoch"],
        "disk_guid": str(disk_guid),
        "bios_partuuid": str(entries[0]["partuuid"]),
        "root_partuuid": str(entries[1]["partuuid"]),
        "root_uuid": filesystem["uuid"],
        "root_hash_seed": filesystem["hash_seed"],
        "root_creation_time": filesystem["creation_time"],
        "root_features": {
            "compat": filesystem["compat"],
            "incompat": filesystem["incompat"],
            "ro_compat": filesystem["ro_compat"],
            "inode_size": filesystem["inode_size"],
            "errors": filesystem["errors"],
        },
    }


def validate_expanded(source_path, output_path, source_contract):
    source_path = plain_file(source_path, "Stage 9B pristine disk", SOURCE_DISK_BYTES)
    output_path = plain_file(output_path, "expanded OS disk", DEPLOYED_OS_BYTES)
    disk_guid, entries = validate_gpt(output_path, DEPLOYED_OS_BYTES)
    if len(entries) != 2:
        fail("expanded OS GPT topology differs")
    expected_entries = (
        {
            "number": 1, "type_guid": BIOS_BOOT_GUID,
            "partuuid": uuid.UUID(source_contract["bios_partuuid"]),
            "first": 2048, "last": 4095, "attributes": 0,
            "name": "BIOS-BOOT",
        },
        {
            "number": 2, "type_guid": LINUX_FILESYSTEM_GUID,
            "partuuid": uuid.UUID(source_contract["root_partuuid"]),
            "first": ROOT_FIRST_SECTOR,
            "last": DEPLOYED_OS_BYTES // SECTOR - 34,
            "attributes": 0, "name": "CAJUNOS-ROOT",
        },
    )
    if str(disk_guid) != source_contract["disk_guid"] or tuple(entries) != expected_entries:
        fail("expanded OS partition identity or geometry differs")
    with source_path.open("rb") as source, output_path.open("rb") as output:
        if source.read(446) != output.read(446):
            fail("expanded OS disk changed GRUB MBR boot code")
        source.seek(2048 * SECTOR); output.seek(2048 * SECTOR)
        if source.read(2048 * SECTOR) != output.read(2048 * SECTOR):
            fail("expanded OS disk changed the embedded GRUB BIOS partition")
    filesystem = ext_superblock(output_path, ROOT_FIRST_SECTOR)
    features = source_contract["root_features"]
    if (
        filesystem["blocks"] != DEPLOYED_ROOT_BLOCKS
        or filesystem["block_size"] != 4096
        or filesystem["uuid"] != source_contract["root_uuid"]
        or filesystem["hash_seed"] != source_contract["root_hash_seed"]
        or filesystem["label"] != "CAJUNOS_ROOT"
        or filesystem["mount_time"] != 0
        or filesystem["write_time"] != source_contract["source_date_epoch"]
        or filesystem["last_check"] != source_contract["source_date_epoch"]
        or filesystem["creation_time"] != source_contract["root_creation_time"]
        or any(filesystem[key] != features[key] for key in features)
        or not filesystem["journal"] or not filesystem["ext4"]
        or not filesystem["clean"]
    ):
        fail("expanded OS ext4 contract differs")
    return {
        "disk_bytes": DEPLOYED_OS_BYTES, "disk_guid": str(disk_guid),
        "root_partuuid": str(entries[1]["partuuid"]),
        "root_filesystem": {
            "blocks": DEPLOYED_ROOT_BLOCKS, "block_size": 4096,
            "bytes": DEPLOYED_ROOT_BLOCKS * 4096,
            "inodes": filesystem["inodes"], "uuid": filesystem["uuid"],
            "journal": True, "clean": True,
            "mount_time": 0,
            "write_time": source_contract["source_date_epoch"],
            "last_check": source_contract["source_date_epoch"],
            "creation_time": source_contract["root_creation_time"],
        },
        "boot_code_preserved": True, "bios_partition_preserved": True,
    }


def validate_evidence(
    evidence_path, receipt_path, source_path, os_path, build_path,
    helper_sha256, trusted_receipt_sha256,
):
    evidence_path = plain_file(
        evidence_path, "deployment evidence", mode=0o644
    )
    os_path = plain_file(
        os_path, "published expanded OS disk", DEPLOYED_OS_BYTES, mode=0o644
    )
    build_path = plain_file(
        build_path, "published build disk", BUILD_DISK_BYTES, mode=0o644
    )
    evidence = load_object(evidence_path, "deployment evidence")
    exact_keys(evidence, {
        "schema", "stage", "source", "os_disk", "build_disk",
        "device_name_dependency", "deployment_contract",
        "deployment_helper_sha256", "validation",
    }, "deployment evidence")
    exact_keys(evidence["source"], {
        "build_id", "receipt", "disk", "receipt_sha256", "disk_sha256",
        "contract",
    }, "deployment evidence source")
    for name in ("os_disk", "build_disk"):
        exact_keys(evidence[name], {
            "path", "sha256", "contract", "prepared_offline_before_first_boot",
        }, f"deployment evidence {name}")
    exact_keys(evidence["validation"], {
        "forced_fsck_after_final_mutation",
        "sentinel_revalidated_after_forced_fsck",
        "published_disks_replayed_before_evidence_publication",
        "runtime_disk_guid_validation",
    }, "deployment evidence validation")
    if (
        evidence.get("schema") != 1
        or evidence.get("stage")
        != "native-developer-deployment-preparation"
        or evidence.get("device_name_dependency") is not False
        or evidence.get("deployment_helper_sha256") != helper_sha256
        or evidence["validation"] != {
            "forced_fsck_after_final_mutation": True,
            "sentinel_revalidated_after_forced_fsck": True,
            "published_disks_replayed_before_evidence_publication": True,
            "runtime_disk_guid_validation": False,
        }
    ):
        fail("deployment evidence fixed contract differs")
    validate_hex(helper_sha256, "deployment helper hash")
    validate_hex(trusted_receipt_sha256, "trusted Stage 9B receipt hash")
    expected_paths = {
        "receipt": str(Path(receipt_path).resolve(strict=True)),
        "source": str(Path(source_path).resolve(strict=True)),
        "os": str(os_path.resolve(strict=True)),
        "build": str(build_path.resolve(strict=True)),
    }
    if (
        evidence["source"]["receipt"] != expected_paths["receipt"]
        or evidence["source"]["disk"] != expected_paths["source"]
        or evidence["os_disk"]["path"] != expected_paths["os"]
        or evidence["build_disk"]["path"] != expected_paths["build"]
    ):
        fail("deployment evidence path binding differs")
    source_contract = validate_source(
        expected_paths["receipt"], expected_paths["source"],
        helper_sha256, trusted_receipt_sha256,
    )
    receipt_hash = sha256(expected_paths["receipt"])
    if (
        evidence["source"]["build_id"] != source_contract["build_id"]
        or evidence["source"]["receipt_sha256"] != receipt_hash
        or evidence["source"]["disk_sha256"]
        != source_contract["source_sha256"]
        or evidence["source"]["contract"] != source_contract
    ):
        fail("deployment evidence source binding differs")
    stored_contract = evidence["deployment_contract"]
    if not isinstance(stored_contract, dict):
        fail("deployment evidence contract is not an object")
    rebuilt_contract = deployment_contract(
        source_contract["build_id"],
        stored_contract.get("build_disk_guid"),
        stored_contract.get("build_partuuid"),
        stored_contract.get("build_filesystem_uuid"),
        source_contract,
    )
    if stored_contract != rebuilt_contract:
        fail("deployment evidence identity contract differs")
    expanded = validate_expanded(
        expected_paths["source"], expected_paths["os"], source_contract
    )
    build = validate_build_disk(
        expected_paths["build"], rebuilt_contract["build_disk_guid"],
        rebuilt_contract["build_partuuid"],
        rebuilt_contract["build_filesystem_uuid"],
        source_contract["source_date_epoch"],
    )
    if (
        evidence["os_disk"]["prepared_offline_before_first_boot"] is not True
        or evidence["build_disk"]["prepared_offline_before_first_boot"] is not True
        or evidence["os_disk"]["contract"] != expanded
        or evidence["build_disk"]["contract"] != build
        or evidence["os_disk"]["sha256"] != sha256(expected_paths["os"])
        or evidence["build_disk"]["sha256"] != sha256(expected_paths["build"])
    ):
        fail("deployment evidence output binding differs")
    return {
        "deployment_id": rebuilt_contract["deployment_id"],
        "source_build_id": source_contract["build_id"],
        "sentinel": rebuilt_contract["sentinel"],
        "sentinel_sha256": rebuilt_contract["sentinel_sha256"],
        "build_partuuid": rebuilt_contract["build_partuuid"],
        "build_filesystem_uuid": rebuilt_contract["build_filesystem_uuid"],
        "fstab_entry": rebuilt_contract["fstab_entry"],
        "os_sha256": evidence["os_disk"]["sha256"],
        "build_sha256": evidence["build_disk"]["sha256"],
        "evidence_sha256": sha256(evidence_path),
    }


def compare_evidence(first_path, second_path):
    first_path = plain_file(first_path, "first deployment evidence", mode=0o644)
    second_path = plain_file(second_path, "second deployment evidence", mode=0o644)
    if first_path.resolve() == second_path.resolve():
        fail("A/B evidence paths must be distinct")
    first = load_object(first_path, "first deployment evidence")
    second = load_object(second_path, "second deployment evidence")
    for value, name in ((first, "first"), (second, "second")):
        exact_keys(value, {
            "schema", "stage", "source", "os_disk", "build_disk",
            "device_name_dependency", "deployment_contract",
            "deployment_helper_sha256", "validation",
        }, f"{name} deployment evidence")
    for key in (
        "schema", "stage", "source", "device_name_dependency",
        "deployment_contract", "deployment_helper_sha256", "validation",
    ):
        if first[key] != second[key]:
            fail(f"A/B deployment evidence differs at {key}")
    for disk in ("os_disk", "build_disk"):
        for key in (
            "sha256", "contract", "prepared_offline_before_first_boot",
        ):
            if first[disk].get(key) != second[disk].get(key):
                fail(f"A/B deployment {disk} differs at {key}")
        if first[disk].get("path") == second[disk].get("path"):
            fail(f"A/B deployment {disk} paths are not independent")
    comparison = {
        "schema": 1,
        "stage": "native-developer-deployment-reproducibility",
        "independent_preparations": 2,
        "evidence_a": {
            "path": str(first_path.resolve()), "sha256": sha256(first_path),
        },
        "evidence_b": {
            "path": str(second_path.resolve()), "sha256": sha256(second_path),
        },
        "deployment_id": first["deployment_contract"]["deployment_id"],
        "os_sha256": first["os_disk"]["sha256"],
        "build_sha256": first["build_disk"]["sha256"],
        "byte_identical": True,
    }
    return comparison


if command == "geometry":
    if arguments:
        fail("geometry takes no arguments")
    print(json.dumps({
        "source_disk_bytes": SOURCE_DISK_BYTES,
        "deployed_os_bytes": DEPLOYED_OS_BYTES,
        "build_disk_bytes": BUILD_DISK_BYTES,
        "first_sector": ROOT_FIRST_SECTOR,
        "deployed_root_sectors": DEPLOYED_ROOT_SECTORS,
        "deployed_root_blocks": DEPLOYED_ROOT_BLOCKS,
        "build_partition_sectors": BUILD_PARTITION_SECTORS,
        "build_filesystem_blocks": BUILD_FILESYSTEM_BLOCKS,
        "build_statfs_blocks": BUILD_STATFS_BLOCKS,
    }, sort_keys=True))
elif command == "canonical-uuid":
    if len(arguments) != 1:
        fail("canonical-uuid requires UUID")
    print(canonical_uuid(arguments[0], "UUID"))
elif command == "validate-build-disk":
    if len(arguments) != 5:
        fail("validate-build-disk requires DISK DISK_GUID PARTUUID FS_UUID EPOCH")
    print(json.dumps(validate_build_disk(*arguments), sort_keys=True))
elif command == "validate-ext-times":
    if len(arguments) != 2:
        fail("validate-ext-times requires FILESYSTEM EPOCH")
    print(json.dumps(validate_ext_times(*arguments), sort_keys=True))
elif command == "validate-source":
    if len(arguments) != 4:
        fail("validate-source requires RECEIPT DISK HELPER_SHA256 TRUSTED_RECEIPT_SHA256")
    receipt_path, disk_path, helper_sha256, trusted_receipt_sha256 = arguments
    print(json.dumps(validate_source(
        receipt_path, disk_path, helper_sha256, trusted_receipt_sha256
    ), sort_keys=True))
elif command == "validate-expanded":
    if len(arguments) != 3:
        fail("validate-expanded requires SOURCE OUTPUT SOURCE_CONTRACT")
    print(json.dumps(validate_expanded(
        arguments[0], arguments[1], json.loads(arguments[2])
    ), sort_keys=True))
elif command == "deployment-contract":
    if len(arguments) != 5:
        fail("deployment-contract requires SOURCE_BUILD_ID DISK_GUID PARTUUID FS_UUID SOURCE_CONTRACT")
    values = arguments[:4]
    source_contract = json.loads(arguments[4])
    print(json.dumps(deployment_contract(*values, source_contract), sort_keys=True))
elif command == "secure-output-parent":
    if not arguments:
        fail("secure-output-parent requires OUTPUT [OUTPUT ...]")
    print(json.dumps([
        validate_secure_output_parent(path) for path in arguments
    ], sort_keys=True))
elif command == "private-directory":
    if len(arguments) != 1:
        fail("private-directory requires DIRECTORY")
    print(validate_private_directory(arguments[0]))
elif command == "private-output":
    if len(arguments) != 1:
        fail("private-output requires OUTPUT")
    print(validate_private_output(arguments[0]))
elif command == "private-sentinel":
    if len(arguments) != 2:
        fail("private-sentinel requires SENTINEL DIRECTORY")
    print(validate_private_sentinel(*arguments))
elif command == "validate-evidence":
    if len(arguments) != 7:
        fail(
            "validate-evidence requires EVIDENCE RECEIPT SOURCE OS BUILD "
            "HELPER_SHA256 TRUSTED_RECEIPT_SHA256"
        )
    print(json.dumps(validate_evidence(*arguments), sort_keys=True))
elif command == "compare-evidence":
    if len(arguments) != 2:
        fail("compare-evidence requires EVIDENCE_A EVIDENCE_B")
    print(json.dumps(compare_evidence(*arguments), indent=2, sort_keys=True))
else:
    fail(f"unknown internal command: {command}")
PY
fi

active_build_loop=
cleanup_active_build_loop()
{
  if [[ -n $active_build_loop ]]; then
    /usr/sbin/losetup --detach "$active_build_loop" 2>/dev/null || true
    active_build_loop=
  fi
}
trap cleanup_active_build_loop EXIT
trap 'cleanup_active_build_loop; exit 130' INT
trap 'cleanup_active_build_loop; exit 143' TERM
trap 'cleanup_active_build_loop; exit 129' HUP

create_build_disk()
{
  local output=$1 disk_bytes=$2 filesystem_type=$3
  local disk_guid=$4 partuuid=$5 filesystem_uuid=$6 epoch=$7
  local sentinel=${8:-}
  [[ ! -e $output && ! -L $output ]] || return 1
  local sectors=$((disk_bytes / 512))
  local partition_sectors=$((sectors - 4096 - 33))
  local filesystem_blocks=$((partition_sectors / 8))
  truncate -s "$disk_bytes" "$output"
  /usr/sbin/sgdisk --clear --disk-guid="$disk_guid" \
    --new=1:4096:0 --typecode=1:8300 --change-name=1:CAJUNOS-BUILD \
    --partition-guid=1:"$partuuid" -- "$output" >/dev/null
  if [[ $filesystem_type == ext4 ]]; then
    MKE2FS_CONFIG=/dev/null E2FSPROGS_FAKE_TIME="$epoch" \
      /usr/sbin/mke2fs -q -b 4096 -I 256 -N 1048576 -m 0 \
      -L CAJUNOS_BUILD -U "$filesystem_uuid" -o linux -e remount-ro \
      -E offset=$((4096 * 512)),lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0,root_perms=0755,hash_seed="$filesystem_uuid",nodiscard \
      -O none,has_journal,ext_attr,dir_index,filetype,extent,64bit,flex_bg,sparse_super,large_file,huge_file,dir_nlink,extra_isize,metadata_csum \
      "$output" "$filesystem_blocks"
  elif [[ $filesystem_type == ext2 ]]; then
    MKE2FS_CONFIG=/dev/null E2FSPROGS_FAKE_TIME="$epoch" \
      /usr/sbin/mke2fs -q -b 4096 -I 256 -i 4194304 -m 0 \
      -L CAJUNOS_BUILD -U "$filesystem_uuid" -o linux -e continue \
      -E offset=$((4096 * 512)),lazy_itable_init=0,root_owner=0:0,root_perms=0755,nodiscard \
      -O none,ext_attr,filetype,sparse_super,large_file \
      "$output" "$filesystem_blocks"
  else
    return 1
  fi
  local partition_device=
  active_build_loop=$(/usr/sbin/losetup --find --show --partscan -- "$output")
  partition_device=$(partition_device "$active_build_loop" 1)
  if [[ -n $sentinel ]]; then
    inject_ext_file "$partition_device" "$sentinel" /.cajunos-build-volume "$epoch"
    validate_ext_file "$partition_device" /.cajunos-build-volume "$sentinel"
  fi
  E2FSCK_TIME="$epoch" /usr/sbin/e2fsck -f -y "$partition_device" >/dev/null
  normalize_ext_superblock_time "$partition_device" "$epoch"
  "$script_path" --internal-python validate-ext-times \
    "$partition_device" "$epoch" >/dev/null
  verify_ext_noop_fsck "$partition_device" "$epoch"
  if [[ -n $sentinel ]]; then
    validate_ext_file "$partition_device" /.cajunos-build-volume "$sentinel"
  fi
  /usr/sbin/losetup --detach "$active_build_loop"
  active_build_loop=
  chmod 0644 "$output"
}

normalize_ext_superblock_time()
{
  local filesystem=$1 epoch=$2 commands epoch_hex output
  commands=$(mktemp)
  epoch_hex=$(printf '0x%x' "$epoch")
  printf '%s\n' \
    "set_current_time $epoch_hex" \
    'set_super_value mtime @0' \
    "set_super_value wtime @$epoch" \
    "set_super_value lastcheck @$epoch" >"$commands"
  output=$(/usr/sbin/debugfs -w -f "$commands" "$filesystem" 2>&1) || {
    rm -f -- "$commands"
    return 1
  }
  rm -f -- "$commands"
  case $output in
    *"invalid field"*|*"Couldn't parse"*|*"Unknown request"*)
      echo "debugfs rejected ext superblock normalization" >&2
      return 1
      ;;
  esac
}

verify_ext_noop_fsck()
{
  local filesystem=$1 epoch=$2 before after
  before=$(/usr/bin/sha256sum "$filesystem" | /usr/bin/awk '{print $1}')
  E2FSCK_TIME="$epoch" /usr/sbin/e2fsck -f -n "$filesystem" >/dev/null
  after=$(/usr/bin/sha256sum "$filesystem" | /usr/bin/awk '{print $1}')
  [[ $after == "$before" ]] || {
    echo "Read-only forced fsck changed the normalized filesystem" >&2
    return 1
  }
}

partition_device()
{
  local disk=$1 number=$2
  local result= attempt=0
  while [[ $attempt -lt 50 ]]; do
    result=$(/usr/bin/lsblk -nrpo NAME,PARTN -- "$disk" \
      | /usr/bin/awk -v number="$number" '$2 == number { count++; value = $1 } END { if (count == 1) print value; else exit 1 }' \
      || true)
    if [[ -n $result && -b $result ]]; then
      printf '%s\n' "$result"
      return 0
    fi
    attempt=$((attempt + 1))
    /bin/sleep 0.1
  done
  return 1
}

inject_ext_file()
{
  local filesystem=$1 source_file=$2 guest_path=$3 epoch=$4 replace=${5:-0}
  local commands
  commands=$(mktemp)
  python3 - "$commands" "$source_file" "$guest_path" "$epoch" "$replace" <<'PY'
from pathlib import Path
import sys

commands, source, guest, epoch, replace = sys.argv[1:]
if not guest.startswith("/") or any(character in guest for character in " \t\r\n\""):
    raise SystemExit("unsafe debugfs guest path")
if any(character in source for character in " \t\r\n\""):
    raise SystemExit("unsafe debugfs source path")
lines = [f"set_current_time {epoch}"]
if replace == "1":
    lines.append(f"rm {guest}")
lines.extend((
        f"write {source} {guest}",
        f"set_inode_field {guest} mode 0100644",
        f"set_inode_field {guest} uid 0",
        f"set_inode_field {guest} gid 0",
        f"set_inode_field {guest} atime @{epoch}",
        f"set_inode_field {guest} ctime @{epoch}",
        f"set_inode_field {guest} mtime @{epoch}",
        f"set_inode_field {guest} crtime @{epoch}",
        "",
    ))
Path(commands).write_text(
    "\n".join(lines), encoding="ascii", newline="\n",
)
PY
  /usr/sbin/debugfs -w -f "$commands" "$filesystem" >/dev/null 2>&1 || {
    rm -f -- "$commands"
    return 1
  }
  rm -f -- "$commands"
}

validate_ext_file()
{
  local filesystem=$1 guest_path=$2 expected=$3
  local dump_directory dumped status=0
  dump_directory=$(mktemp -d)
  chmod 0700 "$dump_directory"
  dumped=$dump_directory/value
  /usr/sbin/debugfs -R "dump -p $guest_path $dumped" \
    "$filesystem" >/dev/null 2>&1 || status=$?
  [[ -f $dumped && ! -L $dumped \
     && $(stat -c '%u:%g:%a:%h' "$dumped") == 0:0:644:1 ]] || {
    rm -f -- "$dumped"
    rmdir -- "$dump_directory"
    return 1
  }
  cmp -- "$expected" "$dumped" || status=$?
  rm -f -- "$dumped"
  rmdir -- "$dump_directory"
  return "$status"
}

ext_path_absent()
{
  local filesystem=$1 guest_path=$2 output
  output=$(/usr/sbin/debugfs -R "stat $guest_path" "$filesystem" 2>&1 || true)
  [[ $output == *"File not found by ext2_lookup"* ]]
}

publish_no_replace()
{
  python3 - "$1" "$2" <<'PY'
import os
from pathlib import Path
import stat
import sys

temporary, final = map(Path, sys.argv[1:])
metadata = temporary.lstat()
if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
    raise SystemExit("publication temporary is not one plain file")
if final.exists() or final.is_symlink():
    raise SystemExit("refusing raced deployment output")
with temporary.open("rb", buffering=0) as stream:
    os.fsync(stream.fileno())
directory = os.open(final.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
    os.link(temporary, final, follow_symlinks=False)
    os.fsync(directory)
    temporary.unlink()
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

materialize_contract_files()
{
  local root=$1 contract_json=$2
  python3 - "$root" "$contract_json" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
contract = json.loads(sys.argv[2])
files = {
    "build-partuuid": contract["build_partuuid"] + "\n",
    "build-fs-uuid": contract["build_filesystem_uuid"] + "\n",
    "build-sentinel-sha256": contract["sentinel_sha256"] + "\n",
    "build-sentinel": contract["sentinel"],
    "base-fstab": (
        "proc /proc proc nosuid,nodev,noexec 0 0\n"
        "sysfs /sys sysfs nosuid,nodev,noexec 0 0\n"
        "devpts /dev/pts devpts nosuid,noexec,gid=5,mode=0620 0 0\n"
        "tmpfs /run tmpfs nosuid,nodev,mode=0755 0 0\n"
    ),
}

files["deployment-fstab"] = files["base-fstab"] + (
    f"PARTUUID={contract['build_partuuid']} "
    "/build ext4 rw,nosuid,nodev 0 2\n"
)
for name, content in files.items():
    path = root / name
    path.write_text(content, encoding="ascii", newline="\n")
    path.chmod(0o600)
PY
}

remove_contract_files()
{
  local root=$1
  rm -f -- "$root/build-partuuid" "$root/build-fs-uuid" \
    "$root/build-sentinel-sha256" "$root/build-sentinel" \
    "$root/base-fstab" "$root/deployment-fstab"
}

require_deployment_tools()
{
  local tool
  for tool in /usr/bin/cmp /usr/bin/cp /usr/bin/lsblk /usr/bin/readlink \
    /usr/bin/sha256sum /usr/bin/stat /usr/bin/truncate /usr/sbin/debugfs \
    /usr/sbin/e2fsck /usr/sbin/losetup /usr/sbin/mke2fs \
    /usr/sbin/resize2fs /usr/sbin/sgdisk; do
    [[ -f $tool && ! -L $tool && -x $tool ]] || {
      echo "Required deployment tool is unavailable: $tool" >&2
      return 1
    }
  done
}

validate_published_deployment()
{
  local evidence_path=$1 receipt_path=$2 trusted_hash=$3 source_path=$4
  local os_path=$5 build_path=$6 helper_hash=$7 expected_root=$8
  local result_output=$9
  local validation_json contract_json expected_os_hash expected_build_hash
  local os_root_device build_device
  validation_json=$("$script_path" --internal-python validate-evidence \
    "$evidence_path" "$receipt_path" "$source_path" "$os_path" \
    "$build_path" "$helper_hash" "$trusted_hash")
  contract_json=$(python3 -c '
import json, sys
evidence = json.load(open(sys.argv[1], encoding="utf-8"))
print(json.dumps(evidence["deployment_contract"], sort_keys=True))
' "$evidence_path")
  materialize_contract_files "$expected_root" "$contract_json"

  os_loop=$(/usr/sbin/losetup --find --show --partscan -- "$os_path")
  os_root_device=$(partition_device "$os_loop" 2)
  /usr/sbin/e2fsck -f -n "$os_root_device" >/dev/null
  validate_ext_file "$os_root_device" /etc/cajunos-build-partuuid \
    "$expected_root/build-partuuid"
  validate_ext_file "$os_root_device" /etc/cajunos-build-fs-uuid \
    "$expected_root/build-fs-uuid"
  validate_ext_file "$os_root_device" /etc/cajunos-build-sentinel-sha256 \
    "$expected_root/build-sentinel-sha256"
  validate_ext_file "$os_root_device" /etc/fstab \
    "$expected_root/deployment-fstab"
  /usr/sbin/losetup --detach "$os_loop"
  os_loop=

  active_build_loop=$(/usr/sbin/losetup --find --show --partscan -- "$build_path")
  build_device=$(partition_device "$active_build_loop" 1)
  /usr/sbin/e2fsck -f -n "$build_device" >/dev/null
  validate_ext_file "$build_device" /.cajunos-build-volume \
    "$expected_root/build-sentinel"
  /usr/sbin/losetup --detach "$active_build_loop"
  active_build_loop=

  mapfile -t expected_hashes < <(python3 -c '
import json, sys
value = json.load(sys.stdin)
print(value["os_sha256"])
print(value["build_sha256"])
' <<<"$validation_json")
  [[ ${#expected_hashes[@]} -eq 2 ]]
  expected_os_hash=${expected_hashes[0]}
  expected_build_hash=${expected_hashes[1]}
  [[ $(/usr/bin/sha256sum "$os_path" | /usr/bin/awk '{print $1}') \
     == "$expected_os_hash" ]]
  [[ $(/usr/bin/sha256sum "$build_path" | /usr/bin/awk '{print $1}') \
     == "$expected_build_hash" ]]
  printf '%s\n' "$validation_json" >"$result_output"
  chmod 0600 "$result_output"
}

if [[ ${1:-} == --internal-materialize-contract ]]; then
  [[ $# -eq 3 ]] || {
    echo "internal materialize-contract requires an empty real directory and JSON" >&2
    exit 64
  }
  private_directory=$("$script_path" --internal-python private-directory "$2") || exit 64
  [[ -z $(find "$private_directory" -mindepth 1 -print -quit) ]] || {
    echo "internal materialize-contract requires an empty private directory" >&2
    exit 64
  }
  materialize_contract_files "$private_directory" "$3"
  exit 0
fi

if [[ ${1:-} == --validate-deployment ]]; then
  shift
  validation_receipt= validation_trusted_hash= validation_source=
  validation_os= validation_build= validation_evidence=
  while [[ $# -gt 0 ]]; do
    [[ $# -ge 2 ]] || exit 64
    case $1 in
      --receipt) validation_receipt=$2 ;;
      --receipt-sha256) validation_trusted_hash=$2 ;;
      --source) validation_source=$2 ;;
      --os-disk) validation_os=$2 ;;
      --build-disk) validation_build=$2 ;;
      --evidence) validation_evidence=$2 ;;
      *) exit 64 ;;
    esac
    shift 2
  done
  for value in "$validation_receipt" "$validation_trusted_hash" \
    "$validation_source" "$validation_os" "$validation_build" \
    "$validation_evidence"; do
    [[ -n $value ]] || exit 64
  done
  [[ $(id -u) -eq 0 ]] || {
    echo "Deployment validation requires root for offline loop-device access" >&2
    exit 65
  }
  require_deployment_tools
  validation_receipt=$(readlink -f -- "$validation_receipt")
  validation_source=$(readlink -f -- "$validation_source")
  validation_os=$(readlink -f -- "$validation_os")
  validation_build=$(readlink -f -- "$validation_build")
  validation_evidence=$(readlink -f -- "$validation_evidence")
  validation_helper_hash=$(/usr/bin/sha256sum "$script_path" | /usr/bin/awk '{print $1}')
  validation_temporary=$(mktemp -d)
  chmod 0700 "$validation_temporary"
  validation_os_loop=
  cleanup_validation()
  {
    local status=$?
    trap - EXIT INT TERM HUP
    [[ -z ${os_loop:-} ]] || /usr/sbin/losetup --detach "$os_loop" 2>/dev/null || true
    cleanup_active_build_loop
    remove_contract_files "$validation_temporary"
    rm -f -- "$validation_temporary/result.json"
    rmdir -- "$validation_temporary" 2>/dev/null || true
    exit "$status"
  }
  trap cleanup_validation EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
  validate_published_deployment \
    "$validation_evidence" "$validation_receipt" "$validation_trusted_hash" \
    "$validation_source" "$validation_os" "$validation_build" \
    "$validation_helper_hash" "$validation_temporary" \
    "$validation_temporary/result.json"
  validation_json=$(<"$validation_temporary/result.json")
  deployment_id=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["deployment_id"])' \
    <<<"$validation_json")
  remove_contract_files "$validation_temporary"
  rm -f -- "$validation_temporary/result.json"
  rmdir -- "$validation_temporary"
  trap - EXIT INT TERM HUP
  echo "CAJUNOS_NATIVE_DEVELOPER_DEPLOYMENT_VALID deployment_id=$deployment_id evidence=$validation_evidence"
  exit 0
fi

if [[ ${1:-} == --validate-reproducibility ]]; then
  shift
  comparison_trusted_hash= comparison_evidence_a= comparison_evidence_b=
  comparison_output=
  while [[ $# -gt 0 ]]; do
    [[ $# -ge 2 ]] || exit 64
    case $1 in
      --receipt-sha256) comparison_trusted_hash=$2 ;;
      --evidence-a) comparison_evidence_a=$2 ;;
      --evidence-b) comparison_evidence_b=$2 ;;
      --comparison-output) comparison_output=$2 ;;
      *) exit 64 ;;
    esac
    shift 2
  done
  for value in "$comparison_trusted_hash" "$comparison_evidence_a" \
    "$comparison_evidence_b" "$comparison_output"; do
    [[ -n $value ]] || exit 64
  done
  [[ $(id -u) -eq 0 ]] || {
    echo "Deployment reproducibility validation requires root" >&2
    exit 65
  }
  require_deployment_tools
  comparison_evidence_a=$(readlink -f -- "$comparison_evidence_a")
  comparison_evidence_b=$(readlink -f -- "$comparison_evidence_b")
  comparison_output=$(readlink -m -- "$comparison_output")
  [[ $comparison_evidence_a != "$comparison_evidence_b" ]]
  "$script_path" --internal-python secure-output-parent \
    "$comparison_output" >/dev/null
  comparison_helper_hash=$(/usr/bin/sha256sum "$script_path" | /usr/bin/awk '{print $1}')
  comparison_stage=$(mktemp -d -p "$(dirname -- "$comparison_output")" \
    ".$(basename -- "$comparison_output").stage.XXXXXX")
  chmod 0700 "$comparison_stage"
  mkdir -m 0700 -- "$comparison_stage/a" "$comparison_stage/b"
  comparison_published=0
  cleanup_comparison()
  {
    local status=$?
    trap - EXIT INT TERM HUP
    [[ -z ${os_loop:-} ]] || /usr/sbin/losetup --detach "$os_loop" 2>/dev/null || true
    cleanup_active_build_loop
    remove_contract_files "$comparison_stage/a"
    remove_contract_files "$comparison_stage/b"
    rm -f -- "$comparison_stage/a/result.json" \
      "$comparison_stage/b/result.json" "$comparison_stage/comparison.json"
    rmdir -- "$comparison_stage/a" "$comparison_stage/b" 2>/dev/null || true
    rmdir -- "$comparison_stage" 2>/dev/null || true
    if [[ $status -ne 0 && $comparison_published == 1 ]]; then
      rm -f -- "$comparison_output"
    fi
    exit "$status"
  }
  trap cleanup_comparison EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
  for run in a b; do
    if [[ $run == a ]]; then
      run_evidence=$comparison_evidence_a
    else
      run_evidence=$comparison_evidence_b
    fi
    mapfile -t run_paths < <(python3 - "$run_evidence" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
print(value["source"]["receipt"])
print(value["source"]["disk"])
print(value["os_disk"]["path"])
print(value["build_disk"]["path"])
PY
)
    [[ ${#run_paths[@]} -eq 4 ]]
    validate_published_deployment "$run_evidence" "${run_paths[0]}" \
      "$comparison_trusted_hash" "${run_paths[1]}" "${run_paths[2]}" \
      "${run_paths[3]}" "$comparison_helper_hash" "$comparison_stage/$run" \
      "$comparison_stage/$run/result.json"
  done
  "$script_path" --internal-python compare-evidence \
    "$comparison_evidence_a" "$comparison_evidence_b" \
    >"$comparison_stage/comparison.json"
  chmod 0644 "$comparison_stage/comparison.json"
  publish_no_replace "$comparison_stage/comparison.json" "$comparison_output"
  comparison_published=1
  remove_contract_files "$comparison_stage/a"
  remove_contract_files "$comparison_stage/b"
  rm -f -- "$comparison_stage/a/result.json" "$comparison_stage/b/result.json"
  rmdir -- "$comparison_stage/a" "$comparison_stage/b"
  rmdir -- "$comparison_stage"
  trap - EXIT INT TERM HUP
  echo "CAJUNOS_NATIVE_DEVELOPER_DEPLOYMENT_REPRODUCIBLE comparison=$comparison_output"
  exit 0
fi

if [[ ${1:-} == --internal-create-build-disk ]]; then
  [[ $# -eq 8 || $# -eq 9 ]] || {
    echo "internal create-build-disk requires OUTPUT BYTES TYPE DISK_GUID PARTUUID FS_UUID EPOCH [SENTINEL]" >&2
    exit 64
  }
  output=$2; disk_bytes=$3; filesystem_type=$4
  disk_guid=$5; partuuid=$6; filesystem_uuid=$7; epoch=$8
  sentinel=${9:-}
  [[ $disk_bytes =~ ^[1-9][0-9]*$ && $disk_bytes -ge $((1024 * 1024 * 1024)) \
     && $((disk_bytes % 512)) -eq 0 && $epoch =~ ^[1-9][0-9]*$ ]] || exit 64
  "$script_path" --internal-python canonical-uuid "$disk_guid" >/dev/null
  "$script_path" --internal-python canonical-uuid "$partuuid" >/dev/null
  "$script_path" --internal-python canonical-uuid "$filesystem_uuid" >/dev/null
  output=$("$script_path" --internal-python private-output "$output") || exit 64
  if [[ -n $sentinel ]]; then
    sentinel=$("$script_path" --internal-python private-sentinel \
      "$sentinel" "$(dirname -- "$output")") || exit 64
  fi
  [[ $(id -u) -eq 0 ]] || {
    echo "internal create-build-disk requires root" >&2
    exit 65
  }
  create_build_disk "$output" "$disk_bytes" "$filesystem_type" \
    "$disk_guid" "$partuuid" "$filesystem_uuid" "$epoch" "$sentinel"
  if [[ $disk_bytes == $((256 * 1024 * 1024 * 1024)) && $filesystem_type == ext4 ]]; then
    "$script_path" --internal-python validate-build-disk \
      "$output" "$disk_guid" "$partuuid" "$filesystem_uuid" "$epoch" >/dev/null
  fi
  exit 0
fi

usage()
{
  echo "Usage: $0 --receipt RECEIPT --receipt-sha256 SHA256 --source STAGE9B.raw --os-output OS.raw --build-output BUILD.raw --evidence RECEIPT.json --build-disk-guid UUID --build-partuuid UUID --build-fs-uuid UUID" >&2
  exit 64
}

receipt= trusted_receipt_sha256= source= os_output= build_output= evidence=
build_disk_guid= build_partuuid= build_fs_uuid=
while [[ $# -gt 0 ]]; do
  [[ $# -ge 2 ]] || usage
  case $1 in
    --receipt) receipt=$2 ;;
    --receipt-sha256) trusted_receipt_sha256=$2 ;;
    --source) source=$2 ;;
    --os-output) os_output=$2 ;;
    --build-output) build_output=$2 ;;
    --evidence) evidence=$2 ;;
    --build-disk-guid) build_disk_guid=$2 ;;
    --build-partuuid) build_partuuid=$2 ;;
    --build-fs-uuid) build_fs_uuid=$2 ;;
    *) usage ;;
  esac
  shift 2
done
for value in "$receipt" "$trusted_receipt_sha256" "$source" "$os_output" "$build_output" "$evidence" \
  "$build_disk_guid" "$build_partuuid" "$build_fs_uuid"; do
  [[ -n $value ]] || usage
done
for identifier in "$build_disk_guid" "$build_partuuid" "$build_fs_uuid"; do
  "$script_path" --internal-python canonical-uuid "$identifier" >/dev/null
done
[[ -f $receipt && ! -L $receipt && -f $source && ! -L $source ]] || {
  echo "Receipt and pristine Stage 9B source must be plain files" >&2
  exit 65
}
[[ $(id -u) -eq 0 ]] || {
  echo "Deployment preparation requires root for offline loop-device access" >&2
  exit 65
}
mapfile -t canonical_outputs < <(/usr/bin/readlink -m -- \
  "$os_output" "$build_output" "$evidence")
[[ ${#canonical_outputs[@]} -eq 3 \
   && ${canonical_outputs[0]} != "${canonical_outputs[1]}" \
   && ${canonical_outputs[0]} != "${canonical_outputs[2]}" \
   && ${canonical_outputs[1]} != "${canonical_outputs[2]}" ]] || {
  echo "Deployment output paths must be three distinct files" >&2
  exit 66
}
os_output=${canonical_outputs[0]}
build_output=${canonical_outputs[1]}
evidence=${canonical_outputs[2]}
source=$(readlink -f -- "$source")
receipt=$(readlink -f -- "$receipt")
for output in "$os_output" "$build_output" "$evidence"; do
  [[ $output != "$source" && $output != "$receipt" ]] || {
    echo "Deployment output collides with a source input" >&2
    exit 66
  }
done
for output in "$os_output" "$build_output" "$evidence"; do
  [[ ! -e $output && ! -L $output ]] || {
    echo "Refusing existing deployment output: $output" >&2
    exit 66
  }
  parent=$(dirname -- "$output")
  [[ -d $parent && ! -L $parent ]] || {
    echo "Deployment output parent is not a real directory: $parent" >&2
    exit 66
  }
done
"$script_path" --internal-python secure-output-parent \
  "$os_output" "$build_output" "$evidence" >/dev/null
require_deployment_tools || exit 67

helper_sha256=$(/usr/bin/sha256sum "$script_path" | /usr/bin/awk '{print $1}')
source_receipt_sha256=$(/usr/bin/sha256sum "$receipt" | /usr/bin/awk '{print $1}')
source_contract_json=$("$script_path" --internal-python validate-source \
  "$receipt" "$source" "$helper_sha256" "$trusted_receipt_sha256")
mapfile -t source_values < <(python3 -c '
import json, sys
value = json.load(sys.stdin)
for key in ("build_id", "source_sha256", "source_date_epoch", "disk_guid",
            "bios_partuuid", "root_partuuid", "root_uuid"):
    print(value[key])
' <<<"$source_contract_json")
[[ ${#source_values[@]} -eq 7 ]] || exit 68
build_id=${source_values[0]}; source_sha256=${source_values[1]}
source_epoch=${source_values[2]}; root_partuuid=${source_values[5]}
deployment_contract_json=$("$script_path" --internal-python deployment-contract \
  "$build_id" "$build_disk_guid" "$build_partuuid" "$build_fs_uuid" \
  "$source_contract_json")
mapfile -t deployment_values < <(python3 -c '
import json, sys
value = json.load(sys.stdin)
for key in ("deployment_id", "sentinel_sha256"):
    print(value[key])
' <<<"$deployment_contract_json")
[[ ${#deployment_values[@]} -eq 2 ]] || exit 68
deployment_id=${deployment_values[0]}
sentinel_sha256=${deployment_values[1]}

os_stage= build_stage= evidence_stage=
os_temporary= build_temporary= evidence_temporary= contract_temporary=
os_loop=
published_os=0; published_build=0; published_evidence=0
cleanup()
{
  local status=$?
  trap - EXIT INT TERM HUP
  if [[ -n $os_loop ]]; then
    /usr/sbin/losetup --detach "$os_loop" 2>/dev/null || true
  fi
  cleanup_active_build_loop
  [[ -z $os_temporary ]] || rm -f -- "$os_temporary"
  [[ -z $build_temporary ]] || rm -f -- "$build_temporary"
  [[ -z $evidence_temporary ]] || rm -f -- "$evidence_temporary"
  [[ -z $os_stage ]] || rmdir -- "$os_stage" 2>/dev/null || true
  [[ -z $build_stage ]] || rmdir -- "$build_stage" 2>/dev/null || true
  [[ -z $evidence_stage ]] || rmdir -- "$evidence_stage" 2>/dev/null || true
  if [[ -n $contract_temporary ]]; then
    rm -f -- "$contract_temporary/build-partuuid" \
      "$contract_temporary/build-fs-uuid" \
      "$contract_temporary/build-sentinel-sha256" \
      "$contract_temporary/build-sentinel" \
      "$contract_temporary/base-fstab" "$contract_temporary/deployment-fstab" \
      "$contract_temporary/replay-result.json"
    rmdir -- "$contract_temporary" 2>/dev/null || true
  fi
  if [[ $status -ne 0 ]]; then
    [[ $published_evidence == 0 ]] || rm -f -- "$evidence"
    [[ $published_build == 0 ]] || rm -f -- "$build_output"
    [[ $published_os == 0 ]] || rm -f -- "$os_output"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
os_stage=$(mktemp -d -p "$(dirname -- "$os_output")" ".$(basename -- "$os_output").stage.XXXXXX")
build_stage=$(mktemp -d -p "$(dirname -- "$build_output")" ".$(basename -- "$build_output").stage.XXXXXX")
evidence_stage=$(mktemp -d -p "$(dirname -- "$evidence")" ".$(basename -- "$evidence").stage.XXXXXX")
chmod 0700 "$os_stage" "$build_stage" "$evidence_stage"
os_temporary=$os_stage/disk.raw
build_temporary=$build_stage/disk.raw
evidence_temporary=$evidence_stage/receipt.json
contract_temporary=$(mktemp -d)
chmod 0700 "$contract_temporary"
materialize_contract_files "$contract_temporary" "$deployment_contract_json"

/usr/bin/cp --sparse=always -- "$source" "$os_temporary"
/usr/bin/truncate -s $((64 * 1024 * 1024 * 1024)) "$os_temporary"
/usr/sbin/sgdisk --move-second-header -- "$os_temporary" >/dev/null
/usr/sbin/sgdisk --delete=2 --new=2:4096:0 --typecode=2:8300 \
  --change-name=2:CAJUNOS-ROOT --partition-guid=2:"$root_partuuid" \
  -- "$os_temporary" >/dev/null
os_loop=$(/usr/sbin/losetup --find --show --partscan -- "$os_temporary")
os_root_device=$(partition_device "$os_loop" 2)
E2FSCK_TIME="$source_epoch" /usr/sbin/e2fsck -f -n \
  "$os_root_device" >/dev/null
E2FSPROGS_FAKE_TIME="$source_epoch" /usr/sbin/resize2fs \
  "$os_root_device" 16776699 >/dev/null
for guest_path in /etc/cajunos-build-partuuid /etc/cajunos-build-fs-uuid \
  /etc/cajunos-build-sentinel-sha256; do
  ext_path_absent "$os_root_device" "$guest_path" \
    || { echo "Deployment root already contains a build-volume contract" >&2; exit 69; }
done
validate_ext_file "$os_root_device" /etc/fstab "$contract_temporary/base-fstab"
inject_ext_file "$os_root_device" "$contract_temporary/build-partuuid" \
  /etc/cajunos-build-partuuid "$source_epoch"
inject_ext_file "$os_root_device" "$contract_temporary/build-fs-uuid" \
  /etc/cajunos-build-fs-uuid "$source_epoch"
inject_ext_file "$os_root_device" "$contract_temporary/build-sentinel-sha256" \
  /etc/cajunos-build-sentinel-sha256 "$source_epoch"
inject_ext_file "$os_root_device" "$contract_temporary/deployment-fstab" \
  /etc/fstab "$source_epoch" 1
E2FSCK_TIME="$source_epoch" /usr/sbin/e2fsck -f -y "$os_root_device" >/dev/null
normalize_ext_superblock_time "$os_root_device" "$source_epoch"
"$script_path" --internal-python validate-ext-times \
  "$os_root_device" "$source_epoch" >/dev/null
verify_ext_noop_fsck "$os_root_device" "$source_epoch"
validate_ext_file "$os_root_device" /etc/cajunos-build-partuuid \
  "$contract_temporary/build-partuuid"
validate_ext_file "$os_root_device" /etc/cajunos-build-fs-uuid \
  "$contract_temporary/build-fs-uuid"
validate_ext_file "$os_root_device" /etc/cajunos-build-sentinel-sha256 \
  "$contract_temporary/build-sentinel-sha256"
validate_ext_file "$os_root_device" /etc/fstab "$contract_temporary/deployment-fstab"
/usr/sbin/losetup --detach "$os_loop"
os_loop=
chmod 0644 "$os_temporary"
expanded_json=$("$script_path" --internal-python validate-expanded \
  "$source" "$os_temporary" "$source_contract_json")

create_build_disk "$build_temporary" $((256 * 1024 * 1024 * 1024)) ext4 \
  "$build_disk_guid" "$build_partuuid" "$build_fs_uuid" "$source_epoch" \
  "$contract_temporary/build-sentinel"
build_json=$("$script_path" --internal-python validate-build-disk \
  "$build_temporary" "$build_disk_guid" "$build_partuuid" "$build_fs_uuid" \
  "$source_epoch")
[[ $(/usr/bin/sha256sum "$source" | /usr/bin/awk '{print $1}') == "$source_sha256" ]] || {
  echo "Pristine Stage 9B source changed during deployment preparation" >&2
  exit 69
}
[[ $(/usr/bin/sha256sum "$receipt" | /usr/bin/awk '{print $1}') \
   == "$source_receipt_sha256" ]] || {
  echo "Stage 9B receipt changed during deployment preparation" >&2
  exit 69
}
os_sha256=$(/usr/bin/sha256sum "$os_temporary" | /usr/bin/awk '{print $1}')
build_sha256=$(/usr/bin/sha256sum "$build_temporary" | /usr/bin/awk '{print $1}')
python3 - "$evidence_temporary" "$build_id" "$receipt" "$source" \
  "$source_sha256" "$os_output" "$os_sha256" "$build_output" "$build_sha256" \
  "$source_contract_json" "$expanded_json" "$build_json" \
  "$deployment_contract_json" "$helper_sha256" "$source_receipt_sha256" <<'PY'
import json, os, sys
(path, build_id, source_receipt, source_disk, source_sha256, os_disk,
 os_sha256, build_disk, build_sha256, source_json, expanded_json,
 build_json, deployment_json, helper_sha256, source_receipt_sha256) = sys.argv[1:]
value = {
    "schema": 1, "stage": "native-developer-deployment-preparation",
    "source": {
        "build_id": build_id, "receipt": source_receipt, "disk": source_disk,
        "receipt_sha256": source_receipt_sha256,
        "disk_sha256": source_sha256, "contract": json.loads(source_json),
    },
    "os_disk": {
        "path": os_disk, "sha256": os_sha256,
        "contract": json.loads(expanded_json),
        "prepared_offline_before_first_boot": True,
    },
    "build_disk": {
        "path": build_disk, "sha256": build_sha256,
        "contract": json.loads(build_json),
        "prepared_offline_before_first_boot": True,
    },
    "device_name_dependency": False,
    "deployment_contract": json.loads(deployment_json),
    "deployment_helper_sha256": helper_sha256,
    "validation": {
        "forced_fsck_after_final_mutation": True,
        "sentinel_revalidated_after_forced_fsck": True,
        "published_disks_replayed_before_evidence_publication": True,
        "runtime_disk_guid_validation": False,
    },
}
with open(path, "w", encoding="utf-8", newline="\n") as stream:
    json.dump(value, stream, indent=2, sort_keys=True); stream.write("\n")
os.chmod(path, 0o644)
PY
publish_no_replace "$os_temporary" "$os_output"; published_os=1
publish_no_replace "$build_temporary" "$build_output"; published_build=1
os_temporary= build_temporary=
validate_published_deployment "$evidence_temporary" "$receipt" \
  "$trusted_receipt_sha256" "$source" "$os_output" "$build_output" \
  "$helper_sha256" "$contract_temporary" \
  "$contract_temporary/replay-result.json"
publish_no_replace "$evidence_temporary" "$evidence"; published_evidence=1
evidence_temporary=
rmdir -- "$os_stage" "$build_stage" "$evidence_stage"
os_stage= build_stage= evidence_stage=
rm -f -- "$contract_temporary/build-partuuid" "$contract_temporary/build-fs-uuid" \
  "$contract_temporary/build-sentinel-sha256" "$contract_temporary/build-sentinel" \
  "$contract_temporary/base-fstab" "$contract_temporary/deployment-fstab" \
  "$contract_temporary/replay-result.json"
rmdir -- "$contract_temporary"
trap - EXIT INT TERM HUP
echo "CAJUNOS_NATIVE_DEVELOPER_DEPLOYMENT_PREPARED deployment_id=$deployment_id evidence=$evidence"
