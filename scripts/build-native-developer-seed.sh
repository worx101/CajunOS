#!/usr/bin/env bash
set -Eeuo pipefail
umask 022
export LC_ALL=C
export TZ=UTC
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

script_path=$(readlink -f -- "${BASH_SOURCE[0]}")
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

# The parsers below are also the replay authority.  Keeping them available
# without a forge lets the unit suite exercise the same fail-closed rules used
# immediately before publication and whenever a completed result is replayed.
if [[ ${1:-} == --internal-python ]]; then
  shift
  command_name=${1:-}
  shift || true
  exec python3 - "$command_name" "$@" <<'PY'
import binascii
import base64
import contextlib
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time


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


def atomic_text(path, value, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        path.chmod(mode)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def reject_xattrs(path, relative):
    try:
        attributes = os.listxattr(path, follow_symlinks=False)
    except OSError as error:
        fail(f"extended-metadata scan failed at {relative}: {error}")
    if attributes:
        fail(
            f"tree contains extended metadata at {relative}: "
            + ", ".join(sorted(attributes))
        )


def normalize_guest_path(base_parts, target, remaining=()):
    target_path = PurePosixPath(target)
    parts = [] if target_path.is_absolute() else list(base_parts)
    for part in (*target_path.parts, *remaining):
        if part in {"", ".", "/"}:
            continue
        if part == "..":
            if not parts:
                fail("symlink escapes the guest root")
            parts.pop()
        else:
            parts.append(part)
    return parts


def resolve_guest(root, parts, seen=None):
    """Resolve a guest path without interpreting / in a link as the host /."""
    root = Path(root)
    parts = list(parts)
    seen = set() if seen is None else seen
    resolved = []
    index = 0
    while index < len(parts):
        candidate = root.joinpath(*resolved, parts[index])
        try:
            metadata = candidate.lstat()
        except OSError as error:
            fail(f"tree contains a broken symlink target: {candidate}: {error}")
        if stat.S_ISLNK(metadata.st_mode):
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in seen or len(seen) >= 64:
                fail("tree contains a symlink cycle")
            seen.add(identity)
            target = os.readlink(candidate)
            remaining = parts[index + 1:]
            parts = normalize_guest_path(resolved, target, remaining)
            resolved = []
            index = 0
            continue
        resolved.append(parts[index])
        index += 1
    return root.joinpath(*resolved)


def validate_guest_symlink(root, path, relative):
    target = os.readlink(path)
    if "\0" in target or target == "":
        fail(f"tree contains an invalid symlink: {relative}")
    base = [] if "/" not in relative else relative.split("/")[:-1]
    parts = normalize_guest_path(base, target)
    resolve_guest(root, parts)
    return target


def scan_tree(root):
    root = Path(root)
    try:
        root_metadata = root.lstat()
    except OSError as error:
        fail(f"cannot inspect tree root: {error}")
    if not stat.S_ISDIR(root_metadata.st_mode) or root.is_symlink():
        fail("tree root is not a real directory")
    reject_xattrs(root, ".")
    records = [(root, root_metadata, ".")]

    def recurse(directory, relative):
        mode = stat.S_IMODE(directory.lstat().st_mode)
        if not any(mode & value == value for value in (0o500, 0o050, 0o005)):
            fail(f"tree contains an unreadable directory: {relative}")
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as error:
            fail(f"tree scan failed at {relative}: {error}")
        for entry in children:
            child_relative = entry.name if relative == "." else f"{relative}/{entry.name}"
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                fail(f"tree stat failed at {child_relative}: {error}")
            child = Path(entry.path)
            reject_xattrs(child, child_relative)
            records.append((child, metadata, child_relative))
            if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                recurse(child, child_relative)

    recurse(root, ".")
    return root, records


def inventory(root):
    root, records = scan_tree(root)
    regular_groups = {}
    for path, metadata, relative in records:
        if stat.S_ISREG(metadata.st_mode):
            regular_groups.setdefault((metadata.st_dev, metadata.st_ino), []).append(
                (path, metadata, relative)
            )
    hardlink_paths = {}
    for identity, group in regular_groups.items():
        expected = group[0][1].st_nlink
        names = sorted(item[2] for item in group)
        if expected != len(group):
            fail(
                "tree contains a regular file hard-linked outside the root: "
                + ", ".join(names)
            )
        modes = {stat.S_IMODE(item[1].st_mode) for item in group}
        if len(modes) != 1:
            fail("hard-linked paths report inconsistent modes")
        if expected > 1:
            hardlink_paths[identity] = names

    entries = {}
    for path, metadata, relative in records:
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
            entries[relative] = {"type": "directory", "mode": f"{mode:04o}"}
        elif stat.S_ISREG(metadata.st_mode):
            value = {
                "type": "file", "mode": f"{mode:04o}",
                "size": metadata.st_size, "sha256": sha256(path),
            }
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in hardlink_paths:
                value["hardlinks"] = hardlink_paths[identity]
            entries[relative] = value
        elif stat.S_ISLNK(metadata.st_mode) and metadata.st_nlink == 1:
            entries[relative] = {
                "type": "symlink", "mode": "0777",
                "target": validate_guest_symlink(root, path, relative),
            }
        else:
            fail(f"tree contains an unsupported entry: {relative}")
    return {"entries": entries, "digest": canonical_digest(entries)}


OVERLAY_EXECUTABLES = {"etc/init.d/rcS", "etc/init.d/rcK"}
OVERLAY_REQUIRED = {
    "etc/init.d/rcS": "0755",
    "etc/init.d/rcK": "0755",
    "etc/profile": "0644",
    "etc/shells": "0644",
    "etc/nsswitch.conf": "0644",
    "etc/ld.so.conf": "0644",
    "etc/dropbear/README": "0644",
}


def canonical_overlay_inventory(root):
    root, records = scan_tree(root)
    entries = {}
    for path, metadata, relative in records:
        mode = stat.S_IMODE(metadata.st_mode)
        if mode & 0o6000 or (mode & 0o002 and relative != "."):
            fail(f"overlay contains unsafe mode bits: {relative}")
        if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
            canonical = "0700" if relative == "etc/dropbear" else "0755"
            entries[relative] = {"type": "directory", "mode": canonical}
        elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            executable = bool(mode & 0o111)
            if executable != (relative in OVERLAY_EXECUTABLES):
                fail(f"overlay executable-bit contract failed: {relative}")
            canonical = "0755" if executable else "0644"
            entries[relative] = {
                "type": "file", "mode": canonical,
                "size": metadata.st_size, "sha256": sha256(path),
            }
        elif stat.S_ISLNK(metadata.st_mode) and metadata.st_nlink == 1:
            entries[relative] = {
                "type": "symlink", "mode": "0777",
                "target": validate_guest_symlink(root, path, relative),
            }
        else:
            fail(f"overlay contains an unsupported or hard-linked entry: {relative}")
    for relative, wanted in OVERLAY_REQUIRED.items():
        value = entries.get(relative)
        if value is None or value.get("type") != "file" or value.get("mode") != wanted:
            fail(f"overlay required-file contract failed: {relative}")
    forbidden = [name for name in entries if "dropbear" in name and "host_key" in name]
    if forbidden:
        fail("overlay must not seal a Dropbear server host key")
    exact = {
        ".", "etc", "etc/init.d", "etc/init.d/rcS", "etc/init.d/rcK",
        "etc/profile", "etc/shells", "etc/nsswitch.conf", "etc/ld.so.conf",
        "etc/dropbear", "etc/dropbear/README",
    }
    if set(entries) != exact:
        fail("overlay topology differs from the closed native-developer allowlist")
    return {"entries": entries, "digest": canonical_digest(entries)}


def canonicalize_root(root):
    root, records = scan_tree(root)
    by_inode = {}
    for path, metadata, relative in records:
        if stat.S_ISREG(metadata.st_mode):
            by_inode.setdefault((metadata.st_dev, metadata.st_ino), []).append(
                (path, metadata, relative)
            )
        elif not (
            stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
        ):
            fail(f"root tree contains an unsupported entry: {relative}")
        if metadata.st_mode & 0o6000:
            fail(f"root tree contains a set-id entry: {relative}")
    broken_hardlinks = 0
    for group in by_inode.values():
        expected = group[0][1].st_nlink
        if expected != len(group):
            fail("root tree contains a file hard-linked outside the root")
        if expected <= 1:
            continue
        for path, metadata, _relative in sorted(group, key=lambda item: item[2])[1:]:
            descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
            try:
                with os.fdopen(descriptor, "wb") as output, path.open("rb") as source:
                    shutil.copyfileobj(source, output, 1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(temporary, stat.S_IMODE(metadata.st_mode))
                os.utime(
                    temporary, ns=(metadata.st_atime_ns, metadata.st_mtime_ns)
                )
                os.replace(temporary, path)
            finally:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
            broken_hardlinks += 1
    if broken_hardlinks:
        root, records = scan_tree(root)
        by_inode = {}
        for path, metadata, relative in records:
            if stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1:
                    fail(f"root hardlink normalization failed: {relative}")
                by_inode[(metadata.st_dev, metadata.st_ino)] = [
                    (path, metadata, relative)
                ]
    directory_modes = {
        ".": 0o755, "root": 0o700, "root/.ssh": 0o700,
        "etc/dropbear": 0o700, "lost+found": 0o700, "tmp": 0o1777,
    }
    for path, metadata, relative in records:
        if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
            path.chmod(directory_modes.get(relative, 0o755))
        elif stat.S_ISLNK(metadata.st_mode):
            validate_guest_symlink(root, path, relative)
    private_files = {
        "etc/shadow", "root/.ssh/authorized_keys",
    }
    for group in by_inode.values():
        if group[0][1].st_nlink != len(group):
            fail("root tree contains a file hard-linked outside the root")
        names = {item[2] for item in group}
        modes = {stat.S_IMODE(item[1].st_mode) for item in group}
        executable = any(value & 0o111 for value in modes)
        if names & private_files:
            if len(names) != 1:
                fail("private root file must not be hard-linked")
            wanted = 0o600
        else:
            wanted = 0o755 if executable else 0o644
        group[0][0].chmod(wanted)
    required = {
        "bin/busybox": (stat.S_ISREG, 0o755),
        "etc/init.d/rcS": (stat.S_ISREG, 0o755),
        "etc/init.d/rcK": (stat.S_ISREG, 0o755),
        "root/.ssh/authorized_keys": (stat.S_ISREG, 0o600),
        "etc/shadow": (stat.S_ISREG, 0o600),
        "root": (stat.S_ISDIR, 0o700),
        "root/.ssh": (stat.S_ISDIR, 0o700),
        "build": (stat.S_ISDIR, 0o755),
        "etc/dropbear": (stat.S_ISDIR, 0o700),
        "lost+found": (stat.S_ISDIR, 0o700),
        "tmp": (stat.S_ISDIR, 0o1777),
    }
    for relative, (predicate, wanted) in required.items():
        path = root / relative
        try:
            metadata = path.lstat()
        except OSError:
            fail(f"canonical root lacks required path: {relative}")
        if path.is_symlink() or not predicate(metadata.st_mode):
            fail(f"canonical root has wrong type at: {relative}")
        if stat.S_IMODE(metadata.st_mode) != wanted:
            fail(f"canonical root has wrong mode at: {relative}")
    host_keys = [
        relative for _path, _metadata, relative in records
        if relative.startswith("etc/dropbear/") and "host_key" in relative
    ]
    if host_keys:
        fail("sealed root contains a Dropbear server host key")
    deployment_contract_paths = {
        "etc/cajunos-build-partuuid",
        "etc/cajunos-build-fs-uuid",
        "etc/cajunos-build-sentinel-sha256",
    }
    if any(relative in deployment_contract_paths for _path, _metadata, relative in records):
        fail("pristine root contains a deployment-specific build-volume contract")
    if any(
        relative == "etc/cajunos-static-network"
        for _path, _metadata, relative in records
    ):
        fail("pristine root contains a deployment-specific static network contract")
    if any(relative.startswith("build/") for _path, _metadata, relative in records):
        fail("pristine build mountpoint is not empty")
    result = inventory(root)
    result["hardlinks_broken"] = broken_hardlinks
    print(json.dumps(result, indent=2, sort_keys=True))


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


def validate_busybox_config(path):
    values = parse_kconfig(path)
    required_y = {
        "CONFIG_STATIC", "CONFIG_ASH", "CONFIG_SH_IS_ASH", "CONFIG_INIT",
        "CONFIG_TAR", "CONFIG_FEATURE_TAR_CREATE", "CONFIG_GZIP", "CONFIG_GUNZIP",
        "CONFIG_BZIP2", "CONFIG_BUNZIP2", "CONFIG_PATCH", "CONFIG_DIFF",
        "CONFIG_CMP", "CONFIG_FLOCK", "CONFIG_NPROC", "CONFIG_TIMEOUT",
        "CONFIG_SHA512SUM", "CONFIG_CKSUM", "CONFIG_FEATURE_SH_STANDALONE",
        "CONFIG_BLKID", "CONFIG_FEATURE_BLKID_TYPE",
        "CONFIG_FEATURE_VOLUMEID_EXT", "CONFIG_FEATURE_STAT_FILESYSTEM",
        "CONFIG_FEATURE_STAT_FORMAT", "CONFIG_POWEROFF", "CONFIG_REBOOT",
        "CONFIG_WC", "CONFIG_MV", "CONFIG_IP", "CONFIG_FEATURE_IP_ADDRESS",
        "CONFIG_FEATURE_IP_LINK", "CONFIG_FEATURE_IP_ROUTE",
        "CONFIG_TEST1",
        "CONFIG_FEATURE_SH_MATH",
    }
    required_n = {
        "CONFIG_AR", "CONFIG_FEATURE_AR_CREATE", "CONFIG_FEATURE_PREFER_APPLETS",
        "CONFIG_TC", "CONFIG_UDHCPC6", "CONFIG_FEATURE_SUID",
        "CONFIG_FEATURE_VOLUMEID_BCACHE", "CONFIG_FEATURE_VOLUMEID_BTRFS",
        "CONFIG_FEATURE_VOLUMEID_CRAMFS", "CONFIG_FEATURE_VOLUMEID_EROFS",
        "CONFIG_FEATURE_VOLUMEID_EXFAT", "CONFIG_FEATURE_VOLUMEID_F2FS",
        "CONFIG_FEATURE_VOLUMEID_FAT", "CONFIG_FEATURE_VOLUMEID_HFS",
        "CONFIG_FEATURE_VOLUMEID_ISO9660", "CONFIG_FEATURE_VOLUMEID_JFS",
        "CONFIG_FEATURE_VOLUMEID_LFS", "CONFIG_FEATURE_VOLUMEID_LINUXRAID",
        "CONFIG_FEATURE_VOLUMEID_LINUXSWAP", "CONFIG_FEATURE_VOLUMEID_LUKS",
        "CONFIG_FEATURE_VOLUMEID_MINIX", "CONFIG_FEATURE_VOLUMEID_NILFS",
        "CONFIG_FEATURE_VOLUMEID_NTFS", "CONFIG_FEATURE_VOLUMEID_OCFS2",
        "CONFIG_FEATURE_VOLUMEID_REISERFS", "CONFIG_FEATURE_VOLUMEID_ROMFS",
        "CONFIG_FEATURE_VOLUMEID_SQUASHFS", "CONFIG_FEATURE_VOLUMEID_SYSV",
        "CONFIG_FEATURE_VOLUMEID_UBIFS", "CONFIG_FEATURE_VOLUMEID_UDF",
        "CONFIG_FEATURE_VOLUMEID_XFS",
    }
    for key in sorted(required_y):
        if values.get(key) != "y":
            fail(f"required native-developer BusyBox symbol is not enabled: {key}")
    for key in sorted(required_n):
        if values.get(key, "n") != "n":
            fail(f"forbidden native-developer BusyBox symbol is enabled: {key}")
    print(json.dumps({"keys": len(values), "busybox_ar": "disabled"}, sort_keys=True))


def validate_dropbear_options(path, source_root):
    path = Path(path)
    source_root = Path(source_root)
    definitions = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = re.fullmatch(r"#define ([A-Z][A-Z0-9_]+)(?: (.+))?", line)
        if not match:
            continue
        name, value = match.group(1), match.group(2) or ""
        if name == "CAJUNOS_DROPBEAR_LOCALOPTIONS_H":
            continue
        if name in definitions:
            fail(f"duplicate Dropbear local option on line {number}: {name}")
        definitions[name] = value
    expected = {
        "DROPBEAR_SVR_PUBKEY_AUTH": "1",
        "DROPBEAR_SVR_PASSWORD_AUTH": "0",
        "DROPBEAR_SVR_PAM_AUTH": "0",
        "DROPBEAR_SVR_LOCALTCPFWD": "0",
        "DROPBEAR_SVR_REMOTETCPFWD": "0",
        "DROPBEAR_SVR_LOCALSTREAMFWD": "0",
        "DROPBEAR_SVR_REMOTESTREAMFWD": "0",
        "DROPBEAR_SVR_AGENTFWD": "0",
        "DROPBEAR_X11FWD": "0",
        "DROPBEAR_SFTPSERVER": "0",
        "DROPBEAR_SVR_PUBKEY_OPTIONS": "0",
        "INETD_MODE": "0",
        "NON_INETD_MODE": "1",
        "DROPBEAR_CLIENT": "0",
        "DROPBEAR_SERVER": "1",
        "DROPBEAR_PIDFILE": '"/run/dropbear.pid"',
    }
    if definitions != expected:
        fail("Dropbear local options differ from the closed key-only contract")
    headers = []
    for candidate in sorted(source_root.rglob("*")):
        if candidate == path:
            continue
        if candidate.is_file() and not candidate.is_symlink() and candidate.suffix in {".h", ".c"}:
            try:
                headers.append(candidate.read_text(encoding="utf-8"))
            except UnicodeDecodeError:
                continue
    source_text = "\n".join(headers)
    selectors = {"DROPBEAR_CLIENT", "DROPBEAR_SERVER", "DROPBEAR_PIDFILE"}
    for name in definitions:
        if name not in selectors and not re.search(rf"\b{re.escape(name)}\b", source_text):
            fail(f"Dropbear local option is unknown to the locked source: {name}")
    forbidden_claims = {"DROPBEAR_ALLOW_EMPTY_PASSWORD"}
    if forbidden_claims & set(definitions):
        fail("Dropbear local options contain an inert security claim")
    print(json.dumps({
        "macros": definitions, "password_code": "compiled-out",
        "pam_code": "compiled-out", "public_key": "enabled",
    }, sort_keys=True))


def validate_runtime_root(root):
    root = Path(root)
    exact_text = {
        "etc/passwd": "root:x:0:0:root:/root:/bin/ash\n",
        "etc/shadow": "root:!:0:0:99999:7:::\n",
        "etc/shells": "/bin/ash\n/bin/sh\n",
        "etc/nsswitch.conf": (
            "passwd: files\ngroup: files\nshadow: files\n"
            "hosts: files dns\nnetworks: files\n"
        ),
        "etc/ld.so.conf": "/lib\n/usr/lib\n/lib64\n/usr/lib64\n",
    }
    for relative, wanted in exact_text.items():
        path = root / relative
        if path.is_symlink() or path.read_text(encoding="utf-8") != wanted:
            fail(f"runtime root account/NSS contract differs: {relative}")
    required = (
        "lib64/ld-linux-x86-64.so.2",
        "usr/bin/gcc", "usr/bin/g++", "usr/bin/make", "usr/bin/ar",
        "usr/bin/as", "usr/bin/ld", "usr/sbin/dropbear", "usr/bin/dropbearkey",
    )
    for relative in required:
        path = root / relative
        try:
            metadata = path.lstat()
        except OSError:
            fail(f"runtime root lacks required closure path: {relative}")
        if stat.S_ISLNK(metadata.st_mode):
            validate_guest_symlink(root, path, relative)
            path = resolve_guest(root, relative.split("/"))
            metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or not metadata.st_mode & 0o111
        ):
            fail(f"runtime root closure path is not executable: {relative}")
        if relative == "lib64/ld-linux-x86-64.so.2":
            header = subprocess.run(
                ["/usr/bin/readelf", "-hW", path], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                env=os.environ | {"LC_ALL": "C"},
            )
            dynamic = subprocess.run(
                ["/usr/bin/readelf", "-dW", path], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                env=os.environ | {"LC_ALL": "C"},
            )
            if header.returncode != 0 or dynamic.returncode != 0:
                fail("runtime root loader is not a valid dynamic ELF")
            exact_header = (
                "Class:                             ELF64",
                "Data:                              2's complement, little endian",
                "Type:                              DYN (Shared object file)",
                "Machine:                           Advanced Micro Devices X86-64",
            )
            if any(line not in header.stdout for line in exact_header):
                fail("runtime root loader ELF identity differs")
            needed = re.findall(
                r"\(NEEDED\).*Shared library: \[([^]]+)\]", dynamic.stdout
            )
            sonames = re.findall(
                r"\(SONAME\).*Library soname: \[([^]]+)\]", dynamic.stdout
            )
            if needed or sonames != ["ld-linux-x86-64.so.2"]:
                fail("runtime root loader dynamic contract differs")
    dynamic_contracts = {
        "libnss_files.so.2": ["libc.so.6"],
        "libnss_dns.so.2": ["libresolv.so.2", "libc.so.6"],
        "libresolv.so.2": ["libc.so.6"],
    }
    dynamic_modules = {}
    for soname, expected_needed in dynamic_contracts.items():
        relative = f"usr/lib/{soname}"
        path = root / relative
        try:
            metadata = path.lstat()
        except OSError:
            fail(f"runtime root lacks the sealed glibc NSS module: {soname}")
        if stat.S_ISLNK(metadata.st_mode):
            validate_guest_symlink(root, path, relative)
            path = resolve_guest(root, relative.split("/"))
            metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            fail(f"runtime root NSS module is not one confined regular file: {soname}")
        result = subprocess.run(
            ["/usr/bin/readelf", "-dW", path], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if result.returncode != 0:
            fail(f"runtime root NSS module is not a valid dynamic ELF: {soname}")
        needed = re.findall(r"\(NEEDED\).*Shared library: \[([^]]+)\]", result.stdout)
        sonames = re.findall(r"\(SONAME\).*Library soname: \[([^]]+)\]", result.stdout)
        if needed != expected_needed or sonames != [soname]:
            fail(f"runtime root NSS module dynamic contract differs: {soname}")
        dynamic_modules[soname] = {
            "path": relative, "needed": needed, "soname": sonames[0],
            "sha256": sha256(path),
        }
    if list(root.rglob("*.la")):
        fail("runtime root contains non-relocatable libtool archives")
    host_keys = list((root / "etc/dropbear").glob("*host_key*"))
    if host_keys:
        fail("sealed runtime root contains a server host key")
    print(json.dumps({
        "loader": "/lib64/ld-linux-x86-64.so.2",
        "nss": {
            "order": ["files", "dns"],
            "modules": {
                name: dynamic_modules[name]
                for name in ("libnss_files.so.2", "libnss_dns.so.2")
            },
            "resolver": dynamic_modules["libresolv.so.2"],
        },
    }, sort_keys=True))


EXT4_FEATURES = frozenset({
    "has_journal", "ext_attr", "dir_index", "filetype", "extent", "64bit",
    "flex_bg", "sparse_super", "large_file", "huge_file", "dir_nlink",
    "extra_isize", "metadata_csum",
})
EXT4_EXACT_FIELDS = {
    "Filesystem volume name": "CAJUNOS_ROOT",
    "Filesystem state": "clean",
    "Errors behavior": "Continue",
    "Filesystem OS type": "Linux",
    "Inode count": "786432",
    "Block count": "3145728",
    "Reserved block count": "0",
    "First block": "0",
    "Block size": "4096",
    "Fragment size": "4096",
    "Group descriptor size": "64",
    "Blocks per group": "32768",
    "Fragments per group": "32768",
    "Inodes per group": "8192",
    "Inode blocks per group": "512",
    "Flex block group size": "16",
    "Reserved blocks uid": "0 (user root)",
    "Reserved blocks gid": "0 (group root)",
    "First inode": "11",
    "Inode size": "256",
    "Required extra isize": "32",
    "Desired extra isize": "32",
    "Journal inode": "8",
    "Default directory hash": "half_md4",
    "Journal backup": "inode blocks",
    "Checksum type": "crc32c",
    "Journal features": "(none)",
    "Total journal size": "64M",
    "Total journal blocks": "16384",
    "Max transaction length": "16384",
    "Fast commit length": "0",
}


def validate_ext4(path, filesystem_uuid, hash_seed, expected_bytes, expected_epoch, mode):
    path = Path(path)
    expected_bytes = int(expected_bytes)
    expected_epoch = int(expected_epoch)
    metadata = path.lstat()
    if (
        path.is_symlink() or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o644
        or expected_bytes != 12 * 1024**3 or metadata.st_size != expected_bytes
        or mode not in {"pristine", "runtime"}
    ):
        fail("journaled ext4 image has the wrong topology or size")
    environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "TZ": "UTC",
        "MKE2FS_CONFIG": "/dev/null",
    }
    result = subprocess.run(
        ["/usr/sbin/dumpe2fs", "-h", path], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
    )
    fields = {}
    for line in result.stdout.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip()
            if key in fields:
                fail(f"duplicate journaled ext4 header field: {key}")
            fields[key] = value.strip()
    if fields.get("Filesystem UUID") != filesystem_uuid:
        fail("journaled ext4 UUID differs")
    if fields.get("Directory Hash Seed") != hash_seed:
        fail("journaled ext4 directory hash seed differs")
    for key, wanted in EXT4_EXACT_FIELDS.items():
        if fields.get(key) != wanted:
            fail(f"journaled ext4 header mismatch for {key}: {fields.get(key)!r}")
    features = set(fields.get("Filesystem features", "").split())
    if features != EXT4_FEATURES:
        fail(
            "journaled ext4 feature contract differs: "
            f"missing={sorted(EXT4_FEATURES - features)!r} "
            f"unexpected={sorted(features - EXT4_FEATURES)!r}"
        )
    if set(fields.get("Filesystem flags", "").split()) != {"signed_directory_hash"}:
        fail("journaled ext4 filesystem flags differ")
    if set(fields.get("Default mount options", "").split()) != {"acl", "user_xattr"}:
        fail("journaled ext4 default mount options differ")
    timestamp = time.strftime(
        "%a %b %e %H:%M:%S %Y", time.gmtime(expected_epoch)
    )
    if fields.get("Filesystem created") != timestamp or fields.get("Last checked") != timestamp:
        fail("journaled ext4 creation/check time differs")
    if mode == "pristine" and (
        fields.get("Last mounted on") != "<not available>"
        or fields.get("Last mount time") != "n/a"
        or fields.get("Last write time") != timestamp
        or fields.get("Mount count") != "0"
        or fields.get("Journal sequence") != "0x00000001"
        or fields.get("Journal start") != "0"
    ):
        fail("pristine journaled ext4 mutable header fields differ")
    check = subprocess.run(
        ["/usr/sbin/e2fsck", "-f", "-n", path], check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=environment,
    )
    if check.returncode != 0:
        fail(f"forced read-only fsck rejected ext4 (status {check.returncode})")
    print(json.dumps({
        "bytes": expected_bytes, "filesystem_uuid": filesystem_uuid,
        "hash_seed": hash_seed, "features": sorted(EXT4_FEATURES),
        "filesystem_state": "clean", "forced_fsck": "passed", "mode": mode,
    }, sort_keys=True))


def validate_public_key(path, output=None):
    path = Path(path)
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) not in {0o600, 0o644}
    ):
        fail("approved SSH public key is not a mode-0600/0644 single-linked file")
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(lines) != 1:
        fail("approved SSH public-key file must contain exactly one non-empty line")
    fields = lines[0].split()
    if len(fields) not in {2, 3} or fields[0] != "ssh-ed25519":
        fail("approved SSH key must be one unoptioned Ed25519 public key")
    try:
        decoded = base64.b64decode(fields[1], validate=True)
    except (ValueError, binascii.Error):
        fail("approved SSH public-key blob is not canonical base64")
    if base64.b64encode(decoded).decode("ascii") != fields[1]:
        fail("approved SSH public-key blob is not canonical base64")
    if len(decoded) != 51 or decoded[:4] != b"\0\0\0\x0b" or decoded[4:15] != b"ssh-ed25519":
        fail("approved SSH key does not have the Ed25519 wire encoding")
    key_length = struct.unpack_from(">I", decoded, 15)[0]
    if key_length != 32 or len(decoded[19:]) != key_length:
        fail("approved SSH Ed25519 key has the wrong length")
    canonical = f"ssh-ed25519 {fields[1]}"
    fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(decoded).digest()
    ).decode("ascii").rstrip("=")
    if output is not None:
        atomic_text(output, canonical + "\n", 0o600)
    print(json.dumps({
        "algorithm": "ssh-ed25519", "blob": fields[1],
        "canonical": canonical, "fingerprint": fingerprint,
        "input_sha256": sha256(path),
        "canonical_sha256": hashlib.sha256((canonical + "\n").encode()).hexdigest(),
    }, sort_keys=True))


def rewrite_gcc_configargs(path, replacements):
    if not replacements or len(replacements) % 2:
        fail("rewrite-gcc-configargs requires exact FROM/TO pairs")
    source = Path(path)
    metadata = source.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail("gcc/configargs.h is not a plain single-linked file")
    raw = source.read_text(encoding="utf-8")
    changed = raw
    seen_targets = set()
    for old, new in zip(replacements[::2], replacements[1::2], strict=True):
        if not old.startswith("/") or not new.startswith("/") or old == new:
            fail("unsafe GCC configargs rewrite pair")
        if old in seen_targets or old not in changed:
            fail(f"GCC configargs rewrite source is absent or duplicate: {old}")
        count = changed.count(old)
        changed = changed.replace(old, new)
        if count < 1 or old in changed:
            fail(f"GCC configargs rewrite was incomplete: {old}")
        seen_targets.add(old)
    if changed == raw:
        fail("GCC configargs rewrite changed nothing")
    atomic_text(source, changed)
    print(json.dumps({"sha256": sha256(source), "pairs": len(replacements) // 2}, sort_keys=True))


def scan_forbidden(root, tokens):
    if not tokens:
        fail("scan-forbidden requires at least one token")
    for token in tokens:
        if not token.startswith("/") or "\0" in token:
            fail("forbidden path token is unsafe")
    root, records = scan_tree(root)
    findings = []
    for path, metadata, relative in records:
        if not stat.S_ISREG(metadata.st_mode):
            continue
        data = path.read_bytes()
        for token in tokens:
            if token.encode() in data:
                findings.append(f"{relative}:{token}")
    if findings:
        fail("installed payload contains forge/build paths: " + ", ".join(findings))
    print(json.dumps({"files": sum(stat.S_ISREG(item[1].st_mode) for item in records)}, sort_keys=True))


def scan_private_material(root):
    root, records = scan_tree(root)
    findings = []

    def has_private_key_header(path):
        # Keep memory bounded even for the sparse 16-GiB raw disk.  Only the
        # beginning of each physical line can be a PEM header; source string
        # literals containing the same words remain harmless and admissible.
        at_line_start = True
        candidate = bytearray()
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                position = 0
                while position < len(chunk):
                    if at_line_start:
                        newline = chunk.find(b"\n", position)
                        end = len(chunk) if newline < 0 else newline
                        room = max(0, 128 - len(candidate))
                        candidate.extend(chunk[position:min(end, position + room)])
                        if len(candidate) >= 128 and newline < 0:
                            candidate.clear()
                            at_line_start = False
                            position = len(chunk)
                            continue
                        if newline < 0:
                            position = len(chunk)
                            continue
                        line = bytes(candidate).rstrip(b"\r")
                        if re.fullmatch(
                            rb"-----BEGIN [A-Z0-9 -]*PRIVATE KEY-----", line
                        ):
                            return True
                        candidate.clear()
                        position = newline + 1
                    else:
                        newline = chunk.find(b"\n", position)
                        if newline < 0:
                            position = len(chunk)
                        else:
                            at_line_start = True
                            position = newline + 1
            if at_line_start:
                line = bytes(candidate).rstrip(b"\r")
                return bool(re.fullmatch(
                    rb"-----BEGIN [A-Z0-9 -]*PRIVATE KEY-----", line
                ))
        return False

    for path, metadata, relative in records:
        if not stat.S_ISREG(metadata.st_mode):
            continue
        if has_private_key_header(path):
            findings.append(f"{relative}:private-key-marker")
        if relative.startswith("etc/dropbear/") and relative != "etc/dropbear/README":
            findings.append(f"{relative}:sealed-dropbear-state")
        if relative.startswith("root/.ssh/") and relative != "root/.ssh/authorized_keys":
            findings.append(f"{relative}:unexpected-root-ssh-state")
    if findings:
        fail("tree contains private or runtime SSH material: " + ", ".join(findings))
    print(json.dumps({"private_key_material": False}, sort_keys=True))


OMITTED_PRIVATE_FIXTURES = [
    {
        "kind": "pem-private-test-key",
        "path": "libtomcrypt/testprof/test.key",
        "reason": "private-test-fixture-not-shipped",
        "sha256": "76ec7faebdc42a4de35ca70024c2d273e9f7856ca61612e89f5f66350ba8cf5f",
    },
    {
        "kind": "pem-private-test-key",
        "path": "libtomcrypt/tests/test.key",
        "reason": "private-test-fixture-not-shipped",
        "sha256": "76ec7faebdc42a4de35ca70024c2d273e9f7856ca61612e89f5f66350ba8cf5f",
    },
    {
        "kind": "pem-private-test-key",
        "path": "libtomcrypt/tests/test_dsa.key",
        "reason": "private-test-fixture-not-shipped",
        "sha256": "8a44ced5b373b6124f56bb33577a98585cce3d65671e5303384c4236f9b4d41c",
    },
    {
        "kind": "embedded-private-host-key-fixture",
        "path": "fuzz/fuzz-hostkeys.c",
        "reason": "private-test-fixture-not-shipped",
        "sha256": "0370305b5582f7375fc00e84ff80b49945cb04e93c401ed11194124b390ee92c",
    },
]


def validate_omitted_private_fixtures(path):
    path = Path(path)
    try:
        metadata = path.lstat()
    except OSError:
        fail("omitted-private-fixture manifest is absent")
    if (
        not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o644
    ):
        fail("omitted-private-fixture manifest is not one mode-0644 file")
    value = load_json(path)
    expected = {"schema": 1, "omitted": OMITTED_PRIVATE_FIXTURES}
    if value != expected:
        fail("omitted-private-fixture manifest topology or records differ")
    return {
        "manifest_sha256": sha256(path),
        "records": OMITTED_PRIVATE_FIXTURES,
    }


def validate_grown_disk(base_path, grown_path, filesystem_bytes):
    base = Path(base_path)
    grown = Path(grown_path)
    filesystem_bytes = int(filesystem_bytes)
    if base.is_symlink() or grown.is_symlink() or not base.is_file() or not grown.is_file():
        fail("disk validation requires plain files")
    if grown.stat().st_size != 16 * 1024**3:
        fail("native-developer raw disk is not exactly 16 GiB")
    if filesystem_bytes != 12 * 1024**3:
        fail("native-developer ext4 filesystem is not exactly 12 GiB")
    with base.open("rb") as first, grown.open("rb") as second:
        if first.read(446) != second.read(446):
            fail("grown disk changed the GRUB MBR boot code")
        first.seek(2048 * 512)
        second.seek(2048 * 512)
        if first.read(2048 * 512) != second.read(2048 * 512):
            fail("grown disk changed the embedded GRUB BIOS partition")
        second.seek(4096 * 512 + 1024)
        superblock = second.read(1024)
    if len(superblock) != 1024 or struct.unpack_from("<H", superblock, 56)[0] != 0xEF53:
        fail("grown disk root partition lacks an ext4 superblock")
    blocks_lo = struct.unpack_from("<I", superblock, 4)[0]
    blocks_hi = struct.unpack_from("<I", superblock, 0x150)[0]
    incompat = struct.unpack_from("<I", superblock, 96)[0]
    compat = struct.unpack_from("<I", superblock, 92)[0]
    filesystem_state = struct.unpack_from("<H", superblock, 58)[0]
    blocks = blocks_lo | ((blocks_hi << 32) if incompat & 0x80 else 0)
    block_size = 1024 << struct.unpack_from("<I", superblock, 24)[0]
    if blocks * block_size != filesystem_bytes:
        fail("embedded ext4 size differs from the 12 GiB contract")
    if not compat & 0x4:
        fail("embedded ext4 lacks its journal")
    if not filesystem_state & 0x1 or incompat & 0x4:
        fail("embedded ext4 is not clean or still needs journal recovery")
    print(json.dumps({
        "disk_bytes": grown.stat().st_size,
        "filesystem_bytes": filesystem_bytes,
        "grub_embedding_preserved": True,
        "has_journal": True,
        "filesystem_state": "clean",
    }, sort_keys=True))


def normalized_serial(path):
    data = Path(path).read_bytes()
    # GRUB's i386-pc serial terminal emits one deterministic clear-screen
    # sequence before its first printable byte.  Remove only that exact
    # byte-zero prologue; any other escape or a repeated prologue remains a
    # fail-closed terminal-control injection.
    grub_serial_prologue = b"\x1b[H\x1b[J\x1b[1;1H"
    if data.startswith(grub_serial_prologue):
        data = data[len(grub_serial_prologue):]
    if b"\x00" in data or b"\x1b" in data:
        fail("serial transcript contains terminal control bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        fail("serial transcript is not UTF-8")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def validate_serial(kind, path, release, build_id, host_key_output=None, normalized_output=None):
    if kind not in {"positive", "negative"}:
        fail("serial kind must be positive or negative")
    if kind == "negative" and host_key_output is not None and normalized_output is None:
        normalized_output = host_key_output
        host_key_output = None
    text = normalized_serial(path)
    lines = text.splitlines()
    if re.search(r"(^|[\[ ])(?:Kernel panic|Oops:|BUG:)", text, re.I | re.M):
        fail("serial transcript contains a kernel failure")
    success_markers = [
        "CAJUNOS_NATIVE_DEVELOPER_BEGIN",
        f"CAJUNOS_NATIVE_DEVELOPER_BUILD_ID {build_id}",
        "CAJUNOS_NATIVE_DEVELOPER_ROOT_OK",
        "CAJUNOS_NATIVE_DEVELOPER_NETWORK_OK",
    ]
    if kind == "negative":
        begin = "CAJUNOS_NATIVE_DEVELOPER_BEGIN"
        failure = "CAJUNOS_NATIVE_DEVELOPER_FAIL cmdline-token"
        if lines.count(begin) != 1 or lines.count(failure) != 1:
            fail("negative serial lacks its exact begin/failure markers")
        if lines.index(begin) >= lines.index(failure):
            fail("negative serial markers are out of order")
        forbidden_prefixes = (
            "CAJUNOS_NATIVE_DEVELOPER_BUILD_ID ",
            "CAJUNOS_NATIVE_DEVELOPER_ROOT_OK",
            "CAJUNOS_NATIVE_DEVELOPER_NETWORK_OK",
            "CAJUNOS_NATIVE_DEVELOPER_IPV4 ",
            "CAJUNOS_NATIVE_DEVELOPER_SSH_HOST_KEY ",
            "CAJUNOS_NATIVE_DEVELOPER_SSH_READY",
            "CAJUNOS_NATIVE_DEVELOPER_UNAME ",
            "CAJUNOS_NATIVE_DEVELOPER_OK",
        )
        if any(any(line.startswith(prefix) for prefix in forbidden_prefixes) for line in lines):
            fail("negative serial contains success identity or completion")
        failures = [line for line in lines if line.startswith("CAJUNOS_NATIVE_DEVELOPER_FAIL ")]
        if failures != [failure]:
            fail("negative serial contains an unexpected failure marker")
        if normalized_output is not None:
            atomic_text(normalized_output, text)
        print(json.dumps({"build_id": build_id, "kind": "negative"}, sort_keys=True))
        return
    host_lines = [
        line for line in lines
        if line.startswith("CAJUNOS_NATIVE_DEVELOPER_SSH_HOST_KEY ")
    ]
    if len(host_lines) != 1:
        fail("serial transcript lacks one exact SSH host-key marker")
    ipv4_lines = [
        line for line in lines
        if line.startswith("CAJUNOS_NATIVE_DEVELOPER_IPV4 ")
    ]
    if len(ipv4_lines) != 1:
        fail("serial transcript lacks one exact IPv4 marker")
    ipv4 = ipv4_lines[0].split(" ", 1)[1]
    try:
        address = ipaddress.IPv4Address(ipv4)
    except ipaddress.AddressValueError:
        fail("serial transcript IPv4 marker is invalid")
    if str(address) != ipv4:
        fail("serial transcript IPv4 marker is not canonical")
    host_key = host_lines[0].split(" ", 1)[1]
    if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\r\n]+)?", host_key):
        fail("serial transcript contains an invalid SSH host public key")
    success_markers.extend([
        ipv4_lines[0],
        host_lines[0],
        "CAJUNOS_NATIVE_DEVELOPER_SSH_READY",
        f"CAJUNOS_NATIVE_DEVELOPER_UNAME {release}",
        "CAJUNOS_NATIVE_DEVELOPER_OK",
    ])
    positions = []
    for marker in success_markers:
        if lines.count(marker) != 1:
            fail(f"serial marker missing or non-unique: {marker}")
        positions.append(lines.index(marker))
    if positions != sorted(positions):
        fail("serial markers are out of order")
    if any(line.startswith("CAJUNOS_NATIVE_DEVELOPER_FAIL ") for line in lines):
        fail("serial transcript contains a failure marker")
    if host_key_output is not None:
        atomic_text(host_key_output, host_key + "\n")
    if normalized_output is not None:
        atomic_text(normalized_output, text)
    print(json.dumps({
        "build_id": build_id, "host_key": host_key, "ipv4": ipv4,
    }, sort_keys=True))


def validate_ssh_evidence(path, build_id, nonce, host_key_sha256):
    value = load_json(path)
    expected = {
        "schema", "build_id", "boot", "host_key_sha256", "authentication",
        "toolchain", "package_rebuild", "persistence", "template_safety",
    }
    if not isinstance(value, dict) or set(value) != expected:
        fail("SSH evidence topology differs")
    if value["schema"] != 1 or value["build_id"] != build_id:
        fail("SSH evidence identity differs")
    if value["host_key_sha256"] != host_key_sha256:
        fail("SSH evidence host key differs")
    if value["boot"] != "disk-only-gpt-bios-grub-qcow2-overlay":
        fail("SSH evidence did not exercise the disk boot path")
    if value["authentication"] != {
        "no_key_rejected": True,
        "wrong_key_rejected": True,
        "password_rejected": True,
        "dedicated_probe_key_succeeded": True,
        "owner_key_succeeded": True,
        "strict_host_key_pinning": True,
        "success_method": "publickey",
        "interactive_pty": True,
    }:
        fail("SSH authentication evidence differs")
    tools = value["toolchain"]
    required_tools = {"gcc", "g++", "ld", "as", "ar", "make"}
    if not isinstance(tools, dict) or set(tools) != required_tools:
        fail("SSH toolchain evidence topology differs")
    if any(not isinstance(item, str) or not item for item in tools.values()):
        fail("SSH toolchain evidence is empty")
    if not tools["ar"].startswith("GNU ar"):
        fail("SSH package probes did not use GNU ar")
    rebuild = value["package_rebuild"]
    if rebuild != {
        "c": True, "c_static": True, "cxx": True, "assembly": True,
        "archive": True, "make": True, "dropbearkey": True,
        "dns_resolution": True,
    }:
        fail("SSH native package rebuild evidence differs")
    if value["persistence"] != {
        "nonce": nonce, "nonce_survived_reboot": True,
        "host_key_survived_reboot": True,
    }:
        fail("SSH persistence evidence differs")
    if value["template_safety"] != {
        "pristine_seed_only": True,
        "validation_disks_forbidden_as_template_sources": True,
        "independent_clone_host_keys_differ": True,
    }:
        fail("SSH template-safety evidence differs")
    print(json.dumps({"build_id": build_id, "valid": True}, sort_keys=True))


def validate_owner_request(path, build_id, owner_key_sha256, port):
    value = load_json(path)
    expected = {
        "schema", "build_id", "challenge", "host", "port", "host_key",
        "host_key_sha256", "owner_public_key_sha256", "namespace",
    }
    if not isinstance(value, dict) or set(value) != expected:
        fail("owner-proof request topology differs")
    if (
        value["schema"] != 1 or value["build_id"] != build_id
        or value["host"] != "127.0.0.1"
        or value["namespace"] != "cajunos-native-developer-owner-proof"
        or value["owner_public_key_sha256"] != owner_key_sha256
    ):
        fail("owner-proof request identity differs")
    if not re.fullmatch(r"[0-9a-f]{64}", value["challenge"]):
        fail("owner-proof request challenge is unsafe")
    try:
        expected_port = int(port)
    except ValueError:
        fail("expected owner-proof request port is unsafe")
    if (
        not isinstance(value["port"], int) or value["port"] != expected_port
        or not 1024 <= value["port"] <= 65535
    ):
        fail("owner-proof request port is unsafe")
    fields = value["host_key"].split() if isinstance(value["host_key"], str) else []
    if len(fields) != 2 or fields[0] != "ssh-ed25519":
        fail("owner-proof request host key is not canonical Ed25519")
    try:
        decoded = base64.b64decode(fields[1], validate=True)
    except (ValueError, binascii.Error):
        fail("owner-proof request host key is not canonical base64")
    if (
        base64.b64encode(decoded).decode("ascii") != fields[1]
        or len(decoded) != 51 or decoded[:4] != b"\0\0\0\x0b"
        or decoded[4:15] != b"ssh-ed25519"
        or struct.unpack_from(">I", decoded, 15)[0] != 32
    ):
        fail("owner-proof request host-key wire encoding differs")
    canonical = " ".join(fields)
    host_key_sha256 = hashlib.sha256((canonical + "\n").encode()).hexdigest()
    if value["host_key_sha256"] != host_key_sha256:
        fail("owner-proof request host key hash differs")
    print(json.dumps({
        "build_id": build_id, "challenge": value["challenge"],
        "host_key": canonical, "host_key_sha256": host_key_sha256,
        "owner_public_key_sha256": owner_key_sha256,
    }, sort_keys=True))


def validate_owner_response(path, build_id, challenge, host_key_sha256, owner_key_sha256):
    value = load_json(path)
    expected = {
        "schema", "build_id", "challenge", "host_key_sha256",
        "owner_public_key_sha256", "authentication", "remote",
    }
    if not isinstance(value, dict) or set(value) != expected:
        fail("trusted owner response topology differs")
    if (
        value["schema"] != 1 or value["build_id"] != build_id
        or value["challenge"] != challenge
        or value["host_key_sha256"] != host_key_sha256
        or value["owner_public_key_sha256"] != owner_key_sha256
    ):
        fail("trusted owner response identity differs")
    if value["authentication"] != {
        "method": "publickey", "strict_host_key_pinning": True,
        "agent_forwarded": False, "private_key_on_forge": False,
        "interactive_pty": True,
    }:
        fail("trusted owner authentication response differs")
    if value["remote"] != {
        "build_id": build_id, "authorized_key_sha256": owner_key_sha256,
        "challenge_written": True,
    }:
        fail("trusted owner remote response differs")
    print(json.dumps({"build_id": build_id, "owner_proof": True}, sort_keys=True))


def validate_owner_ready(path, response_path, signature_path):
    paths = [Path(item) for item in (path, response_path, signature_path)]
    for candidate in paths:
        try:
            metadata = candidate.lstat()
        except OSError:
            fail("trusted owner handoff is incomplete")
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) not in {0o600, 0o644}
        ):
            fail("trusted owner handoff topology is unsafe")
    value = load_json(paths[0])
    if not isinstance(value, dict) or set(value) != {
        "schema", "response_sha256", "signature_sha256"
    }:
        fail("trusted owner ready sentinel topology differs")
    if value["schema"] != 1:
        fail("trusted owner ready sentinel schema differs")
    expected = {
        "response_sha256": sha256(paths[1]),
        "signature_sha256": sha256(paths[2]),
    }
    if any(
        not re.fullmatch(r"[0-9a-f]{64}", value.get(name, ""))
        or value[name] != digest
        for name, digest in expected.items()
    ):
        fail("trusted owner ready sentinel hashes differ")
    print(json.dumps({"ready": True, **expected}, sort_keys=True))


def dotted(value, key):
    for part in key.split("."):
        if not isinstance(value, dict) or part not in value:
            fail(f"receipt lacks required field: {key}")
        value = value[part]
    return value


def validate_receipt_topology(receipt):
    topology = {
        "": {
            "schema", "component", "stage", "build_id", "deployable",
            "diagnostic_only", "target", "source_date_epoch", "base_system",
            "source_sets", "sources", "orchestration", "dependencies", "kernel",
            "bootloader", "filesystem", "disk", "network", "owner_ssh_key",
            "security_contract", "native_toolchain", "qemu", "build_contract",
            "template_contract", "reproducibility", "probe_summary", "outputs",
        },
        "base_system": {
            "build_id", "receipt", "receipt_sha256", "disk_sha256", "consumption",
        },
        "source_sets": {"bootstrap", "base_system", "native_git", "native_archives"},
        "source_sets.bootstrap": {"digest", "authentication"},
        "source_sets.base_system": {"digest", "authentication"},
        "source_sets.native_git": {"digest", "authentication"},
        "source_sets.native_archives": {"digest", "authentication"},
        "orchestration": {
            "commit", "tree", "recipe_sha256", "overlay_digest",
            "deployment_helper_sha256",
        },
        "dependencies": {"sealed_cross_gcc", "sealed_glibc"},
        "dependencies.sealed_cross_gcc": {"build_id", "prefix"},
        "dependencies.sealed_glibc": {"build_id", "snapshot"},
        "kernel": {"version", "release", "root_selector", "unix98_ptys", "devpts"},
        "bootloader": {"name", "platform", "firmware", "inheritance"},
        "filesystem": {
            "type", "bytes", "uuid", "journal", "state", "forced_fsck",
            "directory_hash_seed",
        },
        "disk": {
            "format", "bytes", "sha256", "guid", "bios_boot_partuuid",
            "root_partuuid", "root_filesystem_bytes",
            "in_partition_growth_reserve_bytes",
        },
        "network": {
            "driver", "interface", "configuration", "serial_discovery",
            "resolver_probe",
        },
        "owner_ssh_key": {
            "algorithm", "fingerprint", "input_sha256", "canonical_sha256",
            "authorized_keys_path", "private_key_on_forge",
            "agent_forwarded_to_forge", "possession_proof", "signature_namespace",
        },
        "security_contract": {
            "root_password", "ssh", "password_auth_code", "pam_auth_code",
            "forwarding", "sftp", "inetd", "pubkey_options", "host_key",
            "authentication_logging", "qemu_network",
        },
        "native_toolchain": {
            "build", "host", "target", "components", "resident_sources",
            "source_sanitization", "capability",
        },
        "native_toolchain.source_sanitization": {
            "policy", "manifest_sha256", "records",
        },
        "qemu": {
            "path", "sha256", "qemu_img_path", "qemu_img_sha256", "machine",
            "accelerator", "cpu", "firmware", "positive_cmdline",
            "negative_cmdline", "negative_boot", "persistence_nonce",
            "host_key_sha256", "owner_proof_host_key_sha256",
            "post_shutdown_forced_fsck",
        },
        "qemu.firmware": {"path", "sha256"},
        "build_contract": {
            "independent_builds", "host_contract_sha256", "rootfs_population",
            "rootfs_hash_seed_locked", "canonical_build_path_reused_sequentially",
            "private_key_inputs",
        },
        "template_contract": {
            "source", "booted_validation_disk_forbidden", "reason",
            "independent_clone_host_keys_differ", "deployment_and_vm118_template",
        },
        "reproducibility": {
            "independent_builds", "native_payload_identical",
            "rootfs_inventory_identical", "rootfs_ext4_identical",
            "gpt_disk_identical", "base_disk_immutable_after_probes",
            "selectors_modified", "rootfs_inventory",
        },
        "outputs": {"subtree_inventories"},
        "outputs.subtree_inventories": {"boot", "configuration", "licenses", "probe"},
    }
    for path, expected in topology.items():
        value = receipt if path == "" else dotted(receipt, path)
        if not isinstance(value, dict) or set(value) != expected:
            fail(f"native-developer receipt topology differs: {path or '<root>'}")
    sources = dotted(receipt, "sources")
    git_sources = {"binutils", "gcc", "glibc", "linux", "busybox", "grub", "gnulib", "dropbear"}
    archive_sources = {"make", "gmp", "mpfr", "mpc"}
    if set(sources) != git_sources | archive_sources:
        fail("native-developer receipt source topology differs")
    for name in git_sources:
        if not isinstance(sources[name], dict) or set(sources[name]) != {
            "commit", "tree", "repository"
        }:
            fail(f"native-developer receipt Git source topology differs: {name}")
    for name in archive_sources:
        if not isinstance(sources[name], dict) or set(sources[name]) != {
            "version", "archive_sha256", "signature_sha256"
        }:
            fail(f"native-developer receipt archive source topology differs: {name}")


def validate_retained_serials(artifact, receipt, build_id):
    artifact = Path(artifact)
    with tempfile.TemporaryDirectory() as temporary:
        temporary = Path(temporary)
        host_keys = {}
        for boot in ("first-a", "second-a", "first-b", "owner"):
            raw = artifact / f"probe/{boot}.serial.raw"
            stored_normalized = artifact / f"probe/{boot}.serial.normalized"
            key_output = temporary / f"{boot}.host-key"
            normalized_output = temporary / f"{boot}.serial.normalized"
            with contextlib.redirect_stdout(io.StringIO()):
                validate_serial(
                    "positive", raw, dotted(receipt, "kernel.release"), build_id,
                    key_output, normalized_output,
                )
            if normalized_output.read_bytes() != stored_normalized.read_bytes():
                fail(f"stored {boot}-boot serial normalization differs")
            fields = key_output.read_text(encoding="utf-8").split()
            host_keys[boot] = " ".join(fields[:2])
        negative_output = temporary / "negative.serial.normalized"
        with contextlib.redirect_stdout(io.StringIO()):
            validate_serial(
                "negative", artifact / "probe/negative.serial.raw",
                dotted(receipt, "kernel.release"), build_id,
                None, negative_output,
            )
        if negative_output.read_bytes() != (
            artifact / "probe/negative.serial.normalized"
        ).read_bytes():
            fail("stored negative-boot serial normalization differs")
        if host_keys["first-a"] != host_keys["second-a"]:
            fail("retained persistence boots changed the SSH host key")
        independent = {
            host_keys["first-a"], host_keys["first-b"], host_keys["owner"]
        }
        if len(independent) != 3:
            fail("retained independent clone SSH host keys are not distinct")
        first_hash = hashlib.sha256(
            (host_keys["first-a"] + "\n").encode()
        ).hexdigest()
        owner_hash = hashlib.sha256(
            (host_keys["owner"] + "\n").encode()
        ).hexdigest()
        if (
            first_hash != dotted(receipt, "qemu.host_key_sha256")
            or owner_hash != dotted(receipt, "qemu.owner_proof_host_key_sha256")
        ):
            fail("retained serial host-key hashes differ from the receipt")
    return {"host_keys": host_keys, "negative": "fail-closed"}


def validate_receipt(receipt_path, artifact_path, build_id, pairs):
    if not pairs or len(pairs) % 2:
        fail("validate-receipt requires exact key/value contract pairs")
    receipt_path = Path(receipt_path)
    artifact = Path(artifact_path)
    metadata = receipt_path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o644
    ):
        fail("native-developer receipt is not a plain mode-0644 file")
    if artifact.is_symlink() or not artifact.is_dir():
        fail("native-developer artifact root is not a real directory")
    receipt = load_json(receipt_path)
    validate_receipt_topology(receipt)
    retained_helper = artifact / "configuration/deployment-preparation.sh"
    try:
        helper_metadata = retained_helper.lstat()
    except OSError:
        fail("retained deployment helper is absent")
    if (
        not stat.S_ISREG(helper_metadata.st_mode)
        or helper_metadata.st_nlink != 1
        or stat.S_IMODE(helper_metadata.st_mode) != 0o644
        or sha256(retained_helper)
        != receipt.get("orchestration", {}).get("deployment_helper_sha256")
    ):
        fail("retained deployment helper differs from its receipt hash")
    expected = dict(zip(pairs[::2], pairs[1::2], strict=True))
    if len(expected) != len(pairs) // 2:
        fail("validate-receipt contains duplicate expected keys")
    for key, wanted in expected.items():
        if str(dotted(receipt, key)) != wanted:
            fail(f"native-developer receipt mismatch for {key}")
    if (
        receipt.get("schema") != 1
        or receipt.get("component") != "system-image"
        or receipt.get("stage") != "native-developer-seed"
        or receipt.get("build_id") != build_id
    ):
        fail("native-developer receipt identity differs")
    if set(path.name for path in artifact.iterdir()) != {
        "boot", "configuration", "licenses", "probe", "receipt.json"
    }:
        fail("native-developer artifact topology differs")
    live = {
        name: inventory(artifact / name)
        for name in ("boot", "configuration", "licenses", "probe")
    }
    if receipt.get("outputs", {}).get("subtree_inventories") != live:
        fail("native-developer receipt does not bind artifact subtrees")
    first = load_json(artifact / "configuration/rootfs-a.json")
    second = load_json(artifact / "configuration/rootfs-b.json")
    if first != second or receipt.get("reproducibility", {}).get("rootfs_inventory") != first:
        fail("native-developer root inventory evidence differs")
    omissions = validate_omitted_private_fixtures(
        artifact / "configuration/omitted-private-test-fixtures.json"
    )
    if receipt.get("native_toolchain", {}).get("source_sanitization") != {
        "policy": (
            "three-standalone-pem-plus-one-embedded-host-key-fixture-"
            "omitted-public-crypto-c-vectors-source-bound"
        ),
        **omissions,
    }:
        fail("native-developer receipt omission evidence differs")
    ssh_evidence = artifact / "probe/ssh-evidence.json"
    if receipt.get("probe_summary") != load_json(ssh_evidence):
        fail("native-developer receipt probe summary differs from retained evidence")
    validate_ssh_evidence(
        ssh_evidence, build_id,
        dotted(receipt, "qemu.persistence_nonce"),
        dotted(receipt, "qemu.host_key_sha256"),
    )
    if receipt.get("native_toolchain", {}).get("components") != [
        "binutils", "gcc", "g++", "libgcc", "libatomic", "libstdc++",
        "make", "gmp", "mpfr", "mpc",
    ]:
        fail("native-developer receipt native component list differs")
    validate_retained_serials(artifact, receipt, build_id)
    print(json.dumps({"build_id": build_id, "valid": True}, sort_keys=True))


if command == "inventory":
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
elif command == "validate-busybox-config":
    if len(arguments) != 1:
        fail("validate-busybox-config requires CONFIG")
    validate_busybox_config(arguments[0])
elif command == "validate-dropbear-options":
    if len(arguments) != 2:
        fail("validate-dropbear-options requires OPTIONS LOCKED_SOURCE")
    validate_dropbear_options(*arguments)
elif command == "validate-runtime-root":
    if len(arguments) != 1:
        fail("validate-runtime-root requires ROOT")
    validate_runtime_root(arguments[0])
elif command == "validate-ext4":
    if len(arguments) != 6:
        fail("validate-ext4 requires IMAGE UUID HASH_SEED BYTES EPOCH MODE")
    validate_ext4(*arguments)
elif command == "validate-public-key":
    if len(arguments) not in (1, 2):
        fail("validate-public-key requires INPUT [CANONICAL_OUTPUT]")
    validate_public_key(*arguments)
elif command == "rewrite-gcc-configargs":
    if len(arguments) < 3 or len(arguments[1:]) % 2:
        fail("rewrite-gcc-configargs requires PATH FROM TO [FROM TO ...]")
    rewrite_gcc_configargs(arguments[0], arguments[1:])
elif command == "scan-forbidden":
    if len(arguments) < 2:
        fail("scan-forbidden requires ROOT TOKEN [TOKEN ...]")
    scan_forbidden(arguments[0], arguments[1:])
elif command == "scan-private-material":
    if len(arguments) != 1:
        fail("scan-private-material requires ROOT")
    scan_private_material(arguments[0])
elif command == "validate-omitted-private-fixtures":
    if len(arguments) != 1:
        fail("validate-omitted-private-fixtures requires MANIFEST")
    print(json.dumps(
        validate_omitted_private_fixtures(arguments[0]), sort_keys=True
    ))
elif command == "validate-grown-disk":
    if len(arguments) != 3:
        fail("validate-grown-disk requires BASE GROWN FILESYSTEM_BYTES")
    validate_grown_disk(*arguments)
elif command == "validate-serial":
    if len(arguments) not in (4, 5, 6):
        fail("validate-serial requires KIND LOG RELEASE BUILD_ID [HOST_KEY] [NORMALIZED]")
    validate_serial(*arguments)
elif command == "validate-retained-serials":
    if len(arguments) != 3:
        fail("validate-retained-serials requires ARTIFACT RECEIPT BUILD_ID")
    print(json.dumps(
        validate_retained_serials(
            arguments[0], load_json(arguments[1]), arguments[2]
        ), sort_keys=True
    ))
elif command == "validate-ssh-evidence":
    if len(arguments) != 4:
        fail("validate-ssh-evidence requires JSON BUILD_ID NONCE HOST_KEY_SHA256")
    validate_ssh_evidence(*arguments)
elif command == "validate-owner-request":
    if len(arguments) != 4:
        fail("validate-owner-request requires JSON BUILD_ID OWNER_KEY_SHA256 PORT")
    validate_owner_request(*arguments)
elif command == "validate-owner-response":
    if len(arguments) != 5:
        fail("validate-owner-response requires JSON BUILD_ID CHALLENGE HOST_KEY_SHA256 OWNER_KEY_SHA256")
    validate_owner_response(*arguments)
elif command == "validate-owner-ready":
    if len(arguments) != 3:
        fail("validate-owner-ready requires READY RESPONSE SIGNATURE")
    validate_owner_ready(*arguments)
elif command == "compare-json":
    if len(arguments) != 2:
        fail("compare-json requires FIRST SECOND")
    if load_json(arguments[0]) != load_json(arguments[1]):
        fail("JSON evidence differs")
elif command == "build-id":
    if not arguments or len(arguments[1:]) % 2:
        fail("build-id requires BASE_BUILD_ID and key/value pairs")
    if not re.fullmatch(r"base-system-[A-Za-z0-9._-]+", arguments[0]):
        fail("unsafe base-system build ID")
    fields = dict(zip(arguments[1::2], arguments[2::2], strict=True))
    if len(fields) != len(arguments[1:]) // 2:
        fail("build-id fields contain duplicates")
    print(f"native-developer-{arguments[0][12:24]}-{canonical_digest(fields)[:16]}")
elif command == "validate-receipt":
    if len(arguments) < 5 or len(arguments[3:]) % 2:
        fail("validate-receipt requires RECEIPT ARTIFACT BUILD_ID and pairs")
    validate_receipt(arguments[0], arguments[1], arguments[2], arguments[3:])
else:
    fail(f"unknown internal command: {command}")
PY

fi

# Trusted-side half of the owner-key gate.  Run this on the owner's trusted
# workstation against a local port forwarded to the forge's loopback QEMU
# hostfwd.  The agent is never forwarded; only the signed public evidence is
# returned to the forge build.
if [[ ${1:-} == --trusted-owner-proof ]]; then
  [[ $# -eq 3 ]] || {
    echo "Usage: $0 --trusted-owner-proof REQUEST.json RESPONSE.json" >&2
    exit 64
  }
  request=$2
  response=$3
  response_ready=$response.ready
  owner_public_key=${CAJUNOS_OWNER_SSH_PUBLIC_KEY:-}
  [[ -n $owner_public_key && -n ${SSH_AUTH_SOCK:-} && -S ${SSH_AUTH_SOCK:-} \
     && ! -L ${SSH_AUTH_SOCK:-} ]] || {
    echo "Trusted owner proof requires a local owner public key and local ssh-agent" >&2
    exit 70
  }
  [[ -f $request && ! -L $request && ! -e $response && ! -L $response \
     && ! -e $response.sig && ! -L $response.sig \
     && ! -e $response_ready && ! -L $response_ready ]] || {
    echo "Trusted owner proof request/response topology is unsafe" >&2
    exit 70
  }
  key_json=$("$script_path" --internal-python validate-public-key "$owner_public_key")
  owner_canonical=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["canonical"])' \
    <<<"$key_json")
  owner_sha256=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["canonical_sha256"])' \
    <<<"$key_json")
  agent_matches=$(ssh-add -L | awk -v wanted="$owner_canonical" '
    $1 " " $2 == wanted { count++ } END { print count + 0 }
  ')
  [[ $agent_matches == 1 ]] || {
    echo "Local ssh-agent does not contain exactly one approved owner key" >&2
    exit 70
  }
  mapfile -t request_values < <(python3 - "$request" <<'PY'
import base64, binascii, hashlib, json, re, struct, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    value = json.load(stream)
if set(value) != {
    "schema", "build_id", "challenge", "host", "port", "host_key",
    "host_key_sha256", "owner_public_key_sha256", "namespace",
}:
    raise SystemExit("owner-proof request topology differs")
if value["schema"] != 1 or value["host"] != "127.0.0.1":
    raise SystemExit("owner-proof request identity differs")
if not re.fullmatch(r"native-developer-[A-Za-z0-9._-]+", value["build_id"]):
    raise SystemExit("owner-proof build ID is unsafe")
if not re.fullmatch(r"[0-9a-f]{64}", value["challenge"]):
    raise SystemExit("owner-proof challenge is unsafe")
if not isinstance(value["port"], int) or not 1024 <= value["port"] <= 65535:
    raise SystemExit("owner-proof port is unsafe")
if value["namespace"] != "cajunos-native-developer-owner-proof":
    raise SystemExit("owner-proof namespace differs")
host_key = value["host_key"]
if not isinstance(host_key, str) or len(host_key.split()) != 2:
    raise SystemExit("owner-proof host key is not canonical")
algorithm, encoded = host_key.split()
if algorithm != "ssh-ed25519":
    raise SystemExit("owner-proof host key is not Ed25519")
try:
    decoded = base64.b64decode(encoded, validate=True)
except (ValueError, binascii.Error):
    raise SystemExit("owner-proof host key is not canonical base64")
if base64.b64encode(decoded).decode("ascii") != encoded:
    raise SystemExit("owner-proof host key is not canonical base64")
if (
    len(decoded) != 51 or decoded[:4] != b"\0\0\0\x0b"
    or decoded[4:15] != b"ssh-ed25519"
    or struct.unpack_from(">I", decoded, 15)[0] != 32
):
    raise SystemExit("owner-proof host key wire encoding differs")
host_key_sha256 = hashlib.sha256((host_key + "\n").encode()).hexdigest()
if value["host_key_sha256"] != host_key_sha256:
    raise SystemExit("owner-proof host key hash does not bind the pinned key")
if not re.fullmatch(r"[0-9a-f]{64}", value["owner_public_key_sha256"]):
    raise SystemExit("owner-proof owner-key hash is unsafe")
for name in ("build_id", "challenge", "host", "port", "host_key",
             "host_key_sha256", "owner_public_key_sha256", "namespace"):
    print(value[name])
PY
  )
  [[ ${#request_values[@]} -eq 8 ]] || exit 70
  proof_build_id=${request_values[0]}
  proof_challenge=${request_values[1]}
  proof_host=${request_values[2]}
  proof_request_port=${request_values[3]}
  proof_host_key=${request_values[4]}
  proof_host_key_sha256=${request_values[5]}
  proof_owner_sha256=${request_values[6]}
  proof_namespace=${request_values[7]}
  [[ $proof_owner_sha256 == "$owner_sha256" ]] || {
    echo "Owner-proof request names a different approved public key" >&2
    exit 70
  }
  "$script_path" --internal-python validate-owner-request \
    "$request" "$proof_build_id" "$owner_sha256" "$proof_request_port" \
    >/dev/null
  proof_port=${CAJUNOS_OWNER_PROOF_PORT:-$proof_request_port}
  [[ $proof_port =~ ^[1-9][0-9]*$ && $proof_port -ge 1024 \
     && $proof_port -le 65535 ]] || exit 70
  trusted_tmp=$(mktemp -d)
  chmod 0700 "$trusted_tmp"
  trusted_cleanup() {
    local status=$?
    trap - EXIT INT TERM HUP
    rm -rf -- "$trusted_tmp"
    exit "$status"
  }
  trap trusted_cleanup EXIT
  trap 'exit 130' INT
  printf '[127.0.0.1]:%s %s\n' "$proof_port" "$proof_host_key" \
    >"$trusted_tmp/known_hosts"
  chmod 0600 "$trusted_tmp/known_hosts"
  trusted_ssh=(
    -F /dev/null -p "$proof_port" -o ConnectTimeout=10
    -o GlobalKnownHostsFile=/dev/null
    -o UserKnownHostsFile="$trusted_tmp/known_hosts"
    -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519
    -o IdentityFile="$owner_public_key" -o IdentitiesOnly=yes
    -o ForwardAgent=no -o PasswordAuthentication=no
    -o KbdInteractiveAuthentication=no
  )
  ssh "${trusted_ssh[@]}" -o LogLevel=VERBOSE root@127.0.0.1 \
    "/bin/test \"\$(/bin/cat /etc/cajunos-build-id)\" = '$proof_build_id' && \
     /bin/test \"\$(/bin/sha256sum /root/.ssh/authorized_keys | /usr/bin/awk '{print \$1}')\" = '$owner_sha256' && \
     /bin/mkdir -p /var/lib/cajunos && \
     /bin/printf '%s\\n' '$proof_challenge' >/var/lib/cajunos/owner-proof-challenge && \
     /bin/sync && /bin/echo CAJUNOS_OWNER_KEY_OK" \
    >"$trusted_tmp/ssh.stdout" 2>"$trusted_tmp/ssh.stderr"
  grep -Fqx CAJUNOS_OWNER_KEY_OK "$trusted_tmp/ssh.stdout"
  grep -Fq 'Authenticated to 127.0.0.1' "$trusted_tmp/ssh.stderr"
  grep -Fq 'using "publickey"' "$trusted_tmp/ssh.stderr"
  ssh "${trusted_ssh[@]}" -tt root@127.0.0.1 \
    'test -t 0 && test -t 1 && tty | grep -q "^/dev/pts/" && echo CAJUNOS_OWNER_PTY_OK' \
    >"$trusted_tmp/pty.stdout" 2>"$trusted_tmp/pty.stderr"
  grep -Fq CAJUNOS_OWNER_PTY_OK "$trusted_tmp/pty.stdout"
  python3 - "$response" "$proof_build_id" "$proof_challenge" \
    "$proof_host_key_sha256" "$owner_sha256" <<'PY'
import json, os, sys
path, build_id, challenge, host_key_sha256, owner_sha256 = sys.argv[1:]
value = {
    "schema": 1, "build_id": build_id, "challenge": challenge,
    "host_key_sha256": host_key_sha256,
    "owner_public_key_sha256": owner_sha256,
    "authentication": {
        "method": "publickey", "strict_host_key_pinning": True,
        "agent_forwarded": False, "private_key_on_forge": False,
        "interactive_pty": True,
    },
    "remote": {
        "build_id": build_id, "authorized_key_sha256": owner_sha256,
        "challenge_written": True,
    },
}
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
    json.dump(value, stream, indent=2, sort_keys=True); stream.write("\n")
PY
  ssh-keygen -Y sign -q -f "$owner_public_key" -n "$proof_namespace" "$response"
  printf 'cajunos-owner namespaces="%s" %s\n' "$proof_namespace" "$owner_canonical" \
    >"$trusted_tmp/allowed_signers"
  ssh-keygen -Y verify -f "$trusted_tmp/allowed_signers" -I cajunos-owner \
    -n "$proof_namespace" -s "$response.sig" <"$response" >/dev/null
  python3 - "$response_ready" "$response" "$response.sig" <<'PY'
import hashlib, json, os, sys
ready, response, signature = sys.argv[1:]
def digest(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()
value = {
    "schema": 1,
    "response_sha256": digest(response),
    "signature_sha256": digest(signature),
}
descriptor = os.open(ready, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
    json.dump(value, stream, indent=2, sort_keys=True); stream.write("\n")
PY
  "$script_path" --internal-python validate-owner-ready \
    "$response_ready" "$response" "$response.sig" >/dev/null
  set +e
  ssh "${trusted_ssh[@]}" root@127.0.0.1 /sbin/poweroff \
    >"$trusted_tmp/poweroff.stdout" 2>"$trusted_tmp/poweroff.stderr"
  set -e
  trap - EXIT INT TERM HUP
  rm -rf -- "$trusted_tmp"
  echo "CAJUNOS_TRUSTED_OWNER_PROOF_COMPLETE response=$response signature=$response.sig ready=$response_ready"
  exit 0
fi

preflight_only=0
if [[ $# -eq 1 && $1 == --preflight-only ]]; then
  preflight_only=1
elif [[ $# -ne 0 ]]; then
  echo "Usage: $0 [--preflight-only]" >&2
  exit 64
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
  GNULIB_SRCDIR QEMU_AUDIO_DRV QEMU_PATH QEMU_DATA_DIR \
  E2FSPROGS_FAKE_TIME E2FSPROGS_UNDO_DIR MKE2FS_CONFIG MKE2FS_SYNC \
  MKE2FS_FIRST_META_BG MKE2FS_DEVICE_SECTSIZE \
  MKE2FS_DEVICE_PHYS_SECTSIZE MKE2FS_SKIP_CHECK_MSG; do
  unset "$variable"
done

cajunos_root=${CAJUNOS_ROOT:-/srv/cajunos}
target=${CAJUNOS_TARGET:-x86_64-cajunos-linux-gnu}
build_triplet=x86_64-pc-linux-gnu
expected_user=${CAJUNOS_BUILD_USER:-cajunos}
jobs=${CAJUNOS_JOBS:-6}
qemu_timeout=${CAJUNOS_QEMU_TIMEOUT:-240}
owner_proof_timeout=${CAJUNOS_OWNER_PROOF_TIMEOUT:-900}
ssh_port=${CAJUNOS_QEMU_SSH_PORT:-22222}
base_build_id=${CAJUNOS_BASE_SYSTEM_BUILD_ID:-}
owner_public_key=${CAJUNOS_OWNER_SSH_PUBLIC_KEY:-}
disk_bytes=$((16 * 1024 * 1024 * 1024))
rootfs_bytes=$((12 * 1024 * 1024 * 1024))
root_first_sector=4096
root_hash_seed=4a696d42-6f75-4769-8f73-43616a756e21
rootfs_features=ext_attr,dir_index,filetype,extent,64bit,flex_bg,sparse_super,large_file,huge_file,dir_nlink,extra_isize,metadata_csum
qemu_machine=pc-q35-10.0
qemu_cpu=Nehalem-v1

bootstrap_manifest=$project_root/manifests/bootstrap.json
bootstrap_lock=$project_root/locks/bootstrap.lock.json
system_manifest=$project_root/manifests/base-system.json
system_lock=$project_root/locks/base-system.lock.json
native_manifest=$project_root/manifests/native-developer-seed.json
native_lock=$project_root/locks/native-developer-seed.lock.json
archive_manifest=$project_root/manifests/native-developer-archives.json
archive_lock=$project_root/locks/native-developer-archives.lock.json
archive_verifier=$project_root/scripts/fetch-native-developer-archives.py
deployment_helper=$project_root/scripts/prepare-native-developer-deployment.sh
base_helper=$project_root/scripts/build-base-system-image.sh
gcc_helper=$project_root/scripts/build-gcc-complete.sh
glibc_helper=$project_root/scripts/build-glibc-complete.sh
base_busybox_fragment=$project_root/configs/busybox-base-system.fragment
native_busybox_fragment=$project_root/configs/busybox-native-developer.fragment
dropbear_options=$project_root/configs/dropbear-native-developer.h
overlay=$project_root/rootfs/native-developer

if [[ $(id -u) -eq 0 || $(id -un) != "$expected_user" ]]; then
  echo "Run this build as the unprivileged $expected_user account" >&2
  exit 70
fi
if [[ $target != x86_64-cajunos-linux-gnu ]]; then
  echo "This stage supports only x86_64-cajunos-linux-gnu" >&2
  exit 71
fi
if [[ ! $jobs =~ ^[1-9][0-9]*$ \
   || ! $qemu_timeout =~ ^[1-9][0-9]*$ \
   || ! $owner_proof_timeout =~ ^[1-9][0-9]*$ \
   || ! $ssh_port =~ ^[1-9][0-9]*$ \
   || $ssh_port -lt 1024 || $ssh_port -gt 65535 ]]; then
  echo "Jobs/timeouts must be positive and the QEMU SSH port must be 1024-65535" >&2
  exit 72
fi
if [[ ! $base_build_id =~ ^base-system-[A-Za-z0-9][A-Za-z0-9._-]{0,95}$ ]]; then
  echo "CAJUNOS_BASE_SYSTEM_BUILD_ID must name one explicit sealed Stage 9A build" >&2
  exit 72
fi
if [[ -n ${CAJUNOS_SSH_PROBE_PRIVATE_KEY:-} ]]; then
  echo "Private-key file inputs are forbidden; forward the approved key through ssh-agent" >&2
  exit 72
fi
if [[ -z $owner_public_key ]]; then
  echo "CAJUNOS_OWNER_SSH_PUBLIC_KEY is required" >&2
  exit 72
fi
if [[ -n ${SSH_AUTH_SOCK:-} ]]; then
  echo "The untrusted forge build must not receive an SSH agent socket" >&2
  exit 72
fi

host_tool_names=(
  aclocal ar as autoconf autoheader automake autopoint autoreconf awk bash bc bison
  chown cmp cp dd debugfs dumpe2fs e2fsck fakeroot find flex flock g++ gcc gettext git grep
  help2man install ld libtoolize m4 make mke2fs nm objcopy openssl patch perl
  pkg-config python3 qemu-img qemu-system-x86_64 ranlib readelf readlink sed
  sgdisk sha256sum sh ssh ssh-add ssh-keygen ssh-keyscan stat strings tar timeout
  touch truncate tune2fs
)
for command_name in "${host_tool_names[@]}"; do
  command -v "$command_name" >/dev/null || {
    echo "Missing required host command: $command_name" >&2
    exit 73
  }
done
for frozen in \
  "$bootstrap_manifest" "$bootstrap_lock" "$system_manifest" "$system_lock" \
  "$native_manifest" "$native_lock" "$archive_manifest" "$archive_lock" \
  "$archive_verifier" "$deployment_helper" "$base_helper" "$gcc_helper" "$glibc_helper" \
  "$base_busybox_fragment" "$native_busybox_fragment" "$dropbear_options" "$overlay"; do
  [[ -e $frozen && ! -L $frozen ]] || {
    echo "Missing or symlinked frozen native-developer input: $frozen" >&2
    exit 74
  }
done

cajunos_root=$(readlink -f -- "$cajunos_root")
upstream=$cajunos_root/upstream
cache_root=$cajunos_root/cache
tools_root=$cajunos_root/tools
sysroot_root=$cajunos_root/sysroot
work_root=$cajunos_root/work
artifacts_root=$cajunos_root/artifacts
logs_root=$cajunos_root/logs
for managed in "$cajunos_root" "$upstream" "$cache_root" "$tools_root" \
  "$sysroot_root" "$work_root" "$artifacts_root" "$logs_root"; do
  [[ -d $managed && ! -L $managed ]] || {
    echo "Managed CajunOS directory is unavailable or symlinked: $managed" >&2
    exit 74
  }
done
[[ $cajunos_root != / && $cajunos_root != "$(readlink -f -- "$HOME")" ]] || {
  echo "Unsafe CajunOS root" >&2
  exit 74
}

run_id=${CAJUNOS_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
[[ $run_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || {
  echo "Unsafe CAJUNOS_RUN_ID: $run_id" >&2
  exit 74
}

base_artifact=$artifacts_root/$base_build_id
base_receipt=$base_artifact/receipt.json
base_disk=$base_artifact/boot/disk.raw
for path in "$base_artifact" "$base_receipt" "$base_disk"; do
  [[ -e $path && ! -L $path ]] || {
    echo "Explicit Stage 9A dependency is unavailable: $path" >&2
    exit 74
  }
done

# Canonicalize exactly one approved owner key.  The untrusted forge receives
# only this public material.  Possession is proved later from a separate
# trusted host through a loopback tunnel; no general agent reaches the forge.
key_temporary=$work_root/.native-owner-key-$run_id-$$
[[ ! -e $key_temporary && ! -L $key_temporary ]] || {
  echo "Colliding canonical public-key path" >&2
  exit 74
}
owner_key_json=$("$script_path" --internal-python validate-public-key \
  "$owner_public_key" "$key_temporary")
owner_key_canonical=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["canonical"])' \
  <<<"$owner_key_json")
owner_key_fingerprint=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["fingerprint"])' \
  <<<"$owner_key_json")
owner_key_input_sha256=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["input_sha256"])' \
  <<<"$owner_key_json")
owner_key_canonical_sha256=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["canonical_sha256"])' \
  <<<"$owner_key_json")

# Authenticate release archives before taking the global source lock.  The
# exact object bytes are captured again after the lock is held, so the proof
# remains valid without recursively trying to acquire the same lock.
archive_validation_json=$("$archive_verifier" validate --root "$cajunos_root" \
  --manifest "$archive_manifest" --lock "$archive_lock" \
  --gpgv "${CAJUNOS_GPGV:?CAJUNOS_GPGV is required}" \
  --gpgv-library-root \
    "${CAJUNOS_GPGV_LIBRARY_ROOT:?CAJUNOS_GPGV_LIBRARY_ROOT is required}" \
  --gcc-prerequisites "$upstream/gcc/contrib/prerequisites.sha512" --json)
archive_validation_sha256=$(printf '%s' "$archive_validation_json" | sha256sum | awk '{print $1}')

"$project_root/scripts/fetch.py" validate --root "$cajunos_root" --json >/dev/null
"$project_root/scripts/fetch.py" validate --root "$cajunos_root" \
  --manifest "$system_manifest" --lock "$system_lock" --json >/dev/null
"$project_root/scripts/fetch.py" validate --root "$cajunos_root" \
  --manifest "$native_manifest" --lock "$native_lock" --json >/dev/null

exec 8>"$upstream/.cajunos-source.lock"
flock -n 8 || {
  echo "Another source operation or build owns the source lock" >&2
  exit 75
}
"$project_root/scripts/fetch.py" validate --root "$cajunos_root" >/dev/null
"$project_root/scripts/fetch.py" validate --root "$cajunos_root" \
  --manifest "$system_manifest" --lock "$system_lock" >/dev/null
"$project_root/scripts/fetch.py" validate --root "$cajunos_root" \
  --manifest "$native_manifest" --lock "$native_lock" >/dev/null

if [[ -n $(git -C "$project_root" status --porcelain) ]]; then
  echo "Refusing an official build from a dirty orchestration checkout" >&2
  exit 76
fi

archive_cache_json=$(python3 - "$archive_verifier" "$archive_manifest" \
  "$archive_lock" "$cajunos_root" <<'PY'
import importlib.util
import json
from pathlib import Path
import sys

script, manifest_path, lock_path, root = map(Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location("native_archives_locked", script)
if spec is None or spec.loader is None:
    raise SystemExit("cannot import locked archive verifier")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
manifest = module.load_json(manifest_path)
lock = module.load_json(lock_path)
components = module.validate_lock(manifest, manifest_path, lock)
cache = root / "cache/native-developer-archives"
objects = {}
for component in components:
    for kind in ("archive", "signature", "key"):
        contract = component[kind]
        path = cache / contract["filename"]
        module.validate_object(path, contract, f"locked {component['name']} {kind}")
        objects[f"{component['name']}:{kind}"] = {
            "path": str(path), "bytes": contract["bytes"],
            "sha256": contract["sha256"], "sha512": contract["sha512"],
        }
print(json.dumps({
    "source_set_digest": lock["source_set_digest"],
    "objects": objects,
    "digest": module.canonical_digest(objects),
}, sort_keys=True))
PY
)
archive_cache_digest=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["digest"])' \
  <<<"$archive_cache_json")

mapfile -t lock_values < <(python3 - "$bootstrap_lock" "$system_lock" \
  "$native_lock" "$archive_lock" <<'PY'
import json
import sys

def load(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)

bootstrap, system, native, archives = map(load, sys.argv[1:])
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
print(native["source_set_digest"])
print(native["source_authentication"])
item = native["components"][0]
print(item["commit"]); print(item["tree"]); print(item["repository"])
print(archives["source_set_digest"])
print(archives["source_authentication"])
for name in ("make", "gmp", "mpfr", "mpc"):
    item = next(value for value in archives["components"] if value["name"] == name)
    print(item["version"]); print(item["archive"]["filename"])
    print(item["archive"]["sha256"]); print(item["signature"]["sha256"])
    print(item["topology"]["top_level"])
PY
)
[[ ${#lock_values[@]} -eq 52 ]] || {
  echo "Locked source cohort is incomplete" >&2
  exit 77
}
bootstrap_digest=${lock_values[0]}
bootstrap_auth=${lock_values[1]}
linux_commit=${lock_values[2]}; linux_tree=${lock_values[3]}; linux_repository=${lock_values[4]}
gcc_commit=${lock_values[5]}; gcc_tree=${lock_values[6]}; gcc_repository=${lock_values[7]}
glibc_commit=${lock_values[8]}; glibc_tree=${lock_values[9]}; glibc_repository=${lock_values[10]}
binutils_commit=${lock_values[11]}; binutils_tree=${lock_values[12]}; binutils_repository=${lock_values[13]}
system_digest=${lock_values[14]}; system_auth=${lock_values[15]}
busybox_commit=${lock_values[16]}; busybox_tree=${lock_values[17]}; busybox_repository=${lock_values[18]}
grub_commit=${lock_values[19]}; grub_tree=${lock_values[20]}; grub_repository=${lock_values[21]}
gnulib_commit=${lock_values[22]}; gnulib_tree=${lock_values[23]}; gnulib_repository=${lock_values[24]}
native_digest=${lock_values[25]}; native_auth=${lock_values[26]}
dropbear_commit=${lock_values[27]}; dropbear_tree=${lock_values[28]}; dropbear_repository=${lock_values[29]}
archive_digest=${lock_values[30]}; archive_auth=${lock_values[31]}
make_version=${lock_values[32]}; make_archive=${lock_values[33]}; make_archive_sha256=${lock_values[34]}; make_signature_sha256=${lock_values[35]}; make_top=${lock_values[36]}
gmp_version=${lock_values[37]}; gmp_archive=${lock_values[38]}; gmp_archive_sha256=${lock_values[39]}; gmp_signature_sha256=${lock_values[40]}; gmp_top=${lock_values[41]}
mpfr_version=${lock_values[42]}; mpfr_archive=${lock_values[43]}; mpfr_archive_sha256=${lock_values[44]}; mpfr_signature_sha256=${lock_values[45]}; mpfr_top=${lock_values[46]}
mpc_version=${lock_values[47]}; mpc_archive=${lock_values[48]}; mpc_archive_sha256=${lock_values[49]}; mpc_signature_sha256=${lock_values[50]}; mpc_top=${lock_values[51]}

[[ $bootstrap_auth == authenticated || \
   ${CAJUNOS_ACCEPT_UNAUTHENTICATED_SOURCES:-} == 1 ]] || {
  echo "Bootstrap cohort needs the explicit recorded-transport acceptance" >&2
  exit 78
}
[[ $system_auth == authenticated && $native_auth == authenticated \
   && $archive_auth == authenticated-https-plus-detached-openpgp ]] || {
  echo "Native-developer sources do not meet the authentication contract" >&2
  exit 78
}

linux_source=$upstream/linux
gcc_source=$upstream/gcc
glibc_source=$upstream/glibc
binutils_source=$upstream/binutils
busybox_source=$upstream/busybox
dropbear_source=$upstream/dropbear
for path in "$linux_source" "$gcc_source" "$glibc_source" "$binutils_source" \
  "$busybox_source" "$dropbear_source"; do
  [[ -d $path && ! -L $path ]] || {
    echo "Locked source checkout is unavailable: $path" >&2
    exit 77
  }
done

orchestration_commit=$(git -C "$project_root" rev-parse HEAD)
orchestration_tree=$(git -C "$project_root" rev-parse 'HEAD^{tree}')
SOURCE_DATE_EPOCH=$(git -C "$linux_source" show -s --format=%ct "$linux_commit")
export SOURCE_DATE_EPOCH
kernel_version=$(make -s -C "$linux_source" kernelversion)
kernel_release=$kernel_version-cajunos+

base_receipt_sha256=$(sha256sum "$base_receipt" | awk '{print $1}')
mapfile -t base_values < <(python3 - "$base_receipt" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    value = json.load(stream)
fields = (
    value["source_date_epoch"], value["disk"]["bytes"], value["filesystem"]["bytes"],
    value["disk"]["guid"], value["disk"]["bios_boot_partuuid"],
    value["disk"]["root_partuuid"], value["filesystem"]["uuid"],
    value["kernel"]["version"], value["kernel"]["release"],
    value["dependencies"]["gcc"]["build_id"], value["dependencies"]["gcc"]["prefix"],
    value["dependencies"]["gcc"]["receipt"], value["dependencies"]["gcc"]["receipt_sha256"],
    value["dependencies"]["binutils"]["build_id"], value["dependencies"]["binutils"]["prefix"],
    value["dependencies"]["binutils"]["receipt"], value["dependencies"]["binutils"]["receipt_sha256"],
    value["dependencies"]["glibc"]["build_id"], value["dependencies"]["glibc"]["snapshot"],
    value["dependencies"]["glibc"]["receipt"], value["dependencies"]["glibc"]["receipt_sha256"],
    value["reproducibility"]["rootfs_inventory"]["digest"],
)
for field in fields:
    print(field)
PY
)
[[ ${#base_values[@]} -eq 22 ]] || {
  echo "Stage 9A receipt dependency contract is incomplete" >&2
  exit 79
}
base_source_epoch=${base_values[0]}; base_disk_bytes=${base_values[1]}; base_rootfs_bytes=${base_values[2]}
disk_guid=${base_values[3]}; bios_guid=${base_values[4]}; root_guid=${base_values[5]}; root_uuid=${base_values[6]}
base_kernel_version=${base_values[7]}; base_kernel_release=${base_values[8]}
tools_build_id=${base_values[9]}; tools_prefix=${base_values[10]}; tools_receipt=${base_values[11]}; tools_receipt_sha256=${base_values[12]}
binutils_build_id=${base_values[13]}; binutils_prefix=${base_values[14]}; binutils_receipt=${base_values[15]}; binutils_receipt_sha256=${base_values[16]}
glibc_build_id=${base_values[17]}; glibc_snapshot=${base_values[18]}; glibc_receipt=${base_values[19]}; glibc_receipt_sha256=${base_values[20]}
base_rootfs_inventory_digest=${base_values[21]}

[[ $base_source_epoch == "$SOURCE_DATE_EPOCH" \
   && $base_kernel_version == "$kernel_version" \
   && $base_kernel_release == "$kernel_release" ]] || {
  echo "Stage 9A kernel/source epoch is outside the locked native cohort" >&2
  exit 79
}
"$base_helper" --internal-python validate-receipt \
  "$base_receipt" "$base_artifact" "$base_build_id" \
  schema 1 component system-image stage base-system-image build_id "$base_build_id" \
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
  filesystem.bytes "$base_rootfs_bytes" filesystem.uuid "$root_uuid" \
  filesystem.journal False disk.bytes "$base_disk_bytes" disk.guid "$disk_guid" \
  disk.bios_boot_partuuid "$bios_guid" disk.root_partuuid "$root_guid" \
  security_contract.root_password locked security_contract.ssh deferred-to-stage-9b \
  reproducibility.independent_builds 2 reproducibility.selectors_modified False \
  >/dev/null

[[ $base_disk_bytes == $((1024 * 1024 * 1024)) \
   && $base_rootfs_bytes == $((768 * 1024 * 1024)) ]] || {
  echo "Stage 9A disk geometry differs from the sealed 1 GiB / 768 MiB contract" >&2
  exit 79
}

cohort_id=${bootstrap_digest#sha256:}
cohort_id=${cohort_id:0:16}
tools_selector=$tools_root/current
sysroot_selector=$sysroot_root/$cohort_id/current
initial_tools_selector=$(readlink -- "$tools_selector")
initial_sysroot_selector=$(readlink -- "$sysroot_selector")
[[ $initial_tools_selector == "$tools_build_id" \
   && $initial_sysroot_selector == "snapshots/$glibc_build_id" \
   && $(readlink -f -- "$tools_selector") == "$tools_prefix" \
   && $(readlink -f -- "$sysroot_selector") == "$glibc_snapshot" ]] || {
  echo "Current sealed selectors do not resolve to the explicit Stage 9A cohort" >&2
  exit 80
}
for dependency in "$tools_prefix" "$binutils_prefix" "$glibc_snapshot" \
  "$tools_receipt" "$binutils_receipt" "$glibc_receipt"; do
  [[ -e $dependency && ! -L $dependency ]] || {
    echo "Stage 9A sealed dependency is unavailable: $dependency" >&2
    exit 80
  }
done
[[ $(sha256sum "$tools_receipt" | awk '{print $1}') == "$tools_receipt_sha256" \
   && $(sha256sum "$binutils_receipt" | awk '{print $1}') == "$binutils_receipt_sha256" \
   && $(sha256sum "$glibc_receipt" | awk '{print $1}') == "$glibc_receipt_sha256" ]] || {
  echo "A Stage 9A dependency receipt hash differs" >&2
  exit 80
}

mapfile -t dependency_values < <(python3 - "$tools_receipt" "$glibc_receipt" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    gcc = json.load(stream)
with open(sys.argv[2], encoding="utf-8") as stream:
    glibc = json.load(stream)
dependency = gcc["dependencies"]["binutils"]
print(gcc["base_prefix"])
print(gcc["gcc_version"])
print(gcc["sysroot_snapshot"])
print(glibc["base_snapshot"])
print(dependency["build_id"])
print(dependency["prefix"])
print(dependency["receipt"])
print(dependency["receipt_sha256"])
PY
)
[[ ${#dependency_values[@]} -eq 8 \
   && ${dependency_values[2]} == "$glibc_snapshot" \
   && ${dependency_values[4]} == "$binutils_build_id" \
   && ${dependency_values[5]} == "$binutils_prefix" \
   && ${dependency_values[6]} == "$binutils_receipt" \
   && ${dependency_values[7]} == "$binutils_receipt_sha256" ]] || {
  echo "Stage 9A GCC/glibc/Binutils receipt cohort differs" >&2
  exit 80
}
gcc_base_prefix=${dependency_values[0]}
gcc_version=${dependency_values[1]}
glibc_base_snapshot=${dependency_values[3]}

selector_state_is_initial() {
  [[ $(readlink -- "$tools_selector") == "$initial_tools_selector" \
     && $(readlink -f -- "$tools_selector") == "$tools_prefix" \
     && $(readlink -- "$sysroot_selector") == "$initial_sysroot_selector" \
     && $(readlink -f -- "$sysroot_selector") == "$glibc_snapshot" ]]
}

validate_live_dependencies() {
  selector_state_is_initial || return 1
  "$gcc_helper" --internal-python dependency-inventory \
    "$binutils_prefix" "$tools_root" | python3 -c '
import hashlib, json, pathlib, sys
receipt_path = pathlib.Path(sys.argv[1])
raw = receipt_path.read_bytes()
if hashlib.sha256(raw).hexdigest() != sys.argv[2]:
    raise SystemExit("Binutils receipt changed")
receipt = json.loads(raw)
if json.load(sys.stdin) != receipt.get("installed_entries"):
    raise SystemExit("live Binutils inventory differs from receipt")
' "$binutils_receipt" "$binutils_receipt_sha256" || return 1
  "$base_helper" --internal-python validate-selected-tools \
    "$tools_root" "$tools_prefix" "$binutils_prefix" "$target" >/dev/null \
    || return 1
  "$gcc_helper" --internal-python validate-completed \
    "$tools_receipt" "$tools_prefix" "$gcc_base_prefix" "$tools_root" \
    "$target" "$gcc_version" \
    schema 1 component gcc stage complete build_id "$tools_build_id" \
    source_commit "$gcc_commit" source_tree "$gcc_tree" \
    source_repository "$gcc_repository" source_set_digest "$bootstrap_digest" \
    source_authentication "$bootstrap_auth" target "$target" \
    prefix "$tools_prefix" sysroot_snapshot "$glibc_snapshot" \
    dependencies.binutils.build_id "$binutils_build_id" \
    dependencies.binutils.prefix "$binutils_prefix" \
    dependencies.binutils.receipt "$binutils_receipt" \
    dependencies.binutils.receipt_sha256 "$binutils_receipt_sha256" >/dev/null \
    || return 1
  "$glibc_helper" --internal-python validate-completed \
    "$glibc_receipt" "$glibc_snapshot" "$glibc_base_snapshot" \
    schema 1 component glibc stage complete build_id "$glibc_build_id" \
    source_commit "$glibc_commit" source_tree "$glibc_tree" \
    source_repository "$glibc_repository" source_set_digest "$bootstrap_digest" \
    source_authentication "$bootstrap_auth" target "$target" \
    snapshot "$glibc_snapshot" >/dev/null || return 1
  selector_state_is_initial
}

recipe_sha256=$(sha256sum "$script_path" | awk '{print $1}')
deployment_helper_sha256=$(sha256sum "$deployment_helper" | awk '{print $1}')
base_helper_sha256=$(sha256sum "$base_helper" | awk '{print $1}')
gcc_helper_sha256=$(sha256sum "$gcc_helper" | awk '{print $1}')
glibc_helper_sha256=$(sha256sum "$glibc_helper" | awk '{print $1}')
base_busybox_fragment_sha256=$(sha256sum "$base_busybox_fragment" | awk '{print $1}')
native_busybox_fragment_sha256=$(sha256sum "$native_busybox_fragment" | awk '{print $1}')
dropbear_options_sha256=$(sha256sum "$dropbear_options" | awk '{print $1}')
archive_verifier_sha256=$(sha256sum "$archive_verifier" | awk '{print $1}')
overlay_inventory=$("$script_path" --internal-python overlay-inventory "$overlay")
overlay_digest=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["digest"])' \
  <<<"$overlay_inventory")
base_disk_sha256=$(sha256sum "$base_disk" | awk '{print $1}')

qemu_path=$(readlink -f -- "$(command -v qemu-system-x86_64)")
qemu_img_path=$(readlink -f -- "$(command -v qemu-img)")
qemu_bios=/usr/share/seabios/bios-256k.bin
[[ -f $qemu_bios && ! -L $qemu_bios ]] || {
  echo "Pinned SeaBIOS input is unavailable" >&2
  exit 81
}
qemu_sha256=$(sha256sum "$qemu_path" | awk '{print $1}')
qemu_img_sha256=$(sha256sum "$qemu_img_path" | awk '{print $1}')
qemu_bios_sha256=$(sha256sum "$qemu_bios" | awk '{print $1}')

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
    printf '%s\0%s\0' "$qemu_bios" "$qemu_bios_sha256"
    printf '%s\0%s\0%s\0%s\0%s\0%s\0' \
      "$disk_bytes" "$rootfs_bytes" "$disk_guid" "$bios_guid" "$root_guid" "$root_uuid"
    printf '%s\0%s\0%s\0%s\0%s\0%s\0%s\0' \
      "$qemu_machine" "$qemu_cpu" "$root_first_sector" "$root_hash_seed" \
      "$rootfs_features" "$ssh_port" "$owner_proof_timeout"
  } | sha256sum | awk '{print $1}'
}
host_contract_sha256=$(calculate_host_contract)

build_id=$("$script_path" --internal-python build-id "$base_build_id" \
  bootstrap_digest "$bootstrap_digest" system_digest "$system_digest" \
  native_digest "$native_digest" archive_digest "$archive_digest" \
  orchestration_commit "$orchestration_commit" orchestration_tree "$orchestration_tree" \
  recipe_sha256 "$recipe_sha256" base_helper_sha256 "$base_helper_sha256" \
  deployment_helper_sha256 "$deployment_helper_sha256" \
  gcc_helper_sha256 "$gcc_helper_sha256" glibc_helper_sha256 "$glibc_helper_sha256" \
  base_busybox_fragment_sha256 "$base_busybox_fragment_sha256" \
  native_busybox_fragment_sha256 "$native_busybox_fragment_sha256" \
  dropbear_options_sha256 "$dropbear_options_sha256" \
  archive_verifier_sha256 "$archive_verifier_sha256" \
  overlay_digest "$overlay_digest" base_receipt_sha256 "$base_receipt_sha256" \
  base_disk_sha256 "$base_disk_sha256" archive_validation_sha256 "$archive_validation_sha256" \
  archive_cache_digest "$archive_cache_digest" owner_key_fingerprint "$owner_key_fingerprint" \
  owner_key_input_sha256 "$owner_key_input_sha256" \
  owner_key_canonical_sha256 "$owner_key_canonical_sha256" \
  host_contract_sha256 "$host_contract_sha256")

build_final=$work_root/$build_id
artifact_final=$artifacts_root/$build_id
receipt_final=$artifact_final/receipt.json
temporary_root=$work_root/.tmp-$build_id-$$
artifact_temporary=$artifacts_root/.tmp-$build_id-$$
failed_root=$work_root/.failed-$build_id-$$
failed_artifact=$artifacts_root/.failed-$build_id-$$
canonical_build=$work_root/.canonical-$build_id
archive_extract=$work_root/.archives-$build_id-$$
base_extract=$work_root/.base-root-$build_id-$$
probe_root=$work_root/.probe-$build_id-$$
owner_exchange=$work_root/.owner-proof-$build_id-$$
log_dir=$logs_root/$run_id
log_file=$log_dir/native-developer-seed.log
positive_cmdline="root=PARTUUID=$root_guid rw rootwait console=ttyS0,115200 earlycon=uart8250,io,0x3f8,115200n8 panic=-1 cajunos.native_developer=1"
negative_cmdline="root=PARTUUID=$root_guid rw rootwait console=ttyS0,115200 earlycon=uart8250,io,0x3f8,115200n8 panic=-1 cajunos.native_developer=0"

calculate_archive_cache_digest() {
  python3 - "$archive_verifier" "$archive_manifest" "$archive_lock" \
    "$cajunos_root" <<'PY'
import importlib.util, json
from pathlib import Path
import sys
script, manifest_path, lock_path, root = map(Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location("native_archives_replay", script)
if spec is None or spec.loader is None:
    raise SystemExit("cannot import locked archive verifier")
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
manifest = module.load_json(manifest_path); lock = module.load_json(lock_path)
components = module.validate_lock(manifest, manifest_path, lock)
cache = root / "cache/native-developer-archives"
objects = {}
for component in components:
    for kind in ("archive", "signature", "key"):
        contract = component[kind]
        path = cache / contract["filename"]
        module.validate_object(path, contract, f"replayed {component['name']} {kind}")
        objects[f"{component['name']}:{kind}"] = {
            "path": str(path), "bytes": contract["bytes"],
            "sha256": contract["sha256"], "sha512": contract["sha512"],
        }
print(module.canonical_digest(objects))
PY
}

validate_base_receipt() {
  [[ $(sha256sum "$base_receipt" | awk '{print $1}') == "$base_receipt_sha256" \
     && $(sha256sum "$base_disk" | awk '{print $1}') == "$base_disk_sha256" ]] \
    || return 1
  "$base_helper" --internal-python validate-receipt \
    "$base_receipt" "$base_artifact" "$base_build_id" \
    schema 1 component system-image stage base-system-image build_id "$base_build_id" \
    deployable True diagnostic_only False target "$target" \
    source_date_epoch "$SOURCE_DATE_EPOCH" \
    source_sets.bootstrap.digest "$bootstrap_digest" \
    source_sets.base_system.digest "$system_digest" \
    sources.linux.commit "$linux_commit" sources.busybox.commit "$busybox_commit" \
    sources.grub.commit "$grub_commit" sources.gnulib.commit "$gnulib_commit" \
    filesystem.bytes "$base_rootfs_bytes" filesystem.uuid "$root_uuid" \
    filesystem.journal False disk.bytes "$base_disk_bytes" disk.guid "$disk_guid" \
    disk.bios_boot_partuuid "$bios_guid" disk.root_partuuid "$root_guid" \
    security_contract.root_password locked security_contract.ssh deferred-to-stage-9b \
    reproducibility.independent_builds 2 reproducibility.selectors_modified False \
    >/dev/null
}

validate_inputs() {
  [[ -z ${SSH_AUTH_SOCK:-} ]] || {
    echo "An SSH agent appeared in the untrusted forge environment" >&2
    return 1
  }
  selector_state_is_initial || return 1
  "$project_root/scripts/fetch.py" validate --root "$cajunos_root" --json \
    >/dev/null || return 1
  "$project_root/scripts/fetch.py" validate --root "$cajunos_root" \
    --manifest "$system_manifest" --lock "$system_lock" --json >/dev/null \
    || return 1
  "$project_root/scripts/fetch.py" validate --root "$cajunos_root" \
    --manifest "$native_manifest" --lock "$native_lock" --json >/dev/null \
    || return 1
  if ! [[ -z $(git -C "$project_root" status --porcelain) \
     && $(git -C "$project_root" rev-parse HEAD) == "$orchestration_commit" \
     && $(git -C "$project_root" rev-parse 'HEAD^{tree}') == "$orchestration_tree" \
     && $(sha256sum "$script_path" | awk '{print $1}') == "$recipe_sha256" \
     && $(sha256sum "$deployment_helper" | awk '{print $1}') == "$deployment_helper_sha256" \
     && $(sha256sum "$base_helper" | awk '{print $1}') == "$base_helper_sha256" \
     && $(sha256sum "$gcc_helper" | awk '{print $1}') == "$gcc_helper_sha256" \
     && $(sha256sum "$glibc_helper" | awk '{print $1}') == "$glibc_helper_sha256" \
     && $(sha256sum "$base_busybox_fragment" | awk '{print $1}') == "$base_busybox_fragment_sha256" \
     && $(sha256sum "$native_busybox_fragment" | awk '{print $1}') == "$native_busybox_fragment_sha256" \
     && $(sha256sum "$dropbear_options" | awk '{print $1}') == "$dropbear_options_sha256" \
     && $(sha256sum "$archive_verifier" | awk '{print $1}') == "$archive_verifier_sha256" \
     && $(calculate_archive_cache_digest) == "$archive_cache_digest" \
     && $(calculate_host_contract) == "$host_contract_sha256" ]]; then
    return 1
  fi
  local replay_key
  replay_key=$("$script_path" --internal-python validate-public-key "$owner_public_key") \
    || return 1
  [[ $(python3 -c 'import json,sys; print(json.load(sys.stdin)["canonical_sha256"])' \
      <<<"$replay_key") == "$owner_key_canonical_sha256" ]] || return 1
  "$script_path" --internal-python overlay-inventory "$overlay" | \
    python3 -c 'import json,sys; value=json.load(sys.stdin); raise SystemExit(value["digest"] != sys.argv[1])' \
      "$overlay_digest" || return 1
  "$script_path" --internal-python validate-dropbear-options \
    "$dropbear_options" "$dropbear_source" >/dev/null || return 1
  grep -qx 'CONFIG_UNIX98_PTYS=y' "$base_artifact/boot/kernel.config" \
    || return 1
  grep -qx 'CONFIG_DEVTMPFS=y' "$base_artifact/boot/kernel.config" \
    || return 1
  validate_base_receipt || return 1
  validate_live_dependencies || return 1
  selector_state_is_initial
}

validate_stored_owner_proof() {
  local artifact=$1
  local scratch=$2
  local request_json=$artifact/probe/request.json
  local response_json=$artifact/probe/response.json
  local response_signature=$artifact/probe/response.json.sig
  local response_ready=$artifact/probe/response.json.ready
  "$script_path" --internal-python validate-owner-ready \
    "$response_ready" "$response_json" "$response_signature" >/dev/null \
    || return 1
  local request_result
  request_result=$("$script_path" --internal-python validate-owner-request \
    "$request_json" "$build_id" "$owner_key_canonical_sha256" "$ssh_port") \
    || return 1
  local -a request_values
  mapfile -t request_values < <(python3 -c '
import json, sys
value = json.load(sys.stdin)
for name in ("challenge", "host_key", "host_key_sha256"):
    print(value[name])
' <<<"$request_result")
  [[ ${#request_values[@]} -eq 3 ]] || return 1
  local challenge=${request_values[0]}
  local request_host_key=${request_values[1]}
  local request_host_hash=${request_values[2]}
  local receipt_host_hash
  receipt_host_hash=$(python3 -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream)["qemu"]["owner_proof_host_key_sha256"])
' "$artifact/receipt.json") || return 1
  [[ $receipt_host_hash == "$request_host_hash" ]] || return 1

  "$script_path" --internal-python validate-serial positive \
    "$artifact/probe/owner.serial.raw" "$kernel_release" "$build_id" \
    "$scratch.host-key" "$scratch.serial.normalized" >/dev/null || return 1
  cmp -- "$scratch.serial.normalized" \
    "$artifact/probe/owner.serial.normalized" || return 1
  local serial_host_key serial_host_hash
  serial_host_key=$(awk '{print $1 " " $2}' "$scratch.host-key") || return 1
  serial_host_hash=$(printf '%s\n' "$serial_host_key" | sha256sum | awk '{print $1}')
  [[ $serial_host_key == "$request_host_key" \
     && $serial_host_hash == "$request_host_hash" ]] || return 1

  "$script_path" --internal-python validate-owner-response \
    "$response_json" "$build_id" "$challenge" "$request_host_hash" \
    "$owner_key_canonical_sha256" >/dev/null || return 1
  printf 'cajunos-owner namespaces="cajunos-native-developer-owner-proof" %s\n' \
    "$owner_key_canonical" >"$scratch.allowed-signers"
  chmod 0600 "$scratch.allowed-signers"
  ssh-keygen -Y verify -f "$scratch.allowed-signers" -I cajunos-owner \
    -n cajunos-native-developer-owner-proof \
    -s "$response_signature" \
    <"$response_json" >/dev/null || return 1
}

validate_stage9b_receipt_contract() {
  local receipt=$1 artifact=$2
  "$script_path" --internal-python validate-receipt \
    "$receipt" "$artifact" "$build_id" \
    schema 1 component system-image stage native-developer-seed \
    build_id "$build_id" deployable True diagnostic_only False target "$target" \
    source_date_epoch "$SOURCE_DATE_EPOCH" \
    base_system.build_id "$base_build_id" \
    base_system.receipt "$base_receipt" \
    base_system.receipt_sha256 "$base_receipt_sha256" \
    base_system.disk_sha256 "$base_disk_sha256" \
    base_system.consumption explicit-validated-receipt-artifact-and-root-inventory \
    source_sets.bootstrap.digest "$bootstrap_digest" \
    source_sets.bootstrap.authentication "$bootstrap_auth" \
    source_sets.base_system.digest "$system_digest" \
    source_sets.base_system.authentication "$system_auth" \
    source_sets.native_git.digest "$native_digest" \
    source_sets.native_git.authentication "$native_auth" \
    source_sets.native_archives.digest "$archive_digest" \
    source_sets.native_archives.authentication "$archive_auth" \
    sources.linux.commit "$linux_commit" sources.linux.tree "$linux_tree" \
    sources.linux.repository "$linux_repository" \
    sources.gcc.commit "$gcc_commit" sources.gcc.tree "$gcc_tree" \
    sources.gcc.repository "$gcc_repository" \
    sources.glibc.commit "$glibc_commit" sources.glibc.tree "$glibc_tree" \
    sources.glibc.repository "$glibc_repository" \
    sources.binutils.commit "$binutils_commit" sources.binutils.tree "$binutils_tree" \
    sources.binutils.repository "$binutils_repository" \
    sources.busybox.commit "$busybox_commit" sources.busybox.tree "$busybox_tree" \
    sources.busybox.repository "$busybox_repository" \
    sources.grub.commit "$grub_commit" sources.grub.tree "$grub_tree" \
    sources.grub.repository "$grub_repository" \
    sources.gnulib.commit "$gnulib_commit" sources.gnulib.tree "$gnulib_tree" \
    sources.gnulib.repository "$gnulib_repository" \
    sources.dropbear.commit "$dropbear_commit" sources.dropbear.tree "$dropbear_tree" \
    sources.dropbear.repository "$dropbear_repository" \
    sources.make.version "$make_version" \
    sources.make.archive_sha256 "$make_archive_sha256" \
    sources.make.signature_sha256 "$make_signature_sha256" \
    sources.gmp.version "$gmp_version" \
    sources.gmp.archive_sha256 "$gmp_archive_sha256" \
    sources.gmp.signature_sha256 "$gmp_signature_sha256" \
    sources.mpfr.version "$mpfr_version" \
    sources.mpfr.archive_sha256 "$mpfr_archive_sha256" \
    sources.mpfr.signature_sha256 "$mpfr_signature_sha256" \
    sources.mpc.version "$mpc_version" \
    sources.mpc.archive_sha256 "$mpc_archive_sha256" \
    sources.mpc.signature_sha256 "$mpc_signature_sha256" \
    orchestration.commit "$orchestration_commit" \
    orchestration.tree "$orchestration_tree" \
    orchestration.recipe_sha256 "$recipe_sha256" \
    orchestration.overlay_digest "$overlay_digest" \
    orchestration.deployment_helper_sha256 "$deployment_helper_sha256" \
    dependencies.sealed_cross_gcc.build_id "$tools_build_id" \
    dependencies.sealed_cross_gcc.prefix "$tools_prefix" \
    dependencies.sealed_glibc.build_id "$glibc_build_id" \
    dependencies.sealed_glibc.snapshot "$glibc_snapshot" \
    kernel.version "$kernel_version" kernel.release "$kernel_release" \
    kernel.root_selector PARTUUID kernel.unix98_ptys True kernel.devpts True \
    bootloader.name GRUB bootloader.platform i386-pc \
    bootloader.firmware SeaBIOS \
    bootloader.inheritance Stage-9A-MBR-and-BIOS-partition-byte-preserved \
    filesystem.type ext4 filesystem.bytes "$rootfs_bytes" \
    filesystem.uuid "$root_uuid" filesystem.journal True \
    filesystem.state clean filesystem.forced_fsck True \
    filesystem.directory_hash_seed "$root_hash_seed" \
    disk.format raw-gpt-bios disk.bytes "$disk_bytes" \
    disk.sha256 "$(sha256sum "$artifact/boot/disk.raw" | awk '{print $1}')" \
    disk.guid "$disk_guid" disk.bios_boot_partuuid "$bios_guid" \
    disk.root_partuuid "$root_guid" disk.root_filesystem_bytes "$rootfs_bytes" \
    disk.in_partition_growth_reserve_bytes "$((4 * 1024 * 1024 * 1024 - 4129 * 512))" \
    owner_ssh_key.algorithm ssh-ed25519 \
    owner_ssh_key.fingerprint "$owner_key_fingerprint" \
    owner_ssh_key.input_sha256 "$owner_key_input_sha256" \
    owner_ssh_key.canonical_sha256 "$owner_key_canonical_sha256" \
    owner_ssh_key.authorized_keys_path /root/.ssh/authorized_keys \
    owner_ssh_key.private_key_on_forge False \
    owner_ssh_key.agent_forwarded_to_forge False \
    owner_ssh_key.possession_proof trusted-tunnel-publickey-plus-sshsig \
    owner_ssh_key.signature_namespace cajunos-native-developer-owner-proof \
    security_contract.root_password locked \
    security_contract.ssh static-dropbear-key-only \
    security_contract.password_auth_code compiled-out \
    security_contract.pam_auth_code compiled-out \
    security_contract.forwarding compiled-out \
    security_contract.sftp compiled-out \
    security_contract.inetd compiled-out \
    security_contract.pubkey_options compiled-out \
    security_contract.host_key first-boot-atomic-ed25519-never-sealed \
    security_contract.authentication_logging foreground-stderr-to-serial-console \
    security_contract.qemu_network usernet-restrict-on-loopback-hostfwd-no-egress \
    network.driver virtio-net network.interface eth0 \
    network.configuration dhcpv4-default-static-file-optional \
    network.serial_discovery CAJUNOS_NATIVE_DEVELOPER_IPV4-canonical-ipv4 \
    network.resolver_probe loopback-udp-dns-getaddrinfo-no-egress \
    native_toolchain.build "$build_triplet" native_toolchain.host "$target" \
    native_toolchain.target "$target" \
    native_toolchain.resident_sources True \
    native_toolchain.capability package-build-capable-not-full-self-host \
    qemu.path "$qemu_path" qemu.sha256 "$qemu_sha256" \
    qemu.qemu_img_path "$qemu_img_path" qemu.qemu_img_sha256 "$qemu_img_sha256" \
    qemu.machine "$qemu_machine" qemu.accelerator tcg qemu.cpu "$qemu_cpu" \
    qemu.firmware.path "$qemu_bios" qemu.firmware.sha256 "$qemu_bios_sha256" \
    qemu.positive_cmdline "$positive_cmdline" qemu.negative_cmdline "$negative_cmdline" \
    qemu.negative_boot exact-cmdline-token-fail-closed \
    qemu.post_shutdown_forced_fsck True \
    build_contract.independent_builds 2 \
    build_contract.host_contract_sha256 "$host_contract_sha256" \
    build_contract.rootfs_population fakeroot-mke2fs-d \
    build_contract.rootfs_hash_seed_locked True \
    build_contract.canonical_build_path_reused_sequentially True \
    build_contract.private_key_inputs False \
    template_contract.source pristine-never-booted-stage9b-artifact-only \
    template_contract.booted_validation_disk_forbidden True \
    template_contract.reason deleted-host-private-key-blocks-remain-forensically-recoverable \
    template_contract.independent_clone_host_keys_differ True \
    template_contract.deployment_and_vm118_template later-milestone \
    reproducibility.independent_builds 2 \
    reproducibility.native_payload_identical True \
    reproducibility.rootfs_inventory_identical True \
    reproducibility.rootfs_ext4_identical True \
    reproducibility.gpt_disk_identical True \
    reproducibility.base_disk_immutable_after_probes True \
    reproducibility.selectors_modified False >/dev/null
}

exec 9>"$work_root/.cajunos-build.lock"
flock -n 9 || {
  echo "Another CajunOS build owns the global build lock" >&2
  exit 83
}

if [[ $preflight_only == 1 ]]; then
  validate_inputs
  rm -- "$key_temporary"
  echo "CAJUNOS_NATIVE_DEVELOPER_PREFLIGHT_OK build_id=$build_id"
  exit 0
fi

for candidate_path in "$temporary_root" "$artifact_temporary" "$failed_root" \
  "$failed_artifact" "$canonical_build" "$archive_extract" "$base_extract" \
  "$probe_root" "$owner_exchange"; do
  [[ ! -e $candidate_path && ! -L $candidate_path ]] || {
    echo "Refusing colliding native-developer work path: $candidate_path" >&2
    exit 84
  }
done
mkdir -p -- "$log_dir"
exec > >(tee -a "$log_file") 2>&1
echo "build_id=$build_id"
echo "base_system_build_id=$base_build_id"
echo "native_sources=$native_digest"
echo "release_archives=$archive_digest"

published=0
cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  if [[ -d $probe_root && ! -L $probe_root ]]; then
    local pidfile probe_pid
    for pidfile in "$probe_root"/*.pid; do
      [[ -f $pidfile && ! -L $pidfile ]] || continue
      probe_pid=$(cat -- "$pidfile" 2>/dev/null || true)
      if [[ $probe_pid =~ ^[1-9][0-9]*$ \
         && -e /proc/$probe_pid/exe \
         && $(readlink -f -- "/proc/$probe_pid/exe") == "$qemu_path" ]]; then
        kill -TERM "$probe_pid" 2>/dev/null || true
      fi
    done
  fi
  # owner_exchange contains only public/signed evidence, but is still kept
  # out of the retained build work tree.
  for disposable in "$canonical_build" "$archive_extract" "$base_extract" \
    "$probe_root" "$owner_exchange" "$key_temporary"; do
    if [[ -e $disposable && ! -L $disposable ]]; then
      rm -rf -- "$disposable"
    fi
  done
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
      fi
      if [[ -d $artifact_final && ! -L $artifact_final ]]; then
        mv -T -- "$artifact_final" "$failed_artifact"
      fi
    fi
  else
    for disposable in "$temporary_root" "$artifact_temporary"; do
      if [[ -d $disposable && ! -L $disposable ]]; then
        rm -rf -- "$disposable"
      fi
    done
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

mkdir -- "$temporary_root" "$artifact_temporary"
install -d -m 0700 "$archive_extract" "$base_extract" "$probe_root" "$owner_exchange"

# Extract the already authenticated archives while holding the same source
# lock under which their exact cached bytes were recaptured.  This intentionally
# invokes only the frozen topology/extraction primitives, not its lock-taking
# command-line wrapper.
python3 - "$archive_verifier" "$archive_manifest" "$archive_lock" \
  "$cajunos_root" "$archive_extract" <<'PY'
import importlib.util
from pathlib import Path
import sys
script, manifest_path, lock_path, root, destination = map(Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location("native_archives_extract", script)
if spec is None or spec.loader is None:
    raise SystemExit("cannot import locked archive verifier")
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
manifest = module.load_json(manifest_path); lock = module.load_json(lock_path)
components = module.validate_lock(manifest, manifest_path, lock)
cache = root / "cache/native-developer-archives"
for component in components:
    contract = component["archive"]
    archive = cache / contract["filename"]
    module.validate_object(archive, contract, f"extract {component['name']}")
    module.safe_extract(archive, destination, component["topology"])
    source = destination / component["topology"]["top_level"]
    for relative, expected in component["licenses"].items():
        if module.hash_file(source / relative, "sha256") != expected:
            raise SystemExit(f"license hash differs during extraction: {component['name']}:{relative}")
PY
"$script_path" --internal-python inventory "$archive_extract" \
  >"$temporary_root/archive-sources.json"

# Replay Stage 9A's root inventory against an extraction of the exact sealed
# root partition before using any of its files as the Stage 9B foundation.
base_partition=$base_extract/base.ext4
base_root=$base_extract/root
truncate -s "$base_rootfs_bytes" "$base_partition"
dd if="$base_disk" of="$base_partition" bs=512 skip="$root_first_sector" \
  count=$((base_rootfs_bytes / 512)) conv=sparse,notrunc status=none
mkdir -- "$base_root"
/usr/sbin/debugfs -R "rdump / $base_root" "$base_partition" >/dev/null 2>&1
base_lost_found=$base_root/lost+found
[[ ! -L $base_lost_found && -d $base_lost_found \
   && $(stat -c '%F:%h:%a:%u:%g' "$base_lost_found") == 'directory:2:700:0:0' \
   && -z $(find "$base_lost_found" -mindepth 1 -print -quit) ]] || {
  echo "Stage 9A filesystem-created lost+found contract differs" >&2
  exit 1
}
rmdir -- "$base_lost_found"
"$base_helper" --internal-python inventory "$base_root" \
  >"$temporary_root/base-root.json"
"$base_helper" --internal-python compare-json \
  "$base_artifact/configuration/rootfs-a.json" "$temporary_root/base-root.json"
mkdir -m 0700 -- "$base_lost_found"
"$script_path" --internal-python inventory "$base_root" \
  >"$temporary_root/base-root-foundation.json"
validate_inputs

validate_existing_result() {
  local artifact=$artifact_final
  local receipt=$receipt_final
  local disk=$artifact/boot/disk.raw
  [[ -d $build_final && ! -L $build_final \
     && -d $artifact && ! -L $artifact \
     && -f $receipt && ! -L $receipt ]] || return 1
  cmp -- "$artifact/configuration/archive-source-inventory.json" \
    "$temporary_root/archive-sources.json" || return 1
  cmp -- "$artifact/configuration/base-root-inventory.json" \
    "$temporary_root/base-root.json" || return 1
  cmp -- "$artifact/configuration/base-root-foundation.json" \
    "$temporary_root/base-root-foundation.json" || return 1
  cmp -- "$artifact/configuration/deployment-preparation.sh" \
    "$deployment_helper" || return 1
  validate_stage9b_receipt_contract "$receipt" "$artifact" || return 1
  "$base_helper" --internal-python validate-gpt \
    "$disk" "$disk_guid" "$bios_guid" "$root_guid" "$root_first_sector" \
    >/dev/null
  "$script_path" --internal-python validate-grown-disk \
    "$base_disk" "$disk" "$rootfs_bytes" >/dev/null
  cmp -- "$build_final/root-a.ext4" "$build_final/root-b.ext4" || return 1
  cmp -- "$build_final/disk-a.raw" "$build_final/disk-b.raw" || return 1
  cmp -- "$disk" "$build_final/disk-a.raw" || return 1
  "$script_path" --internal-python validate-ext4 \
    "$build_final/root-a.ext4" "$root_uuid" "$root_hash_seed" \
    "$rootfs_bytes" "$SOURCE_DATE_EPOCH" pristine >/dev/null || return 1
  "$script_path" --internal-python validate-ext4 \
    "$build_final/root-b.ext4" "$root_uuid" "$root_hash_seed" \
    "$rootfs_bytes" "$SOURCE_DATE_EPOCH" pristine >/dev/null || return 1
  "$script_path" --internal-python validate-runtime-root \
    "$build_final/root-a" >/dev/null || return 1
  "$script_path" --internal-python validate-runtime-root \
    "$build_final/root-b" >/dev/null || return 1
  cmp -- "$artifact/configuration/omitted-private-test-fixtures.json" \
    "$build_final/root-a/usr/src/cajunos/build-contract/omitted-private-test-fixtures.json" \
    || return 1
  cmp -- "$artifact/configuration/omitted-private-test-fixtures.json" \
    "$build_final/root-b/usr/src/cajunos/build-contract/omitted-private-test-fixtures.json" \
    || return 1
  "$script_path" --internal-python validate-omitted-private-fixtures \
    "$artifact/configuration/omitted-private-test-fixtures.json" >/dev/null \
    || return 1
  "$script_path" --internal-python inventory "$build_final/root-a" \
    >"$probe_root/replay-root-a.json" || return 1
  "$script_path" --internal-python inventory "$build_final/root-b" \
    >"$probe_root/replay-root-b.json" || return 1
  "$script_path" --internal-python compare-json \
    "$artifact/configuration/rootfs-a.json" \
    "$probe_root/replay-root-a.json" || return 1
  "$script_path" --internal-python compare-json \
    "$artifact/configuration/rootfs-b.json" \
    "$probe_root/replay-root-b.json" || return 1
  "$script_path" --internal-python scan-private-material "$artifact" >/dev/null
  "$script_path" --internal-python scan-private-material "$build_final/root-a" \
    >/dev/null
  "$script_path" --internal-python scan-private-material "$build_final/root-b" \
    >/dev/null
  local stored_disk_sha
  stored_disk_sha=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["disk"]["sha256"])' \
    "$receipt")
  [[ $(sha256sum "$disk" | awk '{print $1}') == "$stored_disk_sha" ]] || return 1
  validate_stored_owner_proof "$artifact" "$probe_root/replay-owner" \
    || return 1

  # Completed-result replay uses a fresh disposable overlay for the real
  # disk-only GRUB path, then a direct-kernel wrong-token boot.  Authentication
  # and native rebuild evidence stays bound by the replayed receipt inventories.
  # The owner response is signed separately; replay never requests owner signing
  # authority again.
  local replay=$probe_root/completed-replay
  mkdir -- "$replay"
  "$qemu_img_path" create -q -f qcow2 -F raw -b "$disk" "$replay/disk.qcow2"
  local before status
  before=$(sha256sum "$disk" | awk '{print $1}')
  set +e
  env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C TZ=UTC \
    timeout --signal=TERM --kill-after=5 60 \
    "$qemu_path" -no-user-config -nodefaults \
      -machine "$qemu_machine,accel=tcg" -cpu "$qemu_cpu" -m 1024M -smp 2 \
      -bios "$qemu_bios" -display none -monitor none -no-reboot \
      -serial stdio \
      -netdev user,id=net0,restrict=on \
      -device virtio-net-pci,netdev=net0 \
      -drive "file=$replay/disk.qcow2,format=qcow2,if=none,id=disk0" \
      -device virtio-blk-pci,drive=disk0 \
      </dev/null >"$replay/positive.serial.raw" 2>&1
  status=$?
  set -e
  [[ $status == 124 ]] || return 1
  "$script_path" --internal-python validate-serial positive \
    "$replay/positive.serial.raw" "$kernel_release" "$build_id" >/dev/null \
    || return 1
  set +e
  env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C TZ=UTC \
    timeout --signal=TERM --kill-after=5 "$qemu_timeout" \
    "$qemu_path" -no-user-config -nodefaults \
      -machine "$qemu_machine,accel=tcg" -cpu "$qemu_cpu" -m 1024M -smp 2 \
      -bios "$qemu_bios" -display none -monitor none -no-reboot \
      -serial stdio -net none \
      -drive "file=$disk,format=raw,if=none,id=disk0,snapshot=on" \
      -device virtio-blk-pci,drive=disk0 \
      -kernel "$artifact/boot/bzImage" -append "$negative_cmdline" \
      </dev/null >"$replay/negative.serial.raw" 2>&1
  status=$?
  set -e
  [[ $status == 0 || $status == 124 ]] || return 1
  "$script_path" --internal-python validate-serial negative \
    "$replay/negative.serial.raw" "$kernel_release" "$build_id" \
    "$replay/negative.serial.normalized" >/dev/null \
    || return 1
  [[ $(stat -c '%F:%h:%a' "$replay/negative.serial.normalized") \
     == 'regular file:1:644' ]] || return 1
  [[ $(sha256sum "$disk" | awk '{print $1}') == "$before" ]] || return 1
  rm -rf -- "$replay"
  validate_inputs
}

if [[ -d $build_final && ! -L $build_final \
   && -d $artifact_final && ! -L $artifact_final \
   && -f $receipt_final && ! -L $receipt_final ]]; then
  validate_existing_result
  echo "CAJUNOS_NATIVE_DEVELOPER_ALREADY_COMPLETE build_id=$build_id"
  exit 0
fi
if [[ -e $build_final || -L $build_final \
   || -e $artifact_final || -L $artifact_final ]]; then
  echo "Refusing incomplete or structurally invalid prior native-developer result" >&2
  exit 84
fi

run_qemu_probes() {
sealed_disk_sha256=$(sha256sum "$temporary_root/disk-a.raw" | awk '{print $1}')
probe_private=$probe_root/id_ed25519_probe
wrong_private=$probe_root/id_ed25519_wrong
ssh-keygen -q -t ed25519 -N '' -C cajunos-stage9b-disposable-probe \
  -f "$probe_private"
ssh-keygen -q -t ed25519 -N '' -C cajunos-stage9b-wrong-probe \
  -f "$wrong_private"
chmod 0600 "$probe_private" "$wrong_private"
probe_public_json=$("$script_path" --internal-python validate-public-key \
  "$probe_private.pub" "$probe_root/authorized_keys")
probe_public=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["canonical"])' \
  <<<"$probe_public_json")

# The disposable probe key is injected only into an equally disposable raw
# copy.  The reproducible artifact retains exactly the approved owner public
# key, while the short-lived probe private key has no authority anywhere but
# the loopback-only, no-egress QEMU guest.
probe_base=$probe_root/probe-base.raw
probe_ext4=$probe_root/probe-base.ext4
cp --sparse=always -- "$temporary_root/disk-a.raw" "$probe_base"
truncate -s "$rootfs_bytes" "$probe_ext4"
dd if="$probe_base" of="$probe_ext4" bs=512 skip="$root_first_sector" \
  count=$((rootfs_bytes / 512)) conv=sparse,notrunc status=none
/usr/sbin/debugfs -w -R 'rm /root/.ssh/authorized_keys' "$probe_ext4" \
  >/dev/null 2>&1
/usr/sbin/debugfs -w -R \
  "write $probe_root/authorized_keys /root/.ssh/authorized_keys" \
  "$probe_ext4" >/dev/null 2>&1
/usr/sbin/debugfs -w -R 'set_inode_field /root/.ssh/authorized_keys mode 0100600' \
  "$probe_ext4" >/dev/null 2>&1
/usr/sbin/debugfs -w -R 'set_inode_field /root/.ssh/authorized_keys uid 0' \
  "$probe_ext4" >/dev/null 2>&1
/usr/sbin/debugfs -w -R 'set_inode_field /root/.ssh/authorized_keys gid 0' \
  "$probe_ext4" >/dev/null 2>&1
E2FSPROGS_FAKE_TIME="$SOURCE_DATE_EPOCH" /usr/sbin/e2fsck -f -y "$probe_ext4" \
  >"$probe_root/probe-base-fsck-repair.txt" 2>&1
"$script_path" --internal-python validate-ext4 \
  "$probe_ext4" "$root_uuid" "$root_hash_seed" "$rootfs_bytes" \
  "$SOURCE_DATE_EPOCH" runtime \
  >"$probe_root/probe-base-fsck.json"
dd if="$probe_ext4" of="$probe_base" bs=512 seek="$root_first_sector" \
  conv=notrunc,sparse status=none
"$base_helper" --internal-python validate-gpt \
  "$probe_base" "$disk_guid" "$bios_guid" "$root_guid" "$root_first_sector" \
  >/dev/null

qemu_common=(
  -no-user-config -nodefaults
  -machine "$qemu_machine,accel=tcg"
  -cpu "$qemu_cpu" -m 2048M -smp 4
  -bios "$qemu_bios"
  -display none -monitor none -no-reboot
  -netdev "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:$ssh_port-:22"
  -device virtio-net-pci,netdev=net0
)

wait_for_qemu_exit() {
  local pidfile=$1
  local pid
  pid=$(cat -- "$pidfile")
  [[ $pid =~ ^[1-9][0-9]*$ ]] || return 1
  local waited=0
  while kill -0 "$pid" 2>/dev/null; do
    waited=$((waited + 1))
    [[ $waited -le $qemu_timeout ]] || return 1
    sleep 1
  done
}

launch_overlay() {
  local overlay_image=$1 serial=$2 pidfile=$3
  [[ ! -e $serial && ! -L $serial && ! -e $pidfile && ! -L $pidfile ]] \
    || return 1
  env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C TZ=UTC \
    "$qemu_path" "${qemu_common[@]}" \
      -daemonize -pidfile "$pidfile" -serial "file:$serial" \
      -drive "file=$overlay_image,format=qcow2,if=none,id=disk0,cache=none" \
      -device virtio-blk-pci,drive=disk0 </dev/null
}

wait_for_serial_ready() {
  local serial=$1
  local waited=0
  # Raw 8250 logs use CRLF.  This is only a liveness poll; the authoritative
  # normalized validator below enforces exact marker uniqueness and order.
  while ! awk '
    { sub(/\r$/, "") }
    $0 == "CAJUNOS_NATIVE_DEVELOPER_SSH_READY" { found = 1 }
    END { exit !found }
  ' "$serial" 2>/dev/null; do
    waited=$((waited + 1))
    [[ $waited -le $qemu_timeout ]] || return 1
    sleep 1
  done
}

prepare_known_hosts() {
  local serial=$1 key_output=$2 known_hosts=$3 scan_output=$4 normalized=$5
  "$script_path" --internal-python validate-serial positive \
    "$serial" "$kernel_release" "$build_id" "$key_output" "$normalized" \
    >/dev/null
  local host_key scanned_key
  host_key=$(cat -- "$key_output")
  timeout 15 ssh-keyscan -T 5 -p "$ssh_port" -t ed25519 127.0.0.1 \
    >"$scan_output" 2>"$scan_output.stderr"
  scanned_key=$(awk '$2 == "ssh-ed25519" { print $2 " " $3 }' "$scan_output")
  [[ $(printf '%s\n' "$scanned_key" | grep -c '^') == 1 \
     && $scanned_key == "$(awk '{print $1 " " $2}' "$key_output")" ]] || {
    echo "ssh-keyscan differs from the serial-attested host key" >&2
    return 1
  }
  printf '[127.0.0.1]:%s %s\n' "$ssh_port" "$scanned_key" >"$known_hosts"
  chmod 0600 "$known_hosts"
}

ssh_base=(
  -F /dev/null -p "$ssh_port"
  -o ConnectTimeout=10 -o ConnectionAttempts=1
  -o GlobalKnownHostsFile=/dev/null
  -o StrictHostKeyChecking=yes
  -o HostKeyAlgorithms=ssh-ed25519
  -o IdentityAgent=none -o IdentitiesOnly=yes
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no
)

run_authentication_gates() {
  local known_hosts=$1 prefix=$2
  local status
  set +e
  ssh "${ssh_base[@]}" -o UserKnownHostsFile="$known_hosts" \
    -o PubkeyAuthentication=no root@127.0.0.1 true \
    >"$prefix.no-key.stdout" 2>"$prefix.no-key.stderr"
  status=$?
  set -e
  [[ $status -ne 0 ]] || {
    echo "SSH unexpectedly accepted a no-key login" >&2
    return 1
  }
  set +e
  ssh "${ssh_base[@]}" -o UserKnownHostsFile="$known_hosts" \
    -o IdentityFile="$wrong_private" root@127.0.0.1 true \
    >"$prefix.wrong-key.stdout" 2>"$prefix.wrong-key.stderr"
  status=$?
  set -e
  [[ $status -ne 0 ]] || {
    echo "SSH unexpectedly accepted the wrong key" >&2
    return 1
  }
  # Password/PAM were compiled out.  This client-side method-only attempt is
  # retained alongside the preprocessor and symbol evidence; no secret or
  # interactive prompt is supplied.
  set +e
  ssh -F /dev/null -p "$ssh_port" -o ConnectTimeout=10 \
    -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile="$known_hosts" \
    -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 \
    -o IdentityAgent=none -o IdentitiesOnly=yes -o PubkeyAuthentication=no \
    -o PreferredAuthentications=password -o NumberOfPasswordPrompts=0 \
    root@127.0.0.1 true >"$prefix.password.stdout" 2>"$prefix.password.stderr"
  status=$?
  set -e
  [[ $status -ne 0 ]] || {
    echo "SSH unexpectedly accepted password authentication" >&2
    return 1
  }
}

probe_nonce=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
probe_script=$probe_root/native-probe.sh
cat >"$probe_script" <<'PROBE'
#!/bin/sh
set -eu
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
[ "$(command -v gcc)" = /usr/bin/gcc ]
[ "$(command -v g++)" = /usr/bin/g++ ]
[ "$(command -v make)" = /usr/bin/make ]
[ "$(command -v ar)" = /usr/bin/ar ]
/usr/bin/ar --version | /bin/grep -q '^GNU ar '
work=/tmp/cajunos-native-probe
/bin/rm -rf "$work"
/bin/mkdir -p "$work"
cd "$work"
cat > hello.c <<'EOF'
#include <stdio.h>
int answer(void) { return 42; }
int main(void) { printf("%d\n", answer()); return 0; }
EOF
cat > hello.cc <<'EOF'
#include <iostream>
int main() { std::cout << "cxx-ok" << std::endl; }
EOF
cat > answer.S <<'EOF'
.text
.globl assembly_answer
assembly_answer:
    mov $42, %eax
    ret
EOF
cat > atomic.c <<'EOF'
__int128 value;
int main(void) { return (int)__atomic_fetch_add(&value, 1, __ATOMIC_SEQ_CST); }
EOF
/usr/bin/gcc -O2 hello.c -o hello
[ "$(./hello)" = 42 ]
/usr/bin/gcc -O2 -static hello.c -o hello.static
[ "$(./hello.static)" = 42 ]
/usr/bin/g++ -O2 hello.cc -o hello-cxx
[ "$(./hello-cxx)" = cxx-ok ]
/usr/bin/gcc -c answer.S -o answer.o
/usr/bin/ar crD libanswer.a answer.o
/usr/bin/ranlib -D libanswer.a
/usr/bin/ar t libanswer.a | /bin/grep -qx answer.o
/usr/bin/gcc atomic.c -latomic -o atomic
cat > Makefile <<'EOF'
all: made
made: hello.c
	/usr/bin/gcc -O2 hello.c -o made
EOF
/usr/bin/make --no-builtin-rules all
[ "$(./made)" = 42 ]
cat > dns-server.c <<'EOF'
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void) {
    unsigned char query[512], response[512];
    struct sockaddr_in local = {0}, peer = {0};
    socklen_t peer_length = sizeof(peer);
    int one = 1, socket_fd, ready_fd;
    ssize_t length;
    size_t question_end = 12, output_length;
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) return 10;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    local.sin_family = AF_INET;
    local.sin_port = htons(53);
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(socket_fd, (struct sockaddr *)&local, sizeof(local)) != 0) return 11;
    ready_fd = open("/tmp/cajunos-dns-ready", O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (ready_fd < 0 || close(ready_fd) != 0) return 12;
    length = recvfrom(socket_fd, query, sizeof(query), 0,
                      (struct sockaddr *)&peer, &peer_length);
    if (length < 17 || query[4] != 0 || query[5] != 1) return 13;
    while (question_end < (size_t)length && query[question_end] != 0) {
        size_t label = query[question_end];
        if (label == 0 || label > 63 || question_end + label + 1 >= (size_t)length)
            return 14;
        question_end += label + 1;
    }
    question_end++;
    if (question_end + 4 > (size_t)length || query[question_end] != 0
        || query[question_end + 1] != 1 || query[question_end + 2] != 0
        || query[question_end + 3] != 1) return 15;
    question_end += 4;
    if (question_end + 16 > sizeof(response)) return 16;
    memcpy(response, query, question_end);
    response[2] = 0x81; response[3] = 0x80;
    response[4] = 0; response[5] = 1;
    response[6] = 0; response[7] = 1;
    response[8] = response[9] = response[10] = response[11] = 0;
    output_length = question_end;
    { const unsigned char answer[] = {
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x3c, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x7b
      };
      memcpy(response + output_length, answer, sizeof(answer));
      output_length += sizeof(answer);
    }
    if (sendto(socket_fd, response, output_length, 0,
               (struct sockaddr *)&peer, peer_length) != (ssize_t)output_length)
        return 17;
    return close(socket_fd) == 0 ? 0 : 18;
}
EOF
cat > resolver.c <<'EOF'
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    struct addrinfo hints, *result, *entry;
    char address[INET_ADDRSTRLEN];
    int matches = 0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo("cajunos-nss-probe.invalid", "80", &hints, &result) != 0)
        return 20;
    for (entry = result; entry != NULL; entry = entry->ai_next) {
        struct sockaddr_in *peer = (struct sockaddr_in *)entry->ai_addr;
        if (inet_ntop(AF_INET, &peer->sin_addr, address, sizeof(address)) == NULL)
            return 21;
        if (strcmp(address, "192.0.2.123") == 0) matches++;
        else return 22;
    }
    freeaddrinfo(result);
    if (matches != 1) return 23;
    puts("RESOLVER_DNS=192.0.2.123");
    return 0;
}
EOF
/usr/bin/gcc -O2 dns-server.c -o dns-server
/usr/bin/gcc -O2 resolver.c -o resolver
/bin/cp -a /etc/nsswitch.conf nsswitch.conf.saved
resolv_existed=0
if [ -e /etc/resolv.conf ] || [ -L /etc/resolv.conf ]; then
    /bin/cp -a /etc/resolv.conf resolv.conf.saved
    resolv_existed=1
fi
dns_pid=
restore_resolver_configuration()
{
    if [ -n "$dns_pid" ]; then
        /bin/kill "$dns_pid" 2>/dev/null || true
        wait "$dns_pid" 2>/dev/null || true
    fi
    /bin/rm -f /etc/nsswitch.conf /etc/resolv.conf /tmp/cajunos-dns-ready
    /bin/cp -a nsswitch.conf.saved /etc/nsswitch.conf
    if [ "$resolv_existed" = 1 ]; then
        /bin/cp -a resolv.conf.saved /etc/resolv.conf
    fi
}
trap restore_resolver_configuration EXIT HUP INT TERM
/bin/printf 'hosts: dns\n' >/etc/nsswitch.conf
/bin/printf 'nameserver 127.0.0.1\noptions attempts:1 timeout:1\n' >/etc/resolv.conf
/bin/rm -f /tmp/cajunos-dns-ready
./dns-server &
dns_pid=$!
dns_wait=0
while [ ! -f /tmp/cajunos-dns-ready ]; do
    /bin/kill -0 "$dns_pid" 2>/dev/null
    dns_wait=$((dns_wait + 1))
    [ "$dns_wait" -le 100 ]
    /bin/usleep 10000
done
[ "$(./resolver)" = RESOLVER_DNS=192.0.2.123 ]
wait "$dns_pid"
dns_pid=
restore_resolver_configuration
trap - EXIT HUP INT TERM
/bin/cp -a /usr/src/cajunos/dropbear rebuild-dropbear
cd rebuild-dropbear
./configure --prefix=/usr --disable-zlib --disable-lastlog --disable-utmp \
  --disable-utmpx --disable-wtmp --disable-wtmpx --disable-syslog \
  --disable-shadow >/tmp/dropbear-rebuild-configure.log 2>&1
/usr/bin/make -j2 PROGRAMS=dropbearkey STATIC=1 MULTI=0 \
  >/tmp/dropbear-rebuild-make.log 2>&1
./dropbearkey -t ed25519 -f /tmp/rebuilt-dropbear-key \
  >/tmp/dropbear-rebuild-key.log 2>&1
[ -s /tmp/rebuilt-dropbear-key ]
/bin/rm -f /tmp/rebuilt-dropbear-key /tmp/rebuilt-dropbear-key.pub
/bin/mkdir -p /var/lib/cajunos
/bin/printf '%s\n' "$CAJUNOS_PROBE_NONCE" >/var/lib/cajunos/probe-nonce
/bin/sync
echo "TOOL_GCC=$(/usr/bin/gcc --version | /usr/bin/head -n 1)"
echo "TOOL_GXX=$(/usr/bin/g++ --version | /usr/bin/head -n 1)"
echo "TOOL_LD=$(/usr/bin/ld --version | /usr/bin/head -n 1)"
echo "TOOL_AS=$(/usr/bin/as --version | /usr/bin/head -n 1)"
echo "TOOL_AR=$(/usr/bin/ar --version | /usr/bin/head -n 1)"
echo "TOOL_MAKE=$(/usr/bin/make --version | /usr/bin/head -n 1)"
echo CAJUNOS_NATIVE_PROBE_OK
PROBE
chmod 0700 "$probe_script"

overlay_a=$probe_root/probe-a.qcow2
overlay_b=$probe_root/probe-b.qcow2
"$qemu_img_path" create -q -f qcow2 -F raw -b "$probe_base" "$overlay_a"
"$qemu_img_path" create -q -f qcow2 -F raw -b "$probe_base" "$overlay_b"

boot_probe_overlay() {
  local name=$1 overlay_image=$2 perform_builds=$3
  local prefix=$probe_root/$name
  launch_overlay "$overlay_image" "$prefix.serial.raw" "$prefix.pid"
  wait_for_serial_ready "$prefix.serial.raw"
  prepare_known_hosts "$prefix.serial.raw" "$prefix.host-key" \
    "$prefix.known-hosts" "$prefix.keyscan" "$prefix.serial.normalized"
  run_authentication_gates "$prefix.known-hosts" "$prefix"
  if [[ $perform_builds == 1 ]]; then
    env CAJUNOS_PROBE_NONCE="$probe_nonce" \
      ssh "${ssh_base[@]}" -o UserKnownHostsFile="$prefix.known-hosts" \
        -o IdentityFile="$probe_private" -o LogLevel=VERBOSE \
        root@127.0.0.1 /usr/bin/env \
          "CAJUNOS_PROBE_NONCE=$probe_nonce" /bin/sh -s \
          <"$probe_script" >"$prefix.probe.stdout" 2>"$prefix.probe.stderr"
    grep -Fq 'Authenticated to 127.0.0.1' "$prefix.probe.stderr"
    grep -Fq 'using "publickey"' "$prefix.probe.stderr"
    grep -Fqx CAJUNOS_NATIVE_PROBE_OK "$prefix.probe.stdout"
    ssh "${ssh_base[@]}" -tt -o UserKnownHostsFile="$prefix.known-hosts" \
      -o IdentityFile="$probe_private" root@127.0.0.1 \
      'test -t 0 && test -t 1 && tty | grep -q "^/dev/pts/" && echo CAJUNOS_PTY_OK' \
      >"$prefix.pty.stdout" 2>"$prefix.pty.stderr"
    grep -Fq CAJUNOS_PTY_OK "$prefix.pty.stdout"
  fi
  set +e
  ssh "${ssh_base[@]}" -o UserKnownHostsFile="$prefix.known-hosts" \
    -o IdentityFile="$probe_private" root@127.0.0.1 /sbin/poweroff \
    >"$prefix.poweroff.stdout" 2>"$prefix.poweroff.stderr"
  set -e
  wait_for_qemu_exit "$prefix.pid"
}

boot_probe_overlay first-a "$overlay_a" 1
first_a_host_key=$(cat -- "$probe_root/first-a.host-key")

# Second boot of the same overlay must preserve both runtime identity and the
# nonce written through the journaled filesystem.
launch_overlay "$overlay_a" "$probe_root/second-a.serial.raw" "$probe_root/second-a.pid"
wait_for_serial_ready "$probe_root/second-a.serial.raw"
prepare_known_hosts "$probe_root/second-a.serial.raw" "$probe_root/second-a.host-key" \
  "$probe_root/second-a.known-hosts" "$probe_root/second-a.keyscan" \
  "$probe_root/second-a.serial.normalized"
[[ $(cat -- "$probe_root/second-a.host-key") == "$first_a_host_key" ]] || {
  echo "A QEMU overlay did not preserve its generated host key" >&2
  exit 1
}
persisted_nonce=$(ssh "${ssh_base[@]}" \
  -o UserKnownHostsFile="$probe_root/second-a.known-hosts" \
  -o IdentityFile="$probe_private" root@127.0.0.1 \
  /bin/cat /var/lib/cajunos/probe-nonce)
[[ $persisted_nonce == "$probe_nonce" ]] || {
  echo "QEMU overlay persistence nonce did not survive a clean reboot" >&2
  exit 1
}
set +e
ssh "${ssh_base[@]}" -o UserKnownHostsFile="$probe_root/second-a.known-hosts" \
  -o IdentityFile="$probe_private" root@127.0.0.1 /sbin/poweroff \
  >"$probe_root/second-a.poweroff.stdout" 2>"$probe_root/second-a.poweroff.stderr"
set -e
wait_for_qemu_exit "$probe_root/second-a.pid"

boot_probe_overlay first-b "$overlay_b" 0
first_b_host_key=$(cat -- "$probe_root/first-b.host-key")
[[ $first_b_host_key != "$first_a_host_key" ]] || {
  echo "Independent pristine overlays generated the same SSH host key" >&2
  exit 1
}

validate_overlay_fsck() {
  local name=$1 overlay_image=$2
  local flattened=$probe_root/$name.flattened.raw
  local filesystem=$probe_root/$name.ext4
  "$qemu_img_path" convert -q -f qcow2 -O raw -S 4096 \
    "$overlay_image" "$flattened"
  truncate -s "$rootfs_bytes" "$filesystem"
  dd if="$flattened" of="$filesystem" bs=512 skip="$root_first_sector" \
    count=$((rootfs_bytes / 512)) conv=sparse,notrunc status=none
  "$script_path" --internal-python validate-ext4 \
    "$filesystem" "$root_uuid" "$root_hash_seed" "$rootfs_bytes" \
    "$SOURCE_DATE_EPOCH" runtime \
    >"$probe_root/$name.forced-fsck.json"
  rm -- "$flattened" "$filesystem"
}
validate_overlay_fsck probe-a "$overlay_a"
validate_overlay_fsck probe-b "$overlay_b"

# Stage 9B owns a new rcS contract, so it retains its own fail-closed negative
# boot rather than inheriting Stage 9A's proof.  No SSH host forward is needed.
negative_raw=$probe_root/negative.serial.raw
set +e
env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C TZ=UTC \
  timeout --signal=TERM --kill-after=5 "$qemu_timeout" \
  "$qemu_path" -no-user-config -nodefaults \
    -machine "$qemu_machine,accel=tcg" -cpu "$qemu_cpu" -m 1024M -smp 2 \
    -bios "$qemu_bios" -display none -monitor none -no-reboot \
    -serial stdio -net none \
    -drive "file=$temporary_root/disk-a.raw,format=raw,if=none,id=disk0,snapshot=on" \
    -device virtio-blk-pci,drive=disk0 \
    -kernel "$base_artifact/boot/bzImage" -append "$negative_cmdline" \
    </dev/null >"$negative_raw" 2>&1
negative_status=$?
set -e
[[ $negative_status == 0 || $negative_status == 124 ]] || {
  echo "Negative QEMU boot exited unexpectedly: $negative_status" >&2
  exit 1
}
"$script_path" --internal-python validate-serial negative \
  "$negative_raw" "$kernel_release" "$build_id" \
  "$probe_root/negative.serial.normalized" >/dev/null
[[ $(stat -c '%F:%h:%a' "$probe_root/negative.serial.normalized") \
   == 'regular file:1:644' ]]

# Boot a pristine overlay backed by the actual owner-key artifact.  A separate
# trusted host reaches this loopback-only forward through an SSH tunnel,
# authenticates with the approved owner key without forwarding its agent, and
# returns a signed challenge response.  No owner signing authority exists in
# this forge process or in any upstream build environment.
owner_overlay=$probe_root/owner.qcow2
"$qemu_img_path" create -q -f qcow2 -F raw \
  -b "$temporary_root/disk-a.raw" "$owner_overlay"
launch_overlay "$owner_overlay" "$probe_root/owner.serial.raw" "$probe_root/owner.pid"
wait_for_serial_ready "$probe_root/owner.serial.raw"
prepare_known_hosts "$probe_root/owner.serial.raw" "$probe_root/owner.host-key" \
  "$probe_root/owner.known-hosts" "$probe_root/owner.keyscan" \
  "$probe_root/owner.serial.normalized"
owner_host_key=$(awk '{print $1 " " $2}' "$probe_root/owner.host-key")
[[ $owner_host_key != "$(awk '{print $1 " " $2}' "$probe_root/first-a.host-key")" \
   && $owner_host_key != "$(awk '{print $1 " " $2}' "$probe_root/first-b.host-key")" ]] || {
  echo "Pristine owner overlay reused another clone's SSH host key" >&2
  exit 1
}
owner_host_key_sha256=$(printf '%s\n' "$owner_host_key" | sha256sum | awk '{print $1}')
owner_challenge=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
owner_request=$owner_exchange/request.json
owner_response=$owner_exchange/response.json
owner_ready=$owner_response.ready
python3 - "$owner_request" "$build_id" "$owner_challenge" "$ssh_port" \
  "$owner_host_key" "$owner_host_key_sha256" "$owner_key_canonical_sha256" <<'PY'
import json, os, sys
path, build_id, challenge, port, host_key, host_key_sha256, owner_sha256 = sys.argv[1:]
value = {
    "schema": 1, "build_id": build_id, "challenge": challenge,
    "host": "127.0.0.1", "port": int(port), "host_key": host_key,
    "host_key_sha256": host_key_sha256,
    "owner_public_key_sha256": owner_sha256,
    "namespace": "cajunos-native-developer-owner-proof",
}
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
    json.dump(value, stream, indent=2, sort_keys=True); stream.write("\n")
PY
"$script_path" --internal-python validate-owner-request \
  "$owner_request" "$build_id" "$owner_key_canonical_sha256" "$ssh_port" \
  >/dev/null
echo "CAJUNOS_NATIVE_DEVELOPER_OWNER_PROOF_REQUIRED request=$owner_request response=$owner_response"
echo "Copy the request to a trusted host, tunnel this forge loopback SSH port, run:"
echo "$script_path --trusted-owner-proof REQUEST.json RESPONSE.json"
echo "Copy RESPONSE.json, RESPONSE.json.sig, and RESPONSE.json.ready to temporary names in $owner_exchange."
echo "Atomically rename RESPONSE.json and RESPONSE.json.sig first, then rename RESPONSE.json.ready last."
proof_waited=0
while ! "$script_path" --internal-python validate-owner-ready \
    "$owner_ready" "$owner_response" "$owner_response.sig" \
    >/dev/null 2>&1; do
  proof_waited=$((proof_waited + 1))
  [[ $proof_waited -le $owner_proof_timeout ]] || {
    echo "Timed out waiting for the trusted owner-key proof" >&2
    exit 1
  }
  if (( proof_waited % 30 == 0 )); then
    echo "Still waiting for trusted owner-key proof ($proof_waited seconds)"
  fi
  sleep 1
done
sealed_owner_response=$probe_root/owner.response.json
sealed_owner_signature=$probe_root/owner.response.json.sig
sealed_owner_ready=$probe_root/owner.response.json.ready
install -m 0600 "$owner_response" "$sealed_owner_response"
install -m 0600 "$owner_response.sig" "$sealed_owner_signature"
install -m 0600 "$owner_ready" "$sealed_owner_ready"
"$script_path" --internal-python validate-owner-ready \
  "$sealed_owner_ready" "$sealed_owner_response" "$sealed_owner_signature" \
  >/dev/null
printf 'cajunos-owner namespaces="cajunos-native-developer-owner-proof" %s\n' \
  "$owner_key_canonical" >"$probe_root/owner.allowed-signers"
chmod 0600 "$probe_root/owner.allowed-signers"
ssh-keygen -Y verify -f "$probe_root/owner.allowed-signers" -I cajunos-owner \
  -n cajunos-native-developer-owner-proof -s "$sealed_owner_signature" \
  <"$sealed_owner_response" >"$probe_root/owner.signature-verify.txt"
"$script_path" --internal-python validate-owner-response \
  "$sealed_owner_response" "$build_id" "$owner_challenge" \
  "$owner_host_key_sha256" "$owner_key_canonical_sha256" >/dev/null
wait_for_qemu_exit "$probe_root/owner.pid"
validate_overlay_fsck owner "$owner_overlay"

install -d -m 0755 "$temporary_root/owner-proof-evidence"
install -m 0644 "$owner_request" \
  "$temporary_root/owner-proof-evidence/request.json"
install -m 0644 "$sealed_owner_response" \
  "$temporary_root/owner-proof-evidence/response.json"
install -m 0644 "$sealed_owner_signature" \
  "$temporary_root/owner-proof-evidence/response.json.sig"
install -m 0644 "$sealed_owner_ready" \
  "$temporary_root/owner-proof-evidence/response.json.ready"
install -m 0644 "$probe_root/owner.serial.raw" \
  "$temporary_root/owner-proof-evidence/owner.serial.raw"
install -m 0644 "$probe_root/owner.serial.normalized" \
  "$temporary_root/owner-proof-evidence/owner.serial.normalized"
install -m 0644 "$probe_root/owner.forced-fsck.json" \
  "$temporary_root/owner-proof-evidence/owner.forced-fsck.json"

first_a_host_key_canonical=$(awk '{print $1 " " $2}' \
  "$probe_root/first-a.host-key")
first_a_host_key_sha256=$(printf '%s\n' "$first_a_host_key_canonical" | \
  sha256sum | awk '{print $1}')
python3 - "$temporary_root/ssh-evidence.json" "$build_id" "$probe_nonce" \
  "$first_a_host_key_sha256" "$probe_root/first-a.probe.stdout" <<'PY'
import json, sys
path, build_id, nonce, host_key_sha256, transcript = sys.argv[1:]
tools = {}
mapping = {
    "TOOL_GCC": "gcc", "TOOL_GXX": "g++", "TOOL_LD": "ld",
    "TOOL_AS": "as", "TOOL_AR": "ar", "TOOL_MAKE": "make",
}
for line in open(transcript, encoding="utf-8"):
    for marker, name in mapping.items():
        if line.startswith(marker + "="):
            tools[name] = line.split("=", 1)[1].strip()
value = {
    "schema": 1, "build_id": build_id,
    "boot": "disk-only-gpt-bios-grub-qcow2-overlay",
    "host_key_sha256": host_key_sha256,
    "authentication": {
        "no_key_rejected": True, "wrong_key_rejected": True,
        "password_rejected": True, "dedicated_probe_key_succeeded": True,
        "owner_key_succeeded": True, "strict_host_key_pinning": True,
        "success_method": "publickey", "interactive_pty": True,
    },
    "toolchain": tools,
    "package_rebuild": {
        "c": True, "c_static": True, "cxx": True, "assembly": True,
        "archive": True, "make": True, "dropbearkey": True,
        "dns_resolution": True,
    },
    "persistence": {
        "nonce": nonce, "nonce_survived_reboot": True,
        "host_key_survived_reboot": True,
    },
    "template_safety": {
        "pristine_seed_only": True,
        "validation_disks_forbidden_as_template_sources": True,
        "independent_clone_host_keys_differ": True,
    },
}
with open(path, "w", encoding="utf-8", newline="\n") as stream:
    json.dump(value, stream, indent=2, sort_keys=True); stream.write("\n")
PY
chmod 0644 "$temporary_root/ssh-evidence.json"
"$script_path" --internal-python validate-ssh-evidence \
  "$temporary_root/ssh-evidence.json" "$build_id" "$probe_nonce" \
  "$first_a_host_key_sha256" >/dev/null

install -d -m 0755 "$temporary_root/qemu-evidence"
for evidence_file in \
  first-a.serial.raw first-a.serial.normalized first-a.host-key first-a.keyscan \
  first-a.no-key.stderr first-a.wrong-key.stderr first-a.password.stderr \
  first-a.probe.stdout first-a.probe.stderr first-a.pty.stdout \
  second-a.serial.raw second-a.serial.normalized second-a.host-key \
  first-b.serial.raw first-b.serial.normalized first-b.host-key \
  probe-a.forced-fsck.json probe-b.forced-fsck.json \
  negative.serial.raw negative.serial.normalized; do
  install -m 0644 "$probe_root/$evidence_file" \
    "$temporary_root/qemu-evidence/$evidence_file"
done

[[ $(sha256sum "$temporary_root/disk-a.raw" | awk '{print $1}') == "$sealed_disk_sha256" \
   && $(sha256sum "$temporary_root/disk-b.raw" | awk '{print $1}') == "$sealed_disk_sha256" ]] || {
  echo "QEMU probes mutated a sealed raw artifact" >&2
  exit 1
}
}

cross_prefix=$tools_prefix/bin/$target-
cross_gcc=${cross_prefix}gcc
cross_gxx=${cross_prefix}g++
cross_ar=$binutils_prefix/bin/$target-ar
cross_as=$binutils_prefix/bin/$target-as
cross_ld=$binutils_prefix/bin/$target-ld
cross_nm=$binutils_prefix/bin/$target-nm
cross_ranlib=$binutils_prefix/bin/$target-ranlib
cross_readelf=$binutils_prefix/bin/$target-readelf
cross_strip=$binutils_prefix/bin/$target-strip
canonical_guest_build=/usr/src/cajunos-build
target_cflags="-O2 -pipe -march=x86-64-v2 -mtune=generic -ffile-prefix-map=$canonical_build=$canonical_guest_build -fmacro-prefix-map=$canonical_build=$canonical_guest_build -ffile-prefix-map=$cajunos_root=/usr/src/cajunos-host -fmacro-prefix-map=$cajunos_root=/usr/src/cajunos-host"

export_git_source() {
  local checkout=$1 commit=$2 destination=$3
  mkdir -- "$destination"
  git -C "$checkout" archive "$commit" | tar -x -C "$destination"
  find "$destination" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
}

build_payload() {
  local label=$1
  local source=$canonical_build/source
  local build=$canonical_build/build
  local stage=$canonical_build/stage
  local root=$canonical_build/root
  local evidence=$canonical_build/evidence
  local busybox_build=$build/busybox
  local gmp_build=$build/gmp
  local mpfr_build=$build/mpfr
  local mpc_build=$build/mpc
  local binutils_build=$build/binutils
  local gcc_build=$build/gcc
  local make_build=$build/make
  local dropbear_build=$build/dropbear
  local warning_status

  [[ ! -e $canonical_build && ! -L $canonical_build ]] || {
    echo "Canonical native build path was not fresh for build $label" >&2
    return 1
  }
  mkdir -- "$canonical_build"
  install -d -m 0755 "$source" "$build" "$stage" "$root" "$evidence"

  export_git_source "$gcc_source" "$gcc_commit" "$source/gcc"
  export_git_source "$binutils_source" "$binutils_commit" "$source/binutils"
  export_git_source "$glibc_source" "$glibc_commit" "$source/glibc"
  export_git_source "$linux_source" "$linux_commit" "$source/linux"
  export_git_source "$busybox_source" "$busybox_commit" "$source/busybox"
  export_git_source "$dropbear_source" "$dropbear_commit" "$source/dropbear"
  cp -a -- "$archive_extract/$make_top" "$source/make"
  cp -a -- "$archive_extract/$gmp_top" "$source/gmp"
  cp -a -- "$archive_extract/$mpfr_top" "$source/mpfr"
  cp -a -- "$archive_extract/$mpc_top" "$source/mpc"
  find "$source" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

  # Start the target staging root with the exact sealed complete-glibc
  # snapshot.  This supplies the loader, headers, crt objects, NSS modules,
  # shared libraries, and static libraries used by every Canadian build.
  cp -a -- "$glibc_snapshot/." "$stage/"

  # Expanded static BusyBox remains the recovery shell, but its ar applet and
  # applet-preference shortcut are deliberately disabled so package builds use
  # the native GNU Binutils driver in /usr/bin.
  mkdir -- "$busybox_build"
  env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    make -s -C "$source/busybox" O="$busybox_build" ARCH=x86_64 \
      CROSS_COMPILE="$cross_prefix" allnoconfig
  "$base_helper" --internal-python merge-kconfig \
    "$busybox_build/.config" "$base_busybox_fragment"
  "$base_helper" --internal-python merge-kconfig \
    "$busybox_build/.config" "$native_busybox_fragment"
  if ! env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    make -s -C "$source/busybox" O="$busybox_build" ARCH=x86_64 \
      CROSS_COMPILE="$cross_prefix" oldconfig </dev/null \
      >"$busybox_build/oldconfig.log" 2>&1; then
    cat -- "$busybox_build/oldconfig.log" >&2
    return 1
  fi
  warning_status=0
  grep -Fq -- 'warning: trying to assign nonexistent symbol' \
    "$busybox_build/oldconfig.log" || warning_status=$?
  [[ $warning_status == 1 ]] || {
    echo "BusyBox fragment contains a symbol absent from the locked revision" >&2
    return 1
  }
  "$base_helper" --internal-python validate-kconfig-resolution \
    "$base_busybox_fragment" "$busybox_build/.config" >/dev/null
  "$base_helper" --internal-python validate-kconfig-resolution \
    "$native_busybox_fragment" "$busybox_build/.config" >/dev/null
  "$script_path" --internal-python validate-busybox-config \
    "$busybox_build/.config" >/dev/null
  rm -- "$busybox_build/oldconfig.log"
  env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    KBUILD_BUILD_TIMESTAMP="$(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%d %H:%M:%S +0000')" \
    make -C "$source/busybox" O="$busybox_build" ARCH=x86_64 \
      CROSS_COMPILE="$cross_prefix" \
      EXTRA_CFLAGS="--sysroot=$glibc_snapshot $target_cflags" \
      EXTRA_LDFLAGS="--sysroot=$glibc_snapshot -static" -j"$jobs" busybox
  "$cross_strip" --strip-all "$busybox_build/busybox"
  env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    make -s -C "$source/busybox" O="$busybox_build" ARCH=x86_64 \
      CROSS_COMPILE="$cross_prefix" \
      EXTRA_CFLAGS="--sysroot=$glibc_snapshot $target_cflags" \
      EXTRA_LDFLAGS="--sysroot=$glibc_snapshot -static" \
      CONFIG_PREFIX="$stage" install
  if "$cross_readelf" -dW "$stage/bin/busybox" 2>/dev/null | grep -q NEEDED; then
    echo "Native-developer BusyBox is not static" >&2
    return 1
  fi
  install -m 0644 "$busybox_build/.config" "$evidence/busybox.config"

  mkdir -- "$gmp_build"
  (
    cd "$gmp_build"
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
      CC="$cross_gcc --sysroot=$stage" AR="$cross_ar" AS="$cross_as" \
      LD="$cross_ld" NM="$cross_nm" RANLIB="$cross_ranlib" \
      CFLAGS="$target_cflags -std=gnu17" \
      "$source/gmp/configure" --prefix=/usr --build="$build_triplet" \
        --host="$target" --disable-shared --enable-static --disable-assembly
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" make -j"$jobs"
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" make DESTDIR="$stage" install
  )

  mkdir -- "$mpfr_build"
  (
    cd "$mpfr_build"
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
      CC="$cross_gcc --sysroot=$stage" AR="$cross_ar" LD="$cross_ld" \
      NM="$cross_nm" RANLIB="$cross_ranlib" \
      CPPFLAGS="-I$stage/usr/include" LDFLAGS="-L$stage/usr/lib" \
      CFLAGS="$target_cflags -std=gnu17" \
      "$source/mpfr/configure" --prefix=/usr --build="$build_triplet" \
        --host="$target" --with-gmp="$stage/usr" --disable-shared --enable-static
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" make -j"$jobs"
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" make DESTDIR="$stage" install
  )

  mkdir -- "$mpc_build"
  (
    cd "$mpc_build"
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
      CC="$cross_gcc --sysroot=$stage" AR="$cross_ar" LD="$cross_ld" \
      NM="$cross_nm" RANLIB="$cross_ranlib" \
      CPPFLAGS="-I$stage/usr/include" LDFLAGS="-L$stage/usr/lib" \
      CFLAGS="$target_cflags -std=gnu17" \
      "$source/mpc/configure" --prefix=/usr --build="$build_triplet" \
        --host="$target" --with-gmp="$stage/usr" --with-mpfr="$stage/usr" \
        --disable-shared --enable-static
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" make -j"$jobs"
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" make DESTDIR="$stage" install
  )

  mkdir -- "$binutils_build"
  (
    cd "$binutils_build"
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
      CC="$cross_gcc --sysroot=$stage" CXX="$cross_gxx --sysroot=$stage" \
      AR="$cross_ar" AS="$cross_as" LD="$cross_ld" NM="$cross_nm" \
      RANLIB="$cross_ranlib" CFLAGS="$target_cflags" CXXFLAGS="$target_cflags" \
      "$source/binutils/configure" --prefix=/usr --build="$build_triplet" \
        --host="$target" --target="$target" --with-sysroot=/ \
        --disable-multilib --disable-nls --disable-werror --disable-gprofng \
        --disable-gdb --disable-gdbserver --disable-sim --disable-shared \
        --enable-static --without-zstd --without-system-zlib
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" make -j"$jobs"
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" make DESTDIR="$stage" install
  )

  mkdir -- "$gcc_build"
  (
    cd "$gcc_build"
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
      CC="$cross_gcc --sysroot=$stage" CXX="$cross_gxx --sysroot=$stage" \
      AR="$cross_ar" AS="$cross_as" LD="$cross_ld" NM="$cross_nm" \
      RANLIB="$cross_ranlib" CFLAGS="$target_cflags" CXXFLAGS="$target_cflags" \
      CFLAGS_FOR_TARGET="$target_cflags" CXXFLAGS_FOR_TARGET="$target_cflags" \
      "$source/gcc/configure" --prefix=/usr --build="$build_triplet" \
        --host="$target" --target="$target" --with-sysroot=/ \
        --with-build-sysroot="$glibc_snapshot" \
        --with-native-system-header-dir=/usr/include \
        --with-build-time-tools="$binutils_prefix/$target/bin" \
        --with-gmp="$stage/usr" --with-mpfr="$stage/usr" --with-mpc="$stage/usr" \
        --with-glibc-version=2.44 --with-arch=x86-64-v2 --with-tune=generic \
        --with-static-standard-libraries --with-toolexeclibdir=/usr/lib \
        --with-slibdir=/usr/lib --enable-languages=c,c++ --disable-bootstrap \
        --disable-multilib --enable-shared --enable-threads=posix --disable-nls \
        --disable-werror --disable-lto --disable-fixincludes --without-isl \
        --without-zstd --disable-libgomp --disable-libitm --disable-libsanitizer \
        --disable-libquadmath --disable-libssp --disable-libvtv \
        --disable-libstdcxx-pch --disable-libstdcxx-debug \
        --disable-libstdcxx-debug-flags
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" make configure-gcc
    "$script_path" --internal-python rewrite-gcc-configargs \
      "$gcc_build/gcc/configargs.h" \
      "$canonical_build" "$canonical_guest_build" \
      "$glibc_snapshot" / \
      "$binutils_prefix" /usr \
      "$tools_prefix" /usr
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" make -j"$jobs" \
        all-gcc all-target-libgcc all-target-libatomic all-target-libstdc++-v3
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" make DESTDIR="$stage" \
        install-gcc install-target-libgcc install-target-libatomic \
        install-target-libstdc++-v3
  )

  mkdir -- "$make_build"
  (
    cd "$make_build"
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
      CC="$cross_gcc --sysroot=$stage" AR="$cross_ar" LD="$cross_ld" \
      NM="$cross_nm" RANLIB="$cross_ranlib" CFLAGS="$target_cflags -std=gnu17" \
      "$source/make/configure" --prefix=/usr --build="$build_triplet" \
        --host="$target" --disable-nls --without-guile
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" make -j"$jobs"
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" make DESTDIR="$stage" install
  )

  mkdir -- "$dropbear_build"
  install -m 0644 "$dropbear_options" "$source/dropbear/localoptions.h"
  "$script_path" --internal-python validate-dropbear-options \
    "$source/dropbear/localoptions.h" "$source/dropbear" \
    >"$evidence/dropbear-options.json"
  (
    cd "$dropbear_build"
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
      CC="$cross_gcc --sysroot=$stage" AR="$cross_ar" LD="$cross_ld" \
      NM="$cross_nm" RANLIB="$cross_ranlib" CFLAGS="$target_cflags" \
      "$source/dropbear/configure" --prefix=/usr --build="$build_triplet" \
        --host="$target" --enable-static --disable-zlib --disable-lastlog \
        --disable-utmp --disable-utmpx --disable-wtmp --disable-wtmpx \
        --disable-syslog --disable-shadow
    env -i PATH="$tools_prefix/bin:$binutils_prefix/bin:$PATH" LC_ALL=C TZ=UTC \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" make -j"$jobs" \
        PROGRAMS="dropbear dropbearkey" STATIC=1 MULTI=0
  )
  "$cross_nm" -A "$dropbear_build/dropbear" >"$evidence/dropbear.nm"
  if grep -Eqi 'svr_auth_password|pam_auth|auth_pam' "$evidence/dropbear.nm"; then
    echo "Dropbear binary retained password/PAM authentication symbols" >&2
    return 1
  fi
  if "$cross_readelf" -dW "$dropbear_build/dropbear" 2>/dev/null | grep -q NEEDED; then
    echo "Dropbear server is not static" >&2
    return 1
  fi
  if "$cross_readelf" -dW "$dropbear_build/dropbearkey" 2>/dev/null | grep -q NEEDED; then
    echo "Dropbear key generator is not static" >&2
    return 1
  fi
  install -D -m 0755 "$dropbear_build/dropbear" "$stage/usr/sbin/dropbear"
  install -D -m 0755 "$dropbear_build/dropbearkey" "$stage/usr/bin/dropbearkey"
  "$cross_strip" --strip-all "$stage/usr/sbin/dropbear" "$stage/usr/bin/dropbearkey"

  # Remove host-only libtool metadata, whose dependency_libs fields are both
  # non-relocatable and unnecessary for a package-build-capable seed.
  find "$stage" -type f -name '*.la' -delete

  cp -a -- "$base_root/." "$root/"
  cp -a -- "$stage/." "$root/"
  cp -a -- "$overlay/." "$root/"
  install -d -m 0755 "$root/build" "$root/usr/src/cajunos" \
    "$root/usr/share/licenses/cajunos"
  for component in linux glibc binutils gcc busybox dropbear make gmp mpfr mpc; do
    cp -a -- "$source/$component" "$root/usr/src/cajunos/$component"
  done
  install -d -m 0755 "$root/usr/src/cajunos/build-contract"
  python3 - "$root/usr/src/cajunos/dropbear" \
    "$root/usr/src/cajunos/build-contract/omitted-private-test-fixtures.json" <<'PY'
import hashlib, json
from pathlib import Path
import stat, sys
root, output = map(Path, sys.argv[1:])
expected = {
    "libtomcrypt/testprof/test.key": {
        "sha256": "76ec7faebdc42a4de35ca70024c2d273e9f7856ca61612e89f5f66350ba8cf5f",
        "kind": "pem-private-test-key",
    },
    "libtomcrypt/tests/test.key": {
        "sha256": "76ec7faebdc42a4de35ca70024c2d273e9f7856ca61612e89f5f66350ba8cf5f",
        "kind": "pem-private-test-key",
    },
    "libtomcrypt/tests/test_dsa.key": {
        "sha256": "8a44ced5b373b6124f56bb33577a98585cce3d65671e5303384c4236f9b4d41c",
        "kind": "pem-private-test-key",
    },
    "fuzz/fuzz-hostkeys.c": {
        "sha256": "0370305b5582f7375fc00e84ff80b49945cb04e93c401ed11194124b390ee92c",
        "kind": "embedded-private-host-key-fixture",
    },
}
records = []
for relative, contract in expected.items():
    path = root / relative
    metadata = path.lstat()
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if (
        not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
        or digest != contract["sha256"]
    ):
        raise SystemExit(f"locked private test fixture contract differs: {relative}")
    if contract["kind"] == "pem-private-test-key" and (
        not raw.startswith(b"-----BEGIN ")
        or b" PRIVATE KEY-----" not in raw.splitlines()[0]
    ):
        raise SystemExit(f"locked PEM private test fixture differs: {relative}")
    if contract["kind"] == "embedded-private-host-key-fixture" and not (
        b"static unsigned char keyr[]" in raw
        and b"static unsigned char keye[]" in raw
        and b"static unsigned char keyd[]" in raw
        and b"static unsigned char keyed25519[]" in raw
    ):
        raise SystemExit(f"locked embedded host-key fixture differs: {relative}")
    records.append({
        "path": relative, "sha256": digest, "kind": contract["kind"],
        "reason": "private-test-fixture-not-shipped",
    })
    path.unlink()
with output.open("w", encoding="utf-8", newline="\n") as stream:
    json.dump({"schema": 1, "omitted": records}, stream, indent=2, sort_keys=True)
    stream.write("\n")
output.chmod(0o644)
PY
  install -m 0644 "$bootstrap_lock" "$system_lock" "$native_lock" "$archive_lock" \
    "$base_busybox_fragment" "$native_busybox_fragment" "$dropbear_options" \
    "$root/usr/src/cajunos/build-contract/"
  install -D -m 0600 "$key_temporary" "$root/root/.ssh/authorized_keys"
  printf '%s\n' "$build_id" >"$root/etc/cajunos-build-id"
  printf '%s\n' "$root_guid" >"$root/etc/cajunos-root-partuuid"
  cat >"$root/boot/grub/grub.cfg" <<EOF
serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1
terminal_input serial
terminal_output serial
set timeout=0
set default=0
search --no-floppy --fs-uuid --set=root $root_uuid
menuentry 'CajunOS native developer seed' {
    linux /boot/vmlinuz-$kernel_release $positive_cmdline
}
EOF

  # Retain exact license inputs in-guest as well as in the artifact bundle.
  mkdir -p -- "$root/usr/share/licenses/cajunos/base-system"
  cp -a -- "$base_artifact/licenses/." "$root/usr/share/licenses/cajunos/base-system/"
  for component in make gmp mpfr mpc; do
    mkdir -p -- "$root/usr/share/licenses/cajunos/native/$component"
  done
  python3 - "$archive_manifest" "$archive_lock" "$archive_extract" \
    "$root/usr/share/licenses/cajunos/native" <<'PY'
import json, shutil, sys
from pathlib import Path
manifest_path, lock_path, extracted, output = map(Path, sys.argv[1:])
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
lock = json.loads(lock_path.read_text(encoding="utf-8"))
tops = {item["name"]: item["topology"]["top_level"] for item in lock["components"]}
for item in manifest["components"]:
    for relative in item["license_files"]:
        source = extracted / tops[item["name"]] / relative
        destination = output / item["name"] / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o644)
PY
  mkdir -p -- "$root/usr/share/licenses/cajunos/native/dropbear"
  install -m 0644 "$source/dropbear/LICENSE" \
    "$root/usr/share/licenses/cajunos/native/dropbear/LICENSE"

  "$script_path" --internal-python canonicalize-root "$root" \
    >"$evidence/rootfs.json"
  "$script_path" --internal-python validate-runtime-root "$root" \
    >"$evidence/runtime-root.json"
  "$script_path" --internal-python scan-forbidden "$root" \
    "$cajunos_root" "$canonical_build" /tmp/cc >/dev/null
  find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  "$script_path" --internal-python inventory "$root" >"$evidence/rootfs.json"

  mv -T -- "$root" "$temporary_root/root-$label"
  mv -T -- "$evidence" "$temporary_root/evidence-$label"
  rm -rf -- "$canonical_build"
}

validate_inputs
build_payload a
validate_inputs
build_payload b
cmp -- \
  "$temporary_root/root-a/usr/src/cajunos/build-contract/omitted-private-test-fixtures.json" \
  "$temporary_root/root-b/usr/src/cajunos/build-contract/omitted-private-test-fixtures.json"
"$script_path" --internal-python validate-omitted-private-fixtures \
  "$temporary_root/root-a/usr/src/cajunos/build-contract/omitted-private-test-fixtures.json" \
  >/dev/null
"$script_path" --internal-python validate-omitted-private-fixtures \
  "$temporary_root/root-b/usr/src/cajunos/build-contract/omitted-private-test-fixtures.json" \
  >/dev/null
"$script_path" --internal-python compare-json \
  "$temporary_root/evidence-a/rootfs.json" "$temporary_root/evidence-b/rootfs.json"
cmp -- "$temporary_root/root-a/bin/busybox" "$temporary_root/root-b/bin/busybox"
cmp -- "$temporary_root/root-a/usr/bin/gcc" "$temporary_root/root-b/usr/bin/gcc"
cmp -- "$temporary_root/root-a/usr/bin/g++" "$temporary_root/root-b/usr/bin/g++"
cmp -- "$temporary_root/root-a/usr/bin/make" "$temporary_root/root-b/usr/bin/make"
cmp -- "$temporary_root/root-a/usr/sbin/dropbear" "$temporary_root/root-b/usr/sbin/dropbear"

make_ext4() {
  local label=$1
  local root=$temporary_root/root-$label
  local image=$temporary_root/root-$label.ext4
  find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  truncate -s "$rootfs_bytes" "$image"
  fakeroot -- sh -ceu '
    chown -R 0:0 "$1"
    MKE2FS_CONFIG=/dev/null E2FSPROGS_FAKE_TIME="$2" /usr/sbin/mke2fs \
      -q -b 4096 -g 32768 -G 16 -i 16384 -I 256 -m 0 \
      -o linux -e continue -L CAJUNOS_ROOT -U "$3" \
      -E lazy_itable_init=0,root_owner=0:0,root_perms=0755,hash_seed="$4",nodiscard \
      -O "none,$6" -d "$1" "$5"
  ' sh "$root" "$SOURCE_DATE_EPOCH" "$root_uuid" "$root_hash_seed" \
    "$image" "$rootfs_features"
  MKE2FS_CONFIG=/dev/null E2FSPROGS_FAKE_TIME="$SOURCE_DATE_EPOCH" \
    /usr/sbin/tune2fs -j -J size=64 "$image" >/dev/null
  chmod 0644 "$image"
  "$script_path" --internal-python validate-ext4 \
    "$image" "$root_uuid" "$root_hash_seed" "$rootfs_bytes" \
    "$SOURCE_DATE_EPOCH" pristine \
    >"$temporary_root/evidence-$label/ext4.json"
}

make_disk() {
  local label=$1
  local disk=$temporary_root/disk-$label.raw
  cp --sparse=always -- "$base_disk" "$disk"
  truncate -s "$disk_bytes" "$disk"
  /usr/sbin/sgdisk --move-second-header -- "$disk" >/dev/null
  /usr/sbin/sgdisk --delete=2 \
    --new=2:"$root_first_sector":0 --typecode=2:8300 \
    --change-name=2:CAJUNOS-ROOT --partition-guid=2:"$root_guid" \
    -- "$disk" >/dev/null
  dd if="$temporary_root/root-$label.ext4" of="$disk" bs=512 \
    seek="$root_first_sector" conv=notrunc,sparse status=none
  chmod 0644 "$disk"
  "$base_helper" --internal-python validate-gpt \
    "$disk" "$disk_guid" "$bios_guid" "$root_guid" "$root_first_sector" \
    >"$temporary_root/evidence-$label/gpt.json"
  /usr/sbin/sgdisk --verify -- "$disk" >"$temporary_root/evidence-$label/sgdisk-verify.txt"
  "$script_path" --internal-python validate-grown-disk \
    "$base_disk" "$disk" "$rootfs_bytes" \
    >"$temporary_root/evidence-$label/grown-disk.json"
}

make_ext4 a
make_ext4 b
cmp -- "$temporary_root/root-a.ext4" "$temporary_root/root-b.ext4"
make_disk a
make_disk b
cmp -- "$temporary_root/disk-a.raw" "$temporary_root/disk-b.raw"
validate_inputs
run_qemu_probes

mkdir -p -- \
  "$artifact_temporary/boot" "$artifact_temporary/configuration" \
  "$artifact_temporary/licenses" "$artifact_temporary/probe"
cp --sparse=always -- "$temporary_root/disk-a.raw" \
  "$artifact_temporary/boot/disk.raw"
chmod 0644 "$artifact_temporary/boot/disk.raw"
install -m 0644 "$base_artifact/boot/bzImage" "$artifact_temporary/boot/bzImage"
install -m 0644 "$base_artifact/boot/kernel.config" \
  "$artifact_temporary/boot/kernel.config"
install -m 0644 "$temporary_root/evidence-a/busybox.config" \
  "$artifact_temporary/boot/busybox.config"
install -m 0644 "$temporary_root/root-a/boot/grub/grub.cfg" \
  "$artifact_temporary/boot/grub.cfg"

install -m 0644 "$temporary_root/evidence-a/rootfs.json" \
  "$artifact_temporary/configuration/rootfs-a.json"
install -m 0644 "$temporary_root/evidence-b/rootfs.json" \
  "$artifact_temporary/configuration/rootfs-b.json"
printf '%s\n' "$overlay_inventory" \
  >"$artifact_temporary/configuration/overlay.json"
chmod 0644 "$artifact_temporary/configuration/overlay.json"
install -m 0644 "$temporary_root/base-root.json" \
  "$artifact_temporary/configuration/base-root-inventory.json"
install -m 0644 "$temporary_root/base-root-foundation.json" \
  "$artifact_temporary/configuration/base-root-foundation.json"
install -m 0644 "$temporary_root/archive-sources.json" \
  "$artifact_temporary/configuration/archive-source-inventory.json"
install -m 0644 "$temporary_root/evidence-a/dropbear-options.json" \
  "$artifact_temporary/configuration/dropbear-options.json"
install -m 0644 "$temporary_root/evidence-a/dropbear.nm" \
  "$artifact_temporary/configuration/dropbear.nm"
install -m 0644 \
  "$temporary_root/root-a/usr/src/cajunos/build-contract/omitted-private-test-fixtures.json" \
  "$artifact_temporary/configuration/omitted-private-test-fixtures.json"
install -m 0644 "$base_busybox_fragment" "$native_busybox_fragment" \
  "$dropbear_options" "$artifact_temporary/configuration/"
install -m 0644 "$deployment_helper" \
  "$artifact_temporary/configuration/deployment-preparation.sh"
install -m 0644 "$key_temporary" \
  "$artifact_temporary/configuration/owner-authorized-key.pub"
python3 - "$artifact_temporary/configuration/build-contract.json" \
  "$build_triplet" "$target" "$canonical_guest_build" "$disk_bytes" \
  "$rootfs_bytes" "$owner_key_fingerprint" <<'PY'
import json, sys
path, build, host_target, canonical, disk_bytes, rootfs_bytes, fingerprint = sys.argv[1:]
value = {
    "schema": 1,
    "canadian_cross": {"build": build, "host": host_target, "target": host_target},
    "canonical_build_path": canonical,
    "disk_bytes": int(disk_bytes), "rootfs_bytes": int(rootfs_bytes),
    "package_capability": "native-package-build-capable-seed-not-full-self-host",
    "owner_key_fingerprint": fingerprint,
    "template_source": "pristine-never-booted-artifact-only",
}
with open(path, "w", encoding="utf-8", newline="\n") as stream:
    json.dump(value, stream, indent=2, sort_keys=True); stream.write("\n")
PY
chmod 0644 "$artifact_temporary/configuration/build-contract.json"

cp -a -- "$temporary_root/root-a/usr/share/licenses/cajunos/." \
  "$artifact_temporary/licenses/"
cp -a -- "$temporary_root/qemu-evidence/." "$artifact_temporary/probe/"
cp -a -- "$temporary_root/owner-proof-evidence/." "$artifact_temporary/probe/"
install -m 0644 "$temporary_root/ssh-evidence.json" \
  "$artifact_temporary/probe/ssh-evidence.json"
find "$artifact_temporary" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

# No disposable probe secret, generated host private key, or owner signing
# authority may cross this publication boundary.
"$script_path" --internal-python scan-private-material "$temporary_root/root-a" \
  >/dev/null
"$script_path" --internal-python scan-private-material "$temporary_root/root-b" \
  >/dev/null
"$script_path" --internal-python scan-private-material "$artifact_temporary" \
  >/dev/null

export CAJUNOS_NATIVE_RECEIPT_SCRIPT=$script_path
export CAJUNOS_NATIVE_RECEIPT_BUILD_ID=$build_id
export CAJUNOS_NATIVE_RECEIPT_BASE_ID=$base_build_id
export CAJUNOS_NATIVE_RECEIPT_BASE_RECEIPT=$base_receipt
export CAJUNOS_NATIVE_RECEIPT_BASE_RECEIPT_SHA256=$base_receipt_sha256
export CAJUNOS_NATIVE_RECEIPT_BASE_DISK_SHA256=$base_disk_sha256
export CAJUNOS_NATIVE_RECEIPT_BOOTSTRAP_DIGEST=$bootstrap_digest
export CAJUNOS_NATIVE_RECEIPT_BOOTSTRAP_AUTH=$bootstrap_auth
export CAJUNOS_NATIVE_RECEIPT_SYSTEM_DIGEST=$system_digest
export CAJUNOS_NATIVE_RECEIPT_SYSTEM_AUTH=$system_auth
export CAJUNOS_NATIVE_RECEIPT_GIT_DIGEST=$native_digest
export CAJUNOS_NATIVE_RECEIPT_GIT_AUTH=$native_auth
export CAJUNOS_NATIVE_RECEIPT_ARCHIVE_DIGEST=$archive_digest
export CAJUNOS_NATIVE_RECEIPT_ARCHIVE_AUTH=$archive_auth
export CAJUNOS_NATIVE_RECEIPT_EPOCH=$SOURCE_DATE_EPOCH
export CAJUNOS_NATIVE_RECEIPT_ORCHESTRATION_COMMIT=$orchestration_commit
export CAJUNOS_NATIVE_RECEIPT_ORCHESTRATION_TREE=$orchestration_tree
export CAJUNOS_NATIVE_RECEIPT_RECIPE_SHA256=$recipe_sha256
export CAJUNOS_NATIVE_RECEIPT_DEPLOYMENT_HELPER_SHA256=$deployment_helper_sha256
export CAJUNOS_NATIVE_RECEIPT_OVERLAY_DIGEST=$overlay_digest
export CAJUNOS_NATIVE_RECEIPT_HOST_CONTRACT=$host_contract_sha256
export CAJUNOS_NATIVE_RECEIPT_DISK_SHA256=$sealed_disk_sha256
export CAJUNOS_NATIVE_RECEIPT_DISK_GUID=$disk_guid
export CAJUNOS_NATIVE_RECEIPT_BIOS_GUID=$bios_guid
export CAJUNOS_NATIVE_RECEIPT_ROOT_GUID=$root_guid
export CAJUNOS_NATIVE_RECEIPT_ROOT_UUID=$root_uuid
export CAJUNOS_NATIVE_RECEIPT_OWNER_FINGERPRINT=$owner_key_fingerprint
export CAJUNOS_NATIVE_RECEIPT_OWNER_INPUT_SHA256=$owner_key_input_sha256
export CAJUNOS_NATIVE_RECEIPT_OWNER_CANONICAL_SHA256=$owner_key_canonical_sha256
export CAJUNOS_NATIVE_RECEIPT_QEMU_PATH=$qemu_path
export CAJUNOS_NATIVE_RECEIPT_QEMU_SHA256=$qemu_sha256
export CAJUNOS_NATIVE_RECEIPT_QEMU_IMG_PATH=$qemu_img_path
export CAJUNOS_NATIVE_RECEIPT_QEMU_IMG_SHA256=$qemu_img_sha256
export CAJUNOS_NATIVE_RECEIPT_QEMU_BIOS=$qemu_bios
export CAJUNOS_NATIVE_RECEIPT_QEMU_BIOS_SHA256=$qemu_bios_sha256
export CAJUNOS_NATIVE_RECEIPT_KERNEL_VERSION=$kernel_version
export CAJUNOS_NATIVE_RECEIPT_KERNEL_RELEASE=$kernel_release
export CAJUNOS_NATIVE_RECEIPT_POSITIVE_CMDLINE=$positive_cmdline
export CAJUNOS_NATIVE_RECEIPT_NEGATIVE_CMDLINE=$negative_cmdline
export CAJUNOS_NATIVE_RECEIPT_PROBE_NONCE=$probe_nonce
export CAJUNOS_NATIVE_RECEIPT_PROBE_HOST_SHA256=$first_a_host_key_sha256
export CAJUNOS_NATIVE_RECEIPT_OWNER_HOST_SHA256=$owner_host_key_sha256
export CAJUNOS_NATIVE_RECEIPT_ARTIFACT=$artifact_temporary
export CAJUNOS_NATIVE_RECEIPT_TOOLS_ID=$tools_build_id
export CAJUNOS_NATIVE_RECEIPT_TOOLS_PREFIX=$tools_prefix
export CAJUNOS_NATIVE_RECEIPT_GLIBC_ID=$glibc_build_id
export CAJUNOS_NATIVE_RECEIPT_GLIBC_SNAPSHOT=$glibc_snapshot

python3 - "$bootstrap_lock" "$system_lock" "$native_lock" "$archive_lock" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

e = os.environ
artifact = Path(e["CAJUNOS_NATIVE_RECEIPT_ARTIFACT"])
script = Path(e["CAJUNOS_NATIVE_RECEIPT_SCRIPT"])

def load(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)

def components(lock):
    return {item["name"]: item for item in lock["components"]}

bootstrap, system, native, archives = map(load, sys.argv[1:])
b = components(bootstrap); s = components(system); n = components(native)
a = {item["name"]: item for item in archives["components"]}
ssh_evidence = load(artifact / "probe/ssh-evidence.json")
omission_manifest = artifact / "configuration/omitted-private-test-fixtures.json"
omissions = load(omission_manifest)
receipt = {
    "schema": 1,
    "component": "system-image",
    "stage": "native-developer-seed",
    "build_id": e["CAJUNOS_NATIVE_RECEIPT_BUILD_ID"],
    "deployable": True,
    "diagnostic_only": False,
    "target": "x86_64-cajunos-linux-gnu",
    "source_date_epoch": int(e["CAJUNOS_NATIVE_RECEIPT_EPOCH"]),
    "base_system": {
        "build_id": e["CAJUNOS_NATIVE_RECEIPT_BASE_ID"],
        "receipt": e["CAJUNOS_NATIVE_RECEIPT_BASE_RECEIPT"],
        "receipt_sha256": e["CAJUNOS_NATIVE_RECEIPT_BASE_RECEIPT_SHA256"],
        "disk_sha256": e["CAJUNOS_NATIVE_RECEIPT_BASE_DISK_SHA256"],
        "consumption": "explicit-validated-receipt-artifact-and-root-inventory",
    },
    "source_sets": {
        "bootstrap": {"digest": e["CAJUNOS_NATIVE_RECEIPT_BOOTSTRAP_DIGEST"], "authentication": e["CAJUNOS_NATIVE_RECEIPT_BOOTSTRAP_AUTH"]},
        "base_system": {"digest": e["CAJUNOS_NATIVE_RECEIPT_SYSTEM_DIGEST"], "authentication": e["CAJUNOS_NATIVE_RECEIPT_SYSTEM_AUTH"]},
        "native_git": {"digest": e["CAJUNOS_NATIVE_RECEIPT_GIT_DIGEST"], "authentication": e["CAJUNOS_NATIVE_RECEIPT_GIT_AUTH"]},
        "native_archives": {"digest": e["CAJUNOS_NATIVE_RECEIPT_ARCHIVE_DIGEST"], "authentication": e["CAJUNOS_NATIVE_RECEIPT_ARCHIVE_AUTH"]},
    },
    "sources": {
        name: {key: value[key] for key in ("commit", "tree", "repository")}
        for name, value in {**b, **s, **n}.items()
    } | {
        name: {
            "version": value["version"],
            "archive_sha256": value["archive"]["sha256"],
            "signature_sha256": value["signature"]["sha256"],
        }
        for name, value in a.items()
    },
    "orchestration": {
        "commit": e["CAJUNOS_NATIVE_RECEIPT_ORCHESTRATION_COMMIT"],
        "tree": e["CAJUNOS_NATIVE_RECEIPT_ORCHESTRATION_TREE"],
        "recipe_sha256": e["CAJUNOS_NATIVE_RECEIPT_RECIPE_SHA256"],
        "overlay_digest": e["CAJUNOS_NATIVE_RECEIPT_OVERLAY_DIGEST"],
        "deployment_helper_sha256": e["CAJUNOS_NATIVE_RECEIPT_DEPLOYMENT_HELPER_SHA256"],
    },
    "dependencies": {
        "sealed_cross_gcc": {"build_id": e["CAJUNOS_NATIVE_RECEIPT_TOOLS_ID"], "prefix": e["CAJUNOS_NATIVE_RECEIPT_TOOLS_PREFIX"]},
        "sealed_glibc": {"build_id": e["CAJUNOS_NATIVE_RECEIPT_GLIBC_ID"], "snapshot": e["CAJUNOS_NATIVE_RECEIPT_GLIBC_SNAPSHOT"]},
    },
    "kernel": {
        "version": e["CAJUNOS_NATIVE_RECEIPT_KERNEL_VERSION"],
        "release": e["CAJUNOS_NATIVE_RECEIPT_KERNEL_RELEASE"],
        "root_selector": "PARTUUID", "unix98_ptys": True, "devpts": True,
    },
    "bootloader": {
        "name": "GRUB", "platform": "i386-pc", "firmware": "SeaBIOS",
        "inheritance": "Stage-9A-MBR-and-BIOS-partition-byte-preserved",
    },
    "filesystem": {
        "type": "ext4", "bytes": 12 * 1024**3,
        "uuid": e["CAJUNOS_NATIVE_RECEIPT_ROOT_UUID"],
        "journal": True, "state": "clean", "forced_fsck": True,
        "directory_hash_seed": "4a696d42-6f75-4769-8f73-43616a756e21",
    },
    "disk": {
        "format": "raw-gpt-bios", "bytes": 16 * 1024**3,
        "sha256": e["CAJUNOS_NATIVE_RECEIPT_DISK_SHA256"],
        "guid": e["CAJUNOS_NATIVE_RECEIPT_DISK_GUID"],
        "bios_boot_partuuid": e["CAJUNOS_NATIVE_RECEIPT_BIOS_GUID"],
        "root_partuuid": e["CAJUNOS_NATIVE_RECEIPT_ROOT_GUID"],
        "root_filesystem_bytes": 12 * 1024**3,
        "in_partition_growth_reserve_bytes": 4 * 1024**3 - 4129 * 512,
    },
    "network": {
        "driver": "virtio-net", "interface": "eth0",
        "configuration": "dhcpv4-default-static-file-optional",
        "serial_discovery": "CAJUNOS_NATIVE_DEVELOPER_IPV4-canonical-ipv4",
        "resolver_probe": "loopback-udp-dns-getaddrinfo-no-egress",
    },
    "owner_ssh_key": {
        "algorithm": "ssh-ed25519",
        "fingerprint": e["CAJUNOS_NATIVE_RECEIPT_OWNER_FINGERPRINT"],
        "input_sha256": e["CAJUNOS_NATIVE_RECEIPT_OWNER_INPUT_SHA256"],
        "canonical_sha256": e["CAJUNOS_NATIVE_RECEIPT_OWNER_CANONICAL_SHA256"],
        "authorized_keys_path": "/root/.ssh/authorized_keys",
        "private_key_on_forge": False,
        "agent_forwarded_to_forge": False,
        "possession_proof": "trusted-tunnel-publickey-plus-sshsig",
        "signature_namespace": "cajunos-native-developer-owner-proof",
    },
    "security_contract": {
        "root_password": "locked", "ssh": "static-dropbear-key-only",
        "password_auth_code": "compiled-out", "pam_auth_code": "compiled-out",
        "forwarding": "compiled-out", "sftp": "compiled-out",
        "inetd": "compiled-out", "pubkey_options": "compiled-out",
        "host_key": "first-boot-atomic-ed25519-never-sealed",
        "authentication_logging": "foreground-stderr-to-serial-console",
        "qemu_network": "usernet-restrict-on-loopback-hostfwd-no-egress",
    },
    "native_toolchain": {
        "build": "x86_64-pc-linux-gnu", "host": "x86_64-cajunos-linux-gnu",
        "target": "x86_64-cajunos-linux-gnu",
        "components": ["binutils", "gcc", "g++", "libgcc", "libatomic", "libstdc++", "make", "gmp", "mpfr", "mpc"],
        "resident_sources": True,
        "source_sanitization": {
            "policy": "three-standalone-pem-plus-one-embedded-host-key-fixture-omitted-public-crypto-c-vectors-source-bound",
            "manifest_sha256": hashlib.sha256(omission_manifest.read_bytes()).hexdigest(),
            "records": omissions["omitted"],
        },
        "capability": "package-build-capable-not-full-self-host",
    },
    "qemu": {
        "path": e["CAJUNOS_NATIVE_RECEIPT_QEMU_PATH"],
        "sha256": e["CAJUNOS_NATIVE_RECEIPT_QEMU_SHA256"],
        "qemu_img_path": e["CAJUNOS_NATIVE_RECEIPT_QEMU_IMG_PATH"],
        "qemu_img_sha256": e["CAJUNOS_NATIVE_RECEIPT_QEMU_IMG_SHA256"],
        "machine": "pc-q35-10.0", "accelerator": "tcg", "cpu": "Nehalem-v1",
        "firmware": {"path": e["CAJUNOS_NATIVE_RECEIPT_QEMU_BIOS"], "sha256": e["CAJUNOS_NATIVE_RECEIPT_QEMU_BIOS_SHA256"]},
        "positive_cmdline": e["CAJUNOS_NATIVE_RECEIPT_POSITIVE_CMDLINE"],
        "negative_cmdline": e["CAJUNOS_NATIVE_RECEIPT_NEGATIVE_CMDLINE"],
        "negative_boot": "exact-cmdline-token-fail-closed",
        "persistence_nonce": e["CAJUNOS_NATIVE_RECEIPT_PROBE_NONCE"],
        "host_key_sha256": e["CAJUNOS_NATIVE_RECEIPT_PROBE_HOST_SHA256"],
        "owner_proof_host_key_sha256": e["CAJUNOS_NATIVE_RECEIPT_OWNER_HOST_SHA256"],
        "post_shutdown_forced_fsck": True,
    },
    "build_contract": {
        "independent_builds": 2,
        "host_contract_sha256": e["CAJUNOS_NATIVE_RECEIPT_HOST_CONTRACT"],
        "rootfs_population": "fakeroot-mke2fs-d",
        "rootfs_hash_seed_locked": True,
        "canonical_build_path_reused_sequentially": True,
        "private_key_inputs": False,
    },
    "template_contract": {
        "source": "pristine-never-booted-stage9b-artifact-only",
        "booted_validation_disk_forbidden": True,
        "reason": "deleted-host-private-key-blocks-remain-forensically-recoverable",
        "independent_clone_host_keys_differ": True,
        "deployment_and_vm118_template": "later-milestone",
    },
    "reproducibility": {
        "independent_builds": 2,
        "native_payload_identical": True, "rootfs_inventory_identical": True,
        "rootfs_ext4_identical": True, "gpt_disk_identical": True,
        "base_disk_immutable_after_probes": True, "selectors_modified": False,
        "rootfs_inventory": load(artifact / "configuration/rootfs-a.json"),
    },
    "probe_summary": ssh_evidence,
}

def inventory(path):
    return json.loads(subprocess.run(
        [script, "--internal-python", "inventory", path], check=True,
        text=True, stdout=subprocess.PIPE,
    ).stdout)

receipt["outputs"] = {"subtree_inventories": {
    name: inventory(artifact / name)
    for name in ("boot", "configuration", "licenses", "probe")
}}
with (artifact / "receipt.json").open("w", encoding="utf-8", newline="\n") as stream:
    json.dump(receipt, stream, indent=2, sort_keys=True); stream.write("\n")
(artifact / "receipt.json").chmod(0o644)
PY
validate_candidate() {
  local artifact=$1 build=$2
  cmp -- "$artifact/configuration/archive-source-inventory.json" \
    "$build/archive-sources.json"
  cmp -- "$artifact/configuration/base-root-inventory.json" \
    "$build/base-root.json"
  cmp -- "$artifact/configuration/base-root-foundation.json" \
    "$build/base-root-foundation.json"
  cmp -- "$build/root-a.ext4" "$build/root-b.ext4"
  cmp -- "$build/disk-a.raw" "$build/disk-b.raw"
  cmp -- "$artifact/boot/disk.raw" "$build/disk-a.raw"
  cmp -- "$artifact/boot/bzImage" "$base_artifact/boot/bzImage"
  cmp -- "$artifact/boot/busybox.config" "$build/evidence-a/busybox.config"
  cmp -- "$artifact/configuration/deployment-preparation.sh" "$deployment_helper"
  validate_stage9b_receipt_contract "$artifact/receipt.json" "$artifact"
  "$base_helper" --internal-python validate-gpt \
    "$artifact/boot/disk.raw" "$disk_guid" "$bios_guid" \
    "$root_guid" "$root_first_sector" >/dev/null
  "$script_path" --internal-python validate-grown-disk \
    "$base_disk" "$artifact/boot/disk.raw" "$rootfs_bytes" >/dev/null
  "$script_path" --internal-python validate-ext4 \
    "$build/root-a.ext4" "$root_uuid" "$root_hash_seed" "$rootfs_bytes" \
    "$SOURCE_DATE_EPOCH" pristine \
    >/dev/null
  "$script_path" --internal-python validate-ext4 \
    "$build/root-b.ext4" "$root_uuid" "$root_hash_seed" "$rootfs_bytes" \
    "$SOURCE_DATE_EPOCH" pristine \
    >/dev/null
  "$script_path" --internal-python validate-runtime-root "$build/root-a" >/dev/null
  "$script_path" --internal-python validate-runtime-root "$build/root-b" >/dev/null
  cmp -- "$artifact/configuration/omitted-private-test-fixtures.json" \
    "$build/root-a/usr/src/cajunos/build-contract/omitted-private-test-fixtures.json"
  cmp -- "$artifact/configuration/omitted-private-test-fixtures.json" \
    "$build/root-b/usr/src/cajunos/build-contract/omitted-private-test-fixtures.json"
  "$script_path" --internal-python validate-omitted-private-fixtures \
    "$artifact/configuration/omitted-private-test-fixtures.json" >/dev/null
  "$script_path" --internal-python inventory "$build/root-a" \
    >"$probe_root/validate-root-a.json"
  "$script_path" --internal-python inventory "$build/root-b" \
    >"$probe_root/validate-root-b.json"
  "$script_path" --internal-python compare-json \
    "$artifact/configuration/rootfs-a.json" "$probe_root/validate-root-a.json"
  "$script_path" --internal-python compare-json \
    "$artifact/configuration/rootfs-b.json" "$probe_root/validate-root-b.json"
  "$script_path" --internal-python validate-busybox-config \
    "$artifact/boot/busybox.config" >/dev/null
  grep -qx 'CONFIG_UNIX98_PTYS=y' "$artifact/boot/kernel.config"
  "$script_path" --internal-python validate-serial positive \
    "$artifact/probe/first-a.serial.raw" "$kernel_release" "$build_id" >/dev/null
  "$script_path" --internal-python validate-serial positive \
    "$artifact/probe/second-a.serial.raw" "$kernel_release" "$build_id" >/dev/null
  "$script_path" --internal-python validate-serial positive \
    "$artifact/probe/first-b.serial.raw" "$kernel_release" "$build_id" >/dev/null
  "$script_path" --internal-python validate-serial negative \
    "$artifact/probe/negative.serial.raw" "$kernel_release" "$build_id" \
    "$probe_root/candidate-negative.serial.normalized" >/dev/null
  cmp -- "$artifact/probe/negative.serial.normalized" \
    "$probe_root/candidate-negative.serial.normalized"
  local ssh_nonce ssh_host_hash
  read -r ssh_nonce ssh_host_hash < <(python3 - "$artifact/receipt.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    value = json.load(stream)
print(value["qemu"]["persistence_nonce"], value["qemu"]["host_key_sha256"])
PY
  )
  "$script_path" --internal-python validate-ssh-evidence \
    "$artifact/probe/ssh-evidence.json" "$build_id" "$ssh_nonce" \
    "$ssh_host_hash" >/dev/null
  validate_stored_owner_proof "$artifact" "$probe_root/candidate-owner"
  "$script_path" --internal-python scan-private-material "$build/root-a" >/dev/null
  "$script_path" --internal-python scan-private-material "$build/root-b" >/dev/null
  "$script_path" --internal-python scan-private-material "$artifact" >/dev/null
  [[ $(sha256sum "$artifact/boot/disk.raw" | awk '{print $1}') == "$sealed_disk_sha256" ]]

  # Replay the on-disk ext4 payload against the pre-mke2fs root inventory.
  local replay_ext4=$probe_root/candidate.ext4
  local replay_root=$probe_root/candidate-root
  truncate -s "$rootfs_bytes" "$replay_ext4"
  dd if="$artifact/boot/disk.raw" of="$replay_ext4" bs=512 \
    skip="$root_first_sector" count=$((rootfs_bytes / 512)) \
    conv=sparse,notrunc status=none
  cmp -- "$replay_ext4" "$build/root-a.ext4"
  mkdir -- "$replay_root"
  /usr/sbin/debugfs -R "rdump / $replay_root" "$replay_ext4" >/dev/null 2>&1
  "$script_path" --internal-python inventory "$replay_root" \
    >"$probe_root/candidate-root.json"
  "$script_path" --internal-python compare-json \
    "$artifact/configuration/rootfs-a.json" "$probe_root/candidate-root.json"
}

validate_inputs
validate_candidate "$artifact_temporary" "$temporary_root"
published=1
mv -T -- "$temporary_root" "$build_final"
mv -T -- "$artifact_temporary" "$artifact_final"
validate_existing_result
published=0
trap - EXIT INT TERM HUP
rm -rf -- "$archive_extract" "$base_extract" "$probe_root" "$owner_exchange"
rm -- "$key_temporary"
echo "CAJUNOS_NATIVE_DEVELOPER_COMPLETE build_id=$build_id"
