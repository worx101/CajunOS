#!/usr/bin/env python3
"""Fetch and authenticate the locked Stage 9B release archives.

This program deliberately does not use a user keyring, GnuPG configuration,
keyserver, or automatic key retrieval.  Every network object, signer field,
archive member, and verifier binary is part of the committed lock contract.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any
from urllib.parse import urlsplit


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = PROJECT_ROOT / "manifests/native-developer-archives.json"
DEFAULT_LOCK = PROJECT_ROOT / "locks/native-developer-archives.lock.json"
COMPONENT_NAMES = ("make", "gmp", "mpfr", "mpc")
HEX256 = re.compile(r"^[0-9a-f]{64}$")
HEX512 = re.compile(r"^[0-9a-f]{128}$")
FINGERPRINT = re.compile(r"^[0-9A-F]{40}$")
SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
FORBIDDEN_STATUS = {
    "BADSIG", "ERRSIG", "NO_PUBKEY", "NODATA", "REVKEYSIG",
    "KEYREVOKED", "BADARMOR", "FAILURE", "ERROR", "UNEXPECTED",
}


class ArchiveError(RuntimeError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, json.JSONDecodeError) as error:
        raise ArchiveError(f"cannot read JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise ArchiveError(f"expected an object in {path}")
    return value


def hash_file(path: Path, algorithm: str) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def require_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ArchiveError(f"{label} keys differ (missing={missing}, extra={extra})")


def require_https(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ArchiveError(f"{label} is not a string")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https" or not parsed.hostname
        or parsed.username is not None or parsed.password is not None
        or parsed.fragment
    ):
        raise ArchiveError(f"{label} is not a credential-free HTTPS URL")
    return value


def require_safe_relative(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\0" in value:
        raise ArchiveError(f"{label} is unsafe")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ArchiveError(f"{label} is unsafe")
    return value


def validate_lock(
    manifest: dict[str, Any], manifest_path: Path, lock: dict[str, Any]
) -> list[dict[str, Any]]:
    require_keys(manifest, {"schema", "selection", "components"}, "manifest")
    if (
        manifest["schema"] != 1
        or manifest["selection"] != "authenticated-signed-release-archives"
    ):
        raise ArchiveError("unsupported archive manifest identity")
    declared = manifest["components"]
    if not isinstance(declared, list) or len(declared) != len(COMPONENT_NAMES):
        raise ArchiveError("archive manifest component count differs")
    declared_by_name: dict[str, dict[str, Any]] = {}
    for item in declared:
        if not isinstance(item, dict):
            raise ArchiveError("manifest component is not an object")
        require_keys(
            item,
            {
                "name", "version", "project", "archive_url", "signature_url",
                "key_url", "license_files",
            },
            "manifest component",
        )
        name = item["name"]
        if name not in COMPONENT_NAMES or name in declared_by_name:
            raise ArchiveError(f"invalid or duplicate manifest component: {name!r}")
        if not isinstance(item["version"], str) or not item["version"]:
            raise ArchiveError(f"invalid version for {name}")
        for field in ("project", "archive_url", "signature_url", "key_url"):
            require_https(item[field], f"{name}.{field}")
        licenses = item["license_files"]
        if not isinstance(licenses, list) or not licenses:
            raise ArchiveError(f"missing license paths for {name}")
        for path in licenses:
            require_safe_relative(path, f"{name} license path")
        declared_by_name[name] = item

    require_keys(
        lock,
        {
            "schema", "selection", "manifest", "manifest_sha256", "generated_at",
            "source_authentication", "source_set_digest", "components", "verifier",
        },
        "archive lock",
    )
    if (
        lock["schema"] != 1
        or lock["selection"] != manifest["selection"]
        or lock["manifest"] != "manifests/native-developer-archives.json"
        or lock["source_authentication"]
        != "authenticated-https-plus-detached-openpgp"
    ):
        raise ArchiveError("archive lock identity differs")
    manifest_digest = "sha256:" + hash_file(manifest_path, "sha256")
    if lock["manifest_sha256"] != manifest_digest:
        raise ArchiveError("archive lock does not match its manifest")

    components = lock["components"]
    if not isinstance(components, list) or len(components) != len(COMPONENT_NAMES):
        raise ArchiveError("archive lock component count differs")
    locked_by_name: dict[str, dict[str, Any]] = {}
    for item in components:
        if not isinstance(item, dict):
            raise ArchiveError("locked component is not an object")
        base_keys = {
            "name", "version", "archive", "signature", "key", "topology", "licenses",
        }
        name = item.get("name")
        if name in {"gmp", "mpfr", "mpc"}:
            base_keys.add("gcc_prerequisite_sha512")
        require_keys(item, base_keys, f"locked component {name}")
        if name not in COMPONENT_NAMES or name in locked_by_name:
            raise ArchiveError(f"invalid or duplicate locked component: {name!r}")
        declared_item = declared_by_name[name]
        if item["version"] != declared_item["version"]:
            raise ArchiveError(f"version differs for {name}")

        for kind, url_field in (
            ("archive", "archive_url"), ("signature", "signature_url"), ("key", "key_url")
        ):
            value = item[kind]
            if not isinstance(value, dict):
                raise ArchiveError(f"{name}.{kind} is not an object")
            if value.get("url") != declared_item[url_field]:
                raise ArchiveError(f"{name}.{kind} URL differs from manifest")
            require_https(value.get("url"), f"{name}.{kind}.url")
            filename = value.get("filename")
            if not isinstance(filename, str) or not SAFE_FILENAME.fullmatch(filename):
                raise ArchiveError(f"unsafe object filename for {name}.{kind}")
            byte_count = value.get("bytes")
            if not isinstance(byte_count, int) or byte_count <= 0 or byte_count > 32_000_000:
                raise ArchiveError(f"unsafe byte count for {name}.{kind}")
            if not HEX256.fullmatch(str(value.get("sha256", ""))):
                raise ArchiveError(f"invalid SHA-256 for {name}.{kind}")
            if not HEX512.fullmatch(str(value.get("sha512", ""))):
                raise ArchiveError(f"invalid SHA-512 for {name}.{kind}")

        archive = item["archive"]
        require_keys(archive, {"url", "filename", "bytes", "sha256", "sha512"}, f"{name}.archive")
        signature = item["signature"]
        signature_keys = {
            "url", "filename", "bytes", "sha256", "sha512", "signer_fingerprint",
            "primary_fingerprint", "signing_epoch", "public_key_algorithm",
            "hash_algorithm",
        }
        if name == "mpc":
            signature_keys.add("historical_expiry")
        require_keys(signature, signature_keys, f"{name}.signature")
        key = item["key"]
        require_keys(
            key,
            {
                "url", "filename", "bytes", "sha256", "sha512", "armored",
                "derived_keyring_sha256",
            },
            f"{name}.key",
        )
        if not isinstance(key["armored"], bool) or not HEX256.fullmatch(
            str(key["derived_keyring_sha256"])
        ):
            raise ArchiveError(f"invalid key format contract for {name}")
        for field in ("signer_fingerprint", "primary_fingerprint"):
            if not FINGERPRINT.fullmatch(str(signature[field])):
                raise ArchiveError(f"invalid {field} for {name}")
        for field in ("signing_epoch", "public_key_algorithm", "hash_algorithm"):
            if not isinstance(signature[field], int) or signature[field] <= 0:
                raise ArchiveError(f"invalid {field} for {name}")

        if name == "mpc":
            expiry = signature["historical_expiry"]
            require_keys(
                expiry, {"allowed", "expiry_epoch", "signer_fingerprint"},
                "mpc historical expiry",
            )
            if (
                expiry["allowed"] is not True
                or expiry["signer_fingerprint"] != signature["signer_fingerprint"]
                or not isinstance(expiry["expiry_epoch"], int)
                or not signature["signing_epoch"] < expiry["expiry_epoch"]
            ):
                raise ArchiveError("MPC historical-expiry exception is not narrow")

        topology = item["topology"]
        require_keys(
            topology,
            {
                "top_level", "members", "directories", "files", "links",
                "declared_bytes", "member_digest",
            },
            f"{name}.topology",
        )
        if (
            not isinstance(topology["top_level"], str)
            or not SAFE_FILENAME.fullmatch(topology["top_level"])
            or topology["links"] != 0
            or topology["members"] != topology["directories"] + topology["files"]
            or any(
                not isinstance(topology[field], int) or topology[field] < 0
                for field in ("members", "directories", "files", "links", "declared_bytes")
            )
            or not HEX256.fullmatch(str(topology["member_digest"]))
        ):
            raise ArchiveError(f"invalid topology contract for {name}")
        licenses = item["licenses"]
        if not isinstance(licenses, dict) or not licenses:
            raise ArchiveError(f"missing license hashes for {name}")
        if set(licenses) != set(declared_item["license_files"]):
            raise ArchiveError(f"manifest and lock license sets differ for {name}")
        for path, digest in licenses.items():
            require_safe_relative(path, f"{name} locked license path")
            if not HEX256.fullmatch(str(digest)):
                raise ArchiveError(f"invalid locked license hash for {name}:{path}")
        if name in {"gmp", "mpfr", "mpc"} and (
            item["gcc_prerequisite_sha512"] != archive["sha512"]
        ):
            raise ArchiveError(f"GCC prerequisite hash differs for {name}")
        locked_by_name[name] = item

    verifier = lock["verifier"]
    require_keys(
        verifier, {"executable", "libraries", "libgcrypt_version"}, "verifier"
    )
    require_keys(verifier["executable"], {"sha256", "version_line"}, "verifier executable")
    if (
        not HEX256.fullmatch(str(verifier["executable"]["sha256"]))
        or verifier["executable"]["version_line"] != "gpgv (GnuPG) 2.4.7"
        or verifier["libgcrypt_version"] != "libgcrypt 1.11.0"
    ):
        raise ArchiveError("verifier executable contract differs")
    libraries = verifier["libraries"]
    if not isinstance(libraries, list) or len(libraries) != 2:
        raise ArchiveError("verifier library contract differs")
    seen_libraries: set[str] = set()
    for library in libraries:
        require_keys(library, {"filename", "soname", "sha256"}, "verifier library")
        filename = library["filename"]
        soname = library["soname"]
        if (
            not isinstance(filename, str) or not SAFE_FILENAME.fullmatch(filename)
            or not isinstance(soname, str) or not SAFE_FILENAME.fullmatch(soname)
            or filename == soname or filename in seen_libraries or soname in seen_libraries
            or not HEX256.fullmatch(str(library["sha256"]))
        ):
            raise ArchiveError("invalid verifier library entry")
        seen_libraries.update((filename, soname))
    if seen_libraries != {
        "libgcrypt.so.20", "libgcrypt.so.20.5.0",
        "libgpg-error.so.0", "libgpg-error.so.0.38.0",
    }:
        raise ArchiveError("verifier library SONAME contract differs")

    calculated = "sha256:" + canonical_digest(
        {"components": components, "verifier": verifier}
    )
    if lock["source_set_digest"] != calculated:
        raise ArchiveError("archive source-set digest differs")
    return [locked_by_name[name] for name in COMPONENT_NAMES]


def validate_object(path: Path, contract: dict[str, Any], label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ArchiveError(f"missing {label}: {path}") from error
    if (
        not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) not in {0o444, 0o600, 0o644}
    ):
        raise ArchiveError(f"{label} is not a plain single-link data file")
    if metadata.st_size != contract["bytes"]:
        raise ArchiveError(f"{label} byte count differs")
    if hash_file(path, "sha256") != contract["sha256"]:
        raise ArchiveError(f"{label} SHA-256 differs")
    if hash_file(path, "sha512") != contract["sha512"]:
        raise ArchiveError(f"{label} SHA-512 differs")


def crc24(data: bytes) -> int:
    value = 0xB704CE
    for octet in data:
        value ^= octet << 16
        for _ in range(8):
            value <<= 1
            if value & 0x1000000:
                value ^= 0x1864CFB
    return value & 0xFFFFFF


def strict_dearmor(raw: bytes) -> bytes:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ArchiveError("armored key is not ASCII") from error
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or lines[0] != "-----BEGIN PGP PUBLIC KEY BLOCK-----":
        raise ArchiveError("armored key has the wrong begin marker")
    try:
        end = lines.index("-----END PGP PUBLIC KEY BLOCK-----")
    except ValueError as error:
        raise ArchiveError("armored key lacks its end marker") from error
    if any(line for line in lines[end + 1:] if line.strip()):
        raise ArchiveError("armored key has trailing data")
    index = 1
    while index < end and lines[index] and ":" in lines[index]:
        key, value = lines[index].split(":", 1)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", key) or not value.startswith(" "):
            raise ArchiveError("armored key has an invalid header")
        index += 1
    if index >= end or lines[index] != "":
        raise ArchiveError("armored key lacks the header separator")
    index += 1
    payload: list[str] = []
    checksum: str | None = None
    for line in lines[index:end]:
        if not line:
            continue
        if line.startswith("="):
            if checksum is not None or len(line) != 5:
                raise ArchiveError("armored key has an invalid CRC line")
            checksum = line[1:]
            continue
        if checksum is not None or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", line):
            raise ArchiveError("armored key has invalid base64 data")
        payload.append(line)
    if not payload or checksum is None:
        raise ArchiveError("armored key lacks payload or CRC-24")
    try:
        binary = base64.b64decode("".join(payload), validate=True)
        expected_crc = base64.b64decode(checksum, validate=True)
    except binascii.Error as error:
        raise ArchiveError("armored key base64 is invalid") from error
    if len(expected_crc) != 3 or int.from_bytes(expected_crc, "big") != crc24(binary):
        raise ArchiveError("armored key CRC-24 differs")
    return binary


def member_name(value: str) -> str:
    if not value or len(value.encode("utf-8", "surrogateescape")) > 4096:
        raise ArchiveError("archive contains an empty or overlong member name")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ArchiveError(f"archive contains control characters in member name: {value!r}")
    if value.startswith("/"):
        raise ArchiveError(f"archive contains an absolute member: {value!r}")
    parts = PurePosixPath(value).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise ArchiveError(f"archive contains non-canonical traversal: {value!r}")
    canonical = "/".join(parts)
    if canonical != value.rstrip("/"):
        raise ArchiveError(f"archive contains a non-canonical member: {value!r}")
    return canonical


def validate_topology(path: Path, expected: dict[str, Any]) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    member_types: dict[str, str] = {}
    directories = files = links = declared_bytes = 0
    try:
        with tarfile.open(path, "r:*") as archive:
            members = archive.getmembers()
            if len(members) > 10_000:
                raise ArchiveError("archive member count exceeds safety limit")
            for member in members:
                name = member_name(member.name)
                if name in seen:
                    raise ArchiveError(f"archive contains duplicate member: {name}")
                seen.add(name)
                if name.split("/", 1)[0] != expected["top_level"]:
                    raise ArchiveError(f"archive member escapes exact top level: {name}")
                if member.mode & 0o6000:
                    raise ArchiveError(f"archive contains set-id mode: {name}")
                if member.pax_headers and any(
                    key.startswith("GNU.sparse") for key in member.pax_headers
                ):
                    raise ArchiveError(f"archive contains sparse metadata: {name}")
                if getattr(member, "sparse", None):
                    raise ArchiveError(f"archive contains a sparse file: {name}")
                if member.isdir():
                    kind = "dir"
                    directories += 1
                elif member.isfile():
                    kind = "file"
                    files += 1
                    declared_bytes += member.size
                    if member.size < 0 or declared_bytes > 64_000_000:
                        raise ArchiveError("archive declared size exceeds safety limit")
                elif member.issym() or member.islnk():
                    links += 1
                    raise ArchiveError(f"archive link is forbidden: {name}")
                else:
                    raise ArchiveError(f"archive special member is forbidden: {name}")
                member_types[name] = kind
                records.append(
                    {"name": member.name, "type": kind, "mode": member.mode, "size": member.size}
                )
    except (tarfile.TarError, OSError) as error:
        raise ArchiveError(f"cannot parse archive {path}: {error}") from error
    if member_types.get(expected["top_level"]) != "dir":
        raise ArchiveError("archive lacks its explicit top-level directory")
    for name in member_types:
        parts = name.split("/")
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            if member_types.get(parent) != "dir":
                raise ArchiveError(
                    f"archive member has a missing or non-directory parent: {name}"
                )
    evidence = {
        "top_level": expected["top_level"],
        "members": len(records),
        "directories": directories,
        "files": files,
        "links": links,
        "declared_bytes": declared_bytes,
        "member_digest": canonical_digest(records),
    }
    if evidence != expected:
        raise ArchiveError(
            "archive topology differs: "
            + json.dumps({"expected": expected, "actual": evidence}, sort_keys=True)
        )
    return evidence


def status_records(raw: str) -> list[list[str]]:
    records: list[list[str]] = []
    for line in raw.splitlines():
        if not line.startswith("[GNUPG:] "):
            continue
        fields = line[len("[GNUPG:] "):].split()
        if not fields:
            raise ArchiveError("gpgv emitted an empty status record")
        records.append(fields)
    return records


def validate_status(component: dict[str, Any], raw: str) -> dict[str, Any]:
    signature = component["signature"]
    records = status_records(raw)
    if not records:
        raise ArchiveError("gpgv emitted no machine-readable status")
    allowed = {
        "NEWSIG", "KEY_CONSIDERED", "SIG_ID", "GOODSIG", "VALIDSIG",
        "KEYEXPIRED", "EXPKEYSIG",
    }
    unknown = [fields[0] for fields in records if fields[0] not in allowed]
    if unknown:
        raise ArchiveError(f"gpgv emitted unknown status: {', '.join(unknown)}")
    forbidden = [fields[0] for fields in records if fields[0] in FORBIDDEN_STATUS]
    if forbidden:
        raise ArchiveError(f"gpgv emitted forbidden status: {', '.join(forbidden)}")
    newsig = [fields for fields in records if fields[0] == "NEWSIG"]
    considered = [fields for fields in records if fields[0] == "KEY_CONSIDERED"]
    signature_ids = [fields for fields in records if fields[0] == "SIG_ID"]
    expected_date = dt.datetime.fromtimestamp(
        signature["signing_epoch"], dt.timezone.utc
    ).strftime("%Y-%m-%d")
    if newsig != [["NEWSIG"]]:
        raise ArchiveError("gpgv NEWSIG grammar differs")
    if considered != [["KEY_CONSIDERED", signature["primary_fingerprint"], "0"]]:
        raise ArchiveError("gpgv KEY_CONSIDERED grammar differs")
    if (
        len(signature_ids) != 1 or len(signature_ids[0]) != 4
        or not re.fullmatch(r"[A-Za-z0-9+/]{20,32}", signature_ids[0][1])
        or signature_ids[0][2] != expected_date
        or signature_ids[0][3] != str(signature["signing_epoch"])
    ):
        raise ArchiveError("gpgv SIG_ID grammar differs")
    valid = [fields for fields in records if fields[0] == "VALIDSIG"]
    if len(valid) != 1 or len(valid[0]) != 11:
        raise ArchiveError("gpgv did not emit exactly one complete VALIDSIG")
    fields = valid[0]
    if (
        fields[1] != signature["signer_fingerprint"]
        or fields[2] != expected_date
        or fields[3] != str(signature["signing_epoch"])
        or fields[4] != "0"
        or fields[5] != "4"
        or fields[6] != "0"
        or fields[7] != str(signature["public_key_algorithm"])
        or fields[8] != str(signature["hash_algorithm"])
        or fields[9] != "00"
        or fields[10] != signature["primary_fingerprint"]
    ):
        raise ArchiveError("VALIDSIG fields differ from the lock")

    good = [fields for fields in records if fields[0] == "GOODSIG"]
    expired = [fields for fields in records if fields[0] == "EXPKEYSIG"]
    expiry_epochs = [fields for fields in records if fields[0] == "KEYEXPIRED"]
    if component["name"] == "mpc":
        exception = signature["historical_expiry"]
        if (
            good or len(expired) != 1 or len(expired[0]) < 3
            or expired[0][1] != signature["signer_fingerprint"][-16:]
            or not expiry_epochs
            or any(
                len(record) != 2 or record[1] != str(exception["expiry_epoch"])
                for record in expiry_epochs
            )
            or signature["signing_epoch"] >= exception["expiry_epoch"]
        ):
            raise ArchiveError("MPC historical-expiry evidence differs")
    elif expired or expiry_epochs:
        raise ArchiveError("expired key status is forbidden for this component")
    elif (
        len(good) != 1 or len(good[0]) < 3
        or good[0][1] != signature["signer_fingerprint"][-16:]
    ):
        raise ArchiveError("gpgv did not emit exactly one GOODSIG")
    return {
        "signer_fingerprint": fields[1],
        "primary_fingerprint": fields[10],
        "signing_epoch": int(fields[3]),
        "public_key_algorithm": int(fields[7]),
        "hash_algorithm": int(fields[8]),
        "historical_expiry_accepted": component["name"] == "mpc",
    }


def verifier_environment(lock: dict[str, Any], executable: Path, library_root: Path) -> dict[str, str]:
    executable = Path(executable)
    library_root = Path(library_root)
    executable_metadata = executable.lstat()
    if (
        not stat.S_ISREG(executable_metadata.st_mode)
        or executable_metadata.st_nlink != 1
        or stat.S_IMODE(executable_metadata.st_mode) != 0o755
        or not os.access(executable, os.X_OK)
    ):
        raise ArchiveError("locked gpgv is not a plain mode-0755 executable")
    if os.listxattr(executable, follow_symlinks=False):
        raise ArchiveError("locked gpgv has extended metadata")
    executable = executable.resolve(strict=True)
    root_metadata = library_root.lstat()
    if (
        not stat.S_ISDIR(root_metadata.st_mode) or library_root.is_symlink()
        or stat.S_IMODE(root_metadata.st_mode) != 0o755
        or os.listxattr(library_root, follow_symlinks=False)
    ):
        raise ArchiveError("gpgv library root is not a plain mode-0755 directory")
    library_root = library_root.resolve(strict=True)
    expected = lock["verifier"]
    if hash_file(executable, "sha256") != expected["executable"]["sha256"]:
        raise ArchiveError("gpgv executable hash differs")
    expected_entries = {
        name
        for library in expected["libraries"]
        for name in (library["filename"], library["soname"])
    }
    actual_entries = {entry.name for entry in os.scandir(library_root)}
    if actual_entries != expected_entries:
        raise ArchiveError("gpgv library root is not closed over the locked entries")
    for library in expected["libraries"]:
        path = library_root / library["filename"]
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o644
            or os.listxattr(path, follow_symlinks=False)
            or hash_file(path, "sha256") != library["sha256"]
        ):
            raise ArchiveError(f"gpgv library contract differs: {library['filename']}")
        alias = library_root / library["soname"]
        alias_metadata = alias.lstat()
        if (
            not stat.S_ISLNK(alias_metadata.st_mode) or alias_metadata.st_nlink != 1
            or os.readlink(alias) != library["filename"]
            or alias.resolve(strict=True) != path
            or os.listxattr(alias, follow_symlinks=False)
        ):
            raise ArchiveError(f"gpgv SONAME alias differs: {library['soname']}")
    environment = {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": "/nonexistent",
        "LD_LIBRARY_PATH": str(library_root),
    }
    result = subprocess.run(
        [str(executable), "--version"], env=environment, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    lines = result.stdout.splitlines()
    if (
        result.returncode != 0 or len(lines) < 2
        or lines[0] != expected["executable"]["version_line"]
        or lines[1] != expected["libgcrypt_version"]
    ):
        raise ArchiveError("gpgv version contract differs")
    return environment


def verify_signature(
    component: dict[str, Any], cache: Path, executable: Path,
    base_environment: dict[str, str], work: Path,
) -> dict[str, Any]:
    key_object = cache / component["key"]["filename"]
    raw = key_object.read_bytes()
    binary = strict_dearmor(raw) if component["key"]["armored"] else raw
    if hashlib.sha256(binary).hexdigest() != component["key"]["derived_keyring_sha256"]:
        raise ArchiveError(f"derived keyring hash differs for {component['name']}")
    component_work = work / component["name"]
    component_work.mkdir(mode=0o700)
    keyring = component_work / "keyring.gpg"
    keyring.write_bytes(binary)
    keyring.chmod(0o600)
    gnupg = component_work / "gnupg"
    gnupg.mkdir(mode=0o700)
    environment = dict(base_environment)
    environment["HOME"] = str(gnupg)
    environment["GNUPGHOME"] = str(gnupg)
    result = subprocess.run(
        [
            # gpgv has no --no-options switch.  A fresh empty mode-0700 home
            # supplies the closed configuration boundary instead.
            str(executable), "--homedir", str(gnupg),
            "--keyring", str(keyring), "--status-fd=1",
            str(cache / component["signature"]["filename"]),
            str(cache / component["archive"]["filename"]),
        ],
        env=environment, text=False, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
    )
    if result.returncode != 0:
        raise ArchiveError(
            f"gpgv rejected {component['name']} with exit {result.returncode}"
        )
    return validate_status(component, result.stdout.decode("utf-8", "surrogateescape"))


def validate_gcc_prerequisites(path: Path, components: list[dict[str, Any]]) -> None:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ArchiveError("GCC prerequisites lock is not a plain file")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) == 2 and HEX512.fullmatch(fields[0]):
            values[Path(fields[1]).name] = fields[0]
    for component in components:
        if component["name"] not in {"gmp", "mpfr", "mpc"}:
            continue
        filename = component["archive"]["filename"]
        expected = component["gcc_prerequisite_sha512"]
        if values.get(filename) != expected or component["archive"]["sha512"] != expected:
            raise ArchiveError(f"GCC prerequisite cross-check differs for {component['name']}")


def validate_root(value: str) -> Path:
    requested = Path(value)
    if requested.is_symlink():
        raise ArchiveError("CajunOS root must not be a symlink")
    root = requested.resolve(strict=True)
    if root == Path("/") or root == Path.home().resolve() or not root.is_dir():
        raise ArchiveError(f"unsafe CajunOS root: {root}")
    for relative in ("cache", "upstream", "work", "artifacts", "logs"):
        path = root / relative
        if path.is_symlink():
            raise ArchiveError(f"managed path is a symlink: {path}")
    return root


def cache_path(root: Path) -> Path:
    cache = root / "cache/native-developer-archives"
    if cache.is_symlink():
        raise ArchiveError("native developer archive cache is a symlink")
    cache.mkdir(parents=True, exist_ok=True)
    cache.chmod(0o755)
    return cache.resolve(strict=True)


def validate_cached(
    root: Path, lock: dict[str, Any], components: list[dict[str, Any]],
    executable: Path, library_root: Path, prerequisites: Path,
) -> dict[str, Any]:
    cache = cache_path(root)
    for component in components:
        for kind in ("archive", "signature", "key"):
            validate_object(
                cache / component[kind]["filename"], component[kind],
                f"{component['name']} {kind}",
            )
    validate_gcc_prerequisites(prerequisites, components)
    environment = verifier_environment(lock, executable, library_root)
    evidence: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(
        prefix=".native-developer-verify-", dir=root / "work"
    ) as temporary:
        work = Path(temporary)
        work.chmod(0o700)
        for component in components:
            topology = validate_topology(
                cache / component["archive"]["filename"], component["topology"]
            )
            signature = verify_signature(component, cache, executable, environment, work)
            evidence[component["name"]] = {
                "archive": component["archive"],
                "key": {
                    "sha256": component["key"]["sha256"],
                    "derived_keyring_sha256": component["key"]["derived_keyring_sha256"],
                },
                "signature": signature,
                "topology": topology,
            }
    return evidence


def download(url: str, destination: Path) -> None:
    temporary = destination.parent / f".{destination.name}.tmp-{os.getpid()}"
    if temporary.exists() or temporary.is_symlink():
        raise ArchiveError(f"colliding download temporary: {temporary}")
    try:
        result = subprocess.run(
            [
                "curl", "--proto", "=https", "--proto-redir", "=https",
                "--fail", "--location", "--silent", "--show-error",
                "--output", str(temporary), url,
            ],
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"},
            check=False,
        )
        if result.returncode != 0:
            raise ArchiveError(f"HTTPS download failed with exit {result.returncode}: {url}")
        temporary.chmod(0o600)
        os.replace(temporary, destination)
        destination.chmod(0o444)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def sync_cached(root: Path, components: list[dict[str, Any]]) -> None:
    cache = cache_path(root)
    for component in components:
        for kind in ("archive", "signature", "key"):
            contract = component[kind]
            destination = cache / contract["filename"]
            if destination.exists() or destination.is_symlink():
                validate_object(destination, contract, f"cached {component['name']} {kind}")
                continue
            download(contract["url"], destination)
            validate_object(destination, contract, f"downloaded {component['name']} {kind}")


def safe_extract(archive_path: Path, destination: Path, expected: dict[str, Any]) -> None:
    validate_topology(archive_path, expected)

    def canonical_mode(mode: int) -> int:
        # Release archives contain a few 0666/0777 regular members.  Preserve
        # read/execute intent while removing group/other write independently
        # of the forge umask.
        return mode & 0o777 & ~0o022

    with tarfile.open(archive_path, "r:*") as archive:
        for member in archive.getmembers():
            relative = member_name(member.name)
            output = destination.joinpath(*PurePosixPath(relative).parts)
            try:
                output.resolve(strict=False).relative_to(destination.resolve(strict=True))
            except ValueError as error:
                raise ArchiveError(f"extraction path escapes destination: {relative}") from error
            if member.isdir():
                output.mkdir(mode=0o755, parents=True, exist_ok=True)
                if output.is_symlink():
                    raise ArchiveError(f"extraction directory became a symlink: {relative}")
                output.chmod(canonical_mode(member.mode))
            elif member.isfile():
                output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                try:
                    descriptor = os.open(
                        output,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL
                        | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                    )
                except OSError as error:
                    raise ArchiveError(
                        f"cannot create extracted file {relative}: {error}"
                    ) from error
                try:
                    source = archive.extractfile(member)
                    if source is None:
                        raise ArchiveError(f"archive file has no payload: {relative}")
                    with source, os.fdopen(descriptor, "wb", closefd=False) as target:
                        shutil.copyfileobj(source, target, length=1024 * 1024)
                        target.flush()
                        os.fsync(target.fileno())
                    os.fchmod(descriptor, canonical_mode(member.mode))
                    if output.stat().st_size != member.size:
                        raise ArchiveError(f"extracted byte count differs: {relative}")
                finally:
                    os.close(descriptor)
            else:  # validate_topology already rejects this; retain fail-closed extraction.
                raise ArchiveError(f"unsupported extraction member: {relative}")


def extract_all(root: Path, components: list[dict[str, Any]], destination: Path) -> None:
    metadata = destination.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode) or destination.is_symlink()
        or stat.S_IMODE(metadata.st_mode) != 0o700 or any(destination.iterdir())
    ):
        raise ArchiveError("extraction destination must be a fresh empty mode-0700 directory")
    cache = cache_path(root)
    for component in components:
        safe_extract(
            cache / component["archive"]["filename"], destination,
            component["topology"],
        )
        source = destination / component["topology"]["top_level"]
        for relative, expected in component["licenses"].items():
            license_path = source / relative
            if hash_file(license_path, "sha256") != expected:
                raise ArchiveError(f"license hash differs for {component['name']}:{relative}")


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("sync", "validate", "extract", "validate-lock", "topology", "dearmor", "validate-status"))
    parser.add_argument("--root", default="/srv/cajunos")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--gpgv", type=Path, default=os.environ.get("CAJUNOS_GPGV"))
    parser.add_argument(
        "--gpgv-library-root", type=Path,
        default=os.environ.get("CAJUNOS_GPGV_LIBRARY_ROOT"),
    )
    parser.add_argument(
        "--gcc-prerequisites", type=Path,
        default=os.environ.get("CAJUNOS_GCC_PREREQUISITES"),
    )
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--component", choices=COMPONENT_NAMES)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--status", type=Path)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    options = arguments()
    manifest_path = options.manifest.resolve(strict=True)
    lock_path = options.lock.resolve(strict=True)
    manifest = load_json(manifest_path)
    lock = load_json(lock_path)
    components = validate_lock(manifest, manifest_path, lock)
    by_name = {component["name"]: component for component in components}

    if options.command == "validate-lock":
        evidence: Any = {
            "components": list(COMPONENT_NAMES),
            "source_set_digest": lock["source_set_digest"],
        }
    elif options.command == "topology":
        if options.component is None or options.archive is None:
            raise ArchiveError("topology requires --component and --archive")
        evidence = validate_topology(options.archive, by_name[options.component]["topology"])
    elif options.command == "dearmor":
        if options.input is None or options.output is None:
            raise ArchiveError("dearmor requires --input and --output")
        if options.output.exists() or options.output.is_symlink():
            raise ArchiveError("dearmor output already exists")
        binary = strict_dearmor(options.input.read_bytes())
        options.output.write_bytes(binary)
        options.output.chmod(0o600)
        evidence = {"bytes": len(binary), "sha256": hashlib.sha256(binary).hexdigest()}
    elif options.command == "validate-status":
        if options.component is None or options.status is None:
            raise ArchiveError("validate-status requires --component and --status")
        evidence = validate_status(
            by_name[options.component], options.status.read_text(encoding="utf-8")
        )
    else:
        root = validate_root(options.root)
        lock_file = root / "upstream/.cajunos-source.lock"
        lock_file.parent.mkdir(parents=True, exist_ok=True)
        with lock_file.open("a+b") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if options.command == "sync":
                sync_cached(root, components)
            if options.gpgv is None or options.gpgv_library_root is None:
                raise ArchiveError("locked --gpgv and --gpgv-library-root are required")
            prerequisites = options.gcc_prerequisites or root / "upstream/gcc/contrib/prerequisites.sha512"
            evidence = validate_cached(
                root, lock, components, options.gpgv, options.gpgv_library_root,
                prerequisites,
            )
            if options.command == "extract":
                if options.destination is None:
                    raise ArchiveError("extract requires --destination")
                extract_all(root, components, options.destination)
                evidence = {"validation": evidence, "destination": str(options.destination)}
    print(json.dumps(evidence, indent=2 if options.json else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ArchiveError, FileNotFoundError, PermissionError, subprocess.SubprocessError) as error:
        print(f"native developer archive error: {error}", file=sys.stderr)
        raise SystemExit(1)
