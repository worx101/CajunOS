#!/usr/bin/env python3

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT / "scripts/fetch-native-developer-archives.py"
MANIFEST = PROJECT / "manifests/native-developer-archives.json"
LOCK = PROJECT / "locks/native-developer-archives.lock.json"
SEED_MANIFEST = PROJECT / "manifests/native-developer-seed.json"
SEED_LOCK = PROJECT / "locks/native-developer-seed.lock.json"


def load_module():
    spec = importlib.util.spec_from_file_location("native_archives", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ARCHIVES = load_module()


class NativeDeveloperSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.lock = json.loads(LOCK.read_text(encoding="utf-8"))
        self.components = {item["name"]: item for item in self.lock["components"]}

    def run_script(self, *arguments: object) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [SCRIPT, *map(str, arguments)], cwd=PROJECT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )

    def tar_fixture(self, name: str, entries: list[dict[str, object]]) -> Path:
        path = self.root / name
        with tarfile.open(path, "w") as archive:
            for entry in entries:
                info = tarfile.TarInfo(str(entry["name"]))
                info.mode = int(entry.get("mode", 0o755 if entry.get("type") == "dir" else 0o644))
                kind = entry.get("type", "file")
                if kind == "dir":
                    info.type = tarfile.DIRTYPE
                    payload = b""
                elif kind == "file":
                    payload = bytes(entry.get("data", b"payload"))
                    info.size = len(payload)
                elif kind == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = str(entry.get("target", "file"))
                    payload = b""
                elif kind == "hardlink":
                    info.type = tarfile.LNKTYPE
                    info.linkname = str(entry.get("target", "pkg/file"))
                    payload = b""
                elif kind == "char":
                    info.type = tarfile.CHRTYPE
                    payload = b""
                elif kind == "block":
                    info.type = tarfile.BLKTYPE
                    payload = b""
                elif kind == "fifo":
                    info.type = tarfile.FIFOTYPE
                    payload = b""
                else:
                    raise AssertionError(kind)
                archive.addfile(info, io.BytesIO(payload) if payload else None)
        return path

    def expected_topology(self, path: Path, top: str = "pkg") -> dict[str, object]:
        records = []
        directories = files = declared = 0
        with tarfile.open(path, "r:*") as archive:
            for member in archive.getmembers():
                kind = "dir" if member.isdir() else "file"
                directories += member.isdir()
                files += member.isfile()
                if member.isfile():
                    declared += member.size
                records.append(
                    {"name": member.name, "type": kind, "mode": member.mode, "size": member.size}
                )
        return {
            "top_level": top, "members": len(records), "directories": directories,
            "files": files, "links": 0, "declared_bytes": declared,
            "member_digest": ARCHIVES.canonical_digest(records),
        }

    def assert_topology_rejects(self, entries: list[dict[str, object]]) -> None:
        path = self.tar_fixture(f"bad-{len(list(self.root.iterdir()))}.tar", entries)
        expected = {
            "top_level": "pkg", "members": len(entries), "directories": 0,
            "files": len(entries), "links": 0, "declared_bytes": 0,
            "member_digest": "0" * 64,
        }
        with self.assertRaises(ARCHIVES.ArchiveError):
            ARCHIVES.validate_topology(path, expected)

    def valid_status(self, name: str) -> str:
        signature = self.components[name]["signature"]
        signer = signature["signer_fingerprint"]
        lines = [
            "[GNUPG:] NEWSIG",
            f"[GNUPG:] KEY_CONSIDERED {signature['primary_fingerprint']} 0",
        ]
        signing_date = dt.datetime.fromtimestamp(
            signature["signing_epoch"], dt.timezone.utc
        ).strftime("%Y-%m-%d")
        if name == "mpc":
            expiry = signature["historical_expiry"]["expiry_epoch"]
            lines.extend(
                [
                    f"[GNUPG:] KEYEXPIRED {expiry}",
                    f"[GNUPG:] EXPKEYSIG {signer[-16:]} locked signer",
                ]
            )
        else:
            lines.append(f"[GNUPG:] GOODSIG {signer[-16:]} locked signer")
        lines.append(
            f"[GNUPG:] SIG_ID ABCDEFGHIJKLMNOPQRSTUVWX {signing_date} "
            f"{signature['signing_epoch']}"
        )
        lines.append(
            "[GNUPG:] VALIDSIG "
            f"{signer} {signing_date} {signature['signing_epoch']} 0 4 0 "
            f"{signature['public_key_algorithm']} {signature['hash_algorithm']} 00 "
            f"{signature['primary_fingerprint']}"
        )
        return "\n".join(lines) + "\n"

    def test_git_and_archive_source_sets_are_separate_and_locked(self) -> None:
        fetch_spec = importlib.util.spec_from_file_location("fetch", PROJECT / "scripts/fetch.py")
        assert fetch_spec is not None and fetch_spec.loader is not None
        fetch = importlib.util.module_from_spec(fetch_spec)
        fetch_spec.loader.exec_module(fetch)
        seed_manifest = json.loads(SEED_MANIFEST.read_text(encoding="utf-8"))
        seed_lock = json.loads(SEED_LOCK.read_text(encoding="utf-8"))
        fetch.validate_lock(seed_manifest, SEED_MANIFEST, seed_lock)
        dropbear = seed_lock["components"][0]
        self.assertEqual(dropbear["commit"], "1442f00d3f0d755d9f8ba83c5edcd893aa4d71db")
        self.assertEqual(dropbear["tree"], "c4a2166ba5bbab692b2ebe2a780f5a73f6a9dc0f")
        self.assertEqual(dropbear["repository"], "https://github.com/mkj/dropbear.git")

        result = self.run_script("validate-lock", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["components"], ["make", "gmp", "mpfr", "mpc"])
        bootstrap = json.loads((PROJECT / "manifests/bootstrap.json").read_text(encoding="utf-8"))
        base = json.loads((PROJECT / "manifests/base-system.json").read_text(encoding="utf-8"))
        self.assertEqual({item["name"] for item in bootstrap["components"]}, {"binutils", "gcc", "glibc", "linux"})
        self.assertEqual({item["name"] for item in base["components"]}, {"busybox", "grub", "gnulib"})

    def test_release_objects_match_reviewed_archive_report(self) -> None:
        expected = {
            "make": (2348200, "dd16fb1d67bfab79a72f5e8390735c49e3e8e70b4945a15ab1f81ddb78658fb3", 416, 8780526),
            "gmp": (2643888, "ac28211a7cfb609bae2e2c8d6058d66c8fe96434f740cf6fe2e47b000d1c20cb", 2343, 16998222),
            "mpfr": (1753999, "9ad62c7dc910303cd384ff8f1f4767a655124980bb6d8650fe62c815a231bb7b", 591, 9590620),
            "mpc": (773573, "ab642492f5cf882b74aa0cb730cd410a81edcdbec895183ce930e706c1c759b8", 357, 3477452),
        }
        for name, (size, digest, members, declared) in expected.items():
            component = self.components[name]
            self.assertEqual(component["archive"]["bytes"], size)
            self.assertEqual(component["archive"]["sha256"], digest)
            self.assertEqual(component["topology"]["members"], members)
            self.assertEqual(component["topology"]["declared_bytes"], declared)
            self.assertEqual(component["topology"]["links"], 0)
            for kind in ("archive", "signature", "key"):
                self.assertTrue(component[kind]["url"].startswith("https://"))
                self.assertEqual(len(component[kind]["sha256"]), 64)
                self.assertEqual(len(component[kind]["sha512"]), 128)

    def test_manifest_and_lock_preserve_exact_real_license_sets(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        declared = {item["name"]: set(item["license_files"]) for item in manifest["components"]}
        expected = {
            "make": {"COPYING", "README"},
            "gmp": {"COPYING", "COPYING.LESSERv3", "COPYINGv2", "COPYINGv3", "README"},
            "mpfr": {"COPYING", "COPYING.LESSER", "README"},
            "mpc": {"COPYING.LESSER", "README", "src/mpc.h"},
        }
        self.assertEqual(declared, expected)
        self.assertNotIn("COPYING", declared["mpc"])
        for name, paths in expected.items():
            self.assertEqual(set(self.components[name]["licenses"]), paths)
            self.assertTrue(all(len(value) == 64 for value in self.components[name]["licenses"].values()))

        mutated_manifest = json.loads(json.dumps(manifest))
        next(item for item in mutated_manifest["components"] if item["name"] == "gmp")["license_files"].remove("COPYINGv2")
        manifest_path = self.root / "manifest.json"
        manifest_path.write_text(json.dumps(mutated_manifest), encoding="utf-8")
        mutated_lock = json.loads(json.dumps(self.lock))
        mutated_lock["manifest_sha256"] = "sha256:" + hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        with self.assertRaises(ARCHIVES.ArchiveError):
            ARCHIVES.validate_lock(mutated_manifest, manifest_path, mutated_lock)

    def test_gcc_prerequisite_hashes_are_independently_bound(self) -> None:
        fixture = self.root / "prerequisites.sha512"
        fixture.write_text(
            "\n".join(
                f"{self.components[name]['archive']['sha512']}  {self.components[name]['archive']['filename']}"
                for name in ("gmp", "mpfr", "mpc")
            ) + "\n",
            encoding="utf-8",
        )
        ARCHIVES.validate_gcc_prerequisites(fixture, list(self.components.values()))
        fixture.write_text(fixture.read_text().replace("3b684", "0b684", 1), encoding="utf-8")
        with self.assertRaises(ARCHIVES.ArchiveError):
            ARCHIVES.validate_gcc_prerequisites(fixture, list(self.components.values()))

    def test_strict_topology_accepts_exact_plain_tree(self) -> None:
        path = self.tar_fixture(
            "valid.tar",
            [
                {"name": "pkg", "type": "dir"},
                {"name": "pkg/file", "type": "file", "data": b"hello", "mode": 0o644},
                {"name": "pkg/sub", "type": "dir", "mode": 0o755},
                {"name": "pkg/sub/tool", "type": "file", "data": b"tool", "mode": 0o755},
            ],
        )
        expected = self.expected_topology(path)
        self.assertEqual(ARCHIVES.validate_topology(path, expected), expected)
        mutated = dict(expected)
        mutated["files"] = 3
        with self.assertRaises(ARCHIVES.ArchiveError):
            ARCHIVES.validate_topology(path, mutated)

    def test_topology_rejects_links_special_members_and_setid(self) -> None:
        cases = [
            [{"name": "/outside"}],
            [{"name": "pkg/../outside"}],
            [{"name": "pkg/link", "type": "symlink", "target": "file"}],
            [{"name": "pkg/link", "type": "hardlink", "target": "pkg/file"}],
            [{"name": "pkg/device", "type": "char"}],
            [{"name": "pkg/device", "type": "block"}],
            [{"name": "pkg/pipe", "type": "fifo"}],
            [{"name": "pkg/tool", "mode": 0o4755}],
            [{"name": "pkg/tool", "mode": 0o2755}],
            [{"name": "pkg/file"}, {"name": "other/file"}],
            [{"name": "pkg/control\nname"}],
        ]
        for entries in cases:
            with self.subTest(entries=entries):
                self.assert_topology_rejects(entries)

    def test_topology_rejects_duplicate_normalized_member(self) -> None:
        path = self.root / "duplicate.tar"
        with tarfile.open(path, "w") as archive:
            for payload in (b"one", b"two"):
                info = tarfile.TarInfo("pkg/file")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
        with self.assertRaises(ARCHIVES.ArchiveError):
            ARCHIVES.validate_topology(path, self.expected_topology(path))

    def test_safe_extract_requires_fresh_mode_0700_and_no_links(self) -> None:
        path = self.tar_fixture(
            "extract.tar",
            [{"name": "pkg", "type": "dir"}, {"name": "pkg/file", "data": b"sealed"}],
        )
        destination = self.root / "extract"
        destination.mkdir(mode=0o700)
        expected = self.expected_topology(path)
        ARCHIVES.safe_extract(path, destination, expected)
        self.assertEqual((destination / "pkg/file").read_bytes(), b"sealed")
        with self.assertRaises(ARCHIVES.ArchiveError):
            ARCHIVES.safe_extract(path, destination, expected)

    def test_extraction_modes_are_canonical_under_different_umasks(self) -> None:
        path = self.tar_fixture(
            "modes.tar",
            [
                {"name": "pkg", "type": "dir", "mode": 0o777},
                {"name": "pkg/read-only", "data": b"r", "mode": 0o444},
                {"name": "pkg/data", "data": b"d", "mode": 0o666},
                {"name": "pkg/tool", "data": b"x", "mode": 0o777},
            ],
        )
        expected = self.expected_topology(path)
        observed = []
        original = os.umask(0o022)
        try:
            for value in (0o077, 0o002):
                os.umask(value)
                destination = self.root / f"extract-{value:o}"
                destination.mkdir(mode=0o700)
                destination.chmod(0o700)
                ARCHIVES.safe_extract(path, destination, expected)
                observed.append(
                    {
                        relative: stat.S_IMODE((destination / relative).stat().st_mode)
                        for relative in ("pkg", "pkg/read-only", "pkg/data", "pkg/tool")
                    }
                )
        finally:
            os.umask(original)
        self.assertEqual(observed[0], observed[1])
        self.assertEqual(
            observed[0],
            {"pkg": 0o755, "pkg/read-only": 0o444, "pkg/data": 0o644, "pkg/tool": 0o755},
        )

    def test_ascii_armor_requires_valid_crc24_and_no_trailing_data(self) -> None:
        payload = b"\x99\x01\x02locked-openpgp-packet"
        crc = ARCHIVES.crc24(payload).to_bytes(3, "big")
        armor = (
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"
            + base64.b64encode(payload).decode() + "\n="
            + base64.b64encode(crc).decode() + "\n"
            "-----END PGP PUBLIC KEY BLOCK-----\n"
        ).encode()
        self.assertEqual(ARCHIVES.strict_dearmor(armor), payload)
        with self.assertRaises(ARCHIVES.ArchiveError):
            ARCHIVES.strict_dearmor(armor.replace(b"=", b"=A", 1))
        with self.assertRaises(ARCHIVES.ArchiveError):
            ARCHIVES.strict_dearmor(armor + b"trailing\n")

    def test_exact_validsig_fields_and_mpc_exception_are_fail_closed(self) -> None:
        for name in self.components:
            with self.subTest(name=name):
                evidence = ARCHIVES.validate_status(self.components[name], self.valid_status(name))
                self.assertEqual(evidence["signer_fingerprint"], self.components[name]["signature"]["signer_fingerprint"])
                self.assertEqual(evidence["historical_expiry_accepted"], name == "mpc")

        for marker in ("BADSIG", "ERRSIG", "NO_PUBKEY", "NODATA", "REVKEYSIG", "KEYREVOKED"):
            with self.subTest(marker=marker):
                with self.assertRaises(ARCHIVES.ArchiveError):
                    ARCHIVES.validate_status(
                        self.components["make"], self.valid_status("make") + f"[GNUPG:] {marker} detail\n"
                    )
        wrong = self.valid_status("make").replace("1677441979", "1677441980")
        with self.assertRaises(ARCHIVES.ArchiveError):
            ARCHIVES.validate_status(self.components["make"], wrong)
        wrong_expiry = self.valid_status("mpc").replace("1720083037", "1720083038")
        with self.assertRaises(ARCHIVES.ArchiveError):
            ARCHIVES.validate_status(self.components["mpc"], wrong_expiry)
        with self.assertRaises(ARCHIVES.ArchiveError):
            ARCHIVES.validate_status(self.components["gmp"], self.valid_status("gmp") + "[GNUPG:] EXPKEYSIG F3599FF828C67298 expired\n")

        for marker in ("EXPSIG", "SIGEXPIRED", "TRUST_FULLY"):
            with self.subTest(marker=marker), self.assertRaises(ARCHIVES.ArchiveError):
                ARCHIVES.validate_status(
                    self.components["make"], self.valid_status("make") + f"[GNUPG:] {marker} detail\n"
                )
        wrong_good = self.valid_status("make").replace(
            "GOODSIG DEACCAAEDB78137A", "GOODSIG 0000000000000000"
        )
        with self.assertRaises(ARCHIVES.ArchiveError):
            ARCHIVES.validate_status(self.components["make"], wrong_good)
        valid_line = next(
            line for line in self.valid_status("make").splitlines()
            if line.startswith("[GNUPG:] VALIDSIG")
        )
        fields = valid_line.split()
        for index, replacement in ((3, "1999-01-01"), (5, "1"), (6, "3"), (7, "1"), (10, "01")):
            mutated = fields.copy()
            mutated[index] = replacement
            raw = self.valid_status("make").replace(valid_line, " ".join(mutated))
            with self.subTest(validsig_index=index), self.assertRaises(ARCHIVES.ArchiveError):
                ARCHIVES.validate_status(self.components["make"], raw)
        with self.assertRaises(ARCHIVES.ArchiveError):
            ARCHIVES.validate_status(
                self.components["make"],
                self.valid_status("make").replace(valid_line, valid_line + " EXTRA"),
            )

    def test_verifier_is_exact_and_never_enables_key_retrieval(self) -> None:
        verifier = self.lock["verifier"]
        self.assertEqual(verifier["executable"]["version_line"], "gpgv (GnuPG) 2.4.7")
        self.assertEqual(verifier["libgcrypt_version"], "libgcrypt 1.11.0")
        self.assertEqual(
            {item["filename"] for item in verifier["libraries"]},
            {"libgcrypt.so.20.5.0", "libgpg-error.so.0.38.0"},
        )
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"--status-fd=1"', source)
        self.assertIn('"--homedir"', source)
        self.assertNotIn('"--options"', source)
        self.assertNotIn("--auto-key-retrieve", source)
        self.assertNotIn("--keyserver", source)

    def test_verifier_library_directory_is_closed_and_sonames_are_exact(self) -> None:
        executable = self.root / "gpgv"
        executable.write_text(
            "#!/bin/sh\nprintf '%s\\n' 'gpgv (GnuPG) 2.4.7' 'libgcrypt 1.11.0'\n",
            encoding="utf-8",
        )
        executable.chmod(0o755)
        libraries = self.root / "lib"
        libraries.mkdir(mode=0o755)
        contract = {
            "executable": {
                "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                "version_line": "gpgv (GnuPG) 2.4.7",
            },
            "libgcrypt_version": "libgcrypt 1.11.0",
            "libraries": [],
        }
        for soname, filename, payload in (
            ("libgcrypt.so.20", "libgcrypt.so.20.5.0", b"gcrypt"),
            ("libgpg-error.so.0", "libgpg-error.so.0.38.0", b"gpg-error"),
        ):
            path = libraries / filename
            path.write_bytes(payload)
            path.chmod(0o644)
            (libraries / soname).symlink_to(filename)
            contract["libraries"].append(
                {"soname": soname, "filename": filename, "sha256": hashlib.sha256(payload).hexdigest()}
            )
        lock = {"verifier": contract}
        environment = ARCHIVES.verifier_environment(lock, executable, libraries)
        self.assertEqual(environment["LD_LIBRARY_PATH"], str(libraries.resolve()))

        extra = libraries / "libz.so.1"
        extra.write_bytes(b"unlocked")
        with self.assertRaises(ARCHIVES.ArchiveError):
            ARCHIVES.verifier_environment(lock, executable, libraries)
        extra.unlink()
        alias = libraries / "libgcrypt.so.20"
        alias.unlink()
        alias.symlink_to("libgpg-error.so.0.38.0")
        with self.assertRaises(ARCHIVES.ArchiveError):
            ARCHIVES.verifier_environment(lock, executable, libraries)
        alias.unlink()
        alias.symlink_to("libgcrypt.so.20.5.0")
        executable.chmod(0o4755)
        with self.assertRaises(ARCHIVES.ArchiveError):
            ARCHIVES.verifier_environment(lock, executable, libraries)

    def test_object_topology_rejects_symlink_hardlink_and_wrong_hash(self) -> None:
        contract = {
            "bytes": 6,
            "sha256": __import__("hashlib").sha256(b"sealed").hexdigest(),
            "sha512": __import__("hashlib").sha512(b"sealed").hexdigest(),
        }
        plain = self.root / "plain"
        plain.write_bytes(b"sealed")
        plain.chmod(0o444)
        ARCHIVES.validate_object(plain, contract, "plain")
        hard = self.root / "hard"
        os.link(plain, hard)
        with self.assertRaises(ARCHIVES.ArchiveError):
            ARCHIVES.validate_object(plain, contract, "hard-linked")
        hard.unlink()
        link = self.root / "link"
        link.symlink_to(plain.name)
        with self.assertRaises(ARCHIVES.ArchiveError):
            ARCHIVES.validate_object(link, contract, "symlink")
        plain.chmod(0o644)
        plain.write_bytes(b"mutate")
        with self.assertRaises(ARCHIVES.ArchiveError):
            ARCHIVES.validate_object(plain, contract, "mutated")

    def test_no_private_key_is_tracked(self) -> None:
        tracked = subprocess.run(
            ["git", "ls-files", "--", "keys/native-developer"], cwd=PROJECT,
            text=True, stdout=subprocess.PIPE, check=True,
        ).stdout.splitlines()
        # The README may still be untracked while this implementation is under review.
        candidates = tracked + [str(path.relative_to(PROJECT)) for path in (PROJECT / "keys/native-developer").iterdir()]
        self.assertFalse(any("private" in Path(path).name.lower() for path in candidates))
        self.assertFalse(any(Path(path).suffix.lower() in {".key", ".pem"} for path in candidates))


if __name__ == "__main__":
    unittest.main()
