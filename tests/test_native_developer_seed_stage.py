#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT / "scripts/build-native-developer-seed.sh"
BUSYBOX = PROJECT / "configs/busybox-native-developer.fragment"
DROPBEAR = PROJECT / "configs/dropbear-native-developer.h"
OVERLAY = PROJECT / "rootfs/native-developer"


class NativeDeveloperSeedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)

    def run_internal(
        self, command: str, *arguments: object
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [SCRIPT, "--internal-python", command, *map(str, arguments)],
            cwd=PROJECT, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )

    def write(self, relative: str, value: str | bytes, mode: int = 0o644) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(value, bytes):
            path.write_bytes(value)
        else:
            path.write_text(value, encoding="utf-8")
        path.chmod(mode)
        return path

    def generate_key(self, name: str = "id_ed25519") -> tuple[Path, Path]:
        private = self.root / name
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", private],
            check=True,
        )
        return private, Path(str(private) + ".pub")

    def canonical_key(self) -> str:
        _private, public = self.generate_key()
        return " ".join(public.read_text(encoding="utf-8").split()[:2])

    def test_script_is_executable_and_has_valid_shell_syntax(self) -> None:
        self.assertEqual(stat.S_IMODE(SCRIPT.stat().st_mode), 0o755)
        result = subprocess.run(
            ["bash", "-n", SCRIPT], cwd=PROJECT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_stage_is_explicitly_16gib_disk_with_12gib_journaled_root(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("disk_bytes=$((16 * 1024 * 1024 * 1024))", text)
        self.assertIn("rootfs_bytes=$((12 * 1024 * 1024 * 1024))", text)
        self.assertIn("lazy_itable_init=0", text)
        self.assertIn("rootfs_features=ext_attr,dir_index,filetype,extent", text)
        self.assertIn("MKE2FS_CONFIG=/dev/null", text)
        self.assertIn('-O "none,$6"', text)
        self.assertIn('/usr/sbin/tune2fs -j -J size=64 "$image"', text)
        self.assertIn('"Total journal size": "64M"', text)
        self.assertNotIn("-t ext4", text)
        self.assertIn('e2fsck", "-f", "-n"', text)
        for variable in (
            "E2FSPROGS_FAKE_TIME", "E2FSPROGS_UNDO_DIR", "MKE2FS_CONFIG",
            "MKE2FS_SYNC", "MKE2FS_FIRST_META_BG", "MKE2FS_DEVICE_SECTSIZE",
            "MKE2FS_DEVICE_PHYS_SECTSIZE", "MKE2FS_SKIP_CHECK_MSG",
        ):
            self.assertIn(variable, text)
        make_ext4 = text.split("make_ext4() {", 1)[1].split("make_disk() {", 1)[0]
        self.assertLess(make_ext4.index("/usr/sbin/mke2fs"),
                        make_ext4.index("/usr/sbin/tune2fs -j -J size=64"))
        self.assertIn('cmp -- "$temporary_root/root-a.ext4"', text)

    def test_grown_disk_preserves_stage9a_boot_identity(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('cp --sparse=always -- "$base_disk" "$disk"', text)
        self.assertIn("--move-second-header", text)
        self.assertIn('--partition-guid=2:"$root_guid"', text)
        self.assertIn("grown disk changed the GRUB MBR boot code", text)
        self.assertIn("grown disk changed the embedded GRUB BIOS partition", text)

    def test_canadian_cross_contract_is_exact(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("build_triplet=x86_64-pc-linux-gnu", text)
        self.assertIn('--host="$target" --target="$target"', text)
        self.assertIn("--with-toolexeclibdir=/usr/lib", text)
        self.assertIn("--with-slibdir=/usr/lib", text)
        self.assertIn("all-target-libatomic", text)
        self.assertIn("all-target-libstdc++-v3", text)
        self.assertIn("--with-arch=x86-64-v2", text)

    def test_two_builds_reuse_one_canonical_path_sequentially(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        first = text.index("build_payload a")
        second = text.index("build_payload b", first)
        self.assertLess(first, second)
        self.assertIn('[[ ! -e $canonical_build && ! -L $canonical_build ]]', text)
        self.assertIn('rm -rf -- "$canonical_build"', text)
        self.assertIn("canonical_build_path_reused_sequentially", text)

    def test_owner_agent_is_split_from_untrusted_build(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("The untrusted forge build must not receive an SSH agent socket", text)
        self.assertIn("--trusted-owner-proof", text)
        self.assertIn("ForwardAgent=no", text)
        self.assertIn('"agent_forwarded": False', text)
        self.assertIn('"private_key_on_forge": False', text)
        self.assertIn("ssh-keygen -Y sign", text)
        self.assertIn("ssh-keygen -Y verify", text)

    def test_qemu_is_no_egress_and_has_no_host_share(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("restrict=on,hostfwd=tcp:127.0.0.1", text)
        self.assertNotIn("-virtfs", text)
        self.assertNotIn("-fsdev", text)
        self.assertNotIn("virtio-9p", text)
        self.assertIn("usernet-restrict-on-loopback-hostfwd-no-egress", text)

    def test_template_contract_is_pristine_only(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("pristine-never-booted-stage9b-artifact-only", text)
        self.assertIn("booted_validation_disk_forbidden", text)
        self.assertIn("deleted-host-private-key-blocks-remain-forensically-recoverable", text)
        self.assertIn("independent_clone_host_keys_differ", text)
        self.assertIn('"deployment_and_vm118_template": "later-milestone"', text)

    def test_busybox_does_not_shadow_gnu_ar(self) -> None:
        text = BUSYBOX.read_text(encoding="utf-8")
        self.assertIn("# CONFIG_AR is not set", text)
        self.assertIn("# CONFIG_FEATURE_AR_CREATE is not set", text)
        self.assertIn("# CONFIG_FEATURE_PREFER_APPLETS is not set", text)
        self.assertIn("CONFIG_FEATURE_SH_STANDALONE=y", text)
        script = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('[ "$(command -v ar)" = /usr/bin/ar ]', script)
        self.assertIn("GNU ar", script)

    def test_busybox_validator_accepts_only_expanded_recovery_contract(self) -> None:
        required_y = {
            "CONFIG_STATIC", "CONFIG_ASH", "CONFIG_SH_IS_ASH", "CONFIG_INIT",
            "CONFIG_TAR", "CONFIG_FEATURE_TAR_CREATE", "CONFIG_GZIP",
            "CONFIG_GUNZIP", "CONFIG_BZIP2", "CONFIG_BUNZIP2", "CONFIG_PATCH",
            "CONFIG_DIFF", "CONFIG_CMP", "CONFIG_FLOCK", "CONFIG_NPROC",
            "CONFIG_TIMEOUT", "CONFIG_SHA512SUM", "CONFIG_CKSUM",
            "CONFIG_FEATURE_SH_STANDALONE", "CONFIG_FEATURE_STAT_FORMAT",
            "CONFIG_POWEROFF", "CONFIG_REBOOT",
            "CONFIG_TEST1",
            "CONFIG_FEATURE_SH_MATH",
        }
        required_n = {
            "CONFIG_AR", "CONFIG_FEATURE_AR_CREATE", "CONFIG_FEATURE_PREFER_APPLETS",
            "CONFIG_TC", "CONFIG_UDHCPC6", "CONFIG_FEATURE_SUID",
        }
        config = self.write(
            "busybox.config",
            "\n".join(
                [f"{name}=y" for name in sorted(required_y)]
                + [f"# {name} is not set" for name in sorted(required_n)]
            ) + "\n",
        )
        result = self.run_internal("validate-busybox-config", config)
        self.assertEqual(result.returncode, 0, result.stderr)
        config.write_text(config.read_text().replace("# CONFIG_AR is not set", "CONFIG_AR=y"))
        result = self.run_internal("validate-busybox-config", config)
        self.assertNotEqual(result.returncode, 0)

    def test_dropbear_options_are_exact_and_recognized(self) -> None:
        source = self.root / "dropbear-source"
        source.mkdir()
        names = []
        for line in DROPBEAR.read_text(encoding="utf-8").splitlines():
            if line.startswith("#define DROPBEAR_") or line.startswith("#define INETD") or line.startswith("#define NON_INETD"):
                names.append(line.split()[1])
        self.write("dropbear-source/default_options.h", "\n".join(f"/* {name} */" for name in names))
        result = self.run_internal("validate-dropbear-options", DROPBEAR, source)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["password_code"], "compiled-out")
        mutated = self.write(
            "dropbear-mutated.h",
            DROPBEAR.read_text().replace(
                "#define DROPBEAR_SERVER 1",
                "#define DROPBEAR_SERVER 1\n#define DROPBEAR_ALLOW_EMPTY_PASSWORD 0",
            ),
        )
        result = self.run_internal("validate-dropbear-options", mutated, source)
        self.assertNotEqual(result.returncode, 0)

    def test_dropbear_header_closes_unused_attack_surface(self) -> None:
        text = DROPBEAR.read_text(encoding="utf-8")
        for line in (
            "DROPBEAR_SVR_PASSWORD_AUTH 0", "DROPBEAR_SVR_PAM_AUTH 0",
            "DROPBEAR_SVR_LOCALTCPFWD 0", "DROPBEAR_SVR_REMOTETCPFWD 0",
            "DROPBEAR_SFTPSERVER 0", "DROPBEAR_SVR_PUBKEY_OPTIONS 0",
            "INETD_MODE 0", "NON_INETD_MODE 1", "DROPBEAR_CLIENT 0",
        ):
            self.assertIn(line, text)
        self.assertNotIn("DROPBEAR_ALLOW_EMPTY_PASSWORD", text)

    def test_rcs_generates_host_key_atomically_and_logs_auth(self) -> None:
        text = (OVERLAY / "etc/init.d/rcS").read_text(encoding="utf-8")
        self.assertIn(".dropbear_ed25519_host_key.new", text)
        self.assertIn("host_key_new.pub", text)
        self.assertIn('/bin/mv -f "$host_key_new" "$host_key"', text)
        self.assertIn("umask 077", text)
        self.assertIn("-F -E -p 22", text)
        self.assertIn(">/dev/console 2>&1 &", text)
        self.assertIn('[ "$dropbear_pid" = "$dropbear_spawned_pid" ]', text)

    def test_rcs_accepts_only_one_valid_devtpmfs_mount(self) -> None:
        text = (OVERLAY / "etc/init.d/rcS").read_text(encoding="utf-8")
        self.assertLess(text.index("mount -t proc"), text.index("dev_mount_count="))
        self.assertIn('/proc/self/mountinfo', text)
        self.assertIn('$5 == "/dev"', text)
        self.assertIn('$(field + 1) == "devtmpfs"', text)
        self.assertIn('0)\n        /bin/mount -t devtmpfs', text)
        self.assertIn('1)\n        ;;', text)
        self.assertIn("fail devtmpfs-inspect", text)
        self.assertIn("fail devtmpfs-count", text)
        self.assertIn("fail devtmpfs-type", text)
        self.assertIn("fail devtmpfs-mode", text)
        self.assertIn("[ -c /dev/console ] || fail devtmpfs-console", text)

    def test_rck_waits_and_remounts_while_proc_is_available(self) -> None:
        text = (OVERLAY / "etc/init.d/rcK").read_text(encoding="utf-8")
        self.assertIn("while /bin/kill -0", text)
        self.assertIn("/bin/umount -a -r", text)
        self.assertIn("/bin/mount -o remount,ro /", text)
        self.assertNotIn("/bin/umount /proc", text)
        self.assertLess(text.index("/bin/sync"), text.index("/bin/umount -a -r"))

    def test_overlay_has_shell_nss_and_loader_contract(self) -> None:
        self.assertEqual(
            (OVERLAY / "etc/shells").read_text(), "/bin/ash\n/bin/sh\n"
        )
        self.assertEqual(
            (OVERLAY / "etc/nsswitch.conf").read_text(),
            "passwd: files\ngroup: files\nshadow: files\nhosts: files dns\nnetworks: files\n",
        )
        self.assertEqual(
            (OVERLAY / "etc/ld.so.conf").read_text(),
            "/lib\n/usr/lib\n/lib64\n/usr/lib64\n",
        )

    def test_overlay_inventory_is_closed_and_rejects_extra_secret(self) -> None:
        result = self.run_internal("overlay-inventory", OVERLAY)
        self.assertEqual(result.returncode, 0, result.stderr)
        inventory = json.loads(result.stdout)
        self.assertNotIn("root", inventory["entries"])
        self.assertNotIn("root/.ssh/authorized_keys", inventory["entries"])
        copy = self.root / "overlay"
        shutil.copytree(OVERLAY, copy, symlinks=True)
        secret = copy / "root/.ssh/id_ed25519"
        secret.parent.mkdir(parents=True)
        secret.write_text("secret", encoding="utf-8")
        secret.chmod(0o600)
        result = self.run_internal("overlay-inventory", copy)
        self.assertNotEqual(result.returncode, 0)

    def test_public_key_validator_canonicalizes_one_ed25519_key(self) -> None:
        _private, public = self.generate_key()
        canonical = self.root / "authorized_keys"
        result = self.run_internal("validate-public-key", public, canonical)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["algorithm"], "ssh-ed25519")
        self.assertEqual(canonical.read_text().count("\n"), 1)
        self.assertEqual(len(canonical.read_text().split()), 2)
        self.assertEqual(stat.S_IMODE(canonical.stat().st_mode), 0o600)
        public.write_text(public.read_text() + public.read_text(), encoding="utf-8")
        result = self.run_internal("validate-public-key", public)
        self.assertNotEqual(result.returncode, 0)

    def test_inventory_supports_only_confined_hardlinks(self) -> None:
        tree = self.root / "tree"
        tree.mkdir()
        first = self.write("tree/a", "payload")
        os.link(first, tree / "b")
        result = self.run_internal("inventory", tree)
        self.assertEqual(result.returncode, 0, result.stderr)
        entries = json.loads(result.stdout)["entries"]
        self.assertEqual(entries["a"]["hardlinks"], ["a", "b"])
        outside = self.root / "outside"
        os.link(first, outside)
        result = self.run_internal("inventory", tree)
        self.assertNotEqual(result.returncode, 0)

    def test_inventory_understands_guest_absolute_symlinks(self) -> None:
        tree = self.root / "tree"
        (tree / "lib").mkdir(parents=True)
        (tree / "lib64").mkdir()
        (tree / "lib/loader").write_text("loader")
        (tree / "lib64/ld.so").symlink_to("/lib/loader")
        result = self.run_internal("inventory", tree)
        self.assertEqual(result.returncode, 0, result.stderr)
        (tree / "lib64/ld.so").unlink()
        (tree / "lib64/ld.so").symlink_to("/missing")
        result = self.run_internal("inventory", tree)
        self.assertNotEqual(result.returncode, 0)
        (tree / "lib64/ld.so").unlink()
        (tree / "lib64/ld.so").symlink_to("../../../escape")
        result = self.run_internal("inventory", tree)
        self.assertNotEqual(result.returncode, 0)

    def minimal_root(self) -> Path:
        root = self.root / "rootfs"
        for directory in (
            "bin", "etc/init.d", "etc/dropbear", "lost+found",
            "root/.ssh", "tmp",
        ):
            (root / directory).mkdir(parents=True, exist_ok=True)
        for relative in ("bin/busybox", "etc/init.d/rcS", "etc/init.d/rcK"):
            path = root / relative
            path.write_text("#!/bin/sh\n", encoding="utf-8")
            path.chmod(0o755)
        (root / "etc/shadow").write_text("root:!\n")
        (root / "root/.ssh/authorized_keys").write_text("ssh-ed25519 AAAA\n")
        return root

    def test_canonical_root_modes_are_exact(self) -> None:
        root = self.minimal_root()
        root.chmod(0o755)
        (root / "lost+found").chmod(0o700)
        result = self.run_internal("canonicalize-root", root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE((root / "root").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((root / "root/.ssh").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((root / "etc/dropbear").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((root / "lost+found").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((root / "tmp").stat().st_mode), 0o1777)
        self.assertEqual(stat.S_IMODE((root / "etc/shadow").stat().st_mode), 0o600)

    def test_canonical_root_rejects_sealed_host_key(self) -> None:
        root = self.minimal_root()
        (root / "etc/dropbear/dropbear_ed25519_host_key").write_bytes(b"private")
        result = self.run_internal("canonicalize-root", root)
        self.assertNotEqual(result.returncode, 0)

    def test_canonical_root_breaks_confined_hardlinks_deterministically(self) -> None:
        root = self.minimal_root()
        first = root / "usr/lib/libfixture.a"
        first.parent.mkdir(parents=True)
        first.write_bytes(b"archive fixture")
        second = first.with_name("libfixture-alias.a")
        os.link(first, second)
        fixed_ns = 1_700_000_000_000_000_000
        os.utime(first, ns=(fixed_ns, fixed_ns))
        result = self.run_internal("canonicalize-root", root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["hardlinks_broken"], 1)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first.stat().st_nlink, 1)
        self.assertEqual(second.stat().st_nlink, 1)
        self.assertEqual(first.stat().st_mtime_ns, fixed_ns)
        self.assertEqual(second.stat().st_mtime_ns, fixed_ns)

    def test_private_material_scan_is_fail_closed(self) -> None:
        tree = self.root / "scan"
        tree.mkdir()
        self.write("scan/public.txt", "ssh-ed25519 AAAA\n")
        self.write(
            "scan/keyimport.c",
            'const char *marker = "-----BEGIN OPENSSH PRIVATE KEY-----";\n',
        )
        result = self.run_internal("scan-private-material", tree)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.write(
            "scan/source.pem",
            b"x" * (1024 * 1024 + 31) + b"\n-----BEGIN DSA PRIVATE KEY-----\n",
        )
        result = self.run_internal("scan-private-material", tree)
        self.assertNotEqual(result.returncode, 0)

    def test_dropbear_private_test_fixtures_are_hash_bound_and_omitted(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        for value in (
            "libtomcrypt/testprof/test.key",
            "libtomcrypt/tests/test.key",
            "libtomcrypt/tests/test_dsa.key",
            "fuzz/fuzz-hostkeys.c",
            "76ec7faebdc42a4de35ca70024c2d273e9f7856ca61612e89f5f66350ba8cf5f",
            "8a44ced5b373b6124f56bb33577a98585cce3d65671e5303384c4236f9b4d41c",
            "0370305b5582f7375fc00e84ff80b49945cb04e93c401ed11194124b390ee92c",
            "embedded-private-host-key-fixture",
        ):
            self.assertIn(value, text)
        self.assertIn("locked private test fixture contract differs", text)
        self.assertIn("private-test-fixture-not-shipped", text)
        self.assertIn("omitted-private-test-fixtures.json", text)
        self.assertIn("path.unlink()", text)

    def test_omission_manifest_is_exact_and_bound_through_replay(self) -> None:
        records = [
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
        path = self.write(
            "omitted-private-test-fixtures.json",
            json.dumps({"schema": 1, "omitted": records}) + "\n",
        )
        result = self.run_internal("validate-omitted-private-fixtures", path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["records"], records)
        for label, mutation in (
            ("removed", records[:-1]),
            ("extra", records + [records[0] | {"path": "extra.key"}]),
            ("digest", [records[0] | {"sha256": "0" * 64}, *records[1:]]),
        ):
            with self.subTest(label=label):
                path.write_text(json.dumps({"schema": 1, "omitted": mutation}) + "\n")
                result = self.run_internal("validate-omitted-private-fixtures", path)
                self.assertNotEqual(result.returncode, 0)
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('configuration/omitted-private-test-fixtures.json', text)
        self.assertIn('"manifest_sha256": hashlib.sha256', text)
        self.assertIn('"records": omissions["omitted"]', text)
        self.assertIn(
            "three-standalone-pem-plus-one-embedded-host-key-fixture-omitted-public-crypto-c-vectors-source-bound",
            text,
        )

    def test_stage9a_lost_found_delta_is_exact_and_retained(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("Stage 9A filesystem-created lost+found contract differs", text)
        self.assertIn("'directory:2:700:0:0'", text)
        self.assertIn('rmdir -- "$base_lost_found"', text)
        self.assertIn('mkdir -m 0700 -- "$base_lost_found"', text)
        self.assertIn("base-root-foundation.json", text)

    @unittest.skipUnless(Path("/usr/sbin/mke2fs").exists(), "e2fsprogs unavailable")
    def test_precreated_lost_found_survives_mke2fs_and_rdump_exactly(self) -> None:
        root = self.minimal_root()
        root.chmod(0o755)
        (root / "lost+found").chmod(0o700)
        image = self.root / "lost-found.ext4"
        replay = self.root / "replay"
        replay.mkdir()
        with image.open("wb") as stream:
            stream.truncate(64 * 1024**2)
        subprocess.run(
            [
                "/usr/sbin/mke2fs", "-q", "-F", "-b", "4096",
                "-O", "none,filetype,extent", "-d", root, image,
            ],
            check=True,
            env=os.environ | {"LC_ALL": "C", "MKE2FS_CONFIG": "/dev/null"},
        )
        subprocess.run(
            ["/usr/sbin/debugfs", "-R", f"rdump / {replay}", image],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        expected = self.run_internal("inventory", root)
        actual = self.run_internal("inventory", replay)
        self.assertEqual(expected.returncode, 0, expected.stderr)
        self.assertEqual(actual.returncode, 0, actual.stderr)
        self.assertEqual(json.loads(expected.stdout), json.loads(actual.stdout))
        self.assertEqual(stat.S_IMODE((replay / "lost+found").stat().st_mode), 0o700)

    def test_gcc_configargs_rewrite_is_exact(self) -> None:
        configargs = self.write(
            "configargs.h",
            'const char *a="/srv/cajunos/work/build"; const char *b="/srv/cajunos/sysroot";\n',
        )
        result = self.run_internal(
            "rewrite-gcc-configargs", configargs,
            "/srv/cajunos/work/build", "/usr/src/cajunos-build",
            "/srv/cajunos/sysroot", "/",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("/srv/cajunos", configargs.read_text())
        result = self.run_internal(
            "rewrite-gcc-configargs", configargs, "/absent", "/guest"
        )
        self.assertNotEqual(result.returncode, 0)

    def test_forbidden_path_scan_rejects_embedded_forge_path(self) -> None:
        tree = self.root / "payload"
        tree.mkdir()
        self.write("payload/tool", b"prefix=/srv/cajunos/work/native")
        result = self.run_internal("scan-forbidden", tree, "/srv/cajunos")
        self.assertNotEqual(result.returncode, 0)
        (tree / "tool").write_bytes(b"prefix=/usr")
        result = self.run_internal("scan-forbidden", tree, "/srv/cajunos")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_positive_and_negative_serial_contracts(self) -> None:
        key = self.canonical_key()
        build_id = "native-developer-base-1234567890abcdef"
        release = "7.2.0-rc6-cajunos+"
        positive = self.write(
            "positive.raw",
            "\r\n".join((
                "CAJUNOS_NATIVE_DEVELOPER_BEGIN",
                f"CAJUNOS_NATIVE_DEVELOPER_BUILD_ID {build_id}",
                "CAJUNOS_NATIVE_DEVELOPER_ROOT_OK",
                "CAJUNOS_NATIVE_DEVELOPER_NETWORK_OK",
                "CAJUNOS_NATIVE_DEVELOPER_IPV4 10.0.2.15",
                f"CAJUNOS_NATIVE_DEVELOPER_SSH_HOST_KEY {key}",
                "CAJUNOS_NATIVE_DEVELOPER_SSH_READY",
                f"CAJUNOS_NATIVE_DEVELOPER_UNAME {release}",
                "CAJUNOS_NATIVE_DEVELOPER_OK", "",
            )),
        )
        result = self.run_internal("validate-serial", "positive", positive, release, build_id)
        self.assertEqual(result.returncode, 0, result.stderr)
        invalid_ipv4 = self.write(
            "invalid-ipv4.raw",
            positive.read_text().replace(" 10.0.2.15", " 010.0.2.15"),
        )
        result = self.run_internal(
            "validate-serial", "positive", invalid_ipv4, release, build_id
        )
        self.assertNotEqual(result.returncode, 0)
        negative = self.write(
            "negative.raw",
            "CAJUNOS_NATIVE_DEVELOPER_BEGIN\r\n"
            "CAJUNOS_NATIVE_DEVELOPER_FAIL cmdline-token\r\n",
        )
        result = self.run_internal("validate-serial", "negative", negative, release, build_id)
        self.assertEqual(result.returncode, 0, result.stderr)
        normalized = self.root / "negative.normalized"
        result = self.run_internal(
            "validate-serial", "negative", negative, release, build_id, normalized
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(normalized.read_text(), negative.read_text().replace("\r\n", "\n"))
        negative.write_text(negative.read_text() + "CAJUNOS_NATIVE_DEVELOPER_OK\n")
        result = self.run_internal("validate-serial", "negative", negative, release, build_id)
        self.assertNotEqual(result.returncode, 0)

    def test_serial_normalizes_only_the_exact_grub_prologue(self) -> None:
        key = self.canonical_key()
        build_id = "native-developer-base-1234567890abcdef"
        release = "7.2.0-rc6-cajunos+"
        transcript = "\r\n".join((
            "  Booting `CajunOS native developer'",
            "CAJUNOS_NATIVE_DEVELOPER_BEGIN",
            f"CAJUNOS_NATIVE_DEVELOPER_BUILD_ID {build_id}",
            "CAJUNOS_NATIVE_DEVELOPER_ROOT_OK",
            "CAJUNOS_NATIVE_DEVELOPER_NETWORK_OK",
            "CAJUNOS_NATIVE_DEVELOPER_IPV4 10.0.2.15",
            f"CAJUNOS_NATIVE_DEVELOPER_SSH_HOST_KEY {key}",
            "CAJUNOS_NATIVE_DEVELOPER_SSH_READY",
            f"CAJUNOS_NATIVE_DEVELOPER_UNAME {release}",
            "CAJUNOS_NATIVE_DEVELOPER_OK", "",
        )).encode()
        prologue = b"\x1b[H\x1b[J\x1b[1;1H"
        raw = self.root / "grub-positive.raw"
        host_key = self.root / "grub-positive.host-key"
        normalized = self.root / "grub-positive.normalized"
        raw.write_bytes(prologue + transcript)
        result = self.run_internal(
            "validate-serial", "positive", raw, release, build_id,
            host_key, normalized,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(normalized.read_bytes(), transcript.replace(b"\r\n", b"\n"))

        for label, mutation in (
            ("wrong", b"\x1b[J" + transcript),
            ("repeated", prologue + prologue + transcript),
            ("embedded", transcript + b"\x1b[J"),
        ):
            with self.subTest(label=label):
                raw.write_bytes(mutation)
                result = self.run_internal(
                    "validate-serial", "positive", raw, release, build_id
                )
                self.assertNotEqual(result.returncode, 0)

    def test_serial_readiness_poll_accepts_raw_crlf_before_exact_validation(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        body = text.split("wait_for_serial_ready() {", 1)[1].split(
            "prepare_known_hosts() {", 1
        )[0]
        self.assertIn('{ sub(/\\r$/, "") }', body)
        self.assertIn('$0 == "CAJUNOS_NATIVE_DEVELOPER_SSH_READY"', body)
        self.assertNotIn("grep -Fq", body)
        self.assertIn("validate-serial positive", text)

        program = (
            r'{ sub(/\r$/, "") } '
            r'$0 == "CAJUNOS_NATIVE_DEVELOPER_SSH_READY" { found = 1 } '
            r'END { exit !found }'
        )
        for label, payload, accepted in (
            ("lf", "CAJUNOS_NATIVE_DEVELOPER_SSH_READY\n", True),
            ("crlf", "CAJUNOS_NATIVE_DEVELOPER_SSH_READY\r\n", True),
            ("prefix", "xCAJUNOS_NATIVE_DEVELOPER_SSH_READY\r\n", False),
            ("suffix", "CAJUNOS_NATIVE_DEVELOPER_SSH_READYx\r\n", False),
            ("embedded", "x CAJUNOS_NATIVE_DEVELOPER_SSH_READY y\r\n", False),
        ):
            with self.subTest(label=label):
                result = subprocess.run(
                    ["awk", program], input=payload, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                )
                self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_retained_serial_replay_revalidates_semantics_and_clone_identity(self) -> None:
        build_id = "native-developer-base-1234567890abcdef"
        release = "7.2.0-rc6-cajunos+"
        artifact = self.root / "artifact"
        probe = artifact / "probe"
        probe.mkdir(parents=True)
        keys = {}
        for name in ("a", "b", "owner"):
            _private, public = self.generate_key(f"retained-{name}")
            keys[name] = " ".join(public.read_text().split()[:2])

        def positive(key: str) -> bytes:
            return ("\r\n".join((
                "CAJUNOS_NATIVE_DEVELOPER_BEGIN",
                f"CAJUNOS_NATIVE_DEVELOPER_BUILD_ID {build_id}",
                "CAJUNOS_NATIVE_DEVELOPER_ROOT_OK",
                "CAJUNOS_NATIVE_DEVELOPER_NETWORK_OK",
                "CAJUNOS_NATIVE_DEVELOPER_IPV4 10.0.2.15",
                f"CAJUNOS_NATIVE_DEVELOPER_SSH_HOST_KEY {key}",
                "CAJUNOS_NATIVE_DEVELOPER_SSH_READY",
                f"CAJUNOS_NATIVE_DEVELOPER_UNAME {release}",
                "CAJUNOS_NATIVE_DEVELOPER_OK", "",
            ))).encode()

        def store(name: str, raw: bytes) -> None:
            (probe / f"{name}.serial.raw").write_bytes(raw)
            (probe / f"{name}.serial.normalized").write_bytes(
                raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            )

        store("first-a", positive(keys["a"]))
        store("second-a", positive(keys["a"]))
        store("first-b", positive(keys["b"]))
        store("owner", positive(keys["owner"]))
        negative = (
            b"CAJUNOS_NATIVE_DEVELOPER_BEGIN\r\n"
            b"CAJUNOS_NATIVE_DEVELOPER_FAIL cmdline-token\r\n"
        )
        store("negative", negative)
        receipt = self.write(
            "retained-receipt.json",
            json.dumps({
                "kernel": {"release": release},
                "qemu": {
                    "host_key_sha256": hashlib.sha256(
                        (keys["a"] + "\n").encode()
                    ).hexdigest(),
                    "owner_proof_host_key_sha256": hashlib.sha256(
                        (keys["owner"] + "\n").encode()
                    ).hexdigest(),
                },
            }) + "\n",
        )
        result = self.run_internal(
            "validate-retained-serials", artifact, receipt, build_id
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        mutations = (
            ("semantic", "first-a", positive(keys["a"]).replace(
                b"CAJUNOS_NATIVE_DEVELOPER_ROOT_OK",
                b"CAJUNOS_NATIVE_DEVELOPER_ROOT_BAD",
            )),
            ("persistence", "second-a", positive(keys["b"])),
            ("clone-identity", "first-b", positive(keys["a"])),
            ("negative", "negative", negative + b"CAJUNOS_NATIVE_DEVELOPER_OK\r\n"),
        )
        originals = {
            "first-a": positive(keys["a"]), "second-a": positive(keys["a"]),
            "first-b": positive(keys["b"]), "negative": negative,
        }
        for label, name, mutation in mutations:
            with self.subTest(label=label):
                store(name, mutation)
                result = self.run_internal(
                    "validate-retained-serials", artifact, receipt, build_id
                )
                self.assertNotEqual(result.returncode, 0)
                store(name, originals[name])

    def ssh_evidence(self, build_id: str, nonce: str, host_hash: str) -> dict[str, object]:
        return {
            "schema": 1, "build_id": build_id,
            "boot": "disk-only-gpt-bios-grub-qcow2-overlay",
            "host_key_sha256": host_hash,
            "authentication": {
                "no_key_rejected": True, "wrong_key_rejected": True,
                "password_rejected": True, "dedicated_probe_key_succeeded": True,
                "owner_key_succeeded": True, "strict_host_key_pinning": True,
                "success_method": "publickey", "interactive_pty": True,
            },
            "toolchain": {
                "gcc": "gcc 17", "g++": "g++ 17", "ld": "GNU ld 2.47",
                "as": "GNU assembler 2.47", "ar": "GNU ar 2.47", "make": "GNU Make 4.4.1",
            },
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

    def test_ssh_evidence_rejects_boolean_only_shortcuts(self) -> None:
        path = self.write(
            "ssh.json", json.dumps(self.ssh_evidence("build", "nonce", "a" * 64))
        )
        result = self.run_internal(
            "validate-ssh-evidence", path, "build", "nonce", "a" * 64
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(path.read_text())
        value["authentication"]["success_method"] = "unknown"
        path.write_text(json.dumps(value))
        result = self.run_internal(
            "validate-ssh-evidence", path, "build", "nonce", "a" * 64
        )
        self.assertNotEqual(result.returncode, 0)

    def test_trusted_owner_response_is_exact(self) -> None:
        value = {
            "schema": 1, "build_id": "build", "challenge": "c" * 64,
            "host_key_sha256": "h" * 64, "owner_public_key_sha256": "o" * 64,
            "authentication": {
                "method": "publickey", "strict_host_key_pinning": True,
                "agent_forwarded": False, "private_key_on_forge": False,
                "interactive_pty": True,
            },
            "remote": {
                "build_id": "build", "authorized_key_sha256": "o" * 64,
                "challenge_written": True,
            },
        }
        path = self.write("owner.json", json.dumps(value))
        result = self.run_internal(
            "validate-owner-response", path, "build", "c" * 64,
            "h" * 64, "o" * 64,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        value["authentication"]["agent_forwarded"] = True
        path.write_text(json.dumps(value))
        result = self.run_internal(
            "validate-owner-response", path, "build", "c" * 64,
            "h" * 64, "o" * 64,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_owner_handoff_waits_for_hash_bound_ready_sentinel(self) -> None:
        response = self.write("handoff/response.json", b"complete-response\n")
        signature = self.write("handoff/response.json.sig", b"complete-signature\n")
        ready_value = {
            "schema": 1,
            "response_sha256": hashlib.sha256(response.read_bytes()).hexdigest(),
            "signature_sha256": hashlib.sha256(signature.read_bytes()).hexdigest(),
        }
        ready = self.write("handoff/response.json.ready", json.dumps(ready_value) + "\n")
        result = self.run_internal(
            "validate-owner-ready", ready, response, signature
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        response.write_bytes(b"partial")
        result = self.run_internal(
            "validate-owner-ready", ready, response, signature
        )
        self.assertNotEqual(result.returncode, 0)
        response.write_bytes(b"complete-response\n")
        ready_value["extra"] = True
        ready.write_text(json.dumps(ready_value) + "\n")
        result = self.run_internal(
            "validate-owner-ready", ready, response, signature
        )
        self.assertNotEqual(result.returncode, 0)

        text = SCRIPT.read_text(encoding="utf-8")
        poll = text.split("proof_waited=0", 1)[1].split(
            "sealed_owner_response=", 1
        )[0]
        self.assertIn("validate-owner-ready", poll)
        self.assertIn("rename RESPONSE.json.ready last", text)
        self.assertIn("response.json.ready", text)

    def test_owner_request_binds_canonical_host_key_hash_and_port(self) -> None:
        _host_private, host_public = self.generate_key("host_ed25519")
        _owner_private, owner_public = self.generate_key("owner_ed25519")
        host_key = " ".join(host_public.read_text().split()[:2])
        owner_key = " ".join(owner_public.read_text().split()[:2])
        owner_hash = hashlib.sha256((owner_key + "\n").encode()).hexdigest()
        host_hash = hashlib.sha256((host_key + "\n").encode()).hexdigest()
        value = {
            "schema": 1,
            "build_id": "native-developer-base-1234",
            "challenge": "c" * 64,
            "host": "127.0.0.1",
            "port": 22222,
            "host_key": host_key,
            "host_key_sha256": host_hash,
            "owner_public_key_sha256": owner_hash,
            "namespace": "cajunos-native-developer-owner-proof",
        }
        path = self.write("owner-request.json", json.dumps(value))
        result = self.run_internal(
            "validate-owner-request", path, value["build_id"], owner_hash, 22222
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        value["host_key_sha256"] = "0" * 64
        path.write_text(json.dumps(value))
        result = self.run_internal(
            "validate-owner-request", path, value["build_id"], owner_hash, 22222
        )
        self.assertNotEqual(result.returncode, 0)
        value["host_key_sha256"] = host_hash
        path.write_text(json.dumps(value))
        result = self.run_internal(
            "validate-owner-request", path, value["build_id"], owner_hash, 22223
        )
        self.assertNotEqual(result.returncode, 0)

    def test_sparse_grown_disk_validator_checks_journal_and_clean_state(self) -> None:
        base = self.root / "base.raw"
        grown = self.root / "grown.raw"
        with base.open("wb") as stream:
            stream.truncate(4096 * 512)
        with grown.open("wb") as stream:
            stream.truncate(16 * 1024**3)
        # Both sparse fixtures have identical zero MBR boot code and BIOS area.
        superblock = bytearray(1024)
        struct.pack_into("<I", superblock, 4, (12 * 1024**3) // 4096)
        struct.pack_into("<I", superblock, 24, 2)
        struct.pack_into("<H", superblock, 56, 0xEF53)
        struct.pack_into("<H", superblock, 58, 0x1)
        struct.pack_into("<I", superblock, 92, 0x4)
        struct.pack_into("<I", superblock, 96, 0)
        with grown.open("r+b") as stream:
            stream.seek(4096 * 512 + 1024)
            stream.write(superblock)
        result = self.run_internal(
            "validate-grown-disk", base, grown, 12 * 1024**3
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        struct.pack_into("<I", superblock, 92, 0)
        with grown.open("r+b") as stream:
            stream.seek(4096 * 512 + 1024)
            stream.write(superblock)
        result = self.run_internal(
            "validate-grown-disk", base, grown, 12 * 1024**3
        )
        self.assertNotEqual(result.returncode, 0)

    @unittest.skipUnless(Path("/usr/sbin/mke2fs").exists(), "e2fsprogs unavailable")
    def test_ext4_validator_requires_journal_clean_state_and_forced_fsck(self) -> None:
        image = self.root / "root.ext4"
        with image.open("wb") as stream:
            stream.truncate(12 * 1024**3)
        uuid = "7a1a6d79-2db5-47b7-87f4-7dbdd9595102"
        seed = "4a696d42-6f75-4769-8f73-43616a756e21"
        features = (
            "ext_attr,dir_index,filetype,extent,64bit,flex_bg,"
            "sparse_super,large_file,huge_file,dir_nlink,extra_isize,metadata_csum"
        )
        environment = os.environ | {
            "LC_ALL": "C", "TZ": "UTC", "MKE2FS_CONFIG": "/dev/null",
            "E2FSPROGS_FAKE_TIME": "1",
        }
        subprocess.run(
            [
                "/usr/sbin/mke2fs", "-q", "-b", "4096", "-g", "32768",
                "-G", "16", "-i", "16384", "-I", "256", "-m", "0",
                "-o", "linux", "-e", "continue", "-L", "CAJUNOS_ROOT",
                "-U", uuid,
                "-E", f"lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0,"
                f"root_perms=0755,hash_seed={seed},nodiscard",
                "-O", f"none,{features}",
                image,
            ], check=True, env=environment,
        )
        subprocess.run(
            ["/usr/sbin/tune2fs", "-j", "-J", "size=64", image],
            check=True, env=environment,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        image.chmod(0o644)
        result = self.run_internal(
            "validate-ext4", image, uuid, seed, image.stat().st_size, 1, "pristine"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        subprocess.run(
            ["/usr/sbin/tune2fs", "-O", "metadata_csum_seed", image], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        result = self.run_internal(
            "validate-ext4", image, uuid, seed, image.stat().st_size, 1, "pristine"
        )
        self.assertNotEqual(result.returncode, 0)
        subprocess.run(
            ["/usr/sbin/tune2fs", "-O", "^metadata_csum_seed", image], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        subprocess.run(["/usr/sbin/tune2fs", "-O", "^has_journal", image], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result = self.run_internal(
            "validate-ext4", image, uuid, seed, image.stat().st_size, 1, "pristine"
        )
        self.assertNotEqual(result.returncode, 0)

    def runtime_root(self, name: str = "runtime") -> Path:
        root = self.root / name
        for directory in (
            "etc/dropbear", "root/.ssh", "tmp", "bin", "lib", "lib64",
            "usr/bin", "usr/sbin", "usr/lib",
        ):
            (root / directory).mkdir(parents=True, exist_ok=True)
        files = {
            "etc/passwd": "root:x:0:0:root:/root:/bin/ash\n",
            "etc/shadow": "root:!:0:0:99999:7:::\n",
            "etc/shells": "/bin/ash\n/bin/sh\n",
            "etc/nsswitch.conf": "passwd: files\ngroup: files\nshadow: files\nhosts: files dns\nnetworks: files\n",
            "etc/ld.so.conf": "/lib\n/usr/lib\n/lib64\n/usr/lib64\n",
        }
        for relative, value in files.items():
            (root / relative).write_text(value)
        result = subprocess.run(
            [
                "gcc", "-shared", "-fPIC", "-nostdlib",
                "-Wl,-soname,ld-linux-x86-64.so.2", "-x", "c", "-",
                "-o", root / "lib/ld.so",
            ],
            input="void cajunos_loader_fixture(void) {}\n", text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        (root / "lib64/ld-linux-x86-64.so.2").symlink_to("/lib/ld.so")
        modules = (
            (
                "libresolv.so.2", "resolver_probe",
                '#include <stdio.h>\nint resolver_probe(void) { return puts("resolver"); }\n',
                [],
            ),
            (
                "libnss_files.so.2", "files_probe",
                '#include <stdio.h>\nint files_probe(void) { return puts("files"); }\n',
                [],
            ),
            (
                "libnss_dns.so.2", "dns_probe",
                (
                    '#include <stdio.h>\nextern int resolver_probe(void);\n'
                    'int dns_probe(void) { puts("dns"); return resolver_probe(); }\n'
                ),
                [f"-L{root / 'usr/lib'}", "-Wl,-rpath-link," + str(root / "usr/lib"),
                 "-Wl,--no-as-needed", "-l:libresolv.so.2"],
            ),
        )
        for soname, _symbol, source, libraries in modules:
            result = subprocess.run(
                [
                    "gcc", "-shared", "-fPIC", f"-Wl,-soname,{soname}",
                    "-x", "c", "-", "-o", root / f"usr/lib/{soname}",
                    *libraries,
                ],
                input=source,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
        for relative in (
            "usr/bin/gcc", "usr/bin/g++", "usr/bin/make", "usr/bin/ar",
            "usr/bin/as", "usr/bin/ld", "usr/sbin/dropbear", "usr/bin/dropbearkey",
        ):
            path = root / relative
            path.write_text("binary")
            path.chmod(0o755)
        return root

    def test_runtime_root_validator_binds_account_loader_and_nss(self) -> None:
        root = self.runtime_root()
        result = self.run_internal("validate-runtime-root", root)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["nss"]["order"], ["files", "dns"])
        self.assertEqual(
            set(value["nss"]["modules"]),
            {"libnss_files.so.2", "libnss_dns.so.2"},
        )
        self.assertEqual(value["nss"]["resolver"]["soname"], "libresolv.so.2")
        (root / "etc/shells").write_text("/bin/sh\n")
        result = self.run_internal("validate-runtime-root", root)
        self.assertNotEqual(result.returncode, 0)

    def test_runtime_root_rejects_missing_or_wrong_dns_nss_module(self) -> None:
        root = self.runtime_root()
        dns = root / "usr/lib/libnss_dns.so.2"
        dns.unlink()
        result = self.run_internal("validate-runtime-root", root)
        self.assertNotEqual(result.returncode, 0)
        shutil.copyfile(root / "usr/lib/libnss_files.so.2", dns)
        result = self.run_internal("validate-runtime-root", root)
        self.assertNotEqual(result.returncode, 0)

    def test_runtime_root_rejects_invalid_loader_symlink_targets(self) -> None:
        for label in ("broken", "directory", "non-executable"):
            with self.subTest(label=label):
                root = self.runtime_root(f"runtime-{label}")
                target = root / "lib/ld.so"
                target.unlink()
                if label == "directory":
                    target.mkdir()
                elif label == "non-executable":
                    target.write_bytes(b"not an executable ELF")
                    target.chmod(0o644)
                result = self.run_internal("validate-runtime-root", root)
                self.assertNotEqual(result.returncode, 0)

    def test_qemu_probe_exercises_local_dns_resolution_without_egress(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        probe = text.split("cat > dns-server.c <<'EOF'", 1)[1].split(
            "/bin/cp -a /usr/src/cajunos/dropbear", 1
        )[0]
        self.assertIn("INADDR_LOOPBACK", probe)
        self.assertIn("htons(53)", probe)
        self.assertIn("cajunos-nss-probe.invalid", probe)
        self.assertIn("nameserver 127.0.0.1", probe)
        self.assertIn("hosts: dns", probe)
        self.assertIn("192.0.2.123", probe)
        self.assertIn("getaddrinfo", probe)
        self.assertIn("restore_resolver_configuration", probe)
        self.assertIn('"dns_resolution": True', text)

    def test_source_authentication_precedes_global_source_lock(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        verify = text.index('archive_validation_json=$("$archive_verifier" validate')
        lock = text.index('exec 8>"$upstream/.cajunos-source.lock"')
        recapture = text.index("archive_cache_json=$(python3", lock)
        self.assertLess(verify, lock)
        self.assertLess(lock, recapture)

    def test_completed_replay_rebinds_full_receipt_and_regenerated_inputs(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        completed = text.split("validate_existing_result() {", 1)[1].split(
            "run_qemu_probes() {", 1
        )[0]
        candidate = text.split("validate_candidate() {", 1)[1].split(
            'validate_inputs\nvalidate_candidate', 1
        )[0]
        self.assertIn("validate_stage9b_receipt_contract", completed)
        self.assertIn("validate_stage9b_receipt_contract", candidate)
        for name, regenerated in (
            ("archive-source-inventory.json", "archive-sources.json"),
            ("base-root-inventory.json", "base-root.json"),
            ("base-root-foundation.json", "base-root-foundation.json"),
        ):
            self.assertIn(name, completed)
            self.assertIn(regenerated, completed)
            self.assertIn(name, candidate)
        contract = text.split("validate_stage9b_receipt_contract() {", 1)[1].split(
            "exec 9>", 1
        )[0]
        for field in (
            "source_date_epoch", "base_system.disk_sha256",
            "source_sets.base_system.authentication", "orchestration.commit",
            "kernel.release", "filesystem.directory_hash_seed", "disk.format",
            "owner_ssh_key.fingerprint", "security_contract.sftp",
            "security_contract.inetd", "security_contract.pubkey_options",
            "network.resolver_probe", "native_toolchain.capability",
            "build_contract.host_contract_sha256",
            "template_contract.deployment_and_vm118_template",
        ):
            self.assertIn(field, contract)

        expected = self.write("regenerated-expected.json", '{"schema": 1}\n')
        actual = self.write("regenerated-actual.json", '{"schema": 1}\n')
        result = self.run_internal("compare-json", expected, actual)
        self.assertEqual(result.returncode, 0, result.stderr)
        actual.write_text('{"schema": 2}\n')
        result = self.run_internal("compare-json", expected, actual)
        self.assertNotEqual(result.returncode, 0)

    def test_receipt_validation_rejects_uninventoried_claim_mutations(self) -> None:
        build_id = "native-developer-base-1234567890abcdef"
        release = "7.2.0-rc6-cajunos+"
        nonce = "n" * 64
        artifact = self.root / "receipt-artifact"
        for name in ("boot", "configuration", "licenses", "probe"):
            (artifact / name).mkdir(parents=True)
        root_inventory = {"entries": {}, "digest": "root-inventory"}
        for name in ("rootfs-a.json", "rootfs-b.json"):
            (artifact / "configuration" / name).write_text(
                json.dumps(root_inventory) + "\n"
            )
        omitted = [
            {
                "kind": "pem-private-test-key", "path": path,
                "reason": "private-test-fixture-not-shipped", "sha256": digest,
            }
            for path, digest in (
                ("libtomcrypt/testprof/test.key", "76ec7faebdc42a4de35ca70024c2d273e9f7856ca61612e89f5f66350ba8cf5f"),
                ("libtomcrypt/tests/test.key", "76ec7faebdc42a4de35ca70024c2d273e9f7856ca61612e89f5f66350ba8cf5f"),
                ("libtomcrypt/tests/test_dsa.key", "8a44ced5b373b6124f56bb33577a98585cce3d65671e5303384c4236f9b4d41c"),
            )
        ]
        omitted.append({
            "kind": "embedded-private-host-key-fixture",
            "path": "fuzz/fuzz-hostkeys.c",
            "reason": "private-test-fixture-not-shipped",
            "sha256": "0370305b5582f7375fc00e84ff80b49945cb04e93c401ed11194124b390ee92c",
        })
        omission_path = artifact / "configuration/omitted-private-test-fixtures.json"
        omission_path.write_text(json.dumps({"schema": 1, "omitted": omitted}) + "\n")
        omission_path.chmod(0o644)

        public_keys = {}
        for name in ("a", "b", "owner"):
            _private, public = self.generate_key(f"receipt-{name}")
            public_keys[name] = " ".join(public.read_text().split()[:2])
        host_hash = hashlib.sha256((public_keys["a"] + "\n").encode()).hexdigest()
        owner_hash = hashlib.sha256(
            (public_keys["owner"] + "\n").encode()
        ).hexdigest()

        def positive(key: str) -> bytes:
            return ("\r\n".join((
                "CAJUNOS_NATIVE_DEVELOPER_BEGIN",
                f"CAJUNOS_NATIVE_DEVELOPER_BUILD_ID {build_id}",
                "CAJUNOS_NATIVE_DEVELOPER_ROOT_OK",
                "CAJUNOS_NATIVE_DEVELOPER_NETWORK_OK",
                "CAJUNOS_NATIVE_DEVELOPER_IPV4 10.0.2.15",
                f"CAJUNOS_NATIVE_DEVELOPER_SSH_HOST_KEY {key}",
                "CAJUNOS_NATIVE_DEVELOPER_SSH_READY",
                f"CAJUNOS_NATIVE_DEVELOPER_UNAME {release}",
                "CAJUNOS_NATIVE_DEVELOPER_OK", "",
            ))).encode()

        def serial(name: str, raw: bytes) -> None:
            (artifact / "probe" / f"{name}.serial.raw").write_bytes(raw)
            (artifact / "probe" / f"{name}.serial.normalized").write_bytes(
                raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            )

        serial("first-a", positive(public_keys["a"]))
        serial("second-a", positive(public_keys["a"]))
        serial("first-b", positive(public_keys["b"]))
        serial("owner", positive(public_keys["owner"]))
        serial(
            "negative",
            b"CAJUNOS_NATIVE_DEVELOPER_BEGIN\r\n"
            b"CAJUNOS_NATIVE_DEVELOPER_FAIL cmdline-token\r\n",
        )
        ssh_evidence = self.ssh_evidence(build_id, nonce, host_hash)
        (artifact / "probe/ssh-evidence.json").write_text(
            json.dumps(ssh_evidence) + "\n"
        )
        git_names = {
            "binutils", "gcc", "glibc", "linux", "busybox", "grub",
            "gnulib", "dropbear",
        }
        archive_names = {"make", "gmp", "mpfr", "mpc"}
        sources = {
            name: {"commit": "locked", "tree": "locked", "repository": "locked"}
            for name in git_names
        } | {
            name: {
                "version": "locked", "archive_sha256": "a" * 64,
                "signature_sha256": "s" * 64,
            }
            for name in archive_names
        }
        receipt = {
            "schema": 1, "component": "system-image",
            "stage": "native-developer-seed", "build_id": build_id,
            "deployable": True, "diagnostic_only": False,
            "target": "x86_64-cajunos-linux-gnu", "source_date_epoch": 1,
            "base_system": {
                "build_id": "base", "receipt": "/base/receipt.json",
                "receipt_sha256": "r" * 64, "disk_sha256": "d" * 64,
                "consumption": "explicit-validated-receipt-artifact-and-root-inventory",
            },
            "source_sets": {
                name: {"digest": "digest", "authentication": "authenticated"}
                for name in ("bootstrap", "base_system", "native_git", "native_archives")
            },
            "sources": sources,
            "orchestration": {
                "commit": "locked", "tree": "locked", "recipe_sha256": "recipe",
                "overlay_digest": "overlay",
            },
            "dependencies": {
                "sealed_cross_gcc": {"build_id": "gcc", "prefix": "/tools"},
                "sealed_glibc": {"build_id": "glibc", "snapshot": "/sysroot"},
            },
            "kernel": {
                "version": "7.2.0-rc6", "release": release,
                "root_selector": "PARTUUID", "unix98_ptys": True, "devpts": True,
            },
            "bootloader": {
                "name": "GRUB", "platform": "i386-pc", "firmware": "SeaBIOS",
                "inheritance": "Stage-9A-MBR-and-BIOS-partition-byte-preserved",
            },
            "filesystem": {
                "type": "ext4", "bytes": 12 * 1024**3, "uuid": "uuid",
                "journal": True, "state": "clean", "forced_fsck": True,
                "directory_hash_seed": "seed",
            },
            "disk": {
                "format": "raw-gpt-bios", "bytes": 16 * 1024**3,
                "sha256": "disk", "guid": "guid", "bios_boot_partuuid": "bios",
                "root_partuuid": "root", "root_filesystem_bytes": 12 * 1024**3,
                "in_partition_growth_reserve_bytes": 1,
            },
            "network": {
                "driver": "virtio-net", "interface": "eth0",
                "configuration": "udhcpc-dhcpv4",
                "serial_discovery": "CAJUNOS_NATIVE_DEVELOPER_IPV4-canonical-ipv4",
                "resolver_probe": "loopback-udp-dns-getaddrinfo-no-egress",
            },
            "owner_ssh_key": {
                "algorithm": "ssh-ed25519", "fingerprint": "fingerprint",
                "input_sha256": "input", "canonical_sha256": "canonical",
                "authorized_keys_path": "/root/.ssh/authorized_keys",
                "private_key_on_forge": False, "agent_forwarded_to_forge": False,
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
                "components": [
                    "binutils", "gcc", "g++", "libgcc", "libatomic",
                    "libstdc++", "make", "gmp", "mpfr", "mpc",
                ],
                "resident_sources": True,
                "source_sanitization": {
                    "policy": "three-standalone-pem-plus-one-embedded-host-key-fixture-omitted-public-crypto-c-vectors-source-bound",
                    "manifest_sha256": hashlib.sha256(
                        omission_path.read_bytes()
                    ).hexdigest(),
                    "records": omitted,
                },
                "capability": "package-build-capable-not-full-self-host",
            },
            "qemu": {
                "path": "/qemu", "sha256": "q" * 64,
                "qemu_img_path": "/qemu-img", "qemu_img_sha256": "i" * 64,
                "machine": "pc-q35-10.0", "accelerator": "tcg",
                "cpu": "Nehalem-v1", "firmware": {"path": "/bios", "sha256": "b" * 64},
                "positive_cmdline": "positive", "negative_cmdline": "negative",
                "negative_boot": "exact-cmdline-token-fail-closed",
                "persistence_nonce": nonce, "host_key_sha256": host_hash,
                "owner_proof_host_key_sha256": owner_hash,
                "post_shutdown_forced_fsck": True,
            },
            "build_contract": {
                "independent_builds": 2, "host_contract_sha256": "host",
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
                "independent_builds": 2, "native_payload_identical": True,
                "rootfs_inventory_identical": True, "rootfs_ext4_identical": True,
                "gpt_disk_identical": True, "base_disk_immutable_after_probes": True,
                "selectors_modified": False, "rootfs_inventory": root_inventory,
            },
            "probe_summary": ssh_evidence,
            "outputs": {"subtree_inventories": {}},
        }
        for name in ("boot", "configuration", "licenses", "probe"):
            result = self.run_internal("inventory", artifact / name)
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt["outputs"]["subtree_inventories"][name] = json.loads(result.stdout)
        receipt_path = artifact / "receipt.json"
        receipt_path.write_text(json.dumps(receipt) + "\n")
        receipt_path.chmod(0o644)
        result = self.run_internal(
            "validate-receipt", receipt_path, artifact, build_id,
            "sources.dropbear.commit", "locked",
            "qemu.firmware.sha256", "b" * 64,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        for label, path, value in (
            ("source", ("sources", "dropbear", "commit"), "mutated"),
            ("firmware", ("qemu", "firmware", "sha256"), "mutated"),
            ("probe-summary", ("probe_summary", "boot"), "mutated"),
        ):
            with self.subTest(label=label):
                changed = json.loads(json.dumps(receipt))
                target = changed
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                receipt_path.write_text(json.dumps(changed) + "\n")
                result = self.run_internal(
                    "validate-receipt", receipt_path, artifact, build_id,
                    "sources.dropbear.commit", "locked",
                    "qemu.firmware.sha256", "b" * 64,
                )
                self.assertNotEqual(result.returncode, 0)

    def test_stage9a_is_consumed_only_by_explicit_receipt_and_inventory(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("CAJUNOS_BASE_SYSTEM_BUILD_ID", text)
        self.assertIn("validate_base_receipt", text)
        self.assertIn("base-root-inventory.json", text)
        self.assertIn("explicit-validated-receipt-artifact-and-root-inventory", text)
        self.assertNotIn("latest", text.lower())

    def test_selectors_are_read_only_and_replayed(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("selector_state_is_initial", text)
        self.assertIn("reproducibility.selectors_modified False", text)
        self.assertNotIn('ln -sfn', text)
        self.assertNotIn('ln -s -f', text)

    def test_package_probes_cover_c_cxx_asm_static_atomic_archive_and_rebuild(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        for fragment in (
            "/usr/bin/gcc -O2 hello.c", "/usr/bin/gcc -O2 -static hello.c",
            "/usr/bin/g++ -O2 hello.cc", "/usr/bin/gcc -c answer.S",
            "/usr/bin/ar crD", "-latomic", "/usr/bin/make --no-builtin-rules",
            "/usr/src/cajunos/dropbear rebuild-dropbear", "PROGRAMS=dropbearkey",
        ):
            self.assertIn(fragment, text)

    def test_ssh_gates_cover_wrong_none_password_publickey_and_pty(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        for fragment in (
            "SSH unexpectedly accepted a no-key login",
            "SSH unexpectedly accepted the wrong key",
            "SSH unexpectedly accepted password authentication",
            'using "publickey"', "CAJUNOS_PTY_OK", "StrictHostKeyChecking=yes",
            "IdentityAgent=none", "IdentitiesOnly=yes",
        ):
            self.assertIn(fragment, text)

    def test_stage9b_retains_its_own_wrong_cmdline_negative_boot(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("cajunos.native_developer=0", text)
        self.assertIn("CAJUNOS_NATIVE_DEVELOPER_FAIL cmdline-token", text)
        self.assertIn("validate-serial negative", text)

    def test_completed_replay_uses_fresh_overlay_and_rechecks_inputs(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("completed-replay", text)
        self.assertIn('create -q -f qcow2 -F raw -b "$disk"', text)
        self.assertIn("CAJUNOS_NATIVE_DEVELOPER_ALREADY_COMPLETE", text)
        body = text[text.index("validate_existing_result()") : text.index("run_qemu_probes()")]
        self.assertGreaterEqual(body.count("validate_inputs"), 1)

    def test_failure_paths_quarantine_work_and_artifact(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("Quarantined failed work", text)
        self.assertIn("Quarantined failed artifact", text)
        self.assertIn(".failed-$build_id", text)

    def test_no_tracked_runtime_host_key_or_private_owner_key_exists(self) -> None:
        for path in OVERLAY.rglob("*"):
            self.assertNotIn("host_key", path.name)
            if path.is_file():
                self.assertNotIn("PRIVATE KEY", path.read_text(encoding="utf-8", errors="ignore"))
        self.assertFalse((OVERLAY / "root").exists())
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(
            'install -D -m 0600 "$key_temporary" "$root/root/.ssh/authorized_keys"',
            text,
        )

    def test_receipt_contract_names_package_limit_and_pristine_template(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("package-build-capable-not-full-self-host", text)
        self.assertIn('"resident_sources": True', text)
        self.assertIn('"post_shutdown_forced_fsck": True', text)
        self.assertIn('"authentication_logging": "foreground-stderr-to-serial-console"', text)
        self.assertIn('"source": "pristine-never-booted-stage9b-artifact-only"', text)

    def test_make_targets_and_stage9b_documentation_are_wired(self) -> None:
        makefile = (PROJECT / "Makefile").read_text(encoding="utf-8")
        for target in (
            "fetch-native-developer-git:",
            "validate-native-developer-git:",
            "fetch-native-developer-archives:",
            "validate-native-developer-archives:",
            "native-developer-preflight:",
            "native-developer-seed:",
        ):
            self.assertIn(target, makefile)
        documentation = (PROJECT / "docs/bootstrap.md").read_text(encoding="utf-8")
        self.assertIn("### Native developer seed", documentation)
        self.assertIn("package-build-capable seed", documentation)
        self.assertIn("does not deploy a VM on tower1", documentation)
        self.assertIn("pristine, never-booted Stage 9B raw artifact", documentation)


if __name__ == "__main__":
    unittest.main()
