#!/usr/bin/env python3

from __future__ import annotations

import binascii
import errno
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest
import uuid


PROJECT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT / "scripts" / "build-base-system-image.sh"
MANIFEST = PROJECT / "manifests" / "base-system.json"
LOCK = PROJECT / "locks" / "base-system.lock.json"
KERNEL_FRAGMENT = PROJECT / "configs" / "x86_64-base-system.fragment"
BUSYBOX_FRAGMENT = PROJECT / "configs" / "busybox-base-system.fragment"
OVERLAY = PROJECT / "rootfs" / "base-system"

DISK_GUID = "6f53d7c2-4ed5-4e54-9a50-d9430b70f101"
BIOS_GUID = "813e4ae2-9e5f-4f2e-a37f-6e3b570ba101"
ROOT_GUID = "bbf9a847-17bc-4665-8af2-5ed2017ca102"


def make_gpt(path: Path) -> None:
    sectors = 32768
    image = bytearray(sectors * 512)
    image[510:512] = b"\x55\xaa"
    image[446 + 4] = 0xEE
    struct.pack_into("<II", image, 446 + 8, 1, sectors - 1)

    entries = bytearray(128 * 128)
    partitions = (
        (
            "21686148-6449-6e6f-744e-656564454649",
            BIOS_GUID,
            2048,
            4095,
            "BIOS-BOOT",
        ),
        (
            "0fc63daf-8483-4772-8e79-3d69d8477de4",
            ROOT_GUID,
            4096,
            sectors - 34,
            "CAJUNOS-ROOT",
        ),
    )
    for index, (type_id, unique_id, first, last, name) in enumerate(partitions):
        offset = index * 128
        entries[offset:offset + 16] = uuid.UUID(type_id).bytes_le
        entries[offset + 16:offset + 32] = uuid.UUID(unique_id).bytes_le
        struct.pack_into("<QQQ", entries, offset + 32, first, last, 0)
        encoded = name.encode("utf-16-le")
        entries[offset + 56:offset + 56 + len(encoded)] = encoded

    def header(current: int, backup: int, entries_lba: int) -> bytearray:
        value = bytearray(512)
        value[:8] = b"EFI PART"
        struct.pack_into("<III", value, 8, 0x10000, 92, 0)
        struct.pack_into("<QQQQ", value, 24, current, backup, 34, sectors - 34)
        value[56:72] = uuid.UUID(DISK_GUID).bytes_le
        struct.pack_into(
            "<QIII", value, 72, entries_lba, 128, 128,
            binascii.crc32(entries) & 0xFFFFFFFF,
        )
        struct.pack_into("<I", value, 16, binascii.crc32(value[:92]) & 0xFFFFFFFF)
        return value

    image[512:1024] = header(1, sectors - 1, 2)
    image[1024:1024 + len(entries)] = entries
    backup_entries_lba = sectors - 33
    image[backup_entries_lba * 512:backup_entries_lba * 512 + len(entries)] = entries
    image[(sectors - 1) * 512:sectors * 512] = header(sectors - 1, 1, backup_entries_lba)
    path.write_bytes(image)


class BaseSystemImageStageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.temporary_root = Path(self.temporary_directory.name)

    def internal(self, *arguments: object) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [SCRIPT, "--internal-python", *map(str, arguments)],
            cwd=PROJECT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def assert_accepts(self, *arguments: object) -> None:
        result = self.internal(*arguments)
        self.assertEqual(result.returncode, 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")

    def assert_rejects(self, *arguments: object) -> None:
        result = self.internal(*arguments)
        self.assertNotEqual(result.returncode, 0, "validator accepted a mutated fixture")

    def root_tree_fixture(self, name: str) -> Path:
        root = self.temporary_root / name
        shutil.copytree(OVERLAY, root)
        for relative in ("bin", "sbin", "root", "tmp", "var"):
            (root / relative).mkdir(parents=True, exist_ok=True)
        (root / "bin/busybox").write_bytes(b"busybox")
        (root / "sbin/init").symlink_to("../bin/busybox")
        return root

    def selected_tools_fixture(self, name: str) -> tuple[Path, Path, Path, str]:
        target = "x86_64-cajunos-linux-gnu"
        tools = self.temporary_root / name / "tools"
        selected = tools / "gcc-complete-test"
        binutils = tools / "binutils-stage1-test"
        (selected / "bin").mkdir(parents=True)
        (binutils / "bin").mkdir(parents=True)
        (binutils / target / "bin").mkdir(parents=True)
        gcc = selected / "bin" / f"{target}-gcc"
        gcc.write_bytes(b"sealed gcc")
        gcc.chmod(0o755)
        for tool in ("strip", "readelf"):
            primary = binutils / "bin" / f"{target}-{tool}"
            primary.write_bytes(f"sealed {tool}".encode())
            primary.chmod(0o755)
            os.link(primary, binutils / target / "bin" / tool)
            reported = selected / "bin" / f"{target}-{tool}"
            reported.symlink_to(os.path.relpath(primary, reported.parent))
        return tools, selected, binutils, target

    def set_named_acl(self, path: Path, specification: str) -> None:
        setfacl = shutil.which("setfacl")
        if setfacl is None:
            self.skipTest("setfacl is unavailable")
        result = subprocess.run(
            [setfacl, "-m", specification, path],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode:
            unsupported = ("not supported", "not implemented")
            if any(marker in result.stderr.lower() for marker in unsupported):
                self.skipTest(f"POSIX ACLs are unavailable: {result.stderr.strip()}")
            self.fail(f"setfacl failed: {result.stderr.strip()}")

    def receipt_fixture(self) -> tuple[Path, Path, str, list[str]]:
        artifact = self.temporary_root / "artifact"
        for name in ("boot", "configuration", "licenses", "probe"):
            (artifact / name).mkdir(parents=True)
        (artifact / "boot/disk.raw").write_bytes(b"disk")
        (artifact / "licenses/COPYING").write_text("license\n", encoding="utf-8")
        root_inventory = {"entries": {}, "digest": "root-inventory"}
        for label in ("a", "b"):
            (artifact / f"configuration/rootfs-{label}.json").write_text(
                json.dumps(root_inventory, sort_keys=True) + "\n", encoding="utf-8"
            )
        for kind in ("positive", "negative"):
            (artifact / f"probe/{kind}.serial.raw").write_text(
                f"{kind}\r\n", encoding="utf-8", newline=""
            )
            (artifact / f"probe/{kind}.serial.normalized").write_text(
                f"{kind}\n", encoding="utf-8"
            )
        inventories = {
            name: json.loads(self.internal("inventory", artifact / name).stdout)
            for name in ("boot", "configuration", "licenses", "probe")
        }
        build_id = "base-system-0d8395707651-deadbeefdeadbeef"
        receipt = {
            "schema": 1,
            "component": "system-image",
            "stage": "base-system-image",
            "build_id": build_id,
            "deployable": True,
            "diagnostic_only": False,
            "target": "x86_64-cajunos-linux-gnu",
            "source_date_epoch": 1785943083,
            "source_sets": {
                "bootstrap": {"digest": "bootstrap-digest", "authentication": "mixed"},
                "base_system": {"digest": "system-digest", "authentication": "authenticated"},
            },
            "sources": {
                "linux": {"commit": "linux-commit", "tree": "linux-tree", "repository": "linux-repo"},
                "busybox": {"commit": "busybox-commit", "tree": "busybox-tree", "repository": "busybox-repo"},
                "grub": {"commit": "grub-commit", "tree": "grub-tree", "repository": "grub-repo"},
                "gnulib": {
                    "commit": "gnulib-commit", "tree": "gnulib-tree",
                    "repository": "gnulib-repo", "purpose": "GRUB bootstrap.conf input",
                },
            },
            "orchestration": {
                "commit": "orchestration-commit", "tree": "orchestration-tree",
                "recipe_sha256": "recipe", "gcc_helper_sha256": "gcc-helper",
                "glibc_helper_sha256": "glibc-helper", "kernel_fragment_sha256": "kernel-fragment",
                "busybox_fragment_sha256": "busybox-fragment", "overlay_digest": "overlay",
            },
            "dependencies": {
                "gcc": {
                    "build_id": "gcc-id", "prefix": "/tools/gcc", "receipt": "/artifacts/gcc/receipt.json",
                    "receipt_sha256": "gcc-receipt",
                },
                "binutils": {
                    "build_id": "binutils-id", "prefix": "/tools/binutils",
                    "receipt": "/artifacts/binutils/receipt.json",
                    "receipt_sha256": "binutils-receipt",
                },
                "glibc": {
                    "build_id": "glibc-id", "snapshot": "/sysroot/glibc",
                    "receipt": "/artifacts/glibc/receipt.json", "receipt_sha256": "glibc-receipt",
                },
            },
            "kernel": {"version": "7.2.0", "release": "7.2.0-cajunos+", "modules": False, "root_selector": "PARTUUID"},
            "bootloader": {
                "name": "GRUB", "platform": "i386-pc", "firmware": "SeaBIOS",
                "installer": "source-installer", "host_grub_used": False,
            },
            "filesystem": {"type": "ext4", "bytes": 805306368, "uuid": "root-uuid", "journal": False},
            "disk": {
                "format": "raw-gpt-bios", "bytes": 1073741824, "guid": "disk-guid",
                "bios_boot_partuuid": "bios-guid", "root_partuuid": "root-guid",
            },
            "network": {"driver": "virtio-net", "interface": "eth0", "configuration": "udhcpc-dhcpv4"},
            "security_contract": {
                "cpu_mitigations": "enabled", "kaslr": "enabled", "stack_protector": "strong",
                "fortify_source": "enabled", "hardened_usercopy": "enabled",
                "root_password": "locked", "ssh": "deferred-to-stage-9b",
            },
            "qemu": {
                "path": "/usr/bin/qemu", "sha256": "qemu", "machine": "pc-q35-10.0",
                "accelerator": "tcg", "cpu": "Nehalem-v1",
                "firmware": {"path": "/usr/share/seabios/bios", "sha256": "bios"},
                "positive_boot": "disk-only-gpt-bios-grub",
                "negative_boot": "direct-kernel-same-gpt-root",
                "positive_cmdline": "positive", "negative_cmdline": "negative",
            },
            "build_contract": {
                "independent_builds": 2, "kernel_kcflags": "warning-flag",
                "busybox_install_arch_and_cross_compile_preserved": True,
                "busybox_tc": "disabled", "host_contract_sha256": "host",
                "rootfs_population": "fakeroot-mke2fs-d", "rootfs_hash_seed_locked": True,
            },
            "reproducibility": {
                "independent_builds": 2, "kernel_identical": True, "busybox_identical": True,
                "rootfs_ext4_identical": True, "gpt_disk_identical": True,
                "selectors_modified": False, "rootfs_inventory": root_inventory,
            },
            "outputs": {"subtree_inventories": inventories},
        }
        receipt_path = artifact / "receipt.json"
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        receipt_path.chmod(0o644)
        expected = [
            "schema", "1", "component", "system-image", "stage", "base-system-image",
            "build_id", build_id, "sources.linux.commit", "linux-commit",
            "dependencies.gcc.receipt_sha256", "gcc-receipt",
            "dependencies.binutils.receipt_sha256", "binutils-receipt",
            "kernel.release", "7.2.0-cajunos+", "disk.root_partuuid", "root-guid",
            "qemu.machine", "pc-q35-10.0", "security_contract.kaslr", "enabled",
            "reproducibility.gpt_disk_identical", "True",
        ]
        return artifact, receipt_path, build_id, expected

    def test_separate_source_lock_is_valid_and_complete(self) -> None:
        spec = importlib.util.spec_from_file_location("sources", PROJECT / "scripts/fetch.py")
        assert spec is not None and spec.loader is not None
        sources = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sources)
        with MANIFEST.open(encoding="utf-8") as stream:
            manifest = json.load(stream)
        with LOCK.open(encoding="utf-8") as stream:
            lock = json.load(stream)
        sources.validate_lock(manifest, MANIFEST, lock)
        self.assertEqual(manifest["selection"], "reviewed-exact-commits")
        self.assertEqual(
            {item["name"] for item in lock["components"]},
            {"busybox", "grub", "gnulib"},
        )
        self.assertEqual(lock["source_authentication"], "authenticated")
        gnulib = next(item for item in lock["components"] if item["name"] == "gnulib")
        self.assertEqual(gnulib["commit"], "9f48fb992a3d7e96610c4ce8be969cff2d61a01b")

    def test_stage_is_wired_without_mutating_bootstrap_sources(self) -> None:
        makefile = (PROJECT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("base-system-image:", makefile)
        self.assertIn("scripts/build-base-system-image.sh", makefile)
        bootstrap = json.loads((PROJECT / "manifests/bootstrap.json").read_text(encoding="utf-8"))
        self.assertEqual(
            {item["name"] for item in bootstrap["components"]},
            {"binutils", "gcc", "glibc", "linux"},
        )

    def test_config_fragments_lock_deployable_contract(self) -> None:
        kernel = KERNEL_FRAGMENT.read_text(encoding="utf-8")
        for line in (
            "CONFIG_ACPI=y", "CONFIG_PCI=y", "CONFIG_BLOCK=y",
            "CONFIG_VIRTIO_BLK=y", "CONFIG_SCSI_VIRTIO=y",
            "CONFIG_VIRTIO_NET=y", "CONFIG_EXT4_FS=y",
            "CONFIG_EFI_PARTITION=y", "CONFIG_RANDOMIZE_BASE=y",
            "CONFIG_STACKPROTECTOR_STRONG=y", "CONFIG_FORTIFY_SOURCE=y",
            "CONFIG_EXPERT=y", "CONFIG_VT=n",
        ):
            self.assertIn(line, kernel)
        self.assertIn("CONFIG_MODULES=n", kernel)
        self.assertIn(
            "# Linux CONFIG_VT defaults y when its prompt is hidden; "
            "headless VT disable requires CONFIG_EXPERT=y.",
            kernel,
        )
        self.assertLess(kernel.index("CONFIG_EXPERT=y"), kernel.index("CONFIG_VT=n"))

        busybox = BUSYBOX_FRAGMENT.read_text(encoding="utf-8")
        self.assertIn(
            "noninteractively with stdin at EOF; this revision has no olddefconfig.",
            busybox,
        )
        self.assertIn("CONFIG_STATIC=y", busybox)
        self.assertIn("CONFIG_BUSYBOX=y", busybox)
        self.assertIn("CONFIG_FEATURE_INSTALLER=y", busybox)
        self.assertIn("CONFIG_FEATURE_SH_MATH=y", busybox)
        self.assertIn(
            "# The locked revision makes FEATURE_INSTALLER depend directly on BUSYBOX.",
            busybox,
        )
        self.assertIn("CONFIG_TC=n", busybox)
        self.assertIn("CONFIG_SWAPON=y", busybox)
        self.assertIn("CONFIG_SWAPOFF=y", busybox)
        self.assertNotIn("CONFIG_SWAPONOFF", busybox)
        self.assertIn("CONFIG_USE_BB_CRYPT=y", busybox)
        self.assertIn("CONFIG_USE_BB_CRYPT_SHA=y", busybox)
        self.assertIn("CONFIG_USE_BB_CRYPT_YES=n", busybox)
        self.assertIn("CONFIG_HALT=y", busybox)
        self.assertIn("CONFIG_POWEROFF=y", busybox)
        self.assertIn("CONFIG_REBOOT=y", busybox)
        self.assertIn("CONFIG_STAT=y", busybox)
        self.assertIn("CONFIG_FEATURE_STAT_FORMAT=y", busybox)
        self.assertIn("CONFIG_TEST=y", busybox)
        self.assertIn("CONFIG_TEST1=y", busybox)
        self.assertLess(
            busybox.index("CONFIG_USE_BB_CRYPT=y"),
            busybox.index("CONFIG_USE_BB_CRYPT_SHA=y"),
        )
        self.assertIn("CONFIG_UDHCPC=y", busybox)
        self.assertIn('CONFIG_UDHCPC_DEFAULT_SCRIPT="/etc/udhcpc/default.script"', busybox)

    def test_config_validators_accept_contract_and_reject_mutations(self) -> None:
        kernel = self.temporary_root / "kernel.config"
        kernel.write_text(
            KERNEL_FRAGMENT.read_text(encoding="utf-8")
            + "\nCONFIG_64BIT=y\nCONFIG_X86_64=y\n",
            encoding="utf-8",
        )
        self.assert_accepts("validate-kernel-config", kernel)
        kernel.write_text(kernel.read_text().replace("CONFIG_VIRTIO_NET=y", "CONFIG_VIRTIO_NET=m"))
        self.assert_rejects("validate-kernel-config", kernel)

        busybox = self.temporary_root / "busybox.config"
        busybox_contract = BUSYBOX_FRAGMENT.read_text(encoding="utf-8")
        busybox.write_text(busybox_contract, encoding="utf-8")
        self.assert_accepts("validate-busybox-config", busybox)
        for symbol in (
            "CONFIG_BUSYBOX", "CONFIG_FEATURE_INSTALLER",
            "CONFIG_SWAPON", "CONFIG_SWAPOFF",
            "CONFIG_USE_BB_CRYPT", "CONFIG_USE_BB_CRYPT_SHA",
            "CONFIG_POWEROFF", "CONFIG_REBOOT",
            "CONFIG_STAT", "CONFIG_FEATURE_STAT_FORMAT", "CONFIG_TEST1",
            "CONFIG_FEATURE_SH_MATH",
        ):
            with self.subTest(symbol=symbol):
                busybox.write_text(
                    busybox_contract.replace(f"{symbol}=y", f"{symbol}=n"),
                    encoding="utf-8",
                )
                self.assert_rejects("validate-busybox-config", busybox)
        busybox.write_text(
            busybox_contract.replace("CONFIG_TC=n", "CONFIG_TC=y"),
            encoding="utf-8",
        )
        self.assert_rejects("validate-busybox-config", busybox)
        busybox.write_text(
            busybox_contract.replace(
                "CONFIG_USE_BB_CRYPT_YES=n", "CONFIG_USE_BB_CRYPT_YES=y"
            ),
            encoding="utf-8",
        )
        self.assert_rejects("validate-busybox-config", busybox)

    def test_kconfig_resolution_is_exact_and_fail_closed(self) -> None:
        fragment = self.temporary_root / "fragment"
        resolved = self.temporary_root / "resolved"
        fragment.write_text("CONFIG_ONE=y\nCONFIG_TWO=n\n", encoding="utf-8")
        resolved.write_text(
            "CONFIG_ONE=y\n# CONFIG_TWO is not set\nCONFIG_THREE=y\n",
            encoding="utf-8",
        )
        self.assert_accepts("validate-kconfig-resolution", fragment, resolved)
        resolved.write_text("# CONFIG_TWO is not set\n", encoding="utf-8")
        result = self.internal("validate-kconfig-resolution", fragment, resolved)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("omitted fragment symbol: CONFIG_ONE", result.stderr)
        resolved.write_text("CONFIG_ONE=n\n# CONFIG_TWO is not set\n", encoding="utf-8")
        result = self.internal("validate-kconfig-resolution", fragment, resolved)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("changed fragment symbol CONFIG_ONE", result.stderr)

    def test_busybox_kconfig_resolution_uses_eof_oldconfig(self) -> None:
        contents = SCRIPT.read_text(encoding="utf-8")
        recipe = contents.split("build_busybox() {", 1)[1].split("\n}", 1)[0]
        resolver = 'oldconfig \\\n      </dev/null >"$resolver_log" 2>&1'
        self.assertIn(resolver, recipe)
        self.assertNotIn("olddefconfig", recipe)
        self.assertIn("if ! env -i", recipe)
        self.assertIn(
            "warning: trying to assign nonexistent symbol", recipe
        )
        self.assertIn("|| warning_status=$?", recipe)
        self.assertIn("case $warning_status in", recipe)
        self.assertLess(recipe.index("allnoconfig"), recipe.index("merge-kconfig"))
        self.assertLess(recipe.index("merge-kconfig"), recipe.index(resolver))
        self.assertLess(
            recipe.index(resolver), recipe.index("validate-kconfig-resolution")
        )
        self.assertLess(
            recipe.index("validate-kconfig-resolution"),
            recipe.index("validate-busybox-config"),
        )

        documentation = (PROJECT / "docs/bootstrap.md").read_text(encoding="utf-8")
        self.assertIn(
            "using explicit stdin EOF because that revision has no `olddefconfig`",
            documentation,
        )
        self.assertIn("rejects any\nnonexistent-symbol assignment warning", documentation)

    def test_headless_vt_resolved_contract_requires_expert(self) -> None:
        resolved = (
            KERNEL_FRAGMENT.read_text(encoding="utf-8")
            + "\nCONFIG_64BIT=y\nCONFIG_X86_64=y\n"
        )
        kernel = self.temporary_root / "resolved-kernel.config"
        kernel.write_text(resolved, encoding="utf-8")
        self.assert_accepts("validate-kernel-config", kernel)

        for old, new, diagnostic in (
            (
                "CONFIG_EXPERT=y",
                "# CONFIG_EXPERT is not set",
                "required configuration is not enabled: CONFIG_EXPERT",
            ),
            (
                "CONFIG_VT=n",
                "CONFIG_VT=y",
                "forbidden configuration is enabled: CONFIG_VT",
            ),
        ):
            with self.subTest(mutation=new):
                kernel.write_text(resolved.replace(old, new), encoding="utf-8")
                result = self.internal("validate-kernel-config", kernel)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(diagnostic, result.stderr)

        recipe = SCRIPT.read_text(encoding="utf-8").split(
            "build_kernel() {", 1
        )[1].split("\n}", 1)[0]
        self.assertLess(recipe.index("merge-kconfig"), recipe.index("olddefconfig"))
        self.assertLess(
            recipe.index("olddefconfig"), recipe.index("validate-kernel-config")
        )

    def test_selected_tool_topology_is_exact_and_fail_closed(self) -> None:
        tools, selected, binutils, target = self.selected_tools_fixture("accepted")
        result = self.internal(
            "validate-selected-tools", tools, selected, binutils, target
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertEqual(evidence["gcc"]["links"], 1)
        self.assertEqual(evidence["strip"]["links"], 2)
        self.assertEqual(evidence["readelf"]["links"], 2)

        tools, selected, binutils, target = self.selected_tools_fixture("third-link")
        os.link(
            binutils / "bin" / f"{target}-strip",
            self.temporary_root / "escaping-strip-hardlink",
        )
        self.assert_rejects(
            "validate-selected-tools", tools, selected, binutils, target
        )

        tools, selected, binutils, target = self.selected_tools_fixture("wrong-alias")
        alias = binutils / target / "bin/strip"
        alias.unlink()
        alias.write_bytes(b"sealed strip")
        alias.chmod(0o755)
        self.assert_rejects(
            "validate-selected-tools", tools, selected, binutils, target
        )

        tools, selected, binutils, target = self.selected_tools_fixture("wrong-target")
        reported = selected / "bin" / f"{target}-strip"
        wrong = binutils / "bin" / f"{target}-readelf"
        reported.unlink()
        reported.symlink_to(os.path.relpath(wrong, reported.parent))
        self.assert_rejects(
            "validate-selected-tools", tools, selected, binutils, target
        )

    def test_overlay_is_locked_serial_dhcp_init_with_locked_root(self) -> None:
        executable_paths = {
            "etc/init.d/rcS",
            "etc/init.d/rcK",
            "etc/udhcpc/default.script",
        }
        tracked = subprocess.run(
            ["git", "ls-files", "--stage", "--", OVERLAY.relative_to(PROJECT)],
            cwd=PROJECT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        index_modes = {}
        for line in tracked.stdout.splitlines():
            mode, _object, _stage, path = line.split(maxsplit=3)
            relative = Path(path).relative_to(OVERLAY.relative_to(PROJECT)).as_posix()
            index_modes[relative] = mode
        self.assertTrue(index_modes)
        self.assertEqual(
            {relative for relative, mode in index_modes.items() if mode == "100755"},
            executable_paths,
        )
        self.assertTrue(
            all(
                mode == ("100755" if relative in executable_paths else "100644")
                for relative, mode in index_modes.items()
            )
        )

        canonical = self.internal("overlay-inventory", OVERLAY)
        self.assertEqual(canonical.returncode, 0, canonical.stderr)
        canonical_inventory = json.loads(canonical.stdout)
        shared_overlay = self.temporary_root / "shared-overlay"
        shutil.copytree(OVERLAY, shared_overlay)
        for path in [shared_overlay, *sorted(shared_overlay.rglob("*"))]:
            if path.is_symlink():
                continue
            if path.is_dir():
                path.chmod(0o2775)
            elif path.is_file():
                relative = path.relative_to(shared_overlay).as_posix()
                path.chmod(0o775 if relative in executable_paths else 0o664)
        self.assertEqual(stat.S_IMODE(shared_overlay.stat().st_mode), 0o2775)
        self.assertEqual(
            stat.S_IMODE((shared_overlay / "etc/init.d").stat().st_mode), 0o2775
        )
        shared = self.internal("overlay-inventory", shared_overlay)
        self.assertEqual(shared.returncode, 0, shared.stderr)
        self.assertEqual(json.loads(shared.stdout), canonical_inventory)
        entries = canonical_inventory["entries"]
        for relative, entry in entries.items():
            if entry["type"] == "directory":
                self.assertEqual(entry["mode"], "0755", relative)
            elif entry["type"] == "file":
                expected = (
                    "0755" if relative in executable_paths
                    else "0600" if relative == "etc/shadow"
                    else "0644"
                )
                self.assertEqual(entry["mode"], expected, relative)

        required_symlinks = {
            "etc/init.d/rcS": "rcK",
            "etc/init.d/rcK": "rcS",
            "etc/udhcpc/default.script": "../init.d/rcS",
            "etc/shadow": "passwd",
        }
        for index, (relative, target) in enumerate(required_symlinks.items()):
            fixture = self.temporary_root / f"required-symlink-{index}"
            shutil.copytree(shared_overlay, fixture, symlinks=True)
            required = fixture / relative
            required.unlink()
            required.symlink_to(target)
            self.assertTrue(required.resolve(strict=True).is_file())
            self.assert_rejects("overlay-inventory", fixture)

        unsafe = shared_overlay / "etc/hostname"
        unsafe.chmod(0o666)
        self.assert_rejects("overlay-inventory", shared_overlay)
        unsafe.chmod(0o664)
        unsafe = shared_overlay / "etc/init.d/rcS"
        unsafe.chmod(0o4775)
        self.assert_rejects("overlay-inventory", shared_overlay)
        unsafe.chmod(0o2775)
        self.assert_rejects("overlay-inventory", shared_overlay)

        rc_s = (OVERLAY / "etc/init.d/rcS").read_text(encoding="utf-8")
        self.assertIn("CAJUNOS_BASE_SYSTEM_OK", rc_s)
        self.assertIn("cajunos.base_system=1", rc_s)
        self.assertIn('$field == "cajunos.base_system=1"', rc_s)
        self.assertNotIn("grep -o", rc_s)
        self.assertIn("/proc/self/mountinfo", rc_s)
        self.assertLess(
            rc_s.index("mount -t proc"), rc_s.index("dev_mount_count=")
        )
        self.assertIn('$5 == "/dev"', rc_s)
        self.assertIn('$(field + 1) == "devtmpfs"', rc_s)
        self.assertIn("fail devtmpfs-count", rc_s)
        self.assertIn("fail devtmpfs-type", rc_s)
        self.assertIn("fail devtmpfs-mode", rc_s)
        self.assertIn("[ -c /dev/console ]", rc_s)
        self.assertIn("/sys/class/block/*", rc_s)
        self.assertIn("udhcpc", rc_s)
        self.assertNotIn("udhcpc -q", rc_s)
        self.assertIn("udhcpc -f -n -p /run/udhcpc.eth0.pid", rc_s)
        self.assertIn("udhcpc_pid=$!", rc_s)
        self.assertIn('dhcp_wait=$((dhcp_wait + 1))', rc_s)
        self.assertIn('[ "$dhcp_wait" -ge 15 ]', rc_s)
        self.assertIn('wait "$udhcpc_pid"', rc_s)
        self.assertIn('[ "$pidfile_pid" = "$udhcpc_pid" ]', rc_s)
        self.assertIn('/bin/kill -0 "$udhcpc_pid"', rc_s)
        self.assertIn("fail dhcp-renewal", rc_s)
        self.assertEqual((OVERLAY / "etc/shadow").read_text().split(":", 2)[1], "!")

    def test_root_tree_modes_are_canonicalized_before_ext4_population(self) -> None:
        executable_paths = {
            "bin/busybox",
            "etc/init.d/rcS",
            "etc/init.d/rcK",
            "etc/udhcpc/default.script",
        }
        root = self.temporary_root / "root"
        shutil.copytree(OVERLAY, root)
        for relative in ("bin", "sbin", "boot/grub", "root", "tmp"):
            (root / relative).mkdir(parents=True, exist_ok=True)
        (root / "bin/busybox").write_bytes(b"busybox")
        (root / "boot/grub/grub.cfg").write_text("serial\n", encoding="utf-8")
        (root / "sbin/init").symlink_to("../bin/busybox")
        for path in [root, *sorted(root.rglob("*"))]:
            if path.is_symlink():
                continue
            if path.is_dir():
                path.chmod(0o2775)
            elif path.is_file():
                relative = path.relative_to(root).as_posix()
                path.chmod(0o775 if relative in executable_paths else 0o664)
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o2775)
        self.assertEqual(stat.S_IMODE((root / "etc").stat().st_mode), 0o2775)
        self.assertEqual(stat.S_IMODE((root / "root").stat().st_mode), 0o2775)

        result = self.internal("canonicalize-root", root)
        self.assertEqual(result.returncode, 0, result.stderr)
        inventory = json.loads(result.stdout)["entries"]
        for relative, entry in inventory.items():
            path = root if relative == "." else root / relative
            self.assertEqual(entry["mode"], f"{stat.S_IMODE(path.lstat().st_mode):04o}")
            if entry["type"] == "directory":
                expected = "0700" if relative == "root" else "1777" if relative == "tmp" else "0755"
            elif entry["type"] == "file":
                expected = (
                    "0755" if relative in executable_paths
                    else "0600" if relative == "etc/shadow"
                    else "0644"
                )
            else:
                expected = "0777"
            self.assertEqual(entry["mode"], expected, relative)
        self.assertEqual((root / "sbin/init").readlink().as_posix(), "../bin/busybox")

        recipe = SCRIPT.read_text(encoding="utf-8")
        make_root = recipe.split("make_root() {", 1)[1].split("make_ext4() {", 1)[0]
        self.assertIn('--internal-python canonicalize-root "$root"', make_root)
        self.assertNotIn('--internal-python inventory "$root"', make_root)

    def test_overlay_inventory_rejects_hard_linked_symlinks(self) -> None:
        overlay = self.temporary_root / "overlay"
        shutil.copytree(OVERLAY, overlay)
        source = overlay / "etc/safe-link"
        alias = overlay / "etc/safe-link.alias"
        source.symlink_to("hostname")
        try:
            os.link(source, alias, follow_symlinks=False)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"hard-linked symlinks are unavailable: {error}")
        self.assertEqual(source.lstat().st_nlink, 2)
        self.assertEqual(alias.lstat().st_nlink, 2)
        self.assert_rejects("overlay-inventory", overlay)

    def test_generic_inventory_and_root_reject_hard_linked_symlinks(self) -> None:
        root = self.root_tree_fixture("hardlink-root")
        source = root / "sbin/init"
        alias = root / "sbin/init.alias"
        try:
            os.link(source, alias, follow_symlinks=False)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"hard-linked symlinks are unavailable: {error}")
        self.assertEqual(source.lstat().st_nlink, 2)
        self.assertEqual(alias.lstat().st_nlink, 2)
        self.assert_rejects("inventory", root)
        self.assert_rejects("canonicalize-root", root)

    def test_tree_walkers_cannot_omit_an_unreadable_directory(self) -> None:
        overlay = self.temporary_root / "unreadable-overlay"
        shutil.copytree(OVERLAY, overlay)
        hidden = overlay / "hidden"
        hidden.mkdir()
        payload = hidden / "payload"
        payload.write_bytes(b"unsafe")
        payload.chmod(0o666)
        hidden.chmod(0o100)
        self.assertEqual(stat.S_IMODE(hidden.stat().st_mode), 0o100)
        self.assertEqual(stat.S_IMODE(payload.stat().st_mode), 0o666)
        try:
            self.assert_rejects("inventory", overlay)
            self.assert_rejects("overlay-inventory", overlay)
        finally:
            hidden.chmod(0o700)

        root = self.temporary_root / "unreadable-root"
        shutil.copytree(OVERLAY, root)
        for relative in ("bin", "sbin", "root", "tmp"):
            (root / relative).mkdir(parents=True, exist_ok=True)
        (root / "bin/busybox").write_bytes(b"busybox")
        (root / "sbin/init").symlink_to("../bin/busybox")
        hidden = root / "hidden"
        hidden.mkdir()
        payload = hidden / "payload"
        payload.write_bytes(b"unsafe")
        payload.chmod(0o666)
        hidden.chmod(0o100)
        try:
            self.assert_rejects("canonicalize-root", root)
        finally:
            hidden.chmod(0o700)

    def test_tree_walkers_reject_user_extended_attributes(self) -> None:
        overlay = self.temporary_root / "xattr-overlay"
        shutil.copytree(OVERLAY, overlay)
        try:
            os.setxattr(
                overlay, "user.cajunos-test", b"present", follow_symlinks=False
            )
        except (AttributeError, OSError) as error:
            unsupported_errors = {
                getattr(errno, "ENOTSUP", -1),
                getattr(errno, "EOPNOTSUPP", -1),
                getattr(errno, "ENOSYS", -1),
            }
            if isinstance(error, AttributeError) or error.errno in unsupported_errors:
                self.skipTest(f"user extended attributes are unavailable: {error}")
            raise
        self.assertIn("user.cajunos-test", os.listxattr(overlay, follow_symlinks=False))
        self.assert_rejects("inventory", overlay)
        self.assert_rejects("overlay-inventory", overlay)

        root = self.root_tree_fixture("xattr-root")
        os.setxattr(root, "user.cajunos-test", b"present", follow_symlinks=False)
        self.assert_rejects("canonicalize-root", root)

    def test_tree_walkers_reject_named_access_and_default_acls(self) -> None:
        overlay = self.temporary_root / "acl-overlay"
        shutil.copytree(OVERLAY, overlay)
        acl_file = overlay / "etc/hostname"
        self.set_named_acl(acl_file, "u:65534:r--")
        self.assertIn(
            "system.posix_acl_access",
            os.listxattr(acl_file, follow_symlinks=False),
        )
        self.assert_rejects("inventory", overlay)
        self.assert_rejects("overlay-inventory", overlay)

        root = self.root_tree_fixture("acl-root")
        acl_directory = root / "var"
        self.set_named_acl(acl_directory, "u:65534:r-x,d:u:65534:r-x")
        attributes = set(os.listxattr(acl_directory, follow_symlinks=False))
        self.assertIn("system.posix_acl_access", attributes)
        self.assertIn("system.posix_acl_default", attributes)
        self.assert_rejects("canonicalize-root", root)

    def test_inventory_accepts_busybox_links_but_rejects_real_escape(self) -> None:
        root = self.temporary_root / "root"
        (root / "bin").mkdir(parents=True)
        (root / "sbin").mkdir()
        (root / "bin/busybox").write_bytes(b"busybox")
        (root / "sbin/init").symlink_to("../bin/busybox")
        self.assert_accepts("inventory", root)
        (root / "sbin/init").unlink()
        (root / "sbin/init").symlink_to("../../outside")
        self.assert_rejects("inventory", root)

    def test_ext4_header_and_creation_contract_are_exact_and_fail_closed(self) -> None:
        filesystem_uuid = "7a1a6d79-2db5-47b7-87f4-7dbdd9595102"
        hash_seed = "4a696d42-6f75-4769-8f73-43616a756e21"
        header = "\n".join(
            (
                "Filesystem volume name:   CAJUNOS_ROOT",
                f"Filesystem UUID:          {filesystem_uuid}",
                "Filesystem features:      ext_attr dir_index filetype extent "
                "64bit flex_bg sparse_super large_file huge_file dir_nlink "
                "extra_isize metadata_csum",
                "Filesystem flags:         signed_directory_hash",
                "Default mount options:    user_xattr acl",
                "Filesystem state:         clean",
                "Errors behavior:          Continue",
                "Filesystem OS type:       Linux",
                "Inode count:              49152",
                "Block count:              196608",
                "Reserved block count:     0",
                "First block:              0",
                "Block size:               4096",
                "Fragment size:            4096",
                "Blocks per group:         32768",
                "Inodes per group:         8192",
                "Group descriptor size:    64",
                "Flex block group size:    16",
                "Inode size:               256",
                "Required extra isize:     32",
                "Desired extra isize:      32",
                "Default directory hash:   half_md4",
                f"Directory Hash Seed:      {hash_seed}",
                "Checksum type:            crc32c",
            )
        ) + "\n"
        header_path = self.temporary_root / "dumpe2fs.header"
        header_path.write_text(header, encoding="utf-8")
        result = self.internal(
            "validate-ext4-header", header_path, filesystem_uuid, hash_seed
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)

        mutations = {
            "plural-extent": header.replace(" filetype extent 64bit ",
                                             " filetype extents 64bit "),
            "journal": header.replace(" metadata_csum\n", " metadata_csum has_journal\n"),
            "missing-checksum": header.replace(" metadata_csum\n", "\n"),
            "orphan-file": header.replace(" metadata_csum\n", " metadata_csum orphan_file\n"),
            "block-size": header.replace("Block size:               4096",
                                         "Block size:               1024"),
            "descriptor-size": header.replace("Group descriptor size:    64",
                                              "Group descriptor size:    32"),
            "flex-size": header.replace("Flex block group size:    16",
                                        "Flex block group size:    8"),
            "dirty-state": header.replace("Filesystem state:         clean",
                                          "Filesystem state:         not clean"),
            "mount-option": header.replace("user_xattr acl", "user_xattr acl quota"),
            "filesystem-flag": header.replace(
                "signed_directory_hash", "signed_directory_hash unsigned_directory_hash"
            ),
            "uuid": header.replace(filesystem_uuid, "00000000-0000-0000-0000-000000000000"),
            "hash-seed": header.replace(hash_seed, "00000000-0000-0000-0000-000000000000"),
            "duplicate-field": header + "Block size:               4096\n",
        }
        for label, mutated in mutations.items():
            with self.subTest(label=label):
                header_path.write_text(mutated, encoding="utf-8")
                self.assert_rejects(
                    "validate-ext4-header", header_path, filesystem_uuid, hash_seed
                )

        contents = SCRIPT.read_text(encoding="utf-8")
        features_line = next(
            line for line in contents.splitlines() if line.startswith("rootfs_features=")
        )
        shell_features = set(features_line.split("=", 1)[1].split(","))
        self.assertEqual(evidence["features"], sorted(shell_features))
        self.assertIn("extent", shell_features)
        self.assertNotIn("extents", shell_features)

        make_ext4 = contents.split("make_ext4() {", 1)[1].split("make_disk() {", 1)[0]
        self.assertIn("MKE2FS_CONFIG=/dev/null", make_ext4)
        self.assertNotIn("-t ext4", make_ext4)
        for option in (
            "-b 4096", "-g 32768", "-G 16", "-i 16384", "-I 256", "-m 0",
            "-o linux", "-e continue", "root_owner=0:0", "root_perms=0755",
            f"hash_seed={hash_seed}", "nodiscard", '-O "none,$5"',
            '"$rootfs_features"',
        ):
            self.assertIn(option, make_ext4)
        self.assertNotIn("^has_journal", make_ext4)
        for variable in (
            "E2FSPROGS_FAKE_TIME", "E2FSPROGS_UNDO_DIR", "MKE2FS_CONFIG",
            "MKE2FS_SYNC", "MKE2FS_FIRST_META_BG", "MKE2FS_DEVICE_SECTSIZE",
            "MKE2FS_DEVICE_PHYS_SECTSIZE", "MKE2FS_SKIP_CHECK_MSG",
        ):
            self.assertIn(variable, contents)

        validate_candidate = contents.split("validate_candidate() {", 1)[1].split(
            "validate_complete() {", 1
        )[0]
        self.assertEqual(validate_candidate.count("validate-ext4 \\\n"), 2)
        self.assertIn('"$build/root-a.ext4" "$root_uuid"', validate_candidate)
        self.assertIn('"$build/root-b.ext4" "$root_uuid"', validate_candidate)
        self.assertLess(
            validate_candidate.index('cmp -- "$build/root-a.ext4"'),
            validate_candidate.index('"$build/root-a.ext4" "$root_uuid"'),
        )

    def test_gpt_validator_and_rootless_grub_patcher(self) -> None:
        disk = self.temporary_root / "disk.raw"
        make_gpt(disk)
        self.assert_accepts("validate-gpt", disk, DISK_GUID, BIOS_GUID, ROOT_GUID, 4096)
        bad_mbr = self.temporary_root / "bad-mbr.raw"
        bad_mbr.write_bytes(disk.read_bytes())
        with bad_mbr.open("r+b") as stream:
            stream.seek(446 + 8)
            stream.write(struct.pack("<I", 123))
        self.assert_rejects("validate-gpt", bad_mbr, DISK_GUID, BIOS_GUID, ROOT_GUID, 4096)
        no_backup = self.temporary_root / "no-backup.raw"
        no_backup.write_bytes(disk.read_bytes())
        with no_backup.open("r+b") as stream:
            stream.seek(-512, 2)
            stream.write(b"\0" * 512)
        self.assert_rejects("validate-gpt", no_backup, DISK_GUID, BIOS_GUID, ROOT_GUID, 4096)

        boot = self.temporary_root / "boot.img"
        boot_data = bytearray(512)
        boot_data[:3] = b"\xeb\x63\x90"
        boot_data[510:] = b"\x55\xaa"
        boot.write_bytes(boot_data)
        core = self.temporary_root / "core.img"
        core_data = bytearray(1537)
        core_data[:2] = b"RV"
        struct.pack_into("<QHH", core_data, 500, 0, 0, 0x0820)
        core.write_bytes(core_data)
        self.assert_accepts("install-grub-raw", disk, boot, core, 2048, 2048)
        self.assert_accepts("validate-gpt", disk, DISK_GUID, BIOS_GUID, ROOT_GUID, 4096)
        installed = disk.read_bytes()
        self.assertEqual(struct.unpack_from("<Q", installed, 0x5C)[0], 2048)
        self.assertEqual(installed[0x64], 0xFF)
        self.assertEqual(struct.unpack_from("<QHH", installed, 2048 * 512 + 500), (2049, 3, 0x0820))

        bad_core = self.temporary_root / "bad-core.img"
        bad_core.write_bytes(core_data[:511])
        self.assert_rejects("install-grub-raw", disk, boot, bad_core, 2048, 2048)

    def test_serial_contract_is_positive_and_fail_closed(self) -> None:
        build_id = "base-system-0d8395707651-deadbeefdeadbeef"
        release = "7.2.0-rc6-cajunos+"
        positive = self.temporary_root / "positive.raw"
        positive.write_text(
            "\r\n".join(
                (
                    "CAJUNOS_BASE_SYSTEM_BEGIN",
                    f"CAJUNOS_BASE_SYSTEM_BUILD_ID {build_id}",
                    "CAJUNOS_BASE_SYSTEM_ROOT_OK",
                    "CAJUNOS_BASE_SYSTEM_NETWORK_OK",
                    f"CAJUNOS_BASE_SYSTEM_UNAME {release}",
                    "CAJUNOS_BASE_SYSTEM_OK",
                )
            ) + "\r\n",
            encoding="utf-8",
        )
        self.assert_accepts("validate-serial", "positive", positive, release, build_id)
        negative = self.temporary_root / "negative.raw"
        negative.write_text(
            "CAJUNOS_BASE_SYSTEM_BEGIN\nCAJUNOS_BASE_SYSTEM_FAIL cmdline-token\n",
            encoding="utf-8",
        )
        self.assert_accepts("validate-serial", "negative", negative, release, build_id)
        negative.write_text(negative.read_text() + "CAJUNOS_BASE_SYSTEM_OK\n")
        self.assert_rejects("validate-serial", "negative", negative, release, build_id)

    def test_serial_normalizes_only_the_exact_grub_prologue(self) -> None:
        build_id = "base-system-0d8395707651-deadbeefdeadbeef"
        release = "7.2.0-rc6-cajunos+"
        transcript = "\r\n".join(
            (
                "  Booting `CajunOS base system'",
                "CAJUNOS_BASE_SYSTEM_BEGIN",
                f"CAJUNOS_BASE_SYSTEM_BUILD_ID {build_id}",
                "CAJUNOS_BASE_SYSTEM_ROOT_OK",
                "CAJUNOS_BASE_SYSTEM_NETWORK_OK",
                f"CAJUNOS_BASE_SYSTEM_UNAME {release}",
                "CAJUNOS_BASE_SYSTEM_OK",
            )
        ).encode() + b"\r\n"
        prologue = b"\x1b[H\x1b[J\x1b[1;1H"
        raw = self.temporary_root / "grub-positive.raw"
        normalized = self.temporary_root / "grub-positive.normalized"
        raw.write_bytes(prologue + transcript)
        self.assert_accepts(
            "validate-serial", "positive", raw, release, build_id, normalized
        )
        self.assertEqual(normalized.read_bytes(), transcript.replace(b"\r\n", b"\n"))

        for label, mutation in (
            ("wrong", b"\x1b[J" + transcript),
            ("repeated", prologue + prologue + transcript),
            ("embedded", transcript + b"\x1b[J"),
        ):
            with self.subTest(label=label):
                raw.write_bytes(mutation)
                self.assert_rejects(
                    "validate-serial", "positive", raw, release, build_id
                )

    def test_receipt_contract_rejects_semantic_and_topology_tampering(self) -> None:
        artifact, receipt_path, build_id, expected = self.receipt_fixture()
        self.assert_accepts("validate-receipt", receipt_path, artifact, build_id, *expected)
        original = json.loads(receipt_path.read_text(encoding="utf-8"))
        mutations = {
            "source": ("sources.linux.commit", "other-linux"),
            "dependency": ("dependencies.gcc.receipt_sha256", "other-gcc"),
            "binutils-dependency": (
                "dependencies.binutils.receipt_sha256", "other-binutils"
            ),
            "kernel": ("kernel.release", "other-kernel"),
            "disk": ("disk.root_partuuid", "other-root"),
            "qemu": ("qemu.machine", "other-machine"),
            "security": ("security_contract.kaslr", "disabled"),
            "reproducibility": ("reproducibility.gpt_disk_identical", False),
        }
        for label, (key, value) in mutations.items():
            with self.subTest(label=label):
                changed = json.loads(json.dumps(original))
                target = changed
                parts = key.split(".")
                for part in parts[:-1]:
                    target = target[part]
                target[parts[-1]] = value
                receipt_path.write_text(
                    json.dumps(changed, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                )
                self.assert_rejects("validate-receipt", receipt_path, artifact, build_id, *expected)
        changed = json.loads(json.dumps(original))
        changed["unbound_claim"] = "accepted"
        receipt_path.write_text(json.dumps(changed, sort_keys=True) + "\n", encoding="utf-8")
        self.assert_rejects("validate-receipt", receipt_path, artifact, build_id, *expected)

    def test_recipe_has_reproducibility_and_no_host_grub_install(self) -> None:
        contents = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("hash_seed=4a696d42-6f75-4769-8f73-43616a756e21", contents)
        self.assertIn("install-grub-raw", contents)
        self.assertIn("grub-mkimage", contents)
        self.assertIn("snapshot=on", contents)
        self.assertIn("QEMU $kind probe mutated the sealed raw disk", contents)
        self.assertIn("GNULIB_REVISION=", contents)
        self.assertIn('chown -R 0:0 "$1"', contents)
        self.assertIn("validate-ext4", contents)
        self.assertIn('local logical_prefix=/usr', contents)
        self.assertIn('local installed_prefix=$prefix$logical_prefix', contents)
        self.assertIn(
            '-ffile-prefix-map=$source_copy=/usr/src/grub', contents
        )
        self.assertIn(
            '-fmacro-prefix-map=$source_copy=/usr/src/grub', contents
        )
        self.assertIn(
            '-fdebug-prefix-map=$source_copy=/usr/src/grub', contents
        )
        self.assertIn(
            '-ffile-prefix-map=$build=/usr/src/grub-build', contents
        )
        self.assertIn('CFLAGS="-O2 -g0 $grub_path_flags"', contents)
        self.assertIn('TARGET_CFLAGS="-Os $grub_path_flags"', contents)
        self.assertIn('--prefix="$logical_prefix"', contents)
        self.assertIn('make DESTDIR="$prefix" install', contents)
        self.assertIn(
            'local grub_prefix=$temporary_root/grub-install-$label/usr', contents
        )
        self.assertNotIn("/usr/sbin/grub-install", contents)
        self.assertNotIn("sudo ", contents)
        self.assertRegex(
            contents,
            r'make -s -C "\$busybox_source" O="\$build" ARCH=x86_64 \\\n'
            r'      CROSS_COMPILE="\$tools_prefix/bin/\$target-" \\\n'
            r'      EXTRA_CFLAGS="\$busybox_extra_cflags" \\\n'
            r'      EXTRA_LDFLAGS="\$busybox_extra_ldflags" \\\n'
            r'      CONFIG_PREFIX="\$install_root" install',
        )
        self.assertIn('busybox_extra_cflags="--sysroot=$glibc_snapshot', contents)
        self.assertIn("cohort_id=${cohort_id:0:16}", contents)
        self.assertIn("validate_live_dependencies", contents)
        self.assertIn('gcc_helper_sha256 "$gcc_helper_sha256"', contents)
        self.assertIn('strip_driver=$binutils_prefix/bin/$target-strip', contents)
        self.assertIn("trap cleanup EXIT", contents)
        self.assertIn("trap 'exit 130' INT", contents)
        self.assertIn("trap 'exit 143' TERM", contents)
        self.assertNotIn("trap cleanup EXIT INT TERM HUP", contents)
        for replay_pair in (
            'cmp -- "$build/bzImage-a" "$build/bzImage-b"',
            'cmp -- "$build/root-a.ext4" "$build/root-b.ext4"',
            'cmp -- "$build/disk-a.raw" "$build/disk-b.raw"',
            'cmp -- "$artifact/boot/bzImage" "$build/bzImage-a"',
            'cmp -- "$artifact/boot/disk.raw" "$build/disk-a.raw"',
        ):
            self.assertIn(replay_pair, contents)
        result = subprocess.run(
            ["bash", "-n", SCRIPT], cwd=PROJECT, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_binutils_replay_and_selector_checks_precede_tool_use(self) -> None:
        contents = SCRIPT.read_text(encoding="utf-8")
        tools_capture = contents.index(
            'initial_tools_selector=$(readlink -- "$tools_selector")'
        )
        tools_resolution = contents.index(
            'tools_prefix=$(readlink -f -- "$tools_root/$initial_tools_selector")'
        )
        sysroot_capture = contents.index(
            'initial_sysroot_selector=$(readlink -- "$sysroot_selector")'
        )
        sysroot_resolution = contents.index("glibc_snapshot=$(readlink -f --")
        self.assertLess(tools_capture, tools_resolution)
        self.assertLess(sysroot_capture, sysroot_resolution)
        selector_check = contents.split("selector_state_is_initial() {", 1)[1].split(
            "\n}", 1
        )[0]
        for contract in (
            'readlink -- "$tools_selector"',
            'readlink -f -- "$tools_selector"',
            'readlink -- "$sysroot_selector"',
            'readlink -f -- "$sysroot_selector"',
        ):
            self.assertIn(contract, selector_check)
        selector_confinement = contents.split(
            '[[ $tools_prefix == "$tools_root/"*', 1
        )[1].split(
            'echo "Selected dependency resolves outside its managed prefix"', 1
        )[0]
        self.assertIn(
            '$tools_prefix == "$tools_root/$initial_tools_selector"',
            selector_confinement,
        )
        self.assertIn(
            '"$sysroot_root/$cohort_id/$initial_sysroot_selector"',
            selector_confinement,
        )

        dependency_replay = contents.split(
            "validate_live_dependencies() {", 1
        )[1].split("\n}", 1)[0]
        self.assertLess(
            dependency_replay.index("validate_binutils_dependency"),
            dependency_replay.index("validate-selected-tools"),
        )
        self.assertLess(
            dependency_replay.index("validate-selected-tools"),
            dependency_replay.index(
                '"$gcc_helper" --internal-python validate-completed'
            ),
        )
        for field in ("build_id", "prefix", "receipt", "receipt_sha256"):
            self.assertIn(f"dependencies.binutils.{field}", dependency_replay)
        binutils_replay = contents.split(
            "validate_binutils_dependency() {", 1
        )[1].split("\n}", 1)[0]
        for topology_check in (
            "receipt_path.lstat()",
            "stat.S_ISREG(receipt_metadata.st_mode)",
            "stat.S_IMODE(receipt_metadata.st_mode) != 0o644",
            "receipt_metadata.st_nlink != 1",
        ):
            self.assertIn(topology_check, binutils_replay)

        live_function = contents.index("validate_live_dependencies() {")
        live_function_end = contents.index("\n}\n", live_function) + 2
        lock = contents.index('exec 9>"$work_root/.cajunos-build.lock"')
        driver_assignment = contents.index("\ngcc_driver=$tools_prefix/bin/$target-gcc")
        self.assertLess(live_function_end, driver_assignment)
        self.assertLess(driver_assignment, lock)
        self.assertNotIn(
            "\nvalidate_live_dependencies\n",
            contents[live_function_end:lock],
        )

        build_id_material = contents.split('build_id=$("$script_path"', 1)[1].split(
            "\n\nrun_id=", 1
        )[0]
        self.assertIn(
            'binutils_receipt_sha256 "$binutils_receipt_sha256"',
            build_id_material,
        )
        glibc_base_confinement = contents.split(
            'glibc_base_snapshot_name=$(basename -- "$glibc_base_snapshot")', 1
        )[1].split(
            'echo "glibc receipt base is not confined', 1
        )[0]
        self.assertIn(
            '$glibc_base_snapshot_name =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$',
            glibc_base_confinement,
        )
        self.assertIn(
            '"$sysroot_root/$cohort_id/snapshots/$glibc_base_snapshot_name"',
            glibc_base_confinement,
        )
        self.assertIn(
            '$(readlink -f -- "$glibc_base_snapshot") == "$glibc_base_snapshot"',
            glibc_base_confinement,
        )
        self.assertIn(
            '"dependencies": {"gcc", "binutils", "glibc"}', contents
        )
        for field in ("build_id", "prefix", "receipt", "receipt_sha256"):
            self.assertIn(f'"dependencies.binutils":', contents)
            self.assertIn(f"dependencies.binutils.{field}", contents)
        receipt_payload = contents.split(
            'CAJUNOS_BASE_SYSTEM_RECEIPT=$(python3 - <<\'PY\'', 1
        )[1].split("\nPY", 1)[0]
        binutils_payload = receipt_payload.split('"binutils": {', 1)[1].split(
            "\n        },", 1
        )[0]
        self.assertEqual(
            {
                line.split('"', 2)[1]
                for line in binutils_payload.splitlines()
                if line.strip().startswith('"')
            },
            {"build_id", "prefix", "receipt", "receipt_sha256"},
        )

        validate_inputs = contents.split("validate_inputs() {", 1)[1].split(
            "\n}", 1
        )[0]
        self.assertEqual(validate_inputs.count("selector_state_is_initial"), 2)
        self.assertLess(
            validate_inputs.index("selector_state_is_initial"),
            validate_inputs.index('"$project_root/scripts/fetch.py" validate'),
        )
        self.assertLess(
            validate_inputs.index("validate_live_dependencies"),
            validate_inputs.rindex("selector_state_is_initial"),
        )
        for guarded_barrier in (
            '"$project_root/scripts/fetch.py" validate --root "$cajunos_root" --json \\\n    >/dev/null || return 1',
            '--manifest "$system_manifest" --lock "$system_lock" --json >/dev/null \\\n    || return 1',
            "validate_live_dependencies || return 1",
            "selector_state_is_initial || return 1",
        ):
            self.assertIn(guarded_barrier, validate_inputs)
        for guarded_barrier in (
            "validate_binutils_dependency || return 1",
            "validate-selected-tools",
            'dependencies.binutils.receipt_sha256 "$binutils_receipt_sha256" >/dev/null \\\n    || return 1',
            'snapshot "$glibc_snapshot" >/dev/null || return 1',
        ):
            self.assertIn(guarded_barrier, dependency_replay)
        self.assertRegex(
            dependency_replay,
            r"validate-selected-tools \\\n(?:.*\\\n)*.*>/dev/null \\\n    \|\| return 1",
        )
        self.assertIn(
            "validate_inputs\nbuild_kernel a\nbuild_kernel b",
            contents,
        )
        prepublish = contents.index(
            '\nvalidate_inputs\nvalidate_candidate "$artifact_temporary"'
        )
        receipt_creation = contents.index(
            'with (artifact / "receipt.json").open("w"'
        )
        self.assertLess(receipt_creation, prepublish)

        preflight = contents.index("if [[ $preflight_only == 1 ]]; then")
        completed = contents.index("if [[ -d $build_final && ! -L $build_final")
        log_creation = contents.index('mkdir -p -- "$log_dir"')
        self.assertLess(lock, preflight)
        self.assertLess(preflight, completed)
        self.assertLess(preflight, log_creation)
        preflight_block = contents[preflight:completed]
        self.assertIn("validate_inputs", preflight_block)
        self.assertIn(
            'CAJUNOS_BASE_SYSTEM_PREFLIGHT_OK build_id=$build_id',
            preflight_block,
        )
        for forbidden in ("build_kernel", "build_busybox", "mkdir --"):
            self.assertNotIn(forbidden, preflight_block)

        validate_complete = contents.split("validate_complete() {", 1)[1].split(
            "\n}", 1
        )[0]
        self.assertNotIn("if ! (", validate_complete)
        self.assertLess(
            validate_complete.index("set +e\n  ("),
            validate_complete.index("replay_status=$?"),
        )
        self.assertLess(
            validate_complete.index("replay_status=$?"),
            validate_complete.index("if [[ $replay_status -ne 0 ]]"),
        )
        self.assertIn("validate_inputs || return 1", validate_complete)

    def test_preflight_mode_rejects_all_other_argument_shapes(self) -> None:
        for arguments in (("--unknown",), ("--preflight-only", "extra")):
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    [SCRIPT, *arguments],
                    cwd=PROJECT,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(result.returncode, 64)
                self.assertIn("Usage:", result.stderr)


if __name__ == "__main__":
    unittest.main()
