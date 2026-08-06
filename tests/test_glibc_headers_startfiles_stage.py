#!/usr/bin/env python3

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = PROJECT_ROOT / "scripts" / "install-glibc-headers-startfiles.sh"
SOURCE_COMMIT = "0123456789abcdef0123456789abcdef01234567"


class GlibcHeadersStartfilesStageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.temporary_root = Path(self.temporary_directory.name)

    def run_internal(
        self, *arguments: object, expected_returncode: int = 0
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [
                str(INSTALLER),
                "--internal-python",
                *(str(argument) for argument in arguments),
            ],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            expected_returncode,
            msg=(
                f"unexpected exit status for {arguments!r}\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            ),
        )
        return result

    def assert_internal_fails(
        self, *arguments: object, message: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [
                str(INSTALLER),
                "--internal-python",
                *(str(argument) for argument in arguments),
            ],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        if message is not None:
            self.assertIn(message, result.stderr)
        return result

    def inventory(self, root: Path) -> dict[str, object]:
        return json.loads(self.run_internal("inventory", root).stdout)

    @staticmethod
    def sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def write_file(path: Path, contents: str | bytes, mode: int = 0o644) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(contents, bytes):
            path.write_bytes(contents)
        else:
            path.write_text(contents, encoding="utf-8")
        path.chmod(mode)

    def populate_base(self, root: Path) -> None:
        self.write_file(root / "usr/include/linux/types.h", "#define LINUX_TYPES 1\n")
        self.write_file(root / "usr/include/linux/version.h", "#define LINUX_VERSION_CODE 1\n")
        self.write_file(root / "usr/include/asm/unistd.h", "#define __NR_read 0\n")
        for path in (root, root / "usr", root / "usr/include"):
            path.chmod(0o755)

    def populate_result(self, base: Path, result: Path) -> None:
        shutil.copytree(base, result, symlinks=True)
        self.write_file(result / "usr/include/features.h", "#define __GLIBC__ 2\n")
        self.write_file(result / "usr/include/stdint.h", "typedef long int64_t;\n")
        self.write_file(
            result / "usr/include/gnu/lib-names.h",
            "#include <gnu/lib-names-64.h>\n",
        )
        self.write_file(
            result / "usr/include/gnu/lib-names-64.h",
            '#define LIBC_SO "libc.so.6"\n',
        )
        self.write_file(
            result / "usr/include/gnu/stubs.h",
            "#if defined __x86_64__ && defined __LP64__\n"
            "# include <gnu/stubs-64.h>\n"
            "#elif defined __x86_64__\n"
            "# include <gnu/stubs-x32.h>\n"
            "#else\n"
            "# include <gnu/stubs-32.h>\n"
            "#endif\n",
        )
        self.write_file(
            result / "usr/include/gnu/stubs-64.h",
            "/* Filtered from include/stubs-prologue.h. */\n"
            "#define __stub___compat_symbol 1\n",
        )
        for name in ("crt1.o", "crti.o", "crtn.o"):
            self.write_file(result / "usr/lib" / name, b"ELF64-REL-" + name.encode())

    def derived_delta(self, base: Path, result: Path, name: str) -> dict[str, object]:
        output = self.temporary_root / name
        self.run_internal("derived-delta", base, result, output)
        return json.loads(output.read_text(encoding="utf-8"))

    def test_build_id_is_stable_order_independent_and_sensitive(self) -> None:
        material = {
            "source_set_digest": "sha256:source",
            "source_authentication": "recorded-mixed",
            "source_tree": "a" * 40,
            "source_repository": "git://sourceware.org/git/glibc.git",
            "source_date_epoch": "1785990000",
            "target": "x86_64-cajunos-linux-gnu",
            "arch": "x86_64",
            "minimum_kernel": "5.4",
            "build_triplet": "x86_64-pc-linux-gnu",
            "orchestration_commit": "b" * 40,
            "orchestration_tree": "c" * 40,
            "recipe_sha256": "d" * 64,
            "helper_sha256": "e" * 64,
            "stubs_prologue_sha256": "f" * 64,
            "options_digest": "1" * 64,
            "base_build_id": "linux-uapi-headers-base",
            "base_receipt_sha256": "2" * 64,
            "base_snapshot_digest": "sha256:" + "3" * 64,
            "gcc_build_id": "gcc-stage1-base",
            "gcc_receipt_sha256": "4" * 64,
            "binutils_build_id": "binutils-stage1-base",
            "binutils_receipt_sha256": "5" * 64,
        }

        def calculate(values: dict[str, str], commit: str = SOURCE_COMMIT) -> str:
            arguments = [item for pair in values.items() for item in pair]
            return self.run_internal("build-id", commit, *arguments).stdout.strip()

        baseline = calculate(material)
        self.assertEqual(baseline, calculate(material))
        self.assertEqual(baseline, calculate(dict(reversed(tuple(material.items())))))
        self.assertRegex(
            baseline,
            r"^glibc-headers-startfiles-0123456789ab-[0-9a-f]{16}$",
        )
        self.assertNotEqual(baseline, calculate(material, "f" * 40))

        for key in material:
            with self.subTest(key=key):
                changed = dict(material)
                changed[key] += "-changed"
                self.assertNotEqual(baseline, calculate(changed))

    def test_derived_delta_is_stable_and_records_only_additions(self) -> None:
        base = self.temporary_root / "base"
        left = self.temporary_root / "left"
        right = self.temporary_root / "right"
        self.populate_base(base)
        self.populate_result(base, left)
        self.populate_result(base, right)

        left_delta = self.derived_delta(base, left, "left-delta.json")
        right_delta = self.derived_delta(base, right, "right-delta.json")
        self.assertEqual(left_delta, right_delta)
        self.assertEqual(left_delta["schema"], "sealed-base-additions-v1")
        self.assertNotIn("usr/include/linux/types.h", left_delta["added_entries"])
        self.assertEqual(
            {
                path
                for path, metadata in left_delta["added_entries"].items()
                if metadata.get("type") == "file" and path.startswith("usr/lib/")
            },
            {"usr/lib/crt1.o", "usr/lib/crti.o", "usr/lib/crtn.o"},
        )
        self.assertEqual((self.temporary_root / "left-delta.json").stat().st_mode & 0o777, 0o644)

    def test_derived_delta_rejects_any_base_mutation_or_deletion(self) -> None:
        base = self.temporary_root / "base"
        pristine = self.temporary_root / "pristine"
        self.populate_base(base)
        self.populate_result(base, pristine)

        mutations = {
            "content": lambda root: self.write_file(
                root / "usr/include/linux/types.h", "#define LINUX_TYPES 9\n"
            ),
            "mode": lambda root: os.chmod(root / "usr/include/linux/types.h", 0o600),
            "deleted": lambda root: (root / "usr/include/linux/types.h").unlink(),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = self.temporary_root / f"changed-{name}"
                shutil.copytree(pristine, changed, symlinks=True)
                mutate(changed)
                self.assert_internal_fails(
                    "derived-delta",
                    base,
                    changed,
                    self.temporary_root / f"delta-{name}.json",
                    message="sealed base entry changed or disappeared",
                )

        self.write_file(base / "usr/include/linux/version.h", "#define LINUX_VERSION_CODE 2\n")
        self.assert_internal_fails(
            "derived-delta",
            base,
            pristine,
            self.temporary_root / "base-mutated.json",
            message="sealed base entry changed or disappeared",
        )

    def test_derived_delta_rejects_runtime_and_extra_startfiles(self) -> None:
        base = self.temporary_root / "base"
        pristine = self.temporary_root / "pristine"
        self.populate_base(base)
        self.populate_result(base, pristine)
        cases = {
            "libc.so": ("usr/lib/libc.so", "forbidden runtime artifact"),
            "libc.a": ("usr/lib/libc.a", "forbidden runtime artifact"),
            "loader": ("usr/lib/ld-linux-x86-64.so.2", "forbidden runtime artifact"),
            "libgcc": ("usr/lib/libgcc_s.so.1", "forbidden runtime artifact"),
            "crtbegin": ("usr/lib/crtbegin.o", "forbidden runtime artifact"),
            "Scrt1": ("usr/lib/Scrt1.o", "unexpected glibc bootstrap addition"),
            "outside": ("etc/ld.so.conf", "unexpected glibc bootstrap addition"),
        }
        for name, (relative, message) in cases.items():
            with self.subTest(name=name):
                changed = self.temporary_root / f"runtime-{name}"
                shutil.copytree(pristine, changed, symlinks=True)
                self.write_file(changed / relative, b"forbidden")
                self.assert_internal_fails(
                    "derived-delta",
                    base,
                    changed,
                    self.temporary_root / f"runtime-{name}.json",
                    message=message,
                )

    def test_derived_delta_requires_exact_plain_mode_0644_crt_set(self) -> None:
        base = self.temporary_root / "base"
        pristine = self.temporary_root / "pristine"
        self.populate_base(base)
        self.populate_result(base, pristine)

        missing = self.temporary_root / "missing-crt"
        shutil.copytree(pristine, missing, symlinks=True)
        (missing / "usr/lib/crtn.o").unlink()
        self.assert_internal_fails(
            "derived-delta",
            base,
            missing,
            self.temporary_root / "missing-crt.json",
            message="lacks exact CRT set",
        )

        wrong_mode = self.temporary_root / "wrong-mode-crt"
        shutil.copytree(pristine, wrong_mode, symlinks=True)
        (wrong_mode / "usr/lib/crt1.o").chmod(0o755)
        self.assert_internal_fails(
            "derived-delta",
            base,
            wrong_mode,
            self.temporary_root / "wrong-mode-crt.json",
            message="unexpected glibc bootstrap addition",
        )

        symlinked = self.temporary_root / "symlinked-crt"
        shutil.copytree(pristine, symlinked, symlinks=True)
        (symlinked / "usr/lib/crti.o").unlink()
        (symlinked / "usr/lib/crti.o").symlink_to("crt1.o")
        self.assert_internal_fails(
            "derived-delta",
            base,
            symlinked,
            self.temporary_root / "symlinked-crt.json",
            message="unexpected glibc bootstrap addition",
        )

    def test_no_shared_inodes_accepts_copy_and_rejects_hardlink(self) -> None:
        base = self.temporary_root / "base"
        independent = self.temporary_root / "independent"
        linked = self.temporary_root / "linked"
        self.populate_base(base)
        shutil.copytree(base, independent, symlinks=True)
        shutil.copytree(base, linked, symlinks=True)

        self.run_internal("no-shared-inodes", base, independent)
        linked_header = linked / "usr/include/linux/types.h"
        linked_header.unlink()
        os.link(base / "usr/include/linux/types.h", linked_header)
        self.assert_internal_fails(
            "no-shared-inodes",
            base,
            linked,
            message="shares regular-file inodes with its sealed base",
        )

    def selector_layout(self, selected: str) -> tuple[Path, Path]:
        workspace = self.temporary_root / "selector-workspace"
        sysroot = workspace / "sysroot" / "cohort"
        snapshots = sysroot / "snapshots"
        snapshots.mkdir(parents=True)
        for build_id in ("linux-base", "glibc-result", selected):
            (snapshots / build_id / "usr").mkdir(parents=True, exist_ok=True)
        (sysroot / "current").symlink_to(f"snapshots/{selected}")
        (sysroot / "usr").symlink_to("current/usr")
        return workspace, sysroot

    @staticmethod
    def retarget(link: Path, target: str) -> None:
        link.unlink()
        link.symlink_to(target)

    def write_ancestry_receipt(
        self, workspace: Path, sysroot: Path, build_id: str, base_build_id: str
    ) -> None:
        receipt = {
            "build_id": build_id,
            "sysroot": str(sysroot),
            "snapshot": str(sysroot / "snapshots" / build_id),
            "base_build_id": base_build_id,
        }
        path = workspace / "artifacts" / build_id / "receipt.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(receipt), encoding="utf-8")
        path.chmod(0o644)

    def test_selector_transition_advances_only_from_the_exact_base(self) -> None:
        _, sysroot = self.selector_layout("linux-base")
        self.assertEqual(
            self.run_internal(
                "selector-state", sysroot, "linux-base", "glibc-result"
            ).stdout.strip(),
            "base",
        )
        self.assertEqual(
            self.run_internal(
                "selector-transition", sysroot, "linux-base", "glibc-result"
            ).stdout.strip(),
            "advanced",
        )
        self.assertEqual(os.readlink(sysroot / "current"), "snapshots/glibc-result")
        self.assertEqual(
            self.run_internal(
                "selector-transition", sysroot, "linux-base", "glibc-result"
            ).stdout.strip(),
            "this",
        )

    def test_selector_preserves_a_proven_transitive_descendant(self) -> None:
        workspace, sysroot = self.selector_layout("later-two")
        (sysroot / "snapshots/later-one/usr").mkdir(parents=True)
        self.write_ancestry_receipt(
            workspace, sysroot, "later-one", "glibc-result"
        )
        self.write_ancestry_receipt(workspace, sysroot, "later-two", "later-one")
        original = os.readlink(sysroot / "current")

        self.assertEqual(
            self.run_internal(
                "selector-state", sysroot, "linux-base", "glibc-result"
            ).stdout.strip(),
            "later:later-two",
        )
        self.assertEqual(
            self.run_internal(
                "selector-transition", sysroot, "linux-base", "glibc-result"
            ).stdout.strip(),
            "later:later-two",
        )
        self.assertEqual(os.readlink(sysroot / "current"), original)

    def test_selector_rejects_unproven_or_cyclic_descendants_without_rewind(self) -> None:
        workspace, sysroot = self.selector_layout("unproven")
        original = os.readlink(sysroot / "current")
        self.assert_internal_fails(
            "selector-transition",
            sysroot,
            "linux-base",
            "glibc-result",
            message="unproven later snapshot",
        )
        self.assertEqual(os.readlink(sysroot / "current"), original)

        self.write_ancestry_receipt(workspace, sysroot, "unproven", "unproven")
        self.assert_internal_fails(
            "selector-state",
            sysroot,
            "linux-base",
            "glibc-result",
            message="cyclic or unsafe",
        )
        self.assertEqual(os.readlink(sysroot / "current"), original)

    def test_selector_rejects_malformed_layout_without_mutation(self) -> None:
        _, sysroot = self.selector_layout("linux-base")
        current = sysroot / "current"
        self.retarget(current, "../outside")
        original = os.readlink(current)
        self.assert_internal_fails(
            "selector-transition",
            sysroot,
            "linux-base",
            "glibc-result",
            message="unsafe target",
        )
        self.assertEqual(os.readlink(current), original)

        self.retarget(current, "snapshots/linux-base")
        (sysroot / "usr").unlink()
        (sysroot / "usr").symlink_to("snapshots/linux-base/usr")
        self.assert_internal_fails(
            "selector-state",
            sysroot,
            "linux-base",
            "glibc-result",
            message="not the managed current/usr symlink",
        )

    @staticmethod
    def regular_hashes(root: Path) -> dict[str, str]:
        return {
            path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

    def completed_fixture(self) -> tuple[Path, Path, Path, dict[str, object]]:
        base = self.temporary_root / "completed-base"
        snapshot = self.temporary_root / "completed-snapshot"
        artifact = self.temporary_root / "completed-artifact"
        self.populate_base(base)
        self.populate_result(base, snapshot)

        options = [
            "--prefix=/usr",
            "--host=x86_64-cajunos-linux-gnu",
            "CXX=false",
            "stubs-selector=upstream-absolute-install-target",
        ]
        artifact.mkdir()
        (artifact / "configure.options").write_text(
            "\n".join(options) + "\n", encoding="utf-8"
        )
        self.write_file(artifact / "probe/header.o", b"probe")
        self.write_file(artifact / "configuration/build-a/config.log", "cross=yes\n")
        self.write_file(artifact / "licenses/glibc/COPYING", "LGPL-2.1-or-later\n")

        license_inventory = self.inventory(artifact / "licenses/glibc")
        (artifact / "license-inventory.json").write_text(
            json.dumps(license_inventory, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        result_inventory = self.inventory(snapshot)
        base_inventory = self.inventory(base)
        delta = self.derived_delta(base, snapshot, "completed-delta.json")
        result_digest = f"sha256:{result_inventory['digest']}"
        base_digest = f"sha256:{base_inventory['digest']}"
        generated_names = (
            "gnu/lib-names.h",
            "gnu/lib-names-64.h",
            "gnu/stubs.h",
            "gnu/stubs-64.h",
        )
        receipt: dict[str, object] = {
            "schema": 1,
            "build_id": "glibc-headers-startfiles-complete",
            "component": "glibc",
            "stage": "headers-startfiles",
            "source_commit": SOURCE_COMMIT,
            "source_tree": "a" * 40,
            "source_repository": "git://sourceware.org/git/glibc.git",
            "base_build_id": "linux-uapi-headers-complete",
            "base_snapshot_digest": base_digest,
            "result_snapshot_digest": result_digest,
            "functional_libc": "absent",
            "options_digest": hashlib.sha256(
                b"".join(value.encode() + b"\0" for value in options)
            ).hexdigest(),
            "configure_options": options,
            "reproducibility": {
                "independent_installations": 2,
                "inventory_schema": "paths-types-modes-sha256-symlink-targets-v1",
                "first_inventory_digest": result_digest,
                "second_inventory_digest": result_digest,
                "identical": True,
                "base_unchanged_after_build": True,
                "post_probe_inventory_digest": result_digest,
            },
            "dependencies": {
                "linux": {
                    "build_id": "linux-uapi-headers-complete",
                    "receipt_sha256": "1" * 64,
                },
                "gcc": {
                    "build_id": "gcc-stage1-complete",
                    "receipt_sha256": "2" * 64,
                },
                "binutils": {
                    "build_id": "binutils-stage1-complete",
                    "receipt_sha256": "3" * 64,
                },
            },
            "delta": delta,
            "installed_entries": result_inventory["entries"],
            "generated_header_sha256": {
                name: self.sha256(snapshot / "usr/include" / name)
                for name in generated_names
            },
            "crt_sha256": {
                name: self.sha256(snapshot / "usr/lib" / name)
                for name in ("crt1.o", "crti.o", "crtn.o")
            },
            "configuration_sha256": self.regular_hashes(artifact / "configuration"),
            "license_inventory": license_inventory,
            "outputs": {"probe_sha256": self.regular_hashes(artifact / "probe")},
        }
        receipt_path = artifact / "receipt.json"
        self.write_receipt(receipt_path, receipt)
        return receipt_path, snapshot, base, receipt

    @staticmethod
    def write_receipt(path: Path, receipt: dict[str, object]) -> None:
        path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        path.chmod(0o644)

    def validate_fixture(self, receipt_path: Path, snapshot: Path, base: Path) -> None:
        self.run_internal(
            "validate-completed",
            receipt_path,
            snapshot,
            base,
            "schema",
            "1",
            "build_id",
            "glibc-headers-startfiles-complete",
            "component",
            "glibc",
            "stage",
            "headers-startfiles",
            "source_commit",
            SOURCE_COMMIT,
            "base_build_id",
            "linux-uapi-headers-complete",
            "dependencies.linux.receipt_sha256",
            "1" * 64,
            "dependencies.gcc.receipt_sha256",
            "2" * 64,
            "dependencies.binutils.receipt_sha256",
            "3" * 64,
        )

    def refresh_snapshot_attestations(
        self,
        receipt: dict[str, object],
        snapshot: Path,
        base: Path,
        delta_name: str,
    ) -> None:
        result_inventory = self.inventory(snapshot)
        base_inventory = self.inventory(base)
        result_digest = f"sha256:{result_inventory['digest']}"
        receipt["installed_entries"] = result_inventory["entries"]
        receipt["result_snapshot_digest"] = result_digest
        receipt["base_snapshot_digest"] = f"sha256:{base_inventory['digest']}"
        receipt["delta"] = self.derived_delta(base, snapshot, delta_name)
        receipt["reproducibility"] = {
            "independent_installations": 2,
            "inventory_schema": "paths-types-modes-sha256-symlink-targets-v1",
            "first_inventory_digest": result_digest,
            "second_inventory_digest": result_digest,
            "identical": True,
            "base_unchanged_after_build": True,
            "post_probe_inventory_digest": result_digest,
        }
        receipt["generated_header_sha256"] = {
            name: self.sha256(snapshot / "usr/include" / name)
            for name in (
                "gnu/lib-names.h",
                "gnu/lib-names-64.h",
                "gnu/stubs.h",
                "gnu/stubs-64.h",
            )
        }
        receipt["crt_sha256"] = {
            name: self.sha256(snapshot / "usr/lib" / name)
            for name in ("crt1.o", "crti.o", "crtn.o")
        }

    def test_completed_validation_is_idempotent_and_detects_snapshot_or_base_tampering(self) -> None:
        receipt_path, snapshot, base, _ = self.completed_fixture()
        receipt_bytes = receipt_path.read_bytes()
        snapshot_before = self.inventory(snapshot)
        self.validate_fixture(receipt_path, snapshot, base)
        self.validate_fixture(receipt_path, snapshot, base)
        self.assertEqual(receipt_path.read_bytes(), receipt_bytes)
        self.assertEqual(self.inventory(snapshot), snapshot_before)

        self.write_file(snapshot / "usr/include/features.h", "#define __GLIBC__ 9\n")
        self.assert_internal_fails(
            "validate-completed",
            receipt_path,
            snapshot,
            base,
            "schema",
            "1",
            message="full inventory validation",
        )

        self.write_file(snapshot / "usr/include/features.h", "#define __GLIBC__ 2\n")
        self.write_file(base / "usr/include/linux/types.h", "#define LINUX_TYPES 9\n")
        self.assert_internal_fails(
            "validate-completed",
            receipt_path,
            snapshot,
            base,
            "schema",
            "1",
            message="base snapshot digest is invalid",
        )

    def test_completed_validation_detects_dependency_receipt_tampering(self) -> None:
        receipt_path, snapshot, base, receipt = self.completed_fixture()
        mutations = (
            ("linux", "0" * 64),
            ("gcc", "0" * 64),
            ("binutils", "0" * 64),
        )
        for component, replacement in mutations:
            with self.subTest(component=component):
                changed = copy.deepcopy(receipt)
                changed["dependencies"][component]["receipt_sha256"] = replacement
                self.write_receipt(receipt_path, changed)
                self.assert_internal_fails(
                    "validate-completed",
                    receipt_path,
                    snapshot,
                    base,
                    "schema",
                    "1",
                    f"dependencies.{component}.receipt_sha256",
                    {"linux": "1", "gcc": "2", "binutils": "3"}[component] * 64,
                    message=(
                        "completed receipt mismatch for "
                        f"dependencies.{component}.receipt_sha256"
                    ),
                )
        self.write_receipt(receipt_path, receipt)

    def test_completed_validation_detects_generated_header_and_crt_attestation_tampering(self) -> None:
        receipt_path, snapshot, base, receipt = self.completed_fixture()

        generated = copy.deepcopy(receipt)
        generated["generated_header_sha256"]["gnu/stubs.h"] = "0" * 64
        self.write_receipt(receipt_path, generated)
        self.assert_internal_fails(
            "validate-completed",
            receipt_path,
            snapshot,
            base,
            "schema",
            "1",
            message="generated-header attestation is invalid",
        )

        crt = copy.deepcopy(receipt)
        crt["crt_sha256"]["crt1.o"] = "0" * 64
        self.write_receipt(receipt_path, crt)
        self.assert_internal_fails(
            "validate-completed",
            receipt_path,
            snapshot,
            base,
            "schema",
            "1",
            message="CRT attestation is invalid",
        )

        libc_claim = copy.deepcopy(receipt)
        libc_claim["functional_libc"] = "present"
        self.write_receipt(receipt_path, libc_claim)
        self.assert_internal_fails(
            "validate-completed",
            receipt_path,
            snapshot,
            base,
            "schema",
            "1",
            message="invalid functional-libc claim",
        )

    def test_completed_validation_enforces_real_stubs_selector_and_filtered_stubs_64(self) -> None:
        receipt_path, snapshot, base, receipt = self.completed_fixture()
        selector = snapshot / "usr/include/gnu/stubs.h"
        self.write_file(selector, "# include <gnu/stubs-64.h>\n")
        self.refresh_snapshot_attestations(receipt, snapshot, base, "selector-delta.json")
        self.write_receipt(receipt_path, receipt)
        self.assert_internal_fails(
            "validate-completed",
            receipt_path,
            snapshot,
            base,
            "schema",
            "1",
            message="selector lacks the upstream x86 ABI branches",
        )

        self.write_file(
            selector,
            "# include <gnu/stubs-64.h>\n"
            "# include <gnu/stubs-32.h>\n"
            "# include <gnu/stubs-x32.h>\n",
        )
        self.write_file(snapshot / "usr/include/gnu/stubs-64.h", "@placeholder@\n")
        self.refresh_snapshot_attestations(receipt, snapshot, base, "template-delta.json")
        self.write_receipt(receipt_path, receipt)
        self.assert_internal_fails(
            "validate-completed",
            receipt_path,
            snapshot,
            base,
            "schema",
            "1",
            message="retains template directives",
        )


if __name__ == "__main__":
    unittest.main()
