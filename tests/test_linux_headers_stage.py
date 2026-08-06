#!/usr/bin/env python3

import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = PROJECT_ROOT / "scripts" / "install-linux-headers.sh"
SOURCE_COMMIT = "0123456789abcdef0123456789abcdef01234567"


class LinuxHeadersStageTests(unittest.TestCase):
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
        self, *arguments: object, message: str
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
        self.assertIn(message, result.stderr)
        return result

    def inventory(self, root: Path) -> dict[str, object]:
        result = self.run_internal("inventory", root)
        return json.loads(result.stdout)

    @staticmethod
    def populate_header_tree(root: Path) -> None:
        include = root / "usr" / "include" / "linux"
        include.mkdir(parents=True)
        os.chmod(root, 0o755)
        os.chmod(root / "usr", 0o755)
        os.chmod(root / "usr" / "include", 0o755)
        os.chmod(include, 0o755)
        (include / "a.h").write_text("#define A 1\n", encoding="utf-8")
        (include / "b.h").write_text("#define B 2\n", encoding="utf-8")
        os.chmod(include / "a.h", 0o644)
        os.chmod(include / "b.h", 0o644)
        (include / "selected.h").symlink_to("a.h")

    def test_inventory_is_stable_for_equivalent_trees(self) -> None:
        left = self.temporary_root / "left"
        right = self.temporary_root / "right"
        self.populate_header_tree(left)
        self.populate_header_tree(right)

        left_inventory = self.inventory(left)
        right_inventory = self.inventory(right)
        self.assertEqual(left_inventory, right_inventory)

        output = self.temporary_root / "inventory.json"
        self.run_internal("compare", left, right, output)
        with output.open(encoding="utf-8") as stream:
            self.assertEqual(json.load(stream), left_inventory)
        self.assertEqual(output.stat().st_mode & 0o777, 0o644)

    def test_inventory_detects_content_mode_and_symlink_target_changes(self) -> None:
        baseline = self.temporary_root / "baseline"
        self.populate_header_tree(baseline)
        baseline_inventory = self.inventory(baseline)

        mutations = {
            "content": lambda root: (root / "usr/include/linux/a.h").write_text(
                "#define A 9\n", encoding="utf-8"
            ),
            "mode": lambda root: os.chmod(root / "usr/include/linux/a.h", 0o600),
            "symlink-target": self._retarget_selected_header,
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = self.temporary_root / f"changed-{name}"
                shutil.copytree(baseline, changed, symlinks=True)
                mutate(changed)
                self.assertNotEqual(
                    self.inventory(changed)["digest"], baseline_inventory["digest"]
                )
                self.assert_internal_fails(
                    "compare",
                    baseline,
                    changed,
                    self.temporary_root / f"{name}.json",
                    message="independent Linux header installations differ",
                )

    @staticmethod
    def _retarget_selected_header(root: Path) -> None:
        link = root / "usr/include/linux/selected.h"
        link.unlink()
        link.symlink_to("b.h")

    def test_inventory_rejects_unsafe_and_broken_symlinks(self) -> None:
        cases = {
            "absolute": ("/etc/passwd", "unsafe absolute or empty symlink"),
            "escaping": ("../outside.h", "escaping symlink"),
            "broken": ("missing.h", "broken or escaping symlink"),
        }
        for name, (target, expected_message) in cases.items():
            with self.subTest(name=name):
                root = self.temporary_root / name
                root.mkdir()
                (root / "bad.h").symlink_to(target)
                self.assert_internal_fails(
                    "inventory", root, message=expected_message
                )

    def test_inventory_rejects_special_files(self) -> None:
        root = self.temporary_root / "special"
        root.mkdir()
        os.mkfifo(root / "headers.fifo")
        self.assert_internal_fails(
            "inventory", root, message="unsupported special file"
        )

    def test_dependency_inventory_attests_internal_hardlinks(self) -> None:
        managed_root = self.temporary_root / "tools"
        prefix = managed_root / "dependency"
        (prefix / "bin").mkdir(parents=True)
        primary = prefix / "bin/tool"
        primary.write_bytes(b"sealed tool")
        os.link(primary, prefix / "bin/tool-alias")

        result = self.run_internal("dependency-inventory", prefix, managed_root)
        entries = json.loads(result.stdout)
        self.assertEqual(
            entries["bin/tool"]["sha256"], entries["bin/tool-alias"]["sha256"]
        )

        os.link(primary, self.temporary_root / "external-hardlink")
        self.assert_internal_fails(
            "dependency-inventory",
            prefix,
            managed_root,
            message="dependency hardlink escapes its attested prefix",
        )

    def test_build_id_is_deterministic_order_independent_and_sensitive(self) -> None:
        first = self.run_internal(
            "build-id", SOURCE_COMMIT, "target", "x86_64", "arch", "x86_64"
        ).stdout.strip()
        repeated = self.run_internal(
            "build-id", SOURCE_COMMIT, "target", "x86_64", "arch", "x86_64"
        ).stdout.strip()
        reordered = self.run_internal(
            "build-id", SOURCE_COMMIT, "arch", "x86_64", "target", "x86_64"
        ).stdout.strip()
        changed_value = self.run_internal(
            "build-id", SOURCE_COMMIT, "target", "i686", "arch", "x86_64"
        ).stdout.strip()
        changed_commit = self.run_internal(
            "build-id", "f" * 40, "target", "x86_64", "arch", "x86_64"
        ).stdout.strip()

        self.assertEqual(first, repeated)
        self.assertEqual(first, reordered)
        self.assertNotEqual(first, changed_value)
        self.assertNotEqual(first, changed_commit)
        self.assertRegex(
            first, r"^linux-uapi-headers-0123456789ab-[0-9a-f]{16}$"
        )

    def make_sysroot(self, current_build: str | None = None) -> Path:
        sysroot = self.temporary_root / "sysroot"
        snapshots = sysroot / "snapshots"
        snapshots.mkdir(parents=True)
        if current_build is not None:
            (snapshots / current_build / "usr").mkdir(parents=True)
            (sysroot / "current").symlink_to(f"snapshots/{current_build}")
            (sysroot / "usr").symlink_to("current/usr")
        return sysroot

    def test_current_state_reports_missing_this_and_other_without_rewinding(self) -> None:
        build_id = "linux-uapi-headers-current"
        missing = self.make_sysroot()
        self.assertEqual(
            self.run_internal("current-state", missing, build_id).stdout.strip(),
            "missing",
        )

        current = self.temporary_root / "current-sysroot"
        (current / "snapshots" / build_id / "usr").mkdir(parents=True)
        (current / "current").symlink_to(f"snapshots/{build_id}")
        (current / "usr").symlink_to("current/usr")
        self.assertEqual(
            self.run_internal("current-state", current, build_id).stdout.strip(),
            "this",
        )

        later_build = "glibc-headers-later"
        later = self.temporary_root / "later-sysroot"
        (later / "snapshots" / later_build / "usr").mkdir(parents=True)
        current_link = later / "current"
        current_link.symlink_to(f"snapshots/{later_build}")
        (later / "usr").symlink_to("current/usr")
        self.assertEqual(
            self.run_internal("current-state", later, build_id).stdout.strip(),
            f"other:{later_build}",
        )
        self.assertEqual(os.readlink(current_link), f"snapshots/{later_build}")

    def test_current_state_rejects_invalid_managed_links(self) -> None:
        build_id = "linux-uapi-headers-current"

        wrong_usr = self.make_sysroot(build_id)
        (wrong_usr / "usr").unlink()
        (wrong_usr / "usr").symlink_to("snapshots/not-current/usr")
        self.assert_internal_fails(
            "current-state",
            wrong_usr,
            build_id,
            message="usr symlink has an unexpected target",
        )

        escaping = self.temporary_root / "escaping-current"
        (escaping / "snapshots").mkdir(parents=True)
        (escaping / "current").symlink_to("../outside")
        self.assert_internal_fails(
            "current-state",
            escaping,
            build_id,
            message="current symlink has an unsafe target",
        )

        broken = self.temporary_root / "broken-current"
        (broken / "snapshots").mkdir(parents=True)
        (broken / "current").symlink_to(f"snapshots/{build_id}")
        self.assert_internal_fails(
            "current-state",
            broken,
            build_id,
            message="current symlink is broken or escaping",
        )

        real_snapshots = self.temporary_root / "real-snapshots"
        real_snapshots.mkdir()
        linked_snapshots = self.temporary_root / "linked-snapshots-sysroot"
        linked_snapshots.mkdir()
        (linked_snapshots / "snapshots").symlink_to(real_snapshots)
        self.assert_internal_fails(
            "current-state",
            linked_snapshots,
            build_id,
            message="snapshots root is not a real directory",
        )

    def completed_fixture(self) -> tuple[Path, Path, dict[str, object]]:
        snapshot = self.temporary_root / "completed-snapshot"
        self.populate_header_tree(snapshot)
        (snapshot / "usr/include/linux/version.h").write_text(
            "#define LINUX_VERSION_CODE 459264\n", encoding="utf-8"
        )
        inventory = self.inventory(snapshot)
        options = ["make-target=headers_install", "ARCH=x86_64"]
        options_digest = hashlib.sha256(
            b"".join(value.encode("utf-8") + b"\0" for value in options)
        ).hexdigest()
        (self.temporary_root / "headers-install.options").write_text(
            "\n".join(options) + "\n", encoding="utf-8"
        )
        license_file = self.temporary_root / "licenses/linux/COPYING"
        license_file.parent.mkdir(parents=True)
        license_file.write_text("GPL-2.0-only\n", encoding="utf-8")
        probe_file = self.temporary_root / "probe/linux-uapi.o"
        probe_file.parent.mkdir()
        probe_file.write_bytes(b"ELF probe")
        unifdef = self.temporary_root / "host/unifdef"
        unifdef.parent.mkdir()
        unifdef.write_bytes(b"kernel unifdef")
        unifdef.chmod(0o755)

        def sha256(path: Path) -> str:
            return hashlib.sha256(path.read_bytes()).hexdigest()

        snapshot_digest = f"sha256:{inventory['digest']}"
        receipt = {
            "schema": 1,
            "build_id": "linux-uapi-headers-complete",
            "component": "linux",
            "stage": "uapi-headers",
            "sysroot_contract": "immutable-snapshots-v1",
            "kernel": {
                "version": "7.2.0-rc6",
                "version_code": 459264,
                "numeric_version": "7.2.0",
            },
            "options_digest": options_digest,
            "headers_install_options": options,
            "reproducibility": {
                "independent_installations": 2,
                "inventory_schema": "paths-types-modes-sha256-symlink-targets-v1",
                "first_inventory_digest": snapshot_digest,
                "second_inventory_digest": snapshot_digest,
                "identical": True,
                "post_probe_inventory_digest": snapshot_digest,
            },
            "dependencies": {"gcc": {"build_id": "gcc-stage1-complete"}},
            "installed_entries": inventory["entries"],
            "result_snapshot_digest": snapshot_digest,
            "license_sha256": {"COPYING": sha256(license_file)},
            "outputs": {"probe_sha256": {"linux-uapi.o": sha256(probe_file)}},
            "host": {
                "kernel_unifdef": {
                    "path": "/published/artifacts/host/unifdef",
                    "sha256": sha256(unifdef),
                }
            },
        }
        receipt_path = self.temporary_root / "receipt.json"
        receipt_path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return receipt_path, snapshot, receipt

    def validate_fixture(self, receipt_path: Path, snapshot: Path) -> None:
        self.run_internal(
            "validate-completed",
            receipt_path,
            snapshot,
            "schema",
            "1",
            "build_id",
            "linux-uapi-headers-complete",
            "component",
            "linux",
            "stage",
            "uapi-headers",
            "dependencies.gcc.build_id",
            "gcc-stage1-complete",
        )

    def test_completed_validation_detects_receipt_and_snapshot_tampering(self) -> None:
        receipt_path, snapshot, receipt = self.completed_fixture()
        self.validate_fixture(receipt_path, snapshot)

        tampered_metadata = dict(receipt)
        tampered_metadata["build_id"] = "linux-uapi-headers-tampered"
        receipt_path.write_text(json.dumps(tampered_metadata), encoding="utf-8")
        self.assert_internal_fails(
            "validate-completed",
            receipt_path,
            snapshot,
            "build_id",
            "linux-uapi-headers-complete",
            message="completed receipt mismatch for build_id",
        )

        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        (snapshot / "usr/include/linux/a.h").write_text(
            "#define A 99\n", encoding="utf-8"
        )
        self.assert_internal_fails(
            "validate-completed",
            receipt_path,
            snapshot,
            "schema",
            "1",
            message="completed snapshot failed full inventory validation",
        )

        (snapshot / "usr/include/linux/a.h").write_text(
            "#define A 1\n", encoding="utf-8"
        )
        tampered_digest = dict(receipt)
        tampered_digest["result_snapshot_digest"] = "sha256:" + "0" * 64
        receipt_path.write_text(json.dumps(tampered_digest), encoding="utf-8")
        self.assert_internal_fails(
            "validate-completed",
            receipt_path,
            snapshot,
            "schema",
            "1",
            message="completed snapshot digest does not match receipt",
        )

        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        (self.temporary_root / "headers-install.options").write_text(
            "ARCH=changed\n", encoding="utf-8"
        )
        self.assert_internal_fails(
            "validate-completed",
            receipt_path,
            snapshot,
            "schema",
            "1",
            message="receipt options differ from the recorded options file",
        )

        (self.temporary_root / "headers-install.options").write_text(
            "make-target=headers_install\nARCH=x86_64\n", encoding="utf-8"
        )
        (self.temporary_root / "probe/linux-uapi.o").write_bytes(b"tampered")
        self.assert_internal_fails(
            "validate-completed",
            receipt_path,
            snapshot,
            "schema",
            "1",
            message="completed probe attestation is invalid",
        )


if __name__ == "__main__":
    unittest.main()
