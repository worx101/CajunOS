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
INSTALLER = PROJECT_ROOT / "scripts" / "build-libgcc-bootstrap.sh"
SOURCE_COMMIT = "0123456789abcdef0123456789abcdef01234567"
TARGET = "x86_64-cajunos-linux-gnu"
GCC_VERSION = "17.0.0"
RUNTIME_ROOT = Path("lib/gcc") / TARGET / GCC_VERSION
RUNTIME_FILES = {
    RUNTIME_ROOT / "libgcc.a",
    RUNTIME_ROOT / "include/unwind.h",
    RUNTIME_ROOT / "include/gcov.h",
    RUNTIME_ROOT / "crtbegin.o",
    RUNTIME_ROOT / "crtbeginS.o",
    RUNTIME_ROOT / "crtbeginT.o",
    RUNTIME_ROOT / "crtend.o",
    RUNTIME_ROOT / "crtendS.o",
    RUNTIME_ROOT / "crtfastmath.o",
    RUNTIME_ROOT / "crtprec32.o",
    RUNTIME_ROOT / "crtprec64.o",
    RUNTIME_ROOT / "crtprec80.o",
}


class LibgccBootstrapStageTests(unittest.TestCase):
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
    def write_file(path: Path, contents: str | bytes, mode: int = 0o644) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(contents, bytes):
            path.write_bytes(contents)
        else:
            path.write_text(contents, encoding="utf-8")
        path.chmod(mode)

    @staticmethod
    def sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def populate_base(self, root: Path) -> None:
        self.write_file(root / "bin" / f"{TARGET}-gcc", b"sealed cross gcc", 0o755)
        self.write_file(
            root / "libexec/gcc" / TARGET / GCC_VERSION / "cc1",
            b"sealed cc1",
            0o755,
        )
        self.write_file(root / RUNTIME_ROOT / "specs", "*cpp:\n")
        (root / RUNTIME_ROOT / "include").mkdir(parents=True, exist_ok=True)
        for path in (root, root / "lib", root / "lib/gcc", root / RUNTIME_ROOT):
            path.chmod(0o755)

    def populate_result(self, base: Path, result: Path) -> None:
        shutil.copytree(base, result, symlinks=True)
        for relative in sorted(RUNTIME_FILES):
            if relative.name == "libgcc.a":
                member = result / ".bootstrap-libgcc-member.o"
                self.write_file(member, b"bootstrap archive member\n")
                (result / relative).parent.mkdir(parents=True, exist_ok=True)
                subprocess.run(
                    ["ar", "rcs", str(result / relative), str(member)], check=True
                )
                member.unlink()
                (result / relative).chmod(0o644)
            else:
                self.write_file(
                    result / relative,
                    b"bootstrap-target-file:" + relative.name.encode() + b"\n",
                )

    def derived_delta(self, base: Path, result: Path, name: str) -> dict[str, object]:
        output = self.temporary_root / name
        tools = base.parent
        self.run_internal(
            "write-delta", base, result, tools, TARGET, GCC_VERSION, output
        )
        return json.loads(output.read_text(encoding="utf-8"))

    def test_build_id_is_stable_order_independent_and_sensitive(self) -> None:
        material = {
            "source_set_digest": "sha256:source",
            "source_authentication": "recorded-mixed",
            "source_tree": "a" * 40,
            "source_repository": "git://gcc.gnu.org/git/gcc.git",
            "source_date_epoch": "1785990000",
            "target": TARGET,
            "build_triplet": "x86_64-pc-linux-gnu",
            "orchestration_commit": "b" * 40,
            "orchestration_tree": "c" * 40,
            "recipe_sha256": "d" * 64,
            "helper_sha256": "e" * 64,
            "options_digest": "f" * 64,
            "base_build_id": "gcc-stage1-base",
            "base_receipt_sha256": "1" * 64,
            "base_prefix_digest": "sha256:" + "2" * 64,
            "glibc_build_id": "glibc-headers-startfiles-base",
            "glibc_receipt_sha256": "3" * 64,
            "glibc_snapshot_digest": "sha256:" + "4" * 64,
            "linux_build_id": "linux-uapi-headers-base",
            "linux_receipt_sha256": "5" * 64,
            "binutils_build_id": "binutils-stage1-base",
            "binutils_receipt_sha256": "6" * 64,
        }

        def calculate(values: dict[str, str], commit: str = SOURCE_COMMIT) -> str:
            arguments = [item for pair in values.items() for item in pair]
            return self.run_internal("build-id", commit, *arguments).stdout.strip()

        baseline = calculate(material)
        self.assertEqual(baseline, calculate(material))
        self.assertEqual(baseline, calculate(dict(reversed(tuple(material.items())))))
        self.assertRegex(
            baseline,
            r"^libgcc-bootstrap-0123456789ab-[0-9a-f]{16}$",
        )
        self.assertNotEqual(baseline, calculate(material, "f" * 40))
        for key in material:
            with self.subTest(key=key):
                changed = dict(material)
                changed[key] += "-changed"
                self.assertNotEqual(baseline, calculate(changed))

    def test_inventory_and_compare_are_stable_and_detect_tampering(self) -> None:
        base = self.temporary_root / "base"
        left = self.temporary_root / "left"
        right = self.temporary_root / "right"
        self.populate_base(base)
        self.populate_result(base, left)
        self.populate_result(base, right)

        left_inventory = self.inventory(left)
        self.assertEqual(left_inventory, self.inventory(right))
        output = self.temporary_root / "comparison.json"
        self.run_internal("compare", left, right, output)
        self.assertEqual(left_inventory, json.loads(output.read_text(encoding="utf-8")))
        right_output = self.temporary_root / "comparison-right.json"
        right_output.write_text(
            json.dumps(self.inventory(right), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.run_internal("compare-json", output, right_output)

        (right / RUNTIME_ROOT / "libgcc.a").write_bytes(b"tampered archive")
        self.assertNotEqual(left_inventory["digest"], self.inventory(right)["digest"])
        self.assert_internal_fails("compare", left, right, output)
        right_output.write_text(
            json.dumps(self.inventory(right), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.assert_internal_fails("compare-json", output, right_output)

        shutil.rmtree(right)
        self.populate_result(base, right)
        (right / RUNTIME_ROOT / "crtbegin.o").chmod(0o600)
        self.assertNotEqual(left_inventory["digest"], self.inventory(right)["digest"])
        self.assert_internal_fails("compare", left, right, output)

    def test_gcc_header_contract_accepts_current_deferred_make_semantics(self) -> None:
        target_sysroot = self.temporary_root / "target-sysroot"
        build_sysroot = self.temporary_root / "sealed-build-sysroot"
        # A non-default name proves the validator evaluates the supplied file.
        makefile = self.temporary_root / "gcc" / "Generated.mk"
        self.write_file(
            makefile,
            "\n".join(
                [
                    "NATIVE_SYSTEM_HEADER_DIR = /usr/include",
                    "CROSS_SYSTEM_HEADER_DIR = "
                    f"`echo {target_sysroot}$${{sysroot_headers_suffix}}"
                    "$(NATIVE_SYSTEM_HEADER_DIR) | sed -e :a "
                    "-e 's,[^/]*/\\.\\.\\/,,' -e ta`",
                    "SYSTEM_HEADER_DIR = "
                    f"`echo {build_sysroot}$${{sysroot_headers_suffix}}"
                    "$(NATIVE_SYSTEM_HEADER_DIR) | sed -e :a "
                    "-e 's,[^/]*/\\.\\.\\/,,' -e ta`",
                    "BUILD_SYSTEM_HEADER_DIR = $(SYSTEM_HEADER_DIR)",
                    f"TARGET_SYSTEM_ROOT = {target_sysroot}",
                    f"SYSROOT_CFLAGS_FOR_TARGET = --sysroot={build_sysroot}",
                    "inhibit_libc = false",
                    "",
                ]
            ),
        )
        self.run_internal(
            "gcc-header-contract", makefile, target_sysroot, build_sysroot
        )

        environment = os.environ.copy()
        environment["sysroot_headers_suffix"] = "/host-leak"
        result = subprocess.run(
            [
                str(INSTALLER),
                "--internal-python",
                "gcc-header-contract",
                str(makefile),
                str(target_sysroot),
                str(build_sysroot),
            ],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_gcc_header_contract_rejects_wrong_roots_or_host_headers(self) -> None:
        target_sysroot = self.temporary_root / "target-sysroot"
        build_sysroot = self.temporary_root / "sealed-build-sysroot"
        baseline = {
            "NATIVE_SYSTEM_HEADER_DIR": "/usr/include",
            "CROSS_SYSTEM_HEADER_DIR": f"{target_sysroot}/usr/include",
            "SYSTEM_HEADER_DIR": f"{build_sysroot}/usr/include",
            "BUILD_SYSTEM_HEADER_DIR": f"{build_sysroot}/usr/include",
            "TARGET_SYSTEM_ROOT": str(target_sysroot),
            "SYSROOT_CFLAGS_FOR_TARGET": f"--sysroot={build_sysroot}",
            "inhibit_libc": "false",
        }
        cases = {
            "cross-host-leak": {"CROSS_SYSTEM_HEADER_DIR": "/usr/include"},
            "system-host-leak": {"SYSTEM_HEADER_DIR": "/usr/include"},
            "build-host-leak": {"BUILD_SYSTEM_HEADER_DIR": "/usr/include"},
            "wrong-target-root": {"TARGET_SYSTEM_ROOT": "/wrong"},
            "wrong-build-flags": {"SYSROOT_CFLAGS_FOR_TARGET": ""},
            "inhibited-libc": {"inhibit_libc": "true"},
        }
        for name, changes in cases.items():
            with self.subTest(name=name):
                values = {**baseline, **changes}
                makefile = self.temporary_root / name / "Makefile"
                self.write_file(
                    makefile,
                    "".join(f"{key} = {value}\n" for key, value in values.items()),
                )
                self.assert_internal_fails(
                    "gcc-header-contract",
                    makefile,
                    target_sysroot,
                    build_sysroot,
                    message="does not match sealed sysroots",
                )

    def test_libgcc_make_contract_accepts_current_included_make_semantics(self) -> None:
        build = self.temporary_root / "build"
        gcc_objdir = build / "gcc"
        build_sysroot = self.temporary_root / "sealed-build-sysroot"
        makefile = build / TARGET / "libgcc" / "Generated.mk"
        self.write_file(gcc_objdir / "xgcc", b"fresh cross compiler\n", 0o755)
        build_sysroot.mkdir()
        self.write_file(gcc_objdir / "libgcc.mvars", "INHIBIT_LIBC_CFLAGS =\n")
        self.write_file(
            makefile,
            "\n".join(
                [
                    "enable_shared = no",
                    "enable_gcov = no",
                    "thread_header = gthr-single.h",
                    "MULTIDIRS =",
                    "MULTISUBDIR =",
                    "LIBGCC2_CFLAGS = -O2 $(INHIBIT_LIBC_CFLAGS)",
                    "CRTSTUFF_CFLAGS = $(INHIBIT_LIBC_CFLAGS)",
                    "CRTSTUFF_T_CFLAGS =",
                    "EXTRA_PARTS = crtbegin.o crtbeginS.o crtbeginT.o "
                    "crtend.o crtendS.o crtprec32.o crtprec64.o crtprec80.o "
                    "crtfastmath.o",
                    "gcc_objdir = ../../gcc",
                    f"CC = {gcc_objdir}/xgcc -B{gcc_objdir}/ "
                    f"--sysroot={build_sysroot}",
                    "include ../../gcc/libgcc.mvars",
                    "",
                ]
            ),
        )
        self.run_internal(
            "libgcc-make-contract", makefile, gcc_objdir, build_sysroot
        )

        environment = os.environ.copy()
        environment.update(
            {
                "MAKEFLAGS": "--eval=$(error hostile MAKEFLAGS was imported)",
                "MAKEFILES": "/does/not/exist",
            }
        )
        result = subprocess.run(
            [
                str(INSTALLER),
                "--internal-python",
                "libgcc-make-contract",
                str(makefile),
                str(gcc_objdir),
                str(build_sysroot),
            ],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_libgcc_make_contract_rejects_unsafe_modes_and_compilers(self) -> None:
        build = self.temporary_root / "negative-build"
        gcc_objdir = build / "gcc"
        build_sysroot = self.temporary_root / "sealed-build-sysroot"
        self.write_file(gcc_objdir / "xgcc", b"fresh cross compiler\n", 0o755)
        build_sysroot.mkdir()
        self.write_file(gcc_objdir / "libgcc.mvars", "INHIBIT_LIBC_CFLAGS =\n")
        baseline = {
            "enable_shared": "no",
            "enable_gcov": "no",
            "thread_header": "gthr-single.h",
            "MULTIDIRS": "",
            "MULTISUBDIR": "",
            "INHIBIT_LIBC_CFLAGS": "",
            "LIBGCC2_CFLAGS": "-O2 $(INHIBIT_LIBC_CFLAGS)",
            "CRTSTUFF_CFLAGS": "$(INHIBIT_LIBC_CFLAGS)",
            "CRTSTUFF_T_CFLAGS": "",
            "EXTRA_PARTS": (
                "crtbegin.o crtbeginS.o crtbeginT.o crtend.o crtendS.o "
                "crtprec32.o crtprec64.o crtprec80.o crtfastmath.o"
            ),
            "gcc_objdir": str(gcc_objdir),
            "CC": f"{gcc_objdir}/xgcc -B{gcc_objdir}/ --sysroot={build_sysroot}",
        }
        cases = {
            "shared": {"enable_shared": "yes"},
            "gcov": {"enable_gcov": "yes"},
            "threads": {"thread_header": "gthr-posix.h"},
            "multidirs": {"MULTIDIRS": ". 32"},
            "multisubdir": {"MULTISUBDIR": "/32"},
            "inhibit-variable": {"INHIBIT_LIBC_CFLAGS": "-Dinhibit_libc"},
            "inhibit-libgcc-flags": {
                "LIBGCC2_CFLAGS": "-O2 -Dinhibit_libc"
            },
            "inhibit-crt-flags": {"CRTSTUFF_CFLAGS": "-Dinhibit_libc"},
            "wrong-extra-parts": {"EXTRA_PARTS": "crtbegin.o crtend.o"},
            "wrong-objdir": {"gcc_objdir": "/wrong/gcc"},
            "host-compiler": {
                "CC": f"/usr/bin/gcc --sysroot={build_sysroot}"
            },
            "missing-sysroot": {"CC": f"{gcc_objdir}/xgcc -B{gcc_objdir}/"},
            "wrong-sysroot": {
                "CC": f"{gcc_objdir}/xgcc -B{gcc_objdir}/ --sysroot=/wrong"
            },
            "inhibit-command": {
                "CC": f"{gcc_objdir}/xgcc -B{gcc_objdir}/ "
                f"--sysroot={build_sysroot} -Dinhibit_libc"
            },
        }
        for name, changes in cases.items():
            with self.subTest(name=name):
                values = {**baseline, **changes}
                makefile = build / name / "Generated.mk"
                self.write_file(
                    makefile,
                    "".join(f"{key} = {value}\n" for key, value in values.items()),
                )
                self.assert_internal_fails(
                    "libgcc-make-contract",
                    makefile,
                    gcc_objdir,
                    build_sysroot,
                )

        self.write_file(
            gcc_objdir / "libgcc.mvars",
            "INHIBIT_LIBC_CFLAGS = -Dinhibit_libc\n",
        )
        valid_makefile = build / "inhibited-mvars" / "Generated.mk"
        self.write_file(
            valid_makefile,
            "".join(f"{key} = {value}\n" for key, value in baseline.items()),
        )
        self.assert_internal_fails(
            "libgcc-make-contract",
            valid_makefile,
            gcc_objdir,
            build_sysroot,
            message="does not record functional-header mode",
        )

    def test_derived_delta_is_stable_and_requires_exact_twelve_file_set(self) -> None:
        tools = self.temporary_root / "delta-tools"
        base = tools / "base"
        left = tools / "left"
        right = tools / "right"
        self.populate_base(base)
        self.populate_result(base, left)
        self.populate_result(base, right)

        left_delta = self.derived_delta(base, left, "left-delta.json")
        right_delta = self.derived_delta(base, right, "right-delta.json")
        self.assertEqual(left_delta, right_delta)
        self.assertEqual(left_delta["schema"], "sealed-tools-prefix-additions-v1")
        added_files = {
            Path(path)
            for path, metadata in left_delta["added_entries"].items()
            if metadata.get("type") == "file"
        }
        self.assertEqual(added_files, RUNTIME_FILES)
        self.assertEqual(len(added_files), 12)

        for missing_file in sorted(RUNTIME_FILES):
            with self.subTest(missing=missing_file.name):
                changed = tools / f"missing-{missing_file.name}"
                shutil.copytree(left, changed, symlinks=True)
                (changed / missing_file).unlink()
                self.assert_internal_fails(
                    "derived-delta",
                    base,
                    changed,
                    tools,
                    TARGET,
                    GCC_VERSION,
                )

    def test_derived_delta_rejects_base_mutation_deletion_and_hardlinks(self) -> None:
        tools = self.temporary_root / "mutation-tools"
        base = tools / "base"
        pristine = tools / "pristine"
        self.populate_base(base)
        self.populate_result(base, pristine)

        cases = {
            "content": lambda root: self.write_file(
                root / "bin" / f"{TARGET}-gcc", b"changed", 0o755
            ),
            "mode": lambda root: os.chmod(root / "bin" / f"{TARGET}-gcc", 0o700),
            "deleted": lambda root: (root / "bin" / f"{TARGET}-gcc").unlink(),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                changed = tools / f"base-change-{name}"
                shutil.copytree(pristine, changed, symlinks=True)
                mutate(changed)
                self.assert_internal_fails(
                    "derived-delta",
                    base,
                    changed,
                    tools,
                    TARGET,
                    GCC_VERSION,
                    message="sealed GCC prefix entry changed or disappeared",
                )

        linked = tools / "hardlinked-base-copy"
        shutil.copytree(base, linked, symlinks=True)
        linked_driver = linked / "bin" / f"{TARGET}-gcc"
        linked_driver.unlink()
        os.link(base / "bin" / f"{TARGET}-gcc", linked_driver)
        self.assert_internal_fails(
            "no-shared-inodes",
            base,
            linked,
            message="shares regular-file inodes with its sealed base",
        )

    def test_derived_delta_rejects_forbidden_unexpected_and_malformed_outputs(self) -> None:
        tools = self.temporary_root / "forbidden-tools"
        base = tools / "base"
        pristine = tools / "pristine"
        self.populate_base(base)
        self.populate_result(base, pristine)
        cases = {
            "shared-libgcc": RUNTIME_ROOT / "libgcc_s.so.1",
            "profiling-runtime": RUNTIME_ROOT / "libgcov.a",
            "libstdcxx": RUNTIME_ROOT / "libstdc++.a",
            "functional-libc": Path("lib/libc.so.6"),
            "unexpected-file": RUNTIME_ROOT / "include/unexpected.h",
            "outside-prefix": Path("etc/ld.so.conf"),
        }
        for name, relative in cases.items():
            with self.subTest(name=name):
                changed = tools / f"forbidden-{name}"
                shutil.copytree(pristine, changed, symlinks=True)
                self.write_file(changed / relative, b"forbidden")
                self.assert_internal_fails(
                    "derived-delta",
                    base,
                    changed,
                    tools,
                    TARGET,
                    GCC_VERSION,
                )

        wrong_mode = tools / "wrong-mode"
        shutil.copytree(pristine, wrong_mode, symlinks=True)
        (wrong_mode / RUNTIME_ROOT / "crtbegin.o").chmod(0o755)
        self.assert_internal_fails(
            "derived-delta",
            base,
            wrong_mode,
            tools,
            TARGET,
            GCC_VERSION,
        )

        symlinked = tools / "symlinked"
        shutil.copytree(pristine, symlinked, symlinks=True)
        (symlinked / RUNTIME_ROOT / "crtend.o").unlink()
        (symlinked / RUNTIME_ROOT / "crtend.o").symlink_to("crtbegin.o")
        self.assert_internal_fails(
            "derived-delta",
            base,
            symlinked,
            tools,
            TARGET,
            GCC_VERSION,
        )

    @staticmethod
    def canonical_digest(value: object) -> str:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def regular_hashes(root: Path) -> dict[str, str]:
        return {
            path.relative_to(root).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

    def dependency_inventory(self, prefix: Path, tools: Path) -> dict[str, object]:
        entries = json.loads(
            self.run_internal("dependency-inventory", prefix, tools).stdout
        )
        return {"entries": entries, "digest": self.canonical_digest(entries)}

    @staticmethod
    def write_receipt(path: Path, receipt: dict[str, object]) -> None:
        path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        path.chmod(0o644)

    def completed_fixture(
        self,
    ) -> tuple[Path, Path, Path, Path, dict[str, object]]:
        workspace = self.temporary_root / "completed-workspace"
        tools = workspace / "tools"
        base = tools / "gcc-stage1-complete"
        prefix = tools / "libgcc-bootstrap-complete"
        artifact = workspace / "artifacts/libgcc-bootstrap-complete"
        self.populate_base(base)
        self.populate_result(base, prefix)
        self.write_file(artifact / "probe/freestanding.elf", b"ELF64 probe")
        self.write_file(artifact / "configuration/build-a.config.log", "configured\n")
        self.write_file(
            artifact / "licenses/gcc/COPYING.RUNTIME", "GCC Runtime Exception\n"
        )
        self.write_file(artifact / "configure.args", "--disable-shared\n")
        sysroot_snapshot = workspace / "sysroot/glibc-headers-startfiles-complete"
        self.write_file(sysroot_snapshot / "usr/include/features.h", "/* sealed */\n")

        base_inventory = self.dependency_inventory(base, tools)
        result_inventory = self.dependency_inventory(prefix, tools)
        base_digest = f"sha256:{base_inventory['digest']}"
        result_digest = f"sha256:{result_inventory['digest']}"
        delta = self.derived_delta(base, prefix, "completed-delta.json")
        runtime_sha256 = {
            relative.as_posix(): self.sha256(prefix / relative)
            for relative in sorted(RUNTIME_FILES)
        }
        license_inventory = self.inventory(artifact / "licenses/gcc")
        sysroot_inventory = self.inventory(sysroot_snapshot)
        configure_args = ["--disable-shared"]
        configure_digest = hashlib.sha256(
            b"".join(value.encode("utf-8") + b"\0" for value in configure_args)
        ).hexdigest()
        archive = prefix / RUNTIME_ROOT / "libgcc.a"
        archive_members = subprocess.run(
            ["ar", "t", str(archive)],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.splitlines()
        receipt: dict[str, object] = {
            "schema": 1,
            "build_id": "libgcc-bootstrap-complete",
            "component": "gcc",
            "stage": "libgcc-bootstrap",
            "source_commit": SOURCE_COMMIT,
            "source_tree": "a" * 40,
            "source_repository": "git://gcc.gnu.org/git/gcc.git",
            "prefix": str(prefix),
            "base_build_id": "gcc-stage1-complete",
            "base_prefix_digest": base_digest,
            "result_prefix_digest": result_digest,
            "sysroot_snapshot": str(sysroot_snapshot),
            "sysroot_snapshot_digest": f"sha256:{sysroot_inventory['digest']}",
            "configure_args": configure_args,
            "configure_digest": configure_digest,
            "installed_entries": result_inventory["entries"],
            "delta": delta,
            "runtime_sha256": runtime_sha256,
            "reproducibility": {
                "independent_builds": 2,
                "inventory_schema": "paths-types-modes-sha256-symlink-targets-v1",
                "first_inventory_digest": result_digest,
                "second_inventory_digest": result_digest,
                "identical": True,
                "base_unchanged_after_build": True,
                "sysroot_unchanged_after_build": True,
                "post_probe_inventory_digest": result_digest,
            },
            "dependencies": {
                "glibc": {
                    "build_id": "glibc-headers-startfiles-complete",
                    "receipt_sha256": "1" * 64,
                },
                "linux": {
                    "build_id": "linux-uapi-headers-complete",
                    "receipt_sha256": "2" * 64,
                },
                "gcc": {
                    "build_id": "gcc-stage1-complete",
                    "receipt_sha256": "3" * 64,
                },
                "binutils": {
                    "build_id": "binutils-stage1-complete",
                    "receipt_sha256": "4" * 64,
                },
            },
            "archive": {
                "sha256": self.sha256(archive),
                "members": archive_members,
                "members_digest": hashlib.sha256(
                    "\n".join(archive_members).encode("utf-8") + b"\n"
                ).hexdigest(),
            },
            "outputs": {
                "probe_sha256": self.regular_hashes(artifact / "probe"),
                "configuration_sha256": self.regular_hashes(
                    artifact / "configuration"
                ),
                "sysroot_inventory_digest": f"sha256:{sysroot_inventory['digest']}",
            },
            "license_inventory": license_inventory,
        }
        receipt_path = artifact / "receipt.json"
        self.write_receipt(receipt_path, receipt)
        return receipt_path, prefix, base, tools, receipt

    def validate_fixture(
        self, receipt_path: Path, prefix: Path, base: Path, tools: Path
    ) -> None:
        self.run_internal(
            "validate-completed",
            receipt_path,
            prefix,
            base,
            tools,
            TARGET,
            GCC_VERSION,
            "schema",
            "1",
            "build_id",
            "libgcc-bootstrap-complete",
            "component",
            "gcc",
            "stage",
            "libgcc-bootstrap",
            "source_commit",
            SOURCE_COMMIT,
            "base_build_id",
            "gcc-stage1-complete",
            "dependencies.glibc.receipt_sha256",
            "1" * 64,
            "dependencies.linux.receipt_sha256",
            "2" * 64,
            "dependencies.gcc.receipt_sha256",
            "3" * 64,
            "dependencies.binutils.receipt_sha256",
            "4" * 64,
        )

    def test_completed_validation_is_idempotent_and_detects_prefix_or_base_tampering(self) -> None:
        receipt_path, prefix, base, tools, _ = self.completed_fixture()
        receipt_bytes = receipt_path.read_bytes()
        prefix_before = self.dependency_inventory(prefix, tools)
        self.validate_fixture(receipt_path, prefix, base, tools)
        self.validate_fixture(receipt_path, prefix, base, tools)
        self.assertEqual(receipt_path.read_bytes(), receipt_bytes)
        self.assertEqual(self.dependency_inventory(prefix, tools), prefix_before)

        (prefix / RUNTIME_ROOT / "libgcc.a").write_bytes(b"tampered")
        self.assert_internal_fails(
            "validate-completed",
            receipt_path,
            prefix,
            base,
            tools,
            TARGET,
            GCC_VERSION,
            "schema",
            "1",
        )

        self.write_file(prefix / RUNTIME_ROOT / "libgcc.a", b"!<arch>\nbootstrap-libgcc\n")
        (base / "bin" / f"{TARGET}-gcc").write_bytes(b"tampered base")
        self.assert_internal_fails(
            "validate-completed",
            receipt_path,
            prefix,
            base,
            tools,
            TARGET,
            GCC_VERSION,
            "schema",
            "1",
        )

    def test_completed_validation_detects_dependency_and_result_attestation_tampering(self) -> None:
        receipt_path, prefix, base, tools, receipt = self.completed_fixture()
        expected_hashes = {"glibc": "1", "linux": "2", "gcc": "3", "binutils": "4"}
        for component, digit in expected_hashes.items():
            with self.subTest(component=component):
                changed = copy.deepcopy(receipt)
                changed["dependencies"][component]["receipt_sha256"] = "0" * 64
                self.write_receipt(receipt_path, changed)
                self.assert_internal_fails(
                    "validate-completed",
                    receipt_path,
                    prefix,
                    base,
                    tools,
                    TARGET,
                    GCC_VERSION,
                    f"dependencies.{component}.receipt_sha256",
                    digit * 64,
                    message=(
                        "completed receipt mismatch for "
                        f"dependencies.{component}.receipt_sha256"
                    ),
                )

        mutations = {
            "installed-entries": lambda value: value["installed_entries"].pop(
                (RUNTIME_ROOT / "libgcc.a").as_posix()
            ),
            "result-digest": lambda value: value.__setitem__(
                "result_prefix_digest", "sha256:" + "0" * 64
            ),
            "base-digest": lambda value: value.__setitem__(
                "base_prefix_digest", "sha256:" + "0" * 64
            ),
            "delta": lambda value: value["delta"].__setitem__(
                "added_entries_digest", "sha256:" + "0" * 64
            ),
            "runtime-hash": lambda value: value["runtime_sha256"].__setitem__(
                (RUNTIME_ROOT / "libgcc.a").as_posix(), "0" * 64
            ),
            "reproducibility": lambda value: value["reproducibility"].__setitem__(
                "identical", False
            ),
            "probe": lambda value: value["outputs"]["probe_sha256"].__setitem__(
                "freestanding.elf", "0" * 64
            ),
            "configuration": lambda value: value["outputs"][
                "configuration_sha256"
            ].__setitem__("build-a.config.log", "0" * 64),
            "configure-digest": lambda value: value.__setitem__(
                "configure_digest", "0" * 64
            ),
            "archive-members": lambda value: value["archive"].__setitem__(
                "members_digest", "0" * 64
            ),
            "sysroot-digest": lambda value: value.__setitem__(
                "sysroot_snapshot_digest", "sha256:" + "0" * 64
            ),
            "license": lambda value: value["license_inventory"].__setitem__(
                "digest", "0" * 64
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(receipt)
                mutate(changed)
                self.write_receipt(receipt_path, changed)
                self.assert_internal_fails(
                    "validate-completed",
                    receipt_path,
                    prefix,
                    base,
                    tools,
                    TARGET,
                    GCC_VERSION,
                    "schema",
                    "1",
                )


    def tools_layout(self, selected: str) -> tuple[Path, Path]:
        workspace = self.temporary_root / f"selector-{selected}"
        tools = workspace / "tools"
        tools.mkdir(parents=True)
        for build_id in ("gcc-stage1-base", "libgcc-result", selected):
            (tools / build_id).mkdir(exist_ok=True)
        (tools / "current").symlink_to(selected)
        return workspace, tools

    def write_ancestry_receipt(
        self, workspace: Path, tools: Path, build_id: str, base_build_id: str
    ) -> None:
        receipt = {
            "build_id": build_id,
            "prefix": str(tools / build_id),
            "base_build_id": base_build_id,
        }
        path = workspace / "artifacts" / build_id / "receipt.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(receipt), encoding="utf-8")
        path.chmod(0o644)

    def test_tools_selector_advances_idempotently_and_never_rewinds(self) -> None:
        workspace, tools = self.tools_layout("gcc-stage1-base")
        artifacts = workspace / "artifacts"
        self.assertEqual(
            self.run_internal(
                "selector-state",
                tools,
                artifacts,
                "gcc-stage1-base",
                "libgcc-result",
            ).stdout.strip(),
            "base",
        )
        self.assertEqual(
            self.run_internal(
                "selector-transition",
                tools,
                artifacts,
                "gcc-stage1-base",
                "libgcc-result",
            ).stdout.strip(),
            "advanced",
        )
        self.assertEqual(os.readlink(tools / "current"), "libgcc-result")
        self.assertEqual(
            self.run_internal(
                "selector-transition",
                tools,
                artifacts,
                "gcc-stage1-base",
                "libgcc-result",
            ).stdout.strip(),
            "this",
        )

        workspace, later_tools = self.tools_layout("later-two")
        (later_tools / "later-one").mkdir()
        self.write_ancestry_receipt(
            workspace, later_tools, "later-one", "libgcc-result"
        )
        self.write_ancestry_receipt(workspace, later_tools, "later-two", "later-one")
        original = os.readlink(later_tools / "current")
        self.assertEqual(
            self.run_internal(
                "selector-transition",
                later_tools,
                workspace / "artifacts",
                "gcc-stage1-base",
                "libgcc-result",
            ).stdout.strip(),
            "later:later-two",
        )
        self.assertEqual(os.readlink(later_tools / "current"), original)

    def test_tools_selector_rejects_unproven_and_malformed_state_without_mutation(self) -> None:
        workspace, tools = self.tools_layout("unproven")
        artifacts = workspace / "artifacts"
        original = os.readlink(tools / "current")
        self.assert_internal_fails(
            "selector-transition",
            tools,
            artifacts,
            "gcc-stage1-base",
            "libgcc-result",
        )
        self.assertEqual(os.readlink(tools / "current"), original)

        self.write_ancestry_receipt(workspace, tools, "unproven", "unproven")
        self.assert_internal_fails(
            "selector-state",
            tools,
            artifacts,
            "gcc-stage1-base",
            "libgcc-result",
            message="cyclic or unsafe",
        )
        self.assertEqual(os.readlink(tools / "current"), original)

        cyclic_receipt = artifacts / "unproven/receipt.json"
        malformed_receipt = json.loads(cyclic_receipt.read_text(encoding="utf-8"))
        malformed_receipt["build_id"] = "different-build"
        self.write_receipt(cyclic_receipt, malformed_receipt)
        self.assert_internal_fails(
            "selector-transition",
            tools,
            artifacts,
            "gcc-stage1-base",
            "libgcc-result",
            message="invalid identity",
        )
        self.assertEqual(os.readlink(tools / "current"), original)

        (tools / "current").unlink()
        (tools / "current").symlink_to("../outside")
        malformed = os.readlink(tools / "current")
        self.assert_internal_fails(
            "selector-state",
            tools,
            artifacts,
            "gcc-stage1-base",
            "libgcc-result",
        )
        self.assertEqual(os.readlink(tools / "current"), malformed)


if __name__ == "__main__":
    unittest.main()
