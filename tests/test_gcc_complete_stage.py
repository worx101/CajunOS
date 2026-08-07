#!/usr/bin/env python3

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT / "scripts/build-gcc-complete.sh"
MAKEFILE = PROJECT / "Makefile"


class GccCompleteStageContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not SCRIPT.is_file():
            raise AssertionError(f"complete GCC orchestrator is missing: {SCRIPT}")
        cls.source = SCRIPT.read_text(encoding="utf-8")
        cls.executable_source = "\n".join(
            line
            for line in cls.source.splitlines()
            if not line.lstrip().startswith("#")
        )

    def assert_contains_all(self, *needles: str) -> None:
        for needle in needles:
            with self.subTest(needle=needle):
                if needle not in self.executable_source:
                    self.fail(f"{needle!r} is absent from the orchestrator")

    def assert_ordered(self, *needles: str) -> None:
        cursor = -1
        for needle in needles:
            with self.subTest(needle=needle):
                position = self.executable_source.find(needle, cursor + 1)
                self.assertNotEqual(
                    position,
                    -1,
                    f"{needle!r} is absent after the preceding stage target",
                )
                cursor = position

    def internal(self, *arguments: object) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [SCRIPT, "--internal-python", *map(str, arguments)],
            cwd=PROJECT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def source_between(self, start: str, end: str) -> str:
        start_index = self.source.index(start)
        end_index = self.source.index(end, start_index + len(start))
        return self.source[start_index:end_index]

    @staticmethod
    def compact(value: str) -> str:
        return re.sub(r"\s+", " ", value.replace("\\\n", " ")).strip()

    @staticmethod
    def write_fixture(
        path: Path, contents: str | bytes = b"fixture\n", mode: int = 0o644
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(contents, str):
            path.write_text(contents, encoding="utf-8")
        else:
            path.write_bytes(contents)
        path.chmod(mode)

    def test_make_target_invokes_the_complete_gcc_orchestrator(self) -> None:
        makefile = MAKEFILE.read_text(encoding="utf-8")
        self.assertRegex(
            makefile,
            re.compile(
                r"(?m)^gcc-complete:\n"
                r'\tCAJUNOS_ROOT="\$\(CAJUNOS_ROOT\)" '
                r"scripts/build-gcc-complete\.sh$"
            ),
        )

    def test_top_level_configuration_is_the_exact_runtime_cohort(self) -> None:
        self.assert_contains_all(
            "TARGET_CONFIGDIRS",
            "libgcc libatomic libstdc++-v3",
            "--enable-languages=c,c++",
            "--disable-libstdcxx-pch",
        )
        exact_set = self.executable_source.find(
            "libgcc libatomic libstdc++-v3"
        )
        target_configdirs = self.executable_source.find("TARGET_CONFIGDIRS")
        self.assertLess(
            abs(exact_set - target_configdirs),
            1200,
            "the exact target runtime set is not tied to TARGET_CONFIGDIRS",
        )

    def test_builds_and_installs_only_the_four_explicit_targets(self) -> None:
        self.assert_ordered(
            "all-gcc",
            "all-target-libgcc",
            "all-target-libatomic",
            "all-target-libstdc++-v3",
        )
        self.assert_ordered(
            "install-gcc",
            "install-target-libgcc",
            "install-target-libatomic",
            "install-target-libstdc++-v3",
        )
        self.assertIn("LIBGCC2_DEBUG_CFLAGS=-g0", self.executable_source)

    def test_two_independent_prefixes_are_compared_before_publication(self) -> None:
        self.assert_contains_all(
            "build_a=",
            "build_b=",
            "candidate_a=",
            "candidate_b=",
            "inventory-a.json",
            "inventory-b.json",
            "compare-json",
            "no-shared-inodes",
        )
        self.assertRegex(
            self.executable_source,
            re.compile(r'build_one\s+"\$build_a"\s+"\$candidate_a"'),
        )
        self.assertRegex(
            self.executable_source,
            re.compile(r'build_one\s+"\$build_b"\s+"\$candidate_b"'),
        )

    def test_sealed_base_and_sysroot_are_revalidated_and_receipt_bound(self) -> None:
        self.assert_contains_all(
            "build-libgcc-bootstrap.sh",
            "build-glibc-complete.sh",
            "validate-completed",
            "dependency-inventory",
            "base-before.json",
            "base-after.json",
            "sysroot-before.json",
            "sysroot-after.json",
            "sysroot_inventory_digest",
            "base_prefix_digest",
            "sysroot_snapshot_digest",
        )

    def test_dependency_resolver_binds_legacy_binutils_repository_provenance(
        self,
    ) -> None:
        resolver = self.source_between(
            "for name, value, component, stage, commit, tree, repository in (",
            "\n\nlibgcc_gcc =",
        )
        self.assertIn(
            'receipt_repository = None if name == "binutils" else repository',
            resolver,
        )
        self.assertIn('value.get("source_commit") != commit', resolver)
        self.assertIn('value.get("source_tree") != tree', resolver)
        self.assertIn('value.get("source_repository") != repository', resolver)
        self.assertIn(
            'receipt.get("source_repository") != receipt_repository',
            resolver,
        )

    def test_compiler_and_runtime_probes_cover_the_complete_toolchain(self) -> None:
        self.assert_contains_all(
            "-dumpmachine",
            "-print-sysroot",
            "-print-multi-lib",
            "-print-prog-name=",
            "-print-file-name=",
            "cc1plus",
            "libgcc_s.so.1",
            "libatomic.so.1",
            "libstdc++.so.6",
            "-std=c++23",
            "-pthread",
            "-static",
            "NEEDED",
        )
        self.assertRegex(self.executable_source, re.compile(r"for program in as ld"))

    def test_completed_path_is_idempotent_and_selector_advance_is_last(self) -> None:
        self.assert_contains_all(
            "receipt_final=",
            "prefix_final=",
            "validate-completed",
            "selector-state",
            "selector-transition",
        )
        last_validation = max(
            self.executable_source.rfind("validate_completed"),
            self.executable_source.rfind("validate-completed"),
        )
        last_transition = self.executable_source.rfind("selector-transition")
        self.assertGreater(
            last_transition,
            last_validation,
            "tools/current may advance only after final completed validation",
        )

    def test_failed_unselected_candidates_are_quarantined(self) -> None:
        self.assert_contains_all(
            "failed_root=",
            'mv -T -- "$candidate_a"',
            'mv -T -- "$candidate_b"',
        )
        self.assertRegex(self.executable_source, re.compile(r"trap\s+\w+\s+EXIT"))

    def test_receipt_covers_inventory_reproducibility_and_evidence(self) -> None:
        self.assert_contains_all(
            "receipt.json",
            "installed_entries",
            "result_prefix_digest",
            "base_prefix_digest",
            "reproducibility",
            "configure_digest",
            "license_inventory",
            "probe_sha256",
            "configuration_sha256",
        )

    def test_recursive_make_and_libgcc_compile_evidence_keep_debug_disabled(
        self,
    ) -> None:
        make_variables = self.source_between(
            "make_target_vars=(", "\n)\n\nbuild_one()"
        )
        self.assertIn(
            '"MAKE=/usr/bin/make LIBGCC2_DEBUG_CFLAGS=-g0"',
            make_variables,
        )
        self.assertIn('"LIBGCC2_DEBUG_CFLAGS=-g0"', make_variables)

        top_level_contract = self.source_between(
            "def validate_top_level_make(", "\n\ndef validate_gcc_headers("
        )
        self.assertIn(
            '"MAKE=/usr/bin/make LIBGCC2_DEBUG_CFLAGS=-g0"',
            top_level_contract,
        )
        self.assertIn(
            'values["LIBGCC2_DEBUG_CFLAGS"] != "-g0"',
            top_level_contract,
        )
        self.assert_contains_all(
            "libgcc-debug-flags-contract",
            "libgcc-debug-flags.txt",
            "-DIN_LIBGCC2",
        )

        with tempfile.TemporaryDirectory() as directory:
            makefile = Path(directory) / "Makefile"
            makefile.write_text(
                "\n".join(
                    (
                        "MAKEOVERRIDES =",
                        "TARGET_CONFIGDIRS = libgcc libatomic libstdc++-v3",
                        "CFLAGS = -O2 -g0",
                        "CXXFLAGS = -O2 -g0",
                        (
                            "CFLAGS_FOR_TARGET = -O2 -g0 -march=x86-64-v2 "
                            "-mtune=generic"
                        ),
                        (
                            "CXXFLAGS_FOR_TARGET = -O2 -g0 -march=x86-64-v2 "
                            "-mtune=generic"
                        ),
                        "XGCC_FLAGS_FOR_TARGET = --sysroot=/sealed/build",
                        (
                            "TOPLEVEL_CONFIGURE_ARGUMENTS = ../configure "
                            "--with-sysroot=/sealed/target "
                            "--with-build-sysroot=/sealed/build "
                            "--enable-languages=c,c++ "
                            "--disable-libstdcxx-pch "
                            "--disable-libstdcxx-debug "
                            "--disable-libstdcxx-debug-flags"
                        ),
                        "",
                    )
                ),
                encoding="utf-8",
            )
            recursive = self.internal(
                "top-level-make-contract",
                makefile,
                "/sealed/target",
                "/sealed/build",
            )
            self.assertEqual(recursive.returncode, 0, recursive.stderr)

            evidence = Path(directory) / "libgcc-debug-flags.txt"
            evidence.write_text(
                "/sealed/xgcc -O2 -g0 -DIN_LIBGCC2 -c libgcc2.c\n",
                encoding="utf-8",
            )
            accepted = self.internal("libgcc-debug-flags-contract", evidence)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            evidence.write_text(
                "/sealed/xgcc -O2 -g0 -DIN_LIBGCC2 -c libgcc2.c \\\n",
                encoding="utf-8",
            )
            continued = self.internal("libgcc-debug-flags-contract", evidence)
            self.assertEqual(continued.returncode, 0, continued.stderr)

            evidence.write_text(
                "/sealed/xgcc -O2 -g -g0 -DIN_LIBGCC2 -c libgcc2.c\n",
                encoding="utf-8",
            )
            rejected = self.internal("libgcc-debug-flags-contract", evidence)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("late debug-enabling -g", rejected.stderr)

    def test_staged_normalization_precedes_overlay_and_inventory(self) -> None:
        build_one = self.source_between(
            "build_one() {", '\n\nbuild_one "$build_a"'
        )
        ordered = (
            'normalize-modes "$staged_prefix"',
            'mode-contract "$staged_prefix"',
            'normalize-hardlinks "$staged_prefix"',
            'no-hardlinks "$staged_prefix"',
            'rsync -a -- "$libgcc_prefix/" "$candidate/"',
            'rsync -a -- "$staged_prefix/" "$candidate/"',
            'no-hardlinks "$candidate"',
            'mode-contract "$candidate"',
        )
        cursor = -1
        compact_build = self.compact(build_one)
        for needle in ordered:
            with self.subTest(needle=needle):
                position = compact_build.find(needle, cursor + 1)
                self.assertNotEqual(position, -1)
                cursor = position
        second_build = self.source.index('build_one "$build_b"')
        self.assertGreater(self.source.index("inventory-a.json"), second_build)
        self.assertGreater(self.source.index("inventory-b.json"), second_build)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "staged"
            private_directory = root / "lib"
            private_directory.mkdir(parents=True)
            private_directory.chmod(0o700)
            first = private_directory / "first"
            second = private_directory / "second"
            first.write_bytes(b"same inode\n")
            first.chmod(0o666)
            os.link(first, second)

            normalized_modes = self.internal("normalize-modes", root)
            self.assertEqual(
                normalized_modes.returncode, 0, normalized_modes.stderr
            )
            self.assertEqual(stat.S_IMODE(private_directory.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o644)
            self.assertEqual(self.internal("mode-contract", root).returncode, 0)

            normalized_links = self.internal("normalize-hardlinks", root)
            self.assertEqual(
                normalized_links.returncode, 0, normalized_links.stderr
            )
            self.assertEqual(self.internal("no-hardlinks", root).returncode, 0)
            self.assertNotEqual(first.stat().st_ino, second.stat().st_ino)

    def test_libgcc_linker_script_is_regular_but_versioned_soname_is_elf(
        self,
    ) -> None:
        topology = self.source_between(
            "def runtime_paths(", "\n\ndef required_programs("
        )
        self.assertRegex(
            topology,
            re.compile(
                r'f"\{runtime_root\}/libgcc_s\.so": \("file", None\)'
            ),
        )
        self.assertRegex(
            topology,
            re.compile(
                r'f"\{runtime_root\}/libgcc_s\.so\.1": \("file", None\)'
            ),
        )

        target = "x86_64-cajunos-linux-gnu"
        version = "17.0.0"
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / "tools/gcc-complete"
            runtime = prefix / target / "lib64"
            (prefix / "lib/gcc" / target / version).mkdir(parents=True)
            runtime.mkdir(parents=True)
            source = Path(directory) / "runtime.c"
            source.write_text(
                "int cajunos_runtime(void) { return 0; }\n",
                encoding="utf-8",
            )
            outputs = (
                ("libgcc_s.so.1", "libgcc_s.so.1"),
                ("libatomic.so.1.2.0", "libatomic.so.1"),
                ("libstdc++.so.6.0.37", "libstdc++.so.6"),
            )
            for filename, soname in outputs:
                subprocess.run(
                    [
                        "/usr/bin/gcc",
                        "-shared",
                        "-fPIC",
                        f"-Wl,-soname,{soname}",
                        source,
                        "-o",
                        runtime / filename,
                    ],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            linker_script = runtime / "libgcc_s.so"
            linker_script.write_text(
                "/* GNU ld script */\nGROUP ( libgcc_s.so.1 )\n",
                encoding="utf-8",
            )
            linker_script.chmod(0o644)

            result = self.internal("runtime-elf-scan", prefix, target, version)
            self.assertEqual(result.returncode, 0, result.stderr)
            scan = json.loads(result.stdout)
            elf_paths = {entry["path"] for entry in scan["elf_files"]}
            self.assertIn(f"{target}/lib64/libgcc_s.so.1", elf_paths)
            self.assertNotIn(f"{target}/lib64/libgcc_s.so", elf_paths)
            self.assertEqual(
                scan["sonames"][f"{target}/lib64/libgcc_s.so.1"],
                "libgcc_s.so.1",
            )

    def test_probes_compile_named_objects_and_enforce_as_needed_atomic(
        self,
    ) -> None:
        probe_build = self.compact(
            self.source_between('(\n  cd "$probe_dir"', "\n)\n\nfor map_name")
        )
        probes = (
            ("cxx-dynamic.cc", "cxx-dynamic.o", "cxx-dynamic.map"),
            ("atomic-dynamic.c", "atomic-dynamic.o", "atomic-dynamic.map"),
            ("cxx-static.cc", "cxx-static.o", "cxx-static.map"),
        )
        for source, object_file, map_file in probes:
            with self.subTest(probe=source):
                compile_position = probe_build.find(
                    f"-c {source} -o {object_file}"
                )
                link_position = probe_build.find(
                    f"{object_file} -Wl,-Map,{map_file}"
                )
                self.assertGreaterEqual(compile_position, 0)
                self.assertGreater(link_position, compile_position)

        dependency_checks = self.compact(
            self.source_between(
                "grep -q 'Shared library: \\[libstdc++",
                "\nruntime_dir=$prefix_final",
            )
        )
        atomic_needed = r"grep -q 'Shared library: \[libatomic\.so\.1\]'"
        first = dependency_checks.find(atomic_needed)
        second = dependency_checks.find(atomic_needed, first + 1)
        self.assertGreaterEqual(first, 0)
        self.assertGreater(second, first)
        self.assertIn("cxx-dynamic.readelf-d", dependency_checks[first:second])
        self.assertIn(
            "unexpectedly depends on libatomic",
            dependency_checks[first:second],
        )
        self.assertIn("atomic-dynamic.readelf-d", dependency_checks[second:])

    def test_cxx_header_search_accepts_only_the_sealed_topology(self) -> None:
        target = "x86_64-cajunos-linux-gnu"
        version = "17.0.0"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix = root / "tools/final"
            snapshot = root / "sysroot/snapshot"
            base = root / "tools/bootstrap"
            expected = (
                prefix / f"{target}/include/c++/{version}",
                prefix / f"{target}/include/c++/{version}/{target}",
                prefix / f"{target}/include/c++/{version}/backward",
                prefix / f"lib/gcc/{target}/{version}/include",
                prefix / f"lib/gcc/{target}/{version}/include-fixed",
                prefix / f"{target}/include",
                snapshot / "usr/include",
            )
            for path in (*expected, base):
                path.mkdir(parents=True, exist_ok=True)

            driver = prefix / "bin" / f"{target}-g++"
            evidence = root / "probe/cxx-header-search.search"

            def install_driver(entries: tuple[Path, ...]) -> str:
                search = (
                    "#include <...> search starts here:\n"
                    + "".join(f" {path}\n" for path in entries)
                    + "End of search list.\n"
                )
                self.write_fixture(
                    driver,
                    "#!/bin/sh\n"
                    "cat >&2 <<'EOF'\n"
                    f"{search}"
                    "EOF\n",
                    0o755,
                )
                evidence.parent.mkdir(parents=True, exist_ok=True)
                evidence.write_text(search, encoding="utf-8")
                return search

            install_driver(expected)
            accepted = self.internal(
                "cxx-header-search-contract",
                evidence,
                prefix,
                snapshot,
                base,
                target,
                version,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            foreign = root / "host/include"
            foreign.mkdir(parents=True)
            install_driver((*expected, foreign))
            rejected = self.internal(
                "cxx-header-search-contract",
                evidence,
                prefix,
                snapshot,
                base,
                target,
                version,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("unexpected C++ header search topology", rejected.stderr)

    def test_driver_policy_accepts_live_mock_and_rejects_stale_evidence(
        self,
    ) -> None:
        target = "x86_64-cajunos-linux-gnu"
        version = "17.0.0"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix = root / "tools/final"
            sysroot = root / "sysroot"
            binutils = root / "tools/binutils"
            sysroot.mkdir()
            cc1 = prefix / f"libexec/gcc/{target}/{version}/cc1"
            cc1plus = prefix / f"libexec/gcc/{target}/{version}/cc1plus"
            assembler = binutils / "bin" / f"{target}-as"
            linker = binutils / "bin" / f"{target}-ld"
            for path in (cc1, cc1plus, assembler, linker):
                self.write_fixture(path, "#!/bin/sh\nexit 0\n", 0o755)
            wrapper = (
                "#!/bin/sh\n"
                "case \"$1\" in\n"
                f"  -dumpmachine) echo '{target}' ;;\n"
                f"  -print-sysroot) echo '{sysroot}' ;;\n"
                "  -print-multi-lib) echo '.;' ;;\n"
                f"  -dumpfullversion) echo '{version}' ;;\n"
                "  -v) echo 'Thread model: posix' >&2 ;;\n"
                "  -Q) printf '%s\\n' '  -march= x86-64-v2' "
                "'  -mtune= generic' ;;\n"
                f"  -print-prog-name=cc1) echo '{cc1}' ;;\n"
                f"  -print-prog-name=cc1plus) echo '{cc1plus}' ;;\n"
                f"  -print-prog-name=as) echo '{assembler}' ;;\n"
                f"  -print-prog-name=ld) echo '{linker}' ;;\n"
                "  *) exit 2 ;;\n"
                "esac\n"
            )
            for name in ("gcc", "g++", "c++"):
                self.write_fixture(
                    prefix / "bin" / f"{target}-{name}", wrapper, 0o755
                )
            evidence = root / "driver-policy.txt"
            written = self.internal(
                "write-driver-evidence",
                prefix,
                evidence,
                target,
                version,
                sysroot,
                binutils,
            )
            self.assertEqual(written.returncode, 0, written.stderr)
            accepted = self.internal(
                "driver-policy-contract",
                prefix,
                evidence,
                target,
                version,
                sysroot,
                binutils,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            evidence.write_text(
                evidence.read_text(encoding="utf-8").replace(
                    "gcc-default-mtune=generic",
                    "gcc-default-mtune=native",
                ),
                encoding="utf-8",
            )
            rejected = self.internal(
                "driver-policy-contract",
                prefix,
                evidence,
                target,
                version,
                sysroot,
                binutils,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("does not match live", rejected.stderr)

    def test_loader_evidence_accepts_sealed_and_rejects_foreign_origins(
        self,
    ) -> None:
        target = "x86_64-cajunos-linux-gnu"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix = root / "tools/final"
            snapshot = root / "sysroot/snapshot"
            probe = root / "probe"
            runtime = prefix / target / "lib64"
            syslib = snapshot / "usr/lib"
            loader = snapshot / "lib64/ld-linux-x86-64.so.2"
            paths = {
                "libstdc++": runtime / "libstdc++.so.6",
                "libgcc": runtime / "libgcc_s.so.1",
                "libatomic": runtime / "libatomic.so.1",
                "libc": syslib / "libc.so.6",
                "libm": syslib / "libm.so.6",
            }
            for path in paths.values():
                self.write_fixture(path)
            for name in ("cxx-dynamic", "atomic-dynamic"):
                self.write_fixture(probe / name, "#!/bin/sh\nexit 0\n", 0o755)

            def install_loader(cxx_stdlib: Path) -> None:
                wrapper = (
                    "#!/bin/sh\n"
                    "last=\n"
                    "for argument in \"$@\"; do last=$argument; done\n"
                    "case \"$last\" in\n"
                    "  *cxx-dynamic)\n"
                    f"    echo 'libstdc++.so.6 => {cxx_stdlib} (0x1000)'\n"
                    f"    echo 'libgcc_s.so.1 => {paths['libgcc']} (0x2000)'\n"
                    f"    echo 'libc.so.6 => {paths['libc']} (0x3000)'\n"
                    f"    echo 'libm.so.6 => {paths['libm']} (0x4000)'\n"
                    f"    echo '{loader} (0x5000)'\n"
                    "    ;;\n"
                    "  *atomic-dynamic)\n"
                    f"    echo 'libatomic.so.1 => {paths['libatomic']} (0x6000)'\n"
                    f"    echo 'libc.so.6 => {paths['libc']} (0x7000)'\n"
                    f"    echo '{loader} (0x8000)'\n"
                    "    ;;\n"
                    "  *) exit 2 ;;\n"
                    "esac\n"
                )
                self.write_fixture(loader, wrapper, 0o755)

            install_loader(paths["libstdc++"])
            written = self.internal(
                "write-loader-evidence", probe, prefix, snapshot
            )
            self.assertEqual(written.returncode, 0, written.stderr)
            accepted = self.internal(
                "loader-evidence-contract", probe, prefix, snapshot
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            foreign = root / "foreign/libstdc++.so.6"
            self.write_fixture(foreign)
            install_loader(foreign)
            rewritten = self.internal(
                "write-loader-evidence", probe, prefix, snapshot
            )
            self.assertEqual(rewritten.returncode, 0, rewritten.stderr)
            rejected = self.internal(
                "loader-evidence-contract", probe, prefix, snapshot
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("escapes its sealed origin", rejected.stderr)

    def test_archive_evidence_binds_members_and_required_symbols(self) -> None:
        target = "x86_64-cajunos-linux-gnu"
        version = "17.0.0"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix = root / "tools/final"
            probe = root / "probe"
            binutils = root / "tools/binutils"
            tools = binutils / "bin"
            tools.mkdir(parents=True)
            probe.mkdir()
            os.symlink("/usr/bin/ar", tools / f"{target}-ar")
            os.symlink("/usr/bin/nm", tools / f"{target}-nm")
            archives = {
                "libgcc": (
                    prefix / f"lib/gcc/{target}/{version}/libgcc.a",
                    ("__udivti3",),
                ),
                "libgcc_eh": (
                    prefix / f"lib/gcc/{target}/{version}/libgcc_eh.a",
                    ("_Unwind_RaiseException",),
                ),
                "libatomic": (
                    prefix / f"{target}/lib64/libatomic.a",
                    ("__atomic_load_16", "__atomic_compare_exchange_16"),
                ),
                "libstdcxx": (
                    prefix / f"{target}/lib64/libstdc++.a",
                    ("_ZSt4cout", "__cxa_throw"),
                ),
                "libsupcxx": (
                    prefix / f"{target}/lib64/libsupc++.a",
                    ("__cxa_begin_catch", "__cxa_throw"),
                ),
            }

            def write_archive(label: str, symbols: tuple[str, ...]) -> None:
                archive = archives[label][0]
                source = root / f"{label}.S"
                object_file = root / f"{label}.o"
                assembly = []
                for symbol in symbols:
                    assembly.extend(
                        (
                            f".globl {symbol}",
                            f".type {symbol}, @function",
                            f"{symbol}:",
                            "  ret",
                        )
                    )
                assembly.append('.section .note.GNU-stack,"",@progbits')
                source.write_text("\n".join(assembly) + "\n", encoding="utf-8")
                subprocess.run(
                    ["/usr/bin/gcc", "-c", source, "-o", object_file],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                archive.parent.mkdir(parents=True, exist_ok=True)
                archive.unlink(missing_ok=True)
                subprocess.run(
                    ["/usr/bin/ar", "rcs", archive, object_file],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

            for label, (_, symbols) in archives.items():
                write_archive(label, symbols)
            written = self.internal(
                "write-archive-evidence",
                prefix,
                probe,
                binutils,
                target,
                version,
            )
            self.assertEqual(written.returncode, 0, written.stderr)
            accepted = self.internal(
                "archive-evidence-contract",
                prefix,
                probe,
                binutils,
                target,
                version,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            members = probe / "libgcc.members"
            members.write_text(
                members.read_text(encoding="utf-8") + "invented.o\n",
                encoding="utf-8",
            )
            stale = self.internal(
                "archive-evidence-contract",
                prefix,
                probe,
                binutils,
                target,
                version,
            )
            self.assertNotEqual(stale.returncode, 0)
            self.assertIn("member evidence differs", stale.stderr)

            write_archive("libatomic", ("__atomic_load_16",))
            missing_symbol = self.internal(
                "write-archive-evidence",
                prefix,
                probe,
                binutils,
                target,
                version,
            )
            self.assertNotEqual(missing_symbol.returncode, 0)
            self.assertIn("lacks required complete-GCC symbols", missing_symbol.stderr)

    def test_probe_elf_contract_accepts_sealed_semantics_and_rejects_atomic_leak(
        self,
    ) -> None:
        target = "x86_64-cajunos-linux-gnu"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix = root / "tools/final"
            runtime = prefix / target / "lib64"
            probe = root / "probe"
            runtime.mkdir(parents=True)
            probe.mkdir()

            def build_runtime(
                filename: str, soname: str, source_text: str, versions: str
            ) -> Path:
                stem = filename.replace("+", "x").replace(".", "-")
                source = root / f"{stem}.c"
                version_script = root / f"{stem}.map"
                output = runtime / filename
                source.write_text(source_text, encoding="utf-8")
                version_script.write_text(versions, encoding="utf-8")
                subprocess.run(
                    [
                        "/usr/bin/gcc",
                        "-shared",
                        "-fPIC",
                        source,
                        f"-Wl,-soname,{soname}",
                        f"-Wl,--version-script={version_script}",
                        "-o",
                        output,
                    ],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                return output

            libstdcxx = build_runtime(
                "libstdc++.so.6",
                "libstdc++.so.6",
                (
                    "int stdcxx_marker(void) { return 0; }\n"
                    "int cxxabi_marker(void) { return 0; }\n"
                ),
                (
                    "GLIBCXX_3.4.37 { global: stdcxx_marker; };\n"
                    "CXXABI_1.3.17 { global: cxxabi_marker; };\n"
                ),
            )
            libgcc = build_runtime(
                "libgcc_s.so.1",
                "libgcc_s.so.1",
                "int gcc_marker(void) { return 0; }\n",
                "GCC_1.0 { global: gcc_marker; };\n",
            )
            libatomic = build_runtime(
                "libatomic.so.1",
                "libatomic.so.1",
                "int atomic_marker(void) { return 0; }\n",
                "LIBATOMIC_1.2 { global: atomic_marker; };\n",
            )

            cxx_source = root / "cxx-dynamic.c"
            cxx_source.write_text(
                "#include <stdio.h>\n"
                "extern int stdcxx_marker(void);\n"
                "extern int gcc_marker(void);\n"
                "int main(void) { puts(\"cxx\"); "
                "return stdcxx_marker() + gcc_marker(); }\n",
                encoding="utf-8",
            )
            subprocess.run(
                [
                    "/usr/bin/gcc",
                    cxx_source,
                    "-Wl,--no-as-needed",
                    libstdcxx,
                    libgcc,
                    "-Wl,--as-needed",
                    "-o",
                    probe / "cxx-dynamic",
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            atomic_source = root / "atomic-dynamic.c"
            atomic_source.write_text(
                "#include <stdio.h>\n"
                "extern int atomic_marker(void);\n"
                "int main(void) { puts(\"atomic\"); return atomic_marker(); }\n",
                encoding="utf-8",
            )
            subprocess.run(
                [
                    "/usr/bin/gcc",
                    atomic_source,
                    "-Wl,--no-as-needed",
                    libatomic,
                    "-Wl,--as-needed",
                    "-o",
                    probe / "atomic-dynamic",
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            static_source = root / "cxx-static.S"
            static_source.write_text(
                ".globl _start\n"
                ".type _start, @function\n"
                "_start:\n"
                "  xor %edi, %edi\n"
                "  mov $60, %eax\n"
                "  syscall\n"
                '.section .note.GNU-stack,"",@progbits\n',
                encoding="utf-8",
            )
            subprocess.run(
                [
                    "/usr/bin/gcc",
                    "-nostdlib",
                    "-static",
                    "-Wl,-e,_start",
                    static_source,
                    "-o",
                    probe / "cxx-static",
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            accepted = self.internal("probe-elf-contract", probe, prefix, target)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            cxx_source.write_text(
                "#include <stdio.h>\n"
                "extern int stdcxx_marker(void);\n"
                "extern int gcc_marker(void);\n"
                "extern int atomic_marker(void);\n"
                "int main(void) { puts(\"cxx\"); return stdcxx_marker() + "
                "gcc_marker() + atomic_marker(); }\n",
                encoding="utf-8",
            )
            subprocess.run(
                [
                    "/usr/bin/gcc",
                    cxx_source,
                    "-Wl,--no-as-needed",
                    libstdcxx,
                    libgcc,
                    libatomic,
                    "-Wl,--as-needed",
                    "-o",
                    probe / "cxx-dynamic",
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            rejected = self.internal("probe-elf-contract", probe, prefix, target)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("ordinary C++ probe unexpectedly needs libatomic", rejected.stderr)

    def test_cleanup_uses_live_selector_state_before_quarantine(self) -> None:
        cleanup = self.source_between("on_exit() {", "\n}\ntrap on_exit EXIT")
        compact_cleanup = self.compact(cleanup)
        self.assertNotIn("selector_advanced", cleanup)
        self.assertIn(
            'live_selector_state=$("$script_path" --internal-python '
            "selector-state",
            compact_cleanup,
        )
        case_start = compact_cleanup.index("case $live_selector_state in")
        case_end = compact_cleanup.index("esac", case_start)
        case_block = compact_cleanup[case_start:case_end]
        self.assertRegex(
            case_block,
            re.compile(r"this\).*?selector-rollback.*?;;"),
        )
        self.assertRegex(case_block, re.compile(r"base\)\s*;;"))
        self.assertRegex(
            case_block,
            re.compile(r"later:\*\|\*\).*?safe_to_quarantine=0.*?;;"),
        )
        quarantine_guard = compact_cleanup.index(
            "if (( safe_to_quarantine == 1 ))", case_end
        )
        prefix_move = compact_cleanup.index(
            'mv -T -- "$prefix_final"', quarantine_guard
        )
        self.assertGreater(quarantine_guard, case_end)
        self.assertGreater(prefix_move, quarantine_guard)

    def test_target_make_contracts_accept_exact_and_reject_unsafe_values(
        self,
    ) -> None:
        target = "x86_64-cajunos-linux-gnu"
        prefix = "/sealed/tools/final"
        gcc_objdir = "/sealed/build/gcc"
        sysroot = "/sealed/sysroot/snapshot"
        common = {
            "libgcc": (
                "\n".join(
                    (
                        "enable_shared = yes",
                        "enable_gcov = yes",
                        "thread_header = gthr-posix.h",
                        "MULTIDIRS = .",
                        "MULTISUBDIR =",
                        "MULTIOSDIR = ../lib64",
                        "INHIBIT_LIBC_CFLAGS =",
                        "LIBGCC2_DEBUG_CFLAGS = -g",
                        f"CC = {gcc_objdir}/xgcc --sysroot={sysroot}",
                        f"slibdir = {prefix}/{target}/lib",
                        f"toolexeclibdir = {prefix}/{target}/lib64",
                        "",
                    )
                ),
                "MULTIOSDIR = ../lib64",
                "MULTIOSDIR = ../lib",
                "multios install mapping",
            ),
            "libatomic": (
                "\n".join(
                    (
                        "enable_shared = yes",
                        "MULTISUBDIR =",
                        f"CC = {gcc_objdir}/xgcc --sysroot={sysroot}",
                        f"toolexecdir = {prefix}/{target}",
                        f"toolexeclibdir = {prefix}/{target}/lib64",
                        "CFLAGS = -O2 -g0",
                        "",
                    )
                ),
                "enable_shared = yes",
                "enable_shared = no",
                "shared mode is disabled",
            ),
            "libstdcxx": (
                "\n".join(
                    (
                        "MULTISUBDIR =",
                        f"CXX = {gcc_objdir}/xg++ --sysroot={sysroot}",
                        f"gxx_include_dir = {prefix}/{target}/include/c++/17.0.0",
                        f"toolexecdir = {prefix}/{target}",
                        f"toolexeclibdir = {prefix}/{target}/lib64",
                        "CXXFLAGS = -O2 -g0",
                        "glibcxx_build_pch = no",
                        "",
                    )
                ),
                "glibcxx_build_pch = no",
                "glibcxx_build_pch = yes",
                "unexpectedly enables PCH",
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            for kind, (contents, old, new, message) in common.items():
                with self.subTest(kind=kind):
                    makefile = Path(directory) / kind / "Makefile"
                    self.write_fixture(makefile, contents)
                    accepted = self.internal(
                        f"{kind}-make-contract",
                        makefile,
                        gcc_objdir,
                        prefix,
                        target,
                        sysroot,
                    )
                    self.assertEqual(accepted.returncode, 0, accepted.stderr)
                    makefile.write_text(
                        contents.replace(old, new),
                        encoding="utf-8",
                    )
                    rejected = self.internal(
                        f"{kind}-make-contract",
                        makefile,
                        gcc_objdir,
                        prefix,
                        target,
                        sysroot,
                    )
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertIn(message, rejected.stderr)

    def test_configuration_normalization_compares_independent_builds(self) -> None:
        suffixes = (
            "config.log",
            "gcc.config.log",
            "libgcc.config.log",
            "libatomic.config.log",
            "libstdcxx.config.log",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configuration = root / "configuration"
            temporary = root / "temporary-root"
            values = {
                "a": (
                    root / "work/build-a",
                    root / "tools/candidate-a",
                    root / "overlay-a",
                    "/tmp/ccAAAA.o",
                ),
                "b": (
                    root / "work/build-b",
                    root / "tools/candidate-b",
                    root / "overlay-b",
                    "/tmp/ccBBBB.o",
                ),
            }
            for label, (build, candidate, overlay, conftest) in values.items():
                contents = (
                    f"build={build}\n"
                    f"candidate={candidate}\n"
                    f"overlay={overlay}\n"
                    f"temporary={temporary}\n"
                    f"conftest={conftest}\n"
                )
                for suffix in suffixes:
                    self.write_fixture(
                        configuration / f"build-{label}.{suffix}",
                        contents,
                    )
            self.write_fixture(
                configuration / "libgcc-debug-flags.txt",
                (
                    f"{values['a'][0]}/xgcc -O2 -g0 -DIN_LIBGCC2 -c a.c\n"
                    f"{values['b'][0]}/xgcc -O2 -g0 -DIN_LIBGCC2 -c b.c\n"
                ),
            )
            normalized = self.internal(
                "normalize-configuration",
                configuration,
                values["a"][0],
                values["b"][0],
                values["a"][1],
                values["b"][1],
                values["a"][2],
                values["b"][2],
                temporary,
            )
            self.assertEqual(normalized.returncode, 0, normalized.stderr)
            accepted = self.internal("configuration-contract", configuration)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            divergent = configuration / "build-b.libatomic.config.log"
            divergent.write_text("diverged\n", encoding="utf-8")
            rejected = self.internal("configuration-contract", configuration)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("independent normalized configuration differs", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
