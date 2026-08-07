#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT / "scripts" / "build-kernel-first-boot.sh"
CONFIG = PROJECT / "configs" / "x86_64-first-boot.config"
INIT = PROJECT / "initramfs" / "first-boot-init.c"
MAKEFILE = PROJECT / "Makefile"
SOURCE_EPOCH = 1785943083


def newc_entry(
    name: str,
    mode: int,
    *,
    data: bytes = b"",
    inode: int,
    rdevmajor: int = 0,
    rdevminor: int = 0,
    uid: int = 0,
    gid: int = 0,
    mtime: int = SOURCE_EPOCH,
    devmajor: int = 3,
    devminor: int = 1,
    nlink: int | None = None,
    check: int = 0,
) -> bytes:
    encoded_name = name.encode("ascii") + b"\0"
    fields = (
        inode,
        mode,
        uid,
        gid,
        nlink if nlink is not None else (2 if stat.S_ISDIR(mode) else 1),
        mtime,
        len(data),
        devmajor,
        devminor,
        rdevmajor,
        rdevminor,
        len(encoded_name),
        check,
    )
    header = b"070701" + b"".join(f"{field:08x}".encode("ascii") for field in fields)
    record = header + encoded_name
    record += b"\0" * (-len(record) % 4)
    record += data
    record += b"\0" * (-len(record) % 4)
    return record


def newc_archive(
    *, unexpected: bool = False, console_major: int = 5, mutation: str = ""
) -> bytes:
    entries = [
        ("dev", stat.S_IFDIR | 0o755, b"", 0, 0),
        ("dev/console", stat.S_IFCHR | 0o600, b"", console_major, 1),
        ("dev/null", stat.S_IFCHR | 0o666, b"", 1, 3),
        ("proc", stat.S_IFDIR | 0o555, b"", 0, 0),
        ("sys", stat.S_IFDIR | 0o555, b"", 0, 0),
        ("run", stat.S_IFDIR | 0o755, b"", 0, 0),
        ("init", stat.S_IFREG | 0o755, b"fixture-static-init\n", 0, 0),
    ]
    if unexpected:
        entries.append(("etc", stat.S_IFDIR | 0o755, b"", 0, 0))
    if mutation == "missing-entry":
        entries = [entry for entry in entries if entry[0] != "run"]
    elif mutation == "duplicate-name":
        entries.append(("proc", stat.S_IFDIR | 0o555, b"", 0, 0))
    elif mutation == "wrong-mode":
        entries = [
            (name, stat.S_IFREG | 0o644, data, major, minor)
            if name == "init"
            else (name, mode, data, major, minor)
            for name, mode, data, major, minor in entries
        ]
    elif mutation == "traversal":
        entries.append(("../escape", stat.S_IFREG | 0o644, b"bad\n", 0, 0))
    elif mutation == "absolute-name":
        entries = [
            ("/init", mode, data, major, minor)
            if name == "init"
            else (name, mode, data, major, minor)
            for name, mode, data, major, minor in entries
        ]
    elif mutation == "wrong-order":
        entries[3], entries[4] = entries[4], entries[3]
    elif mutation == "empty-init":
        entries = [
            (name, mode, b"", major, minor)
            if name == "init"
            else (name, mode, data, major, minor)
            for name, mode, data, major, minor in entries
        ]

    archive = b""
    for index, (name, mode, data, major, minor) in enumerate(entries):
        inode = 721 + index
        if mutation == "duplicate-inode" and name == "dev/console":
            inode = 721
        elif mutation == "wrong-inode-sequence" and name == "proc":
            inode += 100
        archive += newc_entry(
            name,
            mode,
            data=data,
            inode=inode,
            rdevmajor=major,
            rdevminor=minor,
            uid=1 if mutation == "non-root-owner" and name == "init" else 0,
            gid=1 if mutation == "non-root-group" and name == "init" else 0,
            mtime=(
                SOURCE_EPOCH + 1
                if mutation == "wrong-mtime" and name == "proc"
                else SOURCE_EPOCH
            ),
            devmajor=(
                0
                if mutation == "alternate-dev"
                else (4 if mutation == "wrong-dev" and name == "proc" else 3)
            ),
            devminor=0 if mutation == "alternate-dev" else 1,
            nlink=3 if mutation == "wrong-nlink" and name == "proc" else None,
        )
    if mutation != "missing-trailer":
        archive += newc_entry(
            "TRAILER!!!",
            stat.S_IFREG if mutation == "trailer-metadata" else 0,
            inode=0,
            mtime=(SOURCE_EPOCH if mutation == "trailer-metadata" else 0),
            devmajor=0,
            devminor=0,
            nlink=1,
        )
    if mutation == "trailing-garbage":
        archive += b"nonzero-after-trailer"
    if mutation == "truncated":
        return archive[:127]
    archive += b"\0" * (-len(archive) % 512)
    if mutation == "nonzero-entry-padding":
        changed = bytearray(archive)
        changed[114] = 1
        archive = bytes(changed)
    elif mutation == "excess-zero-padding":
        archive += b"\0" * 512
    return archive


class KernelFirstBootStageTests(unittest.TestCase):
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

    def assert_internal_accepts(self, *arguments: object) -> None:
        result = self.internal(*arguments)
        self.assertEqual(
            result.returncode,
            0,
            msg=(
                f"helper rejected {arguments!r}\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            ),
        )

    def assert_internal_rejects(self, *arguments: object) -> None:
        result = self.internal(*arguments)
        self.assertNotEqual(
            result.returncode,
            0,
            msg=f"helper unexpectedly accepted {arguments!r}",
        )

    def test_make_target_invokes_kernel_first_boot_orchestrator(self) -> None:
        makefile = MAKEFILE.read_text(encoding="utf-8")
        self.assertIn(
            'kernel-first-boot:\n\tCAJUNOS_ROOT="$(CAJUNOS_ROOT)" '
            "scripts/build-kernel-first-boot.sh\n",
            makefile,
        )

    def test_committed_config_is_resolved_minimal_and_module_free(self) -> None:
        contents = CONFIG.read_text(encoding="utf-8")
        self.assertIn("Linux/x86_64 7.2.0-rc6 Kernel Configuration", contents)
        self.assertIn('CONFIG_LOCALVERSION="-cajunos"', contents)
        self.assertNotIn("cajunos-spike", contents)

        required = {
            "CONFIG_64BIT=y",
            "CONFIG_X86_64=y",
            "CONFIG_MMU=y",
            "CONFIG_BLK_DEV_INITRD=y",
            "CONFIG_BINFMT_ELF=y",
            "CONFIG_DEVTMPFS=y",
            "CONFIG_DEVTMPFS_MOUNT=y",
            "CONFIG_TTY=y",
            "CONFIG_SERIAL_8250=y",
            "CONFIG_SERIAL_8250_CONSOLE=y",
            "CONFIG_SERIAL_8250_NR_UARTS=1",
            "CONFIG_SERIAL_8250_RUNTIME_UARTS=1",
            "CONFIG_PROC_FS=y",
            "CONFIG_SYSFS=y",
            "CONFIG_TMPFS=y",
            "CONFIG_DEBUG_INFO_NONE=y",
            "CONFIG_LTO_NONE=y",
        }
        lines = set(contents.splitlines())
        self.assertTrue(required <= lines, required - lines)

        forbidden = {
            "CONFIG_MODULES",
            "CONFIG_SMP",
            "CONFIG_BLOCK",
            "CONFIG_NET",
            "CONFIG_PCI",
            "CONFIG_ACPI",
            "CONFIG_EFI",
            "CONFIG_USB_SUPPORT",
            "CONFIG_DRM",
            "CONFIG_SOUND",
            "CONFIG_RUST",
            "CONFIG_WERROR",
        }
        for symbol in forbidden:
            with self.subTest(symbol=symbol):
                self.assertNotIn(f"{symbol}=y", lines)
                self.assertNotIn(f"{symbol}=m", lines)
                if symbol not in {"CONFIG_EFI", "CONFIG_RUST"}:
                    self.assertIn(f"# {symbol} is not set", lines)
        self.assertFalse(any(line.endswith("=m") for line in lines))

    def test_config_helper_accepts_only_the_locked_contract(self) -> None:
        self.assert_internal_accepts("validate-config", CONFIG)

        mutations = {
            "required-off": ("CONFIG_PROC_FS=y", "# CONFIG_PROC_FS is not set"),
            "forbidden-on": ("# CONFIG_NET is not set", "CONFIG_NET=y"),
            "module": ("# CONFIG_DRM is not set", "CONFIG_DRM=m"),
            "cpu-mitigations": (
                "# CONFIG_CPU_MITIGATIONS is not set",
                "CONFIG_CPU_MITIGATIONS=y",
            ),
            "relocatable": (
                "# CONFIG_RELOCATABLE is not set",
                "CONFIG_RELOCATABLE=y",
            ),
            "stack-protector": (
                "# CONFIG_STACKPROTECTOR is not set",
                "CONFIG_STACKPROTECTOR=y",
            ),
            "fortify": (
                "# CONFIG_FORTIFY_SOURCE is not set",
                "CONFIG_FORTIFY_SOURCE=y",
            ),
            "security-framework": (
                "# CONFIG_SECURITY is not set",
                "CONFIG_SECURITY=y",
            ),
            "kaslr": (
                "# CONFIG_RELOCATABLE is not set",
                "# CONFIG_RELOCATABLE is not set\nCONFIG_RANDOMIZE_BASE=y",
            ),
            "randstruct": (
                "CONFIG_RANDSTRUCT_NONE=y",
                "CONFIG_RANDSTRUCT_FULL=y",
            ),
            "wrong-release": (
                'CONFIG_LOCALVERSION="-cajunos"',
                'CONFIG_LOCALVERSION="-cajunos-spike"',
            ),
        }
        baseline = CONFIG.read_text(encoding="utf-8")
        for name, (old, new) in mutations.items():
            with self.subTest(name=name):
                self.assertIn(old, baseline)
                path = self.temporary_root / f"{name}.config"
                path.write_text(baseline.replace(old, new, 1), encoding="utf-8")
                self.assert_internal_rejects("validate-config", path)

    def compile_init_fixture(self) -> Path:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("host C compiler is unavailable")
        output = self.temporary_root / "first-boot-init-test"
        result = subprocess.run(
            [
                compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-DCAJUNOS_FIRST_BOOT_UNIT_TEST",
                str(INIT),
                "-o",
                str(output),
            ],
            cwd=PROJECT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return output

    def test_init_uses_exact_not_substring_command_line_attestation(self) -> None:
        helper = self.compile_init_fixture()
        cases = {
            "console=ttyS0 cajunos.first_boot=1 rdinit=/init": 0,
            "\tcajunos.first_boot=1\n": 0,
            "console=ttyS0 rdinit=/init": 1,
            "cajunos.first_boot=0": 1,
            "prefix.cajunos.first_boot=1": 1,
            "cajunos.first_boot=1suffix": 1,
            "cajunos.first_boot=1 cajunos.first_boot=1": 2,
            "cajunos.first_boot=1 cajunos.first_boot=0": 1,
        }
        for cmdline, expected in cases.items():
            with self.subTest(cmdline=cmdline):
                result = subprocess.run(
                    [helper, "cmdline", cmdline], check=False
                )
                self.assertEqual(result.returncode, expected)

    def test_init_rejects_multiline_or_unbounded_evidence_values(self) -> None:
        helper = self.compile_init_fixture()
        cases = {
            "7.2.0-rc6-cajunos": 0,
            "kernel-first-boot-deadbeef-cafebabe": 0,
            "": 1,
            "contains space": 1,
            "line\nbreak": 1,
            "slash/value": 1,
            "a" * 129: 1,
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                result = subprocess.run(
                    [helper, "evidence-value", value], check=False
                )
                self.assertEqual(result.returncode, expected)

    @staticmethod
    def write_executable(path: Path, contents: str) -> None:
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o755)

    def make_init_validation_fixture(
        self,
        root: Path,
        *,
        header: str | None = None,
        program: str | None = None,
        dynamic: str | None = None,
        undefined: str = "",
        map_extra: str = "",
    ) -> tuple[Path, Path, Path, Path, Path, Path, Path]:
        prefix = root / "tools" / "gcc-final"
        binutils = root / "tools" / "binutils-final"
        snapshot = root / "sysroot" / "cohort" / "snapshots" / "glibc-final"
        gcc_input = prefix / "lib" / "gcc" / "runtime.a"
        glibc_input = snapshot / "usr" / "lib" / "libc.a"
        gcc_input.parent.mkdir(parents=True)
        glibc_input.parent.mkdir(parents=True)
        gcc_input.write_bytes(b"sealed gcc runtime\n")
        glibc_input.write_bytes(b"sealed glibc runtime\n")

        init = root / "init"
        init.write_bytes(b"fixture init ELF bytes\n")
        init.chmod(0o755)
        link_map = root / "init.map"
        link_map.write_text(
            f"LOAD init.o\nLOAD {gcc_input}\nLOAD {glibc_input}\n{map_extra}",
            encoding="utf-8",
        )
        link_map.chmod(0o644)

        elf_header = header or (
            "ELF Header:\n"
            "  Class:                             ELF64\n"
            "  Data:                              2's complement, little endian\n"
            "  Type:                              EXEC (Executable file)\n"
            "  Machine:                           Advanced Micro Devices X86-64\n"
        )
        program_headers = program or (
            "Elf file type is EXEC (Executable file)\n"
            "Program Headers:\n"
            "  Type Offset VirtAddr PhysAddr FileSiz MemSiz Flg Align\n"
            "  LOAD 0x0 0x400000 0x400000 0x100 0x100 R E 0x1000\n"
            "  GNU_STACK 0x0 0x0 0x0 0x0 0x0 RW 0x10\n"
        )
        dynamic_section = dynamic or "There is no dynamic section in this file.\n"
        tool_directory = binutils / "bin"
        tool_directory.mkdir(parents=True)
        readelf = tool_directory / "x86_64-cajunos-linux-gnu-readelf"
        self.write_executable(
            readelf,
            "#!/usr/bin/env python3\n"
            "import sys\n"
            f"outputs = {{'-hW': {elf_header!r}, '-lW': {program_headers!r}, "
            f"'-dW': {dynamic_section!r}}}\n"
            "sys.stdout.write(outputs.get(sys.argv[1], ''))\n",
        )
        nm = tool_directory / "x86_64-cajunos-linux-gnu-nm"
        self.write_executable(
            nm,
            "#!/usr/bin/env python3\n"
            "import sys\n"
            f"sys.stdout.write({undefined!r})\n",
        )
        return init, readelf, nm, link_map, prefix, snapshot, binutils

    def test_init_validator_enforces_static_elf_and_exact_map_provenance(self) -> None:
        fixture_parent = Path("/dev/shm")
        if not fixture_parent.is_dir() or not os.access(fixture_parent, os.W_OK):
            fixture_parent = PROJECT.parent / ".tmp" / "test-fixtures"
            fixture_parent.mkdir(parents=True, exist_ok=True)
        validation_directory = tempfile.TemporaryDirectory(
            prefix="cajunos-kernel-init-fixtures-", dir=fixture_parent
        )
        self.addCleanup(validation_directory.cleanup)
        fixture_root = Path(validation_directory.name)

        valid = self.make_init_validation_fixture(fixture_root / "valid")
        self.assert_internal_accepts("validate-init", *valid)

        for name, replacement in {
            "missing-relative-init": "",
            "duplicate-relative-init": "LOAD init.o\nLOAD init.o\n",
        }.items():
            with self.subTest(map=name):
                values = self.make_init_validation_fixture(
                    fixture_root / f"map-{name}"
                )
                link_map = values[3]
                link_map.write_text(
                    link_map.read_text(encoding="utf-8").replace(
                        "LOAD init.o\n", replacement, 1
                    ),
                    encoding="utf-8",
                )
                self.assert_internal_rejects("validate-init", *values)

        base_header = (
            "ELF Header:\n"
            "  Class: ELF64\n"
            "  Data: 2's complement, little endian\n"
            "  Type: EXEC (Executable file)\n"
            "  Machine: Advanced Micro Devices X86-64\n"
        )
        base_program = (
            "Program Headers:\n"
            "  LOAD 0x0 0x400000 0x400000 0x100 0x100 R E 0x1000\n"
            "  GNU_STACK 0x0 0x0 0x0 0x0 0x0 RW 0x10\n"
        )
        elf_mutations = {
            "elf32": {"header": base_header.replace("ELF64", "ELF32")},
            "big-endian": {
                "header": base_header.replace(
                    "2's complement, little endian",
                    "2's complement, big endian",
                )
            },
            "pie-dynamic": {"header": base_header.replace("EXEC", "DYN", 1)},
            "wrong-machine": {
                "header": base_header.replace(
                    "Advanced Micro Devices X86-64", "Intel 80386"
                )
            },
            "interpreter": {"program": base_program + "  INTERP 0x200\n"},
            "executable-stack": {
                "program": base_program.replace("0x0 RW 0x10", "0x0 RWE 0x10")
            },
            "missing-stack": {
                "program": "\n".join(
                    line
                    for line in base_program.splitlines()
                    if "GNU_STACK" not in line
                )
                + "\n"
            },
            "dynamic-needed": {
                "dynamic": " 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]\n"
            },
            "runpath": {
                "dynamic": " 0x000000000000001d (RUNPATH) Library runpath: [/tmp]\n"
            },
            "undefined-symbol": {"undefined": "                 U malloc\n"},
        }
        for name, overrides in elf_mutations.items():
            with self.subTest(elf=name):
                values = self.make_init_validation_fixture(
                    fixture_root / f"elf-{name}", **overrides
                )
                self.assert_internal_rejects("validate-init", *values)

        for name, extra in {
            "host": "LOAD /usr/lib/x86_64-linux-gnu/libc.a\n",
            "tmp": "LOAD /tmp/host-input.o\n",
            "work": "LOAD /work/disposable-input.o\n",
            "unexpected-absolute": "LOAD /opt/unsealed/input.o\n",
            "unexpected-relative": "LOAD host-relative-input.o\n",
        }.items():
            with self.subTest(map=name):
                values = self.make_init_validation_fixture(
                    fixture_root / f"map-{name}", map_extra=extra
                )
                self.assert_internal_rejects("validate-init", *values)

        current_root = fixture_root / "map-current"
        current_values = self.make_init_validation_fixture(current_root)
        current_map = current_values[3]
        current_map.write_text(
            current_map.read_text(encoding="utf-8")
            + f"LOAD {current_values[4].parent / 'current' / 'libgcc.a'}\n",
            encoding="utf-8",
        )
        self.assert_internal_rejects("validate-init", *current_values)

        disposable_root = fixture_root / "map-disposable"
        disposable_values = self.make_init_validation_fixture(disposable_root)
        disposable_map = disposable_values[3]
        disposable_map.write_text(
            disposable_map.read_text(encoding="utf-8")
            + f"LOAD {disposable_root / '.tmp-build' / 'input.o'}\n",
            encoding="utf-8",
        )
        self.assert_internal_rejects("validate-init", *disposable_values)

        escape_root = fixture_root / "map-escape"
        escape_values = self.make_init_validation_fixture(escape_root)
        outside = escape_root / "outside.a"
        outside.write_bytes(b"outside sealed roots\n")
        escaping = escape_values[4] / "lib" / "escape.a"
        escaping.symlink_to(outside)
        escape_map = escape_values[3]
        escape_map.write_text(
            escape_map.read_text(encoding="utf-8") + f"LOAD {escaping}\n",
            encoding="utf-8",
        )
        self.assert_internal_rejects("validate-init", *escape_values)

    def test_serial_helper_enforces_order_identity_and_terminal_state(self) -> None:
        release = "7.2.0-rc6-cajunos"
        build_id = "kernel-first-boot-0123456789ab-0123456789abcdef"
        positive_lines = [
            "CAJUNOS_KERNEL_FIRST_BOOT_BEGIN",
            "CAJUNOS_KERNEL_FIRST_BOOT_PID1_OK",
            f"CAJUNOS_KERNEL_FIRST_BOOT_UNAME {release}",
            f"CAJUNOS_KERNEL_FIRST_BOOT_BUILD_ID {build_id}",
            "CAJUNOS_KERNEL_FIRST_BOOT_PROC_OK",
            "CAJUNOS_KERNEL_FIRST_BOOT_CMDLINE_OK",
            "CAJUNOS_KERNEL_FIRST_BOOT_OK",
        ]
        positive = self.temporary_root / "positive.log"
        positive.write_text("\n".join(positive_lines) + "\n", encoding="utf-8")
        self.assert_internal_accepts(
            "validate-serial", "positive", positive, release, build_id
        )

        mutations = {
            "wrong-release": [
                line.replace(release, "7.2.0-rc6-host") for line in positive_lines
            ],
            "reordered": [positive_lines[1], positive_lines[0], *positive_lines[2:]],
            "failure-present": [
                *positive_lines[:-1],
                "CAJUNOS_KERNEL_FIRST_BOOT_FAIL cmdline-token",
                positive_lines[-1],
            ],
            "missing-marker": [
                line
                for line in positive_lines
                if line != "CAJUNOS_KERNEL_FIRST_BOOT_PROC_OK"
            ],
            "duplicate-success": [*positive_lines, positive_lines[-1]],
            "duplicate-identity": [positive_lines[0], *positive_lines],
            "unknown-marker": [
                *positive_lines[:-1],
                "CAJUNOS_KERNEL_FIRST_BOOT_MAYBE",
                positive_lines[-1],
            ],
            "kernel-panic": [
                *positive_lines[:-1],
                "Kernel panic - not syncing: attempted to kill init!",
                positive_lines[-1],
            ],
            "kernel-oops": [
                *positive_lines[:-1],
                "Oops: 0000 [#1]",
                positive_lines[-1],
            ],
            "kernel-bug": [
                *positive_lines[:-1],
                "BUG: unable to handle page fault",
                positive_lines[-1],
            ],
        }
        for name, lines in mutations.items():
            with self.subTest(name=name):
                path = self.temporary_root / f"positive-{name}.log"
                path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                self.assert_internal_rejects(
                    "validate-serial", "positive", path, release, build_id
                )

        crlf = self.temporary_root / "positive-crlf.log"
        crlf.write_bytes(("\r\n".join(positive_lines) + "\r\n").encode("ascii"))
        normalized = self.temporary_root / "positive.normalized"
        self.assert_internal_accepts(
            "validate-serial", "positive", crlf, release, build_id, normalized
        )
        self.assertEqual(
            normalized.read_text(encoding="utf-8"),
            "\n".join(positive_lines) + "\n",
        )
        self.assertEqual(stat.S_IMODE(normalized.stat().st_mode), 0o644)

        for name, data in {
            "nul": b"CAJUNOS_KERNEL_FIRST_BOOT_BEGIN\0\n",
            "terminal-escape": b"\x1b[31mCAJUNOS_KERNEL_FIRST_BOOT_BEGIN\n",
            "invalid-utf8": b"CAJUNOS_KERNEL_FIRST_BOOT_BEGIN\xff\n",
        }.items():
            with self.subTest(raw=name):
                path = self.temporary_root / f"positive-{name}.raw"
                path.write_bytes(data)
                self.assert_internal_rejects(
                    "validate-serial", "positive", path, release, build_id
                )

        negative = self.temporary_root / "negative.log"
        negative.write_text(
            "CAJUNOS_KERNEL_FIRST_BOOT_BEGIN\n"
            "CAJUNOS_KERNEL_FIRST_BOOT_PID1_OK\n"
            f"CAJUNOS_KERNEL_FIRST_BOOT_UNAME {release}\n"
            f"CAJUNOS_KERNEL_FIRST_BOOT_BUILD_ID {build_id}\n"
            "CAJUNOS_KERNEL_FIRST_BOOT_PROC_OK\n"
            "CAJUNOS_KERNEL_FIRST_BOOT_FAIL cmdline-token\n",
            encoding="utf-8",
        )
        self.assert_internal_accepts(
            "validate-serial", "negative", negative, release, build_id
        )
        negative.write_text(
            negative.read_text(encoding="utf-8")
            + "CAJUNOS_KERNEL_FIRST_BOOT_OK\n",
            encoding="utf-8",
        )
        self.assert_internal_rejects(
            "validate-serial", "negative", negative, release, build_id
        )

        for name, replacement in {
            "wrong-reason": "CAJUNOS_KERNEL_FIRST_BOOT_FAIL wrong-release",
            "kernel-panic": "Kernel panic - not syncing: fatal exception",
        }.items():
            with self.subTest(negative=name):
                contents = negative.read_text(encoding="utf-8").replace(
                    "CAJUNOS_KERNEL_FIRST_BOOT_FAIL cmdline-token", replacement
                ).replace("CAJUNOS_KERNEL_FIRST_BOOT_OK\n", "")
                path = self.temporary_root / f"negative-{name}.log"
                path.write_text(contents, encoding="utf-8")
                self.assert_internal_rejects(
                    "validate-serial", "negative", path, release, build_id
                )

        out_of_order = self.temporary_root / "negative-out-of-order.log"
        out_of_order.write_text(
            "CAJUNOS_KERNEL_FIRST_BOOT_BEGIN\n"
            "CAJUNOS_KERNEL_FIRST_BOOT_PID1_OK\n"
            f"CAJUNOS_KERNEL_FIRST_BOOT_UNAME {release}\n"
            f"CAJUNOS_KERNEL_FIRST_BOOT_BUILD_ID {build_id}\n"
            "CAJUNOS_KERNEL_FIRST_BOOT_FAIL cmdline-token\n"
            "CAJUNOS_KERNEL_FIRST_BOOT_PROC_OK\n",
            encoding="utf-8",
        )
        self.assert_internal_rejects(
            "validate-serial", "negative", out_of_order, release, build_id
        )

        for name, lines in {
            "duplicate-failure": [
                *negative.read_text(encoding="utf-8").splitlines()[:-1],
                "CAJUNOS_KERNEL_FIRST_BOOT_FAIL cmdline-token",
                "CAJUNOS_KERNEL_FIRST_BOOT_FAIL cmdline-token",
            ],
            "unknown-marker": [
                *negative.read_text(encoding="utf-8").splitlines()[:-1],
                "CAJUNOS_KERNEL_FIRST_BOOT_UNKNOWN",
                "CAJUNOS_KERNEL_FIRST_BOOT_FAIL cmdline-token",
            ],
        }.items():
            with self.subTest(negative=name):
                path = self.temporary_root / f"negative-{name}.log"
                path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                self.assert_internal_rejects(
                    "validate-serial", "negative", path, release, build_id
                )

    def test_newc_helper_parses_exact_topology_and_device_numbers(self) -> None:
        valid = self.temporary_root / "valid.cpio"
        valid.write_bytes(newc_archive())
        self.assert_internal_accepts("validate-newc", valid)
        matching_init = self.temporary_root / "init"
        matching_init.write_bytes(b"fixture-static-init\n")
        self.assert_internal_accepts("validate-newc", valid, matching_init)
        matching_init.write_bytes(b"different sealed init\n")
        self.assert_internal_rejects("validate-newc", valid, matching_init)

        wrong_console = self.temporary_root / "wrong-console.cpio"
        wrong_console.write_bytes(newc_archive(console_major=4))
        self.assert_internal_rejects("validate-newc", wrong_console)

        unexpected = self.temporary_root / "unexpected.cpio"
        unexpected.write_bytes(newc_archive(unexpected=True))
        self.assert_internal_rejects("validate-newc", unexpected)

        corrupt = self.temporary_root / "corrupt.cpio"
        corrupt.write_bytes(b"not-newc\n")
        self.assert_internal_rejects("validate-newc", corrupt)

        for mutation in (
            "missing-entry",
            "duplicate-name",
            "duplicate-inode",
            "wrong-inode-sequence",
            "non-root-owner",
            "non-root-group",
            "wrong-mode",
            "wrong-mtime",
            "wrong-dev",
            "alternate-dev",
            "wrong-nlink",
            "wrong-order",
            "empty-init",
            "traversal",
            "absolute-name",
            "missing-trailer",
            "trailer-metadata",
            "truncated",
            "nonzero-entry-padding",
            "excess-zero-padding",
            "trailing-garbage",
        ):
            with self.subTest(mutation=mutation):
                path = self.temporary_root / f"{mutation}.cpio"
                path.write_bytes(newc_archive(mutation=mutation))
                self.assert_internal_rejects("validate-newc", path)

    @staticmethod
    def regular_tree_hashes(root: Path) -> dict[str, str]:
        return {
            path.relative_to(root).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

    @staticmethod
    def plain_inventory(root: Path) -> dict[str, object]:
        entries: dict[str, object] = {
            ".": {
                "type": "directory",
                "mode": f"{stat.S_IMODE(root.stat().st_mode):04o}",
            }
        }
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                entries[relative] = {
                    "type": "directory",
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                }
            elif stat.S_ISREG(metadata.st_mode):
                entries[relative] = {
                    "type": "file",
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            else:
                raise AssertionError(f"unsupported fixture entry: {path}")
        encoded = json.dumps(
            entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        return {
            "entries": entries,
            "digest": hashlib.sha256(encoded).hexdigest(),
        }

    def test_receipt_helper_rejects_artifact_and_reproducibility_tampering(
        self,
    ) -> None:
        artifact = self.temporary_root / "artifact"
        for subtree in ("boot", "configuration", "probe", "licenses"):
            (artifact / subtree).mkdir(parents=True)
        (artifact / "boot/bzImage").write_bytes(b"sealed kernel\n")
        (artifact / "probe/positive.serial").write_text(
            "CAJUNOS_KERNEL_FIRST_BOOT_OK\n", encoding="utf-8"
        )
        for kind in ("positive", "negative"):
            (artifact / f"probe/{kind}.serial.raw").write_bytes(
                f"{kind} evidence\r\n".encode("ascii")
            )
            (artifact / f"probe/{kind}.serial.normalized").write_text(
                f"{kind} evidence\n", encoding="utf-8"
            )
        (artifact / "licenses/COPYING").write_text(
            "fixture license\n", encoding="utf-8"
        )
        inventory = self.plain_inventory(artifact / "boot")
        inventory_a = artifact / "configuration/inventory-a.json"
        inventory_b = artifact / "configuration/inventory-b.json"
        for path in (inventory_a, inventory_b):
            path.write_text(
                json.dumps(inventory, sort_keys=True) + "\n", encoding="utf-8"
            )

        subtree_hashes = {
            subtree: self.regular_tree_hashes(artifact / subtree)
            for subtree in ("boot", "configuration", "probe", "licenses")
        }
        receipt_value = {
            "schema": 1,
            "component": "linux",
            "stage": "first-boot",
            "outputs": {"subtree_sha256": subtree_hashes},
            "reproducibility": {"inventory": inventory},
        }
        receipt = artifact / "receipt.json"
        receipt.write_text(
            json.dumps(receipt_value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        receipt.chmod(0o644)
        arguments = (
            "validate-receipt",
            receipt,
            artifact,
            "schema",
            "1",
            "component",
            "linux",
            "stage",
            "first-boot",
        )
        self.assert_internal_accepts(*arguments)

        kernel = artifact / "boot/bzImage"
        kernel.write_bytes(b"tampered kernel\n")
        self.assert_internal_rejects(*arguments)
        kernel.write_bytes(b"sealed kernel\n")

        inventory_b.write_text(
            json.dumps({"digest": "different", "entries": []}) + "\n",
            encoding="utf-8",
        )
        mismatched_receipt = json.loads(json.dumps(receipt_value))
        mismatched_receipt["outputs"]["subtree_sha256"]["configuration"] = (
            self.regular_tree_hashes(artifact / "configuration")
        )
        receipt.write_text(
            json.dumps(mismatched_receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.assert_internal_rejects(*arguments)
        inventory_b.write_text(
            json.dumps(inventory, sort_keys=True) + "\n", encoding="utf-8"
        )
        receipt.write_text(
            json.dumps(receipt_value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        tampered_receipt = json.loads(receipt.read_text(encoding="utf-8"))
        tampered_receipt["outputs"]["subtree_sha256"]["boot"]["bzImage"] = "0" * 64
        receipt.write_text(
            json.dumps(tampered_receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.assert_internal_rejects(*arguments)

    def test_orchestrator_binds_surfaces_and_uses_diskless_explicit_qemu(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for expected in (
            "configs/x86_64-first-boot.config",
            "initramfs/first-boot-init.c",
            "pc-q35-10.0",
            "Nehalem-v1",
            "-nodefaults",
            "-nic none",
            "-kernel",
            "-initrd",
            "cajunos.first_boot=1",
            "cajunos.first_boot=0",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, source)

    def test_orchestrator_pins_minimal_environments_firmware_and_mutable_inputs(
        self,
    ) -> None:
        source = SCRIPT.read_text(encoding="utf-8")

        self.assertGreaterEqual(source.count("env -i "), 6)
        self.assertGreaterEqual(
            source.count('KCONFIG_CONFIG="$build/.config"'), 3
        )
        for expected in (
            'host_cc=/usr/bin/gcc',
            'host_cxx=/usr/bin/g++',
            'HOSTCC="$host_cc" HOSTCXX="$host_cxx"',
            'host_cc_sha256=$(sha256sum "$host_cc_resolved"',
            'host_cxx_sha256=$(sha256sum "$host_cxx_resolved"',
            'qemu_bios=/usr/share/seabios/bios-256k.bin',
            'qemu_linuxboot=/usr/share/qemu/linuxboot_dma.bin',
            'qemu_kvmvapic=/usr/share/qemu/kvmvapic.bin',
            '-bios "$qemu_bios"',
            'qemu_bios_sha256=$(sha256sum "$qemu_bios"',
            'qemu_linuxboot_sha256=$(sha256sum "$qemu_linuxboot"',
            'qemu_kvmvapic_sha256=$(sha256sum "$qemu_kvmvapic"',
            'validate_mutable_inputs() {',
            '$(sha256sum "$script_path"',
            '$(sha256sum "$inventory_helper"',
            '$(sha256sum "$gcc_helper"',
            '$(sha256sum "$libgcc_helper"',
            '$(sha256sum "$glibc_helper"',
            '$(sha256sum "$config_source"',
            '$(sha256sum "$init_source"',
            '$(sha256sum "$qemu_path"',
            '$(sha256sum "$host_cc_resolved"',
            '$(sha256sum "$host_cxx_resolved"',
            'recipe_sha256 "$recipe_sha256"',
            'inventory_helper_sha256 "$inventory_helper_sha256"',
            'gcc_helper_sha256 "$gcc_helper_sha256"',
            'libgcc_helper_sha256 "$libgcc_helper_sha256"',
            'glibc_helper_sha256 "$glibc_helper_sha256"',
            'config_sha256 "$config_sha256"',
            'init_source_sha256 "$init_source_sha256"',
            'dependencies.gcc.receipt_sha256 "$gcc_receipt_sha256"',
            'dependencies.libgcc.receipt_sha256 "$libgcc_receipt_sha256"',
            'dependencies.stage1_gcc.receipt_sha256 "$stage1_gcc_receipt_sha256"',
            'dependencies.glibc.receipt_sha256 "$glibc_receipt_sha256"',
            'dependencies.binutils.receipt_sha256 "$binutils_receipt_sha256"',
            'dependencies.linux_uapi.receipt_sha256 "$linux_uapi_receipt_sha256"',
            'qemu.firmware.bios.sha256 "$qemu_bios_sha256"',
            'qemu.firmware.linuxboot_dma.sha256 "$qemu_linuxboot_sha256"',
            'qemu.firmware.kvmvapic.sha256 "$qemu_kvmvapic_sha256"',
            'host.kernel_cc.sha256 "$host_cc_sha256"',
            'host.kernel_cxx.sha256 "$host_cxx_sha256"',
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, source)

        self.assertGreaterEqual(source.count("validate_mutable_inputs ||"), 5)


if __name__ == "__main__":
    unittest.main()
