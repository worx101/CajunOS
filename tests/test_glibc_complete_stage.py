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
SCRIPT = PROJECT / "scripts/build-glibc-complete.sh"
COMMIT = "97f74c6781184a807faa3c0c02f6c5822a98b731"


class GlibcCompleteStageTests(unittest.TestCase):
    def command(self, *arguments, check=True):
        return subprocess.run(
            [SCRIPT, "--internal-python", *map(str, arguments)],
            check=check,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    @staticmethod
    def write(path, data=b"x", mode=0o644):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)

    def make_pair(self, root):
        base = root / "base"
        result = root / "result"
        self.write(
            base / "usr/include/gnu/stubs-64.h",
            b"/* provisional */\n",
        )
        for crt in ("crt1.o", "crti.o", "crtn.o"):
            self.write(base / "usr/lib" / crt, crt.encode())
        shutil.copytree(base, result, symlinks=True)
        self.write(
            result / "usr/include/gnu/stubs-64.h",
            b"#define __stub_chflags\n",
        )
        required = {
            "usr/lib/ld-linux-x86-64.so.2": 0o755,
            "usr/lib/libc.so.6": 0o755,
            "usr/lib/libc.so": 0o644,
            "usr/lib/libc.a": 0o644,
            "usr/lib/libc_nonshared.a": 0o644,
            "usr/bin/getconf": 0o755,
        }
        for relative, mode in required.items():
            self.write(result / relative, relative.encode(), mode)
        os.symlink("usr/lib", result / "lib64")
        return base, result

    def derive(self, base, result, output, check=True):
        return self.command("derived-delta", base, result, output, check=check)

    def test_build_id_is_stable_order_independent_and_sensitive(self):
        first = self.command("build-id", COMMIT, "a", "1", "b", "2").stdout
        reordered = self.command("build-id", COMMIT, "b", "2", "a", "1").stdout
        changed = self.command("build-id", COMMIT, "a", "1", "b", "3").stdout
        self.assertEqual(first, reordered)
        self.assertNotEqual(first, changed)
        self.assertRegex(first.strip(), r"^glibc-complete-97f74c678118-[0-9a-f]{16}$")

    def test_delta_records_one_replacement_and_runtime_additions(self):
        with tempfile.TemporaryDirectory() as directory:
            base, result = self.make_pair(Path(directory))
            output = Path(directory) / "delta.json"
            self.derive(base, result, output)
            delta = json.loads(output.read_text())
            self.assertEqual(delta["schema"], "sealed-base-transform-v1")
            self.assertEqual(
                set(delta["replaced_entries"]),
                {"usr/include/gnu/stubs-64.h"},
            )
            self.assertIn("usr/lib/libc.so.6", delta["added_entries"])
            self.assertEqual(
                delta["added_entries"]["lib64"],
                {"type": "symlink", "mode": "0777", "target": "usr/lib"},
            )

    def test_delta_rejects_a_second_inherited_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            base, result = self.make_pair(Path(directory))
            self.write(base / "usr/include/unchanged.h", b"before\n")
            self.write(result / "usr/include/unchanged.h", b"after\n")
            outcome = self.derive(
                base, result, Path(directory) / "delta.json", check=False
            )
            self.assertNotEqual(outcome.returncode, 0)
            self.assertIn("unexpected inherited-entry replacements", outcome.stderr)

    def test_delta_rejects_an_inherited_deletion(self):
        with tempfile.TemporaryDirectory() as directory:
            base, result = self.make_pair(Path(directory))
            (result / "usr/lib/crt1.o").unlink()
            outcome = self.derive(
                base, result, Path(directory) / "delta.json", check=False
            )
            self.assertNotEqual(outcome.returncode, 0)
            self.assertIn("sealed base entries disappeared", outcome.stderr)

    def test_delta_rejects_wrong_loader_or_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            base, result = self.make_pair(Path(directory))
            (result / "lib64").unlink()
            os.symlink("../outside", result / "lib64")
            outcome = self.derive(
                base, result, Path(directory) / "delta.json", check=False
            )
            self.assertNotEqual(outcome.returncode, 0)

    def test_delta_rejects_set_id_and_unexpected_root_output(self):
        with tempfile.TemporaryDirectory() as directory:
            base, result = self.make_pair(Path(directory))
            self.write(result / "opt/foreign", b"bad\n", 0o4755)
            outcome = self.derive(
                base, result, Path(directory) / "delta.json", check=False
            )
            self.assertNotEqual(outcome.returncode, 0)
            self.assertTrue(
                "set-id output is forbidden" in outcome.stderr
                or "unexpected complete-glibc top-level" in outcome.stderr
            )

    def test_no_shared_inodes_accepts_copy_and_rejects_hardlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base"
            copy = root / "copy"
            self.write(base / "usr/lib/libc.a", b"archive")
            shutil.copytree(base, copy)
            self.command("no-shared-inodes", base, copy)
            (copy / "usr/lib/libc.a").unlink()
            os.link(base / "usr/lib/libc.a", copy / "usr/lib/libc.a")
            outcome = self.command(
                "no-shared-inodes", base, copy, check=False
            )
            self.assertNotEqual(outcome.returncode, 0)
            self.assertIn("shares regular-file inodes", outcome.stderr)

    def test_elf_scan_is_deterministic_and_ignores_symlink_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "usr/bin/probe"
            executable.parent.mkdir(parents=True)
            shutil.copy2("/usr/bin/true", executable)
            os.symlink("probe", executable.parent / "probe-alias")
            first = json.loads(self.command("elf-scan", root).stdout)
            second = json.loads(self.command("elf-scan", root).stdout)
            self.assertEqual(first, second)
            self.assertEqual(first["schema"], "cajunos-glibc-elf-scan-v2")
            self.assertEqual(len(first["elf_files"]), 1)
            self.assertEqual(first["elf_files"][0]["path"], "usr/bin/probe")
            self.assertEqual(first["origin_runpath"], [])

    def test_elf_scan_separates_gconv_origin_from_escaping_runpaths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "usr/lib/gconv/EUC-CN.so"
            escaping = root / "usr/lib/foreign.so"
            allowed.parent.mkdir(parents=True)
            escaping.parent.mkdir(parents=True, exist_ok=True)
            for output, runpath in (
                (allowed, "$ORIGIN"),
                (escaping, "$ORIGIN/.."),
            ):
                subprocess.run(
                    [
                        "/usr/bin/gcc", "-shared", "-fPIC",
                        "-Wl,--enable-new-dtags", f"-Wl,-rpath,{runpath}",
                        "-x", "c", "-", "-o", output,
                    ],
                    input="int cajunos_probe(void) { return 0; }\n",
                    text=True,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            scan = json.loads(self.command("elf-scan", root).stdout)
            self.assertEqual(
                scan["origin_runpath"],
                ["usr/lib/gconv/EUC-CN.so: RUNPATH=$ORIGIN"],
            )
            self.assertEqual(
                scan["escaping_rpath_runpath"],
                ["usr/lib/foreign.so: RUNPATH=$ORIGIN/.."],
            )

    def test_selector_rollback_is_compare_and_swap(self):
        with tempfile.TemporaryDirectory() as directory:
            sysroot = Path(directory) / "sysroot"
            snapshots = sysroot / "snapshots"
            for build_id in ("base", "result", "unrelated"):
                (snapshots / build_id / "usr").mkdir(parents=True)
            os.symlink("snapshots/result", sysroot / "current")
            os.symlink("current/usr", sysroot / "usr")

            outcome = self.command(
                "selector-rollback", sysroot, "base", "result"
            )
            self.assertEqual(outcome.stdout.strip(), "rolled-back")
            self.assertEqual(os.readlink(sysroot / "current"), "snapshots/base")

            (sysroot / "current").unlink()
            os.symlink("snapshots/unrelated", sysroot / "current")
            refused = self.command(
                "selector-rollback", sysroot, "base", "result", check=False
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(
                os.readlink(sysroot / "current"), "snapshots/unrelated"
            )


if __name__ == "__main__":
    unittest.main()
