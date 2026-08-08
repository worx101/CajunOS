import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/prepare-native-developer-deployment.sh"
BUILD = ROOT / "scripts/build-native-developer-seed.sh"
RCS = ROOT / "rootfs/native-developer/etc/init.d/rcS"
RCK = ROOT / "rootfs/native-developer/etc/init.d/rcK"
BUSYBOX = ROOT / "configs/busybox-native-developer.fragment"

DISK_GUID_A = "11111111-1111-4111-8111-111111111111"
PARTUUID_A = "22222222-2222-4222-8222-222222222222"
FS_UUID_A = "33333333-3333-4333-8333-333333333333"
FS_UUID_B = "44444444-4444-4444-8444-444444444444"
SOURCE_BUILD = "native-developer-contract-test"
SOURCE_CONTRACT = {
    "disk_guid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "bios_partuuid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    "root_partuuid": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    "root_uuid": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
    "source_date_epoch": 1735689600,
}


class NativeDeveloperDeploymentTests(unittest.TestCase):
    def run_helper(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(HELPER), *map(str, arguments)], cwd=ROOT,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    def contract(self, filesystem_uuid: str = FS_UUID_A) -> dict:
        result = self.run_helper(
            "--internal-python", "deployment-contract", SOURCE_BUILD,
            DISK_GUID_A, PARTUUID_A, filesystem_uuid,
            json.dumps(SOURCE_CONTRACT),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_helper_is_executable_and_shell_syntax_is_valid(self) -> None:
        self.assertTrue(HELPER.stat().st_mode & 0o111)
        result = subprocess.run(
            ["bash", "-n", str(HELPER)], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_geometry_is_exact_16_to_64_plus_256_gib(self) -> None:
        result = self.run_helper("--internal-python", "geometry")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {
            "source_disk_bytes": 16 * 1024**3,
            "deployed_os_bytes": 64 * 1024**3,
            "build_disk_bytes": 256 * 1024**3,
            "first_sector": 4096,
            "deployed_root_sectors": 134213599,
            "deployed_root_blocks": 16776699,
            "build_partition_sectors": 536866783,
            "build_filesystem_blocks": 67108347,
            "build_statfs_blocks": 66776076,
        })

    def test_a_b_contracts_are_replayable_distinct_and_hash_bound(self) -> None:
        first_a = self.contract()
        second_a = self.contract()
        build_b = self.contract(FS_UUID_B)
        self.assertEqual(first_a, second_a)
        self.assertNotEqual(first_a["deployment_id"], build_b["deployment_id"])
        self.assertNotEqual(first_a["sentinel_sha256"], build_b["sentinel_sha256"])
        self.assertEqual(
            hashlib.sha256(first_a["sentinel"].encode("ascii")).hexdigest(),
            first_a["sentinel_sha256"],
        )
        self.assertIn(f"build_partuuid={PARTUUID_A}\n", first_a["sentinel"])
        self.assertIn(f"build_filesystem_uuid={FS_UUID_A}\n", first_a["sentinel"])
        self.assertIn("filesystem_label=CAJUNOS_BUILD\n", first_a["sentinel"])
        self.assertIn("filesystem_epoch=1735689600\n", first_a["sentinel"])
        self.assertEqual(
            first_a["fstab_entry"],
            f"PARTUUID={PARTUUID_A} /build ext4 rw,nosuid,nodev 0 2",
        )

    def test_contract_materializer_executes_and_writes_exact_files(self) -> None:
        contract = self.contract()
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_helper(
                "--internal-materialize-contract", directory,
                json.dumps(contract, sort_keys=True),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            root = Path(directory)
            self.assertEqual(
                {path.name for path in root.iterdir()},
                {
                    "build-partuuid", "build-fs-uuid",
                    "build-sentinel-sha256", "build-sentinel",
                    "base-fstab", "deployment-fstab",
                },
            )
            for path in root.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                (root / "build-partuuid").read_text(encoding="ascii"),
                PARTUUID_A + "\n",
            )
            self.assertEqual(
                (root / "build-sentinel").read_text(encoding="ascii"),
                contract["sentinel"],
            )
            self.assertEqual(
                (root / "deployment-fstab").read_text(encoding="ascii"),
                (root / "base-fstab").read_text(encoding="ascii")
                + contract["fstab_entry"] + "\n",
            )

    def test_internal_hooks_reject_unsafe_paths_without_writes(self) -> None:
        contract = self.contract()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            protected = root / "protected"
            protected.mkdir(mode=0o700)
            unsafe_777 = root / "unsafe-777"
            unsafe_777.mkdir()
            unsafe_777.chmod(0o777)
            unsafe_755 = root / "unsafe-755"
            unsafe_755.mkdir()
            unsafe_755.chmod(0o755)
            unsafe_ancestor = root / "unsafe-ancestor"
            unsafe_ancestor.mkdir()
            unsafe_ancestor.chmod(0o777)
            unsafe_nested = unsafe_ancestor / "private"
            unsafe_nested.mkdir(mode=0o700)
            linked = root / "linked"
            linked.symlink_to(protected, target_is_directory=True)

            for target in (unsafe_777, unsafe_755, unsafe_nested, linked):
                with self.subTest(target=target, hook="materialize"):
                    result = self.run_helper(
                        "--internal-materialize-contract", target,
                        json.dumps(contract, sort_keys=True),
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(list(target.iterdir()), [])
                with self.subTest(target=target, hook="create-build-disk"):
                    output = target / "build.raw"
                    result = self.run_helper(
                        "--internal-create-build-disk", output,
                        1024**3, "ext2", DISK_GUID_A, PARTUUID_A,
                        FS_UUID_A, SOURCE_CONTRACT["source_date_epoch"],
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output.exists())
                    self.assertFalse(output.is_symlink())

            unsafe_sentinel = protected / "sentinel"
            unsafe_sentinel.write_text("sentinel\n", encoding="ascii")
            unsafe_sentinel.chmod(0o644)
            self.assertEqual(unsafe_sentinel.stat().st_mode & 0o777, 0o644)
            output = protected / "build.raw"
            result = self.run_helper(
                "--internal-create-build-disk", output,
                1024**3, "ext2", DISK_GUID_A, PARTUUID_A,
                FS_UUID_A, SOURCE_CONTRACT["source_date_epoch"],
                unsafe_sentinel,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            self.assertFalse(output.is_symlink())

            real_sentinel = protected / "real-sentinel"
            real_sentinel.write_text("sentinel\n", encoding="ascii")
            real_sentinel.chmod(0o600)
            linked_sentinel = protected / "linked-sentinel"
            linked_sentinel.symlink_to(real_sentinel)
            output = protected / "linked-sentinel.raw"
            result = self.run_helper(
                "--internal-create-build-disk", output,
                1024**3, "ext2", DISK_GUID_A, PARTUUID_A,
                FS_UUID_A, SOURCE_CONTRACT["source_date_epoch"],
                linked_sentinel,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            self.assertFalse(output.is_symlink())

    def test_invalid_identity_fails_closed(self) -> None:
        for invalid in (
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".upper(),
            "not-a-uuid", "22222222-2222-2222-2222-22222222222",
        ):
            with self.subTest(invalid=invalid):
                result = self.run_helper(
                    "--internal-python", "deployment-contract", SOURCE_BUILD,
                    DISK_GUID_A, invalid, FS_UUID_A,
                    json.dumps(SOURCE_CONTRACT),
                )
                self.assertNotEqual(result.returncode, 0)

    def test_nil_duplicate_and_source_identity_collisions_fail_closed(self) -> None:
        nil = "00000000-0000-0000-0000-000000000000"
        source_contract = dict(SOURCE_CONTRACT)
        cases = (
            (nil, PARTUUID_A, FS_UUID_A),
            (DISK_GUID_A, PARTUUID_A, PARTUUID_A),
            (source_contract["disk_guid"], PARTUUID_A, FS_UUID_A),
        )
        for identifiers in cases:
            with self.subTest(identifiers=identifiers):
                result = self.run_helper(
                    "--internal-python", "deployment-contract", SOURCE_BUILD,
                    *identifiers, json.dumps(source_contract),
                )
                self.assertNotEqual(result.returncode, 0)

    def test_helper_uses_offline_loop_mapping_and_sparse_direct_format(self) -> None:
        text = HELPER.read_text(encoding="utf-8")
        self.assertIn("losetup --find --show --partscan", text)
        self.assertIn('"$os_root_device" 16776699', text)
        self.assertIn("offset=$((4096 * 512))", text)
        self.assertIn('hash_seed="$filesystem_uuid"', text)
        self.assertNotIn("copy-sparse-range", text)
        self.assertIn("publish_no_replace", text)
        self.assertIn("secure-output-parent", text)
        self.assertIn("published_disks_replayed_before_evidence_publication", text)
        self.assertIn("validate_published_deployment", text)
        self.assertIn("dump_directory=$(mktemp -d)", text)
        self.assertIn("build_stage=$(mktemp -d", text)
        self.assertIn("Deployment output paths must be three distinct files", text)
        self.assertIn("Stage 9B receipt changed during deployment preparation", text)
        build_function = text.split("create_build_disk()", 1)[1].split(
            "normalize_ext_superblock_time()", 1
        )[0]
        self.assertLess(build_function.index("e2fsck -f -y"),
                        build_function.index("normalize_ext_superblock_time"))
        self.assertLess(build_function.index("normalize_ext_superblock_time"),
                        build_function.index("validate-ext-times"))
        self.assertLess(build_function.index("validate-ext-times"),
                        build_function.index("verify_ext_noop_fsck"))
        self.assertLess(build_function.index("verify_ext_noop_fsck"),
                        build_function.rindex("validate_ext_file"))

    def test_environment_poison_is_scrubbed_before_internal_dispatch(self) -> None:
        result = subprocess.run(
            [str(HELPER), "--internal-python", "geometry"], cwd=ROOT,
            env={
                "PATH": "/usr/bin:/bin", "E2FSPROGS_FAKE_TIME": "1",
                "E2FSPROGS_UNDO_DIR": "/invalid", "MKE2FS_CONFIG": "/invalid",
                "E2FSCK_TIME": "2", "SOURCE_DATE_EPOCH": "3",
            }, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["build_statfs_blocks"], 66776076)

    def test_output_parent_policy_rejects_writable_ancestors(self) -> None:
        rejected = self.run_helper(
            "--internal-python", "secure-output-parent", "/tmp/cajunos-output.raw",
        )
        self.assertNotEqual(rejected.returncode, 0)
        accepted = self.run_helper(
            "--internal-python", "secure-output-parent",
            "/var/lib/cajunos-nonexistent-output.raw",
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

    def test_a_b_evidence_comparison_requires_byte_identical_independent_outputs(self) -> None:
        contract = self.contract()
        common = {
            "schema": 1,
            "stage": "native-developer-deployment-preparation",
            "source": {"same": True},
            "device_name_dependency": False,
            "deployment_contract": contract,
            "deployment_helper_sha256": "a" * 64,
            "validation": {"same": True},
        }
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            paths = []
            for label in ("a", "b"):
                value = {
                    **common,
                    "os_disk": {
                        "path": f"/{label}/os.raw", "sha256": "b" * 64,
                        "contract": {"same": True},
                        "prepared_offline_before_first_boot": True,
                    },
                    "build_disk": {
                        "path": f"/{label}/build.raw", "sha256": "c" * 64,
                        "contract": {"same": True},
                        "prepared_offline_before_first_boot": True,
                    },
                }
                path = directory / f"{label}.json"
                path.write_text(json.dumps(value) + "\n", encoding="utf-8")
                path.chmod(0o644)
                paths.append(path)
            result = self.run_helper(
                "--internal-python", "compare-evidence", *paths,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["byte_identical"])
            value = json.loads(paths[1].read_text(encoding="utf-8"))
            value["build_disk"]["sha256"] = "d" * 64
            paths[1].write_text(json.dumps(value) + "\n", encoding="utf-8")
            result = self.run_helper(
                "--internal-python", "compare-evidence", *paths,
            )
            self.assertNotEqual(result.returncode, 0)

    def test_runtime_hook_is_optional_complete_and_device_name_independent(self) -> None:
        text = RCS.read_text(encoding="utf-8")
        self.assertEqual(
            text.count("echo CAJUNOS_NATIVE_DEVELOPER_BUILD_VOLUME_OK"), 1
        )
        self.assertLess(
            text.index("echo CAJUNOS_NATIVE_DEVELOPER_BUILD_VOLUME_OK"),
            text.index("/usr/sbin/dropbear -F"),
        )
        self.assertIn('case "$build_contract_count" in', text)
        self.assertIn("fail build-contract-count", text)
        self.assertIn('/sbin/blkid "$build_device"', text)
        self.assertIn('TYPE="ext4"', text)
        self.assertIn('LABEL="CAJUNOS_BUILD"', text)
        self.assertIn("536870912", text)
        self.assertIn("536866783", text)
        self.assertIn("4096:66776076:1048576", text)
        self.assertIn("rw,nosuid,nodev,errors=remount-ro", text)
        self.assertIn("/.cajunos-build-volume", text)
        self.assertIn("build-fstab-contract", text)
        self.assertIn("build-pristine-fstab", text)
        self.assertIn(".cajunos-runtime-probe", text)
        self.assertNotIn(".$$", text)
        self.assertNotIn("/dev/sdb", text)

    def test_static_network_is_optional_strict_and_dhcp_remains_default(self) -> None:
        text = RCS.read_text(encoding="utf-8")
        self.assertIn("static_network_file=/etc/cajunos-static-network", text)
        self.assertIn('substr($0, 1, 8) != "address="', text)
        self.assertIn('substr($0, 1, 8) != "gateway="', text)
        self.assertIn('substr($0, 1, 4) != "dns="', text)
        self.assertIn("static-network-lines", text)
        self.assertIn("/sbin/ip -4 addr flush dev eth0", text)
        self.assertIn("/sbin/ip -4 route flush dev eth0", text)
        self.assertIn("/sbin/ip -4 route add default via", text)
        self.assertLess(text.index("if [ -e \"$static_network_file\""),
                        text.index("/sbin/udhcpc -f -n"))
        self.assertEqual(text.count("echo CAJUNOS_NATIVE_DEVELOPER_NETWORK_OK"), 1)
        self.assertEqual(text.count('echo "CAJUNOS_NATIVE_DEVELOPER_IPV4 $ipv4"'), 1)
        self.assertNotIn("10.10.10.", text)

        static_section = text.split("static_network_file=/etc/cajunos-static-network", 1)[1]
        validator = static_section.split("    /usr/bin/awk '\n", 1)[1].split(
            "\n    ' \"$static_network_file\"", 1
        )[0]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "network"
            for value, accepted in (
                ("address=10.10.10.18/24\ngateway=10.10.10.1\ndns=10.10.10.10\n", True),
                ("address=192.0.2.7/32\ngateway=192.0.2.1\ndns=1.1.1.1\n", True),
                ("address=010.10.10.18/24\ngateway=10.10.10.1\ndns=10.10.10.10\n", False),
                ("address=10.10.10.18/33\ngateway=10.10.10.1\ndns=10.10.10.10\n", False),
                ("gateway=10.10.10.1\naddress=10.10.10.18/24\ndns=10.10.10.10\n", False),
            ):
                with self.subTest(value=value):
                    path.write_text(value, encoding="ascii")
                    result = subprocess.run(
                        ["awk", validator, path], text=True,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    )
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_shutdown_unmounts_build_before_general_unmount(self) -> None:
        text = RCK.read_text(encoding="utf-8")
        self.assertLess(text.index("/bin/umount /build"), text.index("/bin/umount -a -r"))
        self.assertLess(text.index("/bin/sync", text.index("stop_pidfile /run/udhcpc")),
                        text.index("/bin/umount /build"))

    def test_busybox_and_pristine_stage_bind_the_hook_and_helper(self) -> None:
        config = BUSYBOX.read_text(encoding="utf-8")
        for line in (
            "CONFIG_BLKID=y", "CONFIG_FEATURE_BLKID_TYPE=y",
            "CONFIG_FEATURE_VOLUMEID_EXT=y", "CONFIG_FEATURE_STAT_FILESYSTEM=y",
        ):
            self.assertIn(line, config)
        build = BUILD.read_text(encoding="utf-8")
        self.assertIn('install -d -m 0755 "$root/build"', build)
        self.assertIn("deployment_helper_sha256", build)
        self.assertIn("retained deployment helper differs from its receipt hash", build)
        self.assertIn(
            'cmp -- "$artifact/configuration/deployment-preparation.sh"', build
        )
        self.assertIn("pristine root contains a deployment-specific", build)
        self.assertIn(
            "pristine root contains a deployment-specific static network contract",
            build,
        )
        self.assertIn("dhcpv4-default-static-file-optional", build)


if __name__ == "__main__":
    unittest.main()
