#!/usr/bin/env python3

import copy
import importlib.util
import json
from pathlib import Path
import re
import unittest
from urllib.parse import urlsplit


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_MODULE_PATH = PROJECT_ROOT / "scripts" / "fetch.py"
SPEC = importlib.util.spec_from_file_location("cajunos_sources", SOURCE_MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
SOURCES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOURCES)


class BootstrapManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with (PROJECT_ROOT / "manifests" / "bootstrap.json").open(encoding="utf-8") as stream:
            cls.manifest = json.load(stream)
        with (PROJECT_ROOT / "locks" / "bootstrap.lock.json").open(encoding="utf-8") as stream:
            cls.lock = json.load(stream)

    def test_schema_and_unique_names(self) -> None:
        SOURCES.validate_manifest(self.manifest)
        self.assertEqual(self.manifest["schema"], 1)
        names = [item["name"] for item in self.manifest["components"]]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), {"binutils", "gcc", "glibc", "linux"})

    def test_explicit_branch_refs(self) -> None:
        for component in self.manifest["components"]:
            self.assertTrue(component["ref"].startswith("refs/heads/"))

    def test_repositories_are_credential_free_official_transports(self) -> None:
        for component in self.manifest["components"]:
            for repository in component["repositories"]:
                parsed = urlsplit(repository)
                self.assertIn(parsed.scheme, {"https", "git"})
                self.assertIsNotNone(parsed.hostname)
                self.assertIsNone(parsed.username)
                self.assertIsNone(parsed.password)

    def test_lock_matches_manifest_and_has_full_object_ids(self) -> None:
        SOURCES.validate_lock(
            self.manifest,
            PROJECT_ROOT / "manifests" / "bootstrap.json",
            self.lock,
        )
        manifest = {item["name"]: item for item in self.manifest["components"]}
        locked = {item["name"]: item for item in self.lock["components"]}
        self.assertEqual(set(locked), set(manifest))
        for name, component in locked.items():
            self.assertRegex(component["commit"], re.compile(r"^[0-9a-f]{40}$"))
            self.assertRegex(component["tree"], re.compile(r"^[0-9a-f]{40}$"))
            self.assertEqual(component["ref"], manifest[name]["ref"])
            self.assertEqual(
                component["canonical_repository"], manifest[name]["repositories"][0]
            )

    def test_source_set_digest_covers_immutable_materials(self) -> None:
        expected = SOURCES.source_set_digest(self.lock["components"])
        self.assertEqual(self.lock["source_set_digest"], expected)

    def test_lock_rejects_incorrect_aggregate_authentication(self) -> None:
        tampered = copy.deepcopy(self.lock)
        tampered["source_authentication"] = "authenticated"
        with self.assertRaises(SOURCES.SourceError):
            SOURCES.validate_lock(
                self.manifest,
                PROJECT_ROOT / "manifests" / "bootstrap.json",
                tampered,
            )

    def test_authenticated_sync_never_downgrades_transport(self) -> None:
        component = next(
            item for item in self.manifest["components"] if item["name"] == "binutils"
        )
        https_url, git_url = component["repositories"]
        self.assertEqual(
            SOURCES.synchronization_urls(component, https_url),
            [https_url],
        )
        self.assertEqual(
            SOURCES.synchronization_urls(component, git_url),
            [git_url, https_url],
        )

    def test_manifest_rejects_credentials_and_bad_depth(self) -> None:
        credentialed = copy.deepcopy(self.manifest)
        credentialed["components"][0]["repositories"][0] = "https://user:secret@example.com/x"
        with self.assertRaises(SOURCES.SourceError):
            SOURCES.validate_manifest(credentialed)

        bad_depth = copy.deepcopy(self.manifest)
        bad_depth["components"][0]["depth"] = 0
        with self.assertRaises(SOURCES.SourceError):
            SOURCES.validate_manifest(bad_depth)


if __name__ == "__main__":
    unittest.main()
