from __future__ import annotations

import argparse
import hashlib
import io
import json
import shutil
import sys
import tarfile
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import build_catalog  # noqa: E402
import validate_release  # noqa: E402


class CatalogTest(unittest.TestCase):
    def setUp(self) -> None:
        test_temp = ROOT / ".test-tmp"
        test_temp.mkdir(exist_ok=True)
        self.root = test_temp / str(uuid.uuid4())
        self.root.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.root)

    def build(self, name: str, counts: dict[str, int], version: str = "2026.08.18.1", source_name: str | None = None) -> Path:
        apps = []
        source_name = source_name or name
        for app_id, count in counts.items():
            source = self.root / f"{source_name}-{app_id}.txt"
            source.write_text("".join(f"domain:{app_id}{index}.example.com\n" for index in range(count)), encoding="utf-8")
            apps.append({"id": app_id, "name": app_id.title(), "category": "test", "sources": [{"type": "fenliu", "path": str(source)}]})
        config = self.root / f"{name}.json"
        config.write_text(json.dumps({"schema": 1, "apps": apps}), encoding="utf-8")
        output = self.root / name
        build_catalog.build(argparse.Namespace(config=config, output=output, version=version, generated_at="2026-08-18T03:17:00Z", cache_dir=None, secret_key=None))
        return output

    def rewrite_archive(self, release: Path, files: dict[str, bytes]) -> None:
        archive = build_catalog.deterministic_archive(files)
        (release / "catalog.tar.gz").write_bytes(archive)
        manifest_path = release / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["archive"]["size"] = len(archive)
        manifest["archive"]["sha256"] = hashlib.sha256(archive).hexdigest()
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def archive_files(self, release: Path) -> dict[str, bytes]:
        with tarfile.open(release / "catalog.tar.gz", "r:gz") as archive:
            return {item.name: archive.extractfile(item).read() for item in archive.getmembers()}

    def test_first_release(self) -> None:
        candidate = validate_release.validate_release(self.build("first", {"alpha": 10}))
        changes, errors, warnings = validate_release.compare_releases(candidate, None, False)
        self.assertEqual((errors, warnings), ([], []))
        self.assertEqual(changes[0]["new"], 10)

    def test_unchanged_archive_is_detected(self) -> None:
        old_path = self.build("old", {"alpha": 10}, "2026.08.18.1", "unchanged")
        new_path = self.build("new", {"alpha": 10}, "2026.08.18.2", "unchanged")
        old = validate_release.validate_release(old_path)
        new = validate_release.validate_release(new_path)
        self.assertEqual(old.archive_sha256, new.archive_sha256)
        self.assertEqual(validate_release.compare_releases(new, old, False)[1], [])

    def test_normal_change_passes(self) -> None:
        old = validate_release.validate_release(self.build("old-normal", {"alpha": 50}))
        new = validate_release.validate_release(self.build("new-normal", {"alpha": 60}, "2026.08.18.2"))
        self.assertEqual(validate_release.compare_releases(new, old, False)[1], [])

    def test_upstream_failure_stops_build(self) -> None:
        config = self.root / "missing.json"
        config.write_text(json.dumps({"schema": 1, "apps": [{"id": "alpha", "name": "Alpha", "sources": [{"type": "fenliu", "path": str(self.root / "missing.txt")}]}]}), encoding="utf-8")
        with self.assertRaises(FileNotFoundError):
            build_catalog.build(argparse.Namespace(config=config, output=self.root / "missing", version="2026.08.18.1", generated_at="2026-08-18T03:17:00Z", cache_dir=None, secret_key=None))

    def test_unsigned_rebuild_removes_stale_signature(self) -> None:
        release = self.build("stale-signature", {"alpha": 5})
        signature = release / "manifest.json.sig"
        signature.write_text("stale", encoding="utf-8")
        self.build("stale-signature", {"alpha": 5}, "2026.08.18.2")
        self.assertFalse(signature.exists())

    def test_missing_required_signature_is_rejected(self) -> None:
        release = self.build("missing-signature", {"alpha": 5})
        with self.assertRaisesRegex(validate_release.ValidationError, "signature is missing"):
            validate_release.validate_release(release, ROOT / "catalog.pub", require_signature=True)

    def test_suspicious_change_is_blocked(self) -> None:
        old = validate_release.validate_release(self.build("old-large", {"alpha": 20}))
        new = validate_release.validate_release(self.build("new-large", {"alpha": 60}, "2026.08.18.2"))
        errors = validate_release.compare_releases(new, old, False)[1]
        self.assertTrue(any("alpha" in item for item in errors))
        self.assertTrue(any("catalog" in item for item in errors))

    def test_manual_override_allows_only_change_guards(self) -> None:
        old = validate_release.validate_release(self.build("old-allow", {"alpha": 20}))
        new = validate_release.validate_release(self.build("new-allow", {"alpha": 60, "beta": 5}, "2026.08.18.2"))
        _, errors, warnings = validate_release.compare_releases(new, old, True)
        self.assertEqual(errors, [])
        self.assertTrue(warnings)

        files = self.archive_files(new.path)
        files["apps/alpha.conf"] = b"# fenliu-catalog-v1\ninvalid:still-blocked\n"
        self.rewrite_archive(new.path, files)
        with self.assertRaises(validate_release.ValidationError):
            validate_release.validate_release(new.path)

    def test_path_traversal_is_rejected(self) -> None:
        release = self.build("traversal", {"alpha": 5})
        archive_path = release / "catalog.tar.gz"
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            info = tarfile.TarInfo("../escape")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        data = buffer.getvalue()
        archive_path.write_bytes(data)
        manifest_path = release / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["archive"]["size"] = len(data)
        manifest["archive"]["sha256"] = hashlib.sha256(data).hexdigest()
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(validate_release.ValidationError, "unsafe archive path"):
            validate_release.validate_release(release)

    def test_illegal_rule_format_is_rejected(self) -> None:
        release = self.build("illegal", {"alpha": 5})
        files = self.archive_files(release)
        files["apps/alpha.conf"] = b"# fenliu-catalog-v1\nIP-CIDR,10.0.0.0/8\n"
        self.rewrite_archive(release, files)
        with self.assertRaisesRegex(validate_release.ValidationError, "invalid rule"):
            validate_release.validate_release(release)

    def test_manifest_count_error_is_rejected(self) -> None:
        release = self.build("count", {"alpha": 5})
        manifest_path = release / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["apps"][0]["domains"] += 1
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(validate_release.ValidationError, "domain count mismatch"):
            validate_release.validate_release(release)

    def test_legacy_previous_manifest_without_source_name_is_accepted(self) -> None:
        release = self.build("legacy-previous", {"alpha": 5})
        manifest_path = release / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for app in manifest["apps"]:
            app.pop("source_name", None)
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(validate_release.ValidationError, "invalid source_name"):
            validate_release.validate_release(release)
        previous = validate_release.validate_release(release, allow_legacy_metadata=True)
        self.assertEqual(previous.manifest["apps"][0]["name"], "Alpha")

    def test_readme_heading_is_used_as_display_name(self) -> None:
        directory = self.root / "CloudApp"
        directory.mkdir()
        (directory / "README.md").write_text("# 🧰 中国移动云盘\n", encoding="utf-8")
        self.assertEqual(build_catalog.read_display_name(directory), "中国移动云盘")

    def test_curated_relative_source_and_metadata(self) -> None:
        source = self.root / "curated.fenliu"
        source.write_text("domain:yun.139.com\ndomain:caiyunapp.com\n", encoding="utf-8")
        config = self.root / "curated.json"
        config.write_text(json.dumps({
            "schema": 1,
            "apps": [{
                "id": "chinamobile-cloud",
                "name": "中国移动云盘",
                "source_name": "和彩云",
                "category": "cloud",
                "sources": [{"type": "fenliu", "path": source.name}],
            }],
        }, ensure_ascii=False), encoding="utf-8")
        release = self.build_catalog_from_config(config, "curated")
        manifest = json.loads((release / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["apps"][0]["source_name"], "和彩云")
        self.assertEqual(manifest["apps"][0]["domains"], 2)

    def build_catalog_from_config(self, config: Path, name: str) -> Path:
        output = self.root / name
        build_catalog.build(argparse.Namespace(
            config=config,
            output=output,
            version="2026.08.18.3",
            generated_at="2026-08-18T03:17:00Z",
            cache_dir=None,
            secret_key=None,
        ))
        return output


class WorkflowContractTest(unittest.TestCase):
    def test_workflow_security_and_schedule_contract(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        self.assertIn('cron: "17 3 * * *"', workflow)
        self.assertIn("pull_request:", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("FENLIU_CATALOG_SECRET_KEY_B64", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn("--require-signature", workflow)
        self.assertNotIn("actions/cache", workflow)
        uses = [line.strip().split("uses: ", 1)[1] for line in workflow.splitlines() if line.strip().startswith("uses: ")]
        self.assertTrue(uses)
        self.assertTrue(all(item.startswith("actions/") for item in uses))


if __name__ == "__main__":
    unittest.main()
