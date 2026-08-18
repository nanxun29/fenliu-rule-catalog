#!/usr/bin/env python3
"""Validate a Fenliu catalog release and guard suspicious upstream changes."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import subprocess
import tarfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any


APP_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
VERSION_RE = re.compile(r"^\d{4}\.\d{2}\.\d{2}\.\d+$")
DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
MAX_APPS = 512
MAX_RULES_PER_APP = 4096
MAX_ARCHIVE_SIZE = 16 * 1024 * 1024
MAX_MANIFEST_SIZE = 1024 * 1024
MAX_MEMBER_SIZE = 4 * 1024 * 1024
MAX_TOTAL_UNPACKED_SIZE = 32 * 1024 * 1024


class ValidationError(ValueError):
    pass


@dataclass
class AppRules:
    domains: set[str] = field(default_factory=set)
    cidr4: set[str] = field(default_factory=set)
    cidr6: set[str] = field(default_factory=set)

    @property
    def count(self) -> int:
        return len(self.domains) + len(self.cidr4) + len(self.cidr6)


@dataclass
class Release:
    path: Path
    manifest: dict[str, Any]
    apps: dict[str, AppRules]
    archive_sha256: str


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"cannot read valid JSON {path.name}: {exc}") from exc


def validate_domain(value: str) -> str:
    require(value == value.strip().lower(), f"domain is not normalized: {value!r}")
    require(not value.startswith("*.") and not value.endswith("."), f"domain is not canonical: {value}")
    try:
        encoded = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValidationError(f"invalid IDN domain: {value}") from exc
    require(encoded == value, f"domain must use ASCII IDNA form: {value}")
    require(bool(DOMAIN_RE.fullmatch(value)) and ".." not in value, f"invalid domain: {value}")
    for label in value.split("."):
        require(0 < len(label) <= 63, f"invalid domain label length: {value}")
        require(label[0].isalnum() and label[-1].isalnum(), f"invalid domain label: {value}")
        require(all(char.isalnum() or char == "-" for char in label), f"invalid domain label: {value}")
    return value


def parse_rules(name: str, data: bytes) -> AppRules:
    require(len(data) <= MAX_MEMBER_SIZE, f"{name}: member is too large")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"{name}: rules are not UTF-8") from exc
    require(text.endswith("\n"), f"{name}: file must end with newline")
    lines = text.splitlines()
    require(lines and lines[0] == "# fenliu-catalog-v1", f"{name}: invalid header")
    rules = AppRules()
    normalized_lines: list[str] = []
    for line in lines[1:]:
        require(bool(line) and line == line.strip(), f"{name}: blank or untrimmed rule")
        kind, sep, value = line.partition(":")
        require(bool(sep and value), f"{name}: invalid rule: {line!r}")
        if kind == "domain":
            value = validate_domain(value)
            require(value not in rules.domains, f"{name}: duplicate domain: {value}")
            rules.domains.add(value)
        elif kind in {"cidr4", "cidr6"}:
            try:
                network = ipaddress.ip_network(value, strict=True)
            except ValueError as exc:
                raise ValidationError(f"{name}: invalid canonical CIDR: {value}") from exc
            expected = 4 if kind == "cidr4" else 6
            require(network.version == expected, f"{name}: {kind} has wrong address family")
            canonical = str(network)
            target = rules.cidr4 if expected == 4 else rules.cidr6
            require(canonical not in target, f"{name}: duplicate CIDR: {canonical}")
            target.add(canonical)
            value = canonical
        else:
            raise ValidationError(f"{name}: unsupported rule type: {kind}")
        normalized_lines.append(f"{kind}:{value}")
    require(0 < rules.count <= MAX_RULES_PER_APP, f"{name}: rule count must be 1..{MAX_RULES_PER_APP}")
    expected_lines = (
        [f"domain:{item}" for item in sorted(rules.domains)]
        + [f"cidr4:{item}" for item in sorted(rules.cidr4)]
        + [f"cidr6:{item}" for item in sorted(rules.cidr6)]
    )
    require(normalized_lines == expected_lines, f"{name}: rules are not sorted canonically")
    return rules


def validate_manifest(data: Any) -> list[dict[str, Any]]:
    require(isinstance(data, dict), "manifest root must be an object")
    require(data.get("schema") == 1, "manifest schema must be 1")
    require(isinstance(data.get("version"), str) and bool(VERSION_RE.fullmatch(data["version"])), "invalid manifest version")
    generated = data.get("generated_at")
    require(isinstance(generated, str) and generated.endswith("Z"), "generated_at must be an ISO-8601 UTC timestamp")
    try:
        datetime.fromisoformat(generated[:-1] + "+00:00")
    except ValueError as exc:
        raise ValidationError("generated_at must be an ISO-8601 UTC timestamp") from exc
    require(isinstance(data.get("min_plugin_version"), str) and bool(data["min_plugin_version"]), "invalid min_plugin_version")
    archive = data.get("archive")
    require(isinstance(archive, dict), "manifest archive must be an object")
    require(archive.get("file") == "catalog.tar.gz", "manifest archive file must be catalog.tar.gz")
    require(type(archive.get("size")) is int and 0 < archive["size"] <= MAX_ARCHIVE_SIZE, "invalid archive size")
    require(isinstance(archive.get("sha256"), str) and bool(re.fullmatch(r"[0-9a-f]{64}", archive["sha256"])), "invalid archive sha256")
    apps = data.get("apps")
    require(isinstance(apps, list) and 0 < len(apps) <= MAX_APPS, f"manifest must contain 1..{MAX_APPS} apps")
    ids: list[str] = []
    for app in apps:
        require(isinstance(app, dict), "manifest app must be an object")
        app_id = app.get("id")
        require(isinstance(app_id, str) and bool(APP_ID_RE.fullmatch(app_id)), f"invalid app id: {app_id!r}")
        require(app_id not in ids, f"duplicate app id: {app_id}")
        ids.append(app_id)
        require(isinstance(app.get("name"), str) and bool(app["name"].strip()), f"{app_id}: invalid name")
        require(isinstance(app.get("category"), str) and bool(app["category"].strip()), f"{app_id}: invalid category")
        for key in ("domains", "cidr4", "cidr6"):
            require(type(app.get(key)) is int and app[key] >= 0, f"{app_id}: invalid {key} count")
        require(sum(app[key] for key in ("domains", "cidr4", "cidr6")) > 0, f"{app_id}: empty app")
    require(ids == sorted(ids), "manifest apps must be sorted by id")
    return apps


def validate_release(path: Path, public_key: Path | None = None, require_signature: bool = False) -> Release:
    path = path.resolve()
    require(path.is_dir(), f"release directory does not exist: {path}")
    manifest_path = path / "manifest.json"
    archive_path = path / "catalog.tar.gz"
    signature_path = path / "manifest.json.sig"
    require(manifest_path.is_file(), "manifest.json is missing")
    require(archive_path.is_file(), "catalog.tar.gz is missing")
    require(manifest_path.stat().st_size <= MAX_MANIFEST_SIZE, "manifest.json is too large")
    manifest = load_json(manifest_path)
    manifest_apps = validate_manifest(manifest)

    archive_data = archive_path.read_bytes()
    require(len(archive_data) == manifest["archive"]["size"], "archive size does not match manifest")
    archive_sha256 = hashlib.sha256(archive_data).hexdigest()
    require(archive_sha256 == manifest["archive"]["sha256"], "archive sha256 does not match manifest")

    if require_signature:
        require(public_key is not None and public_key.is_file(), "public key is required for signature verification")
        require(signature_path.is_file() and 0 < signature_path.stat().st_size <= 1024, "manifest signature is missing or too large")
        result = subprocess.run(
            ["usign", "-V", "-m", str(manifest_path), "-p", str(public_key.resolve()), "-x", str(signature_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        require(result.returncode == 0, f"manifest signature verification failed: {result.stderr.strip()}")

    expected_ids = {app["id"] for app in manifest_apps}
    app_data: dict[str, bytes] = {}
    sources_data: bytes | None = None
    seen_names: set[str] = set()
    total_unpacked_size = 0
    member_count = 0
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            for member in archive:
                member_count += 1
                require(member_count <= MAX_APPS + 1, "archive contains too many members")
                name = member.name
                pure = PurePosixPath(name)
                require(name not in seen_names, f"duplicate archive member: {name}")
                seen_names.add(name)
                require(not pure.is_absolute() and ".." not in pure.parts and "\\" not in name, f"unsafe archive path: {name}")
                require(name == pure.as_posix() and "." not in pure.parts, f"non-canonical archive path: {name}")
                require(member.isfile(), f"archive member must be a regular file: {name}")
                require(member.size <= MAX_MEMBER_SIZE, f"archive member is too large: {name}")
                total_unpacked_size += member.size
                require(total_unpacked_size <= MAX_TOTAL_UNPACKED_SIZE, "archive expands beyond the total size limit")
                extracted = archive.extractfile(member)
                require(extracted is not None, f"cannot read archive member: {name}")
                data = extracted.read()
                require(len(data) == member.size, f"truncated archive member: {name}")
                if name == "sources.json":
                    sources_data = data
                elif len(pure.parts) == 2 and pure.parts[0] == "apps" and pure.suffix == ".conf":
                    app_id = pure.stem
                    require(bool(APP_ID_RE.fullmatch(app_id)), f"invalid app archive path: {name}")
                    app_data[app_id] = data
                else:
                    raise ValidationError(f"unexpected archive member: {name}")
    except (tarfile.TarError, OSError) as exc:
        raise ValidationError(f"invalid catalog archive: {exc}") from exc

    require(set(app_data) == expected_ids, "archive app set does not match manifest")
    require(sources_data is not None, "sources.json is missing from archive")
    try:
        sources = json.loads(sources_data.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationError("sources.json is not valid UTF-8 JSON") from exc
    require(isinstance(sources, list), "sources.json root must be an array")
    source_ids = [row.get("id") for row in sources if isinstance(row, dict)]
    require(len(source_ids) == len(sources) and set(source_ids) == expected_ids and len(set(source_ids)) == len(source_ids), "sources.json app set does not match manifest")
    for row in sources:
        app_id = row["id"]
        require(type(row.get("unsupported")) is int and row["unsupported"] >= 0, f"sources.json {app_id}: invalid unsupported count")
        source_rows = row.get("sources")
        require(isinstance(source_rows, list) and bool(source_rows), f"sources.json {app_id}: sources must be a non-empty array")
        for source in source_rows:
            require(isinstance(source, dict), f"sources.json {app_id}: source must be an object")
            require(source.get("type") in {"clash", "v2fly", "fenliu"}, f"sources.json {app_id}: invalid source type")
            require(isinstance(source.get("url"), str) and bool(source["url"]), f"sources.json {app_id}: invalid source URL")
            require(isinstance(source.get("sha256"), str) and bool(re.fullmatch(r"[0-9a-f]{64}", source["sha256"])), f"sources.json {app_id}: invalid source sha256")

    parsed = {app_id: parse_rules(f"apps/{app_id}.conf", data) for app_id, data in app_data.items()}
    manifest_by_id = {app["id"]: app for app in manifest_apps}
    domain_owner: dict[str, str] = {}
    networks: list[tuple[str, ipaddress._BaseNetwork]] = []
    for app_id in sorted(parsed):
        rules = parsed[app_id]
        row = manifest_by_id[app_id]
        require(len(rules.domains) == row["domains"], f"{app_id}: domain count mismatch")
        require(len(rules.cidr4) == row["cidr4"], f"{app_id}: cidr4 count mismatch")
        require(len(rules.cidr6) == row["cidr6"], f"{app_id}: cidr6 count mismatch")
        for domain in rules.domains:
            owner = domain_owner.setdefault(domain, app_id)
            require(owner == app_id, f"cross-app domain conflict: {domain} ({owner}, {app_id})")
        for cidr in sorted(rules.cidr4 | rules.cidr6):
            network = ipaddress.ip_network(cidr)
            for other_id, other in networks:
                require(other_id == app_id or network.version != other.version or not network.overlaps(other), f"cross-app CIDR conflict: {network} ({app_id}) overlaps {other} ({other_id})")
            networks.append((app_id, network))
    return Release(path=path, manifest=manifest, apps=parsed, archive_sha256=archive_sha256)


def percent_change(old: int, new: int) -> float:
    if old == 0:
        return 0.0 if new == 0 else float("inf")
    return (new - old) * 100.0 / old


def compare_releases(candidate: Release, previous: Release | None, allow_large_change: bool) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    if previous is None:
        rows = [{"id": app_id, "old": 0, "new": rules.count, "delta": rules.count, "percent": None} for app_id, rules in sorted(candidate.apps.items())]
        return rows, [], []
    old_ids, new_ids = set(previous.apps), set(candidate.apps)
    violations: list[str] = []
    warnings: list[str] = []
    if old_ids != new_ids:
        violations.append(f"application set changed (added={sorted(new_ids - old_ids)}, removed={sorted(old_ids - new_ids)})")
    rows: list[dict[str, Any]] = []
    for app_id in sorted(old_ids | new_ids):
        old = previous.apps[app_id].count if app_id in previous.apps else 0
        new = candidate.apps[app_id].count if app_id in candidate.apps else 0
        delta = new - old
        pct = percent_change(old, new)
        rows.append({"id": app_id, "old": old, "new": new, "delta": delta, "percent": None if pct == float("inf") else round(pct, 2)})
        if abs(delta) >= 20 and ((delta < 0 and pct < -30.0) or (delta > 0 and pct > 100.0)):
            violations.append(f"{app_id}: suspicious rule count change {old} -> {new} ({pct:+.2f}%)")
    old_total = sum(item.count for item in previous.apps.values())
    new_total = sum(item.count for item in candidate.apps.values())
    total_pct = percent_change(old_total, new_total)
    if (new_total < old_total and total_pct < -20.0) or (new_total > old_total and total_pct > 75.0):
        violations.append(f"catalog: suspicious total rule count change {old_total} -> {new_total} ({total_pct:+.2f}%)")
    if allow_large_change and violations:
        warnings.extend(f"manually allowed: {item}" for item in violations)
        violations = []
    return rows, violations, warnings


def write_reports(report: dict[str, Any], json_path: Path, markdown_path: Path) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    status = "PASS" if report["valid"] else "FAIL"
    lines = [f"# Fenliu catalog validation: {status}", "", f"- Candidate version: `{report.get('candidate_version', 'unknown')}`", f"- Archive changed: `{str(report.get('archive_changed', True)).lower()}`", f"- Manual large-change override: `{str(report['allow_large_change']).lower()}`", ""]
    if report["errors"]:
        lines.extend(["## Errors", ""] + [f"- {item}" for item in report["errors"]] + [""])
    if report["warnings"]:
        lines.extend(["## Warnings", ""] + [f"- {item}" for item in report["warnings"]] + [""])
    if report["changes"]:
        lines.extend(["## Rule count changes", "", "| App | Previous | Candidate | Delta | Change |", "|---|---:|---:|---:|---:|"])
        for row in report["changes"]:
            pct = "new" if row["percent"] is None else f"{row['percent']:+.2f}%"
            lines.append(f"| `{row['id']}` | {row['old']} | {row['new']} | {row['delta']:+d} | {pct} |")
        lines.append("")
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--require-signature", action="store_true")
    parser.add_argument("--allow-large-change", action="store_true")
    parser.add_argument("--report-json", type=Path, default=Path("candidate-report.json"))
    parser.add_argument("--report-markdown", type=Path, default=Path("candidate-report.md"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report: dict[str, Any] = {
        "valid": False,
        "candidate_version": None,
        "previous_version": None,
        "archive_changed": True,
        "allow_large_change": args.allow_large_change,
        "changes": [],
        "errors": [],
        "warnings": [],
    }
    try:
        candidate = validate_release(args.candidate, args.public_key, args.require_signature)
        report["candidate_version"] = candidate.manifest["version"]
        previous = None
        if args.previous:
            previous = validate_release(args.previous)
            report["previous_version"] = previous.manifest["version"]
            report["archive_changed"] = candidate.archive_sha256 != previous.archive_sha256
        changes, violations, warnings = compare_releases(candidate, previous, args.allow_large_change)
        report["changes"] = changes
        report["errors"].extend(violations)
        report["warnings"].extend(warnings)
        report["valid"] = not report["errors"]
    except (ValidationError, OSError, subprocess.SubprocessError) as exc:
        report["errors"].append(str(exc))
    write_reports(report, args.report_json, args.report_markdown)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
