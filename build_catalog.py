#!/usr/bin/env python3
"""Build the signed Fenliu catalog v1 from heterogeneous upstream rules."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import ipaddress
import io
import json
import re
import subprocess
import tarfile
import urllib.request
from urllib.parse import quote
from dataclasses import dataclass, field
from pathlib import Path


APP_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
MAX_APPS = 1024
MAX_RULES_PER_APP = 4096


@dataclass
class Rules:
    domains: set[str] = field(default_factory=set)
    cidr4: set[str] = field(default_factory=set)
    cidr6: set[str] = field(default_factory=set)
    unsupported: int = 0

    def add_domain(self, value: str) -> None:
        value = value.strip().lower()
        if value.startswith("*."):
            value = value[2:]
        value = value.rstrip(".")
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError(f"invalid IDN domain: {value}") from exc
        # Single-label ICANN suffixes such as the delegated `.youtube` TLD are
        # valid inputs in upstream DOMAIN-SUFFIX rules.
        if not DOMAIN_RE.fullmatch(value) or ".." in value:
            raise ValueError(f"invalid domain: {value}")
        self.domains.add(value)

    def add_cidr(self, value: str) -> None:
        network = ipaddress.ip_network(value.strip(), strict=False)
        target = self.cidr6 if network.version == 6 else self.cidr4
        target.add(str(network))

    @property
    def count(self) -> int:
        return len(self.domains) + len(self.cidr4) + len(self.cidr6)


def parse_clash(text: str, rules: Rules) -> None:
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("-"):
            continue
        parts = [part.strip() for part in line[1:].split(",")]
        if len(parts) < 2:
            continue
        kind, value = parts[0].upper(), parts[1]
        if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
            rules.add_domain(value)
        elif kind in {"IP-CIDR", "IP-CIDR6"}:
            rules.add_cidr(value)
        else:
            rules.unsupported += 1


def parse_v2fly(text: str, rules: Rules) -> None:
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        value = line.split("@", 1)[0].strip()
        if value.startswith(("regexp:", "include:")):
            rules.unsupported += 1
        elif value.startswith(("domain:", "full:")):
            rules.add_domain(value.split(":", 1)[1])
        elif ":" not in value:
            rules.add_domain(value)
        else:
            rules.unsupported += 1


def parse_fenliu(text: str, rules: Rules) -> None:
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        kind, sep, value = line.partition(":")
        if not sep:
            raise ValueError(f"invalid Fenliu rule line: {line}")
        if kind == "domain":
            rules.add_domain(value)
        elif kind in {"cidr4", "cidr6"}:
            rules.add_cidr(value)
        else:
            raise ValueError(f"unsupported Fenliu rule type: {kind}")


PARSERS = {"clash": parse_clash, "v2fly": parse_v2fly, "fenliu": parse_fenliu}


def slug_id(value: str) -> str:
    """Convert an upstream directory name into a stable UCI-safe app ID."""
    result = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not result or not result[0].isalnum():
        raise ValueError(f"cannot derive app id from {value!r}")
    return result[:32]


def discover_clash_apps(root: Path, raw_base: str) -> list[dict]:
    """Discover compatible application rule files from a checked-out Clash tree.

    The upstream tree has both leaf application directories and aggregate
    folders. A leaf `<name>/<name>.yaml` is the canonical source. For a
    directory without that file, use its `_Domain.yaml` / `_IP.yaml` variants.
    Duplicate leaf names are retained only once, preferring the shortest path.
    """
    root = root.resolve()
    candidates: dict[str, list[Path]] = {}
    for path in root.rglob("*.yaml"):
        if path.stem.startswith("README"):
            continue
        if path.stem == path.parent.name:
            candidates.setdefault(slug_id(path.stem), []).append(path)

    for directory in (item for item in root.rglob("*") if item.is_dir()):
        if any(path.parent == directory and path.stem == directory.name for path in directory.glob("*.yaml")):
            continue
        variants = sorted(
            path for path in directory.glob(f"{directory.name}_*.yaml")
            if path.stem.endswith(("_Domain", "_IP"))
        )
        if variants:
            candidates.setdefault(slug_id(directory.name), []).extend(variants)

    apps: list[dict] = []
    for app_id, paths in sorted(candidates.items()):
        source_paths = sorted(set(paths), key=lambda item: (len(item.relative_to(root).parts), item.as_posix()))
        # A canonical leaf wins over variants when it contains compatible
        # rules. Aggregate/process-only leaves fall back to domain/IP variants.
        canonical = [path for path in source_paths if path.stem == path.parent.name]
        selected = canonical[:1] or source_paths
        if canonical:
            probe = Rules()
            parse_clash(canonical[0].read_text(encoding="utf-8"), probe)
            if not probe.count:
                selected = source_paths
        compatible = False
        for path in selected:
            probe = Rules()
            parse_clash(path.read_text(encoding="utf-8"), probe)
            compatible = compatible or bool(probe.count)
        if not compatible:
            continue
        relative = [path.relative_to(root).as_posix() for path in selected]
        category = selected[0].relative_to(root).parts[0] if len(selected[0].relative_to(root).parts) > 2 else "other"
        apps.append({
            "id": app_id,
            "name": selected[0].stem,
            "category": category.lower(),
            "sources": [
                {
                    "type": "clash",
                    "path": str(path),
                    "url": f"{raw_base.rstrip('/')}/{quote(item, safe='/._-')}"
                }
                for path, item in zip(selected, relative)
            ],
        })
    return apps


def read_source(source: dict, cache_dir: Path | None, cache_name: str) -> bytes:
    if "path" in source:
        return Path(source["path"]).read_bytes()
    if cache_dir:
        cached = cache_dir / cache_name
        if cached.is_file():
            return cached.read_bytes()
    request = urllib.request.Request(source["url"], headers={"User-Agent": "fenliu-catalog-builder/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read()
    if cache_dir:
        cache_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / cache_name).write_bytes(data)
    return data


def app_conf(rules: Rules) -> bytes:
    lines = ["# fenliu-catalog-v1"]
    lines.extend(f"domain:{value}" for value in sorted(rules.domains))
    lines.extend(f"cidr4:{value}" for value in sorted(rules.cidr4))
    lines.extend(f"cidr6:{value}" for value in sorted(rules.cidr6))
    return ("\n".join(lines) + "\n").encode("utf-8")


def deterministic_archive(files: dict[str, bytes]) -> bytes:
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for name in sorted(files):
            info = tarfile.TarInfo(name)
            info.size = len(files[name])
            info.mode = 0o644
            info.uid = info.gid = 0
            info.mtime = 0
            archive.addfile(info, io.BytesIO(files[name]))
    gzip_buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=gzip_buffer, mode="wb", mtime=0, filename="") as compressed:
        compressed.write(tar_buffer.getvalue())
    return gzip_buffer.getvalue()


def build(args: argparse.Namespace) -> None:
    config_path = args.config.resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if config.get("schema") not in {1, 2}:
        raise ValueError("catalog source schema must be 1 or 2")
    upstream_root = getattr(args, "upstream_root", None)
    if upstream_root:
        discovery = config.get("discovery", {})
        apps = discover_clash_apps(Path(upstream_root), str(discovery.get("raw_base", "")))
    else:
        apps = config.get("apps", [])
    if not 0 < len(apps) <= MAX_APPS:
        raise ValueError(f"catalog must contain 1..{MAX_APPS} apps")

    app_rules: dict[str, Rules] = {}
    provenance: list[dict] = []
    manifest_apps: list[dict] = []
    seen_ids: set[str] = set()
    cache_dir = args.cache_dir.resolve() if args.cache_dir else None

    for app in apps:
        app_id = app["id"]
        if not APP_ID_RE.fullmatch(app_id) or app_id in seen_ids:
            raise ValueError(f"invalid or duplicate app id: {app_id}")
        seen_ids.add(app_id)
        rules = Rules()
        source_rows = []
        for index, source in enumerate(app.get("sources", [])):
            parser = PARSERS.get(source.get("type"))
            if parser is None:
                raise ValueError(f"unsupported source type for {app_id}: {source.get('type')}")
            data = read_source(source, cache_dir, f"{app_id}-{index}.txt")
            parser(data.decode("utf-8", "strict"), rules)
            source_rows.append({
                "type": source["type"],
                "url": source.get("url", source.get("path", "")),
                "sha256": hashlib.sha256(data).hexdigest(),
            })
        if not rules.count or rules.count > MAX_RULES_PER_APP:
            raise ValueError(f"{app_id}: invalid rule count {rules.count}")
        app_rules[app_id] = rules
        provenance.append({"id": app_id, "sources": source_rows, "unsupported": rules.unsupported})
        manifest_apps.append({
            "id": app_id,
            "name": str(app["name"]),
            "category": str(app.get("category", "other")),
            "domains": len(rules.domains),
            "cidr4": len(rules.cidr4),
            "cidr6": len(rules.cidr6),
        })

    files = {f"apps/{app_id}.conf": app_conf(rules) for app_id, rules in app_rules.items()}
    files["sources.json"] = (json.dumps(provenance, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    archive = deterministic_archive(files)
    manifest = {
        "schema": 1,
        "version": args.version,
        "generated_at": args.generated_at,
        "min_plugin_version": "0.1.0-r10",
        "archive": {
            "file": "catalog.tar.gz",
            "size": len(archive),
            "sha256": hashlib.sha256(archive).hexdigest(),
        },
        "apps": sorted(manifest_apps, key=lambda item: item["id"]),
    }

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = output / "manifest.json"
    (output / "catalog.tar.gz").write_bytes(archive)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    signature_path = output / "manifest.json.sig"
    if signature_path.exists():
        signature_path.unlink()
    if args.secret_key:
        subprocess.run([
            "usign", "-S", "-m", str(manifest_path), "-s", str(args.secret_key.resolve()),
            "-x", str(signature_path),
        ], check=True)
    print(json.dumps({"output": str(output), "version": args.version, "apps": len(apps), "archive_size": len(archive)}))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("catalog-sources.json"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--generated-at", default="2026-08-18T00:00:00Z")
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument("--secret-key", type=Path)
    parser.add_argument("--upstream-root", type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"\d{4}\.\d{2}\.\d{2}\.\d+", args.version):
        parser.error("--version must match YYYY.MM.DD.N")
    return args


if __name__ == "__main__":
    build(parse_args())
