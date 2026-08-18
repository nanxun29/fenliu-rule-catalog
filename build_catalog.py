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
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote
from dataclasses import dataclass, field
from pathlib import Path


APP_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
MAX_APPS = 1024
MAX_RULES_PER_APP = 4096
MAX_ICON_SIZE = 64 * 1024
ICON_WORKERS = 12


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


def read_display_name(directory: Path) -> str:
    readme = directory / "README.md"
    if readme.is_file():
        for line in readme.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("# "):
                title = re.sub(r"^[^\w]+", "", line[2:].strip(), flags=re.UNICODE).strip()
                if title:
                    return title[:64]
    return directory.name[:64]


def representative_domain(rules: Rules) -> str | None:
    if not rules.domains:
        return None
    return min(rules.domains, key=lambda value: (value.count("."), len(value), value))


def valid_png(data: bytes) -> bool:
    return 32 <= len(data) <= MAX_ICON_SIZE and data.startswith(b"\x89PNG\r\n\x1a\n")


def fetch_icon(domain: str) -> bytes | None:
    url = "https://www.google.com/s2/favicons?domain=" + quote(domain, safe=".-") + "&sz=64"
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "fenliu-catalog-builder/1"})
        with urllib.request.urlopen(request, timeout=8) as response:
            data = response.read(MAX_ICON_SIZE + 1)
        return data if valid_png(data) else None
    except (OSError, ValueError):
        return None


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
        source_name = selected[0].parent.name
        apps.append({
            "id": app_id,
            "name": read_display_name(selected[0].parent),
            "source_name": source_name,
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
        # Keep the complete upstream application set, then merge explicitly
        # curated sources into matching applications. This lets the repository
        # carry a small, reviewed supplement for an upstream app without
        # creating a duplicate app ID or a separate user-facing entry.
        discovered = {app["id"]: app for app in apps}
        for curated in config.get("apps", []):
            existing = discovered.get(curated.get("id"))
            if existing is None:
                apps.append(curated)
                discovered[curated["id"]] = curated
                continue
            existing.setdefault("sources", []).extend(curated.get("sources", []))
            if curated.get("name") and not existing.get("name"):
                existing["name"] = curated["name"]
            if curated.get("category") and existing.get("category") in {None, "other"}:
                existing["category"] = curated["category"]
    else:
        apps = config.get("apps", [])
    if not 0 < len(apps) <= MAX_APPS:
        raise ValueError(f"catalog must contain 1..{MAX_APPS} apps")

    app_rules: dict[str, Rules] = {}
    provenance: list[dict] = []
    manifest_apps: list[dict] = []
    seen_ids: set[str] = set()
    cache_dir = args.cache_dir.resolve() if args.cache_dir else None
    previous = getattr(args, "previous", None)
    previous_icons = previous.resolve() / "icons" if previous else None
    icon_overrides = {}
    icon_override_path = getattr(args, "icon_overrides", None)
    if icon_override_path and icon_override_path.is_file():
        override_data = json.loads(icon_override_path.read_text(encoding="utf-8"))
        icon_overrides = override_data.get("domains", {})

    for app in apps:
        app_id = app["id"]
        if not APP_ID_RE.fullmatch(app_id) or app_id in seen_ids:
            raise ValueError(f"invalid or duplicate app id: {app_id}")
        seen_ids.add(app_id)
        rules = Rules()
        source_rows = []
        for index, source in enumerate(app.get("sources", [])):
            source = dict(source)
            source_path = source.get("path")
            if source_path and not Path(source_path).is_absolute():
                source["path"] = str(config_path.parent / source_path)
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
            "source_name": str(app.get("source_name", app["name"])),
            "category": str(app.get("category", "other")),
            "domains": len(rules.domains),
            "cidr4": len(rules.cidr4),
            "cidr6": len(rules.cidr6),
        })

    icon_data: dict[str, bytes] = {}
    icon_domains: dict[str, str] = {}
    pending: dict[object, str] = {}
    enable_icons = bool(getattr(args, "upstream_root", None) or getattr(args, "icon_overrides", None))
    with ThreadPoolExecutor(max_workers=ICON_WORKERS) as executor:
      if enable_icons:
        for app_id, rules in app_rules.items():
            previous_icon = previous_icons / f"{app_id}.png" if previous_icons else None
            if not getattr(args, "refresh_icons", False) and previous_icon and previous_icon.is_file():
                data = previous_icon.read_bytes()
                if valid_png(data):
                    icon_data[app_id] = data
                    continue
            domain = str(icon_overrides.get(app_id) or representative_domain(rules) or "").strip().lower()
            if domain:
                icon_domains[app_id] = domain
                pending[executor.submit(fetch_icon, domain)] = app_id
        for future in as_completed(pending):
            app_id = pending[future]
            data = future.result()
            if data is not None:
                icon_data[app_id] = data

    manifest_by_id = {item["id"]: item for item in manifest_apps}
    for app_id, data in icon_data.items():
        manifest_by_id[app_id]["icon"] = f"icons/{app_id}.png"
        manifest_by_id[app_id]["icon_sha256"] = hashlib.sha256(data).hexdigest()

    files = {f"apps/{app_id}.conf": app_conf(rules) for app_id, rules in app_rules.items()}
    files["sources.json"] = (json.dumps(provenance, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    archive = deterministic_archive(files)
    manifest = {
        "schema": 1,
        "version": args.version,
        "generated_at": args.generated_at,
        "min_plugin_version": "0.1.0-r13",
        "archive": {
            "file": "catalog.tar.gz",
            "size": len(archive),
            "sha256": hashlib.sha256(archive).hexdigest(),
        },
        "apps": sorted(manifest_apps, key=lambda item: item["id"]),
    }

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    icon_output = output / "icons"
    if icon_output.exists():
        for path in icon_output.glob("*.png"):
            path.unlink()
    icon_output.mkdir(exist_ok=True)
    for app_id, data in icon_data.items():
        (icon_output / f"{app_id}.png").write_bytes(data)
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
    print(json.dumps({"output": str(output), "version": args.version, "apps": len(apps), "icons": len(icon_data), "archive_size": len(archive)}))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("catalog-sources.json"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--generated-at", default="2026-08-18T00:00:00Z")
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument("--secret-key", type=Path)
    parser.add_argument("--upstream-root", type=Path)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--icon-overrides", type=Path, default=Path(__file__).with_name("icon-overrides.json"))
    parser.add_argument("--refresh-icons", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"\d{4}\.\d{2}\.\d{2}\.\d+", args.version):
        parser.error("--version must match YYYY.MM.DD.N")
    return args


if __name__ == "__main__":
    build(parse_args())
