#!/usr/bin/env python3
"""Build manifest.json and a single submission.zip for a v2 template.

- Does not execute submission files.
- manifest.json contains only file paths/sizes/SHA-256 and submission UID.
- The ZIP's own SHA-256 is intentionally NOT written into manifest.json
  (avoid a circular dependency); publish-time tooling computes it later.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import zipfile
from pathlib import Path

from validator.schema_v2 import Invalid, load_metadata, manifest_for


def build(source_dir: Path, output_zip: Path) -> dict:
    source_dir = source_dir.resolve()
    output_zip = output_zip.resolve()
    metadata = load_metadata(source_dir / "submission.json")
    manifest = manifest_for(metadata, source_dir)

    # Validate the exact intended members before writing.
    members = ["submission.json", "manifest.json"] + [
        "files/" + item["path"] for item in manifest["files"]
    ]
    if len(members) != len(set(members)):
        raise Invalid("duplicate ZIP member")
    if any(name.startswith("/") or ".." in name.split("/") for name in members):
        raise Invalid("unsafe ZIP member")
    if not output_zip.name.endswith(".zip"):
        raise Invalid("output must end with .zip")

    output_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=6) as archive:
        archive.write(source_dir / "submission.json", "submission.json")
        archive.writestr(
            "manifest.json",
            json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
        )
        for item in manifest["files"]:
            archive.write(source_dir / "files" / item["path"], "files/" + item["path"])

    # Verify the archive contract after writing.
    with zipfile.ZipFile(output_zip, "r") as archive:
        names = archive.namelist()
        if sorted(names) != sorted(members):
            raise Invalid("ZIP member set mismatch")
        if archive.read("manifest.json") != json.dumps(
                manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8"):
            raise Invalid("manifest.json ZIP content mismatch")
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Build v2 submission.zip")
    parser.add_argument("source_dir", type=Path)
    parser.add_argument("output_zip", type=Path)
    args = parser.parse_args()
    try:
        manifest = build(args.source_dir, args.output_zip)
        print(f"PASS zip={args.output_zip} files={manifest['file_count']} bytes={manifest['total_size']}")
        return 0
    except (Invalid, OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
