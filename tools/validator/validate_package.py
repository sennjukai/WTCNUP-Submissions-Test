#!/usr/bin/env python3
"""P2.3 single-ZIP/manifest verifier for a v2 submission package.

This verifies a local `submission.zip`; it does not publish, approve, or trust
the package. It does not write files or execute submission content.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from validator import schema_v2


class Invalid(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Invalid(message)


def _strict_json(raw: bytes):
    try:
        return schema_v2.strict_json(raw)
    except schema_v2.Invalid as exc:
        raise Invalid(str(exc)) from exc


def _canonical_manifest(metadata):
    files = sorted(metadata["files"], key=lambda item: item["path"])
    return {
        "schema_version": 2,
        "submission_uid": metadata["submission_uid"],
        "file_count": len(files),
        "total_size": sum(item["size"] for item in files),
        "files": files,
    }


def verify_package(path: Path, expected_sha256: str | None = None):
    path = Path(path)
    require(path.is_file(), "package is missing")
    size = path.stat().st_size
    require(size <= 64 * 1024 * 1024, "ZIP exceeds 64 MiB")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if expected_sha256 is not None:
        require(schema_v2.HASH_RE.fullmatch(expected_sha256) is not None,
                "invalid expected ZIP SHA-256")
        require(digest == expected_sha256.lower(), "ZIP SHA-256 mismatch")

    try:
        archive = zipfile.ZipFile(path, "r")
    except zipfile.BadZipFile as exc:
        raise Invalid("invalid ZIP") from exc
    with archive:
        infos = archive.infolist()
        require(len(infos) <= schema_v2.MAX_FILES + 2, "too many ZIP entries")
        names = [info.filename for info in infos]
        require(len(names) == len(set(names)), "duplicate ZIP member")
        require("submission.json" in names, "missing submission.json")
        require("manifest.json" in names, "missing manifest.json")
        require("manifest.json" not in names[names.index("manifest.json") + 1:],
                "manifest.json must be unique")
        members = {}
        for info in infos:
            name = info.filename
            require(not info.is_dir(), "directory entries are not allowed")
            require(name == name.replace("\\", "/"), "ZIP names must use /")
            mode = (info.external_attr >> 16) & 0o170000
            require(mode != stat.S_IFLNK, "symlink ZIP member is not allowed")
            require(mode in (0, 0o100000), "only regular ZIP files are allowed")
            require(info.file_size <= schema_v2.MAX_FILE, "ZIP member too large")
            members[name] = info
        require(set(members) == {"submission.json", "manifest.json"} |
                {n for n in members if n.startswith("files/")},
                "unexpected ZIP member")

        submission_raw = archive.read("submission.json")
        metadata = _strict_json(submission_raw)
        try:
            uid, declared = schema_v2.validate_metadata(metadata)
        except schema_v2.Invalid as exc:
            raise Invalid(str(exc)) from exc

        manifest = _strict_json(archive.read("manifest.json"))
        expected = _canonical_manifest(metadata)
        require(manifest == expected, "manifest does not match submission.json")
        require(manifest.get("submission_uid") == uid, "manifest UID mismatch")

        actual = {}
        for name, info in members.items():
            if not name.startswith("files/"):
                continue
            rel = name[len("files/"):]
            try:
                schema_v2.safe_path(rel)
            except schema_v2.Invalid as exc:
                raise Invalid(str(exc)) from exc
            actual[rel] = info
        require(set(actual) == set(declared), "ZIP payload and declared files differ")
        require(sum(info.file_size for info in actual.values()) <= schema_v2.MAX_TOTAL,
                "ZIP payload exceeds 50 MiB before extraction")
        total = 0
        for rel, info in actual.items():
            data = archive.read(info)
            require(len(data) == declared[rel]["size"], "payload size mismatch")
            require(hashlib.sha256(data).hexdigest() == declared[rel]["sha256"],
                    "payload SHA-256 mismatch")
            require(not any(data.startswith(sig) for sig in (b"PK\x03\x04", b"MZ")),
                    "archive/executable payload signature")
            try:
                schema_v2.validate_payload(rel, data)
            except schema_v2.Invalid as exc:
                raise Invalid(str(exc)) from exc
            total += len(data)
        require(total == metadata["total_size"], "total_size mismatch")
        require(len(actual) == metadata["file_count"], "file_count mismatch")
    return {
        "path": str(path),
        "zip_sha256": digest,
        "zip_size": size,
        "submission_uid": metadata["submission_uid"],
        "file_count": metadata["file_count"],
        "total_size": metadata["total_size"],
        "schema_version": 2,
    }


def main():
    parser = argparse.ArgumentParser(description="WTCNUP v2 submission.zip verifier")
    parser.add_argument("package", type=Path)
    parser.add_argument("--sha256", help="optional expected ZIP SHA-256")
    args = parser.parse_args()
    try:
        result = verify_package(args.package, args.sha256)
        print("PASS " + json.dumps(result, ensure_ascii=True))
        return 0
    except (Invalid, OSError, ValueError) as exc:
        print("FAIL " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
