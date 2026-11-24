#!/usr/bin/env python3
"""P2.4 local end-to-end pipeline: Git objects -> v2 validator -> ZIP -> verifier.

Trusted caller supplies exact base/head/author/branch. The PR is never checked
out or executed. This pipeline does not publish, approve, index, or create a
GitHub Release.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from validator import schema_v2, validate_package, validate_v2
from validator.validate import Git, Invalid, require

# Tools directory is already on sys.path only when imported as a package; add
# the repository tools root for the builder import in both script/test modes.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from build_submission_zip import build as build_zip


def _materialize_source(git: Git, head: str, uid: str, dest: Path):
    prefix = f"submissions/{uid}/"
    tree = git.entries(head, prefix)
    metadata_path = prefix + "submission.json"
    require(metadata_path in tree, "missing submission.json")
    metadata_bytes = git.blob(tree[metadata_path][2], schema_v2.MAX_META)
    metadata = schema_v2.strict_json(metadata_bytes)
    schema_v2.validate_metadata(metadata, expected_uid=uid)
    files_root = dest / "files"
    files_root.mkdir(parents=True)
    (dest / "submission.json").write_bytes(metadata_bytes)
    for name, (mode, typ, oid) in tree.items():
        if not name.startswith(prefix + "files/"):
            continue
        require(mode == "100644" and typ == "blob", "unsafe Git object")
        rel = name[len(prefix + "files/"):]
        target = files_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(git.blob(oid, schema_v2.MAX_FILE))
    return metadata


def run_pipeline(repo: str, base: str, head: str, author: str, branch: str,
                 output_zip: Path | None = None):
    git = Git(repo)
    result = validate_v2.validate_v2(git, base, head, author, branch)
    uid = result["uid"]
    temp = None
    if output_zip is None:
        temp = tempfile.TemporaryDirectory(prefix="wtcnup-p24-")
        output_zip = Path(temp.name) / "submission.zip"
    output_zip = Path(output_zip)
    try:
        with tempfile.TemporaryDirectory(prefix="wtcnup-p24-src-") as source:
            source_path = Path(source)
            _materialize_source(git, head, uid, source_path)
            build_zip(source_path, output_zip)
        package = validate_package.verify_package(output_zip)
        return {
            "schema_version": 2,
            "submission_uid": uid,
            "base": base,
            "head": head,
            "zip": str(output_zip),
            "zip_sha256": package["zip_sha256"],
            "zip_size": package["zip_size"],
            "file_count": package["file_count"],
            "total_size": package["total_size"],
        }
    finally:
        if temp is not None:
            temp.cleanup()


def main():
    parser = argparse.ArgumentParser(description="WTCNUP P2.4 local submission pipeline")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--author", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--zip", type=Path, dest="output_zip")
    args = parser.parse_args()
    try:
        result = run_pipeline(args.repo, args.base, args.head, args.author,
                              args.branch, args.output_zip)
        print("PASS " + json.dumps(result, ensure_ascii=True))
        return 0
    except (Invalid, schema_v2.Invalid, OSError, ValueError) as exc:
        print("FAIL " + str(exc).replace("\n", " ").replace("\r", " "), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
