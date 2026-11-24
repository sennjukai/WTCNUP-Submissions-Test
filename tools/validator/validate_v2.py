#!/usr/bin/env python3
"""P2.2 v2 Git-object validator.

Security boundary:
- Trusted caller must supply exact base/head SHAs and PR author/branch.
- Reads only Git objects; never checks out or executes PR files.
- Does not package, approve, publish, or consume PR artifacts.

This validator is intentionally separate from the historical v1 validate.py.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path, PurePosixPath

# Allow both `python -m unittest` (imported as validator.validate_v2)
# and `python tools/validator/validate_v2.py` (script mode).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from validator import schema_v2
from validator.validate import (
    Git,
    Invalid,
    LOGIN_RE,
    MAGIC,
    MAX_FILE,
    MAX_FILES,
    MAX_META,
    OID_RE,
    require,
)


def validate_v2(git: Git, base: str, head: str, author: str, branch: str):
    require(OID_RE.fullmatch(base or "") is not None and
            OID_RE.fullmatch(head or "") is not None and base != head,
            "invalid commit SHA")
    require(isinstance(author, str) and LOGIN_RE.fullmatch(author) is not None,
            "invalid PR author")
    require(branch.startswith("wtcnup/submission-"), "invalid branch")
    uid = branch[len("wtcnup/submission-"):]
    require(schema_v2.UID_RE.fullmatch(uid) is not None, "invalid branch UID")

    prefix = f"submissions/{uid}/"
    metadata_path = prefix + "submission.json"
    files_prefix = prefix + "files/"
    changed = git.changed(base, head)
    require(1 < len(changed) <= MAX_FILES + 1, "invalid changed-file count")
    for status, name in changed:
        require(status == "A" and (name == metadata_path or name.startswith(files_prefix)),
                "PR may only add this v2 submission")
    tree = git.entries(head, prefix)
    require(set(tree) == {name for _, name in changed}, "tree and change set differ")
    require(metadata_path in tree, "missing submission.json")
    for name, (mode, typ, oid) in tree.items():
        require(mode == "100644" and typ == "blob" and OID_RE.fullmatch(oid) is not None,
                "only regular non-executable files are allowed")

    raw = git.blob(tree[metadata_path][2], MAX_META)
    try:
        metadata = schema_v2.strict_json(raw)
        schema_v2.validate_metadata(metadata, expected_uid=uid, expected_author=author)
    except schema_v2.Invalid as exc:
        raise Invalid(str(exc)) from exc
    declared = {item["path"]: item for item in metadata["files"]}

    actual = {name[len(files_prefix):]: value for name, value in tree.items()
              if name.startswith(files_prefix)}
    require(set(actual) == set(declared), "declared and actual file sets differ")
    total = 0
    for path, item in declared.items():
        contents = git.blob(actual[path][2], MAX_FILE)
        require(len(contents) == item["size"], "file size mismatch")
        require(hashlib.sha256(contents).hexdigest() == item["sha256"],
                "file SHA-256 mismatch")
        require(not any(contents.startswith(sig) for sig in MAGIC),
                "archive or executable signature")
        try:
            schema_v2.validate_payload(path, contents)
        except schema_v2.Invalid as exc:
            raise Invalid(str(exc)) from exc
        total += len(contents)
        require(total <= schema_v2.MAX_TOTAL, "submission too large")
    require(total == metadata["total_size"], "total size mismatch")
    return {
        "schema_version": 2,
        "uid": uid,
        "head": head,
        "base": base,
        "file_count": len(actual),
        "total_size": total,
    }


def main():
    parser = argparse.ArgumentParser(description="WTCNUP v2 Git-object validator")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--author", required=True)
    parser.add_argument("--branch", required=True)
    args = parser.parse_args()
    try:
        result = validate_v2(Git(args.repo), args.base, args.head, args.author, args.branch)
        print("Validation passed: " + json.dumps(result, ensure_ascii=True))
        return 0
    except (Invalid, ValueError, OSError) as exc:
        print("Validation failed: " + str(exc).replace("\n", " ").replace("\r", " "),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
