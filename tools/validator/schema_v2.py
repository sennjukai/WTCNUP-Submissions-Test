#!/usr/bin/env python3
"""P2.1 Schema v2 conformance checks.

This is a metadata/template checker, not the P2.2 Git-object validator.
It never executes submission files and does not publish anything.

Path policy (must be shared with the C++ client):
- UTF-8 JSON; path must already be NFC; non-NFC is rejected, not normalized.
- Length is measured in UTF-16 code units (Windows semantics), not Python len().
- exact path: <=240 units; segment: <=120 units; depth: <=10.
- collision key is NFKC(path).casefold(), using the running Python Unicode
  database (currently 17.0.0); C++ must use the same vectors/table.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import unicodedata
from pathlib import Path, PurePosixPath

MAX_FILE = 10 * 1024 * 1024
MAX_TOTAL = 50 * 1024 * 1024
MAX_FILES = 300
MAX_META = 256 * 1024
MAX_PATH_UTF16 = 240
MAX_SEGMENT_UTF16 = 120
MAX_DEPTH = 10
MAX_FIELD_CHARS = 10000
# Owner decision: exact lowercase .csv and .blk are the allowed extensions.
EXTENSIONS = frozenset({".csv", ".blk"})
# Game CSVs in the accepted fixtures use semicolon; comma is also supported.
CSV_DELIMITERS = (",", ";")
CSV_MAX_COLUMNS = 4096
UID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
TIME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$")
RESERVED = {"con", "prn", "aux", "nul", "conin$", "conout$", *(
    f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
REQUIRED = {
    "schema_version", "submission_uid", "author_name", "github_user",
    "project_name", "game_version", "translation_version", "channel",
    "changelog", "created_at", "file_count", "total_size", "files",
}
ALLOWED = REQUIRED | {"project_id"}

UNICODE_VERSION = unicodedata.unidata_version


class Invalid(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Invalid(message)


def utf16_units(text: str) -> int:
    try:
        return len(text.encode("utf-16-le")) // 2
    except UnicodeError as exc:
        raise Invalid("invalid Unicode") from exc


def strict_json(raw: bytes):
    require(len(raw) <= MAX_META, "metadata too large")

    def no_duplicates(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, "duplicate JSON key")
            out[key] = value
        return out

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=no_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(Invalid("non-finite number")),
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Invalid("invalid UTF-8 JSON") from exc


def unsafe_segment(part: str) -> bool:
    if not part or part in (".", "..") or part.endswith((" ", ".")):
        return True
    if utf16_units(part) > MAX_SEGMENT_UTF16:
        return True
    if any(ord(ch) < 32 or ord(ch) == 127 or ch in '<>:"|?*' for ch in part):
        return True
    base = part.split(".")[0].casefold()
    return base in RESERVED


def safe_path(value: str) -> str:
    require(isinstance(value, str) and bool(value), "empty or invalid path")
    require(unicodedata.normalize("NFC", value) == value, "path must use NFC (non-NFC is rejected)")
    require(utf16_units(value) <= MAX_PATH_UTF16, "path too long (UTF-16 units)")
    require(not value.startswith(("/", "\\")), "path must be relative")
    require("\\" not in value and ":" not in value, "path must use / and contain no drive/colon")
    parts = value.split("/")
    require(len(parts) <= MAX_DEPTH, "too many path segments")
    for part in parts:
        require(not unsafe_segment(part), "unsafe path segment")
    name = PurePosixPath(value).name
    require(name.count(".") == 1 and PurePosixPath(value).suffix in EXTENSIONS,
            "only exact lowercase .csv/.blk is allowed; double extension is forbidden")
    return value


def validate_blk_content(data: bytes, path: str = "file") -> None:
    """Validate a .blk as inert UTF-8 text (no CSV/table requirement)."""
    require(isinstance(data, (bytes, bytearray)) and len(data) > 0,
            f"{path}: BLK is empty")
    raw = bytes(data)
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    require(bool(raw), f"{path}: BLK is empty")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise Invalid(f"{path}: BLK must be valid UTF-8") from exc
    require("\x00" not in text, f"{path}: BLK contains NUL")
    for ch in text:
        if (ord(ch) < 32 and ch not in "\t\r\n") or ord(ch) == 127:
            raise Invalid(f"{path}: BLK contains control characters")
    require(any(not ch.isspace() for ch in text), f"{path}: BLK is empty")


def validate_payload(path: str, data: bytes) -> None:
    suffix = PurePosixPath(path).suffix
    if suffix == ".csv":
        validate_csv_content(data, path)
    elif suffix == ".blk":
        validate_blk_content(data, path)
    else:
        raise Invalid(f"{path}: unsupported extension")


def validate_csv_content(data: bytes, path: str = "file") -> None:
    """Validate that a .csv file is inert, UTF-8, delimited text.

    Game localization CSVs in the accepted fixtures use semicolon; comma is
    also supported. Every row must have at least two fields and all rows in a
    file must have the same field count. The delimiter must be one of
    CSV_DELIMITERS and is chosen only when it produces a structurally valid
    table. No field is executed or interpreted.
    """
    import csv
    import io

    require(isinstance(data, (bytes, bytearray)) and len(data) > 0,
            f"{path}: CSV is empty")
    raw = bytes(data)
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    require(bool(raw), f"{path}: CSV is empty")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise Invalid(f"{path}: CSV must be valid UTF-8") from exc
    require("\x00" not in text, f"{path}: CSV contains NUL")
    for ch in text:
        if (ord(ch) < 32 and ch not in "\t\r\n") or ord(ch) == 127:
            raise Invalid(f"{path}: CSV contains control characters")

    errors = []
    for delimiter in CSV_DELIMITERS:
        try:
            rows = list(csv.reader(io.StringIO(text, newline=""),
                                    delimiter=delimiter, strict=True))
        except csv.Error as exc:
            errors.append(f"{delimiter}: malformed CSV")
            continue
        if not rows:
            errors.append(f"{delimiter}: no rows")
            continue
        width = len(rows[0])
        if width < 2:
            errors.append(f"{delimiter}: rows need at least two columns")
            continue
        if width > CSV_MAX_COLUMNS:
            errors.append(f"{delimiter}: too many CSV columns")
            continue
        if any(len(row) != width for row in rows):
            errors.append(f"{delimiter}: inconsistent CSV column count")
            continue
        if not any(any(field != "" for field in row) for row in rows):
            errors.append(f"{delimiter}: empty CSV")
            continue
        return
    raise Invalid(f"{path}: invalid CSV ({'; '.join(errors)})")


def collision_key(value: str) -> str:
    # Conservative: NFKC catches fullwidth/halfwidth; casefold is locale-independent.
    return unicodedata.normalize("NFKC", value).casefold()


def _field(obj, key, max_chars=MAX_FIELD_CHARS, allow_empty=False):
    value = obj.get(key)
    require(isinstance(value, str), f"invalid {key}")
    if not allow_empty:
        require(bool(value.strip()), f"empty {key}")
    require(len(value) <= max_chars, f"{key} too long")
    require(len(value.encode("utf-8")) <= max_chars * 4, f"{key} UTF-8 too long")
    require(not any((ord(c) < 32 and c not in "\n\r\t") or ord(c) == 127 for c in value),
            f"control character in {key}")
    return value


def validate_metadata(metadata, expected_uid: str | None = None,
                      expected_author: str | None = None,
                      source_dir: str | os.PathLike | None = None):
    require(isinstance(metadata, dict), "metadata must be an object")
    keys = set(metadata)
    require(not (keys - ALLOWED), "additionalProperties is not allowed")
    require(not (REQUIRED - keys), "missing required field")
    require(isinstance(metadata["schema_version"], int) and
            not isinstance(metadata["schema_version"], bool) and
            metadata["schema_version"] == 2,
            "schema_version must be integer 2")
    uid = metadata["submission_uid"]
    require(isinstance(uid, str) and UID_RE.fullmatch(uid) is not None, "invalid submission_uid")
    if expected_uid is not None:
        require(uid == expected_uid, "submission_uid does not match expected UID")
    _field(metadata, "author_name", 100)
    _field(metadata, "github_user", 39)
    require(LOGIN_RE.fullmatch(metadata["github_user"]) is not None, "invalid github_user")
    if expected_author is not None:
        require(metadata["github_user"].casefold() == expected_author.casefold(), "PR author mismatch")
    if "project_id" in metadata and metadata["project_id"] is not None:
        require(isinstance(metadata["project_id"], str) and
                PROJECT_RE.fullmatch(metadata["project_id"]) is not None, "invalid project_id")
    _field(metadata, "project_name", 200)
    _field(metadata, "game_version", 100)
    _field(metadata, "translation_version", 100)
    require(metadata["channel"] in ("stable", "beta"), "channel must be stable or beta")
    _field(metadata, "changelog", 10000, allow_empty=True)
    created = metadata["created_at"]
    require(isinstance(created, str) and TIME_RE.fullmatch(created) is not None, "invalid created_at")
    import datetime as dt
    try:
        dt.datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Invalid("invalid created_at") from exc
    require(isinstance(metadata["file_count"], int) and not isinstance(metadata["file_count"], bool)
            and 1 <= metadata["file_count"] <= MAX_FILES, "invalid file_count")
    require(isinstance(metadata["total_size"], int) and not isinstance(metadata["total_size"], bool)
            and 0 <= metadata["total_size"] <= MAX_TOTAL, "invalid total_size")
    files = metadata["files"]
    require(isinstance(files, list) and len(files) == metadata["file_count"], "file_count mismatch")
    declared = {}
    prefixes = {}
    for item in files:
        require(isinstance(item, dict) and set(item) == {"path", "size", "sha256"}, "invalid files entry")
        path = safe_path(item["path"])
        require(path not in declared, "duplicate path")
        key = collision_key(path)
        require(key not in prefixes, "case/width-insensitive path collision")
        parts = path.split("/")
        for i in range(1, len(parts) + 1):
            prefix = "/".join(parts[:i])
            pkey = collision_key(prefix)
            other = prefixes.get(pkey)
            require(other is None or other == prefix, "case/width-insensitive path prefix collision")
            prefixes[pkey] = prefix
        size = item["size"]
        require(isinstance(size, int) and not isinstance(size, bool) and 0 <= size <= MAX_FILE,
                "invalid file size")
        require(isinstance(item["sha256"], str) and HASH_RE.fullmatch(item["sha256"]) is not None,
                "invalid sha256")
        declared[path] = {"path": path, "size": size, "sha256": item["sha256"]}
    require(sum(x["size"] for x in declared.values()) == metadata["total_size"], "total_size mismatch")
    if source_dir is not None:
        root = Path(source_dir)
        files_root = root / "files"
        require(files_root.is_dir(), "files/ is missing")
        actual = {}
        for current, dirs, names in os.walk(files_root, followlinks=False):
            current_path = Path(current)
            for name in dirs:
                require(not (current_path / name).is_symlink(), "symlink directory is not allowed")
            for name in names:
                p = current_path / name
                require(not p.is_symlink(), "symlink file is not allowed")
                rel = p.relative_to(files_root).as_posix()
                safe_path(rel)
                actual[rel] = p
        require(set(actual) == set(declared), "declared and actual file sets differ")
        for rel, p in actual.items():
            data = p.read_bytes()
            require(len(data) == declared[rel]["size"], "file size mismatch")
            require(hashlib.sha256(data).hexdigest() == declared[rel]["sha256"], "file SHA-256 mismatch")
            validate_payload(rel, data)
    return uid, declared


def manifest_for(metadata, source_dir):
    uid, declared = validate_metadata(metadata, source_dir=source_dir)
    return {
        "schema_version": 2,
        "submission_uid": uid,
        "file_count": len(declared),
        "total_size": sum(x["size"] for x in declared.values()),
        "files": [declared[p] for p in sorted(declared)],
    }


def load_metadata(path):
    return strict_json(Path(path).read_bytes())


def main():
    parser = argparse.ArgumentParser(description="P2.1 Schema v2 metadata/template checker")
    parser.add_argument("--submission", required=True)
    parser.add_argument("--dir", dest="source_dir")
    args = parser.parse_args()
    try:
        metadata = load_metadata(args.submission)
        uid, _ = validate_metadata(metadata, source_dir=args.source_dir)
        print(f"PASS schema v2 uid={uid} unicode={UNICODE_VERSION}")
        return 0
    except (Invalid, OSError, ValueError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
