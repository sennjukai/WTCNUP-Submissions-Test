#!/usr/bin/env python3
"""Validate a v1 submission as inert Git objects. Never execute or checkout PR data.

Requires trusted caller to supply exact base/head SHAs and GitHub PR metadata. This
program does not approve, package, publish, or confer trust on a submission.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import unicodedata
from pathlib import PurePosixPath

MAX_FILE = 10 * 1024 * 1024
MAX_TOTAL = 50 * 1024 * 1024
MAX_FILES = 300
MAX_META = 256 * 1024
MAX_TREE = 4 * 1024 * 1024
EXTENSIONS = {'.blk', '.csv', '.json', '.txt', '.yml', '.yaml', '.ini', '.dds', '.png', '.tga', '.ogg', '.wav'}
MAGIC = (b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08', b'Rar!\x1a\x07', b'7z\xbc\xaf\x27\x1c', b'\x1f\x8b', b'MZ')
UID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
OID_RE = re.compile(r'^[0-9a-f]{40}$')
LOGIN_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$')
HASH_RE = re.compile(r'^[0-9a-f]{64}$')
FIELDS = {'schema_version','submission_uid','author_name','github_user','project_name','game_version','translation_version','changelog','created_at','file_count','total_size','files'}
RESERVED = re.compile(r'^(?:con|prn|aux|nul|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])$', re.IGNORECASE)

class Invalid(ValueError):
    pass

def require(ok, message):
    if not ok:
        raise Invalid(message)

def utf16len(text):
    try:
        return len(text.encode('utf-16-le')) // 2
    except UnicodeError as exc:
        raise Invalid('invalid Unicode') from exc

def safe_path(value):
    require(isinstance(value, str) and bool(value), 'empty or invalid path')
    require(unicodedata.normalize('NFC', value) == value, 'path must use NFC')
    require(utf16len(value) <= 240, 'path too long')
    require(not value.startswith('/') and '\\' not in value, 'path must be relative and use /')
    parts = value.split('/')
    require(len(parts) <= 25, 'too many path segments')
    for part in parts:
        require(part not in ('', '.', '..'), 'invalid path segment')
        require(utf16len(part) <= 120 and not part.endswith((' ', '.')), 'invalid path segment length or ending')
        require(not any(ord(c) < 32 or ord(c) == 127 or c in '<>:"|?*' for c in part), 'invalid path character')
        require(not RESERVED.fullmatch(part.split('.')[0]), 'reserved Windows name')
    return value

def strict_json(raw):
    require(len(raw) <= MAX_META, 'metadata too large')
    def no_duplicates(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=no_duplicates,
                          parse_constant=lambda _: (_ for _ in ()).throw(Invalid('non-finite number')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Invalid('invalid UTF-8 JSON') from exc

def text_field(obj, key, max_chars, max_bytes, allow_empty=False):
    v = obj[key]
    require(isinstance(v, str) and (allow_empty or bool(v.strip())), f'invalid {key}')
    try:
        require(len(v) <= max_chars and len(v.encode('utf-8')) <= max_bytes, f'{key} too long')
    except UnicodeError as exc:
        raise Invalid(f'invalid Unicode in {key}') from exc
    require(not any((ord(c) < 32 and c not in '\n\r\t') or ord(c) == 127 for c in v), f'control character in {key}')

def is_integer(value):
    return isinstance(value, int) and not isinstance(value, bool)

def validate_metadata(raw, uid, author):
    m = strict_json(raw)
    require(isinstance(m, dict) and set(m) == FIELDS, 'incorrect metadata fields')
    require(is_integer(m['schema_version']) and m['schema_version'] == 1, 'unsupported schema version')
    require(isinstance(m['submission_uid'], str) and UID_RE.fullmatch(m['submission_uid']) and m['submission_uid'] == uid, 'invalid submission UID')
    for key, chars, nbytes in [('author_name',100,400),('project_name',200,800),('game_version',100,400),('translation_version',100,400),('changelog',10000,40960)]:
        text_field(m, key, chars, nbytes, key == 'changelog')
    require(isinstance(m['github_user'], str) and LOGIN_RE.fullmatch(m['github_user']) and m['github_user'].lower() == author.lower(), 'PR author mismatch')
    created = m['created_at']
    require(isinstance(created,str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z',created), 'invalid UTC timestamp')
    try: dt.datetime.fromisoformat(created.replace('Z','+00:00'))
    except ValueError as exc: raise Invalid('invalid UTC timestamp') from exc
    require(is_integer(m['file_count']) and 1 <= m['file_count'] <= MAX_FILES, 'invalid file count')
    require(is_integer(m['total_size']) and 0 <= m['total_size'] <= MAX_TOTAL, 'invalid total size')
    require(isinstance(m['files'], list) and len(m['files']) == m['file_count'], 'file count mismatch')
    declared = {}
    folded = {}
    for item in m['files']:
        require(isinstance(item,dict) and set(item) == {'path','size','sha256'}, 'invalid file entry')
        p = safe_path(item['path'])
        require(p not in declared, 'duplicate path')
        require(is_integer(item['size']) and 0 <= item['size'] <= MAX_FILE, 'invalid file size')
        require(isinstance(item['sha256'],str) and HASH_RE.fullmatch(item['sha256']), 'invalid SHA-256')
        require(PurePosixPath(p).suffix.lower() in EXTENSIONS, 'forbidden extension')
        for i in range(1, len(p.split('/'))+1):
            prefix = '/'.join(p.split('/')[:i]); key = prefix.casefold()
            require(key not in folded or folded[key] == prefix, 'case-insensitive path collision')
            folded[key] = prefix
        declared[p] = item
    require(sum(x['size'] for x in declared.values()) == m['total_size'], 'total size mismatch')
    return m, declared

class Git:
    def __init__(self, repo): self.repo = repo
    def command(self, *args, max_bytes=MAX_TREE):
        # No shell, no external diff/textconv; Git objects are data. Limit output and time.
        env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_TERMINAL_PROMPT='0', GIT_PAGER='cat', LC_ALL='C')
        try:
            p = subprocess.Popen(['git','-C',self.repo,*args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
            timer = threading.Timer(60, p.kill)
            timer.daemon = True
            timer.start()
            try:
                data = p.stdout.read(max_bytes + 1)
                if len(data) > max_bytes:
                    p.kill(); p.wait(); raise Invalid('git output exceeds limit')
                if p.wait(timeout=60) != 0: raise Invalid('git command failed or timed out')
                return data
            finally:
                timer.cancel()
                p.stdout.close()
        except (OSError, subprocess.TimeoutExpired) as exc:
            if 'p' in locals() and p.poll() is None: p.kill(); p.wait()
            raise Invalid('git unavailable or timed out') from exc
    def changed(self, base, head):
        out = self.command('-c','core.quotepath=false','diff','--no-ext-diff','--no-textconv','--no-renames','--name-status','-z',base,head,'--')
        values = out.split(b'\0')
        require(values[-1] == b'' and (len(values)-1)%2 == 0, 'invalid diff')
        result=[]
        for i in range(0,len(values)-1,2):
            try: result.append((values[i].decode('ascii'), values[i+1].decode('utf-8')))
            except UnicodeError as exc: raise Invalid('invalid filename encoding') from exc
        return result
    def entries(self, head, prefix):
        raw = self.command('-c','core.quotepath=false','ls-tree','-r','-z','--full-tree',head,'--',prefix)
        entries={}
        for row in raw.split(b'\0'):
            if not row: continue
            try:
                info, name = row.split(b'\t',1); mode, typ, oid = info.decode('ascii').split(' ')
                name=name.decode('utf-8')
            except (ValueError,UnicodeError) as exc: raise Invalid('invalid git tree') from exc
            require(name not in entries, 'duplicate git tree entry')
            entries[name]=(mode,typ,oid)
        return entries
    def blob(self, oid, limit):
        require(OID_RE.fullmatch(oid) is not None, 'invalid blob OID')
        size = self.command('cat-file','-s',oid,max_bytes=128)
        try: n = int(size)
        except ValueError as exc: raise Invalid('invalid blob size') from exc
        require(0 <= n <= limit, 'blob too large')
        result=self.command('cat-file','blob',oid,max_bytes=limit)
        require(len(result)==n, 'blob size changed')
        return result

def validate(git, base, head, author, branch):
    require(OID_RE.fullmatch(base or '') is not None and OID_RE.fullmatch(head or '') is not None and base != head, 'invalid commit SHA')
    require(isinstance(author,str) and LOGIN_RE.fullmatch(author) is not None, 'invalid PR author')
    require(branch.startswith('wtcnup/submission-'), 'invalid branch')
    uid = branch[len('wtcnup/submission-'):]
    require(UID_RE.fullmatch(uid) is not None, 'invalid branch UID')
    prefix = f'submissions/{uid}/'; metadata_path = prefix + 'submission.json'; files_prefix = prefix + 'files/'
    changed = git.changed(base,head)
    require(1 < len(changed) <= MAX_FILES+1, 'invalid changed-file count')
    for status,name in changed:
        require(status == 'A' and (name == metadata_path or name.startswith(files_prefix)), 'PR may only add this submission')
    tree = git.entries(head, prefix)
    require(set(tree) == {p for _,p in changed}, 'tree and change set differ')
    require(metadata_path in tree, 'missing submission.json')
    for name,(mode,typ,oid) in tree.items():
        require(mode == '100644' and typ == 'blob' and OID_RE.fullmatch(oid) is not None, 'only regular non-executable files are allowed')
    m, declared = validate_metadata(git.blob(tree[metadata_path][2],MAX_META),uid,author)
    actual = {p[len(files_prefix):]: v for p,v in tree.items() if p.startswith(files_prefix)}
    require(set(actual)==set(declared), 'declared and actual file sets differ')
    total=0
    for name,item in declared.items():
        contents = git.blob(actual[name][2],MAX_FILE)
        require(len(contents)==item['size'], 'file size mismatch')
        require(hashlib.sha256(contents).hexdigest()==item['sha256'], 'file SHA-256 mismatch')
        require(not any(contents.startswith(sig) for sig in MAGIC), 'archive or executable signature')
        total += len(contents)
        require(total <= MAX_TOTAL, 'submission too large')
    require(total == m['total_size'], 'total size mismatch')
    return {'uid':uid,'head':head,'base':base,'file_count':len(actual),'total_size':total}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--repo',required=True); parser.add_argument('--base',required=True); parser.add_argument('--head',required=True)
    parser.add_argument('--author',required=True); parser.add_argument('--branch',required=True)
    args=parser.parse_args()
    try:
        result=validate(Git(args.repo),args.base,args.head,args.author,args.branch)
        print('Validation passed: '+json.dumps(result,ensure_ascii=True))
        return 0
    except (Invalid, ValueError, OSError) as exc:
        # Untrusted strings are not interpolated into GitHub workflow commands.
        print('Validation failed: '+str(exc).replace('\n',' ').replace('\r',' '),file=sys.stderr)
        return 1
if __name__=='__main__': sys.exit(main())
