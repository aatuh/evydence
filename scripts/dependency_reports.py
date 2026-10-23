#!/usr/bin/env python3
"""Schema-owned bounded JSON output with no-follow paths and atomic replacement."""
import json
import os
from pathlib import Path
import stat
import uuid
import dependency_policy as policy
from release_lifecycle import read_bytes

UNSET = object()


class ReportError(ValueError):
    def __init__(self): super().__init__('cannot safely write schema-owned dependency report')


def require(value):
    if not value: raise ReportError()


def directory(root, relative, schema, replace):
    path, fd = Path(relative), None
    try:
        require(not path.is_absolute() and path.parts and '..' not in path.parts)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in path.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        try: old = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError: old = None
        if old is not None:
            require(replace and stat.S_ISREG(old.st_mode))
            previous = policy.parse_document(read_bytes(root, relative, policy.MAX_DOCUMENT_BYTES))
            require(isinstance(previous, dict) and previous.get('schema') == schema)
        return fd, old
    except (OSError, ValueError):
        if fd is not None: os.close(fd)
        raise ReportError() from None


def write(root, relative, document, schema, *, replace=False, expected=UNSET):
    require(isinstance(document, dict) and document.get('schema') == schema)
    raw = (json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode()
    require(len(raw) <= policy.MAX_DOCUMENT_BYTES)
    fd, old = directory(root, relative, schema, replace)
    temporary = None; name = Path(relative).name
    try:
        require(expected is UNSET or old == expected)
        candidate = '.dependency-report-' + uuid.uuid4().hex
        output = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=fd)
        temporary = candidate
        with os.fdopen(output, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        if old is None:
            os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            os.unlink(temporary, dir_fd=fd)
        else:
            require(os.stat(name, dir_fd=fd, follow_symlinks=False) == old)
            os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
        temporary = None; os.fsync(fd)
    except (OSError, ValueError): raise ReportError() from None
    finally:
        if temporary is not None: os.unlink(temporary, dir_fd=fd)
        os.close(fd)
