#!/usr/bin/env python3
"""Check the closed Python QA dependency pin and static SDK import boundary."""
import ast
import importlib.metadata
from pathlib import Path
import re
import sys

from release_lifecycle import read_bytes

ROOT = Path(__file__).resolve().parents[1]


class PythonQAError(ValueError):
    def __init__(self):
        super().__init__('invalid Python QA pin, installed dependency or SDK import boundary')


def parse_requirements(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 32768:
        raise PythonQAError()
    try:
        text = '\n'.join(line for line in raw.decode('ascii').splitlines()
                         if not line.lstrip().startswith('#')).replace('\\\n', ' ')
    except UnicodeError:
        raise PythonQAError() from None
    tokens = text.split()
    if not 2 <= len(tokens) <= 129 or not re.fullmatch(r'PyYAML==[0-9]+\.[0-9]+\.[0-9]+', tokens[0]):
        raise PythonQAError()
    if any(not re.fullmatch(r'--hash=sha256:[0-9a-f]{64}', token) for token in tokens[1:]):
        raise PythonQAError()
    hashes = [token.removeprefix('--hash=sha256:') for token in tokens[1:]]
    if len(hashes) != len(set(hashes)):
        raise PythonQAError()
    return tokens[0].split('==')[1], hashes


def check_distribution(distribution, version):
    if distribution.version != version or distribution.requires not in (None, []):
        raise PythonQAError()


def check_sdk(root):
    files = sorted((Path(root) / 'sdk/python').glob('*.py'))
    if not 1 <= len(files) <= 64:
        raise PythonQAError()
    local = {path.stem for path in files}
    try:
        for path in files:
            tree = ast.parse(read_bytes(root, path.relative_to(root).as_posix(), 1024 * 1024))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [entry.name.split('.')[0] for entry in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module.split('.')[0]] if node.module else [entry.name for entry in node.names]
                    if node.level and (node.level != 1 or any(name not in local for name in names)):
                        raise PythonQAError()
                else:
                    continue
                if any(name not in sys.stdlib_module_names and name not in local for name in names):
                    raise PythonQAError()
    except (OSError, ValueError, SyntaxError):
        raise PythonQAError() from None


def main():
    try:
        if len(sys.argv) != 1:
            raise PythonQAError()
        version, _hashes = parse_requirements(read_bytes(ROOT, 'tools/requirements-qa.txt', 32768))
        check_distribution(importlib.metadata.distribution('PyYAML'), version)
        check_sdk(ROOT)
        print('python-qa: pinned PyYAML version, empty package requirements and static SDK imports verified')
        return 0
    except (ValueError, OSError, importlib.metadata.PackageNotFoundError):
        print('python-qa: invalid pin, missing/mismatched PyYAML or unsupported SDK import', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
