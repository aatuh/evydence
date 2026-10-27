#!/usr/bin/env python3
"""Fixed, credential-free property worker for the native Go fuzz runner."""
import argparse
import base64
import json
from pathlib import Path
import sys

# Python runs in isolated mode; only this committed script directory supplies
# project imports. Neither the payload nor the working directory supplies code.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import tooling_fuzz_properties as properties


def run_request(owner, property_check, body):
    if len(body) > 16 * 1024:
        raise ValueError('property request exceeds its budget')
    request = json.loads(body)
    if (type(request) is not dict or set(request) != {'raw', 'mode', 'seed'}
            or type(request['raw']) is not str or type(request['mode']) is not int
            or not 0 <= request['mode'] <= 255 or type(request['seed']) is not bool):
        raise ValueError('invalid property request')
    raw = base64.b64decode(request['raw'], validate=True)
    if len(raw) > 4096:
        raise ValueError('property input exceeds its budget')
    accepted, seed = property_check(raw, request['mode'])
    result = {'owner': owner, 'status': 'passed', 'accepted': accepted}
    if request['seed']:
        result['seed'] = base64.b64encode(seed).decode('ascii')
    return result


def main():
    if sys.flags.optimize:
        raise ValueError('property assertions must be enabled')
    owners = {'evidence': properties.evidence, 'checksums': properties.checksums,
              'archives': properties.archives, 'signing': properties.signing,
              'backup': properties.backup}
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner', required=True, choices=sorted(owners))
    parser.add_argument('--stream', action='store_true')
    args = parser.parse_args()
    while True:
        body = (sys.stdin.buffer.readline(16 * 1024 + 1) if args.stream
                else sys.stdin.buffer.read(16 * 1024 + 1))
        if args.stream and not body:
            break
        result = run_request(args.owner, owners[args.owner], body)
        print(json.dumps(result, sort_keys=True), flush=True)
        if not args.stream:
            break
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
