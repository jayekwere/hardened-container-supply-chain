#!/usr/bin/env python3
import json, re
from pathlib import Path
lock = json.loads(Path('tools.lock.json').read_text())
version = re.search(r'^go (\S+)$', Path('go.mod').read_text(), re.M).group(1)
assert lock['go']['version'] == version
assert 'golang:' + version + '-alpine@sha256:' in Path('Dockerfile').read_text()
assert '= go' + version in Path('Makefile').read_text()
assert re.search(r'golang:[^\s]+@sha256:[a-f0-9]{64} AS build', Path('Dockerfile').read_text())
for name, tool in lock.items():
    for item in tool['platforms'].values():
        assert item['url'].startswith('https://') and item['checksumSource'].startswith('https://')
        assert re.fullmatch('[a-f0-9]{64}', item['sha256']), name
print('PASS compiler pins and download locks consistent')
