#!/usr/bin/env python3
"""Small regression guard for workflow trust boundaries; actionlint checks syntax."""
import re
from pathlib import Path
for path in Path('.github/workflows').glob('*.yml'):
    raw = path.read_text()
    assert 'pull_request_target' not in raw and 'write-all' not in raw, path
    if 'actions/checkout@' in raw:
        assert 'persist-credentials: false' in raw, path
    for uses in re.findall(r'uses:\s*(\S+)', raw):
        assert uses.startswith('./.github/workflows/') or re.fullmatch(r'[^@]+@[a-f0-9]{40}', uses), uses
    assert 'permissions:\n  contents: read' in raw, path
    if path.name == 'quality.yml':
        assert 'id-token: write' not in raw and 'packages: write' not in raw, path
print('PASS workflow actions pinned and quality permissions restricted')
