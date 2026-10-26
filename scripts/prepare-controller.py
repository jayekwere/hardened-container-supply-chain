#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import urllib.request

def tree_hash(directory):
    digest = hashlib.sha256()
    for path in sorted(directory.rglob('*')):
        relative = path.relative_to(directory)
        if relative.parts[0] == '.git' or str(relative) == '.prepared' or path.is_dir():
            continue
        digest.update(str(relative).encode() + b'\0')
        digest.update(path.read_bytes() if not path.is_symlink() else path.readlink().as_posix().encode())
        digest.update(b'\0')
    return digest.hexdigest()

root = Path.cwd()
lock = json.loads(Path('integration/admission/inputs.lock.json').read_text())['controller']
patch = root / 'patches/policy-controller-freshness.patch'
patch_hash = hashlib.sha256(patch.read_bytes()).hexdigest()
dependency_patch = root / 'patches/policy-controller-dependencies.patch'
dependency_hash = hashlib.sha256(dependency_patch.read_bytes()).hexdigest()
cache = root / '.tools/controller-source'
cache.mkdir(parents=True, exist_ok=True)
archive = cache / (lock['sourceCommit'] + '.tar.gz')
if not archive.exists():
    archive.write_bytes(urllib.request.urlopen(lock['sourceArchive']['url'], timeout=120).read())
if hashlib.sha256(archive.read_bytes()).hexdigest() != lock['sourceArchive']['sha256']:
    raise SystemExit('DENY controller source checksum mismatch')
source = cache / (lock['sourceCommit'][:12] + '-' + patch_hash[:12] + '-' + dependency_hash[:12])
if not (source / '.prepared').exists():
    source.mkdir(exist_ok=True)
    with tarfile.open(archive) as bundle:
        members = bundle.getmembers()
        for member in members:
            member.name = '/'.join(member.name.split('/')[1:])
        bundle.extractall(source, members=[m for m in members if m.name], filter='data')
    subprocess.run(['git', 'init', '--quiet', str(source)], check=True)
    subprocess.run(['git', '-C', str(source), 'apply', '--check', str(patch)], check=True)
    subprocess.run(['git', '-C', str(source), 'apply', str(patch)], check=True)
    subprocess.run(['git', '-C', str(source), 'apply', '--check', str(dependency_patch)], check=True)
    subprocess.run(['git', '-C', str(source), 'apply', str(dependency_patch)], check=True)
    (source / '.prepared').write_text(json.dumps({'patch': patch_hash, 'dependencies': dependency_hash, 'tree': tree_hash(source)}))
prepared = json.loads((source / '.prepared').read_text())
if prepared != {'patch': patch_hash, 'dependencies': dependency_hash, 'tree': tree_hash(source)}:
    raise SystemExit('DENY prepared source changed; remove this ignored source cache and rebuild: ' + str(source))
print(source)
