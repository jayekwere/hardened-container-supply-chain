#!/usr/bin/env python3
"""Bind inventory to saved image config and enforce the one-binary image contract."""
import hashlib
import io
import json
import posixpath
import tarfile
import struct
import sys
from pathlib import Path

base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('artifacts')
def require(ok, message='image contract violation'):
    if not ok:
        raise SystemExit('DENY ' + message)

metadata = json.loads((base / 'build-metadata.json').read_text())
with tarfile.open(base / 'image.tar') as archive:
    manifests = json.load(archive.extractfile('manifest.json'))
    require(len(manifests) == 1, 'expected one image')
    manifest = manifests[0]
    config_bytes = archive.extractfile(manifest['Config']).read()
    digest = 'sha256:' + hashlib.sha256(config_bytes).hexdigest()
    require(digest == metadata['containerimage.config.digest'], 'archive/config identity mismatch')
    config = json.loads(config_bytes)
    require(config['config']['User'] == '65532:65532')
    require(config['config']['Entrypoint'] == ['/service'])
    require(not config['config'].get('Volumes'))
    require(len(manifest['Layers']) == 1, 'expected scratch plus one binary layer')
    layer_bytes = archive.extractfile(manifest['Layers'][0]).read()
    with tarfile.open(fileobj=io.BytesIO(layer_bytes)) as layer:
        files = [m for m in layer if not m.isdir()]
        require(len(files) == 1)
        binary = files[0]
        require(posixpath.normpath(binary.name) == 'service' and binary.isfile())
        require(binary.uid == binary.gid == 65532 and binary.mode & 0o111)
        elf = layer.extractfile(binary).read(20)
        require(elf[:4] == b'\x7fELF' and elf[5] == 1)
        machine = struct.unpack('<H', elf[18:20])[0]
        require(machine == {'amd64': 62, 'arm64': 183}[config['architecture']], 'binary/image architecture mismatch')
print(digest)
