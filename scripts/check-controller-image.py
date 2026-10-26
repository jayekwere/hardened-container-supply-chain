#!/usr/bin/env python3
"""Check saved verifier archive identity and runtime configuration without extraction."""
import hashlib, io, json, tarfile
from pathlib import Path

a = Path('artifacts/controller')
m = json.loads((a/'build-metadata.json').read_text())
with tarfile.open(a/'image.tar') as image:
    manifest = json.load(image.extractfile('manifest.json'))
    assert len(manifest) == 1
    raw = image.extractfile(manifest[0]['Config']).read()
    config_digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
    assert config_digest == m['containerimage.config.digest']
    config = json.loads(raw)
    assert config['architecture'] == json.loads((a/'source.json').read_text())['architecture']
    assert config['os'] == 'linux' and config['architecture'] in ['amd64', 'arm64']
    assert config['config']['User'] == '1000:1000'
    assert config['config']['Entrypoint'] == ['/webhook']
    assert not config['config'].get('Volumes')
    binaries = []
    for name in manifest[0]['Layers']:
        with tarfile.open(fileobj=io.BytesIO(image.extractfile(name).read())) as layer:
            for item in layer:
                if item.name.lstrip('./') == 'webhook':
                    assert item.isfile() and item.uid == item.gid == 1000
                    binaries.append(hashlib.sha256(layer.extractfile(item).read()).hexdigest())
    assert binaries == [json.loads((a/'source.json').read_text())['binarySHA256']]
print(config_digest)
