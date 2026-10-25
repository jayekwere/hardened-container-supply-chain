"""Synthetic archive regression cases for identity, ownership and architecture."""
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


def add(archive, name, data, uid=0, mode=0o644):
    entry = tarfile.TarInfo(name)
    entry.size, entry.uid, entry.gid, entry.mode = len(data), uid, uid, mode
    archive.addfile(entry, io.BytesIO(data))


class ImageGateTests(unittest.TestCase):
    def check(self, mutation, accepted):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = {'architecture': 'amd64', 'config': {'User': '65532:65532', 'Entrypoint': ['/service']}}
            if mutation == 'root':
                config['config']['User'] = '0:0'
            raw = json.dumps(config).encode()
            digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
            metadata = {'containerimage.config.digest': digest if mutation != 'identity' else 'sha256:bad'}
            (base / 'build-metadata.json').write_text(json.dumps(metadata))
            binary = bytearray(20)
            binary[:4], binary[5], binary[18] = b'\x7fELF', 1, 183 if mutation == 'architecture' else 62
            layer = io.BytesIO()
            with tarfile.open(fileobj=layer, mode='w') as archive:
                add(archive, 'service', binary, uid=0 if mutation == 'ownership' else 65532, mode=0o755)
                if mutation == 'extra-file':
                    add(archive, 'bin/sh', b'synthetic shell')
            with tarfile.open(base / 'image.tar', 'w') as archive:
                add(archive, 'manifest.json', json.dumps([{'Config': 'config.json', 'Layers': ['layer.tar']}]).encode())
                add(archive, 'config.json', raw)
                add(archive, 'layer.tar', layer.getvalue())
            result = subprocess.run([sys.executable, 'scripts/check-image.py', str(base)], capture_output=True)
            self.assertEqual(result.returncode == 0, accepted, result.stderr + result.stdout)

    def test_valid_archive(self):
        self.check('valid', True)

    def test_security_mutations(self):
        for mutation in ['root', 'identity', 'architecture', 'ownership', 'extra-file']:
            with self.subTest(mutation=mutation):
                self.check(mutation, False)


if __name__ == '__main__':
    unittest.main()
