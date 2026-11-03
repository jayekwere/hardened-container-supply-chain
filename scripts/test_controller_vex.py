"""A fixed dependency record must preserve every scanner finding."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('vex', 'scripts/controller-vex.py')
vex = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vex)


def closure_hash(packages):
    return hashlib.sha256(('\n'.join(packages) + '\n').encode()).hexdigest()


class VEXTests(unittest.TestCase):
    def setUp(self):
        self.lock = json.loads(Path('security/verifier-vex.lock.json').read_text())
        self.raw = Path(self.lock['advisoryPath']).read_bytes()
        self.advisory = json.loads(self.raw)
        self.packages = ['github.com/sigstore/policy-controller/cmd/webhook',
                         'golang.org/x/crypto/cryptobyte'] + [
                             f'example.invalid/package/{i}' for i in range(101)]
        self.report = {'Metadata': {'ImageID': 'sha256:' + 'c' * 64}, 'Results': [
            {'Type': 'gobinary', 'Packages': [{'Name': self.lock['module'],
                                             'Version': self.lock['moduleVersion']}]}]}
        self.source = {'architecture': 'amd64', 'packageClosureSHA256': closure_hash(self.packages),
                       'manifestDigest': 'sha256:' + 'a' * 64, 'binarySHA256': 'b' * 64}

    def test_every_finding_is_preserved(self):
        for architecture in ['amd64', 'arm64']:
            for severities in [[], ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN']]:
                with self.subTest(architecture=architecture, severities=severities):
                    report = copy.deepcopy(self.report)
                    report['Results'][0]['Vulnerabilities'] = [
                        {'VulnerabilityID': 'TEST-' + severity, 'Severity': severity,
                         'PkgName': self.lock['module'], 'InstalledVersion': self.lock['moduleVersion']}
                        for severity in severities]
                    before = copy.deepcopy(report)
                    source = {**self.source, 'architecture': architecture}
                    unchanged, inventory = vex.evaluate(report, self.raw, self.packages, source, self.lock)
                    self.assertEqual(unchanged, before)
                    self.assertEqual(report, before)
                    self.assertIsNot(unchanged, report)
                    self.assertEqual(inventory['Version'], self.lock['moduleVersion'])

    def test_unsafe_inputs_are_rejected(self):
        mutations = ['changed-advisory', 'withdrawn-advisory', 'changed-id', 'extra-module',
                     'duplicate-advisory-module', 'broader-root-scope', 'broader-legacy-scope',
                     'empty-imports', 'wrong-ecosystem', 'changed-fixed-range', 'changed-legacy-range',
                     'affected-package', 'affected-subpackage', 'missing-inventory',
                     'duplicate-inventory', 'wrong-module', 'old-version', 'unreviewed-version',
                     'legacy-module', 'legacy-submodule', 'reappeared-advisory',
                     'reappeared-advisory-other-result', 'wrong-architecture', 'closure-hash',
                     'duplicate-package', 'short-closure', 'missing-entrypoint',
                     'missing-crypto-closure', 'wrong-image-id', 'old-status', 'filtering-mode',
                     'broader-prefix']
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(self.report)
                advisory = copy.deepcopy(self.advisory)
                packages, source, lock, raw = self.packages[:], self.source.copy(), self.lock.copy(), self.raw
                rows = report['Results'][0]['Packages']
                if mutation == 'changed-advisory':
                    raw += b'\n'
                elif mutation == 'withdrawn-advisory':
                    advisory['withdrawn'] = '2026-11-03T00:00:00Z'
                elif mutation == 'changed-id':
                    advisory['id'] = 'GO-2099-0000'
                elif mutation == 'extra-module':
                    advisory['affected'].append(copy.deepcopy(advisory['affected'][0]))
                elif mutation == 'duplicate-advisory-module':
                    advisory['affected'][1] = copy.deepcopy(advisory['affected'][0])
                elif mutation in ['broader-root-scope', 'broader-legacy-scope']:
                    index = 0 if mutation == 'broader-root-scope' else 1
                    advisory['affected'][index]['ecosystem_specific']['imports'].append(
                        {'path': 'golang.org/x/crypto/cryptobyte'})
                elif mutation == 'empty-imports':
                    advisory['affected'][0]['ecosystem_specific']['imports'] = []
                elif mutation == 'wrong-ecosystem':
                    advisory['affected'][0]['package']['ecosystem'] = 'invalid'
                elif mutation == 'changed-fixed-range':
                    advisory['affected'][0]['ranges'][0]['events'][1]['fixed'] = '0.58.0'
                elif mutation == 'changed-legacy-range':
                    advisory['affected'][1]['ranges'] = []
                elif mutation in ['affected-package', 'affected-subpackage']:
                    packages.append(lock['packagePrefix'] + ('/packet' if mutation == 'affected-subpackage' else ''))
                elif mutation == 'missing-inventory':
                    rows.clear()
                elif mutation == 'duplicate-inventory':
                    rows.append(rows[0].copy())
                elif mutation == 'wrong-module':
                    rows[0]['Name'] = 'invalid'
                elif mutation in ['old-version', 'unreviewed-version']:
                    rows[0]['Version'] = 'v0.58.0' if mutation == 'old-version' else 'v0.59.0'
                elif mutation in ['legacy-module', 'legacy-submodule']:
                    rows.append({'Name': lock['packagePrefix'] + ('/packet' if mutation == 'legacy-submodule' else ''),
                                 'Version': 'v0.0.0-synthetic'})
                elif mutation in ['reappeared-advisory', 'reappeared-advisory-other-result']:
                    finding = {'VulnerabilityID': lock['id'], 'Severity': 'UNKNOWN',
                               'PkgName': lock['module'], 'InstalledVersion': lock['moduleVersion']}
                    if mutation == 'reappeared-advisory':
                        report['Results'][0]['Vulnerabilities'] = [finding]
                    else:
                        report['Results'].append({'Type': 'other', 'Vulnerabilities': [finding]})
                elif mutation == 'wrong-architecture':
                    source['architecture'] = 'invalid'
                elif mutation == 'closure-hash':
                    source['packageClosureSHA256'] = 'f' * 64
                elif mutation == 'duplicate-package':
                    packages.append(packages[-1])
                elif mutation == 'short-closure':
                    packages = packages[:2]
                elif mutation == 'missing-entrypoint':
                    packages[0] = 'example.invalid/other'
                elif mutation == 'missing-crypto-closure':
                    packages.pop(1)
                elif mutation == 'wrong-image-id':
                    report['Metadata']['ImageID'] = 'invalid'
                elif mutation == 'old-status':
                    lock['status'] = 'not_affected'
                elif mutation == 'filtering-mode':
                    lock['findingPolicy'] = 'filtered'
                elif mutation == 'broader-prefix':
                    lock['packagePrefix'] = lock['module']
                if advisory != self.advisory:
                    raw = json.dumps(advisory).encode()
                    lock['sha256'] = hashlib.sha256(raw).hexdigest()
                if packages != self.packages:
                    source['packageClosureSHA256'] = closure_hash(packages)
                with self.assertRaises(AssertionError):
                    vex.evaluate(report, raw, packages, source, lock)

    def test_generated_record_preserves_raw_bytes(self):
        script = Path('scripts/controller-vex.py').resolve()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = root / 'artifacts/controller'
            artifacts.mkdir(parents=True)
            (root / 'security').mkdir()
            (root / 'security/verifier-vex.lock.json').write_text(json.dumps(self.lock))
            (artifacts / 'openpgp-advisory.json').write_bytes(self.raw)
            raw = json.dumps(self.report, separators=(', ', ' : ')).encode() + b'\n\n'
            (artifacts / 'scan.json').write_bytes(raw)
            (artifacts / 'source.json').write_text(json.dumps(self.source))
            (artifacts / 'packages.txt').write_text('\n'.join(self.packages) + '\n')
            (artifacts / 'build-metadata.json').write_text(json.dumps({
                'containerimage.digest': self.source['manifestDigest'],
                'containerimage.config.digest': self.report['Metadata']['ImageID']}))
            result = subprocess.run([sys.executable, str(script)], cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((artifacts / 'scan-policy-input.json').read_bytes(), raw)
            statement = json.loads((artifacts / 'vex.json').read_text())['statements'][0]
            self.assertEqual(statement['status'], 'fixed')
            self.assertNotIn('justification', statement)
            self.assertEqual(statement['products'][0]['@id'], 'urn:' + self.source['manifestDigest'])
            evidence = json.loads((artifacts / 'vex-evidence.json').read_text())
            self.assertFalse(evidence['filteringApplied'])
            self.assertEqual(evidence['rawScanSHA256'], evidence['policyInputSHA256'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
