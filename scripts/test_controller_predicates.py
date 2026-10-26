"""Claim mutations must reject even after an envelope signature was verified."""
import copy, hashlib, importlib.util, json, tempfile, unittest
from pathlib import Path

spec=importlib.util.spec_from_file_location('claims','scripts/verify-controller-predicates.py')
claims=importlib.util.module_from_spec(spec);spec.loader.exec_module(claims)

class ClaimsTests(unittest.TestCase):
    def test_claims(self):
        image='ghcr.io/jayekwere/hardened-container-supply-chain@sha256:'+'a'*64
        revision='b'*40
        upstream=json.loads(Path('integration/admission/inputs.lock.json').read_text())['controller']
        def statement(kind,predicate):
            return {'_type':'https://in-toto.io/Statement/v0.1','predicateType':kind,'subject':[{'name':image.split('@')[0],'digest':{'sha256':'a'*64}}],'predicate':predicate}
        sbom=statement('https://cyclonedx.org/bom',{'bomFormat':'CycloneDX','specVersion':'1.7','components':[{'name':'stdlib','version':'v1.27.3'}]+[{'name':str(i)} for i in range(101)]})
        evidence=statement('https://github.com/jayekwere/hardened-container-supply-chain/verifier-evidence/v1',{'vexProfile':json.loads(Path('security/verifier-vex.lock.json').read_text()),'schemaVersion':1,'image':image,'sourceRevision':revision,'builder':'controller-release.yml','platform':'linux/amd64','exceptions':{'schemaVersion':1,'entries':[]},'upstream':{'sourceCommit':upstream['sourceCommit'],'sourceArchiveSHA256':upstream['sourceArchive']['sha256'],'buildImage':upstream['buildImage'],'architecture':'amd64','goModSHA256':'c'*64,'goSumSHA256':'c'*64,'manifestDigest':'sha256:'+'a'*64,'patchSHA256':hashlib.sha256(Path('patches/policy-controller-freshness.patch').read_bytes()).hexdigest(),'dependencyPatchSHA256':hashlib.sha256(Path('patches/policy-controller-dependencies.patch').read_bytes()).hexdigest()},'checksums':{n:'c'*64 for n in ['scan.json','sbom.cdx.json','db-metadata.json','scanner-version.txt','source.json','modules.txt','unit-tests.txt','go.mod','go.sum','reproducibility.txt','packages.txt','vex.json','vex-evidence.json','openpgp-advisory.json','scan-policy-input.json']}})
        claims.validate(sbom,evidence,image,revision)
        mutations=['sbom-subject','evidence-subject','type','compiler','empty','image','revision','builder','platform','exceptions','source','patch','dependency-patch','manifest','checksums']
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                s,e=copy.deepcopy(sbom),copy.deepcopy(evidence);p=e['predicate']
                if mutation=='sbom-subject':s['subject'][0]['digest']['sha256']='d'*64
                elif mutation=='evidence-subject':e['subject'][0]['digest']['sha256']='d'*64
                elif mutation=='type':s['predicateType']='invalid'
                elif mutation=='compiler':s['predicate']['components'][0]['version']='v0.0.0'
                elif mutation=='empty':s['predicate']['components']=[]
                elif mutation in ['image','builder','platform']:p[mutation]='invalid'
                elif mutation=='revision':p['sourceRevision']='d'*40
                elif mutation=='exceptions':p['exceptions']['entries']=[{}]
                elif mutation=='source':p['upstream']['sourceCommit']='d'*40
                elif mutation=='patch':p['upstream']['patchSHA256']='d'*64
                elif mutation=='dependency-patch':p['upstream']['dependencyPatchSHA256']='d'*64
                elif mutation=='manifest':p['upstream']['manifestDigest']='sha256:'+'d'*64
                elif mutation=='checksums':p['checksums']={}
                with self.assertRaises(AssertionError):claims.validate(s,e,image,revision)
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises((AssertionError,FileNotFoundError)):claims.validate(sbom,evidence,image,revision,temp)
        print('PASS 1 valid claim set; 15 claim mutations and missing reports rejected')

if __name__=='__main__':unittest.main()
