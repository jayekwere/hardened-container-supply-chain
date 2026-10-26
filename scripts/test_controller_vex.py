"""Bounded VEX must fail if affected code, advisory scope or inventory changes."""
import copy, hashlib, importlib.util, json, unittest

spec=importlib.util.spec_from_file_location('vex','scripts/controller-vex.py')
vex=importlib.util.module_from_spec(spec);spec.loader.exec_module(vex)

class VEXTests(unittest.TestCase):
    def test_scope(self):
        advisory={'id':'GO-2026-5932','affected':[{'package':{'name':'golang.org/x/crypto','ecosystem':'Go'},'ecosystem_specific':{'imports':[{'path':'golang.org/x/crypto/openpgp'}]}}]}
        raw=json.dumps(advisory).encode()
        lock={'id':advisory['id'],'sha256':hashlib.sha256(raw).hexdigest(),'module':'golang.org/x/crypto','packagePrefix':'golang.org/x/crypto/openpgp'}
        package_list=['github.com/sigstore/policy-controller/cmd/webhook','golang.org/x/crypto/cryptobyte']+[f'example.invalid/package/{i}' for i in range(101)]
        finding={'VulnerabilityID':lock['id'],'PkgName':lock['module'],'InstalledVersion':'v0.57.0','Severity':'UNKNOWN'}
        other={'VulnerabilityID':'UNEXPECTED','PkgName':lock['module'],'InstalledVersion':'v0.57.0','Severity':'UNKNOWN'}
        report={'Metadata':{'ImageID':'sha256:'+'a'*64},'Results':[{'Type':'gobinary','Packages':[{'Name':lock['module'],'Version':'v0.57.0'}],'Vulnerabilities':[finding,other]}]}
        source={'architecture':'amd64','packageClosureSHA256':hashlib.sha256(('\n'.join(package_list)+'\n').encode()).hexdigest()}
        filtered,_=vex.evaluate(report,raw,package_list,source,lock)
        self.assertEqual(filtered['Results'][0]['Vulnerabilities'],[other])
        self.assertEqual(len(report['Results'][0]['Vulnerabilities']),2)
        for mutation in ['affected-package','affected-subpackage','changed-advisory','broader-scope','missing-inventory','duplicate-finding','wrong-module','wrong-architecture']:
            with self.subTest(mutation=mutation):
                r,p,s,l,b=copy.deepcopy(report),package_list[:],source.copy(),lock.copy(),raw
                if mutation=='affected-package':p.append('golang.org/x/crypto/openpgp')
                elif mutation=='affected-subpackage':p.append('golang.org/x/crypto/openpgp/packet')
                elif mutation=='changed-advisory':b+=b'\n'
                elif mutation=='broader-scope':
                    a=copy.deepcopy(advisory);a['affected'][0]['ecosystem_specific']['imports'].append({'path':'golang.org/x/crypto/cryptobyte'});b=json.dumps(a).encode();l['sha256']=hashlib.sha256(b).hexdigest()
                elif mutation=='missing-inventory':r['Results'][0]['Packages']=[]
                elif mutation=='duplicate-finding':r['Results'][0]['Vulnerabilities'].append(finding)
                elif mutation=='wrong-module':r['Results'][0]['Vulnerabilities'][0]['PkgName']='invalid'
                elif mutation=='wrong-architecture':s['architecture']='invalid'
                if mutation in ['affected-package','affected-subpackage']:s['packageClosureSHA256']=hashlib.sha256(('\n'.join(p)+'\n').encode()).hexdigest()
                with self.assertRaises(AssertionError):vex.evaluate(r,b,p,s,l)
        print('PASS bounded VEX; unrelated UNKNOWN retained; 8 unsafe mutations rejected')

if __name__=='__main__':unittest.main()
