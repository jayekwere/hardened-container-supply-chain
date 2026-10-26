"""Exercise the observed startup refusal, genuine policy denial and retry bound."""
import importlib.util
import subprocess
import unittest

spec = importlib.util.spec_from_file_location('bootstrap', 'scripts/apply-bootstrap-policy.py')
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class BootstrapTests(unittest.TestCase):
    def execute(self, outputs):
        remaining = iter(outputs)
        calls = []
        def runner(args, **kwargs):
            calls.append(args)
            code, output = next(remaining)
            return subprocess.CompletedProcess(args, code, stdout=output)
        passed, observations = bootstrap.apply('explicit-config', 'policy.json', runner=runner, pause=lambda _: None, attempts=3)
        return passed, observations, calls

    def test_transport_failure_recovers(self):
        refused = 'failed calling webhook "defaulting.clusterimagepolicy.sigstore.dev": connect: connection refused'
        passed, observations, calls = self.execute([(1, refused), (0, 'created\n')])
        self.assertTrue(passed)
        self.assertEqual([x['outcome'] for x in observations], ['webhook-unavailable', 'applied'])
        self.assertEqual(len(calls), 2)
        self.assertIn('--kubeconfig', calls[0])

    def test_validation_eof_recovers(self):
        failed = 'failed calling webhook "validating.clusterimagepolicy.sigstore.dev": Post validating: EOF'
        passed, observations, calls = self.execute([(1, failed), (0, 'configured\n')])
        self.assertTrue(passed)
        self.assertEqual([x['outcome'] for x in observations], ['webhook-unavailable', 'applied'])
        self.assertEqual(len(calls), 2)

    def test_denial_is_not_retried(self):
        denied = 'admission webhook "validation.clusterimagepolicy.sigstore.dev" denied the request: invalid policy'
        passed, observations, calls = self.execute([(1, denied)])
        self.assertFalse(passed)
        self.assertEqual(observations[0]['outcome'], 'rejected')
        self.assertEqual(len(calls), 1)

    def test_conversion_failure_recovers(self):
        failed = 'conversion webhook for policy.sigstore.dev/v1alpha1, Kind=ClusterImagePolicy failed: EOF'
        passed, observations, calls = self.execute([(1, failed), (0, 'configured\n')])
        self.assertTrue(passed)
        self.assertEqual([x['outcome'] for x in observations], ['webhook-unavailable', 'applied'])
        self.assertEqual(len(calls), 2)

    def test_foreign_webhook_is_not_retried(self):
        passed, _, calls = self.execute([(1, 'failed calling webhook "other.invalid": connection refused')])
        self.assertFalse(passed)
        self.assertEqual(len(calls), 1)

    def test_denial_quoting_transport_error_is_not_retried(self):
        denied = 'admission webhook "validation.clusterimagepolicy.sigstore.dev" denied the request: failed calling webhook "defaulting.clusterimagepolicy.sigstore.dev": connection refused'
        passed, _, calls = self.execute([(1, denied)])
        self.assertFalse(passed)
        self.assertEqual(len(calls), 1)

    def test_execution_timeout_fails_closed(self):
        def runner(args, **kwargs):
            raise subprocess.TimeoutExpired(args, 20)
        passed, observations = bootstrap.apply('explicit-config', 'policy.json', runner=runner, pause=lambda _: None)
        self.assertFalse(passed)
        self.assertEqual([x['outcome'] for x in observations], ['execution-error'])

    def test_persistent_outage_exhausts_bound(self):
        unavailable = 'failed calling webhook "defaulting.clusterimagepolicy.sigstore.dev": no endpoints available'
        passed, observations, calls = self.execute([(1, unavailable)]*3)
        self.assertFalse(passed)
        self.assertEqual(len(observations), 3)
        self.assertEqual(len(calls), 3)


if __name__ == '__main__':
    unittest.main()
