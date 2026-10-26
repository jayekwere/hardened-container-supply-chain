#!/usr/bin/env python3
"""Bounded installation retry for unavailable policy webhooks; never ignore denials."""
import json
import subprocess
import sys
import time
from pathlib import Path


def apply(kubeconfig, policy, runner=subprocess.run, pause=time.sleep, attempts=10):
    observations = []
    started = time.monotonic()
    for attempt in range(1, attempts + 1):
        if attempt > 1 and time.monotonic() - started >= 60:
            return False, observations
        try:
            result = runner(['kubectl', '--kubeconfig', kubeconfig, '--request-timeout=15s',
                             'apply', '-f', policy], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired) as error:
            observations.append({'attempt': attempt, 'outcome': 'execution-error', 'output': str(error)})
            return False, observations
        text = result.stdout.lower()
        transport = any(word in text for word in ['connection refused', 'no endpoints available',
                                                  'context deadline exceeded', 'tls handshake timeout', 'i/o timeout'])
        unavailable = 'failed calling webhook' in text and '.clusterimagepolicy.sigstore.dev' in text and transport
        conversion = ('conversion webhook for policy.sigstore.dev/' in text and 'failed:' in text and
                      (transport or 'eof' in text))
        retryable = 'denied the request' not in text and (unavailable or conversion)
        outcome = 'applied' if result.returncode == 0 else 'webhook-unavailable' if retryable else 'rejected'
        observations.append({'attempt': attempt, 'outcome': outcome, 'exitCode': result.returncode, 'output': result.stdout})
        if result.returncode == 0:
            return True, observations
        if not retryable or attempt == attempts or time.monotonic() - started >= 60:
            return False, observations
        pause(1)
    return False, observations


if __name__ == '__main__':
    kubeconfig, policy = sys.argv[1:]
    passed, observations = apply(kubeconfig, policy)
    directory = Path('artifacts/admission')
    directory.mkdir(parents=True, exist_ok=True)
    (directory/('bootstrap-'+Path(policy).stem+'.json')).write_text(json.dumps({
        'schemaVersion': 1, 'policy': policy, 'outcome': 'passed' if passed else 'failed',
        'attempts': observations}, indent=2)+'\n')
    for item in observations:
        print(f"bootstrap {Path(policy).name} attempt {item['attempt']}: {item['outcome']}")
        if item.get('output'):
            print(item['output'], end='' if item['output'].endswith('\n') else '\n')
    raise SystemExit(0 if passed else 1)
