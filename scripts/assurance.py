"""Reproduce bounded demonstrations. Metadata summary, no operational telemetry."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description='Synthetic assurance demonstrations; not a formal proof.')
    parser.add_argument('--all', action='store_true', help='Include the baseline regression suite.')
    parser.add_argument('--lab', action='store_true', help='Also try the ephemeral two-UID Linux laboratory.')
    args = parser.parse_args()
    started = time.monotonic()
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'), pattern='test*.py' if args.all else 'test_assurance_*.py')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = {'scope': 'synthetic-demonstrations-not-formal-proof', 'python': sys.version.split()[0],
               'testsRun': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
               'skipped': len(result.skipped), 'fuzzSeed': 0xA551,
               'malformedFrameCases': 133, 'providerOutputCases': 136}
    success = result.wasSuccessful()
    if args.lab:
        lab = subprocess.run([sys.executable, str(ROOT / 'scripts/two-uid-lab.py')], capture_output=True, timeout=25)
        try: summary['twoUidLab'] = json.loads(lab.stdout)
        except Exception: summary['twoUidLab'] = {'ok': False, 'failed': True}
        summary['twoUidLab']['exitCode'] = lab.returncode
        lab_ok = lab.returncode == 0 and summary['twoUidLab'].get('ok') is True
        lab_unavailable = (lab.returncode == 77 and summary['twoUidLab'].get('unsupported') is True
                           and not summary['twoUidLab'].get('failed'))
        success = success and (lab_ok or lab_unavailable)
    summary['durationMs'] = round((time.monotonic() - started) * 1000)
    summary['ok'] = success
    print(json.dumps(summary, separators=(',', ':')))
    return 0 if success else 1


if __name__ == '__main__':
    raise SystemExit(main())
