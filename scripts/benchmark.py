"""Reproducible local microbenchmarks, fake metadata and no upstream requests."""
import json
from pathlib import Path
import resource
import ssl
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from credential_broker.executor import _tls_context, _lookup_addresses
from credential_broker.governance import TaskGrant, QuotaStore
from credential_broker.host import AuditLog


def measure(callback, count=30):
    samples = []
    for _ in range(count):
        start = time.perf_counter()
        callback()
        samples.append((time.perf_counter() - start) * 1000)
    return {'samples': count, 'medianMs': statistics.median(samples),
            'p95Ms': sorted(samples)[int((count - 1) * .95)]}


_tls_context()
result = {'scope': 'microbenchmarks, not end-to-end provider performance',
          'tlsContextBeforeFresh': measure(ssl.create_default_context),
          'tlsContextAfterCached': measure(_tls_context),
          'dnsChildLocalhost': measure(lambda: _lookup_addresses('localhost', 443, time.monotonic() + 2), 10)}
with tempfile.TemporaryDirectory(prefix='broker-benchmark-') as directory:
    writer = AuditLog(directory)
    result['durableAuditMetadata'] = measure(lambda: writer({'event': 'intent', 'actionIdHash': 'a' * 16,
                                                            'status': 'intent', 'durationMs': 1}))
    grant = TaskGrant({'taskId': 'benchmark-fixture', 'expiresAt': int(time.time()) + 300,
                       'maxUses': 100, 'actions': {'fixture': {}}}, 1234)
    store = QuotaStore(directory)
    result['durableQuotaAttempt'] = measure(lambda: store.consume(grant, 'fake-ref', 100))
result['maxRssKiB'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(json.dumps(result, indent=2))
