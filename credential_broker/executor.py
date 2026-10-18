"""Bounded public HTTPS transport. No redirects, retries or exception detail."""
import http.client
import ipaddress
import functools
import json
import socket
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

_DNS_SLOTS = threading.BoundedSemaphore(2)

_DNS_CODE = """import json,socket,sys
try:
 values=sorted({entry[4][0] for entry in socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),type=socket.SOCK_STREAM)})
 if not 1<=len(values)<=64: raise ValueError()
 print(json.dumps(values,separators=(',',':')))
except Exception: sys.exit(1)
"""

class TransportError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _lookup_addresses(host, port, deadline):
    child = subprocess.Popen([sys.executable, '-I', '-c', _DNS_CODE, host, str(port)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, close_fds=True)
    try:
        output, _ = child.communicate(timeout=max(.001, deadline-time.monotonic()))
        if child.returncode or len(output) > 8192:
            raise TransportError('UPSTREAM_FAILED')
        return json.loads(output)
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate()
        raise TransportError('UPSTREAM_TIMEOUT') from None
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()


def _resolve(host, port, deadline):
    # Disposable resolver processes release bounded slots even when libc stalls.
    if not _DNS_SLOTS.acquire(blocking=False):
        raise TransportError('RESOLVER_BUSY')
    try:
        addresses = _lookup_addresses(host, port, deadline)
    except TransportError:
        raise
    except Exception:
        raise TransportError('UPSTREAM_FAILED') from None
    finally:
        _DNS_SLOTS.release()
    if not isinstance(addresses, list) or not 1 <= len(addresses) <= 64:
        raise TransportError('UPSTREAM_FAILED')
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise TransportError('DESTINATION_DENIED')
    return addresses[0]


@functools.lru_cache(maxsize=1)
def _tls_context():
    return ssl.create_default_context()


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, address, timeout):
        super().__init__(host, port=port, timeout=timeout, context=_tls_context())
        self.address = address
        self._cancelled = threading.Event()
        self._raw = None
    def abort(self):
        self._cancelled.set()
        for sock in (self.sock, self._raw):
            if sock:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    sock.close()
                except OSError:
                    pass
    def connect(self):
        if self._cancelled.is_set():
            raise TimeoutError()
        raw = socket.create_connection((self.address, self.port), self.timeout)
        self._raw = raw
        try:
            if self._cancelled.is_set():
                raise TimeoutError()
            # Wrap before handshake so watchdog can interrupt the actual TLS fd.
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host, do_handshake_on_connect=False)
            if self._cancelled.is_set():
                raise TimeoutError()
            self.sock.do_handshake()
        except Exception:
            self.abort()
            raise


def secure_request(*, method, url, headers, body, timeout=10, max_bytes=131072):
    conn = timer = None
    response = None
    expired = threading.Event()
    deadline = time.monotonic() + max(.001, min(10, timeout))
    try:
        parsed = urlsplit(url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise TransportError('DESTINATION_DENIED')
        port = parsed.port or 443
        if port != 443:
            raise TransportError('DESTINATION_DENIED')
        address = _resolve(parsed.hostname, port, deadline)
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            raise TransportError('UPSTREAM_TIMEOUT')
        conn = _PinnedHTTPS(parsed.hostname, port, address, remaining)
        def abort():
            expired.set()
            conn.abort()
        timer = threading.Timer(max(.001, deadline-time.monotonic()), abort)
        timer.daemon = True
        timer.start()
        conn.request(method, (parsed.path or '/') + ('?' + parsed.query if parsed.query else ''), body=body, headers=headers)
        response = conn.getresponse()
        if expired.is_set() or time.monotonic() >= deadline:
            raise TransportError('UPSTREAM_TIMEOUT')
        if not 200 <= response.status < 300:
            raise TransportError('UPSTREAM_REJECTED')
        chunks, size = [], 0
        while True:
            remaining = deadline-time.monotonic()
            if remaining <= 0 or expired.is_set():
                raise TransportError('UPSTREAM_TIMEOUT')
            if conn.sock:
                conn.sock.settimeout(remaining)
            chunk = response.read1(min(16384, max_bytes+1-size))
            if expired.is_set() or time.monotonic() >= deadline:
                raise TransportError('UPSTREAM_TIMEOUT')
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > max_bytes:
                raise TransportError('RESPONSE_TOO_LARGE')
        return response.status, b''.join(chunks)
    except TransportError:
        raise
    except (TimeoutError, socket.timeout):
        raise TransportError('UPSTREAM_TIMEOUT') from None
    except Exception:
        raise TransportError('UPSTREAM_TIMEOUT' if expired.is_set() else 'UPSTREAM_FAILED') from None
    finally:
        if timer:
            timer.cancel()
        if response:
            response.close()
        if conn:
            conn.close()
