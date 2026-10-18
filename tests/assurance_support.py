"""Synthetic TLS fixture; every private-IP/port/trust substitution stays in tests."""
import datetime
import http.server
from pathlib import Path
import socket
import ssl
import tempfile
import threading
from contextlib import ExitStack
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class TLSFixture:
    host = 'fixture.example.test'
    pinned_ip = '8.8.8.8'  # Synthetic DNS answer; never contacted.

    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='broker-tls-fixture-')
        self.requests, self.connections, self.sni = [], [], []
        self.stall = threading.Event()
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.host)])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                       .public_key(private_key.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(now - datetime.timedelta(minutes=1))
                       .not_valid_after(now + datetime.timedelta(minutes=10))
                       .add_extension(x509.SubjectAlternativeName([x509.DNSName(self.host)]), critical=False)
                       .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                       .sign(private_key, hashes.SHA256()))
        cert, key = Path(self.temp.name) / 'fake-cert.pem', Path(self.temp.name) / 'fake-key.pem'
        cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key.write_bytes(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()))
        cert.chmod(0o600); key.chmod(0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        context.set_servername_callback(lambda sock, name, ctx: self.sni.append(name))
        self.trust = ssl.create_default_context(cafile=str(cert))
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *args):
                pass
            def do_GET(self):
                fixture.requests.append({'path': self.path, 'host': self.headers.get('Host'),
                                         'authorization': self.headers.get('Authorization')})
                if self.path == '/stall-headers':
                    fixture.stall.wait(2)
                status = 302 if self.path == '/redirect' else 200
                body = b'{"state":"ready","token":"FAKE_PROVIDER_ONLY_KEY"}'
                if self.path == '/oversized':
                    body = b'x' * 2048
                try:
                    self.send_response(status)
                    if status == 302:
                        self.send_header('Location', 'https://another.example.test/never-contact')
                    self.send_header('Content-Length', str(len(body)))
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    if self.path == '/stall-body':
                        fixture.stall.wait(2)
                    self.wfile.write(body)
                except OSError:
                    pass

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = True
            def handle_error(self, *args):
                pass

        self.server = Server(('127.0.0.1', 0), Handler)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()
        original_connect = socket.create_connection
        def route(address, *args, **kwargs):
            self.connections.append(address)
            if address != (self.pinned_ip, 443):
                raise AssertionError('UNEXPECTED_FIXTURE_DESTINATION')
            return original_connect(('127.0.0.1', self.server.server_port), *args, **kwargs)
        self.stack = ExitStack()
        self.lookup = self.stack.enter_context(patch('credential_broker.executor._lookup_addresses', return_value=[self.pinned_ip]))
        self.stack.enter_context(patch('credential_broker.executor._tls_context', return_value=self.trust))
        self.stack.enter_context(patch('credential_broker.executor.socket.create_connection', side_effect=route))
        return self

    def __exit__(self, *args):
        self.stall.set()
        self.stack.close()
        self.server.shutdown(); self.server.server_close()
        self.thread.join(2)
        self.temp.cleanup()
