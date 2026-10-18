import unittest
import threading
import time
from unittest.mock import patch
from credential_broker.executor import secure_request, TransportError

class Response:
    status=200
    def __init__(self): self.chunks=[b'{"state":"ok"}',b'']
    def read1(self,size): return self.chunks.pop(0)
    def close(self): pass
class Connection:
    def __init__(self,*args,**kwargs): self.sock=None; self.closed=False; self.response=Response()
    def request(self,*args,**kwargs): pass
    def getresponse(self): return self.response
    def close(self): self.closed=True
    def abort(self): self.closed=True

class ExecutorTests(unittest.TestCase):
    def request(self,url='https://example.com/v1'):
        return secure_request(method='GET',url=url,headers={},body=None)
    def assertCode(self,code,fn):
        with self.assertRaises(TransportError) as err: fn()
        self.assertEqual(err.exception.code,code)
    def test_private_and_mixed_dns_denied(self):
        for addresses in [['127.0.0.1'],['169.254.169.254'],['::1'],['8.8.8.8','10.0.0.1']]:
            entries=addresses
            with patch('credential_broker.executor._lookup_addresses',return_value=entries):
                self.assertCode('DESTINATION_DENIED',self.request)
    def test_https_and_credentials_required(self):
        for url in ['http://example.com','https://a:b@example.com','https://example.com:444/','https://example.com/#secret']:
            self.assertCode('DESTINATION_DENIED',lambda:self.request(url))
    def test_public_connection_pinned_and_closed(self):
        conn=Connection()
        with patch('credential_broker.executor._lookup_addresses',return_value=['8.8.8.8']),patch('credential_broker.executor._PinnedHTTPS',return_value=conn) as factory:
            self.assertEqual(self.request(),(200,b'{"state":"ok"}'))
            self.assertEqual(factory.call_args.args[:3],('example.com',443,'8.8.8.8'))
            self.assertTrue(conn.closed)
    def test_redirect_and_unauthorized_no_retry(self):
        for status in [301,302,401,403,500]:
            conn=Connection();conn.response.status=status
            with patch('credential_broker.executor._lookup_addresses',return_value=['8.8.8.8']),patch('credential_broker.executor._PinnedHTTPS',return_value=conn) as factory:
                self.assertCode('UPSTREAM_REJECTED',self.request)
                self.assertEqual(factory.call_count,1)
                self.assertTrue(conn.closed)
    def test_dns_timeout_process_is_reaped_and_slots_recover(self):
        import subprocess
        import sys
        original = subprocess.Popen
        children=[]
        def stalled(*args, **kwargs):
            child=original([sys.executable,'-I','-c','import time; time.sleep(10)'], **kwargs)
            children.append(child)
            return child
        started=time.monotonic()
        with patch('credential_broker.executor.subprocess.Popen', side_effect=stalled):
            for _ in range(3):
                self.assertCode('UPSTREAM_TIMEOUT',lambda:secure_request(method='GET',url='https://example.com',headers={},body=None,timeout=.03))
        self.assertLess(time.monotonic()-started,1)
        self.assertTrue(all(child.poll() is not None for child in children))
        self.assertEqual(len(children),3)
    def test_cached_tls_context_validates_certificates_and_hostname(self):
        import ssl
        from credential_broker.executor import _tls_context
        context=_tls_context()
        self.assertIs(context,_tls_context())
        self.assertEqual(context.verify_mode,ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
    def test_header_and_body_deadline_interrupt_transport(self):
        for phase in ('headers','body'):
            event=threading.Event()
            class Slow(Connection):
                def abort(self): event.set()
                def getresponse(self):
                    if phase=='headers': event.wait(1)
                    return self.response
            conn=Slow()
            if phase=='body':
                def slow_read(size): event.wait(1); return b'x'
                conn.response.read1=slow_read
            start=time.monotonic()
            with patch('credential_broker.executor._lookup_addresses',return_value=['8.8.8.8']),patch('credential_broker.executor._PinnedHTTPS',return_value=conn):
                self.assertCode('UPSTREAM_TIMEOUT',lambda:secure_request(method='GET',url='https://example.com',headers={},body=None,timeout=.03))
            self.assertLess(time.monotonic()-start,.5)
            self.assertTrue(conn.closed)
    def test_size_and_errors_safe(self):
        conn=Connection();conn.response.chunks=[b'x'*131073]
        with patch('credential_broker.executor._lookup_addresses',return_value=['8.8.8.8']),patch('credential_broker.executor._PinnedHTTPS',return_value=conn):
            self.assertCode('RESPONSE_TOO_LARGE',self.request)
        with patch('credential_broker.executor._lookup_addresses',side_effect=OSError('SECRET')):
            self.assertCode('UPSTREAM_FAILED',self.request)
if __name__=='__main__': unittest.main()
