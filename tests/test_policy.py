import base64
import copy
import json
import unittest
from credential_broker.policy import ActionBroker, PolicyError

SECRET = b'super-private-fixture-value'
class Vault:
    def __init__(self): self.calls = 0
    def use(self, ref, callback):
        self.calls += 1
        assert ref == 'fixture'
        return callback(SECRET)

def action(**extra):
    data = {'id':'status','credentialRef':'fixture','method':'GET','url':'https://example.com/v1/status?q={q}', 'inputSchema':{'type':'object','properties':{'q':{'type':'string','maxLength':80}},'required':['q']}, 'effect':'read','responseFields':['state'],'auth':'bearer','outputSchema':{'type':'object','properties':{'state':{'type':'string','maxLength':100,'enum':['ready','ok']}},'required':['state'],'additionalProperties':False}}
    data.update(extra)
    return data

class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.now = 1
        self.vault = Vault()
        self.calls, self.audit = [], []
        self.response = b'{"state":"ready","token":"hidden"}'
        def executor(**kwargs):
            self.calls.append(kwargs)
            return 200, self.response
        self.broker = ActionBroker(self.vault,[action()],1000,clock=lambda:self.now,executor=executor,audit=self.audit.append)
    def plan(self, broker=None, **kwargs):
        return (broker or self.broker).plan(1000, {'action':'status','input':{'q':'hello /&?'},**kwargs})
    def run_plan(self, broker=None):
        broker = broker or self.broker
        return broker.execute(1000,{'planId':self.plan(broker)['planId']})
    def assertCode(self, code, fn):
        with self.assertRaises(PolicyError) as err: fn()
        self.assertEqual(err.exception.code, code)
    def test_read_is_secretless_allowlisted_and_single_use(self):
        plan = self.plan()
        self.assertNotIn(SECRET.decode(),json.dumps(plan))
        self.assertEqual(self.broker.execute(1000,{'planId':plan['planId']}),{'ok':True,'output':{'state':'ready'}})
        self.assertEqual(self.calls[0]['url'],'https://example.com/v1/status?q=hello%20%2F%26%3F')
        self.assertEqual(self.calls[0]['headers']['Authorization'],'Bearer '+SECRET.decode())
        self.assertCode('PLAN_INVALID',lambda:self.broker.execute(1000,{'planId':plan['planId']}))
        self.assertNotIn(SECRET.decode(),json.dumps(self.audit))
        self.assertNotIn('fixture',json.dumps(self.audit))
    def test_wrong_uid_and_unknown_fields(self):
        plan = self.plan()
        self.assertCode('PRINCIPAL_DENIED',lambda:self.broker.execute(9,{'planId':plan['planId']}))
        self.assertCode('INVALID_REQUEST',lambda:self.plan(url='https://evil.test'))
        self.assertCode('CREDENTIAL_DENIED',lambda:self.plan(credentialRef='other'))
        self.assertCode('INVALID_INPUT',lambda:self.broker.plan(1000,{'action':'status','input':{'q':'a','headers':{}}}))
    def test_expiry_and_invalidation(self):
        plan = self.plan(); self.now = 62
        self.assertCode('PLAN_INVALID',lambda:self.broker.execute(1000,{'planId':plan['planId']}))
        plan = self.plan(); self.broker.invalidate_session()
        self.assertCode('PLAN_INVALID',lambda:self.broker.execute(1000,{'planId':plan['planId']}))
    def test_read_budget_and_no_retry(self):
        self.broker.session_budget=1
        self.run_plan()
        self.assertCode('REQUEST_BUDGET_EXCEEDED',self.run_plan)
        self.assertEqual(len(self.calls),1)
    def test_credential_hour_budget(self):
        self.broker.actions['status']['maxRequestsPerHour']=1
        self.run_plan()
        self.assertCode('REQUEST_BUDGET_EXCEEDED',self.run_plan)
        self.now+=3601
        self.run_plan()
    def test_write_host_approval_and_ttl_recheck(self):
        config=action(method='POST',effect='write',url='https://example.com/v1/status')
        denied=ActionBroker(self.vault,[config],1000,executor=lambda **k:(200,b'{"state":"ok"}'))
        self.assertCode('APPROVAL_REQUIRED',lambda:self.run_plan(denied))
        approved=[]
        def approve(plan): approved.append(plan); return True
        broker=ActionBroker(self.vault,[config],1000,approve_host=approve,audit=lambda _:None,executor=lambda **k:(200,b'{"state":"ok"}'))
        self.assertEqual(self.run_plan(broker)['output']['state'],'ok')
        self.assertEqual(approved[0]['input'],{'q':'hello /&?'})
        def slow(plan): self.now+=61; return True
        broker=ActionBroker(self.vault,[config],1000,approve_host=slow,clock=lambda:self.now)
        self.assertCode('PLAN_EXPIRED',lambda:self.run_plan(broker))
    def test_invalidate_during_approval(self):
        config=action(method='POST',effect='write')
        broker=None
        def approve(plan): broker.invalidate_session(); return True
        broker=ActionBroker(self.vault,[config],1000,approve_host=approve)
        self.assertCode('PLAN_EXPIRED',lambda:self.run_plan(broker))
    def test_response_cannot_echo_secret_plain_base64_urlencoded(self):
        from urllib.parse import quote
        for variant in [SECRET.decode(),base64.b64encode(SECRET).decode(),quote(SECRET.decode(),safe='')]:
            self.response=json.dumps({'state':'echo '+variant}).encode()
            self.assertCode('RESPONSE_DENIED',self.run_plan)
    def test_response_nested_large_and_unexpected_status(self):
        for response,code in [(b'{"state":{}}','RESPONSE_DENIED'),(json.dumps({'state':'x'*5000}).encode(),'RESPONSE_DENIED'),(b'invalid','UPSTREAM_FAILED')]:
            self.response=response
            self.assertCode(code,self.run_plan)
    def test_schema_boolean_not_integer(self):
        config=action(inputSchema={'type':'object','properties':{'q':{'type':'integer','minimum':0,'maximum':2}}})
        broker=ActionBroker(self.vault,[config],1000)
        for value in [True,3,-1,'1']:
            self.assertCode('INVALID_INPUT',lambda:broker.plan(1000,{'action':'status','input':{'q':value}}))
    def test_write_audit_fail_closed_before_secret_or_network(self):
        config=action(method='POST',effect='write')
        for audit in [None,lambda _: (_ for _ in ()).throw(OSError('private-error'))]:
            broker=ActionBroker(self.vault,[config],1000,approve_host=lambda _:True,audit=audit,executor=self.broker.executor)
            self.assertCode('AUDIT_UNAVAILABLE',lambda:self.run_plan(broker))
        self.assertEqual(self.vault.calls,0)
        self.assertEqual(self.calls,[])
    def test_write_post_audit_failure_is_uncertain_no_replay(self):
        config=action(method='POST',effect='write')
        events=[]
        def audit(event):
            events.append(event)
            if event['event']=='outcome': raise OSError('private-error')
        broker=ActionBroker(self.vault,[config],1000,approve_host=lambda _:True,audit=audit,executor=self.broker.executor)
        plan=self.plan(broker)
        self.assertCode('OUTCOME_UNCERTAIN',lambda:broker.execute(1000,{'planId':plan['planId']}))
        self.assertCode('PLAN_INVALID',lambda:broker.execute(1000,{'planId':plan['planId']}))
        self.assertEqual(len(self.calls),1)
        self.assertEqual(events[0]['event'],'intent')
    def test_write_timeout_is_uncertain_never_retried(self):
        from credential_broker.executor import TransportError
        calls=[]
        def timeout(**kwargs): calls.append(kwargs); raise TransportError('UPSTREAM_TIMEOUT')
        broker=ActionBroker(self.vault,[action(method='POST',effect='write')],1000,approve_host=lambda _:True,audit=lambda _:None,executor=timeout)
        self.assertCode('OUTCOME_UNCERTAIN',lambda:self.run_plan(broker))
        self.assertEqual(len(calls),1)
    def test_revoke_during_audit_prevents_network(self):
        config=action(method='POST',effect='write')
        broker=None
        def audit(event):
            if event['event']=='intent': broker.invalidate_session()
        broker=ActionBroker(self.vault,[config],1000,approve_host=lambda _:True,audit=audit,executor=self.broker.executor)
        self.assertCode('PLAN_EXPIRED',lambda:self.run_plan(broker))
        self.assertEqual(self.calls,[])
    def test_output_schema_enum_pattern_required_and_types(self):
        self.response=b'{"state":"unexpected"}'
        self.assertCode('RESPONSE_DENIED',self.run_plan)
        self.response=b'{}'
        self.assertCode('RESPONSE_DENIED',self.run_plan)
        config=action(outputSchema={'type':'object','properties':{'state':{'type':'string','maxLength':100,'pattern':'^[A-Za-z0-9_-]{1,100}$'}},'required':['state']})
        broker=ActionBroker(self.vault,[config],1000,executor=self.broker.executor)
        self.response=json.dumps({'state':SECRET.decode()}).encode()
        self.assertCode('RESPONSE_DENIED',lambda:self.run_plan(broker))
        self.response=b'{"state":"valid_id"}'
        self.assertEqual(self.run_plan(broker)['output']['state'],'valid_id')
    def test_bad_catalogs(self):
        for config in [action(url='http://example.com'),action(url='https://{q}.example.com'),action(url='https://example.com/{q}'),action(responseFields=['access_token']),action(method='POST'),action(url='https://example.com:8443'),action(headers={'Authorization':'oops'}),action(outputSchema=None),action(outputSchema={'type':'object','properties':{'state':{'type':'string','maxLength':100}}}),action(outputSchema={'type':'object','properties':{'state':{'type':'string','maxLength':100,'pattern':'(a+)+$'}}})]:
            self.assertCode('INVALID_CATALOG',lambda:ActionBroker(self.vault,[config],1000))
    def test_request_size_and_plan_budget(self):
        self.broker.actions['status']['inputSchema']['properties']['q']['maxLength']=10000
        self.assertCode('INVALID_INPUT',lambda:self.broker.plan(1000,{'action':'status','input':{'q':'x'*1025}}))
        for _ in range(128): self.plan()
        self.assertCode('PLAN_BUDGET_EXCEEDED',self.plan)
    def test_exception_text_is_never_forwarded(self):
        def bad(**kwargs): raise ValueError(SECRET.decode())
        self.broker.executor=bad
        self.assertCode('UPSTREAM_FAILED',self.run_plan)
        self.assertNotIn(SECRET.decode(),json.dumps(self.audit))

if __name__=='__main__': unittest.main()
