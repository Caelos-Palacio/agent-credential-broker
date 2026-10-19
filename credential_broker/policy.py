"""Host-owned action catalog, single-use plans and secretless execution."""
import base64
import copy
import datetime
import hashlib
import json
import math
import re
import secrets
import threading
import time
from urllib.parse import quote, urlsplit
from .executor import secure_request, TransportError
from .governance import GovernanceError
from .vault import Vault, VaultError

class PolicyError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)

_SENSITIVE = re.compile(r'password|passwd|secret|token|authorization|cookie|api.?key|credential', re.I)
_FIELD = re.compile(r'^[A-Za-z][A-Za-z0-9_]{0,63}$')
_ALIAS = re.compile(r'^[A-Za-z0-9_-]{1,128}$')

def _json_size(value):
    try:
        return len(json.dumps(value, allow_nan=False, separators=(',', ':'), ensure_ascii=False).encode())
    except Exception:
        raise PolicyError('INVALID_REQUEST') from None

def _input(schema, value):
    if not isinstance(value, dict) or schema.get('type') != 'object':
        raise PolicyError('INVALID_INPUT')
    props = schema.get('properties', {})
    if set(value) - set(props) or set(schema.get('required', [])) - set(value):
        raise PolicyError('INVALID_INPUT')
    for key, item in value.items():
        rule = props[key]
        kind = rule.get('type')
        valid = ((kind == 'string' and isinstance(item, str) and len(item) <= min(rule.get('maxLength', 1024), 1024)) or
                 (kind == 'integer' and type(item) is int and abs(item) <= 2**53 - 1) or
                 (kind == 'boolean' and type(item) is bool))
        if not valid or ('enum' in rule and item not in rule['enum']):
            raise PolicyError('INVALID_INPUT')
        if kind == 'integer' and (item < rule.get('minimum', -(2**53-1)) or item > rule.get('maximum', 2**53-1)):
            raise PolicyError('INVALID_INPUT')
    if _json_size(value) > 4096:
        raise PolicyError('REQUEST_TOO_LARGE')
    return copy.deepcopy(value)

class ActionBroker:
    def __init__(self, vault, actions, allowed_uid, approve_host=None, clock=None, executor=None, audit=None, session_budget=100, task_grant=None, quota_store=None):
        self.vault, self.allowed_uid = vault, allowed_uid
        self.approve_host = approve_host
        self.clock = clock or time.monotonic
        self.executor, self.audit = executor or secure_request, audit
        self.session_budget = max(1, min(session_budget, 10000))
        self.lock = threading.RLock()
        self.plans, self.usage, self.count = {}, {}, 0
        self.generation = 0
        self.task_grant, self.quota_store = task_grant, quota_store
        self.credential_versions = {}
        self.actions = {}
        items = actions.values() if isinstance(actions, dict) else actions
        for raw in items:
            action = copy.deepcopy(raw)
            self._validate_action(action)
            if action['id'] in self.actions:
                raise PolicyError('INVALID_CATALOG')
            self.actions[action['id']] = action

    def _validate_action(self, action):
        try:
            if set(action) - {'id','credentialRef','method','url','inputSchema','effect','responseFields','auth','maxRequestsPerHour','bodyFields','outputSchema'}:
                raise ValueError()
            if not _FIELD.fullmatch(action['id']) or not _ALIAS.fullmatch(action['credentialRef']):
                raise ValueError()
            if action['method'] not in ('GET','POST','PUT','PATCH','DELETE') or action['effect'] not in ('read','write'):
                raise ValueError()
            if action['effect'] == 'read' and action['method'] != 'GET':
                raise ValueError()
            if action.get('auth', 'bearer') not in ('bearer','basic'):
                raise ValueError()
            p = urlsplit(action['url'])
            if p.scheme != 'https' or not p.hostname or p.username or p.password or p.fragment or (p.port and p.port != 443):
                raise ValueError()
            # Only query values may vary: endpoint host, port and path are host-owned.
            if '{' in p.netloc + p.path or '}' in p.netloc + p.path or '..' in p.path or '\\' in p.path:
                raise ValueError()
            props = action['inputSchema'].get('properties', {})
            if action['inputSchema'].get('type') != 'object' or not isinstance(props, dict) or len(props)>32 or set(action['inputSchema']) - {'type','properties','required','additionalProperties'} or action['inputSchema'].get('additionalProperties',False) is not False:
                raise ValueError()
            if any(not _FIELD.fullmatch(k) or _SENSITIVE.search(k) or r.get('type') not in ('string','integer','boolean') for k,r in props.items()):
                raise ValueError()
            for name, rule in props.items():
                if set(rule) - {'type','enum','maxLength','minimum','maximum','description'}:
                    raise ValueError()
                if 'maxLength' in rule and (type(rule['maxLength']) is not int or not 0 <= rule['maxLength'] <= 1024):
                    raise ValueError()
                for bound in ('minimum','maximum'):
                    if bound in rule and (rule['type'] != 'integer' or type(rule[bound]) is not int or abs(rule[bound]) > 2**53-1):
                        raise ValueError()
                if rule.get('minimum',0) > rule.get('maximum',2**53-1):
                    raise ValueError()
                if 'enum' in rule:
                    if not isinstance(rule['enum'],list) or not 1 <= len(rule['enum']) <= 64:
                        raise ValueError()
                    for item in rule['enum']:
                        _input({'type':'object','properties':{name:{k:v for k,v in rule.items() if k!='enum'}}}, {name:item})
                if 'description' in rule and (not isinstance(rule['description'],str) or len(rule['description'])>500):
                    raise ValueError()
            if not isinstance(action['inputSchema'].get('required',[]),list) or set(action['inputSchema'].get('required', [])) - set(props):
                raise ValueError()
            if not isinstance(action['responseFields'],list) or len(action['responseFields'])>32 or any(not _FIELD.fullmatch(f) or _SENSITIVE.search(f) for f in action['responseFields']):
                raise ValueError()
            placeholders = re.findall(r'\{([^{}]+)\}', p.query)
            if set(placeholders) - set(props) or re.sub(r'\{[^{}]+\}', '', p.query).count('{'):
                raise ValueError()
            if set(action.get('bodyFields', props if action['method'] != 'GET' else [])) - set(props):
                raise ValueError()
            output = action.get('outputSchema')
            if output is None:
                raise ValueError()
            if output is not None:
                if set(output) - {'type','properties','required','additionalProperties'} or output.get('type')!='object' or output.get('additionalProperties',False) is not False:
                    raise ValueError()
                if set(output.get('properties',{})) != set(action['responseFields']) or set(output.get('required',[]))-set(action['responseFields']):
                    raise ValueError()
                for rule in output['properties'].values():
                    if set(rule)-{'type','enum','maxLength','pattern','minimum','maximum'} or rule.get('type') not in ('string','integer','number','boolean','null'):
                        raise ValueError()
                    if rule['type']=='string' and (type(rule.get('maxLength',1024)) is not int or not 0<=rule.get('maxLength',1024)<=1024):
                        raise ValueError()
                    if rule['type']=='string' and ('maxLength' not in rule or not ('enum' in rule or 'pattern' in rule)):
                        raise ValueError()
                    if 'pattern' in rule:
                        if not isinstance(rule['pattern'],str) or len(rule['pattern'])>128 or re.search(r'[^A-Za-z0-9_\^\$\[\]\-\.\+\*\?\{\},]',rule['pattern']):
                            raise ValueError()
                        # Only simple character-class repetition patterns, no nested quantifiers/backtracking groups.
                        if not re.fullmatch(r'\^?\[[A-Za-z0-9_\-]+\](?:[+*?]|\{[0-9]+(?:,[0-9]*)?\})?\$?',rule['pattern']):
                            raise ValueError()
                        if not (rule['pattern'].startswith('^') and rule['pattern'].endswith('$')):
                            raise ValueError()
                        re.compile(rule['pattern'])
                    if 'enum' in rule and (not isinstance(rule['enum'],list) or not 1<=len(rule['enum'])<=64 or _json_size(rule['enum'])>4096):
                        raise ValueError()
                    for bound in ('minimum','maximum'):
                        if bound in rule and (rule['type'] not in ('integer','number') or type(rule[bound]) not in (int,float) or not math.isfinite(rule[bound])):
                            raise ValueError()
                    if rule.get('minimum',-float('inf'))>rule.get('maximum',float('inf')):
                        raise ValueError()
            if type(action.get('maxRequestsPerHour',60)) is not int or not 1 <= action.get('maxRequestsPerHour', 60) <= 10000:
                raise ValueError()
        except Exception:
            raise PolicyError('INVALID_CATALOG') from None

    def _uid(self, uid):
        if type(uid) is not int or uid != self.allowed_uid:
            raise PolicyError('PRINCIPAL_DENIED')

    def plan(self, principal_uid, request):
        self._uid(principal_uid)
        if not isinstance(request, dict) or set(request) - {'action','input','credentialRef'}:
            raise PolicyError('INVALID_REQUEST')
        action = self.actions.get(request.get('action'))
        if not action:
            raise PolicyError('ACTION_DENIED')
        if request.get('credentialRef', action['credentialRef']) != action['credentialRef']:
            raise PolicyError('CREDENTIAL_DENIED')
        value = _input(action['inputSchema'], request.get('input', {}))
        self._grant(principal_uid, action, value)
        url = action['url']
        for key in re.findall(r'\{([^{}]+)\}', url):
            if key not in value:
                raise PolicyError('INVALID_INPUT')
            url = url.replace('{' + key + '}', quote(str(value[key]), safe=''))
        fields = action.get('bodyFields', list(action['inputSchema']['properties']))
        body = None if action['method'] == 'GET' else json.dumps({k:value[k] for k in fields if k in value}, allow_nan=False, separators=(',', ':')).encode()
        if len(url.encode()) + len(body or b'') > 4096:
            raise PolicyError('REQUEST_TOO_LARGE')
        with self.lock:
            now = self.clock()
            self.plans = {k:v for k,v in self.plans.items() if v['expires'] > now}
            if len(self.plans) >= 128:
                raise PolicyError('PLAN_BUDGET_EXCEEDED')
            plan_id = secrets.token_urlsafe(32)
            plan_grant = self.task_grant
            record = {'action': action, 'input': value, 'url': url, 'body': body, 'uid': principal_uid, 'expires': now + 60, 'generation': self.generation,
                      'credentialVersion': self._version(action['credentialRef']),
                      'grantId': plan_grant.id if plan_grant else None, 'grantObject': plan_grant}
            self.plans[plan_id] = record
        return {'planId': plan_id, 'action': action['id'], 'effect': action['effect'], 'method': action['method'], 'destination': url, 'input': value, 'expiresInSeconds':60, 'requiresApproval':action['effect']=='write'}

    def capabilities(self):
        return [{
            'id':action['id'], 'effect':action['effect'], 'method':action['method'],
            'inputSchema':copy.deepcopy(action['inputSchema']),
            'responseFields':list(action['responseFields']),
            **({'outputSchema':copy.deepcopy(action['outputSchema'])} if 'outputSchema' in action else {}),
            'requiresApproval':action['effect']=='write'
        } for action in self.actions.values() if not self.task_grant or action['id'] in self.task_grant.document['actions']]

    def _grant(self, uid, action, value):
        if self.task_grant:
            try:
                self.task_grant.check(uid, action['id'], value)
            except GovernanceError as exc:
                raise PolicyError(str(exc)) from None

    def revoke_credential(self, alias):
        """Trusted custodian only; never exposed by the agent transport."""
        with self.lock:
            self.credential_versions[alias] = self.credential_versions.get(alias, 0) + 1
            self.plans = {key: plan for key, plan in self.plans.items() if plan['action']['credentialRef'] != alias}
            self.vault.remove(alias)

    def _version(self, alias):
        try:
            return (self.credential_versions.get(alias, 0),
                    self.vault.version(alias) if isinstance(self.vault, Vault) else None)
        except VaultError:
            raise PolicyError('CREDENTIAL_UNAVAILABLE') from None

    def invalidate_session(self):
        with self.lock:
            self.plans.clear()
            self.generation += 1

    def _emit(self, event, action, uid, status, start, mandatory=False, execution_id=None):
        if not self.audit:
            if mandatory:
                raise PolicyError('AUDIT_UNAVAILABLE')
            return
        try:
            self.audit({'event':event, 'actionIdHash':hashlib.sha256(action['id'].encode()).hexdigest()[:16], 'uid':uid, 'status':status, 'durationMs':max(0, int((self.clock()-start)*1000)),
                        'executionId': execution_id or secrets.token_hex(32),
                        'occurredAtUTC': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')})
        except Exception:
            if mandatory:
                raise PolicyError('AUDIT_UNAVAILABLE') from None

    def _output(self, action, field, value):
        schema = action.get('outputSchema')
        if not schema:
            if value is not None and type(value) not in (str,int,bool,float):
                raise PolicyError('RESPONSE_DENIED')
            if isinstance(value,str) and len(value)>1024:
                raise PolicyError('RESPONSE_DENIED')
            return
        rule = schema['properties'][field]
        kind = rule['type']
        valid = ((kind=='string' and type(value) is str and len(value)<=rule.get('maxLength',1024)) or
                 (kind=='integer' and type(value) is int and abs(value)<=2**53-1) or
                 (kind=='number' and type(value) in (int,float) and math.isfinite(value)) or
                 (kind=='boolean' and type(value) is bool) or
                 (kind=='null' and value is None))
        if not valid or ('enum' in rule and value not in rule['enum']):
            raise PolicyError('RESPONSE_DENIED')
        if kind in ('integer','number') and (value<rule.get('minimum',-float('inf')) or value>rule.get('maximum',float('inf'))):
            raise PolicyError('RESPONSE_DENIED')
        if 'pattern' in rule and (type(value) is not str or not re.fullmatch(rule['pattern'],value)):
            raise PolicyError('RESPONSE_DENIED')

    def execute(self, principal_uid, request):
        self._uid(principal_uid)
        if not isinstance(request, dict) or set(request) != {'planId'} or not isinstance(request['planId'], str):
            raise PolicyError('INVALID_REQUEST')
        with self.lock:
            plan = self.plans.pop(request['planId'], None)
            if not plan or plan['uid'] != principal_uid or self.clock() >= plan['expires']:
                raise PolicyError('PLAN_INVALID')
        action, start, status = plan['action'], self.clock(), 'denied'
        execution_id = secrets.token_hex(32)
        sent = False
        try:
            self._grant(principal_uid, action, plan['input'])
            if (plan['grantObject'] is not self.task_grant
                    or plan['grantId'] != (self.task_grant.id if self.task_grant else None)):
                raise PolicyError('GRANT_CHANGED')
            if action['effect'] == 'write':
                review = {'action':action['id'], 'method':action['method'], 'destination':plan['url'], 'input':copy.deepcopy(plan['input'])}
                if not self.approve_host or self.approve_host(review) is not True:
                    raise PolicyError('APPROVAL_REQUIRED')
            with self.lock:
                if self.clock() >= plan['expires'] or plan['generation'] != self.generation:
                    raise PolicyError('PLAN_EXPIRED')
                # Human approval may overlap host authority updates. An old plan
                # must never reserve an attempt against a replacement grant.
                reservation_grant = self.task_grant
                if (plan['grantObject'] is not reservation_grant
                        or plan['grantId'] != (reservation_grant.id if reservation_grant else None)):
                    raise PolicyError('GRANT_CHANGED')
                if plan['credentialVersion'] != self._version(action['credentialRef']):
                    raise PolicyError('CREDENTIAL_REVOKED')
                if reservation_grant:
                    try:
                        reservation_grant.check(principal_uid, action['id'], plan['input'])
                    except GovernanceError as exc:
                        raise PolicyError(str(exc)) from None
                now = self.clock()
                ref = action['credentialRef']
                times = [t for t in self.usage.get(ref, []) if now-t < 3600]
                if self.count >= self.session_budget or len(times) >= action.get('maxRequestsPerHour',60):
                    raise PolicyError('REQUEST_BUDGET_EXCEEDED')
                self.usage[ref] = times + [now]
                self.count += 1
                if reservation_grant:
                    if not self.quota_store:
                        raise PolicyError('QUOTA_UNAVAILABLE')
                    try:
                        self.quota_store.consume(reservation_grant, ref, action.get('maxRequestsPerHour', 60))
                    except GovernanceError as exc:
                        raise PolicyError(str(exc)) from None
            if action['effect']=='write':
                self._emit('intent', action, principal_uid, 'intent', start, mandatory=True, execution_id=execution_id)
            # Audit I/O and human approval can consume TTL or overlap revocation.
            with self.lock:
                if (self.clock()>=plan['expires'] or plan['generation']!=self.generation
                        or plan['grantObject'] is not self.task_grant
                        or plan['grantId'] != (self.task_grant.id if self.task_grant else None)
                        or plan['credentialVersion'] != self._version(ref)):
                    raise PolicyError('PLAN_EXPIRED')
                self._grant(principal_uid, action, plan['input'])
            def run(secret):
                nonlocal sent
                # Vault callbacks are trusted host code; no callback result carries raw credentials.
                if not isinstance(secret, (bytes,bytearray)) or not secret or len(secret) > 8192:
                    raise PolicyError('CREDENTIAL_UNAVAILABLE')
                raw = bytes(secret)
                try:
                    auth = ('Basic ' + base64.b64encode(raw).decode('ascii')) if action.get('auth','bearer') == 'basic' else ('Bearer ' + raw.decode('ascii'))
                    if '\r' in auth or '\n' in auth:
                        raise PolicyError('CREDENTIAL_UNAVAILABLE')
                    sent = True
                    http_status, data = self.executor(method=action['method'], url=plan['url'], headers={'Authorization':auth,'Accept':'application/json','Content-Type':'application/json'}, body=plan['body'], timeout=10, max_bytes=131072)
                    if not 200 <= http_status < 300 or not isinstance(data, bytes) or len(data)>131072:
                        raise PolicyError('UPSTREAM_REJECTED')
                    decoded = json.loads(data)
                    if not isinstance(decoded, dict):
                        raise PolicyError('RESPONSE_DENIED')
                    if set(action.get('outputSchema',{}).get('required',[]))-set(decoded):
                        raise PolicyError('RESPONSE_DENIED')
                    result = {}
                    variants = {raw, base64.b64encode(raw), quote(raw.decode('utf-8', errors='replace'), safe='').encode()}
                    for field in action['responseFields']:
                        if field not in decoded:
                            continue
                        item = decoded[field]
                        self._output(action, field, item)
                        if item is None or type(item) in (str,int,bool,float):
                            if isinstance(item,float) and not math.isfinite(item):
                                raise PolicyError('RESPONSE_DENIED')
                            encoded = json.dumps(item, ensure_ascii=False).encode()
                            rendered = str(item).encode('utf-8')
                            if any(v and (v in encoded or v in rendered) for v in variants):
                                raise PolicyError('RESPONSE_DENIED')
                            result[field] = item
                        elif field in decoded:
                            raise PolicyError('RESPONSE_DENIED')
                    if _json_size(result)>4096:
                        raise PolicyError('RESPONSE_TOO_LARGE')
                    return result
                except PolicyError:
                    raise
                except TransportError as exc:
                    raise PolicyError(exc.code) from None
                except Exception:
                    raise PolicyError('UPSTREAM_FAILED') from None
            if isinstance(self.vault, Vault):
                output = self.vault.use(ref, run, expected_version=plan['credentialVersion'][1])
            else:
                output = self.vault.use(ref, run)
            with self.lock:
                if (plan['generation'] != self.generation
                        or plan['grantObject'] is not self.task_grant
                        or plan['grantId'] != (self.task_grant.id if self.task_grant else None)):
                    raise PolicyError('AUTHORITY_REVOKED')
                if plan['credentialVersion'] != self._version(ref):
                    raise PolicyError('CREDENTIAL_REVOKED')
                self._grant(principal_uid, action, plan['input'])
            status = 'ok'
            if action['effect']=='write':
                try:
                    self._emit('outcome',action,principal_uid,'ok',start,mandatory=True, execution_id=execution_id)
                except PolicyError:
                    status = 'uncertain'
                    raise PolicyError('OUTCOME_UNCERTAIN') from None
            else:
                self._emit('outcome',action,principal_uid,'ok',start,execution_id=execution_id)
            # Linearize disclosure after potentially blocking audit I/O, without
            # holding this lock during network calls or audit callbacks.
            with self.lock:
                if (plan['generation'] != self.generation
                        or plan['grantObject'] is not self.task_grant
                        or plan['grantId'] != (self.task_grant.id if self.task_grant else None)):
                    raise PolicyError('AUTHORITY_REVOKED')
                if plan['credentialVersion'] != self._version(ref):
                    raise PolicyError('CREDENTIAL_REVOKED')
                self._grant(principal_uid, action, plan['input'])
                return {'ok':True, 'output':output}
        except PolicyError:
            if sent and action['effect']=='write':
                status = 'uncertain'
                raise PolicyError('OUTCOME_UNCERTAIN') from None
            status = 'denied'
            raise
        except Exception:
            if sent and action['effect']=='write':
                status = 'uncertain'
                raise PolicyError('OUTCOME_UNCERTAIN') from None
            raise PolicyError('EXECUTION_FAILED') from None
        finally:
            if status != 'ok':
                self._emit('outcome',action,principal_uid,'uncertain' if sent and action['effect']=='write' else 'denied',start,execution_id=execution_id)
