import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createEVM} from '@ethereumjs/evm';
import {Common,Hardfork,Mainnet} from '@ethereumjs/common';
import {Account,createAddressFromString,hexToBytes,bytesToHex} from '@ethereumjs/util';
import {compile} from './compiler.mjs';
const {contract}=await compile();
const word=value=>typeof value==='bigint'?value.toString(16).padStart(64,'0'):value.replace(/^0x/,'').padStart(64,'0');
const ZERO='0x'+'0'.repeat(64),PRODUCER='0x'+'a'.repeat(64),SCOPE='0x'+'b'.repeat(64);
const publisher=createAddressFromString('0x0000000000000000000000000000000000000011');
const stranger=createAddressFromString('0x0000000000000000000000000000000000000022');
const hash=value=>'0x'+createHash('sha256').update(String(value)).digest('hex');
async function fixture(){
  const evm=await createEVM({common:new Common({chain:Mainnet,hardfork:Hardfork.Prague})});
  await evm.stateManager.putAccount(publisher,new Account(0n,0n));
  await evm.stateManager.putAccount(stranger,new Account(0n,0n));
  const result=await evm.runCall({caller:publisher,gasLimit:5_000_000n,data:hexToBytes('0x'+contract.evm.bytecode.object+word(publisher.toString())+word(PRODUCER)+word(SCOPE))});
  assert.equal(result.execResult.exceptionError,undefined);assert.ok(result.createdAddress);
  const address=result.createdAddress;
  async function call(signature,args=[],caller=publisher){
    const selector=contract.evm.methodIdentifiers[signature];assert.ok(selector);
    return evm.runCall({caller,to:address,gasLimit:300_000n,data:hexToBytes('0x'+selector+args.map(word).join(''))});
  }
  const read=async(signature,args=[])=>{const result=await call(signature,args);assert.equal(result.execResult.exceptionError,undefined);return bytesToHex(result.execResult.returnValue);};
  const domain=await read('domain()');
  const append=(sequence,digest,{caller=publisher,scope=domain,producer=PRODUCER,previous=ZERO}={})=>call('append(bytes32,bytes32,uint64,bytes32,bytes32)',[scope,producer,sequence,previous,digest],caller);
  return {evm,address,call,read,domain,append};
}
test('compiled bytecode records a checkpoint and preserves historical digests',async()=>{
  const f=await fixture(),one=hash('synthetic-one'),two=hash('synthetic-two');
  assert.equal((await f.append(10n,one)).execResult.exceptionError,undefined);
  assert.equal((await f.append(20n,two,{previous:one})).execResult.exceptionError,undefined);
  assert.equal(await f.read('lastSequence()'),'0x'+word(20n));assert.equal(await f.read('lastDigest()'),two);
  assert.equal(await f.read('digestAt(uint64)',[10n]),one);
});
test('unauthorized caller, wrong domain/producer and stale predecessor revert without changing state',async()=>{
  const f=await fixture(),digest=hash('synthetic');
  for(const options of [{caller:stranger},{scope:hash('other-deployment')},{producer:hash('other-producer')},{previous:hash('stale')}]){
    assert.ok((await f.append(1n,digest,options)).execResult.exceptionError);
    assert.equal(await f.read('lastSequence()'),'0x'+word(0n));assert.equal(await f.read('lastDigest()'),ZERO);
  }
});
test('duplicates, backwards sequence and zero digest revert; a sequence gap is intentionally allowed',async()=>{
  const f=await fixture(),digest=hash('first');
  assert.ok((await f.append(0n,digest)).execResult.exceptionError);assert.ok((await f.append(1n,ZERO)).execResult.exceptionError);
  assert.equal((await f.append(100n,digest)).execResult.exceptionError,undefined);
  for(const sequence of [99n,100n])assert.ok((await f.append(sequence,hash(sequence),{previous:digest})).execResult.exceptionError);
  assert.equal(await f.read('digestAt(uint64)',[100n]),digest);
});
test('bounded randomized EVM campaign preserves state for rejected requests and every prior accepted digest',async t=>{
  const f=await fixture(),history=new Map();let sequence=0n,last=ZERO,seed=0x4123,accepted=0,rejected=0;
  for(let i=0;i<256;i++){
    seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;const choice=(seed>>>0)%6,digest=hash(`synthetic-${i}`);
    const next=choice===0?sequence:sequence+BigInt(1+(seed>>>0)%100),options={previous:last};
    if(choice===1)options.caller=stranger;if(choice===2)options.scope=hash('wrong-domain');if(choice===3)options.previous=ZERO;
    const shouldAccept=next>sequence&&choice!==1&&choice!==2&&!(choice===3&&last!==ZERO);
    const result=await f.append(next,digest,options);
    assert.equal(!result.execResult.exceptionError,shouldAccept);
    if(shouldAccept){accepted++;sequence=next;last=digest;history.set(sequence,digest);}else rejected++;
    assert.equal(await f.read('lastSequence()'),'0x'+word(sequence));assert.equal(await f.read('lastDigest()'),last);
  }
  assert.ok(accepted>20&&rejected>20);
  t.diagnostic(JSON.stringify({seed:'0x4123',calls:256,accepted,rejected,executed:'compiled EVM bytecode; not a formal proof'}));
  for(const [sequence,digest] of history)assert.equal(await f.read('digestAt(uint64)',[sequence]),digest);
});
test('publisher can anchor invented contents: the registry cannot attest off-chain truth',async()=>{
  const f=await fixture();assert.equal((await f.append(999n,hash('invented audit, no real events'))).execResult.exceptionError,undefined);
});

test('constructor rejects zero publisher, producer and scope',async()=>{
  const f=await fixture();
  for(const [writer,producer,scope] of [[ZERO,PRODUCER,SCOPE],[publisher.toString(),ZERO,SCOPE],[publisher.toString(),PRODUCER,ZERO]]){
    const result=await f.evm.runCall({caller:publisher,gasLimit:5_000_000n,data:hexToBytes('0x'+contract.evm.bytecode.object+word(writer)+word(producer)+word(scope))});
    assert.ok(result.execResult.exceptionError);
  }
});
test('uint64 boundary and malformed ABI fail without overwriting the last checkpoint',async()=>{
  const f=await fixture(),maximum=(1n<<64n)-1n,digest=hash('maximum');
  assert.equal((await f.append(maximum,digest)).execResult.exceptionError,undefined);
  assert.ok((await f.append(maximum+1n,hash('overflow'),{previous:digest})).execResult.exceptionError);
  const selector=contract.evm.methodIdentifiers['append(bytes32,bytes32,uint64,bytes32,bytes32)'];
  const malformed=await f.evm.runCall({caller:publisher,to:f.address,gasLimit:300_000n,data:hexToBytes('0x'+selector)});
  assert.ok(malformed.execResult.exceptionError);
  assert.equal(await f.read('lastSequence()'),'0x'+word(maximum));assert.equal(await f.read('lastDigest()'),digest);
});
test('a commitment domain from one deployment is rejected by another deployment',async()=>{
  const f=await fixture();
  const second=await f.evm.runCall({caller:publisher,gasLimit:5_000_000n,data:hexToBytes('0x'+contract.evm.bytecode.object+word(publisher.toString())+word(PRODUCER)+word(SCOPE))});
  assert.equal(second.execResult.exceptionError,undefined);
  const result=await f.evm.runCall({caller:publisher,to:second.createdAddress,gasLimit:300_000n,
    data:hexToBytes('0x'+contract.evm.methodIdentifiers['append(bytes32,bytes32,uint64,bytes32,bytes32)']+[f.domain,PRODUCER,1n,ZERO,hash('cross-deployment')].map(word).join(''))});
  assert.ok(result.execResult.exceptionError);
});
