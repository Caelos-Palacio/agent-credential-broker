import {readFile,open} from 'node:fs/promises';
import {constants} from 'node:fs';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
export const COMPILER=Object.freeze({version:'0.8.37+commit.f401782d',sha256:'5de843c2c93563cc66425c99a4fb13fdbf32b4c4ae07469480faaf126e14404a',
  url:'https://raw.githubusercontent.com/ethereum/solc-bin/gh-pages/linux-amd64/solc-linux-amd64-v0.8.37+commit.f401782d'});
export async function compile({smt=false,binary=process.env.ASSURANCE_SOLC}={}){
  if(!binary)throw new Error('Set ASSURANCE_SOLC to the explicitly downloaded pinned compiler; no automatic download.');
  const executable=await open(binary,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
  const info=await executable.stat();if(!info.isFile()||info.nlink!==1||info.size>32*1024*1024||(info.mode&0o022)||(process.getuid&&![0,process.getuid()].includes(info.uid)))throw new Error('Unsafe pinned compiler file');
  const bytes=Buffer.alloc(info.size+1),{bytesRead}=await executable.read(bytes,0,bytes.length,0);
  if(bytesRead!==info.size||createHash('sha256').update(bytes.subarray(0,bytesRead)).digest('hex')!==COMPILER.sha256)throw new Error('Pinned compiler checksum mismatch; not executed');
  const source=await readFile(new URL('./AuditCheckpoint.sol',import.meta.url),'utf8');
  const settings={optimizer:{enabled:false},evmVersion:'prague',outputSelection:{'*':{'*':['abi','evm.bytecode.object','evm.methodIdentifiers']}}};
  if(smt)settings.modelChecker={engine:'chc',targets:['assert'],showProvedSafe:true,showUnproved:true,timeout:10000};
  const result=spawnSync('/proc/self/fd/3',['--standard-json'],{input:JSON.stringify({language:'Solidity',sources:{'AuditCheckpoint.sol':{content:source}},settings}),encoding:'utf8',stdio:['pipe','pipe','pipe',executable.fd],timeout:20000,maxBuffer:2*1024*1024,env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8'}});
  if(result.error||result.status!==0)throw new Error('Pinned compiler failed; no private inputs were supplied');
  const output=JSON.parse(result.stdout),diagnostics=output.errors??[];
  if(diagnostics.some(item=>item.severity==='error'))throw new Error('Contract compilation failed');
  return {contract:output.contracts['AuditCheckpoint.sol'].AuditCheckpoint,diagnostics};
  }finally{await executable.close();}
}
