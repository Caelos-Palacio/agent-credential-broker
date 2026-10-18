import {compile} from './compiler.mjs';
const {diagnostics}=await compile({smt:true});
const solverUnavailable=diagnostics.some(item=>['8158','7649'].includes(String(item.errorCode)));
const unproved=diagnostics.some(item=>item.severity==='warning');
const proved=diagnostics.reduce((sum,item)=>sum+Number(item.message?.match(/(\d+) verification condition\(s\) proved safe/)?.[1]??0),0);
console.log(JSON.stringify({status:solverUnavailable?'solver-unavailable':unproved||!proved?'unproved':'specified-assertions-proved',
  provedAssertions:proved,diagnosticCodes:diagnostics.map(item=>({severity:item.severity,code:String(item.errorCode??'unknown')})),
  limitation:'Only specified contract assertions under compiler/solver assumptions; never proof of broker security or off-chain audit truth.'},null,2));
if(solverUnavailable||unproved||!proved)process.exitCode=2;
