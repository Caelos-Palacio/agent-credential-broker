import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,open,writeFile,symlink,link,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {compile} from './compiler.mjs';
test('compiler gate rejects a device, oversized sparse file, symlink and wrong checksum before execution',{timeout:3000},async()=>{
  const directory=await mkdtemp(join(tmpdir(),'assurance-compiler-'));
  try{
    await assert.rejects(compile({binary:'/dev/zero'}),/Unsafe pinned compiler file/);
    const oversized=join(directory,'oversized'),handle=await open(oversized,'wx',0o700);
    try{await handle.truncate(32*1024*1024+1);}finally{await handle.close();}
    await assert.rejects(compile({binary:oversized}),/Unsafe pinned compiler file/);
    const fake=join(directory,'fake');await writeFile(fake,'#!/bin/sh\nexit 99\n',{mode:0o700});
    await assert.rejects(compile({binary:fake}),/checksum mismatch; not executed/);
    const symbolic=join(directory,'symbolic');await symlink(fake,symbolic);await assert.rejects(compile({binary:symbolic}));
    await link(fake,join(directory,'hardlink'));await assert.rejects(compile({binary:fake}),/Unsafe pinned compiler file/);
  }finally{await rm(directory,{recursive:true,force:true});}
});
