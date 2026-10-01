'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const {webcrypto}=require('node:crypto'),core=require('./crypto.js'),fixtures=require('./check-fixtures.json');
const bytes=x=>new Uint8Array(Buffer.from(x,'hex'));
for(const row of fixtures.hashes){
  const x=bytes(row.input);assert.equal(core.sm3(x).digest,row.sm3);assert.equal(core.sha3(x),row.sha3);
  assert.equal(core.sm3(x).trace.length,core.sm3(x).blocks*64);
}
for(const row of fixtures.blocks){
  const key=bytes(row.key),input=bytes(row.input);assert.equal(core.sm4(key,input).digest,row.sm4);assert.equal(core.aes128(key,input).digest,row['aes-128']);
  assert.equal(core.sm4(key,bytes(row.sm4),true).digest,row.input);
}
const standard=bytes('0123456789abcdeffedcba9876543210');
assert.equal(core.sm4(standard,standard).digest,'681edf34d206965e86b3e94f536e4246');
assert.equal(core.sm4(standard,standard).trace[0].rk,'f12186f9');
assert.equal(core.aes128(bytes('000102030405060708090a0b0c0d0e0f'),bytes('00112233445566778899aabbccddeeff')).digest,'69c4e0d86a7b0430d8cdb78070b4c55a');
for(const [domain,choices] of Object.entries(fixtures.curves))for(const [choice,point] of Object.entries(choices)){
  const q=core.curvePoint(domain,choice);assert.deepEqual(q.point,point);assert.equal(q.onCurve,point?true:null);
}
assert.throws(()=>core.curvePoint('sm2','private'));
async function testUI(lang){
  const elements={};for(const id of ['hash-message','block-message','block-key','curve-domain','curve-scalar','hash-state','hash-output','block-state','block-output','curve-state','curve-output'])elements[id]={value:'',textContent:'',dataset:{}};
  let handler;const document={documentElement:{lang},getElementById:id=>elements[id],addEventListener:(event,fn)=>{assert.equal(event,'click');handler=fn;}};
  vm.runInNewContext(fs.readFileSync('labs.js','utf8'),{SMCore:core,TextEncoder,Uint8Array,document,crypto:webcrypto});
  async function click(action){const button={dataset:{action},disabled:false};await handler({target:{closest:()=>button}});assert.equal(button.disabled,false);}
  for(const message of ['abc','','国密算法🔐']){
    elements['hash-message'].value=message;await click('hash');const output=elements['hash-output'].textContent;
    const data=Buffer.from(message);const row=fixtures.hashes.find(v=>v.input===data.toString('hex'));
    assert.ok(row);assert.ok(output.includes(row.sm3));assert.ok(output.includes(row.sha256));assert.ok(output.includes(row.sha3));
  }
  elements['hash-message'].value='中'.repeat(683);await click('hash');assert.equal(elements['hash-state'].dataset.pass,'false');assert.equal(elements['hash-output'].textContent,'');
  elements['block-key'].value='standard';elements['block-message'].value=Buffer.from(standard).toString('hex');await click('block');assert.ok(elements['block-output'].textContent.includes('681edf34d206965e86b3e94f536e4246'));assert.equal(elements['block-state'].dataset.pass,'true');
  elements['block-key'].value='aes';elements['block-message'].value='00112233445566778899aabbccddeeff';await click('block');assert.ok(elements['block-output'].textContent.includes('69c4e0d86a7b0430d8cdb78070b4c55a'));
  elements['block-message'].value='invalid';await click('block');assert.equal(elements['block-state'].dataset.pass,'false');assert.equal(elements['block-output'].textContent,'');
  for(const domain of ['sm2','p256'])for(const scalar of ['one','two','order']){elements['curve-domain'].value=domain;elements['curve-scalar'].value=scalar;await click('curve');assert.ok(elements['curve-output'].textContent.includes(core.curves[domain].name));assert.notEqual(elements['curve-state'].dataset.pass,'false');}
  assert.ok(elements['curve-output'].textContent.includes(lang==='zh'?'无穷远点':'Point at infinity'));
}
(async()=>{await testUI('en');await testUI('zh');console.log('PASS: JS hash padding/rate boundaries and UTF-8; SM4/AES OpenSSL vectors and inverse; both public curves; real EN/ZH lab handlers and invalid-input handling');})().catch(e=>{console.error(e);process.exitCode=1;});
