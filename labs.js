/* Local teaching inputs only. No network, account, key storage or upload. */
(() => {
  const zh=document.documentElement.lang.startsWith('zh');
  const t=(en,cn)=>zh?cn:en,el=id=>document.getElementById(id);
  function show(id,state,output,pass='info'){el(id+'-state').textContent=state;el(id+'-state').dataset.pass=pass;el(id+'-output').textContent=output;}
  const keys={standard:'0123456789abcdeffedcba9876543210',aes:'000102030405060708090a0b0c0d0e0f',zero:'00000000000000000000000000000000'};
  const fromhex=s=>new Uint8Array(s.match(/../g).map(x=>parseInt(x,16)));
  const actions={
    async hash(){
      const input=new TextEncoder().encode(el('hash-message').value);
      if(input.length>2048){show('hash',t('Use at most 2048 UTF-8 bytes','请使用不超过 2048 个 UTF-8 字节'),'','false');return;}
      const sm=SMCore.sm3(input),sha2=SMCore.hex(new Uint8Array(await crypto.subtle.digest('SHA-256',input))),sha3=SMCore.sha3(input);
      const rounds=sm.trace.map(x=>t(`Block ${x.block+1} · round ${x.round.toString().padStart(2,'0')} · A=${x.A} E=${x.E}`,`分组 ${x.block+1} · 轮 ${x.round.toString().padStart(2,'0')} · A=${x.A} E=${x.E}`)).join('\n');
      show('hash',t('Computed three distinct 256-bit digests','已计算三种不同的 256 位摘要'),t(`Input: ${input.length} UTF-8 bytes\nSM3 padded blocks: ${sm.blocks}`,`输入：${input.length} 个 UTF-8 字节\nSM3 填充分组：${sm.blocks}`)+`\n\nSM3      ${sm.digest}\nSHA-256  ${sha2}\nSHA3-256 ${sha3}\n\n`+t('SM3 compression trace (A/E after each round):\n','SM3 压缩轨迹（各轮之后 A/E）：\n')+rounds);
    },
    block(){
      const text=el('block-message').value.trim();
      if(!/^[0-9a-fA-F]{32}$/.test(text)||!Object.hasOwn(keys,el('block-key').value)){show('block',t('Enter exactly 32 hexadecimal digits for one 16-byte block','请输入恰好 32 个十六进制数字作为一个 16 字节分组'),'','false');return;}
      const input=fromhex(text),key=fromhex(keys[el('block-key').value]),sm=SMCore.sm4(key,input),aes=SMCore.aes128(key,input),back=SMCore.sm4(key,fromhex(sm.digest),true);
      const out=`Key      ${SMCore.hex(key)}\nInput    ${SMCore.hex(input)}\nSM4      ${sm.digest}\nAES-128  ${aes.digest}\nSM4⁻¹    ${back.digest}\n\n`+t('SM4 rounds (round key / new word):\n','SM4 轮（轮密钥 / 新字）：\n')+sm.trace.map(x=>`${x.round.toString().padStart(2,'0')}  ${x.rk}  ${x.newWord}`).join('\n')+'\n\n'+t('AES-128 state after AddRoundKey:\n','AES-128 各轮 AddRoundKey 后状态：\n')+aes.trace.map(x=>`${x.round.toString().padStart(2,'0')}  ${x.state}`).join('\n');
      show('block',t('Computed two block cores; SM4 inverse restores the input','已计算两个分组核心；SM4 逆运算恢复输入'),out,back.digest===SMCore.hex(input)?'true':'false');
    },
    curve(){
      const c=SMCore.curvePoint(el('curve-domain').value,el('curve-scalar').value);
      const q=c.point?`x = ${c.point[0]}\ny = ${c.point[1]}`:t('Point at infinity (group identity)','无穷远点（群单位元）');
      show('curve',c.point?t('Computed a public example point on the selected curve','已计算所选曲线的公开示例点'):t('nG = infinity for this domain','此域中 nG = 无穷远点'),`${c.name}\nk = ${c.scalar}\n${q}\n\n`+(c.point?t(`Satisfies curve equation: ${c.onCurve}`,`满足曲线方程：${c.onCurve}`):'')+'\n\n'+Object.entries(c.parameters).filter(([k])=>k!=='name').map(([k,v])=>`${k} = ${v}`).join('\n')+'\n\n'+t('Only public scalar examples are offered. This is not key generation or signing.','仅提供公开标量示例；这不是密钥生成或签名。'));
    }
  };
  document.addEventListener('click',async event=>{
    const b=event.target.closest('[data-action]');if(!b||!Object.hasOwn(actions,b.dataset.action))return;
    const id=b.dataset.action;b.disabled=true;
    try{await actions[id]();}catch{show(id,t('The local computation could not complete','本地计算未能完成'),t('Hash comparison needs Web Crypto in a modern secure context. Use synthetic data only.','杂凑对比需要现代安全环境的 Web Crypto；请仅使用合成数据。'),'false');}finally{b.disabled=false;}
  });
})();
