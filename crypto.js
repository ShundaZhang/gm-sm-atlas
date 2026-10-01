/* Original teaching implementations. Not constant-time; no production-key use. */
const SMCore = (() => {
  const hex=bytes=>Array.from(bytes,x=>x.toString(16).padStart(2,'0')).join('');
  const rol=(x,n)=>{n%=32;return ((x<<n)|(x>>>(32-n)))>>>0;};
  const words=bytes=>Array.from({length:bytes.length/4},(_,i)=>new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength).getUint32(4*i,false));
  const bytes=words=>{const out=new Uint8Array(words.length*4),d=new DataView(out.buffer);words.forEach((w,i)=>d.setUint32(4*i,w,false));return out;};
  function sm3(input){
    const size=Math.ceil((input.length+9)/64)*64,padded=new Uint8Array(size);padded.set(input);padded[input.length]=128;
    new DataView(padded.buffer).setBigUint64(size-8,BigInt(input.length)*8n,false);
    let state=[0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e];const trace=[];
    for(let off=0;off<size;off+=64){
      const w=words(padded.slice(off,off+64));
      for(let j=16;j<68;j++){let x=w[j-16]^w[j-9]^rol(w[j-3],15);w.push((x^rol(x,15)^rol(x,23)^rol(w[j-13],7)^w[j-6])>>>0);}
      let [a,b,c,d,e,f,g,h]=state;
      for(let j=0;j<64;j++){
        const ss1=rol((rol(a,12)+e+rol(j<16?0x79cc4519:0x7a879d8a,j))>>>0,7),ss2=ss1^rol(a,12);
        const ff=j<16?a^b^c:(a&b)|(a&c)|(b&c),gg=j<16?e^f^g:(e&f)|(~e&g);
        const tt1=(ff+d+ss2+((w[j]^w[j+4])>>>0))>>>0,tt2=(gg+h+ss1+w[j])>>>0;
        [a,b,c,d]=[tt1,a,rol(b,9),c];[e,f,g,h]=[(tt2^rol(tt2,9)^rol(tt2,17))>>>0,e,rol(f,19),g];
        trace.push({block:off/64,round:j,A:a.toString(16).padStart(8,'0'),E:e.toString(16).padStart(8,'0')});
      }
      state=state.map((x,i)=>(x^[a,b,c,d,e,f,g,h][i])>>>0);
    }
    return {digest:hex(bytes(state)),trace,blocks:size/64};
  }
  const sm4box=[214, 144, 233, 254, 204, 225, 61, 183, 22, 182, 20, 194, 40, 251, 44, 5, 43, 103, 154, 118, 42, 190, 4, 195, 170, 68, 19, 38, 73, 134, 6, 153, 156, 66, 80, 244, 145, 239, 152, 122, 51, 84, 11, 67, 237, 207, 172, 98, 228, 179, 28, 169, 201, 8, 232, 149, 128, 223, 148, 250, 117, 143, 63, 166, 71, 7, 167, 252, 243, 115, 23, 186, 131, 89, 60, 25, 230, 133, 79, 168, 104, 107, 129, 178, 113, 100, 218, 139, 248, 235, 15, 75, 112, 86, 157, 53, 30, 36, 14, 94, 99, 88, 209, 162, 37, 34, 124, 59, 1, 33, 120, 135, 212, 0, 70, 87, 159, 211, 39, 82, 76, 54, 2, 231, 160, 196, 200, 158, 234, 191, 138, 210, 64, 199, 56, 181, 163, 247, 242, 206, 249, 97, 21, 161, 224, 174, 93, 164, 155, 52, 26, 85, 173, 147, 50, 48, 245, 140, 177, 227, 29, 246, 226, 46, 130, 102, 202, 96, 192, 41, 35, 171, 13, 83, 78, 111, 213, 219, 55, 69, 222, 253, 142, 47, 3, 255, 106, 114, 109, 108, 91, 81, 141, 27, 175, 146, 187, 221, 188, 127, 17, 217, 92, 65, 31, 16, 90, 216, 10, 193, 49, 136, 165, 205, 123, 189, 45, 116, 208, 18, 184, 229, 180, 176, 137, 105, 151, 74, 12, 150, 119, 126, 101, 185, 241, 9, 197, 110, 198, 132, 24, 240, 125, 236, 58, 220, 77, 32, 121, 238, 95, 62, 215, 203, 57, 72];
  const aesbox=[99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22];

  const tau=x=>((sm4box[x>>>24]<<24)|(sm4box[(x>>>16)&255]<<16)|(sm4box[(x>>>8)&255]<<8)|sm4box[x&255])>>>0;
  function sm4(key,input,decrypt=false){
    if(key.length!==16||input.length!==16)throw Error('16-byte key and block required');
    const fk=[0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc],k=words(key).map((v,i)=>(v^fk[i])>>>0);
    for(let i=0;i<32;i++){
      const ck=((((4*i)*7%256)<<24)|(((4*i+1)*7%256)<<16)|(((4*i+2)*7%256)<<8)|((4*i+3)*7%256))>>>0;
      const z=tau(k[i+1]^k[i+2]^k[i+3]^ck);k.push((k[i]^z^rol(z,13)^rol(z,23))>>>0);
    }
    const keys=k.slice(4);if(decrypt)keys.reverse();const x=words(input),trace=[];
    keys.forEach((rk,i)=>{const z=tau(x[i+1]^x[i+2]^x[i+3]^rk);x.push((x[i]^z^rol(z,2)^rol(z,10)^rol(z,18)^rol(z,24))>>>0);trace.push({round:i+1,rk:rk.toString(16).padStart(8,'0'),newWord:x.at(-1).toString(16).padStart(8,'0')});});
    return {digest:hex(bytes(x.slice(-4).reverse())),trace};
  }
  function gm(a,b){let out=0;while(b){if(b&1)out^=a;a=((a<<1)^(a&128?0x11b:0))&255;b>>>=1;}return out;}
  function aes128(key,input){
    if(key.length!==16||input.length!==16)throw Error('16-byte key and block required');
    const expanded=Array.from(key);let rc=1;
    while(expanded.length<176){let w=expanded.slice(-4);if(expanded.length%16===0){w=[...w.slice(1),w[0]].map(x=>aesbox[x]);w[0]^=rc;rc=gm(rc,2);}w.forEach(v=>expanded.push(expanded[expanded.length-16]^v));}
    let s=Array.from(input,(v,i)=>v^expanded[i]);const trace=[];
    for(let round=1;round<=10;round++){
      s=s.map(v=>aesbox[v]);const old=s;s=Array.from({length:16},(_,i)=>old[4*((Math.floor(i/4)+i%4)%4)+i%4]);
      if(round<10){const mixed=[];for(let c=0;c<4;c++){const a=s.slice(4*c,4*c+4);for(let r=0;r<4;r++)mixed.push(gm(a[r],2)^gm(a[(r+1)%4],3)^a[(r+2)%4]^a[(r+3)%4]);}s=mixed;}
      s=s.map((v,i)=>v^expanded[16*round+i]);trace.push({round,state:hex(s)});
    }
    return {digest:hex(s),trace};
  }
  const mask64=(1n<<64n)-1n;
  const rot64=(x,n)=>n?((x<<BigInt(n))|(x>>BigInt(64-n)))&mask64:x;
  const rc=[0x0000000000000001n,0x0000000000008082n,0x800000000000808an,0x8000000080008000n,0x000000000000808bn,0x0000000080000001n,0x8000000080008081n,0x8000000000008009n,0x000000000000008an,0x0000000000000088n,0x0000000080008009n,0x000000008000000an,0x000000008000808bn,0x800000000000008bn,0x8000000000008089n,0x8000000000008003n,0x8000000000008002n,0x8000000000000080n,0x000000000000800an,0x800000008000000an,0x8000000080008081n,0x8000000000008080n,0x0000000080000001n,0x8000000080008008n];
  const rotation=[0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14];
  function sha3(input){
    const size=Math.ceil((input.length+1)/136)*136,padded=new Uint8Array(size);padded.set(input);padded[input.length]^=6;padded[size-1]^=128;
    let a=Array(25).fill(0n);
    for(let off=0;off<size;off+=136){
      for(let i=0;i<136;i++)a[Math.floor(i/8)]^=BigInt(padded[off+i])<<BigInt(8*(i%8));
      for(let round=0;round<24;round++){
        const c=Array.from({length:5},(_,x)=>a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20]);
        const d=c.map((_,x)=>c[(x+4)%5]^rot64(c[(x+1)%5],1));a=a.map((v,i)=>v^d[i%5]);
        const b=Array(25).fill(0n);for(let x=0;x<5;x++)for(let y=0;y<5;y++)b[y+5*((2*x+3*y)%5)]=rot64(a[x+5*y],rotation[x+5*y]);
        for(let x=0;x<5;x++)for(let y=0;y<5;y++)a[x+5*y]=(b[x+5*y]^((~b[(x+1)%5+5*y])&b[(x+2)%5+5*y]))&mask64;
        a[0]^=rc[round];
      }
    }
    return hex(Array.from({length:32},(_,i)=>Number((a[Math.floor(i/8)]>>BigInt(8*(i%8)))&255n)));
  }
  const curves={"sm2": {"name": "curveSM2", "p": "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff", "a": "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc", "b": "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93", "n": "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123", "gx": "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7", "gy": "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"}, "p256": {"name": "NIST P-256", "p": "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", "a": "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", "b": "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", "n": "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", "gx": "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", "gy": "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"}};
  const mod=(x,p)=>(x%p+p)%p;
  function inverse(x,p){let a=mod(x,p),b=p,u=1n,v=0n;while(b){let q=a/b;[a,b]=[b,a-q*b];[u,v]=[v,u-q*v];}if(a!==1n)throw Error('No inverse');return mod(u,p);}
  function plus(c,q,r){if(!q)return r;if(!r)return q;const [x,y]=q,[u,v]=r;if(x===u&&mod(y+v,c.p)===0n)return null;const m=mod((x===u?(3n*x*x+c.a)*inverse(2n*y,c.p):(v-y)*inverse(u-x,c.p)),c.p);const z=mod(m*m-x-u,c.p);return [z,mod(m*(x-z)-y,c.p)];}
  function curvePoint(name,choice){
    if(!Object.hasOwn(curves,name)||!['one','two','order'].includes(choice))throw Error('Unsupported public example');
    const raw=curves[name],c=Object.fromEntries(Object.entries(raw).filter(([k])=>k!=='name').map(([k,v])=>[k,BigInt('0x'+v)]));
    const g=[c.gx,c.gy];let scalar=choice==='one'?1n:choice==='two'?2n:c.n,k=scalar,q=g,result=null;
    while(k){if(k&1n)result=plus(c,result,q);q=plus(c,q,q);k>>=1n;}
    const onCurve=result===null?null:mod(result[1]**2n-result[0]**3n-c.a*result[0]-c.b,c.p)===0n;
    return {name:raw.name,scalar:scalar.toString(16),point:result?result.map(v=>v.toString(16).padStart(64,'0')):null,onCurve,parameters:raw};
  }
  return {hex,sm3,sm4,aes128,sha3,curves,curvePoint};
})();
if(typeof module!=='undefined')module.exports=SMCore;
