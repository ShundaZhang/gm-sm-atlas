"""Readable GM teaching primitives. NOT constant-time or production cryptography.
Only synthetic/public test keys belong here. Standard-library Python >=3.9.
"""
from dataclasses import dataclass
import hmac
import secrets
MASK=0xffffffff

def rol(x,n):
    n%=32
    return ((x<<n)|(x>>(32-n)))&MASK

def sm3(message, trace=False):
    raw=bytes(message);bits=len(raw)*8
    if bits>=1<<64: raise ValueError('SM3 input too long')
    raw+=b'\x80'+b'\x00'*((55-len(raw))%64)+bits.to_bytes(8,'big')
    state=[0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e];rounds=[]
    for offset in range(0,len(raw),64):
        w=[int.from_bytes(raw[offset+i:offset+i+4],'big') for i in range(0,64,4)]
        for j in range(16,68):
            x=w[j-16]^w[j-9]^rol(w[j-3],15)
            w.append(x^rol(x,15)^rol(x,23)^rol(w[j-13],7)^w[j-6])
        wp=[w[j]^w[j+4] for j in range(64)]
        a,b,c,d,e,f,g,h=state
        for j in range(64):
            ss1=rol((rol(a,12)+e+rol(0x79cc4519 if j<16 else 0x7a879d8a,j))&MASK,7)
            ss2=ss1^rol(a,12)
            ff=a^b^c if j<16 else (a&b)|(a&c)|(b&c)
            gg=e^f^g if j<16 else (e&f)|((~e)&g)
            tt1=(ff+d+ss2+wp[j])&MASK;tt2=(gg+h+ss1+w[j])&MASK
            a,b,c,d=tt1,a,rol(b,9),c
            e,f,g,h=tt2^rol(tt2,9)^rol(tt2,17),e,rol(f,19),g
            if trace: rounds.append({'block':offset//64,'round':j,'A':f'{a:08x}','E':f'{e:08x}'})
        state=[x^y for x,y in zip(state,[a,b,c,d,e,f,g,h])]
    digest=b''.join(x.to_bytes(4,'big') for x in state)
    return (digest,rounds) if trace else digest

SM4_SBOX=bytes.fromhex('''d690e9fecce13db716b614c228fb2c05
2b679a762abe04c3aa44132649860699
9c4250f491ef987a33540b43edcfac62
e4b31ca9c908e89580df94fa758f3fa6
4707a7fcf37317ba83593c19e6854fa8
686b81b27164da8bf8eb0f4b70569d35
1e240e5e6358d1a225227c3b01217887
d40046579fd327524c3602e7a0c4c89e
eabf8ad240c738b5a3f7f2cef96115a1
e0ae5da49b341a55ad933230f58cb1e3
1df6e22e8266ca60c02923ab0d534e6f
d5db3745defd8e2f03ff6a726d6c5b51
8d1baf92bbddbc7f11d95c411f105ad8
0ac13188a5cd7bbd2d74d012b8e5b4b0
8969974a0c96777e65b9f109c56ec684
18f07dec3adc4d2079ee5f3ed7cb3948''')
SM4_FK=[0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc]
SM4_CK=[int.from_bytes(bytes(((4*i+j)*7)%256 for j in range(4)),'big') for i in range(32)]

def tau(x): return int.from_bytes(bytes(SM4_SBOX[b] for b in x.to_bytes(4,'big')),'big')

def sm4_keys(key):
    if len(key)!=16: raise ValueError('SM4 key must be exactly 16 bytes')
    k=[int.from_bytes(key[i:i+4],'big')^f for i,f in zip(range(0,16,4),SM4_FK)]
    for i in range(32):
        x=tau(k[i+1]^k[i+2]^k[i+3]^SM4_CK[i])
        k.append(k[i]^x^rol(x,13)^rol(x,23))
    return k[4:]

def sm4_block(key,block,decrypt=False,trace=False):
    if len(block)!=16: raise ValueError('SM4 block must be exactly 16 bytes')
    keys=sm4_keys(key);keys=keys[::-1] if decrypt else keys
    x=[int.from_bytes(block[i:i+4],'big') for i in range(0,16,4)];rows=[]
    for i,rk in enumerate(keys):
        z=tau(x[i+1]^x[i+2]^x[i+3]^rk)
        x.append(x[i]^z^rol(z,2)^rol(z,10)^rol(z,18)^rol(z,24))
        rows.append({'round':i+1,'rk':f'{rk:08x}','newWord':f'{x[-1]:08x}'})
    result=b''.join(v.to_bytes(4,'big') for v in x[-4:][::-1])
    return (result,rows) if trace else result

@dataclass(frozen=True)
class Curve:
    name:str;p:int;a:int;b:int;n:int;gx:int;gy:int;h:int=1
    @property
    def G(self):return (self.gx,self.gy)

def hx(x):return int(x,16)
SM2=Curve('curveSM2',hx('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF'),hx('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC'),hx('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93'),hx('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123'),hx('32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7'),hx('BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0'))
P256=Curve('NIST P-256',hx('FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF'),hx('FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC'),hx('5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B'),hx('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551'),hx('6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296'),hx('4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5'))

def on_curve(c,q):
    return q is not None and len(q)==2 and all(isinstance(v,int) and 0<=v<c.p for v in q) and (q[1]*q[1]-q[0]**3-c.a*q[0]-c.b)%c.p==0

def add(c,q,r):
    if q is None:return r
    if r is None:return q
    x,y=q;u,v=r
    if x==u and (y+v)%c.p==0:return None
    m=((3*x*x+c.a)*pow(2*y,-1,c.p) if q==r else (v-y)*pow(u-x,-1,c.p))%c.p
    z=(m*m-x-u)%c.p
    return z,(m*(x-z)-y)%c.p

def mul(c,k,q):
    if k<0:raise ValueError('negative scalar')
    result=None
    while k:
        if k&1:result=add(c,result,q)
        q=add(c,q,q);k>>=1
    return result

def validate(c,q):
    if not on_curve(c,q) or mul(c,c.n,q) is not None:raise ValueError('invalid public point')
    return q

def keygen():
    d=secrets.randbelow(SM2.n-2)+1
    return d,mul(SM2,d,SM2.G)

def b32(v):return v.to_bytes(32,'big')
def za(identity,public,c=SM2):
    identity=bytes(identity);validate(c,public)
    if len(identity)>=8192:raise ValueError('identity bit length exceeds 16-bit ENTL')
    return sm3((8*len(identity)).to_bytes(2,'big')+identity+b''.join(b32(v) for v in [c.a,c.b,c.gx,c.gy,*public]))

def sign(message,d,identity=b'1234567812345678',nonce=None,c=SM2):
    if not 1<=d<c.n-1:raise ValueError('SM2 signing private scalar must be 1..n-2')
    public=mul(c,d,c.G);e=int.from_bytes(sm3(za(identity,public,c)+bytes(message)),'big')
    while True:
        k=secrets.randbelow(c.n-1)+1 if nonce is None else nonce
        if not 1<=k<c.n:raise ValueError('invalid nonce')
        x,_=mul(c,k,c.G);r=(e+x)%c.n;s=(pow(1+d,-1,c.n)*(k-r*d))%c.n
        if r and r+k!=c.n and s:return r,s
        if nonce is not None:raise ValueError('test nonce requires retry')

def verify(message,signature,public,identity=b'1234567812345678',c=SM2):
    try:
        validate(c,public);r,s=signature
        if not 1<=r<c.n or not 1<=s<c.n:return False
        t=(r+s)%c.n
        if not t:return False
        q=add(c,mul(c,s,c.G),mul(c,t,public))
        if q is None:return False
        e=int.from_bytes(sm3(za(identity,public,c)+bytes(message)),'big')
        return (e+q[0])%c.n==r
    except (ValueError,TypeError,OverflowError):return False

def kdf(z,size):
    if not 1<=size<=1_048_576:raise ValueError('teaching KDF length must be 1..1048576 bytes')
    return b''.join(sm3(z+i.to_bytes(4,'big')) for i in range(1,(size+31)//32+1))[:size]

def encrypt(message,public,nonce=None):
    validate(SM2,public);message=bytes(message)
    if not message:raise ValueError('empty teaching plaintext is not supported')
    while True:
        k=secrets.randbelow(SM2.n-1)+1 if nonce is None else nonce
        if not 1<=k<SM2.n:raise ValueError('invalid nonce')
        c1=mul(SM2,k,SM2.G);q=mul(SM2,k,public);z=b32(q[0])+b32(q[1]);t=kdf(z,len(message))
        if any(t):break
        if nonce is not None:raise ValueError('test nonce requires retry')
    c2=bytes(a^b for a,b in zip(message,t));c3=sm3(b32(q[0])+message+b32(q[1]))
    return b'\x04'+b32(c1[0])+b32(c1[1])+c3+c2 # explicit C1C3C2, uncompressed C1

def decrypt(ciphertext,d):
    ciphertext=bytes(ciphertext)
    if not 1<=d<SM2.n or len(ciphertext)<98 or ciphertext[0]!=4:raise ValueError('invalid teaching ciphertext')
    c1=(int.from_bytes(ciphertext[1:33],'big'),int.from_bytes(ciphertext[33:65],'big'));validate(SM2,c1)
    q=mul(SM2,d,c1);t=kdf(b32(q[0])+b32(q[1]),len(ciphertext)-97)
    if not any(t):raise ValueError('all-zero KDF output')
    message=bytes(a^b for a,b in zip(ciphertext[97:],t))
    expected=sm3(b32(q[0])+message+b32(q[1]))
    if not hmac.compare_digest(expected,ciphertext[65:97]):raise ValueError('integrity check failed')
    return message

def exchange(role,d,r,peer_public,peer_ephemeral,ida,idb,size=16):
    """Algebraic exchange core; no network, state machine or key-release policy."""
    if role not in ('A','B') or not 1<=d<SM2.n or not 1<=r<SM2.n:raise ValueError('invalid exchange input')
    validate(SM2,peer_public);validate(SM2,peer_ephemeral)
    public=mul(SM2,d,SM2.G);own=mul(SM2,r,SM2.G)
    w=(SM2.n.bit_length()+1)//2-1
    xb=lambda x:(1<<w)+(x&((1<<w)-1))
    t=(d+xb(own[0])*r)%SM2.n
    shared=mul(SM2,SM2.h*t,add(SM2,peer_public,mul(SM2,xb(peer_ephemeral[0]),peer_ephemeral)))
    if shared is None:raise ValueError('invalid shared point')
    pa,pb,ra,rb=(public,peer_public,own,peer_ephemeral) if role=='A' else (peer_public,public,peer_ephemeral,own)
    az,bz=za(ida,pa),za(idb,pb);x,y=map(b32,shared)
    key=kdf(x+y+az+bz,size);inner=sm3(x+az+bz+b''.join(b32(v) for v in (*ra,*rb)))
    return key,sm3(b'\x02'+y+inner),sm3(b'\x03'+y+inner)

# AES-128 encryption for a side-by-side round trace, no mode or padding.
def gf_mul(a,b):
    out=0
    while b:
        if b&1:out^=a
        a=((a<<1)^ (0x11b if a&128 else 0))&255;b>>=1
    return out

def gf_pow(a,n):
    out=1
    while n:
        if n&1:out=gf_mul(out,a)
        a=gf_mul(a,a);n>>=1
    return out

def aes_sbox(x):
    x=gf_pow(x,254) if x else 0
    rotate=lambda a,n:((a<<n)|(a>>(8-n)))&255
    return x^rotate(x,1)^rotate(x,2)^rotate(x,3)^rotate(x,4)^0x63
AES_SBOX=bytes(aes_sbox(x) for x in range(256))

def aes128_block(key,block,trace=False):
    if len(key)!=16 or len(block)!=16:raise ValueError('AES-128 teaching key/block must be 16 bytes')
    expanded=list(key);rcon=1
    while len(expanded)<176:
        word=expanded[-4:]
        if len(expanded)%16==0:
            word=[AES_SBOX[v] for v in word[1:]+word[:1]];word[0]^=rcon;rcon=gf_mul(rcon,2)
        for v in word:expanded.append(expanded[-16]^v)
    state=[a^b for a,b in zip(block,expanded[:16])];rows=[]
    for rnd in range(1,11):
        state=[AES_SBOX[v] for v in state]
        state=[state[4*((col+row)%4)+row] for col in range(4) for row in range(4)]
        if rnd<10:
            mixed=[]
            for col in range(4):
                a=state[4*col:4*col+4]
                for row in range(4):mixed.append(gf_mul(a[row],2)^gf_mul(a[(row+1)%4],3)^a[(row+2)%4]^a[(row+3)%4])
            state=mixed
        state=[a^b for a,b in zip(state,expanded[16*rnd:16*(rnd+1)])]
        rows.append({'round':rnd,'state':bytes(state).hex()})
    result=bytes(state)
    return (result,rows) if trace else result
