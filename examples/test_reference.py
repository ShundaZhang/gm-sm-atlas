"""Known answers, rejection paths and optional independent OpenSSL checks."""
import hashlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from reference import *

def tlv(tag,data):
    n=len(data);length=bytes([n]) if n<128 else bytes([0x80+(n.bit_length()+7)//8])+n.to_bytes((n.bit_length()+7)//8,'big')
    return bytes([tag])+length+data

def integer(n):
    data=n.to_bytes(max(1,(n.bit_length()+7)//8),'big')
    if data[0]&128:data=b'\x00'+data
    return tlv(2,data)

def seq(*parts):return tlv(0x30,b''.join(parts))
def parse(data):
    result=[];i=0
    while i<len(data):
        tag=data[i];size=data[i+1];i+=2
        if size&128:
            n=size&127;size=int.from_bytes(data[i:i+n],'big');i+=n
        result.append((tag,data[i:i+size]));i+=size
    if i!=len(data):raise ValueError('DER length')
    return result

def private_der(d):
    q=mul(SM2,d,SM2.G);pub=b'\x04'+b32(q[0])+b32(q[1])
    inner=seq(integer(1),tlv(4,b32(d)),tlv(0xa1,tlv(3,b'\x00'+pub)))
    alg=seq(bytes.fromhex('06072a8648ce3d0201'),bytes.fromhex('06082a811ccf5501822d'))
    return seq(integer(0),alg,tlv(4,inner))

def cipher_der(c):
    return seq(integer(int.from_bytes(c[1:33],'big')),integer(int.from_bytes(c[33:65],'big')),tlv(4,c[65:97]),tlv(4,c[97:]))

def cipher_raw(c):
    fields=parse(parse(c)[0][1]);x,y=(int.from_bytes(v,'big') for _,v in fields[:2])
    return b'\x04'+b32(x)+b32(y)+fields[2][1]+fields[3][1]

class Answers(unittest.TestCase):
    def test_sm3_known_answers(self):
        self.assertEqual(sm3(b'abc').hex(),'66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')
        self.assertEqual(sm3(b'abcd'*16).hex(),'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732')
        self.assertEqual(len(sm3(b'abc',True)[1]),64)
    def test_sm4_known_answer_and_inverse(self):
        key=bytes.fromhex('0123456789abcdeffedcba9876543210');cipher=sm4_block(key,key)
        self.assertEqual(cipher.hex(),'681edf34d206965e86b3e94f536e4246')
        self.assertEqual(sm4_block(key,cipher,True),key)
        _,trace=sm4_block(key,key,trace=True)
        self.assertEqual(trace[0]['rk'],'f12186f9');self.assertEqual(trace[0]['newWord'],'27fad345')
        with self.assertRaises(ValueError):sm4_block(b'bad',key)
        with self.assertRaises(ValueError):sm4_block(key,b'bad')
    def test_aes128_known_answer(self):
        key=bytes.fromhex('000102030405060708090a0b0c0d0e0f');block=bytes.fromhex('00112233445566778899aabbccddeeff')
        cipher,trace=aes128_block(key,block,True)
        self.assertEqual(cipher.hex(),'69c4e0d86a7b0430d8cdb78070b4c55a');self.assertEqual(len(trace),10)
    def test_sm2_historical_signature_vector(self):
        # Draft-shen-sm2-ecdsa-02 A.2 uses a DIFFERENT historical test curve.
        c=Curve('historical test only',hx('8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3'),hx('787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498'),hx('63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A'),hx('8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7'),hx('421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D'),hx('0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2'))
        d=hx('128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263');k=hx('6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F')
        q=mul(c,d,c.G);identity=b'ALICE123@YAHOO.COM'
        self.assertEqual(za(identity,q,c).hex(),'f4a38489e32b45b6f876e3ac2168ca392362dc8f23459c1d1146fc3dbfb7bc9a')
        signature=sign(b'message digest',d,identity,k,c)
        self.assertEqual(signature,(hx('40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1'),hx('6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7')))
        self.assertTrue(verify(b'message digest',signature,q,identity,c))
    def test_domain_parameters(self):
        for c in (SM2,P256):
            self.assertTrue(on_curve(c,c.G));self.assertIsNone(mul(c,c.n,c.G))
            self.assertEqual(add(c,c.G,c.G),mul(c,2,c.G))
            with self.assertRaises(ValueError):validate(c,(0,0))
        self.assertNotEqual(SM2.p,P256.p);self.assertFalse(on_curve(P256,SM2.G))
    def test_signature_and_identity_rejections(self):
        d=7;q=mul(SM2,d,SM2.G);s=sign(b'teaching message',d,nonce=11)
        self.assertTrue(verify(b'teaching message',s,q))
        self.assertFalse(verify(b'changed',s,q));self.assertFalse(verify(b'teaching message',s,q,b'other ID'))
        self.assertFalse(verify(b'teaching message',(0,s[1]),q));self.assertFalse(verify(b'teaching message',s,(0,0)))
        with self.assertRaises(ValueError):sign(b'abc',SM2.n-1)
        with self.assertRaises(ValueError):za(b'x'*8192,q)
    def test_encryption_integrity_and_point_validation(self):
        d=7;q=mul(SM2,d,SM2.G);c=encrypt(b'synthetic plaintext',q,nonce=11)
        self.assertEqual(decrypt(c,d),b'synthetic plaintext')
        for pos in (65,len(c)-1):
            bad=bytearray(c);bad[pos]^=1
            with self.assertRaises(ValueError):decrypt(bad,d)
        with self.assertRaises(ValueError):encrypt(b'abc',(0,0))
        with self.assertRaises(ValueError):decrypt(b'\x04'+b'\x00'*100,d)
    def test_key_exchange_sides_confirmations_and_identity(self):
        da,db,ra,rb=7,13,11,17 # public synthetic test scalars only
        pa,pb=mul(SM2,da,SM2.G),mul(SM2,db,SM2.G);qa,qb=mul(SM2,ra,SM2.G),mul(SM2,rb,SM2.G)
        a=exchange('A',da,ra,pb,qb,b'Alice',b'Bob');b=exchange('B',db,rb,pa,qa,b'Alice',b'Bob')
        self.assertEqual(a,b)
        self.assertNotEqual(a[0],exchange('B',db,rb,pa,qa,b'changed',b'Bob')[0])
        with self.assertRaises(ValueError):exchange('A',da,ra,pb,(0,0),b'Alice',b'Bob')

@unittest.skipUnless(shutil.which('openssl'),'OpenSSL CLI not available; independent checks skipped')
class Independent(unittest.TestCase):
    def run_ssl(self,args,data=None):
        r=subprocess.run(['openssl',*args],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if r.returncode:raise AssertionError(r.stderr.decode(errors='replace'))
        return r.stdout
    def test_hash_and_block_cipher_boundary_cases(self):
        for n in [0,1,55,56,63,64,65,127,128,513]:
            data=bytes((i*31+7)%256 for i in range(n))
            self.assertEqual(sm3(data),self.run_ssl(['dgst','-sm3','-binary'],data))
        for i in range(8):
            key=bytes((j*17+i)%256 for j in range(16));block=bytes((j*29+i)%256 for j in range(16))
            self.assertEqual(sm4_block(key,block),self.run_ssl(['enc','-sm4-ecb','-K',key.hex(),'-nopad','-nosalt'],block))
            self.assertEqual(aes128_block(key,block),self.run_ssl(['enc','-aes-128-ecb','-K',key.hex(),'-nopad','-nosalt'],block))
    def test_signature_and_encryption_interoperability(self):
        with tempfile.TemporaryDirectory(prefix='gm-atlas-test-') as directory:
            p=Path(directory);d=7;public=mul(SM2,d,SM2.G);message=b'local OpenSSL interoperability';identity=b'1234567812345678'
            (p/'key.der').write_bytes(private_der(d));(p/'message').write_bytes(message)
            self.run_ssl(['pkey','-inform','DER','-in',str(p/'key.der'),'-out',str(p/'key.pem')])
            self.run_ssl(['pkey','-in',str(p/'key.pem'),'-pubout','-out',str(p/'pub.pem')])
            r,s=sign(message,d,identity,nonce=11);(p/'ref.sig').write_bytes(seq(integer(r),integer(s)))
            result=self.run_ssl(['pkeyutl','-verify','-pubin','-inkey',str(p/'pub.pem'),'-rawin','-digest','sm3','-pkeyopt','distid:'+identity.decode(),'-in',str(p/'message'),'-sigfile',str(p/'ref.sig')])
            self.assertIn(b'Signature Verified',result)
            signature=self.run_ssl(['pkeyutl','-sign','-inkey',str(p/'key.pem'),'-rawin','-digest','sm3','-pkeyopt','distid:'+identity.decode(),'-in',str(p/'message')])
            parts=parse(parse(signature)[0][1]);pair=tuple(int.from_bytes(x,'big') for _,x in parts)
            self.assertTrue(verify(message,pair,public,identity))
            cipher=encrypt(message,public,nonce=11);(p/'ref.enc').write_bytes(cipher_der(cipher))
            self.assertEqual(self.run_ssl(['pkeyutl','-decrypt','-inkey',str(p/'key.pem'),'-in',str(p/'ref.enc')]),message)
            cipher=self.run_ssl(['pkeyutl','-encrypt','-pubin','-inkey',str(p/'pub.pem'),'-in',str(p/'message')])
            self.assertEqual(decrypt(cipher_raw(cipher),d),message)

if __name__=='__main__':unittest.main(verbosity=2)
