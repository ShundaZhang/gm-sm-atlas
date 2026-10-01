"""Synthetic local examples. Fixed scalars are PUBLIC teaching values, not keys."""
import hashlib
from reference import *
message=b'abc';key=bytes.fromhex('0123456789abcdeffedcba9876543210')
print('SM3:',sm3(message).hex())
print('SHA-256:',hashlib.sha256(message).hexdigest())
print('SHA3-256:',hashlib.sha3_256(message).hexdigest())
print('SM4 single block:',sm4_block(key,key).hex())
print('AES-128 single block:',aes128_block(key,key).hex())
d=7;public=mul(SM2,d,SM2.G);signature=sign(message,d,nonce=11)
print('SM2 verify:',verify(message,signature,public))
print('Changed ID rejected:',not verify(message,signature,public,b'other'))
print('SM2 decrypt:',decrypt(encrypt(message,public,nonce=11),d))
a=exchange('A',7,11,mul(SM2,13,SM2.G),mul(SM2,17,SM2.G),b'Alice',b'Bob')
b=exchange('B',13,17,mul(SM2,7,SM2.G),mul(SM2,11,SM2.G),b'Alice',b'Bob')
print('Exchange key and confirmation tags match:',a==b)
print('Reference code is not constant-time and is not a production API.')
