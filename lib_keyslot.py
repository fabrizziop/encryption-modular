from lib_random import *
from lib_elementary_operations import do_xor_on_bytes
import hashlib

def create_psk_header(passphrase):
	encoded_passphrase = passphrase.encode()
	k1, k2 = create_random_key(64), create_random_key(64)
	nkslot = bytearray()
	nkslot.append(create_random_lower_half())
	s1, s2 = create_random_key(64), create_random_key(64)
	xm1, xm2 = bytearray(hashlib.pbkdf2_hmac('sha512', encoded_passphrase, s1, 100000)), bytearray(hashlib.pbkdf2_hmac('sha512', encoded_passphrase, s2, 100000))
	ek1, ek2 = do_xor_on_bytes(xm1,k1), do_xor_on_bytes(xm2,k2)
	rp = create_random_key(2815)
	nkslot.extend(s1+ek1+s2+ek2+rp)
	return nkslot, k1+k2
	
def decrypt_psk_header(nkslot, passphrase):
	encoded_passphrase = passphrase.encode()
	s1, ek1, s2, ek2 = nkslot[1:65], nkslot[65:129], nkslot[129:193], nkslot[193:257]
	print(len(s1),len(ek1),len(s2),len(ek2))
	xm1, xm2 = bytearray(hashlib.pbkdf2_hmac('sha512', encoded_passphrase, s1, 100000)), bytearray(hashlib.pbkdf2_hmac('sha512', encoded_passphrase, s2, 100000))
	k1, k2 = do_xor_on_bytes(xm1,ek1), do_xor_on_bytes(xm2,ek2)
	return k1+k2

def is_header_psk(first_byte):
	if first_byte <= 127:
		return True
	else:
		return False