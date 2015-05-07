from lib_random import *
from lib_elementary_operations import do_xor_on_bytes
import hashlib

# All headers, RSA or PSK are 3072-byte long. For PSK headers,
# two 64-byte salts are created, to do PBKDF2 with them both along
# with the password. That result is XOR'd with the encrypted key.
# That way, we could change the password without re-encrypting
# the whole file, only changing the header (and MAC)

def create_psk_header(passphrase, prov_key=None):
	encoded_passphrase = passphrase.encode()
	if prov_key == None:
		k1, k2 = create_random_key(64), create_random_key(64)
	else:
		k1, k2 = prov_key[:64], prov_key[64:]
	nkslot = bytearray()
	nkslot.append(create_random_lower_half())
	s1, s2 = create_random_key(64), create_random_key(64)
	xm1, xm2 = bytearray(hashlib.pbkdf2_hmac('sha512', encoded_passphrase, s1, 4000000)), bytearray(hashlib.pbkdf2_hmac('sha512', encoded_passphrase, s2, 4000000))
	ek1, ek2 = do_xor_on_bytes(xm1,k1), do_xor_on_bytes(xm2,k2)
	rp = create_random_key(2815)
	nkslot.extend(s1+ek1+s2+ek2+rp)
	return nkslot, k1+k2
	
def decrypt_psk_header(nkslot, passphrase):
	encoded_passphrase = passphrase.encode()
	s1, ek1, s2, ek2 = nkslot[1:65], nkslot[65:129], nkslot[129:193], nkslot[193:257]
	# print(len(s1),len(ek1),len(s2),len(ek2))
	xm1, xm2 = bytearray(hashlib.pbkdf2_hmac('sha512', encoded_passphrase, s1, 4000000)), bytearray(hashlib.pbkdf2_hmac('sha512', encoded_passphrase, s2, 4000000))
	k1, k2 = do_xor_on_bytes(xm1,ek1), do_xor_on_bytes(xm2,ek2)
	return k1+k2

def is_header_psk(first_byte):
	if first_byte <= 127:
		return True
	else:
		return False