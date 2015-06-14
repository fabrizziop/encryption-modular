import hashlib
from Crypto.Cipher import AES
from lib_bitwise import int_to_big_endian, big_endian_to_int
from tkinter.messagebox import showerror
# An attempt to create a stream cipher resistant to AES
# weaknesses if found. 768-bit triple AES-256-EDE, used
# in CTR mode. Probably 512-bit equivalent. Hope to never
# have to need it.
class aes256_ede3_ctr(object):
	def __init__(self,init_key):
		k1 = init_key[:32]
		k2 = init_key[32:64]
		k3 = init_key[64:96]
		k4 = init_key[96:128]
		# Paranoid last-resort sanity check!.
		if (len(init_key)!=128) or (k1 == k2 == k3):
			showerror(title="Please report this",message="AES KEY ERROR, CIPHER UNSAFE")
		aes_first = hashlib.sha256(k1+k4).digest()
		aes_second = hashlib.sha256(k2+k4).digest()
		aes_third = hashlib.sha256(k3+k4).digest()
		self.first_aes = AES.new(aes_first,AES.MODE_ECB)
		self.second_aes = AES.new(aes_second,AES.MODE_ECB)
		self.third_aes = AES.new(aes_third,AES.MODE_ECB)
		aes_iv = hashlib.md5(hashlib.sha256(hashlib.sha512(k1+k2+k3+k4).digest()).digest()).digest()
		# print('K1:',list(aes_first))
		# print('K2:',list(aes_second))
		# print('K3:',list(aes_third))
		# print('IV:',list(aes_iv))
		self.to_encrypt = big_endian_to_int(aes_iv)
	def get_bytes_to_xor(self):
		bytes_to_xor = bytearray()
		for i in range(0,4):
			cur_bytes_to_encrypt = bytes(int_to_big_endian(self.to_encrypt))
			self.to_encrypt = (self.to_encrypt + 1) % (2**128)
			# print(list(cur_bytes_to_encrypt))
			e1 = self.first_aes.encrypt(cur_bytes_to_encrypt)
			e2 = self.second_aes.decrypt(e1)
			e3 = self.third_aes.encrypt(e2)
			bytes_to_xor.extend(e3)
		return bytes_to_xor