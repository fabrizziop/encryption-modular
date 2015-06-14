from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA512
from Crypto.Signature import PKCS1_v1_5
import hashlib
import binascii
import time
from lib_user_input import force_integer_input
from lib_random import create_random_key
from lib_misc import get_user_attention
from lib_main_crypto import *
from lib_gui import *
class rsa_keystore(object):
	# e = 65537 fixed
	def __init__(self):
		self.key_list = []
		self.key_fingerprint_list = []
		#self.key_type_list = []
	def generate_key(self):
		progress_object = simple_progress_popup_indeterminate("RSA Key Generation", "Generating 8192 bit RSA key")
		key = RSA.generate(8192)
		progress_object.destroy_progress()
		self.key_list.append(key)
		self.update_fingerprints()
	def update_fingerprints(self):
		self.key_fingerprint_list = []
		for i in range(0,len(self.key_list)):
			self.key_fingerprint_list.append(hashlib.sha256(bytes(str(self.key_list[i].n).encode())).digest())
	def view_keys(self):
		if len(self.key_fingerprint_list) == 0:
			print("No keys found")
		else:
			for i in range(0,len(self.key_fingerprint_list)):
				print("Key number :",i+1)
				print("Fingerprint:",bytes.decode(binascii.hexlify(self.key_fingerprint_list[i])))
				# print("Size",self.key_list[i].size())
				print("Private key:", self.key_list[i].has_private())
	def export_key(self,kte):
		kte_ac = self.key_list[kte]
		kte_hasprivate = kte_ac.has_private()
		priv_override = False
		if kte_hasprivate == True:
			epprompt = askyesno('RSA Private Export Warning','The RSA private exponent will be exported, please confirm')
			if epprompt == True:
				priv_override = True
		if (kte_hasprivate == False) or (kte_hasprivate == True and priv_override == True):
			enc_status = encrypt_file_from_bytearray(bytearray(kte_ac.exportKey(format='DER')))
			if enc_status:
				showinfo(title="Key Export Successful",message="Key Export Successful")
			else:
				showerror(title="Key Export Failed.",message="Key Export Failed.")
	def import_key(self, read_file):
		keyraw, hmac_state, decryption_done = decrypt_file_to_bytearray(read_file)
		if decryption_done == False:
			print("Decryption Failed")
			return False
		else:
			try:
				self.key_list.append(RSA.importKey(keyraw))
				self.update_fingerprints()
				return True
			except ValueError:
				print()
				get_user_attention(True)
				print("Malformed RSA key.")
				return False
	def delete_key(self,kte):
		self.key_list.pop(kte)
		self.update_fingerprints()
	def create_public_from_private(self,kte):
		kte_ac = self.key_list[kte]
		self.key_list.append(kte_ac.publickey())
		self.update_fingerprints()
	def create_rsa_header(self, prov_key=None):
		ktu = ask_for_rsa_key(self, False)
		if ktu == None:
			showwarning(title="No Key Available",message="No suitable key for encryption is in Keystore.")
			return False,False,False
		try:
			ktu_ac = self.key_list[ktu]
			# Was 1024 bit previously, don't know why.
			# Reduced to 128 byte to match the PSK key.
			if prov_key == None:
				key_to_encrypt = create_random_key(128)
			else:
				key_to_encrypt = prov_key
			rsa_cipher = PKCS1_OAEP.new(ktu_ac,hashAlgo=SHA512)
			ciphered_key = rsa_cipher.encrypt(key_to_encrypt)
			# decrypted_key = rsa_cipher.decrypt(ciphered_key)
			#print(len(ciphered_key))
			header = bytearray()
			header.append(create_random_upper_half())
			header.extend(ciphered_key)
			header.extend(create_random_key(2047))
			return header, key_to_encrypt, True
		except IndexError:
			showerror(title="Please report this error",message="Keystore selected key out of index.")
			return False, False, False
	def decrypt_rsa_header(self, header):
		ktu = ask_for_rsa_key(self, True)
		if ktu == None:
			showwarning(title="No Key Available",message="No suitable key for decryption is in Keystore.")
			return False,False
		try:
			ktu_ac = self.key_list[ktu]
			is_key_private = ktu_ac.has_private()
			if is_key_private == True:
				rsacipher = PKCS1_OAEP.new(ktu_ac,hashAlgo=SHA512)
				try:
					deciphered_header = rsacipher.decrypt(bytes(header[1:1025]))
					# print(deciphered_header)
					return deciphered_header, True
				except ValueError:
					showerror(title="Decryption Incorrect",message="Decryption Incorrect. Wrong key or tampered file.")
					return False, False
			else:
				showerror(title="Please report this error",message="The key selected doesn't have its private decryption exponent.")
		except IndexError:
			showerror(title="Please report this error",message="Keystore selected key out of index.")
			return False, False
	def return_first_key_position_from_sig(self, sig_in):
		hash_to_search = sig_in[:32]
		for i in range(0,len(self.key_fingerprint_list)):
			if self.key_fingerprint_list[i] == hash_to_search:
				return i
		return None
	def sign_rsa(self, content_to_sign):
		ktu = ask_for_rsa_key(self, True)
		if ktu == None:
			showwarning(title="No Key Available",message="No suitable key for signing is in Keystore.")
			return None
		try:
			ktu_ac = self.key_list[ktu]
			is_key_private = ktu_ac.has_private()
			if is_key_private == True:
				m_hash = SHA512.new(content_to_sign)
				sign_object = PKCS1_v1_5.new(ktu_ac)
				signature = sign_object.sign(m_hash)
				signature_to_append = bytearray()
				signature_to_append.extend(self.key_fingerprint_list[ktu])
				signature_to_append.extend(signature)
				signature_to_append.extend(create_random_key(2016))
				return signature_to_append
			else:
				showerror(title="Please report this error",message="The key selected doesn't have its private decryption exponent.")
				return None
		except IndexError:
			showerror(title="Please report this error",message="Keystore selected key out of index.")
			return None
	def verify_rsa(self, content_to_verify):
		signature_block = content_to_verify[-3072:]
		actual_signature = signature_block[:1056]
		ktu = self.return_first_key_position_from_sig(actual_signature)
		if type(ktu) == int:
			ktu_ac = self.key_list[ktu]
			m_hash = SHA512.new(content_to_verify[:-3072])
			verify_object = PKCS1_v1_5.new(ktu_ac)
			verify_status = verify_object.verify(m_hash, bytes(actual_signature[32:]))
			return verify_status, bytes.decode(binascii.hexlify(actual_signature[:32]))
		else:
			showinfo(title="Key not found", message="Key not in keystore, desired fingerprint is: "+str(bytes.decode(binascii.hexlify(actual_signature[:32]))))
			return None, None