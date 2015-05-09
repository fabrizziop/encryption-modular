from math import ceil
import hmac
import sys
from lib_stream_ciphers import aes256_ede3_ctr
from lib_elementary_operations import do_xor_on_bytes
from lib_bitwise import int_to_big_endian, big_endian_to_int
from lib_keyslot import *
from lib_user_input import *
from lib_file_ops import *
from lib_random import *
from lib_misc import get_user_attention

print_same_line = sys.stdout.write

def derive_hmac_key_from_main(tkey_bytes):
	return hashlib.sha512(bytearray(hashlib.sha512(tkey_bytes).digest())+bytearray(hashlib.sha256(tkey_bytes).digest())+bytearray(hashlib.md5(tkey_bytes).digest())+bytearray(hashlib.sha384(tkey_bytes).digest())+bytearray(hashlib.sha1(tkey_bytes).digest())).digest()

def calculate_hmac(bytearray_to_hmac, main_key):
	return hmac.new(derive_hmac_key_from_main(main_key),msg=bytearray_to_hmac,digestmod=hashlib.sha512).digest()

def verify_hmac(bytearray_to_hmac,main_key):
	return hmac.compare_digest(hmac.new(derive_hmac_key_from_main(main_key),msg=bytearray_to_hmac[:-64],digestmod=hashlib.sha512).digest(), bytearray_to_hmac[-64:])

def encrypt_length(lte, cipher_object):
	len_bytes = int_to_big_endian(lte, pad_to=64)
	return do_xor_on_bytes(len_bytes,cipher_object.get_bytes_to_xor())

def decrypt_length(ltd, cipher_object):
	len_bytes = do_xor_on_bytes(ltd,cipher_object.get_bytes_to_xor())
	return big_endian_to_int(len_bytes)

def encrypt_bytearray_with_aes256_ede3_ctr(bytearray_to_encrypt, cipher_object):
	tte = ceil(len(bytearray_to_encrypt)/ 64)
	out_array = bytearray()
	pc = max(tte // 80,1)
	cnt = 0
	print("Keystream Progress:")
	for i in range(0,tte):
		cnt += 1
		if (cnt // pc) == 1:
			print_same_line("=")
			sys.stdout.flush()
			cnt = 0
		out_array.extend(do_xor_on_bytes(bytearray_to_encrypt[(i*64):(i*64)+64],cipher_object.get_bytes_to_xor()))
	return out_array

def encrypt_bytearray_main(header,file_array,main_key):
	out_array = bytearray()
	current_cipher = aes256_ede3_ctr(main_key)
	lte = len(file_array)
	# print('length encrypted: ',lte)
	# print('main key: ',list(main_key))
	out_array.extend(header)
	out_array.extend(encrypt_length(lte, current_cipher))
	out_array.extend(encrypt_bytearray_with_aes256_ede3_ctr(file_array,current_cipher))
	out_array.extend(calculate_hmac(out_array,main_key))
	return out_array

def decrypt_bytearray_main(file_array,main_key):
	out_array = bytearray()
	current_cipher = aes256_ede3_ctr(main_key)
	ltd = decrypt_length(file_array[3072:3136],current_cipher)
	# print('length decrypted: ',ltd)
	# print('main key: ',list(main_key))
	file_array = file_array[:3200+ltd]
	hmac_state = verify_hmac(file_array,main_key)
	encryption_done = False
	if hmac_state == True:
		print("HMAC OK.")
		out_array.extend(encrypt_bytearray_with_aes256_ede3_ctr(file_array[3136:(3136+ltd)],current_cipher))
		encryption_done = True
	else:
		#print("HMAC Fucked up.")
		get_user_attention(True)
		print("HMAC Mismatch, want to continue?. 0: No, 1: Yes [0]")
		hmac_ignore = input_int_until_list_or_default([0,1],0)
		if hmac_ignore == 1:
			out_array.extend(encrypt_bytearray_with_aes256_ede3_ctr(file_array[3136:(3136+ltd)],current_cipher))
			encryption_done = True
		else:
			pass
	return out_array, hmac_state, encryption_done

def extract_and_validate(file_array,main_key):
	out_array = bytearray()
	current_cipher = aes256_ede3_ctr(main_key)
	ltd = decrypt_length(file_array[3072:3136],current_cipher)
	# print('length decrypted: ',ltd)
	# print('main key: ',list(main_key))
	file_array = file_array[:3200+ltd]
	hmac_state = verify_hmac(file_array,main_key)
	if hmac_state == True:
		return True, ltd
	else:
		return False, None
	
def encrypt_file_from_bytearray(bytearray_to_encrypt):
	file_name = input("File name to save into:")
	if is_file_accessible(file_name) == True:
		print("File Already Exists, NOT OVERWRITING.")
		return False
	else:
		file_to_save, encryption_done = encrypt_file(bytearray_to_encrypt, False, allow_rsa=False)
		file_to_save.extend(create_random_key(rng.randint(128,16384)))
		write_file_from_bytearray(file_name,file_to_save)

def decrypt_file_to_bytearray():
	read_file, file_name = user_file_prompt("File to decrypt: ")
	if (file_name == False) and (read_file == False):
		print("File Not Found")
		return False, False, False
	return decrypt_file(read_file, False, allow_rsa=False)

def encrypt_file(file_to_encrypt, current_keystore, allow_rsa=True):
	is_psk, password = user_encryption_type_prompt(allow_rsa)
	if is_psk == True:
		header, key = create_psk_header(password)
		file_to_save = encrypt_bytearray_main(header,file_to_encrypt, key)
		return file_to_save, True
	else:
		header, key, key_state = current_keystore.create_rsa_header()
		if key_state == False:
			return False, False
		else:
			file_to_save = encrypt_bytearray_main(header,file_to_encrypt, key)
			return file_to_save, True
		
def decrypt_file(file_to_decrypt, current_keystore, allow_rsa=True):
	is_psk, password = user_decryption_prompt(file_to_decrypt[0])
	header = file_to_decrypt[:3072]
	if is_psk == True:
		key = decrypt_psk_header(header,password)
		file_to_save, hmac_state, decryption_done = decrypt_bytearray_main(file_to_decrypt,key)
		return file_to_save, hmac_state, decryption_done
	else:
		key, key_state = current_keystore.decrypt_rsa_header(header)
		if key_state == False:
			return False, False, False
		else:
			file_to_save, hmac_state, decryption_done = decrypt_bytearray_main(file_to_decrypt,key)
			return file_to_save, hmac_state, decryption_done

def extract_key_and_validate(file_to_decrypt, current_keystore):
	is_psk, password = user_decryption_prompt(file_to_decrypt[0])
	header = file_to_decrypt[:3072]
	if is_psk == True:
		key = decrypt_psk_header(header,password)
		hmac_state, file_length = extract_and_validate(file_to_decrypt,key)
		return hmac_state, file_length, key
	else:
		key, key_state = current_keystore.decrypt_rsa_header(header)
		if key_state == False:
			return False, False, False
		else:
			hmac_state, file_length = extract_and_validate(file_to_decrypt,key)
			return hmac_state, file_length, key

def change_already_validated_header(file_to_decrypt, key, file_length, current_keystore, allow_rsa=True):
	new_file = bytearray()
	is_psk, password = user_encryption_type_prompt(allow_rsa)
	if is_psk == True:
		header, key = create_psk_header(password, prov_key=key)
		new_file.extend(header)
		new_file.extend(file_to_decrypt[3072:3136+file_length])
		new_file.extend(calculate_hmac(new_file,key))
		new_file.extend(file_to_decrypt[3200+file_length:])
		return new_file, True
	else:
		header, key, key_state = current_keystore.create_rsa_header(prov_key=key)
		if key_state == False:
			return False, False
		else:
			new_file.extend(header)
			new_file.extend(file_to_decrypt[3072:3136+file_length])
			new_file.extend(calculate_hmac(new_file,key))
			new_file.extend(file_to_decrypt[3200+file_length:])
			return new_file, True