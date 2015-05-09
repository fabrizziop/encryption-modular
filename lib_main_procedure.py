from lib_user_input import *
from lib_main_crypto import *
from lib_rsa import *
from lib_file_ops import *
from lib_wave import *
from lib_random import *

def encrypt_file_with_full_prompt(main_keystore):
	read_file, file_name = user_file_prompt("File to encrypt: ")
	if (file_name == False) and (read_file == False):
		print("File Not Found")
		return False
	file_to_save, encryption_done = encrypt_file(read_file, main_keystore)
	if encryption_done == True:
		# Appending random bytes at the end, to obfuscate the actual file length.
		file_to_save.extend(create_random_key(rng.randint(128,131072)))
		write_file_from_bytearray(file_name,file_to_save)
	else:
		print("Encryption Failed.")
	
def decrypt_file_with_full_prompt(main_keystore):
	read_file, file_name = user_file_prompt("File to decrypt: ")
	if file_name == False:
		print("File Not Found")
		return False
	file_to_save, hmac_state, decryption_done = decrypt_file(read_file, main_keystore)
	if decryption_done == True:
		write_file_from_bytearray(file_name,file_to_save)
	else:
		print("Decryption Failed or Aborted.")

def encrypt_file_into_wav(main_keystore):
	read_file, file_name = user_file_prompt("File to encrypt: ")
	if (file_name == False) and (read_file == False):
		print("File Not Found")
		return False
	min_len = len(read_file)
	wav_in_file = input("WAV file to read: ")
	if is_file_accessible(wav_in_file) == False:
		print("File Not Found")
		return False
	max_len = calculate_max_wave_encryption(wav_in_file)
	# Being sure that the file actually WILL fit into the wav.
	print('Length of file to encrypt:',min_len+3200)
	print('Length available in WAV:', max_len)
	if (min_len+3200) > max_len:
		print("File won't fit into WAV.")
		return False
	wav_out_name = input("File name to save into:")
	file_to_save, encryption_done = encrypt_file(read_file, main_keystore)
	if encryption_done == True:
		wav_in, parameters_wav = read_wave_to_bytearray(wav_in_file)
		out_bytearray = merge_bytearray_and_wav(file_to_save,wav_in)
		write_wave_from_bytearray(wav_out_name,out_bytearray,parameters_wav)
	else:
		print("Encryption Failed.")

def decrypt_file_from_wav(main_keystore):
	wav_in_file = input("WAV file to read: ")
	if is_file_accessible(wav_in_file) == False:
		print("File Not Found")
		return False
	file_out_name = input("File name to save into:")
	wav_bytes, parameters_wav = read_wave_to_bytearray(wav_in_file)
	input_bytearray = get_bytearray_from_wav(wav_bytes)
	file_to_save, hmac_state, decryption_done = decrypt_file(input_bytearray, main_keystore)
	if decryption_done == True:
		write_file_from_bytearray(file_out_name,file_to_save)
	else:
		print("Decryption Failed or Aborted.")

def print_information(main_keystore):
	read_file, file_name = user_file_prompt("File to decrypt: ")
	if file_name == False:
		print("File Not Found")
		return False
	hmac_state, file_length, key_useless = extract_key_and_validate(read_file, main_keystore)
	if hmac_state == True:
		print("HMAC Correct.")
		print("The file length is:",file_length,"bytes.")
	else:
		print("HMAC Failed.")

def change_password_main(main_keystore):
	read_file, file_name = user_file_prompt("File to decrypt: ")
	if file_name == False:
		print("File Not Found")
		return False
	hmac_state, file_length, key = extract_key_and_validate(read_file, main_keystore)
	if hmac_state == True:
		print("HMAC Correct. Password change possible.")
		new_file, change_done = change_already_validated_header(read_file, key, file_length, main_keystore)
		if change_done == True:
			write_file_from_bytearray(file_name,new_file)
			print("Password Change Applied")
		else:
			print("Password Change Failed.")
	else:
		print("HMAC Failed. Password change aborted.")