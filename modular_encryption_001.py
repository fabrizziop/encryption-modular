from lib_user_input import *
from lib_main_crypto import *
from lib_rsa import *
from lib_file_ops import *
from lib_wave import *
main_keystore = rsa_keystore()
def encrypt_file_with_full_prompt():
	read_file, file_name = user_file_prompt("File to encrypt: ")
	if file_name == False:
		print("File Not Found")
		return False
	file_to_save, encryption_done = encrypt_file(read_file, main_keystore)
	if encryption_done == True:
		write_file_from_bytearray(file_name,file_to_save)
	else:
		print("Encryption Failed.")
	
def decrypt_file_with_full_prompt():
	read_file, file_name = user_file_prompt("File to decrypt: ")
	if file_name == False:
		print("File Not Found")
		return False
	file_to_save, hmac_state, decryption_done = decrypt_file(read_file, main_keystore)
	if decryption_done == True:
		write_file_from_bytearray(file_name,file_to_save)
	else:
		print("Decryption Failed or Aborted.")

def encrypt_file_into_wav():
	read_file, file_name = user_file_prompt("File to encrypt: ")
	wav_in_file = input("WAV file to read: ")
	wav_out_name = input("File name to save into:")
	file_to_save, encryption_done = encrypt_file(read_file, main_keystore)
	wav_in, parameters_wav = read_wave_to_bytearray(wav_in_file)
	out_bytearray = merge_bytearray_and_wav(file_to_save,wav_in)
	write_wave_from_bytearray(wav_out_name,out_bytearray,parameters_wav)

def decrypt_file_from_wav():
	wav_in_file = input("WAV file to read: ")
	file_out_name = input("File name to save into:")
	wav_bytes, parameters_wav = read_wave_to_bytearray(wav_in_file)
	input_bytearray = get_bytearray_from_wav(wav_bytes)
	file_to_save, hmac_state, decryption_done = decrypt_file(input_bytearray, main_keystore)
	if decryption_done == True:
		write_file_from_bytearray(file_out_name,file_to_save)
	else:
		print("Decryption Failed or Aborted.")

def main_loop(current_keystore):
	loop_done = False
	while loop_done == False:
		print("1: Encrypt, 2: Decrypt, 3: Keystore, 4: WAV.")
		option = input_int_until_list_or_default([1,2,3,4,99],100)
		if option == 1:
			encrypt_file_with_full_prompt()
		elif option == 2:
			decrypt_file_with_full_prompt()
		elif option == 3:
			rsa_loop = True
			while rsa_loop == True:
				try:	
					print("1: Generate Key, 2: Export Key, 3: Import Key, 4: View Keys, 5: Delete Key, 99: Exit ")
					rsaop = input_int_until_list_or_default([1,2,3,4,5,99],100)
				except ValueError:
					rsaop = 100
				if rsaop == 1:
					current_keystore.generate_key()
				elif rsaop == 2:
					current_keystore.export_key()
				elif rsaop == 3:
					current_keystore.import_key()
				elif rsaop == 4:
					current_keystore.view_keys()
				elif rsaop == 5:
					current_keystore.delete_key()
				elif rsaop == 99:
					rsa_loop = False
				else:
					print('Invalid option')
		elif option == 4:
			wav_loop = True
			while wav_loop == True:
				print("1: Encrypt into WAV, 2: Decrypt from WAV.")
				rsaop = input_int_until_list_or_default([1,2,99],100)
				if rsaop == 1:
					encrypt_file_into_wav()
				elif rsaop == 2:
					decrypt_file_from_wav()
				elif rsaop == 99:
					wav_loop = False
				else:
					print('Invalid option')
		elif option == 99:
			loop_done = True
		else:
			pass
#encrypt_file_with_full_prompt()
#decrypt_file_with_full_prompt()
main_loop(main_keystore)