from lib_user_input import *
from lib_main_crypto import *
from lib_rsa import *
from lib_file_ops import *
from lib_wave import *
from lib_random import *
from lib_misc import *
from lib_gui import *

def encrypt_file_with_full_prompt(main_keystore, file_name):
	read_file = read_file_to_bytearray(file_name)
	if read_file == False:
		showerror(title="File not found", message="File not found")
		return False
	file_to_save, encryption_done = encrypt_file(read_file, main_keystore)
	if encryption_done == True:
		# Appending random bytes at the end, to obfuscate the actual file length.
		file_to_save.extend(create_random_key(rng.randint(128,131072)))
		write_file_from_bytearray(file_name,file_to_save)
		showinfo(title="Encryption Successful",message="Encryption Successful")
		return True
	else:
		showerror(title="Encryption Failed.",message="Encryption Failed.")
		return False
	
def decrypt_file_with_full_prompt(main_keystore, file_name):
	read_file = read_file_to_bytearray(file_name)
	if read_file == False:
		showerror(title="File not found", message="File not found")
		return False
	file_to_save, hmac_state, decryption_done = decrypt_file(read_file, main_keystore)
	if decryption_done == True:
		write_file_from_bytearray(file_name,file_to_save)
		showinfo(title="Decryption Successful",message="Decryption Successful")
		return True
	else:
		showerror(title="Decryption Failed.",message="Decryption Failed.")
		return False

def encrypt_file_into_wav(main_keystore, file_name, wav_in_file, wav_out_name):
	read_file = read_file_to_bytearray(file_name)
	if read_file == False:
		showerror(title="File not found", message="File not found")
		return False
	min_len = len(read_file)
	max_len = calculate_max_wave_encryption(wav_in_file)
	# Being sure that the file actually WILL fit into the wav.
	# print('Length of file to encrypt:',min_len+3200)
	# print('Length available in WAV:', max_len)
	# if (min_len+3200) > max_len:
		# print("File won't fit into WAV.")
		# return False
	file_to_save, encryption_done = encrypt_file(read_file, main_keystore)
	if encryption_done == True:
		wav_in, parameters_wav = read_wave_to_bytearray(wav_in_file)
		out_bytearray = merge_bytearray_and_wav(file_to_save,wav_in)
		write_wave_from_bytearray(wav_out_name,out_bytearray,parameters_wav)
		showinfo(title="Encryption Successful",message="Encryption and WAV Steganography Successful")
	else:
		showerror(title="Encryption Failed.",message="Encryption Failed.")

def decrypt_file_from_wav(main_keystore,wav_in_file,file_out_name):
	if is_file_accessible(wav_in_file) == False:
		showerror(title="File not found", message="File not found")
		return False
	wav_bytes, parameters_wav = read_wave_to_bytearray(wav_in_file)
	input_bytearray = get_bytearray_from_wav(wav_bytes)
	file_to_save, hmac_state, decryption_done = decrypt_file(input_bytearray, main_keystore)
	if decryption_done == True:
		write_file_from_bytearray(file_out_name,file_to_save)
		showinfo(title="Decryption Successful",message="WAV Steganography and Decryption Successful")
	else:
		showerror(title="Decryption Failed.",message="Decryption Failed.")

def print_information(main_keystore,file_name):
	read_file = read_file_to_bytearray(file_name)
	if read_file == False:
		print("File Not Found")
		return False
	hmac_state, file_length, key_useless = extract_key_and_validate(read_file, main_keystore)
	if hmac_state == True:
		showinfo(title="HMAC Correct",message="HMAC OK, integrity and authenticity verified, the file length is "+str(file_length)+" bytes.")
	else:
		showerror(title="HMAC Fail",message="HMAC Fail, integrity and authenticity NOT guaranteed")

def change_password_main(main_keystore, file_name):
	read_file = read_file_to_bytearray(file_name)
	if read_file == False:
		showerror(title="File not found", message="File not found")
		return False
	hmac_state, file_length, key = extract_key_and_validate(read_file, main_keystore)
	if hmac_state == True:
		showinfo(title="HMAC OK",message="HMAC OK. Password change possible.")
		new_file, change_done = change_already_validated_header(read_file, key, file_length, main_keystore)
		if change_done == True:
			write_file_from_bytearray(file_name,new_file)
			showinfo(title="Password Change OK",message="Password changed correctly")
		else:
			showerror(title="Password Change FAIL",message="Password change failed.")
	else:
		showerror(title="HMAC Fail",message="HMAC Failed. Password change aborted.")

def sign_file(main_keystore, file_name):
	read_file = read_file_to_bytearray(file_name)
	if read_file == False:
		showerror(title="File not found", message="File not found")
		return False
	signature = main_keystore.sign_rsa(read_file)
	if signature == None:
		showerror(title="Signature FAIL",message="Signature creation failed.")
		return None
	elif type(signature) == bytearray:
		read_file.extend(signature)
		write_file_from_bytearray(file_name, read_file)
		showinfo(title="Signature OK",message="Signature creation successful.")

def verify_file(main_keystore, file_name):
	read_file = read_file_to_bytearray(file_name)
	if read_file == False:
		showerror(title="File not found", message="File not found")
		return False
	verify_status, key_used = main_keystore.verify_rsa(read_file)
	if verify_status == True:
		showinfo(title="Signature OK",message="Signature OK from "+str(key_used))
		return None
	elif verify_status == False:
		showerror(title="Signature BAD",message="Signature BAD from "+str(key_used))
		return None
	elif verify_status == None:
		showerror(title="Signature FAIL",message="Signature Verification Failed.")
		return None
	return None