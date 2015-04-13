import getpass
from lib_file_ops import *
from lib_keyslot import is_header_psk
def input_int_until_list_or_default(list_desired, default_val):
	is_done = False
	while is_done == False:
		try:
			tv = int(input())
			if tv in list_desired:
				is_done = True
			else:
				print('Incorrect Value')
		except ValueError:
			tv = default_val
			is_done = True
	return tv
	
def input_password_until_match():
	pass_ok = False
	while pass_ok == False:
		passwn = getpass.getpass('Password: ')
		passwn_check = getpass.getpass('Confirm password: ')
		if passwn == passwn_check:
			pass_ok = True
		else:
			print("Passwords don't match, please retry.")
	return passwn

def force_integer_input(des_str):
	cor_key = False
	while cor_key == False:
		try:
			ipt = int(input(des_str))
			cor_key = True
		except ValueError:
			print("Try again.")
	return ipt

def user_file_prompt(prompt_string):
	file_name = input(prompt_string)
	file_condition = is_file_accessible(file_name)
	if file_condition == True:
		return read_file_to_bytearray(file_name), file_name
	else:
		return False, file_name

def user_encryption_type_prompt(allow_rsa):
	encryption_type = 1
	if allow_rsa == True:
		print("1: PSK, 2: RSA.")
		encryption_type = input_int_until_list_or_default([1,2],1)
	if encryption_type == 1:
		password = input_password_until_match()
		return True, password
	else:
		return False, False
def user_decryption_prompt(b0f):
	if is_header_psk(b0f) == True:
		password = input_password_until_match()
		return True, password
	else:
		return False, False
	