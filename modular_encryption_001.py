from lib_user_input import input_int_until_list_or_default
from lib_main_procedure import *
actual_keystore = rsa_keystore()


print("Modular Encryption 1.1.0")
print("by fabrizziop@github.com")
print("GNU GPLv2 License")
print()
def main_loop(current_keystore):
	loop_done = False
	while loop_done == False:
		print("1: Encrypt, 2: Decrypt, 3: Keystore, 4: WAV, 5: File Info")
		print("6: Change Password/RSA, 90: Help, 99: Exit.")
		option = input_int_until_list_or_default([1,2,3,4,5,6,90,99],100)
		if option == 1:
			encrypt_file_with_full_prompt(current_keystore)
		elif option == 2:
			decrypt_file_with_full_prompt(current_keystore)
		elif option == 3:
			rsa_loop = True
			while rsa_loop == True:
				try:	
					print("1: Generate Key, 2: Export Key, 3: Import Key, 4: View Keys.")
					print("5: Delete Key, 6: Create Public, 7: Sign, 8: Verify, 99: Exit.")
					rsaop = input_int_until_list_or_default([1,2,3,4,5,6,7,8,99],100)
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
				elif rsaop == 6:
					current_keystore.create_public_from_private()
				elif rsaop == 7:
					sign_file(current_keystore)
				elif rsaop == 8:
					verify_file(current_keystore)
				elif rsaop == 99:
					rsa_loop = False
				else:
					print('Invalid option')
		elif option == 4:
			wav_loop = True
			while wav_loop == True:
				print("1: Encrypt into WAV, 2: Decrypt from WAV, 99: Exit.")
				rsaop = input_int_until_list_or_default([1,2,99],100)
				if rsaop == 1:
					encrypt_file_into_wav(current_keystore)
				elif rsaop == 2:
					decrypt_file_from_wav(current_keystore)
				elif rsaop == 99:
					wav_loop = False
				else:
					print('Invalid option')
		elif option == 5:
			print_information(current_keystore)
		elif option == 6:
			change_password_main(current_keystore)
		elif option == 90:
			print("The cipher used is 3AES-256-EDE, in CTR mode, the keys")
			print("are 1024 bits long. From that key, three independent")
			print("keys are created for each AES-256 cipher object, and ")
			print("a 128-bit IV is created and used as a starting point")
			print("for the counter. No nonce is used as we don't reuse")
			print("keys, ever. The counter will wrap around at the end.")
			print("The header in PSK mode consists of two 512-bit salts")
			print("and two 512-bit encrypted keys. Each key is encrypted")
			print("by XORing the result of 4M PBKDF2-SHA512 iterations")
			print("of the password + salt. All files are HMAC'd, and that")
			print("is verified as soon as the program obtains the key.")
			print("Allowing password changes on WAV-hidden files isn't")
			print("smart. It will not __ever__ be implemented.")
		elif option == 99:
			loop_done = True
		else:
			pass

main_loop(actual_keystore)