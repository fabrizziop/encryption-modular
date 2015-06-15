from tkinter import *
from tkinter import ttk
from lib_main_procedure import *
from lib_gui import *
from lib_file_ops import *
class main_program_gui(Frame):
	def __init__(self,parent):
		Frame.__init__(self,parent)
		self.parent = parent
		self.keystore = rsa_keystore()
		self.current_key_selection= [False,False]
		#self.keystore.import_key()
		self.init_ui()
		self.pack()
	def init_ui(self):
		# self.state_cheap_hack = state_saver_and_closer(self.parent)
		self.parent.title("Modular Encryption r2.0.1")
		self.parent.geometry("864x524")
		self.frame_notebook = ttk.Notebook(self)
		self.keystore_frame = ttk.Frame(self.frame_notebook)
		self.create_keystore_frame()
		self.file_encryption_frame = ttk.Frame(self.frame_notebook)
		self.create_file_encryption_frame()
		self.wav_steg_frame = ttk.Frame(self.frame_notebook)
		self.create_wav_steganography_frame()
		self.change_pass_frame = ttk.Frame(self.frame_notebook)
		self.create_change_pass_frame()
		self.file_info_frame = ttk.Frame(self.frame_notebook)
		self.create_file_info_frame()
		self.file_sign_frame = ttk.Frame(self.frame_notebook)
		self.create_file_sign_frame()
		self.frame_notebook.add(self.keystore_frame, text="RSA keystore")
		self.frame_notebook.add(self.file_encryption_frame, text="File Encryption")
		self.frame_notebook.add(self.wav_steg_frame, text="WAV Steganography")
		self.frame_notebook.add(self.change_pass_frame, text="Change Pass")
		self.frame_notebook.add(self.file_info_frame, text="File Info")
		self.frame_notebook.add(self.file_sign_frame, text="File Signing")
		# self.button_quit = ttk.Button(self, text="Quit",command=self.state_cheap_hack.set_false)
		# self.button_quit.pack(side="bottom")
		self.frame_notebook.pack()
		self.pack()
	def populate_keystore_frame(self,frame_to_populate,private_required):
		self.current_key_selection = IntVar()
		ttk.Label(frame_to_populate,text="##",width=2,font="TkFixedFont").grid(row=0,column=0,padx=15,pady=10)
		ttk.Label(frame_to_populate,text="          Fingerprints          ",width=32,font="TkFixedFont").grid(row=0,column=1,padx=15,pady=10)
		ttk.Label(frame_to_populate,text="Priv",width=4,font="TkFixedFont").grid(row=0,column=2,padx=15,pady=10)
		ttk.Label(frame_to_populate,text="S",width=1,font="TkFixedFont").grid(row=0,column=3,padx=15,pady=10)
		for i in range(0,12):
			if (i+1 <= len(self.keystore.key_fingerprint_list)):
				ttk.Label(frame_to_populate,text=str(i+1),font="TkFixedFont").grid(row=i+1,column=0,padx=15,pady=4)
				ttk.Label(frame_to_populate,text=str(bytes.decode(binascii.hexlify(self.keystore.key_fingerprint_list[i]))),font="TkFixedFont").grid(row=i+1,column=1,padx=15,pady=4)
				ttk.Label(frame_to_populate,text=str(self.keystore.key_list[i].has_private()),font="TkFixedFont").grid(row=i+1,column=2,padx=15,pady=4)
				if (private_required == True and self.keystore.key_list[i].has_private()==True) or private_required == False :
					ttk.Radiobutton(frame_to_populate,variable=self.current_key_selection,value=i).grid(row=i+1,column=3,padx=15,pady=4)
				else:
					ttk.Radiobutton(frame_to_populate,variable=self.current_key_selection,value=i,state="disabled").grid(row=i+1,column=3,padx=15,pady=4)
			else:
				ttk.Label(frame_to_populate,text="--",font="TkFixedFont").grid(row=i+1,column=0,padx=15,pady=4)
				ttk.Label(frame_to_populate,text="----------------------------------------------------------------",font="TkFixedFont").grid(row=i+1,column=1,padx=15,pady=4)
				ttk.Label(frame_to_populate,text="----",font="TkFixedFont").grid(row=i+1,column=2,padx=15,pady=4)
				ttk.Radiobutton(frame_to_populate,variable=self.current_key_selection,value=i,state="disabled").grid(row=i+1,column=3,padx=15,pady=4)
				pass
	def create_keystore_frame(self):
		self.keystore_frame_temporal = ttk.Frame(self.keystore_frame)
		self.populate_keystore_frame(self.keystore_frame_temporal,False)
		self.button_frame = ttk.Frame(self.keystore_frame_temporal)
		b1 = ttk.Button(self.button_frame,text="Generate Key",command=self.generate_key_rsa)
		b2 = ttk.Button(self.button_frame,text="Import Key",command=self.import_key_rsa)
		b3 = ttk.Button(self.button_frame,text="Export Key",command=self.export_key_rsa)
		b4 = ttk.Button(self.button_frame,text="Copy Public Key",command=self.clone_public_key_rsa)
		b5 = ttk.Button(self.button_frame,text="Delete Key",command=self.delete_key_rsa)
		b1.grid(row=0,column=0)
		b2.grid(row=0,column=1)
		b3.grid(row=0,column=2)
		b4.grid(row=0,column=3)
		b5.grid(row=0,column=4)
		if len(self.keystore.key_fingerprint_list) == 12:
			b1.state(["disabled"])
			b2.state(["disabled"])
			b4.state(["disabled"])
		if len(self.keystore.key_fingerprint_list) == 0:
			b3.state(["disabled"])
			b4.state(["disabled"])
			b5.state(["disabled"])
		self.button_frame.grid(row=13,column=0,columnspan=3)
		self.keystore_frame_temporal.pack()
	def refresh_keystore_frame(self):
		self.keystore_frame_temporal.destroy()
		self.create_keystore_frame()
	def generate_key_rsa(self):
		self.keystore.generate_key()
		self.refresh_keystore_frame()
	def import_key_rsa(self):
		temp_filename = gui_get_filename_to_open()
		self.keystore.import_key(read_file_to_bytearray(temp_filename))
		self.refresh_keystore_frame()
	def export_key_rsa(self):
		self.keystore.export_key(self.current_key_selection.get())
		self.refresh_keystore_frame()
	def clone_public_key_rsa(self):
		self.keystore.create_public_from_private(self.current_key_selection.get())
		self.refresh_keystore_frame()
	def delete_key_rsa(self):
		self.keystore.delete_key(self.current_key_selection.get())
		self.refresh_keystore_frame()
	# def is_keystore_able_to_encrypt(self):
		# is_able = False
		# if len(self.keystore.key_fingerprint_list) > 0:
			# is_able = True
		# return is_able
	# def is_keystore_able_to_decrypt(self):
		# is_able = False
		# for i in range(0,12):
			# if self.keystore.key_list[i].has_private() == True:
				# is_able = True
		# return is_able
	def encrypt_decrypt_file(self):
		if self.file_encryption_encrypt_or_decrypt.get() == 0:
			encrypt_file_with_full_prompt(self.keystore,self.file_path_object.filepath)
		else:
			decrypt_file_with_full_prompt(self.keystore,self.file_path_object.filepath)
	def create_file_encryption_frame(self):
		self.file_path_object = file_dialog_state_saver()
		self.file_encryption_frame_temporal = ttk.Frame(self.file_encryption_frame)
		self.file_encryption_encrypt_or_decrypt = IntVar()
		self.file_l1 = ttk.Label(self.file_encryption_frame_temporal,text="The file is encrypted or decrypted in place")
		self.file_l1.grid(row=0,column=1)
		self.file_l2 = ttk.Label(self.file_encryption_frame_temporal,textvariable=self.file_path_object.filepathvar)
		self.file_l2.grid(row=1,column=1)
		self.file_b1 = ttk.Button(self.file_encryption_frame_temporal,text="Open...",command=self.file_path_object.get_open_path)
		self.file_b1.grid(row=1,column=0)
		ttk.Radiobutton(self.file_encryption_frame_temporal,text="Encrypt",variable=self.file_encryption_encrypt_or_decrypt,value=0).grid(row=2,column=0,padx=15,pady=4)
		ttk.Radiobutton(self.file_encryption_frame_temporal,text="Decrypt",variable=self.file_encryption_encrypt_or_decrypt,value=1).grid(row=2,column=1,padx=15,pady=4)
		self.file_b2 = ttk.Button(self.file_encryption_frame_temporal,text="Encrypt/Decrypt",command=self.encrypt_decrypt_file)
		self.file_b2.grid(row=3,column=0, columnspan=2)
		self.file_encryption_frame_temporal.pack()
	def wav_steganography_update_buttons(self):
		if self.wav_steg_encrypt_or_decrypt.get() == 0:
			self.wav_b1.state(["!disabled"])
			self.wav_b2.state(["!disabled"])
			self.wav_b3.state(["!disabled"])
			self.wav_b4.state(["disabled"])
			self.wav_b5.state(["!disabled"])
			self.wav_b6.state(["disabled"])
		elif self.wav_steg_encrypt_or_decrypt.get() == 1:
			self.wav_b1.state(["!disabled"])
			self.wav_b2.state(["disabled"])
			self.wav_b3.state(["disabled"])
			self.wav_b4.state(["!disabled"])
			self.wav_b5.state(["disabled"])
			self.wav_b6.state(["!disabled"])
	def wav_calculate(self):
		encryption_possible = False
		file_length = False
		if is_file_accessible(self.wav_path_object_3.filepath) == True:
			file_length = read_file_length(self.wav_path_object_3.filepath)+3200
		self.wav_space_var_1.set(str(file_length))
		wav_length = calculate_max_wave_encryption(self.wav_path_object_1.filepath)
		self.wav_space_var_2.set(str(wav_length))
		if file_length <= wav_length:
			self.wav_b6.state(["!disabled"])
		else:
			self.wav_b6.state(["disabled"])
	def wav_encrypt_decrypt_file(self):
		if self.wav_steg_encrypt_or_decrypt.get() == 0:
			encrypt_file_into_wav(self.keystore,self.wav_path_object_3.filepath,self.wav_path_object_1.filepath,self.wav_path_object_2.filepath)
		elif self.wav_steg_encrypt_or_decrypt.get() == 1:
			decrypt_file_from_wav(self.keystore,self.wav_path_object_1.filepath,self.wav_path_object_4.filepath)
	def create_wav_steganography_frame(self):
		self.wav_path_object_1 = file_dialog_state_saver()
		self.wav_path_object_2 = file_dialog_state_saver()
		self.wav_path_object_3 = file_dialog_state_saver()
		self.wav_path_object_4 = file_dialog_state_saver()
		self.wav_space_var_1 = StringVar()
		self.wav_space_var_2 = StringVar()
		self.wav_steg_frame_temporal = ttk.Frame(self.wav_steg_frame)
		self.wav_steg_encrypt_or_decrypt = IntVar()
		self.wav_l1 = ttk.Label(self.wav_steg_frame_temporal,text="In encrypt mode, WAV input and FILE input are combined. In decrypt mode, WAV input and FILE output")
		self.wav_l1.grid(row=0,column=1)
		self.wav_l2 = ttk.Label(self.wav_steg_frame_temporal,textvariable=self.wav_path_object_1.filepathvar)
		self.wav_l2.grid(row=1,column=1)
		self.wav_l3 = ttk.Label(self.wav_steg_frame_temporal,textvariable=self.wav_path_object_2.filepathvar)
		self.wav_l3.grid(row=2,column=1)
		self.wav_l4 = ttk.Label(self.wav_steg_frame_temporal,textvariable=self.wav_path_object_3.filepathvar)
		self.wav_l4.grid(row=3,column=1)
		self.wav_l5 = ttk.Label(self.wav_steg_frame_temporal,textvariable=self.wav_path_object_4.filepathvar)
		self.wav_l5.grid(row=4,column=1)
		self.wav_b1 = ttk.Button(self.wav_steg_frame_temporal,text="Open WAV input... ",command=self.wav_path_object_1.get_open_path)
		self.wav_b1.grid(row=1,column=0)
		self.wav_b2 = ttk.Button(self.wav_steg_frame_temporal,text="Open WAV output...",command=self.wav_path_object_2.get_save_path)
		self.wav_b2.grid(row=2,column=0)
		self.wav_b3 = ttk.Button(self.wav_steg_frame_temporal,text="Open FILE input...",command=self.wav_path_object_3.get_open_path)
		self.wav_b3.grid(row=3,column=0)
		self.wav_b4 = ttk.Button(self.wav_steg_frame_temporal,text="Open FILE output..",command=self.wav_path_object_4.get_save_path,state="disabled")
		self.wav_b4.grid(row=4,column=0)
		ttk.Radiobutton(self.wav_steg_frame_temporal,text="FILE -> WAV",variable=self.wav_steg_encrypt_or_decrypt,value=0).grid(row=5,column=0,padx=15,pady=4)
		ttk.Radiobutton(self.wav_steg_frame_temporal,text="FILE <- WAV",variable=self.wav_steg_encrypt_or_decrypt,value=1).grid(row=5,column=1,padx=15,pady=4)
		self.wav_steg_encrypt_or_decrypt.trace_variable('w',lambda x,y,z:self.wav_steganography_update_buttons())
		self.wav_b5 = ttk.Button(self.wav_steg_frame_temporal,text="Calculate",command=self.wav_calculate)
		self.wav_b5.grid(row=6,column=0)
		self.wav_b6 = ttk.Button(self.wav_steg_frame_temporal,text="Encrypt/Decrypt",command=self.wav_encrypt_decrypt_file,state="disabled")
		self.wav_b6.grid(row=6,column=1)
		self.wav_l6 = ttk.Label(self.wav_steg_frame_temporal,text="Length Required")
		self.wav_l6.grid(row=7,column=0)
		self.wav_l7 = ttk.Label(self.wav_steg_frame_temporal,text="Space Available")
		self.wav_l7.grid(row=7,column=1)
		self.wav_l8 = ttk.Label(self.wav_steg_frame_temporal,textvariable=self.wav_space_var_1)
		self.wav_l8.grid(row=8,column=0)
		self.wav_l9 = ttk.Label(self.wav_steg_frame_temporal,textvariable=self.wav_space_var_2)
		self.wav_l9.grid(row=8,column=1)
		self.wav_steg_frame_temporal.pack()
	def change_pass_file(self):
		change_password_main(self.keystore,self.pass_path_object.filepath)
	def create_change_pass_frame(self):
		self.pass_path_object = file_dialog_state_saver()
		self.change_pass_frame_temporal = ttk.Frame(self.change_pass_frame)
		self.pass_l1 = ttk.Label(self.change_pass_frame_temporal,text="This is ONLY for NORMAL PSK/RSA encrypted files. NOT for steganography")
		self.pass_l1.grid(row=0,column=1)
		self.pass_l2 = ttk.Label(self.change_pass_frame_temporal,textvariable=self.pass_path_object.filepathvar)
		self.pass_l2.grid(row=1,column=1)
		self.pass_b1 = ttk.Button(self.change_pass_frame_temporal,text="Open...",command=self.pass_path_object.get_open_path)
		self.pass_b1.grid(row=1,column=0)
		self.pass_b2 = ttk.Button(self.change_pass_frame_temporal,text="Change Password",command=self.change_pass_file)
		self.pass_b2.grid(row=2,column=0, columnspan=2)
		self.change_pass_frame_temporal.pack()
	def file_info_file(self):
		print_information(self.keystore,self.file_info_path_object.filepath)
	def create_file_info_frame(self):
		self.file_info_path_object = file_dialog_state_saver()
		self.file_info_frame_temporal = ttk.Frame(self.file_info_frame)
		self.file_info_l1 = ttk.Label(self.file_info_frame_temporal,text="This is ONLY for NORMAL PSK/RSA encrypted files. NOT for steganography")
		self.file_info_l1.grid(row=0,column=1)
		self.file_info_l2 = ttk.Label(self.file_info_frame_temporal,textvariable=self.file_info_path_object.filepathvar)
		self.file_info_l2.grid(row=1,column=1)
		self.file_info_b1 = ttk.Button(self.file_info_frame_temporal,text="Open...",command=self.file_info_path_object.get_open_path)
		self.file_info_b1.grid(row=1,column=0)
		self.file_info_b2 = ttk.Button(self.file_info_frame_temporal,text="Show File Info",command=self.file_info_file)
		self.file_info_b2.grid(row=2,column=0, columnspan=2)
		self.file_info_frame_temporal.pack()
	def file_sign_file(self):
		if self.file_sign_or_verify.get() == 0:
			sign_file(self.keystore,self.file_sign_object.filepath)
		else:
			verify_file(self.keystore,self.file_sign_object.filepath)
	def create_file_sign_frame(self):
		self.file_sign_object = file_dialog_state_saver()
		self.file_sign_frame_temporal = ttk.Frame(self.file_sign_frame)
		self.file_sign_or_verify = IntVar()
		self.file_sign_l1 = ttk.Label(self.file_sign_frame_temporal,text="The file signature is appended at the end")
		self.file_sign_l1.grid(row=0,column=1)
		self.file_sign_l2 = ttk.Label(self.file_sign_frame_temporal,textvariable=self.file_sign_object.filepathvar)
		self.file_sign_l2.grid(row=1,column=1)
		self.file_sign_b1 = ttk.Button(self.file_sign_frame_temporal,text="Open...",command=self.file_sign_object.get_open_path)
		self.file_sign_b1.grid(row=1,column=0)
		ttk.Radiobutton(self.file_sign_frame_temporal,text="Sign",variable=self.file_sign_or_verify,value=0).grid(row=2,column=0,padx=15,pady=4)
		ttk.Radiobutton(self.file_sign_frame_temporal,text="Verify",variable=self.file_sign_or_verify,value=1).grid(row=2,column=1,padx=15,pady=4)
		self.file_sign_b2 = ttk.Button(self.file_sign_frame_temporal,text="Sign/Verify",command=self.file_sign_file)
		self.file_sign_b2.grid(row=3,column=0, columnspan=2)
		self.file_sign_frame_temporal.pack()
		