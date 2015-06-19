from tkinter import *
from tkinter import ttk
import binascii
import time
from tkinter.filedialog import askopenfilename, asksaveasfilename
from tkinter.messagebox import askyesno, showinfo, showwarning, showerror, askyesno
class state_saver(object):
	def __init__(self):
		self.state = True
	def set_false(self):
		self.state = False
	def set_true(self):
		self.state = True
class state_saver_and_closer(object):
	def __init__(self,window_main):
		self.state = True
		self.window_main = window_main
	def set_false(self):
		self.state = False
		self.window_main.destroy()
	def set_true(self):
		self.state = True
		self.window_main.destroy()
# THIS SHOULD BE MERGED ABOVE! VERY CHEAP HACK!
class state_saver_and_closer_rsa(object):
	def __init__(self,window_main):
		self.state = True
		self.stateloop = True
		self.window_main = window_main
	def set_false(self):
		self.state = False
		self.stateloop = False
	def set_true(self):
		self.state = True
		self.stateloop = False
class file_dialog_state_saver(object):
	def __init__(self):
		self.filepath = ""
		self.filepathvar = StringVar()
	def get_open_path(self):
		# Tk().withdraw()
		self.filepath = askopenfilename()
		self.filepathvar.set(self.filepath)
	def get_save_path(self):
		# Tk().withdraw()
		self.filepath = asksaveasfilename()
		self.filepathvar.set(self.filepath)
class simple_progress_popup_determinate(object):
	def __init__(self,maximum,title,prompt_string):
		self.new_win = Toplevel()
		self.new_win.geometry("336x80")
		self.new_win.title(title)
		self.label1 = ttk.Label(self.new_win,text=prompt_string)
		# self.label1.grid(row=0,column=0,padx=8,pady=5)
		self.label1.pack(side="top",padx=8,pady=5)
		self.progressbar1 = ttk.Progressbar(self.new_win,length=288,mode='determinate',maximum=maximum)
		# self.progressbar1.grid(row=1,column=0,padx=8,pady=5)
		self.progressbar1.pack(side="top",padx=8,pady=5)
		self.new_win.update()
	def step_progress(self):
		self.progressbar1.step()
		self.new_win.update()
	def destroy_progress(self):
		self.new_win.destroy()
class simple_progress_popup_indeterminate(object):
	def __init__(self,title,prompt_string):
		self.new_win = Toplevel()
		self.new_win.geometry("336x80")
		self.new_win.title(title)
		self.label1 = ttk.Label(self.new_win,text=prompt_string)
		# self.label1.grid(row=0,column=0,padx=8,pady=5)
		self.label1.pack(side="top",padx=8,pady=5)
		self.progressbar1 = ttk.Progressbar(self.new_win,length=288,mode='indeterminate')
		# self.progressbar1.grid(row=1,column=0,padx=8,pady=5)
		self.progressbar1.pack(side="top",padx=8,pady=5)
		self.progressbar1.start()
		self.new_win.update()
	def destroy_progress(self):
		self.new_win.destroy()
def gui_get_filename_to_open():
	# Tk().withdraw()
	filename = askopenfilename()
	return filename
def gui_get_filename_to_save():
	# Tk().withdraw()
	filename = asksaveasfilename()
	return filename
def destroy_win(window):
	window.destroy()
def simple_password_prompt(prompt_string):
	new_win = Toplevel()
	loop_state_obj = state_saver_and_closer_rsa(new_win)
	new_win.geometry("192x128")
	new_win.title("Password Prompt")
	password1 = StringVar()
	label1 = ttk.Label(new_win,text=prompt_string)
	# label1.grid(row=0,column=0,padx=5,pady=5)
	label1.pack(side="top",padx=5,pady=5)
	entry1 = ttk.Entry(new_win,textvariable=password1,show="*")
	# entry1.grid(row=1,column=0,padx=5,pady=5)
	entry1.pack(side="top",padx=5,pady=5)
	entry1.focus()
	btn1 = ttk.Button(new_win,text='OK',command=loop_state_obj.set_false)
	# btn1.grid(row=2,column=0,padx=5,pady=5)
	btn1.pack(side="top",padx=5,pady=5)
	entry1.bind('<Return>',lambda _:loop_state_obj.set_false())
	while loop_state_obj.stateloop == True:
		new_win.update()
		time.sleep(0.02)
	new_win.destroy()
	return password1.get()
def ask_psk_or_rsa():
	new_win = Toplevel()
	loop_state_obj = state_saver_and_closer_rsa(new_win)
	new_win.geometry("256x96")
	new_win.title("PSK or RSA")
	label1 = ttk.Label(new_win,text="Choose PSK or RSA encryption")
	# label1.grid(row=0,column=0,columnspan=2,padx=5,pady=5)
	label1.pack(side="top",padx=5,pady=5)
	btn1 = ttk.Button(new_win,text='PSK',command=loop_state_obj.set_true)
	# btn1.grid(row=1,column=0,padx=5,pady=5)
	btn1.pack(side="left",padx=15,pady=5)
	btn2 = ttk.Button(new_win,text='RSA',command=loop_state_obj.set_false)
	# btn2.grid(row=1,column=1,padx=5,pady=5)
	btn2.pack(side="right",padx=15,pady=5)
	while loop_state_obj.stateloop == True:
		new_win.update()
		time.sleep(0.02)
	new_win.destroy()
	return loop_state_obj.state

def ask_for_rsa_key(current_keystore, private_required):
	if len(current_keystore.key_fingerprint_list) == 0:
		return None
	if private_required == True:
		private_found = False
		for i in range(0,len(current_keystore.key_fingerprint_list)):
			if current_keystore.key_list[i].has_private()==True:
				private_found = True
		if private_found == False:
			return None
	new_win = Toplevel()
	new_win.geometry("864x524")
	loop_state_obj = state_saver_and_closer(new_win)
	current_key_selection = IntVar()
	current_key_selection.set(0)
	ttk.Label(new_win,text="##",width=2,font="TkFixedFont").grid(row=0,column=0,padx=15,pady=10)
	ttk.Label(new_win,text="          Fingerprints          ",width=32,font="TkFixedFont").grid(row=0,column=1,padx=15,pady=10)
	ttk.Label(new_win,text="Priv",width=4,font="TkFixedFont").grid(row=0,column=2,padx=15,pady=10)
	ttk.Label(new_win,text="S",width=1,font="TkFixedFont").grid(row=0,column=3,padx=15,pady=10)
	for i in range(0,12):
		if (i+1 <= len(current_keystore.key_fingerprint_list)):
			ttk.Label(new_win,text=str(i+1),font="TkFixedFont").grid(row=i+1,column=0,padx=15,pady=4)
			ttk.Label(new_win,text=str(bytes.decode(binascii.hexlify(current_keystore.key_fingerprint_list[i]))),font="TkFixedFont").grid(row=i+1,column=1,padx=15,pady=4)
			ttk.Label(new_win,text=str(current_keystore.key_list[i].has_private()),font="TkFixedFont").grid(row=i+1,column=2,padx=15,pady=4)
			if (private_required == True and current_keystore.key_list[i].has_private()==True) or private_required == False :
				ttk.Radiobutton(new_win,variable=current_key_selection,value=i).grid(row=i+1,column=3,padx=15,pady=4)
			else:
				ttk.Radiobutton(new_win,variable=current_key_selection,value=i,state="disabled").grid(row=i+1,column=3,padx=15,pady=4)
		else:
			ttk.Label(new_win,text="--",font="TkFixedFont").grid(row=i+1,column=0,padx=15,pady=4)
			ttk.Label(new_win,text="----------------------------------------------------------------",font="TkFixedFont").grid(row=i+1,column=1,padx=15,pady=4)
			ttk.Label(new_win,text="----",font="TkFixedFont").grid(row=i+1,column=2,padx=15,pady=4)
			ttk.Radiobutton(new_win,variable=current_key_selection,value=i,state="disabled").grid(row=i+1,column=3,padx=15,pady=4)
	ttk.Button(new_win,text="OK",command=loop_state_obj.set_false).grid(row=13,column=2)
	new_win.update()
	while loop_state_obj.state == True:
		new_win.update()
		time.sleep(0.02)
	return current_key_selection.get()

def button_compare(e1,e2,button):
	p1 = e1.get()
	p2 = e2.get()
	if p1==p2:
		button.state(["!disabled"])
	else:
		button.state(["disabled"])
def compare_and_destroy_window(e1,e2,window):
	p1 = e1.get()
	p2 = e2.get()
	if p1==p2:
		window.stateloop = False
	else:
		pass
def dual_password_prompt(prompt_string):
	new_win = Toplevel()
	loop_state_obj = state_saver_and_closer_rsa(new_win)
	new_win.geometry("192x160")
	new_win.title("Password Prompt")
	password1 = StringVar()
	password2 = StringVar()
	label1 = ttk.Label(new_win,text=prompt_string)
	label1.pack(side="top",padx=5,pady=5)
	entry1 = ttk.Entry(new_win,textvariable=password1,show="*")
	entry2 = ttk.Entry(new_win,textvariable=password2,show="*")
	entry1.pack(side="top",padx=5,pady=5)
	entry2.pack(side="top",padx=5,pady=5)
	entry1.focus()
	btn1 = ttk.Button(new_win,text='OK',command=loop_state_obj.set_false)
	btn1.pack(side="top",padx=5,pady=5)
	password1.trace_variable('w',lambda x,y,z:button_compare(entry1,entry2,btn1))
	password2.trace_variable('w',lambda x,y,z:button_compare(entry1,entry2,btn1))
	entry1.bind('<Return>',lambda _:compare_and_destroy_window(password1,password2,loop_state_obj))
	entry2.bind('<Return>',lambda _:compare_and_destroy_window(password1,password2,loop_state_obj))
	while loop_state_obj.stateloop == True:
		new_win.update()
		time.sleep(0.02)
	new_win.destroy()
	return password1.get()

		
