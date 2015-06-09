from tkinter import Tk
from tkinter.filedialog import askopenfilename, asksaveasfilename
def gui_get_filename_to_open():
	Tk().withdraw()
	filename = askopenfilename()
	return filename
def gui_get_filename_to_save():
	Tk().withdraw()
	filename = asksaveasfilename()
	return filename