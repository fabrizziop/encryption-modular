def is_file_accessible(file_name):
	try:
		test_file = open(file_name,'r')
		test_file.close()
		return True
	except:
		return False

# NEEDS TO OUTPUT FALSE IF ERROR
def read_file_to_bytearray(file_name):
	try:
		test_file = open(file_name,'rb')
		output = bytearray(test_file.read())
		test_file.close()
		return output
	except FileNotFoundError:
		return False
def read_file_length(file_name):
	try:
		test_file = open(file_name,'rb')
		output = len(test_file.read())
		test_file.close()
		return output
	except FileNotFoundError:
		return False
	
def write_file_from_bytearray(file_name,input_bytearray):
	if input_bytearray != None:
		test_file = open(file_name,'wb')
		test_file.write(input_bytearray)
		test_file.close()
	return True

