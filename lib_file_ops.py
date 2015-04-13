def is_file_accessible(file_name):
	try:
		test_file = open(file_name,'r')
		return True
	except:
		return False

def read_file_to_bytearray(file_name):
	test_file = open(file_name,'rb')
	output = bytearray(test_file.read())
	test_file.close()
	return output
	
def write_file_from_bytearray(file_name,input_bytearray):
	if input_bytearray != None:
		test_file = open(file_name,'wb')
		test_file.write(input_bytearray)
	return True

