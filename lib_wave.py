import wave
from lib_random import *
from lib_bitwise import *
def read_wave_to_bytearray(file_name):
	test_file = wave.open(file_name,'rb')
	parameters = test_file.getparams()
	output = bytearray(test_file.readframes(parameters[3]))
	test_file.close()
	return output, parameters
	
def write_wave_from_bytearray(file_name,input_bytearray, parameters):
	if input_bytearray != None:
		test_file = wave.open(file_name,'wb')
		test_file.setparams(parameters)
		test_file.writeframesraw(input_bytearray)
		test_file.close()
	return True
	
def merge_bytearray_and_wav(input_bytearray, wav_bytearray):
	cf = 0
	out_bytearray = bytearray()
	len_in = len(input_bytearray)
	for i in range(0,len_in):
		current_byte = input_bytearray[i]
		current_chunks = byte_to_2_bit_chunks(current_byte)
		#print(current_chunks)
		b1, b2, b3, b4, b5, b6, b7, b8 = wav_bytearray[i*8], wav_bytearray[(i*8)+1], wav_bytearray[(i*8)+2], wav_bytearray[(i*8)+3], wav_bytearray[(i*8)+4], wav_bytearray[(i*8)+5], wav_bytearray[(i*8)+6], wav_bytearray[(i*8)+7]
		b1 &= 0b11111100
		b1 |= current_chunks[0]
		b3 &= 0b11111100
		b3 |= current_chunks[1]
		b5 &= 0b11111100
		b5 |= current_chunks[2]
		b7 &= 0b11111100
		b7 |= current_chunks[3]
		#print(b1&0b11,b3&0b11,b5&0b11,b7&0b11)
		#print(b1, b2, b3, b4, b5, b6, b7, b8)
		out_bytearray.extend(bytes([b1,b2,b3,b4,b5,b6,b7,b8]))
	cpos = (len_in*8)
	while cpos < len(wav_bytearray):
		if cpos % 2 == 0:
			out_bytearray.append((wav_bytearray[cpos]&0b11111100)|rng.randint(0,3))
		else:
			out_bytearray.append(wav_bytearray[cpos])
		cpos +=1
	return out_bytearray
def get_bytearray_from_wav(wav_bytearray):
	out_bytearray = bytearray()
	ltu = len(wav_bytearray) // 8
	for i in range(0,ltu):
		#print(i)
		#print(len(wav_bytearray))
		b1, b2, b3, b4, b5, b6, b7, b8 = wav_bytearray[i*8], wav_bytearray[(i*8)+1], wav_bytearray[(i*8)+2], wav_bytearray[(i*8)+3], wav_bytearray[(i*8)+4], wav_bytearray[(i*8)+5], wav_bytearray[(i*8)+6], wav_bytearray[(i*8)+7]
		current_chunks = [b1&0b11,b3&0b11,b5&0b11,b7&0b11]
		current_byte = bit_2_chunks_to_byte(current_chunks)
		out_bytearray.append(current_byte)
	return out_bytearray