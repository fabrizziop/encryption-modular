import wave
import sys
from lib_random import *
from lib_bitwise import *
print_same_line = sys.stdout.write
def read_wave_parameters(file_name):
	test_file = wave.open(file_name,'rb')
	parameters = test_file.getparams()
	test_file.close()
	return parameters

def calculate_max_wave_encryption(file_name):
	parameters = read_wave_parameters(file_name)
	return parameters[0]*parameters[1]*parameters[3] // 8

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
	pc = max(len_in // 80,1)
	cnt = 0
	print("WAV Merging Progress:")
	for i in range(0,len_in):
		current_byte = input_bytearray[i]
		current_chunks = byte_to_2_bit_chunks(current_byte)
		#print(current_chunks)
		# Here we are splitting a byte into four 2-bit chunks. As WAVs are little-endian,
		# and 16 bit per channel per sample, we must interleave the storage. The program
		# will store one byte in two 16-bit stereo frames (one byte per eight bytes).
		# This collects each byte in the original wav.
		b1, b2, b3, b4, b5, b6, b7, b8 = wav_bytearray[i*8], wav_bytearray[(i*8)+1], wav_bytearray[(i*8)+2], wav_bytearray[(i*8)+3], wav_bytearray[(i*8)+4], wav_bytearray[(i*8)+5], wav_bytearray[(i*8)+6], wav_bytearray[(i*8)+7]
		# This removes the last two bits and stores the needed info there.
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
		# This reassembles the WAV.
		out_bytearray.extend(bytes([b1,b2,b3,b4,b5,b6,b7,b8]))
		cnt += 1
		if (cnt // pc) == 1:
			print_same_line("=")
			sys.stdout.flush()
			cnt = 0
	cpos = (len_in*8)
	pc = max((len(wav_bytearray)-cpos) // 80,1)
	cnt = 0
	# Most times, the file won't fit exactly into the WAV. So we must fill out that
	# space, to avoid creating a noticeable difference that possibly leaks the file
	# length, or makes the steganography more obvious.
	print("Padding Randomization Progress:")
	while cpos < len(wav_bytearray):
		cnt += 1
		if cpos % 2 == 0:
			out_bytearray.append((wav_bytearray[cpos]&0b11111100)|rng.randint(0,3))
		else:
			out_bytearray.append(wav_bytearray[cpos])
		if (cnt // pc) == 1:
			print_same_line("=")
			sys.stdout.flush()
			cnt = 0
		cpos +=1
	return out_bytearray
def get_bytearray_from_wav(wav_bytearray):
	out_bytearray = bytearray()
	ltu = len(wav_bytearray) // 8
	pc = max(ltu // 80,1)
	cnt = 0
	print("WAV Decoding Progress:")
	for i in range(0,ltu):
		#print(i)
		#print(len(wav_bytearray))
		b1, b2, b3, b4, b5, b6, b7, b8 = wav_bytearray[i*8], wav_bytearray[(i*8)+1], wav_bytearray[(i*8)+2], wav_bytearray[(i*8)+3], wav_bytearray[(i*8)+4], wav_bytearray[(i*8)+5], wav_bytearray[(i*8)+6], wav_bytearray[(i*8)+7]
		# This recovers everything from the WAV, including the padding garbage at the end.
		current_chunks = [b1&0b11,b3&0b11,b5&0b11,b7&0b11]
		current_byte = bit_2_chunks_to_byte(current_chunks)
		out_bytearray.append(current_byte)
		cnt += 1
		if (cnt // pc) == 1:
			print_same_line("=")
			sys.stdout.flush()
			cnt = 0
	return out_bytearray