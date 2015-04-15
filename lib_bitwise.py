from math import ceil
m_big = 0b11111111

def int_to_big_endian(intg, pad_to=16):
	big_endian_int = bytearray()
	times_to_iterate = ceil(len(bin(intg)[2:])/8)
	for i in range(0,times_to_iterate):
		big_endian_int.append((intg >> (i*8)) & m_big)
	while len(big_endian_int) < pad_to:
		big_endian_int.append(0)
	big_endian_int.reverse()
	return big_endian_int

def big_endian_to_int(big_endian_barr):
	big_endian = big_endian_barr
	cur_num = 0
	for i in range(0,len(big_endian)):
		cur_num = (cur_num << 8) | big_endian[i]
	return cur_num
	
# def bytes_to_3_bit_chunks(bytearr):
	# des_int = big_endian_to_int(bytearr)
	# i_list = []
	# for i in range(0,8):
		# i_list.append(des_int & bit_3_mask)
		# des_int >>= 3
	# i_list.reverse()
	# return i_list
def byte_to_2_bit_chunks(current_byte):
	chunk_list = []
	for i in range(0,4):
		chunk_list.append(current_byte & 0b11)
		current_byte >>= 2
	chunk_list.reverse()
	return chunk_list

def bit_2_chunks_to_byte(chunks):
	byte_output = 0
	for i in range(0,4):
		byte_output <<= 2
		byte_output |= chunks[i]
	#print(byte_output)
	return byte_output
	
# def bit_3_chunks_to_bytes(chunks):
	# int_des = 0
	# for i in range(0,8):
		# int_des <<= 3
		# int_des |= chunks[i]
	# return int_to_big_endian(int_des, pad_to=3)