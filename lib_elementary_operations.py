def do_xor_on_bytes(bs1,bs2):
	l1 = len(bs1)
	xor = bytearray()
	for i in range(0,l1):
		xor.append(bs1[i] ^ bs2[i])
	return xor