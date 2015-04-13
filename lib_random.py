import random
rng = random.SystemRandom()

def create_random_byte():
	return rng.randint(0,255)

def create_random_lower_half():
	return rng.randint(0,127)

def create_random_upper_half():
	return rng.randint(128,255)

def create_random_key(length):
	rndkey = bytearray()
	for i in range(0,length):
		rndkey.append(rng.randint(0,255))
	return rndkey