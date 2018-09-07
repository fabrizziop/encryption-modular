# encryption-modular
File encryption, plus steganography inside WAV.

# PLEASE USE new_steg_tool! https://github.com/fabrizziop/new_steg_tool

Any questions or suggestions, please mail me. PGP keys:

B48D57027501810FBE2538332C14F1ACFB154963 - New key.

4A9473F846DEE9C93DF20207D5880D1DC7015FAD - Old key.

Now featuring a GUI (using tkinter), encryption-modular features:

* Triple AES-256, in EDE mode, with separate 256-bit keys, used in CTR mode. The counter is 128-bit and its initial value depends on the whole 1024-bit key used. The nonce isn't needed because keys aren't reused.

* Files can be encrypted using either a password or a RSA key. When using a password, the 1024-bit key is split on two parts, a salt is created for each part, and 4M PBKDF2-SHA512 iterations are applied. When using RSA, the 1024-bit key is encrypted under a 8192-bit public RSA key using RSA-OAEP

* An HMAC-SHA512 is appended to each file after encryption (encrypt-then-mac). The key for the HMAC is created using several hashes, from the encryption key. The HMAC is verified before decrypting the whole file.

* The file to encrypt has a maximum length of 2^512 bytes. The file length is also encrypted. Random bytes are appended to the encrypted file, to help mask the original file length.

* In WAV steganography mode, the encrypted contents are placed in the 2 least significant bits of each channel of each audio frame. After the file is merged with the WAV source, the remaining space is also filled with random bytes, to avoid creating noise floor differences and to mask the file length.

* The RSA keystore holds up to 12 different keys, and allows you to generate, import, export and delete keys.

* RSA file signing and verification is supported. The signature is appended to the end of the file, so there may be some problems with several file formats.

