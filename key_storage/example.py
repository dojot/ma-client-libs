from Crypto import Random
from Crypto.Protocol import KDF
from Crypto.Cipher import AES

BS = AES.block_size
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]

# Key-encryption Key derivation from password
password = "password"
salt = "saltsalt".encode('ASCII')
key = KDF.PBKDF2(password, salt, dkLen=16, count=1000, prf=None)

# Encrypting the Application Key
appKey = "applicationKey"
appKey_pad = pad(appKey) # AppKey is padded so its length is multiple of cipher block size
iv = Random.new().read(AES.block_size)
cipher = AES.new(key, AES.MODE_CBC, iv)
ct = cipher.encrypt(appKey_pad)

# Decrypting the Application Key
cipher2 = AES.new(key, AES.MODE_CBC, iv)
appKey_pad = cipher2.decrypt(ct)
appKey = unpad(appKey_pad)
