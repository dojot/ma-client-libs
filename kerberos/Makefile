CC=gcc
SRC=$(wildcard src/*/*.c)
all:
	@echo "-------- Compiling CryptoLibrary --------"
	@echo $(LIBCRYPTO)
	@echo "-> Compile the library into a .js"
#	$(CC) -Wno-implicit -O0 -s RESERVED_FUNCTION_POINTERS=2 -s EXPORTED_FUNCTIONS='["_executeKerberosHandshake", "_setCallback", "_initializeKerberos", "_encryptTo", "_encryptToJS", "_decryptTo", "_decryptToJS", "_clearSecureChannel", "_processError", "_processReply", "_unicodeInit_prof", "_unicodeFill", "_unicodeBackSpace", "_all_backspace", "_campo_end","_getObfuscatedSize", "_returnObsData"]' $(SRC) lib/*.bc -o ../libsecurity.js
	$(CC) -g -Wall -shared -fPIC -Wno-implicit -O0 $(SRC) -o ../libkerberos.so -Llib -lcurl -laes

clean:
	rm -f *.o libcrypto.js
