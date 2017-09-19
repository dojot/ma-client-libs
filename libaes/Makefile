CC=gcc
SRC=$(wildcard */*.c)
JNI="/usr/lib/jvm/java-8-openjdk-amd64/include/"
JNIMD="/usr/lib/jvm/java-8-openjdk-amd64/include/linux/"
#JNI="/cygdrive/c/Program Files\Java\jdk1.7.0_51\include"
#JNIMD="/cygdrive/c/Program Files\Java\jdk1.7.0_51\include\win32"
AR=emar

static:
	@echo "-------- Compiling CryptoLibrary static for Kerberos --------"
	@echo "-> Compile the library into .o"
#	$(CC) -s LINKABLE=1 -o libaes.bc $(SRC)
#	mv libaes.bc ../kerberos/lib/
	$(CC) -g -Wall -shared -fPIC -o libaes.so $(SRC)
	mv libaes.so ../kerberos/lib/
.FORCE:

clean:
	rm -f *.o *.bc 
