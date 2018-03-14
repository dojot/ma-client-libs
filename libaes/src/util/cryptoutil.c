#include "cryptoutil.h"

/**
* Cryptographic utility functions.
* 
* @author Erick Nogueira do Nascimento (erick@cpqd.com.br)
* 
*/

/**
* Unpack the 32-bit integer 'word' into the uint8_t array 'out', starting at
* outOffset, in little endian order.
* 
* @param word
*            32-bit integer
* @param out
*            output uint8_t array
* @param outOffset
*            start index
*/
void unpackWordLittleEndian(uint32_t word, uint8_t* out, uint32_t outOffset) {
	out[outOffset] = (uint8_t) (word & 0xff);
	out[outOffset + 1] = (uint8_t) (word >> 8); // removed one > 
	out[outOffset + 2] = (uint8_t) (word >> 16);
	out[outOffset + 3] = (uint8_t) (word >> 24);
}

/**
* Unpack the 32-bit integer 'word' into the uint8_t array 'out', starting at
* outOffset, in big endian order.
* 
* @param word
*            32-bit integer
* @param out
*            output uint8_t array
* @param outOffset
*            start index
*/
void unpackWordBigEndian(uint32_t word, uint8_t* out, uint32_t outOffset) {
	out[outOffset] =     (uint8_t) (word >> 24); // Removed one > 
	out[outOffset + 1] = (uint8_t) (word >> 16);
	out[outOffset + 2] = (uint8_t) (word >> 8);
	out[outOffset + 3] = (uint8_t) (word);
}

/**
* Pack the first 4 elements of 'in', starting at index 'inOffset', into a
* 32-bit word and return that word.
* 
* @param in
* @param inOffset
* @return
*/
uint32_t packWordBigEndian(const uint8_t* in, uint32_t inOffset) {
	return ((in[inOffset + 0] & 0x000000FF) << 24)
		|  ((in[inOffset + 1] & 0x000000FF) << 16)
		|  ((in[inOffset + 2] & 0x000000FF) << 8)
		|  ((in[inOffset + 3] & 0x000000FF));
}

/**
* left-rotate x by n bits, 0 <= n <= 32
* 
* @param x
*            the word to rotate
* @param n
*            number of bits to rotate
* @return the rotated word
*/
uint8_t rotL(uint8_t x, uint8_t n) {
	//assert (n >= 0) && (n <= 32);
	return (x << n) | (x >> (32 - n)); // Removed one >
}

/**
* left-rotate x by n bits, 0 <= n <= 32
* 
* @param x
*            the word to rotate
* @param n
*            number of bits to rotate
* @return the rotated word
*/
uint8_t rotR(uint8_t x, uint8_t n) {
	//assert (n >= 0) && (n <= 32);
	return (x >> n) | (x << (32 - n)); // Removed one >
}

/**
* Xor the first len uint8_ts from array 'a' and 'b', starting at offsetA and
* offset B, respectively.
* 
* @param a
*            first operand
* @param offsetA
*            start index of 'a'
* @param b
*            second operand
* @param offsetB
*            start index of 'b'
* @param len
*            number of uint8_ts to operate
* @return the xor'ed array
*/
void xor(const uint8_t* a, uint32_t offsetA, const uint8_t* b, uint32_t offsetB, uint8_t* output, uint32_t offsetOutput, uint32_t length) 
{
	uint8_t i;
	for(i = 0; i < length; i++)
		output[i + offsetOutput] = (uint8_t) (((a[i + offsetA] & 0xFF) ^ (b[i + offsetB] & 0xFF)) & 0xFF);
}

/**
* Shift uint8_t 'a' one bit to the right
* 
* @param a
*            uint8_t to be shifted
* @return shifted uint8_t
*/
uint8_t shiftCharRightOne(uint8_t a) {
	// The AND mask is necessary because uint8_t is signed,
	// and bitwise operations (in this case the & and >>>) is applied only
	// to 'uint8_t' operators
	// So, the 'a' is promoted to 'uint8_t' before the AND
	return (uint8_t) ((a & 0xFF) >> 1); // Removed one >
}

/**
* Shift array 'A' one bit to the right
* 
* @param A
*            array to be shifted
* @return shifted array
*/
uint8_t* shiftRightOne(uint8_t* A, uint32_t length) {
	uint8_t* R = (uint8_t*)malloc(sizeof(uint8_t) * length);

	if (length == 1) {
		R[0] = shiftCharRightOne(A[0]);
	} else {
		int64_t i;
		for (i = length - 2; i >= 0; i--) {
			uint8_t cur = A[i];
			uint8_t next = A[i + 1];
			uint8_t lastBitCur = (cur & 0x0FF) & 0x01;
			next = (uint8_t) ((lastBitCur << 7) | shiftCharRightOne(next)); // put
			// on first bit of next
			R[i + 1] = next;
		}
		R[0] = shiftCharRightOne(A[0]);
	}
	return R;
}

/**
* Shift array 'A' 'n'-bits to the right.
* 
* @param A
*            array to be shifted
* @param n
*            number of shift bits
* @return shifted arrays
*/
uint8_t* shiftRight(uint8_t* A, uint32_t length, uint8_t n) {
	// TODO receive 'R' as a parameter
	uint8_t* R = (uint8_t*)malloc(sizeof(uint8_t) * length);
	uint8_t i;

	memcpy(R, A, sizeof(uint8_t) * length);
	for (i = 0; i < n; i++) {
		R = shiftRightOne(R, length);
	}
	return R;
}

/**
* Convert the uint8_t array 'arr' to uppercase hexadecimal string
* representation. Each element of 'arr' is converted into two uint8_tacters of
* the string.
* 
* @param arr
*            the array to convert
* @return uppercase hexadecimal string representation
*/
uint8_t* charArrayToHexStr(uint8_t* arr, uint32_t length) {
	uint8_t* out = (uint8_t*) malloc(sizeof(uint8_t) * length * 2 + 1);
	uint8_t count = 0;

	uint8_t hexMap[] = { '0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	uint8_t i;
	for (i = 0; i < length; i++) {
		uint8_t b = arr[i];
		out[count++] = hexMap[((b & 0xf0) >> 4) & 0xff]; // Removed one >
		out[count++] = hexMap[(b & 0x0f)];
	}
	out[sizeof(uint8_t) * length * 2] = '\0';
	return out;
}

/**
* Convert a hexadecimal string into a uint8_t array
* 
* @param hexStr
*            string to be converted
* @return uint8_t array
* @throws ParseException
*             If not a valid hexadecimal string
*/
uint8_t* HexStrToCharArray(const uint8_t* hexStr, uint32_t length) {
	uint8_t* out = (uint8_t*)malloc(sizeof(uint8_t) * length / 2);
	uint8_t value[2], b;
	uint8_t i;

	if (length % 2 != 0){
		/* Invalid hexadecimal uint8_t string */
		free(out);
		return NULL;
	}
	
	for (i = 0; i < length; i += 2) {
		value[0] = hexStr[i];
		value[1] = hexStr[i+1];
		b = HexCharStrToChar(value, 2);
		out[i / 2] = b;
	}
	return out;
}

/**
* Convert a 2-uint8_tacter hexadecimal string into a uint8_t value
* 
* @param uint8_tHexStr
*            the string to be converted
* @return the uint8_t
* @throws ParseException
*             If not a valid hexadecimal string
*/
uint8_t HexCharStrToChar(uint8_t* HexStr, uint32_t length) {
		uint8_t hexMap[] = { '0', '1', '2', '3', '4', '5', '6', '7',
			'8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
		uint8_t first, second;
		uint32_t i;
		uint32_t firstVal = 0x100, secondVal = 0x100;

		if (length != 2)
			/* Invalid hexadecimal uint8_t string */
			return 1;

		first = (uint8_t) toupper(HexStr[0]);
		second = (uint8_t) toupper(HexStr[1]);

		for (i = 0; i < 16; i++) {
			if (first == hexMap[i])
				firstVal = i;
			if (second == hexMap[i])
				secondVal = i;
		}
		if (firstVal == 0x100 || secondVal == 0x100) {
			/* Invalid hexadecimal uint8_t string */
			return 1;
		} else {
			return (uint8_t) ((firstVal << 4) | secondVal);
		}
}

/**
* Ceil function. Returns the smallest integer greater or equal than a/b.
* 
* @param a
*            first operand
* @param b
*            second operand
* @return ceil(a/b)
*/
uint8_t intDivisionCeil(uint8_t a, uint8_t b) {
	//assert a >= 0 && b > 0;
	if (a % b == 0) {
		return a / b;
	} else {
		return a / b + 1;
	}
}

/**
* Ceil function. Returns the smallest integer greater or equal than a/b.
* 
* @param a
*            first operand
* @param b
*            second operand
* @return ceil(a/b)
*/
uint64_t longDivisionCeil(uint64_t a, uint64_t b) {
	//assert a >= 0 && b > 0;
	if (a % b == 0) {
		return a / b;
	} else {
		return a / b + 1;
	}
}

/**
* 
* Compare a uint8_t array with a uint8_t
* 
* @param arr
*            the uint8_t array
* @param arrB
*            the uint8_t array to be compared
* @return true if all uint8_ts in the array are equal to the other array and
*         false if there are at least one uint8_t different or the sizes are
*         different
*/
uint8_t compareArrayToArrayDiffConstant(const uint8_t* arr, uint32_t lenA, const uint8_t* arrB, uint32_t lenB) {
		uint8_t res = 0x00;
		uint8_t i;

		if (lenA == lenB) {
			for (i = 0; i < lenA; i++) {
				res |= (arrB[i] ^ arr[i]);
			}
		} else {
			res = 0x01;
		}
		return res;
}

void inc32(uint8_t* X, uint32_t length) {
	uint32_t word = packWordBigEndian(X, length - 4);
	word += 1;
	unpackWordBigEndian(word, X, length - 4);
}

errno_t inc(uint8_t* X, uint32_t length) {
	errno_t result;
	int64_t i = ((int64_t)length)-1;
	uint8_t previous, calculated;

	if(X == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	while(i >= 0) {
		previous = X[i];
		calculated = previous + 1;
		X[i] = calculated;
		if(calculated != 0) {
			break;
		}
		i--;
	}
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}
