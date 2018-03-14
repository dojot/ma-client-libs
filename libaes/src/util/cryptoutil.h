#ifndef CRYPTOUTIL_
#define CRYPTOUTIL_

#include "codes.h"
#include "errno.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>

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
void unpackWordLittleEndian(uint32_t word, uint8_t* out, uint32_t outOffset);

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
void unpackWordBigEndian(uint32_t word, uint8_t* out, uint32_t outOffset);

/**
* Pack the first 4 elements of 'in', starting at index 'inOffset', into a
* 32-bit word and return that word.
* 
* @param in
* @param inOffset
* @return
*/
uint32_t packWordBigEndian(const uint8_t* in, uint32_t inOffset);

/**
* left-rotate x by n bits, 0 <= n <= 32
* 
* @param x
*            the word to rotate
* @param n
*            number of bits to rotate
* @return the rotated word
*/
uint8_t rotL(uint8_t x, uint8_t n);

/**
* left-rotate x by n bits, 0 <= n <= 32
* 
* @param x
*            the word to rotate
* @param n
*            number of bits to rotate
* @return the rotated word
*/
uint8_t rotR(uint8_t x, uint8_t n);

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
void xor(const uint8_t* a, uint32_t offsetA, const uint8_t* b, uint32_t offsetB, uint8_t* output, uint32_t offsetOutput, uint32_t length);

/**
* Shift uint8_t 'a' one bit to the right
* 
* @param a
*            uint8_t to be shifted
* @return shifted uint8_t
*/
uint8_t shiftCharRightOne(uint8_t a);

/**
* Shift array 'A' one bit to the right
* 
* @param A
*            array to be shifted
* @return shifted array
*/
uint8_t* shiftRightOne(uint8_t* A, uint32_t length);

/**
* Shift array 'A' 'n'-bits to the right.
* 
* @param A
*            array to be shifted
* @param n
*            number of shift bits
* @return shifted arrays
*/
uint8_t* shiftRight(uint8_t* A, uint32_t length, uint8_t n);

/**
* Convert the uint8_t array 'arr' to uppercase hexadecimal string
* representation. Each element of 'arr' is converted into two uint8_tacters of
* the string.
* 
* @param arr
*            the array to convert
* @return uppercase hexadecimal string representation
*/
uint8_t* charArrayToHexStr(uint8_t* arr, uint32_t length);

/**
* Convert a hexadecimal string into a uint8_t array
* 
* @param hexStr
*            string to be converted
* @return uint8_t array
* @throws ParseException
*             If not a valid hexadecimal string
*/
uint8_t* HexStrToCharArray(const uint8_t* chrStr, uint32_t length);

/**
* Convert a 2-uint8_tacter hexadecimal string into a uint8_t value
* 
* @param uint8_tHexStr
*            the string to be converted
* @return the uint8_t
* @throws ParseException
*             If not a valid hexadecimal string
*/
uint8_t HexCharStrToChar(uint8_t* HexStr, uint32_t length);

/**
* Ceil function. Returns the smallest integer greater or equal than a/b.
* 
* @param a
*            first operand
* @param b
*            second operand
* @return ceil(a/b)
*/
uint8_t intDivisionCeil(uint8_t a, uint8_t b);

/**
* Ceil function. Returns the smallest integer greater or equal than a/b.
* 
* @param a
*            first operand
* @param b
*            second operand
* @return ceil(a/b)
*/
uint64_t longDivisionCeil(uint64_t a, uint64_t b);

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
uint8_t compareArrayToArrayDiffConstant(const uint8_t* arr, uint32_t lenA, const uint8_t* arrB, uint32_t lenB);

void inc32(uint8_t* X, uint32_t length);

/* Used to increment the IV by 1 */
errno_t inc(uint8_t* X, uint32_t length);

#endif /* CRYPTOUTIL_ */