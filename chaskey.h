/*  C interface for C++ implementation of Chaskey MAC algorithm
 *  Very efficient MAC algorithm for microcontrollers
 *  http://mouha.be/chaskey/
 */
#include <stdint.h>
#pragma once
#ifdef __cplusplus
extern "C" {
#endif
/** MAC algorithm  															*/
void chaskey(
		uint8_t *tag,		/** destination buffer for the message digest	*/
		uint32_t taglen,		/** length of the destination buffer 		*/
		const uint8_t *m,		/** message to process						*/
		const uint32_t mlen,	/** message length							*/
		const uint32_t k[4],	/** encryption key							*/
		const uint32_t k1[4],	/** derived subkey k<<1						*/
		const uint32_t k2[4]	/** derived subkey k<<2						*/
);

/** Key derivation routine													*/
void subkeys(
	uint32_t k1[4],				/** destination for subkey k<<1				*/
	uint32_t k2[4],				/** destination for subkey k<<2				*/
	const uint32_t k[4]			/** source key 								*/
);
#ifdef __cplusplus
}
#endif
