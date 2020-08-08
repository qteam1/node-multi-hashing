#include "tribus.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_echo.h"

void tribus_hash(const char* input, char* output, uint32_t len)
{
	sph_jh512_context ctx_jh;
	sph_keccak512_context ctx_keccak;
	sph_echo512_context ctx_echo;

	//these uint512 in the c++ source of the client are backed by an array of uint32
	uint32_t hashA[16], hashB[16];

	// JH
	sph_jh512_init(&ctx_jh);
	sph_jh512(&ctx_jh, input, len);
	sph_jh512_close(&ctx_jh, hashA);

	// KECCAK
	sph_keccak512_init(&ctx_keccak);
	sph_keccak512(&ctx_keccak, hashA, 64);
	sph_keccak512_close(&ctx_keccak, hashB);

	// ECHO
	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, hashB, 64);
	sph_echo512_close(&ctx_echo, hashA);

	memcpy(output, hashA, 32);
}
