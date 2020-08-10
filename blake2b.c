#include <string.h>
#include <stdint.h>

#include "crypto/blake2b.h"

void blake2b_hash(const char *input, char *output, uint32_t len)
{
	uint8_t hash[32];
	blake2b_state ctx;

	blake2b_init(&ctx, 32);
	blake2b_update(&ctx, input, len);
	blake2b_final(&ctx, hash, 32);

	memcpy(output, hash, 32);
}
