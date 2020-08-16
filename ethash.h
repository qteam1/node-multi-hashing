#ifndef ETHASH_H
#define ETHASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void ethash_hash(const char* input, char* output, uint64_t height, uint64_t nonce);

#ifdef __cplusplus
}
#endif

#endif
