#ifndef X5_H
#define X5_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void x5_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
