#ifndef X11GOST_H
#define X11GOST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void x11gost_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
