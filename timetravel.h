#ifndef TIMETRAVEL_H
#define TIMETRAVEL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void timetravel_hash(const char* input, char* output, uint32_t len, uint32_t timestamp);

#ifdef __cplusplus
}
#endif

#endif