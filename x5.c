#include "x5.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"

void x5_hash(const char* input, char* output, uint32_t len)
{
    sph_blake512_context     ctx_blake;
    sph_groestl512_context   ctx_groestl;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;

    //these uint512 in the c++ source of the client are backed by an array of uint32
    uint32_t hashA[16], hashB[16];

    // BLAKE
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, input, len);
    sph_blake512_close(&ctx_blake, hashA);
    // GROESTL
    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, hashA, 64);
    sph_groestl512_close(&ctx_groestl, hashB);
    // JH
    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, hashB, 64);
    sph_jh512_close(&ctx_jh, hashA);
    // KECCAK
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, hashA, 64);
    sph_keccak512_close(&ctx_keccak, hashB);
    // SKEIN
    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, hashB, 64);
    sph_skein512_close(&ctx_skein, hashA);

    memcpy(output, hashA, 32);
}
