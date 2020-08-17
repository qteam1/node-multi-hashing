#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ethash.h"
#include "sha3.h"

#if defined(_MSC_VER)
     /* Microsoft C/C++-compatible compiler */
     #include <intrin.h>
#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
     /* GCC-compatible compiler, targeting x86/x86-64 */
     #include <x86intrin.h>
#elif defined(__GNUC__) && defined(__ARM_NEON__)
     /* GCC-compatible compiler, targeting ARM with NEON */
     #include <arm_neon.h>
#elif defined(__GNUC__) && defined(__IWMMXT__)
     /* GCC-compatible compiler, targeting ARM with WMMX */
     #include <mmintrin.h>
#elif (defined(__GNUC__) || defined(__xlC__)) && (defined(__VEC__) || defined(__ALTIVEC__))
     /* XLC or GCC-compatible compiler, targeting PowerPC with VMX/VSX */
     #include <altivec.h>
#elif defined(__GNUC__) && defined(__SPE__)
     /* GCC-compatible compiler, targeting PowerPC with SPE */
     #include <spe.h>
#endif

#ifdef __AVX2__
#define ENABLE_AVX2 1
#else
#define ENABLE_AVX2 0
#ifdef __SSE2__
#define ENABLE_SSE 1
#else
#define ENABLE_SSE 0
#endif
#endif

#define FNV_PRIME    0x01000193

#define NODE_WORDS (64/4)
#define MIX_WORDS (ETHASH_MIX_BYTES/4)
#define MIX_NODES (MIX_WORDS / NODE_WORDS)

#define fnv(x, y)    (((x) * FNV_PRIME) ^ (y))
#define fnv_reduce(v)  fnv(fnv(fnv((v)[0], (v)[1]), (v)[2]), (v)[3])

typedef union _node
{
    uint8_t bytes[16 * 4];
    uint32_t words[16];
    uint64_t double_words[16 / 2];
} node;

#if ENABLE_SSE
typedef struct _node128
{
    __m128i xmm[NODE_WORDS/2];
} node128;
#elif ENABLE_AVX2
typedef struct _node256
{
    __m256i ymm[NODE_WORDS/4];
} node256;
#endif

typedef struct ethash_h256 { uint8_t b[32]; } ethash_h256_t;

ethash_h256_t ethash_get_seedhash(uint64_t block_number)
{
    ethash_h256_t ret;
    memset(&ret, 0, 32);
    uint64_t const epochs = block_number / ETHASH_EPOCH_LENGTH;
    for (uint32_t i = 0; i < epochs; ++i)
        SHA3_256((uint8_t*)&ret, (uint8_t*)&ret, 32);
    return ret;
}

// Output (cache_nodes) MUST have at least cache_size bytes
static void ethash_generate_cache(uint8_t *cache_nodes_in, const uint8_t *seedhash, uint64_t cache_size)
{
    uint32_t const num_nodes = (uint32_t)(cache_size / sizeof(node));
    node *cache_nodes = (node *)cache_nodes_in;

    SHA3_512(cache_nodes[0].bytes, seedhash, 32);

    for (uint32_t i = 1; i < num_nodes; ++i) {
        SHA3_512(cache_nodes[i].bytes, cache_nodes[i - 1].bytes, 64);
    }

    for (uint32_t j = 0; j < ETHASH_CACHE_ROUNDS; j++) { // this one can be unrolled entirely, ETHASH_CACHE_ROUNDS is constant
        for (uint32_t i = 0; i < num_nodes; i++) {
            uint32_t const idx = cache_nodes[i].words[0] % num_nodes;
            node data;
            data = cache_nodes[(num_nodes - 1 + i) % num_nodes];
#if ENABLE_SSE
            node128 *data128 = (node128 *)&data;
            node128 *cache128 = (node128 *)&cache_nodes[idx];

            data128->xmm[0] = _mm_xor_si128(data128->xmm[0], cache128->xmm[0]);
            data128->xmm[1] = _mm_xor_si128(data128->xmm[1], cache128->xmm[1]);
            data128->xmm[2] = _mm_xor_si128(data128->xmm[2], cache128->xmm[2]);
            data128->xmm[3] = _mm_xor_si128(data128->xmm[3], cache128->xmm[3]);
#elif ENABLE_AVX2
            node256 *data256 = (node256 *)&data;
            node256 *cache256 = (node256 *)&cache_nodes[idx];

            data256->ymm[0] = _mm256_xor_si256(data256->ymm[0], cache256->ymm[0]);
            data256->ymm[1] = _mm256_xor_si256(data256->ymm[1], cache256->ymm[1]);
#else
            for (uint32_t w = 0; w < NODE_WORDS; ++w) { // this one can be unrolled entirely as well
                data.words[w] ^= cache_nodes[idx].words[w];
            }
#endif

            SHA3_512(cache_nodes[i].bytes, data.bytes, sizeof(data));
        }
    }
}

node ethash_calc_dag_item(const node *cache_nodes, uint32_t num_nodes, uint32_t node_index)
{
    node dag_node = cache_nodes[node_index % num_nodes];

    dag_node.words[0] ^= node_index;

    SHA3_512(dag_node.bytes, dag_node.bytes, sizeof(node));
#if ENABLE_SSE
    node128 *dag128 = (node128 *)&dag_node;
    __m128i const fnv_prime = _mm_set1_epi32(FNV_PRIME);
    __m128i xmm0 = dag128->xmm[0];
    __m128i xmm1 = dag128->xmm[1];
    __m128i xmm2 = dag128->xmm[2];
    __m128i xmm3 = dag128->xmm[3];
#elif ENABLE_AVX2
    node256 *dag256 = (node256 *)&dag_node;
    __m256i const fnv_prime = _mm256_set1_epi32(FNV_PRIME);
    __m256i ymm0 = dag256->ymm[0];
    __m256i ymm1 = dag256->ymm[1];
#endif

    for (uint32_t i = 0; i < ETHASH_DATASET_PARENTS; ++i) {
        uint32_t parent_index = fnv(node_index ^ i, dag_node.words[i % NODE_WORDS]) % num_nodes;
#if ENABLE_SSE
        node128 *parent = (node128 *)&cache_nodes[parent_index];

        xmm0 = _mm_mullo_epi32(xmm0, fnv_prime);
        xmm1 = _mm_mullo_epi32(xmm1, fnv_prime);
        xmm2 = _mm_mullo_epi32(xmm2, fnv_prime);
        xmm3 = _mm_mullo_epi32(xmm3, fnv_prime);
        xmm0 = _mm_xor_si128(xmm0, parent->xmm[0]);
        xmm1 = _mm_xor_si128(xmm1, parent->xmm[1]);
        xmm2 = _mm_xor_si128(xmm2, parent->xmm[2]);
        xmm3 = _mm_xor_si128(xmm3, parent->xmm[3]);

        // have to write to ret as values are used to compute index
        dag128->xmm[0] = xmm0;
        dag128->xmm[1] = xmm1;
        dag128->xmm[2] = xmm2;
        dag128->xmm[3] = xmm3;
#elif ENABLE_AVX2
        node256 *parent = (node256 *)&cache_nodes[parent_index];

        ymm0 = _mm256_mullo_epi32(ymm0, fnv_prime);
        ymm1 = _mm256_mullo_epi32(ymm1, fnv_prime);
        ymm0 = _mm256_xor_si256(ymm0, parent->ymm[0]);
        ymm1 = _mm256_xor_si256(ymm1, parent->ymm[1]);

        // have to write to ret as values are used to compute index
        dag256->ymm[0] = ymm0;
        dag256->ymm[1] = ymm1;
#else
        node const *parent = &cache_nodes[parent_index];

        for (uint32_t j = 0; j < NODE_WORDS; ++j) {
            dag_node.words[j] = fnv(dag_node.words[j], parent->words[j]);
        }
#endif
    }

    SHA3_512(dag_node.bytes, dag_node.bytes, sizeof(node));

    return dag_node;
}

static node *dag_cache = NULL;
static uint64_t current_epoch = -1;

// output (result + mixhash) MUST have 64 bytes allocated (at least)
void ethash_hash(const char* input, char* output, uint64_t height, uint64_t nonce)
{
    uint32_t tmpbuf[24];
    uint64_t epoch = height / ETHASH_EPOCH_LENGTH;
    uint64_t dagsize;
    uint32_t num_nodes = ethash_get_cache_size(epoch) / sizeof(node);
#ifndef ETH_USE_NODE
    uint32_t mixstate[32];
#else
    node mixstate[MIX_NODES + 1];
#endif

    if (current_epoch != epoch) {
        uint64_t cache_size = num_nodes * sizeof(node);
        if (dag_cache)
            free(dag_cache);
        dag_cache = (node *)malloc(cache_size);
        ethash_h256_t seedhash = ethash_get_seedhash(height);
        ethash_generate_cache((uint8_t*)dag_cache, (uint8_t*)&seedhash, cache_size);
        current_epoch = epoch;
    }

    // Initial hash - append nonce to header PoW hash and
    // run it through SHA3 - this becomes the initial value
    // for the mixing state buffer. The init value is used
    // later for the final hash, and is therefore saved.
    memcpy(tmpbuf, input, 32);
    memcpy(tmpbuf + 8, &nonce, 8);
    SHA3_512((uint8_t *)tmpbuf, (uint8_t *)tmpbuf, 40);

#ifndef ETH_USE_NODE
    memcpy(mixstate, tmpbuf, 64);
#else
    memcpy(mixstate[0].bytes, tmpbuf, 64);
#endif

    // The other half of the state is filled by simply
    // duplicating the first half of its initial value.
#ifndef ETH_USE_NODE
    memcpy(mixstate + 16, mixstate, 64);
#else
    node* const mix = mixstate + 1;
    for (uint32_t w = 0; w < MIX_WORDS; ++w) {
        mix->words[w] = mixstate[0].words[w % NODE_WORDS];
    }
#endif

#if ENABLE_SSE
    node128 *mix128 = (node128 *)mixstate;
    __m128i fnv_prime = _mm_set1_epi32(FNV_PRIME);
#elif ENABLE_AVX2
    node256 *mix256 = (node256 *)mixstate;
    __m256i fnv_prime = _mm256_set1_epi32(FNV_PRIME);
#endif

    dagsize = ethash_get_dag_size(epoch) / (sizeof(node) << 1);

    // Main mix of Ethash
#ifndef ETH_USE_NODE
    for (uint32_t i = 0, init0 = mixstate[0]; i < ETHASH_ACCESSES; ++i) {
        uint32_t index = fnv(init0 ^ i, mixstate[i % MIX_WORDS]) % dagsize;
        node dagslice_nodes[2];
        dagslice_nodes[0] = ethash_calc_dag_item(dag_cache, num_nodes, (index << 1) + 0);
        dagslice_nodes[1] = ethash_calc_dag_item(dag_cache, num_nodes, (index << 1) + 1);
#if ENABLE_SSE
        node128 *dag128 = (node128 *)dagslice_nodes;
#elif ENABLE_AVX2
        node256 *dag256 = (node256 *)dagslice_nodes;
#else
        uint32_t *dagslice = (uint32_t *)dagslice_nodes;
#endif

#if ENABLE_SSE
        __m128i xmm0 = _mm_mullo_epi32(fnv_prime, mix128->xmm[0]);
        __m128i xmm1 = _mm_mullo_epi32(fnv_prime, mix128->xmm[1]);
        __m128i xmm2 = _mm_mullo_epi32(fnv_prime, mix128->xmm[2]);
        __m128i xmm3 = _mm_mullo_epi32(fnv_prime, mix128->xmm[3]);
        __m128i xmm4 = _mm_mullo_epi32(fnv_prime, mix128->xmm[4]);
        __m128i xmm5 = _mm_mullo_epi32(fnv_prime, mix128->xmm[5]);
        __m128i xmm6 = _mm_mullo_epi32(fnv_prime, mix128->xmm[6]);
        __m128i xmm7 = _mm_mullo_epi32(fnv_prime, mix128->xmm[7]);
        mix128->xmm[0] = _mm_xor_si128(xmm0, dag128->xmm[0]);
        mix128->xmm[1] = _mm_xor_si128(xmm1, dag128->xmm[1]);
        mix128->xmm[2] = _mm_xor_si128(xmm2, dag128->xmm[2]);
        mix128->xmm[3] = _mm_xor_si128(xmm3, dag128->xmm[3]);
        mix128->xmm[4] = _mm_xor_si128(xmm4, dag128->xmm[4]);
        mix128->xmm[5] = _mm_xor_si128(xmm5, dag128->xmm[5]);
        mix128->xmm[6] = _mm_xor_si128(xmm6, dag128->xmm[6]);
        mix128->xmm[7] = _mm_xor_si128(xmm7, dag128->xmm[7]);
#elif ENABLE_AVX2
        __m256i ymm0 = _mm256_mullo_epi32(fnv_prime, mix256->ymm[0]);
        __m256i ymm1 = _mm256_mullo_epi32(fnv_prime, mix256->ymm[1]);
        __m256i ymm2 = _mm256_mullo_epi32(fnv_prime, mix256->ymm[2]);
        __m256i ymm3 = _mm256_mullo_epi32(fnv_prime, mix256->ymm[3]);
        mix256->ymm[0] = _mm256_xor_si256(ymm0, dag256->ymm[0]);
        mix256->ymm[1] = _mm256_xor_si256(ymm1, dag256->ymm[1]);
        mix256->ymm[2] = _mm256_xor_si256(ymm2, dag256->ymm[2]);
        mix256->ymm[3] = _mm256_xor_si256(ymm3, dag256->ymm[3]);
#else
        for (uint32_t m = 0; m < MIX_WORDS; ++m) {
            mixstate[m] = fnv(mixstate[m], dagslice[m]);
        }
#endif
    }
#else
    for (uint32_t i = 0; i < ETHASH_ACCESSES; ++i) {
        uint32_t const index = fnv(mixstate->words[0] ^ i, mix->words[i % MIX_WORDS]) % dagsize;

        for (unsigned n = 0; n < MIX_NODES; ++n) {
            node dag_node;
            dag_node = ethash_calc_dag_item(dag_cache, num_nodes, MIX_NODES * index + n);
            for (unsigned w = 0; w < NODE_WORDS; ++w) {
                mix[n].words[w] = fnv(mix[n].words[w], dag_node.words[w]);
            }
        }
    }
#endif

    // The reducing of the mix state directly into where
    // it will be hashed to produce the final hash. Note
    // that the initial hash is still in the first 64
    // bytes of tmpbuf - we're appending the mix hash.
#ifndef ETH_USE_NODE
    for (int i = 0; i < 8; ++i)
        tmpbuf[i + 16] = fnv_reduce(mixstate + (i << 2));
#else
    for (int i = 0; i < MIX_WORDS / 4; ++i) {
        tmpbuf[i + 16] = fnv_reduce(&mix->words[i << 2]);
    }
#endif

    memcpy(output + 32, tmpbuf + 16, 32);
    //memcpy(mixhash, tmpbuf + 16, 32);

    // Hash the initial hash and the mix hash concatenated
    // to get the final proof-of-work hash that is our output.
    // final Keccak hash
    SHA3_256((uint8_t*)output, (uint8_t *)tmpbuf, 64 + 32); // Keccak-256(s + compressed_mix)
}
