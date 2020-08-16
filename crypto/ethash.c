#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ethash.h"
#include "sha3.h"

#define FNV_PRIME    0x01000193

#define fnv(x, y)    (((x) * FNV_PRIME) ^ (y))
#define fnv_reduce(v)  fnv(fnv(fnv((v)[0], (v)[1]), (v)[2]), (v)[3])
#define ETHASH_EPOCH_LENGTH 30000UL

typedef struct _DAG128
{
    uint32_t Columns[32];
} DAG128;

typedef union _node
{
    uint8_t bytes[16 * 4];
    uint32_t words[16];
    uint64_t double_words[16 / 2];
} node;

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
static void EthGenerateCache(uint8_t *cache_nodes_in, const uint8_t *seedhash, uint64_t cache_size)
{
    uint32_t const num_nodes = (uint32_t)(cache_size / sizeof(node));
    node *cache_nodes = (node *)cache_nodes_in;

    SHA3_512(cache_nodes[0].bytes, seedhash, 32);

    for(uint32_t i = 1; i < num_nodes; ++i) {
        SHA3_512(cache_nodes[i].bytes, cache_nodes[i - 1].bytes, 64);
    }

    for(uint32_t j = 0; j < 3; j++) { // this one can be unrolled entirely, ETHASH_CACHE_ROUNDS is constant
        for(uint32_t i = 0; i < num_nodes; i++) {
            uint32_t const idx = cache_nodes[i].words[0] % num_nodes;
            node data;
            data = cache_nodes[(num_nodes - 1 + i) % num_nodes];
            for(uint32_t w = 0; w < 16; ++w) { // this one can be unrolled entirely as well
                data.words[w] ^= cache_nodes[idx].words[w];
            }

            SHA3_512(cache_nodes[i].bytes, data.bytes, sizeof(data));
        }
    }
}

node CalcDAGItem(const node *CacheInputNodes, uint32_t NodeCount, uint32_t NodeIdx)
{
    node DAGNode = CacheInputNodes[NodeIdx % NodeCount];

    DAGNode.words[0] ^= NodeIdx;

    SHA3_512(DAGNode.bytes, DAGNode.bytes, sizeof(node));

    for(uint32_t i = 0; i < 256; ++i) {
        uint32_t parent_index = fnv(NodeIdx ^ i, DAGNode.words[i % 16]) % NodeCount;
        node const *parent = CacheInputNodes + parent_index; //&cache_nodes[parent_index];

        for(int i = 0; i < 16; ++i) {
            DAGNode.words[i] *= FNV_PRIME;
            DAGNode.words[i] ^= parent->words[i];
        }
    }

    SHA3_512(DAGNode.bytes, DAGNode.bytes, sizeof(node));

    return DAGNode;
}

static node *dag_cache = NULL;
static uint64_t current_epoch = -1;

// output (result + mixhash) MUST have 64 bytes allocated (at least)
void ethash_hash(const char* input, char* output, uint64_t height, uint64_t nonce)
{
    uint32_t MixState[32], TmpBuf[24];
    uint64_t epoch = height / ETHASH_EPOCH_LENGTH;
    uint64_t DagSize;
    uint32_t NodeCount = EthGetCacheSize(epoch) / sizeof(node);

    if (current_epoch != epoch) {
        uint64_t cache_size = EthGetCacheSize(epoch);
        if (dag_cache)
            free(dag_cache);
        dag_cache = (node *)malloc(cache_size);
        ethash_h256_t seedhash = ethash_get_seedhash(height);
        EthGenerateCache((uint8_t*)dag_cache, (uint8_t*)&seedhash, cache_size);
        current_epoch = epoch;
    }

    // Initial hash - append nonce to header PoW hash and
    // run it through SHA3 - this becomes the initial value
    // for the mixing state buffer. The init value is used
    // later for the final hash, and is therefore saved.
    memcpy(TmpBuf, input, 32);
    memcpy(TmpBuf + 8, &nonce, 8);
    //sha3_512((uint8_t *)TmpBuf, 64UL, (uint8_t *)TmpBuf, 40UL);
    SHA3_512((uint8_t *)TmpBuf, (uint8_t *)TmpBuf, 40);

    memcpy(MixState, TmpBuf, 64);

    // The other half of the state is filled by simply
    // duplicating the first half of its initial value.
    memcpy(MixState + 16, MixState, 64);

    DagSize = EthGetDAGSize(epoch) / (sizeof(node) << 1);

    // Main mix of Ethash
    for(uint32_t i = 0, Init0 = MixState[0], MixValue = MixState[0]; i < 64; ++i) {
        uint32_t row = fnv(Init0 ^ i, MixValue) % DagSize;
        node DAGSliceNodes[2];
        DAGSliceNodes[0] = CalcDAGItem(dag_cache, NodeCount, row << 1);
        DAGSliceNodes[1] = CalcDAGItem(dag_cache, NodeCount, (row << 1) + 1);
        DAG128 *DAGSlice = (DAG128 *)DAGSliceNodes;

        for(uint32_t col = 0; col < 32; ++col) {
            MixState[col] = fnv(MixState[col], DAGSlice->Columns[col]);
            MixValue = col == ((i + 1) & 0x1F) ? MixState[col] : MixValue;
        }
    }

    // The reducing of the mix state directly into where
    // it will be hashed to produce the final hash. Note
    // that the initial hash is still in the first 64
    // bytes of TmpBuf - we're appending the mix hash.
    for(int i = 0; i < 8; ++i)
        TmpBuf[i + 16] = fnv_reduce(MixState + (i << 2));

    memcpy(output + 32, TmpBuf + 16, 32);
    //memcpy(MixHash, TmpBuf + 16, 32);

    // Hash the initial hash and the mix hash concatenated
    // to get the final proof-of-work hash that is our output.
    // final Keccak hash
    SHA3_256((uint8_t*)output, (uint8_t *)TmpBuf, 64 + 32); // Keccak-256(s + compressed_mix)
}
