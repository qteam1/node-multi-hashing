#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ethash.h"
#include "sha3.h"

#define FNV_PRIME    0x01000193

#define NODE_WORDS (64/4)
#define MIX_WORDS (ETHASH_MIX_BYTES/4)
#define MIX_NODES (MIX_WORDS / NODE_WORDS)

#define fnv(x, y)    (((x) * FNV_PRIME) ^ (y))
#define fnv_reduce(v)  fnv(fnv(fnv((v)[0], (v)[1]), (v)[2]), (v)[3])

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
            for (uint32_t w = 0; w < NODE_WORDS; ++w) { // this one can be unrolled entirely as well
                data.words[w] ^= cache_nodes[idx].words[w];
            }

            SHA3_512(cache_nodes[i].bytes, data.bytes, sizeof(data));
        }
    }
}

node ethash_calc_dag_item(const node *cache_nodes, uint32_t num_nodes, uint32_t node_index)
{
    node dag_node = cache_nodes[node_index % num_nodes];

    dag_node.words[0] ^= node_index;

    SHA3_512(dag_node.bytes, dag_node.bytes, sizeof(node));

    for (uint32_t i = 0; i < ETHASH_DATASET_PARENTS; ++i) {
        uint32_t parent_index = fnv(node_index ^ i, dag_node.words[i % NODE_WORDS]) % num_nodes;
        node const *parent = &cache_nodes[parent_index];

        for (uint32_t j = 0; j < NODE_WORDS; ++j) {
            dag_node.words[j] = fnv(dag_node.words[j], parent->words[j]);
        }
    }

    SHA3_512(dag_node.bytes, dag_node.bytes, sizeof(node));

    return dag_node;
}

static node *dag_cache = NULL;
static uint64_t current_epoch = -1;

// output (result + mixhash) MUST have 64 bytes allocated (at least)
void ethash_hash(const char* input, char* output, uint64_t height, uint64_t nonce)
{
    uint32_t mixstate[32], tmpbuf[24];
    uint64_t epoch = height / ETHASH_EPOCH_LENGTH;
    uint64_t dagsize;
    uint32_t num_nodes = ethash_get_cache_size(epoch) / sizeof(node);

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

    memcpy(mixstate, tmpbuf, 64);

    // The other half of the state is filled by simply
    // duplicating the first half of its initial value.
    memcpy(mixstate + 16, mixstate, 64);

    dagsize = ethash_get_dag_size(epoch) / (sizeof(node) << 1);

    // Main mix of Ethash
    for (uint32_t i = 0, init0 = mixstate[0], mixvalue = mixstate[0]; i < ETHASH_ACCESSES; ++i) {
        uint32_t row = fnv(init0 ^ i, mixvalue) % dagsize;
        node dag_slice_nodes[2];
        dag_slice_nodes[0] = ethash_calc_dag_item(dag_cache, num_nodes, row << 1);
        dag_slice_nodes[1] = ethash_calc_dag_item(dag_cache, num_nodes, (row << 1) + 1);
        DAG128 *dagslice = (DAG128 *)dag_slice_nodes;

        for (uint32_t col = 0; col < 32; ++col) {
            mixstate[col] = fnv(mixstate[col], dagslice->Columns[col]);
            mixvalue = col == ((i + 1) & 0x1F) ? mixstate[col] : mixvalue;
        }
    }

    // The reducing of the mix state directly into where
    // it will be hashed to produce the final hash. Note
    // that the initial hash is still in the first 64
    // bytes of tmpbuf - we're appending the mix hash.
    for (int i = 0; i < 8; ++i)
        tmpbuf[i + 16] = fnv_reduce(mixstate + (i << 2));

    memcpy(output + 32, tmpbuf + 16, 32);
    //memcpy(mixhash, tmpbuf + 16, 32);

    // Hash the initial hash and the mix hash concatenated
    // to get the final proof-of-work hash that is our output.
    // final Keccak hash
    SHA3_256((uint8_t*)output, (uint8_t *)tmpbuf, 64 + 32); // Keccak-256(s + compressed_mix)
}
