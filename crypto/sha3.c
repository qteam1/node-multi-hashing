/** libkeccak-tiny
 *
 * A single-file implementation of SHA-3 and SHAKE.
 *
 * Implementor: David Leon Gil
 * License: CC0, attribution kindly requested. Blame taken too,
 * but not liability.
 */
#include "sha3.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

/*** Helper macros to unroll the permutation. ***/
#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))

/**
 * keccakf1600
 *
 * The implementation based on the "simple" implementation by Ronny Van Keer.
 * from https://keccak.team/archives.html
 * ref: https://github.com/chfast/ethash/blob/master/lib/keccak/keccakf1600.c
 */
static inline void keccakf(void* st)
{
    uint64_t Aba, Abe, Abi, Abo, Abu;
    uint64_t Aga, Age, Agi, Ago, Agu;
    uint64_t Aka, Ake, Aki, Ako, Aku;
    uint64_t Ama, Ame, Ami, Amo, Amu;
    uint64_t Asa, Ase, Asi, Aso, Asu;

    uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
    uint64_t Ega, Ege, Egi, Ego, Egu;
    uint64_t Eka, Eke, Eki, Eko, Eku;
    uint64_t Ema, Eme, Emi, Emo, Emu;
    uint64_t Esa, Ese, Esi, Eso, Esu;

    uint64_t Ba, Be, Bi, Bo, Bu;

    uint64_t Da, De, Di, Do, Du;

    int round;

    uint64_t *state = (uint64_t*)st;

    Aba = state[0];
    Abe = state[1];
    Abi = state[2];
    Abo = state[3];
    Abu = state[4];
    Aga = state[5];
    Age = state[6];
    Agi = state[7];
    Ago = state[8];
    Agu = state[9];
    Aka = state[10];
    Ake = state[11];
    Aki = state[12];
    Ako = state[13];
    Aku = state[14];
    Ama = state[15];
    Ame = state[16];
    Ami = state[17];
    Amo = state[18];
    Amu = state[19];
    Asa = state[20];
    Ase = state[21];
    Asi = state[22];
    Aso = state[23];
    Asu = state[24];

    for (round = 0; round < 24; round += 2)
    {
        /* Round (round + 0): Axx -> Exx */

        Ba = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
        Be = Abe ^ Age ^ Ake ^ Ame ^ Ase;
        Bi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
        Bo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
        Bu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

        Da = Bu ^ rol(Be, 1);
        De = Ba ^ rol(Bi, 1);
        Di = Be ^ rol(Bo, 1);
        Do = Bi ^ rol(Bu, 1);
        Du = Bo ^ rol(Ba, 1);

        Ba = Aba ^ Da;
        Be = rol(Age ^ De, 44);
        Bi = rol(Aki ^ Di, 43);
        Bo = rol(Amo ^ Do, 21);
        Bu = rol(Asu ^ Du, 14);
        Eba = Ba ^ (~Be & Bi) ^ RC[round];
        Ebe = Be ^ (~Bi & Bo);
        Ebi = Bi ^ (~Bo & Bu);
        Ebo = Bo ^ (~Bu & Ba);
        Ebu = Bu ^ (~Ba & Be);

        Ba = rol(Abo ^ Do, 28);
        Be = rol(Agu ^ Du, 20);
        Bi = rol(Aka ^ Da, 3);
        Bo = rol(Ame ^ De, 45);
        Bu = rol(Asi ^ Di, 61);
        Ega = Ba ^ (~Be & Bi);
        Ege = Be ^ (~Bi & Bo);
        Egi = Bi ^ (~Bo & Bu);
        Ego = Bo ^ (~Bu & Ba);
        Egu = Bu ^ (~Ba & Be);

        Ba = rol(Abe ^ De, 1);
        Be = rol(Agi ^ Di, 6);
        Bi = rol(Ako ^ Do, 25);
        Bo = rol(Amu ^ Du, 8);
        Bu = rol(Asa ^ Da, 18);
        Eka = Ba ^ (~Be & Bi);
        Eke = Be ^ (~Bi & Bo);
        Eki = Bi ^ (~Bo & Bu);
        Eko = Bo ^ (~Bu & Ba);
        Eku = Bu ^ (~Ba & Be);

        Ba = rol(Abu ^ Du, 27);
        Be = rol(Aga ^ Da, 36);
        Bi = rol(Ake ^ De, 10);
        Bo = rol(Ami ^ Di, 15);
        Bu = rol(Aso ^ Do, 56);
        Ema = Ba ^ (~Be & Bi);
        Eme = Be ^ (~Bi & Bo);
        Emi = Bi ^ (~Bo & Bu);
        Emo = Bo ^ (~Bu & Ba);
        Emu = Bu ^ (~Ba & Be);

        Ba = rol(Abi ^ Di, 62);
        Be = rol(Ago ^ Do, 55);
        Bi = rol(Aku ^ Du, 39);
        Bo = rol(Ama ^ Da, 41);
        Bu = rol(Ase ^ De, 2);
        Esa = Ba ^ (~Be & Bi);
        Ese = Be ^ (~Bi & Bo);
        Esi = Bi ^ (~Bo & Bu);
        Eso = Bo ^ (~Bu & Ba);
        Esu = Bu ^ (~Ba & Be);

        /* Round (round + 1): Exx -> Axx */

        Ba = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        Be = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        Bi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        Bo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        Bu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

        Da = Bu ^ rol(Be, 1);
        De = Ba ^ rol(Bi, 1);
        Di = Be ^ rol(Bo, 1);
        Do = Bi ^ rol(Bu, 1);
        Du = Bo ^ rol(Ba, 1);

        Ba = Eba ^ Da;
        Be = rol(Ege ^ De, 44);
        Bi = rol(Eki ^ Di, 43);
        Bo = rol(Emo ^ Do, 21);
        Bu = rol(Esu ^ Du, 14);
        Aba = Ba ^ (~Be & Bi) ^ RC[round + 1];
        Abe = Be ^ (~Bi & Bo);
        Abi = Bi ^ (~Bo & Bu);
        Abo = Bo ^ (~Bu & Ba);
        Abu = Bu ^ (~Ba & Be);

        Ba = rol(Ebo ^ Do, 28);
        Be = rol(Egu ^ Du, 20);
        Bi = rol(Eka ^ Da, 3);
        Bo = rol(Eme ^ De, 45);
        Bu = rol(Esi ^ Di, 61);
        Aga = Ba ^ (~Be & Bi);
        Age = Be ^ (~Bi & Bo);
        Agi = Bi ^ (~Bo & Bu);
        Ago = Bo ^ (~Bu & Ba);
        Agu = Bu ^ (~Ba & Be);

        Ba = rol(Ebe ^ De, 1);
        Be = rol(Egi ^ Di, 6);
        Bi = rol(Eko ^ Do, 25);
        Bo = rol(Emu ^ Du, 8);
        Bu = rol(Esa ^ Da, 18);
        Aka = Ba ^ (~Be & Bi);
        Ake = Be ^ (~Bi & Bo);
        Aki = Bi ^ (~Bo & Bu);
        Ako = Bo ^ (~Bu & Ba);
        Aku = Bu ^ (~Ba & Be);

        Ba = rol(Ebu ^ Du, 27);
        Be = rol(Ega ^ Da, 36);
        Bi = rol(Eke ^ De, 10);
        Bo = rol(Emi ^ Di, 15);
        Bu = rol(Eso ^ Do, 56);
        Ama = Ba ^ (~Be & Bi);
        Ame = Be ^ (~Bi & Bo);
        Ami = Bi ^ (~Bo & Bu);
        Amo = Bo ^ (~Bu & Ba);
        Amu = Bu ^ (~Ba & Be);

        Ba = rol(Ebi ^ Di, 62);
        Be = rol(Ego ^ Do, 55);
        Bi = rol(Eku ^ Du, 39);
        Bo = rol(Ema ^ Da, 41);
        Bu = rol(Ese ^ De, 2);
        Asa = Ba ^ (~Be & Bi);
        Ase = Be ^ (~Bi & Bo);
        Asi = Bi ^ (~Bo & Bu);
        Aso = Bo ^ (~Bu & Ba);
        Asu = Bu ^ (~Ba & Be);
    }

    state[0] = Aba;
    state[1] = Abe;
    state[2] = Abi;
    state[3] = Abo;
    state[4] = Abu;
    state[5] = Aga;
    state[6] = Age;
    state[7] = Agi;
    state[8] = Ago;
    state[9] = Agu;
    state[10] = Aka;
    state[11] = Ake;
    state[12] = Aki;
    state[13] = Ako;
    state[14] = Aku;
    state[15] = Ama;
    state[16] = Ame;
    state[17] = Ami;
    state[18] = Amo;
    state[19] = Amu;
    state[20] = Asa;
    state[21] = Ase;
    state[22] = Asi;
    state[23] = Aso;
    state[24] = Asu;
}

/******** The FIPS202-defined functions. ********/

/*** Some helper macros. ***/

#define _(S) do { S } while (0)
#define FOR(i, ST, L, S) \
  _(for (size_t i = 0; i < L; i += ST) { S; })
#define mkapply_ds(NAME, S)                                          \
  static inline void NAME(uint8_t* dst,                              \
                          const uint8_t* src,                        \
                          size_t len) {                              \
    FOR(i, 1, len, S);                                               \
  }
#define mkapply_sd(NAME, S)                                          \
  static inline void NAME(const uint8_t* src,                        \
                          uint8_t* dst,                              \
                          size_t len) {                              \
    FOR(i, 1, len, S);                                               \
  }

mkapply_ds(xorin, dst[i] ^= src[i])  // xorin
mkapply_sd(setout, dst[i] = src[i])  // setout

#define P keccakf
#define Plen 200

// Fold P*F over the full blocks of an input.
#define foldP(I, L, F) \
  while (L >= rate) {  \
    F(a, I, rate);     \
    P(a);              \
    I += rate;         \
    L -= rate;         \
  }

/** The sponge-based hash construction. **/
static inline int hash(uint8_t* out, size_t outlen,
                       const uint8_t* in, size_t inlen,
                       size_t rate, uint8_t delim) {
  if ((out == NULL) || ((in == NULL) && inlen != 0) || (rate >= Plen)) {
    return -1;
  }
  uint8_t a[Plen] = {0};
  // Absorb input.
  foldP(in, inlen, xorin);
  // Xor in the DS and pad frame.
  a[inlen] ^= delim;
  a[rate - 1] ^= 0x80;
  // Xor in the last block.
  xorin(a, in, inlen);
  // Apply P
  P(a);
  // Squeeze output.
  foldP(out, outlen, setout);
  setout(a, out, outlen);
  memset(a, 0, 200);
  return 0;
}

/*** Helper macros to define SHA3 and SHAKE instances. ***/
#define defsha3(bits)                                             \
  int sha3_##bits(uint8_t* out, size_t outlen,                    \
                  const uint8_t* in, size_t inlen) {              \
    if (outlen > (bits/8)) {                                      \
      return -1;                                                  \
    }                                                             \
    return hash(out, outlen, in, inlen, 200 - (bits / 4), 0x01);  \
  }

/*** FIPS202 SHA3 FOFs ***/
defsha3(256)
defsha3(512)
