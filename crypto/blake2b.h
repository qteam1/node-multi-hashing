/**
 * BLAKE2 reference source code package - reference C implementations
 *
 * Written in 2012 by Samuel Neves <sneves@dei.uc.pt>
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along with
 * this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
#pragma once
#ifndef __BLAKE2B_H__
#define __BLAKE2B_H__

#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER)
#include <inttypes.h>
#define inline __inline
#define ALIGN(x) __declspec(align(x))
#else
#define ALIGN(x) __attribute__((aligned(x)))
#endif

#if defined(_MSC_VER) || defined(__x86_64__) || defined(__x86__)
#define NATIVE_LITTLE_ENDIAN
#endif

#if defined(_MSC_VER)
#define BLAKE2_PACKED(x) __pragma(pack(push, 1)) x __pragma(pack(pop))
#else
#define BLAKE2_PACKED(x) x __attribute__((packed))
#endif

/* blake2-impl.h */

static inline uint32_t load32( const void *src )
{
#if defined(NATIVE_LITTLE_ENDIAN)
	return *(uint32_t *)(src);
#else
	const uint8_t *p = (uint8_t *)src;
	uint32_t w = *p++;
	w |= (uint32_t)(*p++) << 8;
	w |= (uint32_t)(*p++) << 16;
	w |= (uint32_t)(*p++) << 24;
	return w;
#endif
}

static inline uint64_t load64( const void *src )
{
#if defined(NATIVE_LITTLE_ENDIAN)
	uint64_t w;
	memcpy(&w, src, sizeof w);
	return w;
#else
	const uint8_t *p = ( const uint8_t * )src;
	return (( uint64_t )( p[0] ) <<  0) |
		(( uint64_t )( p[1] ) <<  8) |
		(( uint64_t )( p[2] ) << 16) |
		(( uint64_t )( p[3] ) << 24) |
		(( uint64_t )( p[4] ) << 32) |
		(( uint64_t )( p[5] ) << 40) |
		(( uint64_t )( p[6] ) << 48) |
		(( uint64_t )( p[7] ) << 56) ;
#endif
}

static inline void store32( void *dst, uint32_t w )
{
#if defined(NATIVE_LITTLE_ENDIAN)
	*(uint32_t *)(dst) = w;
#else
	uint8_t *p = (uint8_t *)dst;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w;
#endif
}

static inline void store64( void *dst, uint64_t w )
{
#if defined(NATIVE_LITTLE_ENDIAN)
	memcpy(dst, &w, sizeof w);
#else
	uint8_t *p = ( uint8_t * )dst;
	p[0] = (uint8_t)(w >>  0);
	p[1] = (uint8_t)(w >>  8);
	p[2] = (uint8_t)(w >> 16);
	p[3] = (uint8_t)(w >> 24);
	p[4] = (uint8_t)(w >> 32);
	p[5] = (uint8_t)(w >> 40);
	p[6] = (uint8_t)(w >> 48);
	p[7] = (uint8_t)(w >> 56);
#endif
}

static inline uint64_t load48(const void *src)
{
	const uint8_t *p = (const uint8_t *)src;
	uint64_t w = *p++;
	w |= (uint64_t)(*p++) << 8;
	w |= (uint64_t)(*p++) << 16;
	w |= (uint64_t)(*p++) << 24;
	w |= (uint64_t)(*p++) << 32;
	w |= (uint64_t)(*p++) << 40;
	return w;
}

static inline void store48(void *dst, uint64_t w)
{
	uint8_t *p = (uint8_t *)dst;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w;
}

static inline uint64_t rotr64( const uint64_t w, const unsigned c )
{
  return ( w >> c ) | ( w << ( 64 - c ) );
}

/* prevents compiler optimizing out memset() */
static inline void secure_zero_memory(void *v, size_t n)
{
	volatile uint8_t *p = ( volatile uint8_t * )v;

	while( n-- ) *p++ = 0;
}

/* blake2.h */

enum blake2b_constant
{
	BLAKE2B_BLOCKBYTES = 128,
	BLAKE2B_OUTBYTES   = 64,
	BLAKE2B_KEYBYTES   = 64,
	BLAKE2B_SALTBYTES  = 16,
	BLAKE2B_PERSONALBYTES = 16
};

BLAKE2_PACKED(struct blake2b_param__
{
	uint8_t  digest_length; /* 1 */
	uint8_t  key_length;    /* 2 */
	uint8_t  fanout;        /* 3 */
	uint8_t  depth;         /* 4 */
	uint32_t leaf_length;   /* 8 */
	uint32_t node_offset;   /* 12 */
	uint32_t xof_length;    /* 16 */
	uint8_t  node_depth;    /* 17 */
	uint8_t  inner_length;  /* 18 */
	uint8_t  reserved[14];  /* 32 */
	uint8_t  salt[BLAKE2B_SALTBYTES]; /* 48 */
	uint8_t  personal[BLAKE2B_PERSONALBYTES];  /* 64 */
});

typedef struct blake2b_param__ blake2b_param;

ALIGN( 64 ) typedef struct __blake2b_state
{
	uint64_t h[8];
	uint64_t t[2];
	uint64_t f[2];
	uint8_t  buf[2 * BLAKE2B_BLOCKBYTES];
	size_t   buflen;
	size_t   outlen;
	uint8_t  last_node;
} blake2b_state;

#if defined(__cplusplus)
extern "C" {
#endif

	// Streaming API
	int blake2b_init( blake2b_state *S, size_t outlen );
	int blake2b_init_key( blake2b_state *S, size_t outlen, const void *key, size_t keylen );
	int blake2b_init_param( blake2b_state *S, const blake2b_param *P );
	int blake2b_update( blake2b_state *S, const void *in, size_t inlen );
	int blake2b_final( blake2b_state *S, void *out, size_t outlen );

#if defined(__cplusplus)
}
#endif

#endif
