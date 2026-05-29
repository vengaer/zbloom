/*
 * Copyright (c) 2026 Vilhelm Engström
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @ingroup hash_functions
 * @brief 128-bit murmur3 hash optimized for 32-bit architectures.
 */

#include <assert.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/sys/hash-murmur128.h>
#include <zephyr/sys/util.h>
#include <zephyr/toolchain.h>


#define MM128_X86_C1 UINT32_C(0x239b961b)
#define MM128_X86_C2 UINT32_C(0xab0e9789)
#define MM128_X86_C3 UINT32_C(0x38b34ae5)
#define MM128_X86_C4 UINT32_C(0xa1e38b93)


static inline uint_fast32_t mm128_rol32(uint32_t value, uint_fast8_t by)
{
	return (value << by) | (value >> (32u - by));
}


static inline uint_fast32_t mm128_fmix32(uint32_t h)
{
	h ^= h >> 16u;
	h *= UINT32_C(0x85ebca6b);
	h ^= h >> 13u;
	h *= UINT32_C(0xc2b2ae35);
	h ^= h >> 16u;
	return h;
}


static void mm128_calc(uint32_t hs[static restrict 4u],
                uint32_t ks[static restrict 4u])
{
	ks[0u] *= MM128_X86_C1;
	ks[0u] = mm128_rol32(ks[0u], 15u);
	ks[0u] *= MM128_X86_C2;

	hs[0u] ^= ks[0u];
	hs[0u] = mm128_rol32(hs[0u], 19u);
	hs[0u] += hs[1u];
	hs[0u] *= 5u;
	hs[0u] += UINT32_C(0x561ccd1b);

	ks[1u] *= MM128_X86_C2;
	ks[1u] = mm128_rol32(ks[1u], 16u);
	ks[1u] *= MM128_X86_C3;

	hs[1u] ^= ks[1u];
	hs[1u] = mm128_rol32(hs[1u], 17u);
	hs[1u] += hs[2u];
	hs[1u] *= 5u;
	hs[1u] += UINT32_C(0x0bcaa747);

	ks[2u] *= MM128_X86_C3;
	ks[2u] = mm128_rol32(ks[2u], 17u);
	ks[2u] *= MM128_X86_C4;

	hs[2u] ^= ks[2u];
	hs[2u] = mm128_rol32(hs[2u], 15u);
	hs[2u] += hs[3u];
	hs[2u] *= 5u;
	hs[2u] += UINT32_C(0x96cd1c35);

	ks[3u] *= MM128_X86_C4;
	ks[3u] = mm128_rol32(ks[3u], 18u);
	ks[3u] *= MM128_X86_C1;

	hs[3u] ^= ks[3u];
	hs[3u] = mm128_rol32(hs[3u], 13u);
	hs[3u] += hs[0u];
	hs[3u] *= 5u;
	hs[3u] += UINT32_C(0x32ac3b17);
}

static void mm128_unaligned(uint32_t hs[static restrict 4u],
                void const *restrict data, size_t size)
{
	unsigned long res = (unsigned long)data & (alignof(uint32_t) - 1u);
	uint32_t tmp = UINT32_C(0);
	memcpy((unsigned char *)&tmp + sizeof(uint32_t) - res, data, res);

	uint32_t const *p32 = (void const *)((unsigned char const *)data + res);

	unsigned const rsft = res << 3u;
	unsigned const msft = (sizeof(tmp) - res) << 3u;

	uint32_t ks[4u];

	for (unsigned i = 0u; i < size >> 4u; ++i) {
		ks[1u] = p32[i << 2u];
		ks[0u] = (tmp >> msft) | (ks[1u] << rsft);

		ks[2u] = p32[(i << 2u) + 1u];
		ks[1u] = (ks[1u] >> msft) | (ks[2u] << rsft);

		ks[3u] = p32[(i << 2u) + 2u];
		ks[2u] = (ks[2u] >> msft) | (ks[3u] << rsft);

		tmp = p32[(i << 2u) + 3u];
		ks[3u] = (ks[3u] >> msft) | (tmp << rsft);

		mm128_calc(hs, ks);
	}
}


static void mm128_aligned(uint32_t hs[static restrict 4u],
                void const *restrict data, size_t size)
{
	uint32_t const *p32 = data;
	uint32_t ks[4u];
	for (unsigned i = 0u; i < size >> 4u; ++i) {
		ks[0u] = p32[(i << 2u)];
		ks[1u] = p32[(i << 2u) + 1u];
		ks[2u] = p32[(i << 2u) + 2u];
		ks[3u] = p32[(i << 2u) + 3u];
		mm128_calc(hs, ks);
	}
}


static void mm128_residual(uint32_t hs[static restrict 4u],
		void const *restrict data, size_t size)
{
	unsigned char const *p = data;
	p += size & ~15u;

	uint32_t ks[4u] = { 0 };

	switch (size & 15u) {
	case 15u: ks[3u] ^= p[14u] << 16u;
	case 14u: ks[3u] ^= p[13u] << 8u;
	case 13u:
		ks[3u] ^= p[12u];
		ks[3u] *= MM128_X86_C4;
		ks[3u] = mm128_rol32(ks[3u], 18u);
		ks[3u] *= MM128_X86_C1;
		hs[3u] ^= ks[3u];
		__fallthrough;
	case 12u: ks[2u] ^= p[11u] << 24u;
	case 11u: ks[2u] ^= p[10u] << 16u;
	case 10u: ks[2u] ^= p[9u] << 8u;
	case 9u:
		ks[2u] ^= p[8u];
		ks[2u] *= MM128_X86_C3;
		ks[2u] = mm128_rol32(ks[2u], 17u);
		ks[2u] *= MM128_X86_C4;
		hs[2u] ^= ks[2u];
		__fallthrough;
	case 8u: ks[1u] ^= p[7u] << 24u;
	case 7u: ks[1u] ^= p[6u] << 16u;
	case 6u: ks[1u] ^= p[5u] << 8u;
	case 5u:
		ks[1u] ^= p[4u];
		ks[1u] *= MM128_X86_C2;
		ks[1u] = mm128_rol32(ks[1u], 16u);
		ks[1u] *= MM128_X86_C3;
		hs[1u] ^= ks[1u];
		__fallthrough;
	case 4u: ks[0u] ^= p[3u] << 24u;
	case 3u: ks[0u] ^= p[2u] << 16u;
	case 2u: ks[0u] ^= p[1u] << 8u;
	case 1u:
		ks[0u] ^= p[0u];
		ks[0u] *= MM128_X86_C1;
		ks[0u] = mm128_rol32(ks[0u], 15u);
		ks[0u] *= MM128_X86_C2;
		hs[0u] ^= ks[0u];
		break;
	}
}


void sys_hash128_murmur3(union sys_digest128 *digest, void const *data,
		size_t size, uint_fast32_t seed)
{
	uint32_t hs[] = { seed, seed, seed, seed };

	if ((unsigned long)data & (alignof(uint32_t) - 1u))
		mm128_unaligned(hs, data, size);
	else
		mm128_aligned(hs, data, size);

	if (size & 15u)
		mm128_residual(hs, data, size);

	hs[0u] ^= size;
	hs[1u] ^= size;
	hs[2u] ^= size;
	hs[3u] ^= size;

	hs[0u] += hs[1u];
	hs[0u] += hs[2u];
	hs[0u] += hs[3u];

	hs[1u] += hs[0u];
	hs[2u] += hs[0u];
	hs[3u] += hs[0u];

	hs[0u] = mm128_fmix32(hs[0u]);
	hs[1u] = mm128_fmix32(hs[1u]);
	hs[2u] = mm128_fmix32(hs[2u]);
	hs[3u] = mm128_fmix32(hs[3u]);

	hs[0u] += hs[1u];
	hs[0u] += hs[2u];
	hs[0u] += hs[3u];

	hs[1u] += hs[0u];
	hs[2u] += hs[0u];
	hs[3u] += hs[0u];

	static_assert(sizeof(digest->d8) == sizeof(hs), "");
	memcpy(digest->d8, hs, sizeof(hs));
}
