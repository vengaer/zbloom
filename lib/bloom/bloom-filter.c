/*
 * Copyright (c) 2026 Vilhelm Engström
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <stdalign.h>

#include <zephyr/sys/bloom-filter.h>
#include <zephyr/sys/hash-murmur128.h>


int z_bloom_filter_init(struct bloom_filter *flt, size_t fltsize,
		unsigned int num_hashes);
void bloom_filter_insert(void *flt, void const *elem, size_t elemsize);
bool bloom_filter_test(void const *flt, void const *elem, size_t elemsize);
void bloom_filter_clear(void *fltadr);
#ifdef CONFIG_BLOOM_FILTER_SIZE
size_t bloom_filter_size(void const *fltadr);
#endif


static inline void bloom_filter_set_bit(struct bloom_filter *flt,
			unsigned int index)
{
	flt->bitset[index >> 3u] |= (1u << (index & 7u));
}


static inline bool bloom_filter_bit_is_set(struct bloom_filter const *flt,
			unsigned int index)
{
	return !!(flt->bitset[index >> 3u] & (1u << (index & 7u)));
}


void z_bloom_filter_insert(struct bloom_filter *flt, void const *elem,
	size_t elemsize)
{
	static_assert(alignof(union sys_digest128) >= alignof(uint32_t), "");

	unsigned int i;
	union sys_digest128 digest;

	for (i = 0u; i < flt->nhashes >> 2u; ++i) {
		sys_hash128_murmur3(&digest, elem, elemsize, i);

		bloom_filter_set_bit(flt, digest.d32[0u] % flt->nbits);
		bloom_filter_set_bit(flt, digest.d32[1u] % flt->nbits);
		bloom_filter_set_bit(flt, digest.d32[2u] % flt->nbits);
		bloom_filter_set_bit(flt, digest.d32[3u] % flt->nbits);
	}

	if (flt->nhashes & 3u) {
		sys_hash128_murmur3(&digest, elem, elemsize, i);
		for (unsigned int j = 0u; j < (flt->nhashes & 3u); ++j)
			bloom_filter_set_bit(flt, digest.d32[j] % flt->nbits);
	}

#ifdef CONFIG_BLOOM_FILTER_SIZE
	flt->size += 1u;
#endif
}


bool z_bloom_filter_test(struct bloom_filter const *flt, void const *elem,
	size_t elemsize)
{
	bool present;
	unsigned int i;
	union sys_digest128 digest;


	present = true;
	for (i = 0u; present && i < flt->nhashes >> 2u; ++i) {
		sys_hash128_murmur3(&digest, elem, elemsize, i);

		present &= bloom_filter_bit_is_set(flt,
				digest.d32[0u] % flt->nbits);
		present &= bloom_filter_bit_is_set(flt,
				digest.d32[1u] % flt->nbits);
		present &= bloom_filter_bit_is_set(flt,
				digest.d32[2u] % flt->nbits);
		present &= bloom_filter_bit_is_set(flt,
				digest.d32[3u] % flt->nbits);
	}

	if (present && flt->nhashes & 3u) {
		sys_hash128_murmur3(&digest, elem, elemsize, i);
		for (unsigned int j = 0u; present && j < (flt->nhashes & 3u); ++j)
			present &= bloom_filter_bit_is_set(flt,
					digest.d32[j] % flt->nbits);
	}

	return present;
}
