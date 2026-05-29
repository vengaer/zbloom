/*
 * Copyright (c) 2026 Vilhelm Engström
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @ingroup hash_functions
 * @brief x86 version of the 128-bit digest murmur3 hash.
 */

#ifndef ZEPHYR_INCLUDE_SYS_HASH_MURMUR128_H_
#define ZEPHYR_INCLUDE_SYS_HASH_MURMUR128_H_

#include <stddef.h>
#include <stdint.h>

/**
 * @brief x86 128-bit murmur3 hash
 * @ingroup hash_functions
 * @{
 */

#ifdef __cplusplus
extern "C" {
#endif

/** 128-bit digest */
union sys_digest128 {
	/** As u8 array */
	uint8_t d8[128u >> 3u];
	/** As u16 array */
	uint16_t d16[128 >> 4u];
	/** As u32 array */
	uint32_t d32[128 >> 5u];
};


/**
 * @brief Calculate x86 version of the 128-bit digest murmur3 hash.
 *
 * @param digest Address to store the digest at.
 * @param data   Data to calculate the hash of.
 * @param size   Size of the data at @p data.
 * @param seed   Initial seed.
 */
void sys_hash128_murmur3(union sys_digest128 *digest, void const *data,
		size_t size, uint_fast32_t seed);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* ZEPHYR_INCLUDE_SYS_HASH_MURMUR128_H_ */
