/*
 * Copyright (c) 2026 Vilhelm Engström
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @ingroup bloom
 * @brief Bloom Filter Header
 */

#ifndef ZEPHYR_INCLUDE_SYS_BLOOM_FILTER_H_
#define ZEPHYR_INCLUDE_SYS_BLOOM_FILTER_H_

#include <assert.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/sys/iterable_sections.h>

/**
 * @brief Generic bloom filter implementation.
 * @defgroup bloom Bloom Filter
 * @ingroup libs
 * @{
 *
 * This implementation is heavily based on the bloom filter provided
 * by <a href="https://github.com/vengaer/scc">scc</a>, albeit altered to
 * fit Zephyr and be C++-compatible.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** Generic bloom filter representation */
struct bloom_filter {
	/** Number of bits in the @c bitfield field */
	unsigned int nbits;
	/** Number of hashes to use */
	unsigned int nhashes;
#if defined CONFIG_BLOOM_FILTER_SIZE || defined __DOXYGEN__
	/** Number of entries in the filter */
	size_t size;
#endif
#if !defined __cplusplus || defined __DOXYGEN__
	/** Bitset used for tracking membership */
	uint8_t bitset[];
#else
	uint8_t bitset[1u];
#endif
};



#if defined CONFIG_BLOOM_FILTER_SIZE || defined __DOXYGEN__
/**
 * @brief Structure representing a bloom filter storing @p bitsize bits
 *
 * Used wherever BLOOM_FILTER_DEFINE() cannot be used, e.g. in structs, to
 * create a bloom filter storing @p bitsize bits.
 *
 * @code{.c}
 *
 * struct context {
 *	// Other members
 *
 *	// 23-bit bloom filter
 *	BLOOM_FILTER_STRUCT(23) flt;
 *
 *	// Even more members
 * };
 *
 * @endcode
 *
 * @param bitsize Number of bits to store in the filter.
 */
#define BLOOM_FILTER_STRUCT(bitsize)				\
	struct {						\
		unsigned int nbits;				\
		unsigned int nhashes;				\
		size_t size;					\
		static_assert(					\
			bitsize > 0, "Bitsize must be >0"	\
		);						\
		uint8_t bitset[(((bitsize) + 7u) & ~7u) >> 3u];	\
	}

#else /* BLOOM_FILTER_SIZE || __DOXYGEN__ */

#define BLOOM_FILTER_STRUCT(bitsize)				\
	struct {						\
		unsigned int nbits;				\
		unsigned int nhashes;				\
		static_assert(					\
			bitsize > 0, "Bitsize must be >0"	\
		);						\
		uint8_t bitset[(((bitsize) + 7u) & ~7u) >> 3u];	\
	}

#endif

#ifdef __cplusplus
static_assert(sizeof(BLOOM_FILTER_STRUCT(1)) == sizeof(struct bloom_filter),
"Filter struct mismatch");
#else
static_assert(sizeof(BLOOM_FILTER_STRUCT(1)) ==
		sizeof(struct bloom_filter) +
			((sizeof(uint8_t) + alignof(struct bloom_filter) - 1) &
				~(alignof(struct bloom_filter) - 1)),
"Filter struct mismatch");
#endif


/**
 * @brief Define a bloom filter with the given @p name.
 *
 * @param name       Name of the instance to create.
 * @param bitsize    Size of the filter, in bits.
 * @param num_hashes Number of hashes to use.
 */
#define BLOOM_FILTER_DEFINE(name, bitsize, num_hashes)		\
	BLOOM_FILTER_STRUCT(bitsize) name = {			\
		.nbits = (bitsize),				\
		.nhashes = (num_hashes),			\
	}


inline int z_bloom_filter_init(struct bloom_filter *flt, size_t fltsize,
		unsigned int num_hashes)
{
	flt->nbits = (fltsize - sizeof(*flt)) << 3u;
	flt->nhashes = num_hashes;
	memset(flt->bitset, 0, flt->nbits >> 3u);
	return 0;
}


/**
 * @brief Initiailize a bloom filter.
 *
 * May be used with filters declared using BLOOM_FILTER_STRUCT(). The bitsize
 * is derived from the size of @p flt.
 *
 * @note As BLOOM_FILTER_STRUCT() expands to an anonymous struct, this macro
 *       must by necessity support arbitrary types. Thus, the caller is
 *       responsible the @p flt parameter actually being a pointer to a bloom
 *       filter.
 *
 * @code{.c}
 *
 * // Declare a bloom filter with bitsize 43
 * BLOOM_FILTER_STRUCT(43) flt;
 *
 * // Initialise flt, use 6 hashes.
 * bloom_filter_init(&flt, 6);
 *
 * @endcode
 *
 * @param flt        Address of the filter to initialize. Must not
 *                   be a pointer to void.
 * @param num_hashes Number of hashes to use.
 *
 * @retval 0       Filter initialized.
 * @retval -EINVAL @p flt is a pointer to void.
 */
#define bloom_filter_init(flt, num_hashes)				\
	(int)_Generic((flt),						\
		void *: -EINVAL,					\
		void const *: -EINVAL,					\
		void volatile *: -EINVAL,				\
		void const volatile *: -EINVAL,				\
		default: z_bloom_filter_init(				\
			(void *)flt, sizeof(*(flt)), num_hashes		\
		)							\
	)


void z_bloom_filter_insert(struct bloom_filter *flt, void const *elem,
		size_t elemsize);

/**
 * @brief Insert value in the bloom filter.
 *
 * @param flt      The filter in which the value is to be inserted.
 * @param elem     Address of the element to be inserted.
 * @param elemsize Size of the element at @p elem, in bytes.
 */
inline void bloom_filter_insert(void *flt, void const *elem,
		size_t elemsize)
{
	z_bloom_filter_insert(flt, elem, elemsize);
}


bool z_bloom_filter_test(struct bloom_filter const *flt, void const *elem,
		size_t elemsize);

/**
 * @brief Test for set membership.
 *
 * @note By design, members ship tests in bloom filters @a may yield false
 *       positives. False negatives are, however, not possible.
 *
 * @param flt      The filter to check for membership in.
 * @param elem     Address of the element whose membership is to be tested.
 * @param elemsize Size of the element at @p elem.
 *
 * @retval true  The element appears to be present in the set.
 * @retval false The elemtn is not present in the set.
 */
inline bool bloom_filter_test(void const *flt, void const *elem,
	size_t elemsize)
{
	return z_bloom_filter_test(flt, elem, elemsize);
}


/**
 * @brief Remove all entries in a bloom filter.
 *
 * @param flt The filter to clear
 */
inline void bloom_filter_clear(void *fltadr)
{
	struct bloom_filter *flt = fltadr;
	memset(flt->bitset, 0, flt->nbits >> 3u);
#ifdef CONFIG_BLOOM_FILTER_SIZE
	flt->size = 0u;
#endif
}

#if defined CONFIG_BLOOM_FILTER_SIZE || defined __DOXYGEN__

inline size_t bloom_filter_size(void const *fltadr)
{
	struct bloom_filter const *flt = fltadr;
	return flt->size;
}

#endif /* BLOOM_FILTER_SIZE || __DOXYGEN__ */


#ifdef __cplusplus
}
#endif

/** @} */

#endif /* ZEPHYR_INCLUDE_SYS_BLOOM_FILTER_H_ */
