#ifndef __KRG_NODEMASK_H
#define __KRG_NODEMASK_H

/*
 * This file is nearly a copy/paste of linux/cpumask.h (2.6.20)
 * Btw this code is very closed to the NUMA related code linux/nodemask.h
 * It will be a good idea to check if can merge these two files
 *
 * nodemasks provide a bitmap suitable for representing the
 * set of nodes in a system, one bit position per node number.
 *
 * See detailed comments in the file linux/bitmap.h describing the
 * data type on which these krgnodemasks are based.
 *
 * For details of krgnodemask_scnprintf() and krgnodemask_parse_user(),
 * see bitmap_scnprintf() and bitmap_parse_user() in lib/bitmap.c.
 * For details of krgnodelist_scnprintf() and krgnodelist_parse(), see
 * bitmap_scnlistprintf() and bitmap_parselist(), also in bitmap.c.
 * For details of krgnode_remap(), see bitmap_bitremap in lib/bitmap.c
 * For details of krgnodes_remap(), see bitmap_remap in lib/bitmap.c.
 *
 * The available nodemask operations are:
 *
 * void krgnode_set(node, mask)		turn on bit 'node' in mask
 * void krgnode_clear(node, mask)		turn off bit 'node' in mask
 * void krgnodes_setall(mask)		set all bits
 * void krgnodes_clear(mask)		clear all bits
 * int krgnode_isset(node, mask)		true iff bit 'node' set in mask
 * int krgnode_test_and_set(node, mask)	test and set bit 'node' in mask
 *
 * void krgnodes_and(dst, src1, src2)	dst = src1 & src2  [intersection]
 * void krgnodes_or(dst, src1, src2)	dst = src1 | src2  [union]
 * void krgnodes_xor(dst, src1, src2)	dst = src1 ^ src2
 * void krgnodes_andnot(dst, src1, src2)	dst = src1 & ~src2
 * void krgnodes_complement(dst, src)	dst = ~src
 *
 * int krgnodes_equal(mask1, mask2)		Does mask1 == mask2?
 * int krgnodes_intersects(mask1, mask2)	Do mask1 and mask2 intersect?
 * int krgnodes_subset(mask1, mask2)	Is mask1 a subset of mask2?
 * int krgnodes_empty(mask)			Is mask empty (no bits sets)?
 * int krgnodes_full(mask)			Is mask full (all bits sets)?
 * int krgnodes_weight(mask)		Hamming weigh - number of set bits
 *
 * void krgnodes_shift_right(dst, src, n)	Shift right
 * void krgnodes_shift_left(dst, src, n)	Shift left
 *
 * int first_krgnode(mask)			Number lowest set bit, or KERRIGHED_MAX_NODES
 * int next_krgnode(node, mask)		Next node past 'node', or KERRIGHED_MAX_NODES
 *
 * krgnodemask_t krgnodemask_of_node(node)	Return nodemask with bit 'node' set
 * KRGNODE_MASK_ALL				Initializer - all bits set
 * KRGNODE_MASK_NONE			Initializer - no bits set
 * unsigned long *krgnodes_addr(mask)	Array of unsigned long's in mask
 *
 * int krgnodemask_scnprintf(buf, len, mask) Format nodemask for printing
 * int krgnodemask_parse_user(ubuf, ulen, mask)	Parse ascii string as nodemask
 * int krgnodelist_scnprintf(buf, len, mask) Format nodemask as list for printing
 * int krgnodelist_parse(buf, map)		Parse ascii string as nodelist
 * int krgnode_remap(oldbit, old, new)	newbit = map(old, new)(oldbit)
 * int krgnodes_remap(dst, src, old, new)	*dst = map(old, new)(src)
 *
 * for_each_krgnode_mask(node, mask)		for-loop node over mask
 *
 * int num_online_krgnodes()		Number of online NODEs
 * int num_possible_krgnodes()		Number of all possible NODEs
 * int num_present_krgnodes()		Number of present NODEs
 *
 * int krgnode_online(node)			Is some node online?
 * int krgnode_possible(node)		Is some node possible?
 * int krgnode_present(node)			Is some node present (can schedule)?
 *
 * int any_online_krgnode(mask)		First online node in mask
 *
 * for_each_possible_krgnode(node)		for-loop node over node_possible_map
 * for_each_online_krgnode(node)		for-loop node over node_online_map
 * for_each_present_krgnode(node)		for-loop node over node_present_map
 *
 * Subtlety:
 * 1) The 'type-checked' form of node_isset() causes gcc (3.3.2, anyway)
 *    to generate slightly worse code.  Note for example the additional
 *    40 lines of assembly code compiling the "for each possible node"
 *    loops buried in the disk_stat_read() macros calls when compiling
 *    drivers/block/genhd.c (arch i386, CONFIG_SMP=y).  So use a simple
 *    one-line #define for node_isset(), instead of wrapping an inline
 *    inside a macro, the way we do the other calls.
 */

#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/bitmap.h>
#include <kerrighed/sys/types.h>
#if KERRIGHED_MAX_NODES <= 1
/* kerrighed_node_id is used for some macros in this special case */
#include <kerrighed/krginit.h>
#endif


typedef struct { DECLARE_BITMAP(bits, KERRIGHED_MAX_NODES); } krgnodemask_t;
typedef struct { DECLARE_BITMAP(bits, KERRIGHED_HARD_MAX_NODES); } __krgnodemask_t;

extern krgnodemask_t _unused_krgnodemask_arg_;

#define krgnode_set(node, dst) __krgnode_set((node), &(dst))
static inline void __krgnode_set(int node, volatile krgnodemask_t *dstp)
{
	set_bit(node, dstp->bits);
}

#define krgnode_clear(node, dst) __krgnode_clear((node), &(dst))
static inline void __krgnode_clear(int node, volatile krgnodemask_t *dstp)
{
	clear_bit(node, dstp->bits);
}

#define krgnodes_setall(dst) __krgnodes_setall(&(dst))
static inline void __krgnodes_setall(krgnodemask_t *dstp)
{
	bitmap_fill(dstp->bits, KERRIGHED_MAX_NODES);
}

#define krgnodes_clear(dst) __krgnodes_clear(&(dst))
static inline void __krgnodes_clear(krgnodemask_t *dstp)
{
	bitmap_zero(dstp->bits, KERRIGHED_MAX_NODES);
}

#define krgnodes_copy(dst, src) __krgnodes_copy(&(dst), &(src))
static inline void __krgnodes_copy(krgnodemask_t *dstp, const krgnodemask_t *srcp)
{
	bitmap_copy(dstp->bits, srcp->bits, KERRIGHED_MAX_NODES);
}

/* No static inline type checking - see Subtlety (1) above. */
#define krgnode_isset(node, krgnodemask) test_bit((node), (krgnodemask).bits)
#define __krgnode_isset(node, krgnodemask) test_bit((node), (krgnodemask)->bits)

#define krgnode_test_and_set(node, krgnodemask) __krgnode_test_and_set((node), &(krgnodemask))
static inline int __krgnode_test_and_set(int node, krgnodemask_t *addr)
{
	return test_and_set_bit(node, addr->bits);
}

#define krgnodes_and(dst, src1, src2) __krgnodes_and(&(dst), &(src1), &(src2), KERRIGHED_MAX_NODES)
static inline void __krgnodes_and(krgnodemask_t *dstp, const krgnodemask_t *src1p,
					const krgnodemask_t *src2p, int nbits)
{
	bitmap_and(dstp->bits, src1p->bits, src2p->bits, nbits);
}

#define krgnodes_or(dst, src1, src2) __krgnodes_or(&(dst), &(src1), &(src2), KERRIGHED_MAX_NODES)
static inline void __krgnodes_or(krgnodemask_t *dstp, const krgnodemask_t *src1p,
					const krgnodemask_t *src2p, int nbits)
{
	bitmap_or(dstp->bits, src1p->bits, src2p->bits, nbits);
}

#define krgnodes_xor(dst, src1, src2) __krgnodes_xor(&(dst), &(src1), &(src2), KERRIGHED_MAX_NODES)
static inline void __krgnodes_xor(krgnodemask_t *dstp, const krgnodemask_t *src1p,
					const krgnodemask_t *src2p, int nbits)
{
	bitmap_xor(dstp->bits, src1p->bits, src2p->bits, nbits);
}

#define krgnodes_andnot(dst, src1, src2) \
				__krgnodes_andnot(&(dst), &(src1), &(src2), KERRIGHED_MAX_NODES)
static inline void __krgnodes_andnot(krgnodemask_t *dstp, const krgnodemask_t *src1p,
					const krgnodemask_t *src2p, int nbits)
{
	bitmap_andnot(dstp->bits, src1p->bits, src2p->bits, nbits);
}

#define krgnodes_complement(dst, src) __krgnodes_complement(&(dst), &(src), KERRIGHED_MAX_NODES)
static inline void __krgnodes_complement(krgnodemask_t *dstp,
					const krgnodemask_t *srcp, int nbits)
{
	bitmap_complement(dstp->bits, srcp->bits, nbits);
}

#define krgnodes_equal(src1, src2) __krgnodes_equal(&(src1), &(src2))
static inline int __krgnodes_equal(const krgnodemask_t *src1p,
				   const krgnodemask_t *src2p)
{
	return bitmap_equal(src1p->bits, src2p->bits, KERRIGHED_MAX_NODES);
}

#define krgnodes_intersects(src1, src2) __krgnodes_intersects(&(src1), &(src2), KERRIGHED_MAX_NODES)
static inline int __krgnodes_intersects(const krgnodemask_t *src1p,
					const krgnodemask_t *src2p, int nbits)
{
	return bitmap_intersects(src1p->bits, src2p->bits, nbits);
}

#define krgnodes_subset(src1, src2) __krgnodes_subset(&(src1), &(src2), KERRIGHED_MAX_NODES)
static inline int __krgnodes_subset(const krgnodemask_t *src1p,
					const krgnodemask_t *src2p, int nbits)
{
	return bitmap_subset(src1p->bits, src2p->bits, nbits);
}

#define krgnodes_empty(src) __krgnodes_empty(&(src))
static inline int __krgnodes_empty(const krgnodemask_t *srcp)
{
	return bitmap_empty(srcp->bits, KERRIGHED_MAX_NODES);
}

#define krgnodes_full(nodemask) __krgnodes_full(&(nodemask), KERRIGHED_MAX_NODES)
static inline int __krgnodes_full(const krgnodemask_t *srcp, int nbits)
{
	return bitmap_full(srcp->bits, nbits);
}

#define krgnodes_weight(nodemask) __krgnodes_weight(&(nodemask))
static inline int __krgnodes_weight(const krgnodemask_t *srcp)
{
	return bitmap_weight(srcp->bits, KERRIGHED_MAX_NODES);
}

#define krgnodes_shift_right(dst, src, n) \
			__krgnodes_shift_right(&(dst), &(src), (n), KERRIGHED_MAX_NODES)
static inline void __krgnodes_shift_right(krgnodemask_t *dstp,
					const krgnodemask_t *srcp, int n, int nbits)
{
	bitmap_shift_right(dstp->bits, srcp->bits, n, nbits);
}

#define krgnodes_shift_left(dst, src, n) \
			__krgnodes_shift_left(&(dst), &(src), (n), KERRIGHED_MAX_NODES)
static inline void __krgnodes_shift_left(krgnodemask_t *dstp,
					const krgnodemask_t *srcp, int n, int nbits)
{
	bitmap_shift_left(dstp->bits, srcp->bits, n, nbits);
}

#define first_krgnode(src) __first_krgnode(&(src))
static inline int __first_krgnode(const krgnodemask_t *srcp)
{
	return min_t(int, KERRIGHED_MAX_NODES, find_first_bit(srcp->bits, KERRIGHED_MAX_NODES));
}

#define next_krgnode(n, src) __next_krgnode((n), &(src))
static inline int __next_krgnode(int n, const krgnodemask_t *srcp)
{
	return min_t(int, KERRIGHED_MAX_NODES,find_next_bit(srcp->bits, KERRIGHED_MAX_NODES, n+1));
}

#define krgnodemask_of_node(node)						\
({									\
	typeof(_unused_krgnodemask_arg_) m;					\
	if (sizeof(m) == sizeof(unsigned long)) {			\
		m.bits[0] = 1UL<<(node);					\
	} else {							\
		krgnodes_clear(m);						\
		krgnode_set((node), m);					\
	}								\
	m;								\
})

#define KRGNODE_MASK_LAST_WORD BITMAP_LAST_WORD_MASK(KERRIGHED_MAX_NODES)

#if KERRIGHED_MAX_NODES <= BITS_PER_LONG

#define KRGNODE_MASK_ALL							\
(krgnodemask_t) { {								\
	[BITS_TO_LONGS(KERRIGHED_MAX_NODES)-1] = KRGNODE_MASK_LAST_WORD			\
} }

#else

#define KRGNODE_MASK_ALL							\
(krgnodemask_t) { {								\
	[0 ... BITS_TO_LONGS(KERRIGHED_MAX_NODES)-2] = ~0UL,			\
	[BITS_TO_LONGS(KERRIGHED_MAX_NODES)-1] = KRGNODE_MASK_LAST_WORD			\
} }

#endif

#define KRGNODE_MASK_NONE							\
(krgnodemask_t) { {								\
	[0 ... BITS_TO_LONGS(KERRIGHED_MAX_NODES)-1] =  0UL				\
} }

#define KRGNODE_MASK_NODE0							\
(krgnodemask_t) { {								\
	[0] =  1UL							\
} }

#define krgnodes_addr(src) ((src).bits)

#define krgnodemask_scnprintf(buf, len, src) \
			__krgnodemask_scnprintf((buf), (len), &(src), KERRIGHED_MAX_NODES)
static inline int __krgnodemask_scnprintf(char *buf, int len,
					const krgnodemask_t *srcp, int nbits)
{
	return bitmap_scnprintf(buf, len, srcp->bits, nbits);
}

#define krgnodemask_parse_user(ubuf, ulen, dst) \
			__krgnodemask_parse_user((ubuf), (ulen), &(dst), KERRIGHED_MAX_NODES)
static inline int __krgnodemask_parse_user(const char __user *buf, int len,
					krgnodemask_t *dstp, int nbits)
{
	return bitmap_parse_user(buf, len, dstp->bits, nbits);
}

#define krgnodelist_scnprintf(buf, len, src) \
			__krgnodelist_scnprintf((buf), (len), &(src), KERRIGHED_MAX_NODES)
static inline int __krgnodelist_scnprintf(char *buf, int len,
					const krgnodemask_t *srcp, int nbits)
{
	return bitmap_scnlistprintf(buf, len, srcp->bits, nbits);
}

#define krgnodelist_parse(buf, dst) __krgnodelist_parse((buf), &(dst), KERRIGHED_MAX_NODES)
static inline int __krgnodelist_parse(const char *buf, krgnodemask_t *dstp, int nbits)
{
	return bitmap_parselist(buf, dstp->bits, nbits);
}

#define krgnode_remap(oldbit, old, new) \
		__krgnode_remap((oldbit), &(old), &(new), KERRIGHED_MAX_NODES)
static inline int __krgnode_remap(int oldbit,
		const krgnodemask_t *oldp, const krgnodemask_t *newp, int nbits)
{
	return bitmap_bitremap(oldbit, oldp->bits, newp->bits, nbits);
}

#define krgnodes_remap(dst, src, old, new) \
		__krgnodes_remap(&(dst), &(src), &(old), &(new), KERRIGHED_MAX_NODES)
static inline void __krgnodes_remap(krgnodemask_t *dstp, const krgnodemask_t *srcp,
		const krgnodemask_t *oldp, const krgnodemask_t *newp, int nbits)
{
	bitmap_remap(dstp->bits, srcp->bits, oldp->bits, newp->bits, nbits);
}

#if KERRIGHED_MAX_NODES > 1
#define for_each_krgnode_mask(node, mask)		\
	for ((node) = first_krgnode(mask);		\
		(node) < KERRIGHED_MAX_NODES;		\
		(node) = next_krgnode((node), (mask)))
#define __for_each_krgnode_mask(node, mask)		\
	for ((node) = __first_krgnode(mask);		\
		(node) < KERRIGHED_MAX_NODES;		\
		(node) = __next_krgnode((node), (mask)))

#else /* KERRIGHED_MAX_NODES == 1 */
#define for_each_krgnode_mask(node, mask)		\
	for ((node) = kerrighed_node_id; (node) < (kerrighed_node_id+1); (node)++, (void)mask)
#define __for_each_krgnode_mask(node, mask)		\
	for ((node) = kerrighed_node_id; (node) < (kerrighed_node_id+1); (node)++, (void)mask)
#endif /* KERRIGHED_MAX_NODES */

#define next_krgnode_in_ring(node, v) __next_krgnode_in_ring(node, &(v))
static inline kerrighed_node_t __next_krgnode_in_ring(kerrighed_node_t node,
						      const krgnodemask_t *v)
{
	kerrighed_node_t res;
	res = __next_krgnode(node, v);

	if (res < KERRIGHED_MAX_NODES)
		return res;

	return __first_krgnode(v);
}

#define nth_krgnode(node, v) __nth_krgnode(node, &(v))
static inline kerrighed_node_t __nth_krgnode(kerrighed_node_t node,
					     const krgnodemask_t *v)
{
	kerrighed_node_t iter;

	iter = __first_krgnode(v);
	while (node > 0) {
		iter = __next_krgnode(iter, v);
		node--;
	}

	return iter;
}

/** Return true if the index is the only one set in the vector */
#define krgnode_is_unique(node, v) __krgnode_is_unique(node, &(v))
static inline int __krgnode_is_unique(kerrighed_node_t node,
				      const krgnodemask_t *v)
{
  int i;
  
  i = __first_krgnode(v);
  if(i != node) return 0;
  
  i = __next_krgnode(node, v);
  if(i != KERRIGHED_MAX_NODES) return 0;
  
  return 1;
}

/*
 * krgnode_online_map: list of nodes available as object injection target
 * krgnode_present_map: list of nodes ready to be added in a cluster
 * krgnode_possible_map: list of nodes that may join the cluster in the future
 */

extern krgnodemask_t krgnode_possible_map;
extern krgnodemask_t krgnode_online_map;
extern krgnodemask_t krgnode_present_map;

#if KERRIGHED_MAX_NODES > 1
#define num_online_krgnodes()	krgnodes_weight(krgnode_online_map)
#define num_possible_krgnodes()	krgnodes_weight(krgnode_possible_map)
#define num_present_krgnodes()	krgnodes_weight(krgnode_present_map)
#define krgnode_online(node)	krgnode_isset((node), krgnode_online_map)
#define krgnode_possible(node)	krgnode_isset((node), krgnode_possible_map)
#define krgnode_present(node)	krgnode_isset((node), krgnode_present_map)

#define any_online_krgnode(mask) __any_online_krgnode(&(mask))
int __any_online_krgnode(const krgnodemask_t *mask);

#else

#define num_online_krgnodes()	1
#define num_possible_krgnodes()	1
#define num_present_krgnodes()	1
#define krgnode_online(node)		((node) == kerrighed_node_id)
#define krgnode_possible(node)	((node) == kerrighed_node_id)
#define krgnode_present(node)	((node) == kerrighed_node_id)

#define any_online_krgnode(mask)		kerrighed_node_id
#endif

#define for_each_possible_krgnode(node)  for_each_krgnode_mask((node), krgnode_possible_map)
#define for_each_online_krgnode(node)  for_each_krgnode_mask((node), krgnode_online_map)
#define for_each_present_krgnode(node) for_each_krgnode_mask((node), krgnode_present_map)

#define set_krgnode_possible(node) krgnode_set(node, krgnode_possible_map)
#define set_krgnode_online(node)   krgnode_set(node, krgnode_online_map)
#define set_krgnode_present(node)  krgnode_set(node, krgnode_present_map)

#define clear_krgnode_possible(node) krgnode_clear(node, krgnode_possible_map)
#define clear_krgnode_online(node)   krgnode_clear(node, krgnode_online_map)
#define clear_krgnode_present(node)  krgnode_clear(node, krgnode_present_map)

#define nth_possible_krgnode(node) nth_krgnode(node, krgnode_possible_map)
#define nth_online_krgnode(node) nth_krgnode(node, krgnode_online_map)
#define nth_present_krgnode(node) nth_krgnode(node, krgnode_present_map)

#define krgnode_next_possible(node) next_krgnode(node, krgnode_possible_map)
#define krgnode_next_online(node) next_krgnode(node, krgnode_online_map)
#define krgnode_next_present(node) next_krgnode(node, krgnode_present_map)

#define krgnode_next_possible_in_ring(node) next_krgnode_in_ring(node, krgnode_possible_map)
#define krgnode_next_online_in_ring(node) next_krgnode_in_ring(node, krgnode_online_map)
#define krgnode_next_present_in_ring(node) next_krgnode_in_ring(node, krgnode_present_map)

#endif /* __KRG_NODEMASK_H */
