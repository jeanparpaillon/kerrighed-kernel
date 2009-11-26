/** KDDM benchmark module.
 *  @file kddm_bench.c
 *
 *  Copyright (C) 2007, Renaud Lottiaux, Kerlabs.
 */

#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>

#define NR_TEST_LOOPS 16
#define NR_TESTS 12
#define BARRIER_ID 100000


/****************************************************************************/

int test_first_touch (struct kddm_obj * obj_entry,
		      struct kddm_set * set,
		      objid_t objid,
		      int flags)
{
	int *data;

	if (obj_entry->object == NULL) {
		data = kmalloc(set->obj_size, GFP_KERNEL);
		obj_entry->object = data;
		*data = 0;
	}

	return 0;
}

/* Init the KDDM test IO linker */

struct iolinker_struct kddm_test_linker = {
	first_touch:       test_first_touch,
	linker_name:       "kddm_test",
	linker_id:         KDDM_TEST_LINKER,
};

struct kddm_set *kddm_test4_dist = NULL;
struct kddm_set *kddm_test4_loc = NULL;
struct kddm_set *kddm_test4096_dist = NULL;

static inline void start_timer (struct timeval *tv)
{
	do_gettimeofday(tv);
}

static inline long stop_timer (struct timeval *tv_start)
{
	u64 start = 0, end;
	struct timeval tv_end;

	do_gettimeofday(&tv_end);

	start = tv_start->tv_usec + tv_start->tv_sec * 1000000;
	end = tv_end.tv_usec + tv_end.tv_sec * 1000000;
	return end - start;
}

void kddm_test_barrier(void)
{
	int *val, done = 0;

	if (kerrighed_node_id == 0) {
		val = _kddm_grab_object (kddm_test4_loc, BARRIER_ID);
		*val = kerrighed_nb_nodes;
		_kddm_put_object (kddm_test4_loc, BARRIER_ID);
	}
	else {
		while (! done) {
			val = _kddm_get_object (kddm_test4_loc, BARRIER_ID);
			done = (*val != 0);
			_kddm_put_object (kddm_test4_loc, BARRIER_ID);
			schedule();
		}
	}

	val = _kddm_grab_object (kddm_test4_loc, BARRIER_ID);
	(*val)--;
	_kddm_put_object (kddm_test4_loc, BARRIER_ID);

	done = 0;

	while (! done) {
		val = _kddm_get_object (kddm_test4_loc, BARRIER_ID);
		done = (*val == 0);
		_kddm_put_object (kddm_test4_loc, BARRIER_ID);
		schedule();
	}
}



long do_grab(struct kddm_set *set, int start, int end)
{
	struct timeval tv;
	long tot_time = 0;
	int i;

	for (i = start; i < end; i++) {
		start_timer (&tv);
		_kddm_grab_object (set, i);
		tot_time += stop_timer(&tv);
	}

	for (i = start; i < end; i++)
		_kddm_put_object (set, i);

	return tot_time / NR_TEST_LOOPS;
}

long do_get(struct kddm_set *set, int start, int end)
{
	struct timeval tv;
	long tot_time = 0;
	int i;

	for (i = start; i < end; i++) {
		start_timer (&tv);
		_kddm_get_object (set, i);
		tot_time += stop_timer(&tv);
	}

	for (i = start; i < end; i++)
		_kddm_put_object (set, i);

	return tot_time / NR_TEST_LOOPS;
}

long do_remove(struct kddm_set *set, int start, int end)
{
	struct timeval tv;
	long tot_time = 0;
	int i ;

	for (i = start; i < end; i++)
		_kddm_get_object (set, i);

	for (i = start; i < end; i++) {
		start_timer (&tv);
		_kddm_remove_frozen_object (set, i);
		tot_time += stop_timer(&tv);
	}

	return tot_time / NR_TEST_LOOPS;
}

void alloc_test_kddm_sets(int master_node)
{
	kddm_test4_dist = create_new_kddm_set (kddm_def_ns,
					       KDDM_TEST4_DIST,
					       KDDM_TEST_LINKER,
					       master_node + 1, 4, 0);

	kddm_test4_loc = create_new_kddm_set (kddm_def_ns,
					      KDDM_TEST4_LOC,
					      KDDM_TEST_LINKER,
					      master_node, 4, 0);

	kddm_test4096_dist = create_new_kddm_set (kddm_def_ns,
						  KDDM_TEST4096,
						  KDDM_TEST_LINKER,
						  master_node + 1, 4096, 0);
}

void prepare_bench (struct kddm_set *set, int master_node)
{
	int start, end, test_nr;

	for (test_nr = 0; test_nr <= NR_TESTS; test_nr++) {

		start = test_nr * NR_TEST_LOOPS;
		end = start + NR_TEST_LOOPS;

		switch (test_nr) {
		case 0:  /* Get - 0 copies (FT) */
			break;

		case 1:  /* Get - Fetch from node 1 */
			if (kerrighed_node_id == master_node + 1)
				do_grab(set, start, end);
			break;

		case 2:  /* Get - Fetch from node 2 */
			if (kerrighed_node_id == master_node + 2)
				do_grab(set, start, end);
			break;

		case 3:  /* Grab - 0 copies (FT) */
			break;

		case 4:  /* Grab - 1 local copy */
			if (kerrighed_node_id == master_node)
				do_grab(set, start, end);
			break;

		case 5:  /* Grab - 1 remote copy */
		case 6:  /* Grab - 2 remote copies */
		case 7:  /* Grab - 3 remote copies */
			if (kerrighed_node_id > master_node + (7 - test_nr))
				do_get(set, start, end);
			break;

		case 8:  /* Grab - 1 local 3 remotes copies */
			do_get(set, start, end);
			break;

		case 9:  /* Remove - 1 local copy */
			if (kerrighed_node_id == master_node)
				do_get(set, start, end);
			break;

		case 10: /* Remove - 1 remote copy */
		case 11: /* Remove - 2 remote copies */
		case 12: /* Remove - 3 remote copies */
			if ((kerrighed_node_id > master_node + (12 - test_nr))
			    || (kerrighed_node_id == master_node))
				do_get(set, start, end);
			break;
		}
	}
}

void do_one_bench (struct kddm_set *set, char *buff, int size, int *index)
{
	int start, end, test_nr;

	for (test_nr = 0; test_nr <= NR_TESTS; test_nr++) {

		start = test_nr * NR_TEST_LOOPS;
		end = start + NR_TEST_LOOPS;

		switch (test_nr) {
		case 0:  /* Get - 0 copies (FT) */
			*index += snprintf (&buff[*index], size - *index,
					    "Get (FT): %ld\n",
					    do_get(set, start, end));
			break;

		case 1:  /* Get - Fetch from node 1 */
			*index += snprintf (&buff[*index], size - *index,
					    "Get (Fetch from node 1): %ld\n",
					    do_get(set, start, end));
			break;

		case 2:  /* Get - Fetch from node 2 */
			*index += snprintf (&buff[*index], size - *index,
					    "Get (Fetch from node 2): %ld\n",
					    do_get(set, start, end));
			break;

		case 3:  /* Grab - 0 copies (FT) */
			*index += snprintf (&buff[*index], size - *index,
					    "Grab (FT): %ld\n",
					    do_grab(set, start, end));
			break;

		case 4:  /* Grab - 1 local copy */
			*index += snprintf (&buff[*index], size - *index,
					    "Grab (1 local copy): %ld\n",
					    do_grab(set, start, end));
			break;

		case 5:  /* Grab - 1 remote copy */
		case 6:  /* Grab - 2 remote copies */
		case 7:  /* Grab - 3 remote copies */
			*index += snprintf (&buff[*index], size - *index,
					    "Grab (%d remote copy): %ld\n",
					    test_nr - 4,
					    do_grab(set, start, end));
			break;

		case 8:  /* Grab - 4 copies */
			*index += snprintf (&buff[*index], size - *index,
					    "Grab (1 loc - 3 remote): %ld\n",
					    do_grab(set, start, end));
			break;

		case 9:  /* Remove - 1 local copy */
			*index += snprintf (&buff[*index], size - *index,
					    "Remove (1 local copy): %ld\n",
					    do_remove(set, start, end));
			break;

		case 10: /* Remove - 1 remote copy */
		case 11: /* Remove - 2 remote copies */
		case 12: /* Remove - 3 remote copies */
			*index += snprintf (&buff[*index], size - *index,
					    "Remove (%d remote copy): %ld\n",
					    test_nr - 9,
					    do_remove(set, start, end));
			break;
		}
	}
}



void cleanup_bench (struct kddm_set *set)
{
	int start, end, test_nr;

	for (test_nr = 0; test_nr <= NR_TESTS; test_nr++) {
		start = test_nr * NR_TEST_LOOPS;
		end = start + NR_TEST_LOOPS;
		do_remove (set, start, end);
	}
}



int do_bench (char *buff, int size, int master_node)
{
	int index = 0;

	if (kddm_test4_dist == NULL)
		alloc_test_kddm_sets(master_node);

	prepare_bench(kddm_test4_loc, master_node);
	prepare_bench(kddm_test4_dist, master_node);
	prepare_bench(kddm_test4096_dist, master_node);

	kddm_test_barrier();

	if (kerrighed_node_id == master_node) {
		index += snprintf (&buff[index], size - index, "----- KDDM "
				   "BENCH - Local Manager   - Object size = "
				   "4 -----\n");
		do_one_bench(kddm_test4_loc, buff, size, &index);
		index += snprintf (&buff[index], size - index, "----- KDDM "
				   "BENCH - Distant Manager - Object size = "
				   "4 -----\n");
		do_one_bench(kddm_test4_dist, buff, size, &index);
		index += snprintf (&buff[index], size - index, "----- KDDM "
				   "BENCH - Distant Manager - Object size = "
				   "4096 -----\n");
		do_one_bench(kddm_test4096_dist, buff, size, &index);
		cleanup_bench(kddm_test4_loc);
		cleanup_bench(kddm_test4_dist);
		cleanup_bench(kddm_test4096_dist);
	}
	return index;
}



int handle_kddm_bench (struct rpc_desc* desc, void *_msg, size_t size)
{
	int *master_node = _msg;

	do_bench(NULL, 0, *master_node);
	return 0;
}



int kddm_bench(char *buff, int size)
{
	int n, i, master_node = kerrighed_node_id;
	krgnodemask_t nodes;

	if (kerrighed_nb_nodes < 4) {
		n = snprintf (buff, size, "Not enough nodes (min nodes: 4)\n");
		return n;
	}

	krgnodes_clear(nodes);

	for (i = master_node + 1; i <= master_node + 3; i++)
		krgnode_set(i, nodes);

	rpc_async_m(KDDM_BENCH, kddm_def_ns->rpc_comm, &nodes,
		    &master_node, sizeof(int));

	return do_bench(buff, size, master_node);
}



void init_kddm_test (void)
{
	struct rpc_synchro* test_server;

	test_server = rpc_synchro_new(1, "kddm test", 0);

	register_io_linker (KDDM_TEST_LINKER, &kddm_test_linker);

	__rpc_register(KDDM_BENCH,
		       RPC_TARGET_NODE, RPC_HANDLER_KTHREAD_VOID,
		       test_server, handle_kddm_bench, 0);
}
