/** KDDM name space interface.
 *  @file name_space.h
 *
 *  Definition of KDDM name space interface.
 *  @author Renaud Lottiaux
 */

#ifndef __KDDM_NS__
#define __KDDM_NS__

#include <linux/unique_id.h>
#include <linux/hashtable.h>
#include <kddm/kddm_types.h>



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/



struct kddm_ns;

typedef struct kddm_ns_ops {
	struct kddm_set *(*kddm_set_lookup)(struct kddm_ns *ns,
					    kddm_set_id_t set_id);
} kddm_ns_ops_t;

typedef struct kddm_ns {
	atomic_t count;
	struct rw_semaphore table_sem;
	hashtable_t *kddm_set_table;
	unique_id_root_t kddm_set_unique_id_root;
	struct kddm_ns_ops *ops;
	void *private;
	int id;
} kddm_ns_t;



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN VARIABLES                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



#define KDDM_DEF_NS_ID 0

extern struct kddm_ns *kddm_def_ns;



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



void kddm_ns_init(void);
void kddm_ns_finalize(void);


struct kddm_ns * create_kddm_ns(int ns_id, void *private,
				struct kddm_ns_ops *ops);
int remove_kddm_ns(int ns_id);

struct kddm_ns *kddm_ns_get(int ns_id);
void kddm_ns_put(struct kddm_ns *ns);


#endif // __KDDM_NS__
