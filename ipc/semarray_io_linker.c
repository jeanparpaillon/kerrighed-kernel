/*
 *  Kerrighed/modules/ipc/semarray_io_linker.c
 *
 *  KDDM SEM array Linker.
 *
 *  Copyright (C) 2007-2008 Matthieu Fertré - INRIA
 */

#include <linux/sem.h>
#include <linux/lockdep.h>
#include <linux/security.h>
#include <linux/ipc_namespace.h>
#include <linux/ipc.h>
#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>

#include "semarray_io_linker.h"
#include "util.h"
#include "krgsem.h"

struct kmem_cache *semarray_object_cachep;

#define sc_semmni       sem_ctls[3]

/** Create a local instance of an remotly existing Semaphore.
 *
 *  @author Matthieu Fertré
 */
struct sem_array *create_local_sem(struct sem_array *received_sma)
{
	struct ipc_namespace *ns = &init_ipc_ns; /* TODO: manage namespace */
	struct sem_array *sma;
	int size_sems;
	int retval;

	size_sems = received_sma->sem_nsems * sizeof (struct sem);
	sma = ipc_rcu_alloc(sizeof (*sma) + size_sems);
	if (!sma) {
		return ERR_PTR(-ENOMEM);
	}
	*sma = *received_sma;

	sma->sem_base = (struct sem *) &sma[1];
	memcpy(sma->sem_base, received_sma->sem_base, size_sems);

	retval = security_sem_alloc(sma);
	if (retval)
		goto err_putref;

	/*
	 * ipc_reserveid() locks msq
	 */
	retval = local_ipc_reserveid(&sem_ids(ns), &sma->sem_perm, ns->sc_semmni);
	if (retval)
		goto err_security_free;

	INIT_LIST_HEAD(&sma->sem_pending);
	INIT_LIST_HEAD(&sma->list_id);
	INIT_LIST_HEAD(&sma->remote_sem_pending);

	sma->sem_perm.krgops = &krg_sysvipc_sem_ops;
	local_sem_unlock(sma);

	return sma;

err_security_free:
	security_sem_free(sma);
err_putref:
	ipc_rcu_putref(sma);
	return ERR_PTR(retval);
}

#define IN_WAKEUP 1

static inline void update_sem_queues(struct sem_array *sma,
				     struct sem_array *received_sma)
{
	struct sem_queue *q, *tq, *local_q;

	BUG_ON(!list_empty(&received_sma->sem_pending));

	/* adding (to local sem) semqueues that are not local */
	list_for_each_entry_safe(q, tq, &received_sma->remote_sem_pending, list) {

		int is_local = 0;

		/* checking if the sem_queue is local */
		list_for_each_entry(local_q, &sma->sem_pending, list) {

			/* comparing local_q->pid to q->pid is not sufficient
			 *  as they contains only tgid, two or more threads
			 *  can be pending.
			 */
			if (local_q->sleeper->pid == remote_sleeper_pid(q)) {
				/* the sem_queue is local */
				is_local = 1;

				BUG_ON(q->undo && !local_q->undo);
				BUG_ON(local_q->undo && !q->undo);
				local_q->undo = q->undo;
				/* No need to update q->status, as it is done when
				   needed in handle_ipcsem_wake_up_process */
				BUG_ON(q->status == IN_WAKEUP);
				BUG_ON(local_q->status != q->status);

				goto next;
			}
		}
	next:
		list_del(&q->list);
		if (is_local)
			free_semqueue(q);
		else
			list_add(&q->list, &sma->remote_sem_pending);
	}

	BUG_ON(!list_empty(&received_sma->remote_sem_pending));
}

/** Update a local instance of a remotly existing IPC semaphore.
 *
 *  @author Matthieu Fertré
 */
static void update_local_sem(struct sem_array *local_sma,
			     struct sem_array *received_sma)
{
	int size_sems;

	size_sems = local_sma->sem_nsems * sizeof (struct sem);

	/* getting new values from received semaphore */
	local_sma->sem_otime = received_sma->sem_otime;
	local_sma->sem_ctime = received_sma->sem_ctime;
	memcpy(local_sma->sem_base, received_sma->sem_base, size_sems);

	/* updating sem_undos list */
	list_splice_init(&received_sma->list_id, &local_sma->list_id);

	/* updating semqueues list */
	update_sem_queues(local_sma, received_sma);
}

/*****************************************************************************/
/*                                                                           */
/*                         SEM Array KDDM IO FUNCTIONS                       */
/*                                                                           */
/*****************************************************************************/

int semarray_alloc_object (struct kddm_obj * obj_entry,
			   struct kddm_set * set,
			   objid_t objid)
{
	semarray_object_t *sem_object;

	sem_object = kmem_cache_alloc(semarray_object_cachep, GFP_KERNEL);
	if (!sem_object)
		return -ENOMEM;

	sem_object->local_sem = NULL;
	sem_object->mobile_sem_base = NULL;
	obj_entry->object = sem_object;

	return 0;
}



/** Handle a kddm set sem_array first touch
 *  @author Matthieu Fertré, Renaud Lottiaux
 *
 *  @param  obj_entry  Kddm object descriptor.
 *  @param  set       Kddm set descriptor
 *  @param  objid     Id of the object to create.
 *
 *  @return  0 if everything is ok. Negative value otherwise.
 */
int semarray_first_touch (struct kddm_obj * obj_entry,
			  struct kddm_set * set,
			  objid_t objid,
			  int flags)
{
	BUG(); // I should never get here !

	return 0;
}



/** Insert a new sem_array in local structures.
 *  @author Matthieu Fertré, Renaud Lottiaux
 *
 *  @param  obj_entry  Descriptor of the object to insert.
 *  @param  set       Kddm set descriptor
 *  @param  objid     Id of the object to insert.
 */
int semarray_insert_object (struct kddm_obj * obj_entry,
			    struct kddm_set * set,
			    objid_t objid)
{
	semarray_object_t *sem_object;
	struct sem_array *sem;

	sem_object = obj_entry->object;
	BUG_ON(!sem_object);

	if (!sem_object->local_sem) {
		/* This is the first time the object is inserted locally.
		 * We need to allocate kernel sem_array structure.
		 */
		sem = create_local_sem(&sem_object->imported_sem);
		sem_object->local_sem = sem;
	}

	update_local_sem(sem_object->local_sem,
			 &sem_object->imported_sem);

	return 0;
}



/** Invalidate a kddm object semarray.
 *  @author Matthieu Fertré, Renaud Lottiaux
 *
 *  @param  obj_entry  Descriptor of the object to invalidate.
 *  @param  set       Kddm set descriptor
 *  @param  objid     Id of the object to invalidate
 */
int semarray_invalidate_object (struct kddm_obj * obj_entry,
				struct kddm_set * set,
				objid_t objid)
{
	semarray_object_t *sem_object = obj_entry->object;
	struct sem_array *sma = sem_object->local_sem;
	struct sem_undo *un, *tu;
	struct sem_queue *q, *tq;

	BUG_ON(!list_empty(&sem_object->imported_sem.list_id));
	BUG_ON(!list_empty(&sem_object->imported_sem.sem_pending));
	BUG_ON(!list_empty(&sem_object->imported_sem.remote_sem_pending));

	/* freeing the semundo list */
	list_for_each_entry_safe(un, tu, &sma->list_id, list_id) {
		list_del(&un->list_id);
		kfree(un);
	}

	/* freeing the remote semqueues */
	list_for_each_entry_safe(q, tq, &sma->remote_sem_pending, list) {
		list_del(&q->list);
		free_semqueue(q);
	}

	return KDDM_IO_KEEP_OBJECT;
}

/** Handle a kddm semaphore remove.
 *  @author Matthieu Fertré, Renaud Lottiaux
 *
 *  @param  obj_entry  Descriptor of the object to remove.
 *  @param  set       Kddm set descriptor.
 *  @param  padeid    Id of the object to remove.
 */
int semarray_remove_object(void *object, struct kddm_set * set,
			   objid_t objid)
{
	struct ipc_namespace *ns = &init_ipc_ns; /* TODO: manage namespace */
	semarray_object_t *sem_object;
	struct sem_array *sma;

	sem_object = object;
	if (sem_object) {
		sma = sem_object->local_sem;

		local_sem_lock(ns, sma->sem_perm.id);
		local_freeary(ns, &sma->sem_perm);

		kfree(sem_object->mobile_sem_base);
		sem_object->mobile_sem_base = NULL;
		kmem_cache_free(semarray_object_cachep, sem_object);
	}

	return 0;
}

static inline void __export_semarray(struct rpc_desc *desc,
				     const semarray_object_t *sem_object,
				     const struct sem_array* sma)
{
	rpc_pack(desc, 0, sma, sizeof(struct sem_array));
	rpc_pack(desc, 0, sma->sem_base, sma->sem_nsems * sizeof (struct sem));
}

static inline void __export_semundos(struct rpc_desc *desc,
				     const struct sem_array* sma)
{
	long nb_semundo = 0;
	struct sem_undo *un;

	list_for_each_entry(un, &sma->list_id, list_id)
		nb_semundo++;

	rpc_pack_type(desc, nb_semundo);

	list_for_each_entry(un, &sma->list_id, list_id) {
		BUG_ON(!list_empty(&un->list_proc));

		rpc_pack(desc, 0, un, sizeof(struct sem_undo) +
			 sma->sem_nsems * sizeof(short));
	}
}

static inline void __export_one_local_semqueue(struct rpc_desc *desc,
					       const struct sem_queue* q)
{
	/* Fill q2->sleeper with the pid (and not tgid) of q->sleeper
	   (needed to be thread aware) */
	struct sem_queue q2 = *q;

	/* Make remote_sleeper_pid(q2) equal to q->sleeper->pid */
	q2.sleeper = (void*)((long)(q->sleeper->pid));

	rpc_pack_type(desc, q2);
	if (q->nsops)
		rpc_pack(desc, 0, q->sops,
			 q->nsops * sizeof(struct sembuf));

	if (q->undo) {
		BUG_ON(!list_empty(&q->undo->list_proc));
		rpc_pack_type(desc, q->undo->proc_list_id);
	}
}

static inline void __export_one_remote_semqueue(struct rpc_desc *desc,
						const struct sem_queue* q)
{
	rpc_pack(desc, 0, q, sizeof(struct sem_queue));
	if (q->nsops)
		rpc_pack(desc, 0, q->sops,
			 q->nsops * sizeof(struct sembuf));

	if (q->undo) {
		BUG_ON(!list_empty(&q->undo->list_proc));
		rpc_pack_type(desc, q->undo->proc_list_id);
	}
}

static inline void __export_semqueues(struct rpc_desc *desc,
				      const struct sem_array* sma)
{
	struct sem_queue *q;
	long nb_sem_pending = 0;

	/* count local sem_pending */
	list_for_each_entry(q, &sma->sem_pending, list)
		nb_sem_pending++;

	/* count remote sem_pending */
	list_for_each_entry(q, &sma->remote_sem_pending, list)
		nb_sem_pending++;

	rpc_pack_type(desc, nb_sem_pending);

	/* send local sem_queues */
	list_for_each_entry(q, &sma->sem_pending, list)
		__export_one_local_semqueue(desc, q);

	/* send remote sem_queues */
	list_for_each_entry(q, &sma->remote_sem_pending, list)
		__export_one_remote_semqueue(desc, q);
}

/** Export an object
 *  @author Matthieu Fertré, Renaud Lottiaux
 *
 *  @param  buffer    Buffer to export object data in.
 *  @param  object    The object to export data from.
 */
int semarray_export_object (struct rpc_desc *desc,
			    struct kddm_obj *obj_entry)
{
	semarray_object_t *sem_object;
	struct sem_array *sma;

	sem_object = obj_entry->object;
	sma = sem_object->local_sem;

	BUG_ON(!sma);

	__export_semarray(desc, sem_object, sma);
	__export_semundos(desc, sma);
	__export_semqueues(desc, sma);

	return 0;
}

static inline int __import_semarray(struct rpc_desc *desc,
				    semarray_object_t *sem_object)
{
	struct sem_array buffer;
	int size_sems;

	rpc_unpack_type(desc, buffer);
	sem_object->imported_sem = buffer;

	size_sems = sem_object->imported_sem.sem_nsems * sizeof(struct sem);
	if (!sem_object->mobile_sem_base)
		sem_object->mobile_sem_base = kmalloc(size_sems, GFP_KERNEL);
	if (!sem_object->mobile_sem_base)
		return -ENOMEM;

	rpc_unpack(desc, 0, sem_object->mobile_sem_base, size_sems);
	sem_object->imported_sem.sem_base = sem_object->mobile_sem_base;

	INIT_LIST_HEAD(&sem_object->imported_sem.sem_pending);
	INIT_LIST_HEAD(&sem_object->imported_sem.remote_sem_pending);
	INIT_LIST_HEAD(&sem_object->imported_sem.list_id);

	return 0;
}

static inline int __import_semundos(struct rpc_desc *desc,
				    struct sem_array *sma)
{
	struct sem_undo* undo;
	long nb_semundo, i;
	int size_undo;
	size_undo = sizeof(struct sem_undo) +
		sma->sem_nsems * sizeof(short);

	rpc_unpack_type(desc, nb_semundo);

	BUG_ON(!list_empty(&sma->list_id));

	for (i=0; i < nb_semundo; i++) {
		undo = kzalloc(size_undo, GFP_KERNEL);
		if (!undo)
			goto unalloc_undos;

		rpc_unpack(desc, 0, undo, size_undo);
		INIT_LIST_HEAD(&undo->list_id);
		INIT_LIST_HEAD(&undo->list_proc);

		undo->semadj = (short *) &undo[1];
		list_add(&undo->list_id, &sma->list_id);
	}

	return 0;

unalloc_undos:
	return -ENOMEM;
}

static inline void __unimport_semundos(struct sem_array *sma)
{
	struct sem_undo * un, *tu;

	list_for_each_entry_safe(un, tu, &sma->list_id, list_id) {
		list_del(&un->list_id);
		kfree(un);
	}
}

static inline int import_one_semqueue(struct rpc_desc *desc,
				      struct sem_array *sma)
{
	unique_id_t undo_proc_list_id;
	struct sem_undo* undo;
	int r = -ENOMEM;
	struct sem_queue *q = kmalloc(sizeof(struct sem_queue), GFP_KERNEL);
	if (!q)
		goto exit;

	rpc_unpack(desc, 0, q, sizeof(struct sem_queue));
	INIT_LIST_HEAD(&q->list);

	if (q->nsops) {
		q->sops = kzalloc(q->nsops * sizeof(struct sembuf),
				  GFP_KERNEL);
		if (!q->sops)
			goto unalloc_q;
		rpc_unpack(desc, 0, q->sops, q->nsops * sizeof(struct sembuf));
	}

	if (q->undo) {
		rpc_unpack_type(desc, undo_proc_list_id);

		list_for_each_entry(undo, &sma->list_id, list_id) {
			if (undo->proc_list_id == undo_proc_list_id) {
				q->undo = undo;
				goto undo_found;
			}
		}
	}

undo_found:
	r = 0;

	/* split between remote and local
	   queues is done in update_local_sem */
	list_add(&q->list, &sma->remote_sem_pending);

	BUG_ON(!q->sleeper);
	return r;

unalloc_q:
	kfree(q);

exit:
	return r;
}

static inline int __import_semqueues(struct rpc_desc *desc,
				     struct sem_array *sma)
{
	long nb_sempending, i;
	int r;

	r = rpc_unpack_type(desc, nb_sempending);
	if (r)
		goto err;

	BUG_ON(!list_empty(&sma->remote_sem_pending));

	for (i=0; i < nb_sempending; i++) {
		r = import_one_semqueue(desc, sma);
		if (r)
			goto err;
	}

#ifdef CONFIG_KRG_DEBUG
	{
		struct sem_queue *q;
		i=0;
		list_for_each_entry(q, &sma->remote_sem_pending, list)
			i++;

		BUG_ON(nb_sempending != i);
	}
#endif

err:
	return r;
}

static inline void __unimport_semqueues(struct sem_array *sma)
{
	struct sem_queue *q, *tq;

	list_for_each_entry_safe(q, tq, &sma->remote_sem_pending, list) {
		list_del(&q->list);
		free_semqueue(q);
	}
}

/** Import an object
 *  @author Matthieu Fertré, Renaud Lottiaux
 *
 *  @param  object    The object to import data in.
 *  @param  buffer    Data to import in the object.
 */
int semarray_import_object (struct kddm_obj *obj_entry,
			    struct rpc_desc *desc)
{
	semarray_object_t *sem_object;
	int r = 0;
	sem_object = obj_entry->object;

	r = __import_semarray(desc, sem_object);
	if (r)
		goto err;

	r = __import_semundos(desc, &sem_object->imported_sem);
	if (r)
		goto unimport_semundos;

	r = __import_semqueues(desc, &sem_object->imported_sem);
	if (r)
		goto unimport_semqueues;

	goto err;

unimport_semqueues:
	__unimport_semqueues(&sem_object->imported_sem);

unimport_semundos:
	__unimport_semundos(&sem_object->imported_sem);

err:
	return r;
}

/****************************************************************************/

/* Init the semarray IO linker */
struct iolinker_struct semarray_linker = {
	first_touch:       semarray_first_touch,
	remove_object:     semarray_remove_object,
	invalidate_object: semarray_invalidate_object,
	insert_object:     semarray_insert_object,
	linker_name:       "semarray",
	linker_id:         SEMARRAY_LINKER,
	alloc_object:      semarray_alloc_object,
	export_object:     semarray_export_object,
	import_object:     semarray_import_object
};

/*****************************************************************************/
/*                                                                           */
/*                         SEMKEY KDDM IO FUNCTIONS                          */
/*                                                                           */
/*****************************************************************************/

/* Init the sem key IO linker */
struct iolinker_struct semkey_linker = {
	linker_name:       "semkey",
	linker_id:         SEMKEY_LINKER,
};
