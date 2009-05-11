/*
 *  Copyright (C) 2008, Louis Rilling - Kerlabs.
 */

#include <linux/uaccess.h>
#include <linux/hardirq.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <kerrighed/faf.h>
#include <kerrighed/hotplug.h>
#include <net/krgrpc/rpc.h>


enum ruaccess_op {
	RUACCESS_COPY = 0,
	RUACCESS_STRNCPY,
	RUACCESS_STRNLEN,
	RUACCESS_CLEAR,
	RUACCESS_END
};

enum ruaccess_type {
	RUACCESS_TO,
	RUACCESS_FROM,
	RUACCESS_IN
};

struct ruaccess_req {
	enum ruaccess_op op;
	enum ruaccess_type type;
	unsigned long len;
	union {
		struct {
			void *to;
			const void *from;
			int zerorest;
		} copy;
		struct {
			const char *src;
		} strncpy;
		struct {
			const char *str;
			unsigned long n;
		} strnlen;
		struct {
			void *mem;
			unsigned long len;
		} clear;
	} u;
};

typedef void (*ruaccess_handler_t)(const struct ruaccess_req *req, void *buf,
				   unsigned long *ret, unsigned long *count);

struct ruaccess_desc {
	struct hlist_node list;
	struct rpc_desc *desc;
	struct task_struct *thread;
	mm_segment_t old_fs;
	int err;
	struct rcu_head rcu;
};

#define RUACCESS_DESC_BITS 8
#define RUACCESS_DESC_BUCKETS (1 << RUACCESS_DESC_BITS)

static struct hlist_head desc_table[RUACCESS_DESC_BUCKETS];
static DEFINE_SPINLOCK(desc_table_lock);

static struct ruaccess_desc *ruaccess_desc_alloc(struct rpc_desc *desc)
{
	struct ruaccess_desc *ru_desc;
	struct task_struct *tsk = current;
	unsigned long hash;

	ru_desc = kmalloc(sizeof(*ru_desc), GFP_KERNEL);
	if (!ru_desc)
		goto out;
	ru_desc->desc = desc;
	ru_desc->thread = tsk;
	ru_desc->err = 0;

	hash = hash_ptr(tsk, RUACCESS_DESC_BITS);
	spin_lock(&desc_table_lock);
	hlist_add_head_rcu(&ru_desc->list, &desc_table[hash]);
	spin_unlock(&desc_table_lock);

out:
	return ru_desc;
}

static struct ruaccess_desc *ruaccess_desc_find(void)
{
	struct ruaccess_desc *desc;
	struct hlist_node *node;
	struct task_struct *tsk = current;
	unsigned long hash;

	hash = hash_ptr(tsk, RUACCESS_DESC_BITS);
	rcu_read_lock();
	hlist_for_each_entry_rcu(desc, node, &desc_table[hash], list)
		if (desc->thread == tsk)
			goto out;
	rcu_read_unlock();
	desc = NULL;
out:
	return desc;
}

static void ruaccess_desc_delayed_free(struct rcu_head *rcu)
{
	kfree(container_of(rcu, struct ruaccess_desc, rcu));
}

static void ruaccess_desc_free(struct ruaccess_desc *desc)
{
	spin_lock(&desc_table_lock);
	hlist_del_rcu(&desc->list);
	spin_unlock(&desc_table_lock);
	call_rcu(&desc->rcu, ruaccess_desc_delayed_free);
}

int prepare_ruaccess(struct rpc_desc *desc)
{
	struct ruaccess_desc *ru_desc;
	int err;

#ifndef ARCH_HAS_RUACCESS
	return -ENOSYS;
#endif

	err = -ENOMEM;
	ru_desc = ruaccess_desc_alloc(desc);
	if (!ru_desc)
		goto out;

#ifdef ARCH_HAS_RUACCESS_FIXUP
	use_mm(&init_mm);
#endif
	ru_desc->old_fs = get_fs();
	set_fs(USER_DS);
	set_thread_flag(TIF_RUACCESS);
	err = 0;

out:
	return err;
}

int cleanup_ruaccess(struct rpc_desc *desc)
{
	struct ruaccess_req req = { .op = RUACCESS_END };
	struct ruaccess_desc *ru_desc;
	int err;

	ru_desc = ruaccess_desc_find();
	BUG_ON(!desc);

	clear_thread_flag(TIF_RUACCESS);
	set_fs(ru_desc->old_fs);
#ifdef ARCH_HAS_RUACCESS_FIXUP
	unuse_mm(&init_mm);
#endif

	err = ru_desc->err;
	if (err)
		goto out;
	err = rpc_pack_type(desc, req);
out:
	ruaccess_desc_free(ru_desc);
	return err;
}

static int do_ruaccess(struct ruaccess_req *req, unsigned long *ret, void *buf)
{
	struct ruaccess_desc *ru_desc;
	struct rpc_desc *desc;
	unsigned long count;
	int err;

	ru_desc = ruaccess_desc_find();
	BUG_ON(!ru_desc);
	err = ru_desc->err;
	if (err)
		goto out;
	desc = ru_desc->desc;

	err = rpc_pack_type(desc, *req);
	if (err)
		goto out_err;
	if (req->type == RUACCESS_TO) {
		err = rpc_pack(desc, 0, buf, req->len);
		if (err)
			goto out_err;
	}
	if (req->type == RUACCESS_FROM) {
		err = rpc_unpack_type(desc, count);
		if (err)
			goto out_err;
		if (count) {
			BUG_ON(count > req->len);
			err = rpc_unpack(desc, 0, buf, count);
			if (err)
				goto out_err;
		}
	}
	err = rpc_unpack_type(desc, *ret);
	if (err)
		goto out_err;

out:
	return err;

out_err:
	printk(KERN_ERR "access to remote user memory failed!\n");
	ru_desc->err = err;
	goto out;
}

#define DO_RUACCESS(req, ret) do_ruaccess(&req, &ret, NULL)

unsigned long krg_copy_user_generic(void *to, const void *from,
				    unsigned long n, int zerorest)
{
	struct ruaccess_req req = {
		.op = RUACCESS_COPY,
		.len = n,
		.u.copy = {
			.to = to,
			.from = from,
			.zerorest = zerorest
		},
	};
	void *buf;

	if (in_atomic())
		goto out;
	BUG_ON(!segment_eq(get_fs(), USER_DS));

	if ((unsigned long)to >= TASK_SIZE) {
		req.type = RUACCESS_FROM;
		buf = (void *)to;
	} else if ((unsigned long)from >= TASK_SIZE) {
		req.type = RUACCESS_TO;
		buf = (void *)from;
	} else {
#ifndef CONFIG_COMPAT
		BUG();
#endif
		req.type = RUACCESS_IN;
		buf = NULL;
	}

	do_ruaccess(&req, &n, buf);

out:
	return n;
}

static void handle_copy(const struct ruaccess_req *req, void *buf,
			unsigned long *ret, unsigned long *count)
{
	unsigned long n = req->len;

	switch (req->type) {
	case RUACCESS_TO:
		n = __copy_to_user(req->u.copy.to, buf, n);
		break;
	case RUACCESS_FROM:
		if (req->u.copy.zerorest) {
			n = __copy_from_user(buf, req->u.copy.from, n);
			*count = req->len;
		} else {
			n = __copy_from_user_inatomic(buf, req->u.copy.from, n);
			*count = req->len - n;
		}
		break;
	case RUACCESS_IN:
#ifdef CONFIG_COMPAT
		n = __copy_in_user(req->u.copy.to, req->u.copy.from, n);
#else
		BUG();
#endif
		break;
	};

	*ret = n;
}

long krg___strncpy_from_user(char *dst, const char __user *src,
			     unsigned long count)
{
	struct ruaccess_req req = {
		.op = RUACCESS_STRNCPY,
		.type = RUACCESS_FROM,
		.len = count,
		.u.strncpy = {
			.src = src,
		}
	};
	long res = -EFAULT;

	if (in_atomic()) {
		printk("__strncpy_from_user() called in atomic!\n");
		goto out;
	}
	BUG_ON(!segment_eq(get_fs(), USER_DS));

	do_ruaccess(&req, (unsigned long *)&res, dst);

out:
	return res;
}

static void handle_strncpy(const struct ruaccess_req *req, void *buf,
			   unsigned long *ret, unsigned long *count)
{
	long res;

	res = __strncpy_from_user(buf, req->u.strncpy.src, req->len);
	*count = (res > 0) ? min((unsigned long)res + 1, req->len) : 0;
	*ret = (unsigned long)res;
}

unsigned long krg___strnlen_user(const char __user *str, unsigned long n)
{
	struct ruaccess_req req = {
		.op = RUACCESS_STRNLEN,
		.type = RUACCESS_IN,
		.u.strnlen = {
			.str = str,
			.n = n
		}
	};
	unsigned long len = 0;

	if (in_atomic()) {
		printk("__strnlen_user() called in atomic!\n");
		goto out;
	}
	BUG_ON(!segment_eq(get_fs(), USER_DS));

	DO_RUACCESS(req, len);

out:
	return len;
}

static void handle_strnlen(const struct ruaccess_req *req, void *buf,
			   unsigned long *ret, unsigned long *count)
{
	const char __user *str = req->u.strnlen.str;
	unsigned long n = req->u.strnlen.n;

	*count = 0;
	if (n == ~0UL)
		*ret = strlen_user(str);
	else
		*ret = strnlen_user(str, n);
}

unsigned long krg___clear_user(void __user *mem, unsigned long len)
{
	struct ruaccess_req req = {
		.op = RUACCESS_CLEAR,
		.type = RUACCESS_IN,
		.u.clear = {
			.mem = mem,
			.len = len
		}
	};

	if (in_atomic()) {
		printk("__clear_user() called in atomic!\n");
		goto out;
	}
	BUG_ON(!segment_eq(get_fs(), USER_DS));

	DO_RUACCESS(req, len);

out:
	return len;
}

static void handle_clear(const struct ruaccess_req *req, void *buf,
			 unsigned long *ret, unsigned long *count)
{
	*count = 0;
	*ret = __clear_user(req->u.clear.mem, req->u.clear.len);
}

static ruaccess_handler_t ruaccess_handler[] = {
	[RUACCESS_COPY] = handle_copy,
	[RUACCESS_STRNCPY] = handle_strncpy,
	[RUACCESS_STRNLEN] = handle_strnlen,
	[RUACCESS_CLEAR] = handle_clear
};

static int handle_ruaccess_req(struct rpc_desc *desc, const struct ruaccess_req *req)
{
	void *buf = NULL;
	unsigned long ret;
	unsigned long count;
	int err;

	if (req->type == RUACCESS_TO || req->type == RUACCESS_FROM) {
		err = -ENOMEM;
		buf = kmalloc(req->len, GFP_KERNEL);
		if (!buf)
			goto out;
	}
	if (req->type == RUACCESS_TO) {
		err = rpc_unpack(desc, 0, buf, req->len);
		if (err)
			goto out;
	}

	ruaccess_handler[req->op](req, buf, &ret, &count);

	if (req->type == RUACCESS_FROM) {
		BUG_ON(count > req->len);
		err = rpc_pack_type(desc, count);
		if (err)
			goto out;
		if (count) {
			err = rpc_pack(desc, 0, buf, count);
			if (err)
				goto out;
		}
	}
	err = rpc_pack_type(desc, ret);

out:
	kfree(buf);
	return err;
}

int handle_ruaccess(struct rpc_desc *desc)
{
	struct ruaccess_req req;
	int err;

	BUG_ON(!segment_eq(get_fs(), USER_DS));

	for (;;) {
		err = rpc_unpack_type(desc, req);
		if (err)
			break;
		if (req.op == RUACCESS_END)
			break;
		err = handle_ruaccess_req(desc, &req);
		if (err)
			break;
	}

	return err;
}

int ruaccess_start(void)
{
	return 0;
}

void ruaccess_exit(void)
{
}
