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
#include <kerrighed/krginit.h>
#include <kerrighed/krg_services.h>
#include <kerrighed/krg_syscalls.h>
#include <net/krgrpc/rpc.h>
#include <net/krgrpc/rpcid.h>


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

#define OP_NAME(name) [RUACCESS_##name] = #name
static const char *op_name[] = {
	OP_NAME(COPY),
	OP_NAME(STRNCPY),
	OP_NAME(STRNLEN),
	OP_NAME(CLEAR),
};

#define TYPE_NAME(name) [RUACCESS_##name] = #name
static const char *type_name[] = {
	TYPE_NAME(TO),
	TYPE_NAME(FROM),
	TYPE_NAME(IN),
};

static int do_ruaccess(struct ruaccess_req *req, unsigned long *ret, void *buf)
{
	struct ruaccess_desc *ru_desc;
	struct rpc_desc *desc;
	unsigned long count;
	int err;

	printk("%d do_ruaccess: op=%s type=%s len=%lu\n",
	       current->pid, op_name[req->op], type_name[req->type], req->len);
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

	printk("%d do_ruaccess: ret=%lu\n", current->pid, *ret);

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

	printk("%d handle_ruaccess_req: op=%s type=%s len=%lu\n",
	       current->pid, op_name[req->op], type_name[req->type], req->len);

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

struct ruaccess_autotest {
	int str_len;
	int __user *read_str_len;
	unsigned char __user *str[14];
	__u64 __user *u64[3];
	__u32 __user *u32[3];
	__u16 __user *u16[3];
	__u8 __user *u8[3];
	int __user *compat;
};

static int ruaccess_autotest(void __user *arg)
{
	struct ruaccess_autotest __user *at = arg;
#ifdef CONFIG_COMPAT
	int compat = 1;
#else
	int compat = 0;
#endif
	struct rpc_desc *desc;
	int res;
	int err = -ENOMEM;

	desc = rpc_begin(RUACCESS_AUTOTEST,
			 krgnode_next_possible_in_ring(kerrighed_node_id));
	if (!desc)
		goto out;
	err = rpc_pack_type(desc, arg);
	if (err)
		goto cancel;
	err = handle_ruaccess(desc);
	if (err)
		goto cancel;
	err = rpc_unpack_type(desc, res);
	if (err)
		goto cancel;
	err = res;
end:
	rpc_end(desc, 0);
out:
	if (!err)
		err = put_user(compat, at->compat);
	return err;
cancel:
	rpc_cancel(desc);
	goto end;
}

static
void handle_ruaccess_autotest(struct rpc_desc *desc, void *msg, size_t size)
{
	struct ruaccess_autotest __user *uautotest = *(void **)msg;
	struct ruaccess_autotest autotest;
	char *buf = NULL;
	int read_str_len;
	__u64 u64;
	__u32 u32;
#if BITS_PER_LONG < 64
	__u32 u32_2;
#endif
	__u16 u16;
	__u8 u8;
	int res, err;

	err = prepare_ruaccess(desc);
	if (err)
		goto cancel;

	res = -EFAULT;
	if (copy_from_user(&autotest, uautotest, sizeof(autotest)))
		goto cleanup;

	res = -ENOMEM;
	buf = kmalloc(autotest.str_len + 1, GFP_KERNEL);
	if (!buf)
		goto cleanup;

	/* read str_len */
	/* with get_user() */
	res = get_user(read_str_len, &uautotest->str_len);
	if (res)
		goto cleanup;
	res = -EINVAL;
	if (read_str_len != autotest.str_len)
		goto cleanup;
	/* with __get_user() */
	res = -EFAULT;
	if (!access_ok(VERIFY_READ, &uautotest->str_len,
		       sizeof(uautotest->str_len)))
		goto cleanup;
	res = __get_user(read_str_len, &uautotest->str_len);
	if (res)
		goto cleanup;
	res = -EINVAL;
	if (read_str_len != autotest.str_len)
		goto cleanup;

	/* write read_str_len */
	/* with copy_to_user() */
	res = -EFAULT;
	if (copy_to_user(&autotest.read_str_len[0],
			 &autotest.str_len,
			 sizeof(autotest.str_len)))
		goto cleanup;
	/* with put_user() */
	res = put_user(autotest.str_len, &autotest.read_str_len[1]);
	if (res)
		goto cleanup;
	/* with __put_user() */
	res = -EFAULT;
	if (!access_ok(VERIFY_WRITE, &autotest.read_str_len[2],
		       sizeof(autotest.str_len)))
		goto cleanup;
	res = __put_user(autotest.str_len, &autotest.read_str_len[2]);
	if (res)
		goto cleanup;

	/* strnlen_user() */
	read_str_len = strnlen_user(autotest.str[0], autotest.str_len / 2);
	res = put_user(read_str_len, &autotest.read_str_len[3]);
	if (res)
		goto cleanup;
	/*
	 * There seems to be no real rule for an arch defining __strnlen_user()
	 * or not. Just list them in the condition.
	 */
#if defined(CONFIG_X86_64)
	res = -EFAULT;
	/* __strnlen_user() */
	if (!access_ok(VERIFY_READ, autotest.str[0], autotest.str_len / 2))
		goto cleanup;
	read_str_len = __strnlen_user(autotest.str[0], autotest.str_len / 2);
	res = put_user(read_str_len, &autotest.read_str_len[4]);
	if (res)
		goto cleanup;
#endif

	/* get_user()/put_user() */
#if BITS_PER_LONG == 64
	u64 = 0xb6b6b6b6b6b6b6b6;
	res = get_user(u64, autotest.u64[0]);
	if (res)
		goto cleanup;
#else
	u32 = 0xb6b6b6b6;
	res = get_user(u32, (__u32 *)autotest.u64[0]);
	if (res)
		goto cleanup;
	u32_2 = 0xb6b6b6b6;
	res = get_user(u32_2, (__u32 *)autotest.u64[0] + 1);
	if (res)
		goto cleanup;
#ifdef __LITTLE_ENDIAN
	u64 = (__u64)u32_2 << 32 | u32;
#else /* __LITTLE_ENDIAN */
	u64 = (__u64)u32 << 32 | u32_2;
#endif /* __LITTLE_ENDIAN */
#endif
	res = put_user(u64, autotest.u64[1]);
	if (res)
		goto cleanup;
	u32 = 0xb6b6b6b6;
	res = get_user(u32, autotest.u32[0]);
	if (res)
		goto cleanup;
	res = put_user(u32, autotest.u32[1]);
	if (res)
		goto cleanup;
	u16 = 0xb6b6;
	res = get_user(u16, autotest.u16[0]);
	if (res)
		goto cleanup;
	res = put_user(u16, autotest.u16[1]);
	if (res)
		goto cleanup;
	u8 = 0xb6;
	res = get_user(u8, autotest.u8[0]);
	if (res)
		goto cleanup;
	res = put_user(u8, autotest.u8[1]);
	if (res)
		goto cleanup;

	/* __get_user() / __put_user() */
#if BITS_PER_LONG == 64
	u64 = 0xb6b6b6b6b6b6b6b6;
	res = __get_user(u64, autotest.u64[0]);
	if (res)
		goto cleanup;
#else
	u32 = 0xb6b6b6b6;
	res = __get_user(u32, (__u32 *)autotest.u64[0]);
	if (res)
		goto cleanup;
	u32_2 = 0xb6b6b6b6;
	res = __get_user(u32_2, (__u32 *)autotest.u64[0] + 1);
	if (res)
		goto cleanup;
#ifdef __LITTLE_ENDIAN
	u64 = (__u64)u32_2 << 32 | u32;
#else /* __LITTLE_ENDIAN */
	u64 = (__u64)u32 << 32 | u32_2;
#endif /* __LITTLE_ENDIAN */
#endif
	res = -EFAULT;
	if (!access_ok(VERIFY_WRITE, autotest.u64[2], 8))
		goto cleanup;
	res = __put_user(u64, autotest.u64[2]);
	if (res)
		goto cleanup;
	u32 = 0xb6b6b6b6;
	res = __get_user(u32, autotest.u32[0]);
	if (res)
		goto cleanup;
	res = -EFAULT;
	if (!access_ok(VERIFY_WRITE, autotest.u32[2], 4))
		goto cleanup;
	res = __put_user(u32, autotest.u32[2]);
	if (res)
		goto cleanup;
	u16 = 0xb6b6;
	res = __get_user(u16, autotest.u16[0]);
	if (res)
		goto cleanup;
	res = -EFAULT;
	if (!access_ok(VERIFY_WRITE, autotest.u16[2], 2))
		goto cleanup;
	res = __put_user(u16, autotest.u16[2]);
	if (res)
		goto cleanup;
	u8 = 0xb6;
	res = __get_user(u8, autotest.u8[0]);
	if (res)
		goto cleanup;
	res = -EFAULT;
	if (!access_ok(VERIFY_WRITE, autotest.u8[2], 8))
		goto cleanup;
	res = __put_user(u8, autotest.u8[2]);
	if (res)
		goto cleanup;

	/* strncpy_from_user() */
	/* truncated string */
	/* with strncpy_from_user() and copy_to_user() */
	memset(buf, 0xb6, autotest.str_len + 1);
	read_str_len = strncpy_from_user(buf,
					 autotest.str[0],
					 autotest.str_len / 2);
	res = put_user(read_str_len, &autotest.read_str_len[5]);
	if (res)
		goto cleanup;
	res = -EFAULT;
	if (read_str_len >= 0 &&
	    copy_to_user(autotest.str[1], buf, read_str_len))
		goto cleanup;
	/* with __strncpy_from_user() and __copy_to_user() */
	if (!access_ok(VERIFY_READ, autotest.str[0], autotest.str_len / 2))
		goto cleanup;
	memset(buf, 0xb6, autotest.str_len + 1);
	read_str_len = __strncpy_from_user(buf,
					   autotest.str[0],
					   autotest.str_len / 2);
	res = put_user(read_str_len, &autotest.read_str_len[6]);
	if (res)
		goto cleanup;
	res = -EFAULT;
	if (!access_ok(VERIFY_WRITE, autotest.str[2], read_str_len))
		goto cleanup;
	if (read_str_len >= 0 &&
	    __copy_to_user(autotest.str[2], buf, read_str_len))
		goto cleanup;
	/* full string */
	/* with strncpy_from_user() and copy_to_user() */
	memset(buf, 0xb6, autotest.str_len + 1);
	read_str_len = strncpy_from_user(buf,
					 autotest.str[0],
					 autotest.str_len + 1);
	res = put_user(read_str_len, &autotest.read_str_len[7]);
	if (res)
		goto cleanup;
	res = -EFAULT;
	if (read_str_len >= 0 &&
	    copy_to_user(autotest.str[3], buf, read_str_len + 1))
		goto cleanup;
	/* with __strncpy_from_user() and __copy_to_user() */
	if (!access_ok(VERIFY_READ, autotest.str[0], autotest.str_len + 1))
		goto cleanup;
	memset(buf, 0xb6, autotest.str_len + 1);
	read_str_len = __strncpy_from_user(buf,
					   autotest.str[0],
					   autotest.str_len + 1);
	res = put_user(read_str_len, &autotest.read_str_len[8]);
	if (res)
		goto cleanup;
	res = -EFAULT;
	if (!access_ok(VERIFY_WRITE, autotest.str[4], read_str_len + 1))
		goto cleanup;
	if (read_str_len >= 0 &&
	    copy_to_user(autotest.str[4], buf, read_str_len + 1))
		goto cleanup;

	/* copy_from_user() + copy_to_user() */
	res = -EFAULT;
	memset(buf, 0xb6, autotest.str_len + 1);
	if (copy_from_user(buf, autotest.str[0], autotest.str_len + 1))
		goto cleanup;
	if (copy_to_user(autotest.str[5], buf, autotest.str_len + 1))
		goto cleanup;
	/* __copy_from_user() + __copy_to_user() */
	if (!access_ok(VERIFY_WRITE, autotest.str[6], autotest.str_len + 1))
		goto cleanup;
	memset(buf, 0xb6, autotest.str_len + 1);
	if (__copy_from_user(buf, autotest.str[0], autotest.str_len + 1))
		goto cleanup;
	if (__copy_to_user(autotest.str[6], buf, autotest.str_len + 1))
		goto cleanup;

	/* __copy_from_user_nocache() + __copy_to_user() */
	if (!access_ok(VERIFY_WRITE, autotest.str[7], autotest.str_len + 1))
		goto cleanup;
	memset(buf, 0xb6, autotest.str_len + 1);
	if (__copy_from_user_nocache(buf, autotest.str[0], autotest.str_len + 1))
		goto cleanup;
	if (__copy_to_user(autotest.str[7], buf, autotest.str_len + 1))
		goto cleanup;

#ifdef CONFIG_COMPAT
	/* copy_in_user() */
	if (copy_in_user(autotest.str[8], autotest.str[0], autotest.str_len + 1))
		goto cleanup;
	if (!access_ok(VERIFY_WRITE, autotest.str[9], autotest.str_len + 1))
		goto cleanup;
	if (__copy_in_user(autotest.str[9], autotest.str[0], autotest.str_len + 1))
		goto cleanup;
#endif

	pagefault_disable();

	/* __copy_from_user_inatomic() + __copy_to_user_inatomic() */
	/* Must fail with ruaccess */
	if (!access_ok(VERIFY_WRITE, autotest.str[10], autotest.str_len + 1))
		goto cleanup_pagefault_enable;
	if (!__copy_from_user_inatomic(buf, autotest.str[0], autotest.str_len + 1))
		goto cleanup_pagefault_enable;
	if (!__copy_to_user_inatomic(autotest.str[10], buf, autotest.str_len + 1))
		goto cleanup_pagefault_enable;

	/* __copy_from_user_inatomic_nocache() + __copy_to_user_inatomic() */
	/* Must fail with ruaccess */
	if (!access_ok(VERIFY_WRITE, autotest.str[11], autotest.str_len + 1))
		goto cleanup_pagefault_enable;
	if (!__copy_from_user_inatomic_nocache(buf, autotest.str[0], autotest.str_len + 1))
		goto cleanup_pagefault_enable;
	if (!__copy_to_user_inatomic(autotest.str[11], buf, autotest.str_len + 1))
		goto cleanup_pagefault_enable;

	pagefault_enable();

	/* clear_user() */
	if (clear_user(autotest.str[12], autotest.str_len))
		goto cleanup;
	if (!access_ok(VERIFY_WRITE, autotest.str[13], autotest.str_len))
		goto cleanup;
	if (__clear_user(autotest.str[13], autotest.str_len))
		goto cleanup;

	res = 0;

cleanup:
	kfree(buf);
	err = cleanup_ruaccess(desc);
	if (err)
		goto cancel;
	err = rpc_pack_type(desc, res);
	if (err)
		goto cancel;
out:
	return;

cancel:
	rpc_cancel(desc);
	goto out;

cleanup_pagefault_enable:
	pagefault_enable();
	goto cleanup;
}

int ruaccess_start(void)
{
	rpc_register_void(RUACCESS_AUTOTEST, handle_ruaccess_autotest, 0);
	register_proc_service(KSYS_RUACCESS_AUTOTEST, ruaccess_autotest);
	return 0;
}

void ruaccess_exit(void)
{
}
