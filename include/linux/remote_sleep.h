#ifndef __REMOTE_SLEEP_H__
#define __REMOTE_SLEEP_H__

#include <linux/sched.h>
#include <linux/thread_info.h>
#include <linux/wait.h>
#include <linux/types.h>
#include <linux/errno.h>

struct remote_sleepers_queue {
	wait_queue_head_t wqh;
	bool abort;
};

#define DEFINE_REMOTE_SLEEPERS_QUEUE(name)                      \
        struct remote_sleepers_queue name = {                   \
                .wqh = __WAIT_QUEUE_HEAD_INITIALIZER(name.wqh), \
                .abort = false                                  \
	}

static inline void remote_sleepers_cancel(struct remote_sleepers_queue *q)
{
	q->abort = true;
	wake_up_interruptible_sync(&q->wqh);
}

static inline void remote_sleepers_enable(struct remote_sleepers_queue *q)
{
	q->abort = false;
}

int remote_sleepers_wake_function(wait_queue_t *curr, unsigned mode, int sync,
				  void *key);

#define DEFINE_REMOTE_SLEEPERS_WAIT(name) \
	DEFINE_WAIT_FUNC(name, remote_sleepers_wake_function)

struct rpc_desc;

int remote_sleep_prepare(struct rpc_desc *desc,
			 struct remote_sleepers_queue *q, wait_queue_t *wq);
void remote_sleep_finish(struct remote_sleepers_queue *q, wait_queue_t *wq);

int unpack_remote_sleep_res_prepare(struct rpc_desc *desc);
int unpack_remote_sleep_res(struct rpc_desc *desc, void *res, size_t size);

#define unpack_remote_sleep_res_type_nocheck(desc, v) \
	unpack_remote_sleep_res(desc, &v, sizeof(v))

#define remote_sleep_res_check(v) ({                       \
        if ((v) >= -ERESTARTNOHAND && (v) <= -ERESTARTSYS) \
                set_thread_flag(TIF_SIGPENDING);           \
})

#define unpack_remote_sleep_res_type_struct(desc, v, err) ({       \
        int __err = unpack_remote_sleep_res_type_nocheck(desc, v); \
        if (!__err)                                                \
                remote_sleep_res_check(err);                       \
        __err;                                                     \
})

#define unpack_remote_sleep_res_type(desc, v) \
	unpack_remote_sleep_res_type_struct(desc, v, v)

#endif /* __REMOTE_SLEEP_H__ */
