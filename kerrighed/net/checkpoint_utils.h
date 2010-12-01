
#ifndef __KRGIP_CHECKPOINT_UTILS_H__
#define __KRGIP_CHECKPOINT_UTILS_H__

#include <kerrighed/action.h>
#include <kerrighed/ghost.h>

/* Note : Could be added to the epm toolbox */
#define KRGIP_CKPT_COPY(action, ghost, data, error) \
{ \
	if (!error) { \
		if (KRGIP_CKPT_ISDST(action)) { \
			error = ghost_read(ghost, &data, sizeof(data)); \
			if (error) \
				printk("Error when reading var " #data ", errno %d\n", error); \
		} else { \
			error = ghost_write(ghost, &data, sizeof(data)); \
			if (error) \
				printk("Error when writing var " #data ", errno %d\n", error); \
		} \
	} \
}

#define KRGIP_CKPT_DATA(action, ghost, buffer, bufsize, error) \
{ \
	if (!error) { \
		if (KRGIP_CKPT_ISDST(action)) { \
			error = ghost_read(ghost, &bufsize, sizeof(bufsize)); \
			if (!error) \
				error = ghost_read(ghost, buffer, bufsize); \
			if (error) \
				printk("Error when reading data " #buffer ", errno %d\n", error); \
		} else { \
			error = ghost_write(ghost, &bufsize, sizeof(bufsize)); \
			if (!error) \
				error = ghost_write(ghost, buffer, bufsize); \
			if (error) \
				printk("Error when writing data " #buffer ", errno %d\n", error); \
		} \
	} \
}

/* " */

#define KRGIP_CKPT_SOCKOPT(action, ghost, sock, optname, opttype, error) \
{ \
	opttype optval; \
	int len = sizeof(opttype); \
	if (!error) { \
		if (KRGIP_CKPT_ISSRC(action)) { \
			error = kernel_getsockopt(sock, SOL_SOCKET, optname, (char *) &optval, &len); \
			KRGIP_CKPT_COPY(action, ghost, optval, error); \
			if (error) \
				printk("Error when getting socket option " #optname " of type " #opttype "errno %d\n", error); \
		} else { \
			KRGIP_CKPT_COPY(action, ghost, optval, error); \
			if (!error) \
				error = kernel_setsockopt(sock, SOL_SOCKET, optname, (char *) &optval, len); \
			if (error) \
				printk("Error when setting socket option " #optname " of type " #opttype " errno %d\n", error); \
		} \
	} \
}




#if 0
#define KRGIP_CKPT_INTOPT(action, ghost, sock, optname, error) \
{ \
	mm_segment_t fs; \
	unsigned int optval; \
	int len = sizeof(optval); \
	if (!error) { \
		fs = get_fs(); \
		set_fs(KERNEL_DS); \
		if (KRGIP_CKPT_ISSRC(action)) { \
			error = sock_getsockopt(sock, SOL_SOCKET, optname, (char *) &optval, &len); \
			KRGIP_CKPT_COPY(action, ghost, optval, error); \
			if (error) \
				printk("Error when getting socket option " #optname " errno %d\n", error); \
		} else { \
			KRGIP_CKPT_COPY(action, ghost, optval, error); \
			if (!error) \
				error = sock_setsockopt(sock, SOL_SOCKET, optname, (char *) &optval, len); \
			if (error) \
				printk("Error when setting socket option " #optname " errno %d\n", error); \
		} \
		set_fs(fs); \
	} \
}

#define KRGIP_CKPT_TVOPT(action, ghost, sock, optname, error) \
{ \
	mm_segment_t fs; \
	struct timeval tv; \
	int len = sizeof(tv); \
	unsigned long exported_tv; \
	if (!error) { \
		fs = get_fs(); \
		set_fs(KERNEL_DS); \
		if (KRGIP_CKPT_ISSRC(action)) { \
			error = sock_getsockopt(sock, SOL_SOCKET, optname, (char *) &tv, &len); \
			exported_tv = timeval_to_ns(&tv); \
			KRGIP_CKPT_COPY(action, ghost, exported_tv, error); \
			if (error) \
				printk("Error when getting socket option " #optname ", errno %d\n", error); \ /* " (workaround to fix syntax coloration in nano) */
		} else { \
			KRGIP_CKPT_COPY(action, ghost, exported_tv, error); \
			tv = ns_to_timeval(exported_tv); \
			if (!error) \
				error = sock_setsockopt(sock, SOL_SOCKET, optname, (char *) &tv, len); \
			if (error) \
				printk("Error when setting socket option " #optname ", errno %d\n", error); \
		} \
		set_fs(fs); \
	} \
}
#endif

#define KRGIP_CKPT_ISDST(action) (epm_target_node(action) == kerrighed_node_id)
#define KRGIP_CKPT_ISSRC(action) (epm_target_node(action) != kerrighed_node_id)

#endif
