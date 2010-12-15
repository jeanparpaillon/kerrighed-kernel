/*
 *  kerrighed/net/checkpoint_utils.h
 *
 *  Copyright (C) 2010, Emmanuel Thierry - Kerlabs
 */

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
			error = ghost_read(ghost, buffer, bufsize); \
			if (error) \
				printk("Error when reading data " #buffer ", errno %d\n", error); \
		} else { \
			error = ghost_write(ghost, buffer, bufsize); \
			if (error) \
				printk("Error when writing data " #buffer ", errno %d\n", error); \
		} \
	} \
}

#define KRGIP_CKPT_TSTAMP(action, ghost, time, base, error) \
{ \
	if (!error) { \
		if (KRGIP_CKPT_ISDST(action)) { \
			error = ghost_read(ghost, &time, sizeof(time)); \
			if (error) \
				printk("Error when reading var " #time ", errno %d\n", error); \
			else \
				time += base; \
		} else { \
			typeof(time) delta = time - base; \
			error = ghost_write(ghost, &delta, bufsize); \
			if (error) \
				printk("Error when writing data " #time ", errno %d\n", error); \
		} \
	} \
}

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


#define KRGIP_CKPT_ISDST(action) (epm_target_node(action) == kerrighed_node_id)
#define KRGIP_CKPT_ISSRC(action) (epm_target_node(action) != kerrighed_node_id)

#endif
