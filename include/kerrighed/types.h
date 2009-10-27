#ifndef __KRG_TYPES_INTERNAL__
#define __KRG_TYPES_INTERNAL__

#include <kerrighed/sys/types.h>

#ifdef __KERNEL__
#include <kerrighed/krgnodemask.h>
#endif

#define KRGFCT(p) if(p!=NULL) p

#if defined(CONFIG_KERRIGHED) || defined(CONFIG_KRGRPC)

typedef unsigned char kerrighed_session_t;
typedef int kerrighed_subsession_t;
typedef unsigned long unique_id_t;   /**< Unique id type */

#endif /* CONFIG_KERRIGHED */

#ifdef __KERNEL__

#ifdef CONFIG_KRG_STREAM
struct dstream_socket { // shared node-wide
	unique_id_t id_socket;
	unique_id_t id_container;
	struct dstream_interface_ctnr *interface_ctnr;
	struct stream_socket *krg_socket;
};
#endif

#endif /* __KERNEL__ */

#endif /* __KRG_TYPES_INTERNAL__ */
