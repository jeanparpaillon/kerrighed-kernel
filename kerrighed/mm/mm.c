/** KerMM module initialization.
 *  @file mm.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2009, Renaud Lottiaux, Kerlabs.
 *
 *  Implementation of functions used to initialize and finalize the
 *  kermm module.
 */

#include <linux/mm.h>
#include <asm/mman.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <kerrighed/krgsyms.h>
#include <kerrighed/mm.h>
#ifdef CONFIG_KRG_DEBUG
#include <linux/netpoll.h>
#include <linux/percpu.h>
#include <linux/hardirq.h>
#include <linux/irqflags.h>
#endif

#include "debug_kermm.h"

#ifdef MODULE_DEBUG
#define DEBUG_THIS_MODULE
#endif

#include <kerrighed/hotplug.h>
#include <kddm/kddm.h>
#include "page_table_tree.h"
#include "mm_struct.h"
#include "memory_int_linker.h"
#include "memory_io_linker.h"
#include "mm_struct_io_linker.h"
#include "mm_server.h"
#include "injection.h"

#ifdef CONFIG_KRG_DEBUG
#define KRGMM_DBG_BUF_SIZE 512

struct krgmm_debug_buffer {
	char buf[KRGMM_DBG_BUF_SIZE];
	char softirq_buf[KRGMM_DBG_BUF_SIZE];
	char hardirq_buf[KRGMM_DBG_BUF_SIZE];
};

static DEFINE_PER_CPU(struct krgmm_debug_buffer, krgmm_dbg_buf);

void krgmm_debug(const char *format, ...)
{
	int nc_only = 0;
	va_list args;
	int cpu;
	struct krgmm_debug_buffer *dbg_buf;
	unsigned long flags;
	char *buffer;

	if (nc_only) {
		cpu = get_cpu();
		dbg_buf = &per_cpu(krgmm_dbg_buf, cpu);
		flags = 0;
		if (in_irq()) {
			local_irq_save(flags);
			buffer = dbg_buf->hardirq_buf;
		} else if (in_softirq()) {
			buffer = dbg_buf->softirq_buf;
		} else {
			buffer = dbg_buf->buf;
		}

		va_start(args, format);
		vsprintf(buffer, format, args);
		va_end(args);
		nc_write_msg(buffer);

		if (in_irq())
			local_irq_restore(flags);
		put_cpu();
	} else {
		va_start(args, format);
		vprintk(format, args);
		va_end(args);
	}
}
#endif

/** Initialisation of the DSM module.
 *  @author Renaud Lottiaux
 *
 *  Start object server, object manager and kddm set manager threads.
 *  Register kermm services in the /proc/kerrighed/services.
 */
int init_kermm(void)
{
	printk("KerMM initialisation : start\n");

	krgsyms_register (KRGSYMS_VM_OPS_NULL, &null_vm_ops);
	krgsyms_register (KRGSYMS_VM_OPS_FILE_GENERIC, &generic_file_vm_ops);
	special_mapping_vm_ops_krgsyms_register ();
	krgsyms_register (KRGSYMS_VM_OPS_MEMORY_KDDM_VMOPS,
			  &anon_memory_kddm_vmops);

	krgsyms_register (KRGSYMS_ARCH_UNMAP_AREA, arch_unmap_area);
	krgsyms_register (KRGSYMS_ARCH_UNMAP_AREA_TOPDOWN,
			  arch_unmap_area_topdown);
	krgsyms_register (KRGSYMS_ARCH_GET_UNMAP_AREA, arch_get_unmapped_area);
	krgsyms_register (KRGSYMS_ARCH_GET_UNMAP_AREA_TOPDOWN,
			  arch_get_unmapped_area_topdown);
	krgsyms_register (KRGSYMS_KDDM_PT_OPS, &kddm_pt_set_ops);

	register_io_linker (MEMORY_LINKER, &memory_linker);
	register_io_linker (MM_STRUCT_LINKER, &mm_struct_io_linker);

	mm_struct_init ();
	mm_server_init();
	mm_injection_init();

	INIT_MM_DEBUG();

	printk ("KerMM initialisation done\n");

	return 0;
}



/** Cleanup of the DSM module.
 *  @author Renaud Lottiaux
 *
 *  Kill object manager, object server and kddm set manager threads.
 */
void cleanup_kermm (void)
{
	printk ("KerMM termination : start\n");

	mm_injection_finalize();
	mm_server_finalize();
	mm_struct_finalize();

	krgsyms_unregister (KRGSYMS_VM_OPS_FILE_GENERIC);
	special_mapping_vm_ops_krgsyms_unregister ();
	krgsyms_unregister (KRGSYMS_VM_OPS_MEMORY_KDDM_VMOPS);
	krgsyms_unregister (KRGSYMS_ARCH_UNMAP_AREA);
	krgsyms_unregister (KRGSYMS_ARCH_UNMAP_AREA_TOPDOWN);
	krgsyms_unregister (KRGSYMS_ARCH_GET_UNMAP_AREA);
	krgsyms_unregister (KRGSYMS_ARCH_GET_UNMAP_AREA_TOPDOWN);

	printk ("KerMM termination done\n");
}
