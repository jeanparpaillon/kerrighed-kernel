/** Memory injection.
 *  @file injection.h
 *
 *  @author Renaud Lottiaux
 */

#ifndef __MEMORY_INJECTION__
#define __MEMORY_INJECTION__

#include <kerrighed/sys/types.h>

#define FREE_MEM 1
#define LOW_MEM 2
#define OUT_OF_MEM 3

extern int node_mem_usage[KERRIGHED_MAX_NODES];

void mm_injection_init (void);
void mm_injection_finalize (void);

#endif // __MEMORY_INJECTION__
