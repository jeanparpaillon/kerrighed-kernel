#ifndef __DEBUG_FAF_H__

#define __DEBUG_FAF_H__

#include <kerrighed/debug_tools2.h>
#include "../debug_fs.h"

#ifdef DEBUG
#undef DEBUG
#endif

#ifndef CONFIG_KRG_DEBUG
#       define DEBUG(mask, level, fd, server_id, server_fd, file_id, tsk, \
                     file, dbg_id, data) do {} while(0)

#else
#      define DEBUG(mask, level, fd, server_id, server_fd, file_id, tsk, file, dbg_id, data)\
       dvfs_save_log(_THIS_IP_, "faf", mask, level, fd, server_id, server_fd, file_id, tsk, file, dbg_id, (unsigned long)data)
#endif

#endif // __DEBUG_FAF_H__
