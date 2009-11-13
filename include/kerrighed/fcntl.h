#ifndef __KKRG_FCNTL__
#define __KKRG_FCNTL__

#define O_FAF_CLT_BIT_NR        22        /* Client File Access Forwarding flag */
#define O_FAF_SRV_BIT_NR        23        /* Server File Access Forwarding flag */
#define O_KRG_SHARED_BIT_NR     24        /* Cluster wide shared file pointer */
#define O_FAF_TTY_BIT_NR        25        /* The file is faffed and is a tty */

#define O_FAF_CLT               (1<<O_FAF_CLT_BIT_NR)
#define O_FAF_SRV               (1<<O_FAF_SRV_BIT_NR)
#define O_KRG_SHARED            (1<<O_KRG_SHARED_BIT_NR)
#define O_FAF_TTY               (1<<O_FAF_TTY_BIT_NR)

/* Mask for Kerrighed O flags */
#define O_KRG_FLAGS             (O_FAF_CLT|O_FAF_SRV|O_KRG_SHARED|O_FAF_TTY)

#endif // __KKRG_FCNTL__
