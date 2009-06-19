/*
 * __put_user functions.
 *
 * (C) Copyright 2005 Linus Torvalds
 * (C) Copyright 2005 Andi Kleen
 * (C) Copyright 2008 Glauber Costa
 *
 * These functions have a non-standard call interface
 * to make them more efficient, especially as they
 * return an error value in addition to the "real"
 * return value.
 */
#include <linux/linkage.h>
#include <asm/dwarf2.h>
#include <asm/thread_info.h>
#include <asm/errno.h>
#include <asm/asm.h>


/*
 * __put_user_X
 *
 * Inputs:	%eax[:%edx] contains the data
 *		%ecx contains the address
 *
 * Outputs:	%eax is error code (0 or -EFAULT)
 *
 * These functions should not modify any other registers,
 * as they get called from within inline assembly.
 */

#define ENTER	CFI_STARTPROC ; \
		GET_THREAD_INFO(%_ASM_BX)
#define EXIT	ret ; \
		CFI_ENDPROC

.text
ENTRY(__put_user_1)
	ENTER
	cmp TI_addr_limit(%_ASM_BX),%_ASM_CX
	jae bad_put_user
1:	movb %al,(%_ASM_CX)
	xor %eax,%eax
#ifdef CONFIG_KRG_FAF
	ret
10:	mov $1,%_ASM_BX
	jmp ruaccess_put_user
	CFI_ENDPROC
#else
	EXIT
#endif
ENDPROC(__put_user_1)

ENTRY(__put_user_2)
	ENTER
	mov TI_addr_limit(%_ASM_BX),%_ASM_BX
	sub $1,%_ASM_BX
	cmp %_ASM_BX,%_ASM_CX
	jae bad_put_user
2:	movw %ax,(%_ASM_CX)
	xor %eax,%eax
#ifdef CONFIG_KRG_FAF
	ret
20:	mov $2,%_ASM_BX
	jmp ruaccess_put_user
	CFI_ENDPROC
#else
	EXIT
#endif
ENDPROC(__put_user_2)

ENTRY(__put_user_4)
	ENTER
	mov TI_addr_limit(%_ASM_BX),%_ASM_BX
	sub $3,%_ASM_BX
	cmp %_ASM_BX,%_ASM_CX
	jae bad_put_user
3:	movl %eax,(%_ASM_CX)
	xor %eax,%eax
#ifdef CONFIG_KRG_FAF
	ret
30:	mov $4,%_ASM_BX
	jmp ruaccess_put_user
	CFI_ENDPROC
#else
	EXIT
#endif
ENDPROC(__put_user_4)

ENTRY(__put_user_8)
	ENTER
	mov TI_addr_limit(%_ASM_BX),%_ASM_BX
	sub $7,%_ASM_BX
	cmp %_ASM_BX,%_ASM_CX
	jae bad_put_user
4:	mov %_ASM_AX,(%_ASM_CX)
#ifdef CONFIG_X86_32
5:	movl %edx,4(%_ASM_CX)
#endif
	xor %eax,%eax
#ifdef CONFIG_KRG_FAF
	ret
40:	mov $8,%_ASM_BX
	jmp ruaccess_put_user
	CFI_ENDPROC
#else
	EXIT
#endif
ENDPROC(__put_user_8)

bad_put_user:
	CFI_STARTPROC
	movl $-EFAULT,%eax
	EXIT
END(bad_put_user)

.section __ex_table,"a"
#ifdef CONFIG_KRG_FAF
	_ASM_PTR 1b,10b
	_ASM_PTR 2b,20b
	_ASM_PTR 3b,30b
	_ASM_PTR 4b,40b
#else /* !CONFIG_KRG_FAF */
	_ASM_PTR 1b,bad_put_user
	_ASM_PTR 2b,bad_put_user
	_ASM_PTR 3b,bad_put_user
	_ASM_PTR 4b,bad_put_user
#endif /* !CONFIG_KRG_FAF */
#ifdef CONFIG_X86_32
	_ASM_PTR 5b,bad_put_user
#endif
.previous

#ifdef CONFIG_KRG_FAF

#ifdef CONFIG_X86_64
ruaccess_put_user:
	CFI_STARTPROC
	pushq_cfi %r8
	CFI_REL_OFFSET r8,0
	CFI_REMEMBER_STATE
	GET_THREAD_INFO(%r8)
	testl $_TIF_RUACCESS,TI_flags(%r8)
	jz no_ruaccess
	cmpq $-1,TI_addr_limit(%r8)
	je no_ruaccess
	/*
	 * gcc does not know that we (may) clobber rdi,rsi,rdx,rcx,r8,r9,r10,r11,
	 * and we don't really care about the cost of saving registers here,
	 * since we are going to wait for the result from a remote host.
	 */
	pushq_cfi %rdi
	CFI_REL_OFFSET rdi,0
	pushq_cfi %rsi
	CFI_REL_OFFSET rsi,0
	pushq_cfi %rdx
	CFI_REL_OFFSET rdx,0
	pushq_cfi %rcx
	CFI_REL_OFFSET rcx,0
	pushq_cfi %r9
	CFI_REL_OFFSET r9,0
	pushq_cfi %r10
	CFI_REL_OFFSET r10,0
	pushq_cfi %r11
	CFI_REL_OFFSET r11,0
	pushq_cfi %rax
	/* The value to write is at %rsp */
	movq %rcx,%rdi
	movq %rsp,%rsi
	movq %rbx,%rdx
	xorl %ecx,%ecx
	callq krg_copy_user_generic
	addq $8,%rsp
	CFI_ADJUST_CFA_OFFSET -8
	popq_cfi %r11
	CFI_RESTORE r11
	popq_cfi %r10
	CFI_RESTORE r10
	popq_cfi %r9
	CFI_RESTORE r9
	popq_cfi %rcx
	CFI_RESTORE rcx
	popq_cfi %rdx
	CFI_RESTORE rdx
	popq_cfi %rsi
	CFI_RESTORE rsi
	popq_cfi %rdi
	CFI_RESTORE rdi
	popq_cfi %r8
	CFI_RESTORE r8
	testl %eax,%eax
	jnz bad_put_user
	ret
no_ruaccess:
	CFI_RESTORE_STATE
	popq_cfi %r8
	CFI_RESTORE r8
	jmp bad_put_user
	CFI_ENDPROC
END(ruaccess_put_user)
#else /* CONFIG_X86_32 */
ruaccess_put_user:
	CFI_STARTPROC
	pushl %edx
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET edx,0
	CFI_REMEMBER_STATE
	GET_THREAD_INFO(%edx)
	testl $_TIF_RUACCESS,TI_flags(%edx)
	jz no_ruaccess
	cmpq $-1,TI_addr_limit(%edx)
	je no_ruaccess
	pushl %eax
	CFI_ADJUST_CFA_OFFSET 4
	/* The value to write is at %esp */
	pushl %ecx
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET ecx,0
	/* C arg4 (zerorest) */
	xorl %edx,%edx
	pushl %edx
	CFI_ADJUST_CFA_OFFSET 4
	movl %ecx,%eax
	movl %ebx,%ecx
	lea 8(%esp),%edx
	call krg_copy_user_generic
	addl $4,%esp
	CFI_ADJUST_CFA_OFFSET -4
	popl %ecx
	CFI_ADJUST_CFA_OFFSET -4
	CFI_RESTORE ecx
	addl $4,%esp
	CFI_ADJUST_CFA_OFFSET -4
	popl %edx
	CFI_ADJUST_CFA_OFFSET -4
	CFI_RESTORE edx
	testl %eax,%eax
	jnz bad_put_user
	ret
no_ruaccess:
	CFI_RESTORE_STATE
	popl %edx
	CFI_ADJUST_CFA_OFFSET -4
	CFI_RESTORE edx
	jmp bad_put_user
	CFI_ENDPROC
END(ruaccess_put_user)
#endif /* CONFIG_X86_32 */

#ifdef CONFIG_X86_64
/*
 * Inputs:	%rax contains the address to copy to
 *		16(%rsp) is the number of bytes to write
 *		8(%rsp) is the value to write
 *
 * Outputs:	%rax contains 0 if a value was successfully written remotely, or
 *		the number of bytes that were failed to write (either because no
 *		remote access was setup, or because write failed remotely).
 *
 * All (possibly) clobbered registers but %rax are saved since we are called
 * from inline assembly, and don't want to slow down the fast path with added
 * clobbers.
 */
ENTRY(ruaccess_put_user_asm)
	CFI_STARTPROC
	pushq_cfi %rdi
	CFI_REL_OFFSET rdi,0
	pushq_cfi %rdx
	CFI_REL_OFFSET rdx,0
	CFI_REMEMBER_STATE
	GET_THREAD_INFO(%rdi)
	/* 16 + 2*8 = 32 */
	movq 32(%rsp),%rdx
	testl $_TIF_RUACCESS,TI_flags(%rdi)
	jz 6f
	cmpq $-1,TI_addr_limit(%rdi)
	je 6f
	pushq_cfi %rsi
	CFI_REL_OFFSET rsi,0
	pushq_cfi %rcx
	CFI_REL_OFFSET rcx,0
	/* krg_copy_user_generic may clobber r8-r11 */
	pushq_cfi %r8
	CFI_REL_OFFSET r8,0
	pushq_cfi %r9
	CFI_REL_OFFSET r9,0
	pushq_cfi %r10
	CFI_REL_OFFSET r10,0
	pushq_cfi %r11
	CFI_REL_OFFSET r11,0
	movq %rax,%rdi
	/* 8 + 2*8 + 6*8 = 72 */
	leaq 72(%rsp),%rsi
	/* %rdx is already loaded */
	xorl %ecx,%ecx
	call krg_copy_user_generic
	popq_cfi %r11
	CFI_RESTORE r11
	popq_cfi %r10
	CFI_RESTORE r10
	popq_cfi %r9
	CFI_RESTORE r9
	popq_cfi %r8
	CFI_RESTORE r8
	popq_cfi %rcx
	CFI_RESTORE rcx
	popq_cfi %rsi
	CFI_RESTORE rsi
5:
	popq_cfi %rdx
	CFI_RESTORE rdx
	popq_cfi %rdi
	CFI_RESTORE rdi
	ret
6:
	CFI_RESTORE_STATE
	movq %rdx,%rax
	jmp 5b
	CFI_ENDPROC
END(ruaccess_put_user_asm)
#else /* CONFIG_X86_32 */
/*
 * Inputs:	%eax contains the address to copy to
 *		12(%esp) is the number of bytes to write
 *		4(%esp) is the value to write
 *
 * Outputs:	%eax contains 0 if a value was successfully written remotely, or
 *		the number of bytes that were failed to write (either because no
 *		remote access was setup, or because write failed remotely).
 *
 * All (possibly) clobbered registers but %eax are saved since we are called
 * from inline assembly, and don't want to slow down the fast path with added
 * clobbers.
 */
ENTRY(ruaccess_put_user_asm)
	CFI_STARTPROC
	pushl %edx
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET edx,0
	pushl %ecx
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET ecx,0
	CFI_REMEMBER_STATE
	GET_THREAD_INFO(%edx)
	/* 12 + 2*4 = 20 */
	movl 20(%esp),%ecx
	testl $_TIF_RUACCESS,TI_flags(%edx)
	jz 6f
	cmpl $-1,TI_addr_limit(%edx)
	je 6f
	/* C arg4 (zerorest) */
	xorl %edx,%edx
	pushl %edx
	CFI_ADJUST_CFA_OFFSET 4
	/* 4 + 2*4 + 4 = 16 */
	lea 16(%esp),%edx
	call krg_copy_user_generic
	addl $4,%esp
	CFI_ADJUST_CFA_OFFSET -4
5:
	popl %ecx
	CFI_ADJUST_CFA_OFFSET -4
	CFI_RESTORE ecx
	popl %edx
	CFI_ADJUST_CFA_OFFSET -4
	CFI_RESTORE edx
	ret
6:
	CFI_RESTORE_STATE
	movl %ecx,%eax
	jmp 5b
	CFI_ENDPROC
END(ruaccess_put_user_asm)
#endif /* CONFIG_X86_32 */

#endif /* CONFIG_KRG_FAF */
