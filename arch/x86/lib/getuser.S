/*
 * __get_user functions.
 *
 * (C) Copyright 1998 Linus Torvalds
 * (C) Copyright 2005 Andi Kleen
 * (C) Copyright 2008 Glauber Costa
 *
 * These functions have a non-standard call interface
 * to make them more efficient, especially as they
 * return an error value in addition to the "real"
 * return value.
 */

/*
 * __get_user_X
 *
 * Inputs:	%[r|e]ax contains the address.
 *		The register is modified, but all changes are undone
 *		before returning because the C code doesn't know about it.
 *
 * Outputs:	%[r|e]ax is error code (0 or -EFAULT)
 *		%[r|e]dx contains zero-extended value
 *
 *
 * These functions should not modify any other registers,
 * as they get called from within inline assembly.
 */

#include <linux/linkage.h>
#include <asm/dwarf2.h>
#include <asm/page_types.h>
#include <asm/errno.h>
#include <asm/asm-offsets.h>
#include <asm/thread_info.h>
#include <asm/asm.h>

	.text
ENTRY(__get_user_1)
	CFI_STARTPROC
	GET_THREAD_INFO(%_ASM_DX)
	cmp TI_addr_limit(%_ASM_DX),%_ASM_AX
	jae bad_get_user
1:	movzb (%_ASM_AX),%edx
	xor %eax,%eax
	ret
#ifdef CONFIG_KRG_FAF
10:
	mov $1,%_ASM_DX
	jmp ruaccess_get_user
#endif
	CFI_ENDPROC
ENDPROC(__get_user_1)

ENTRY(__get_user_2)
	CFI_STARTPROC
	add $1,%_ASM_AX
	jc bad_get_user
	GET_THREAD_INFO(%_ASM_DX)
	cmp TI_addr_limit(%_ASM_DX),%_ASM_AX
	jae bad_get_user
2:	movzwl -1(%_ASM_AX),%edx
	xor %eax,%eax
	ret
#ifdef CONFIG_KRG_FAF
20:
	sub $1,%_ASM_AX
	mov $2,%_ASM_DX
	jmp ruaccess_get_user
#endif
	CFI_ENDPROC
ENDPROC(__get_user_2)

ENTRY(__get_user_4)
	CFI_STARTPROC
	add $3,%_ASM_AX
	jc bad_get_user
	GET_THREAD_INFO(%_ASM_DX)
	cmp TI_addr_limit(%_ASM_DX),%_ASM_AX
	jae bad_get_user
3:	mov -3(%_ASM_AX),%edx
	xor %eax,%eax
	ret
#ifdef CONFIG_KRG_FAF
30:
	sub $3,%_ASM_AX
	mov $4,%_ASM_DX
	jmp ruaccess_get_user
#endif
	CFI_ENDPROC
ENDPROC(__get_user_4)

#ifdef CONFIG_X86_64
ENTRY(__get_user_8)
	CFI_STARTPROC
	add $7,%_ASM_AX
	jc bad_get_user
	GET_THREAD_INFO(%_ASM_DX)
	cmp TI_addr_limit(%_ASM_DX),%_ASM_AX
	jae	bad_get_user
4:	movq -7(%_ASM_AX),%_ASM_DX
	xor %eax,%eax
	ret
#ifdef CONFIG_KRG_FAF
40:
	sub $7,%_ASM_AX
	mov $8,%_ASM_DX
	jmp ruaccess_get_user
#endif
	CFI_ENDPROC
ENDPROC(__get_user_8)
#endif

bad_get_user:
	CFI_STARTPROC
	xor %edx,%edx
	mov $(-EFAULT),%_ASM_AX
	ret
	CFI_ENDPROC
END(bad_get_user)

.section __ex_table,"a"
#ifdef CONFIG_KRG_FAF
	_ASM_PTR 1b,10b
	_ASM_PTR 2b,20b
	_ASM_PTR 3b,30b
#ifdef CONFIG_X86_64
	_ASM_PTR 4b,40b
#endif
.previous
#else /* CONFIG_KRG_FAF */
	_ASM_PTR 1b,bad_get_user
	_ASM_PTR 2b,bad_get_user
	_ASM_PTR 3b,bad_get_user
#ifdef CONFIG_X86_64
	_ASM_PTR 4b,bad_get_user
#endif
#endif /* CONFIG_KRG_FAF */

#ifdef CONFIG_KRG_FAF

#ifdef CONFIG_X86_64
ruaccess_get_user:
	CFI_STARTPROC
	pushq_cfi %rcx
	CFI_REL_OFFSET rcx,0
	CFI_REMEMBER_STATE
	GET_THREAD_INFO(%rcx)
	testl $_TIF_RUACCESS,TI_flags(%rcx)
	jz no_ruaccess
	cmpq $-1,TI_addr_limit(%rcx)
	je no_ruaccess
	/*
	 * gcc does not know that we (may) clobber rdi,rsi,rcx,r8,r9,r10,r11,
	 * and we don't really care about the cost of saving registers here,
	 * since we are going to wait for the result from a remote host.
	 */
	pushq_cfi %rdi
	CFI_REL_OFFSET rdi,0
	pushq_cfi %rsi
	CFI_REL_OFFSET rsi,0
	pushq_cfi %r8
	CFI_REL_OFFSET r8,0
	pushq_cfi %r9
	CFI_REL_OFFSET r9,0
	pushq_cfi %r10
	CFI_REL_OFFSET r10,0
	pushq_cfi %r11
	CFI_REL_OFFSET r11,0
	/* %rdx is zero-filled on success */
	xorl %ecx,%ecx
	pushq_cfi %rcx
	movq %rsp,%rdi
	movq %rax,%rsi
	/* %rdx is set by the caller */
	callq krg_copy_user_generic
	/* shorter form of 'movq (%rsp),%rdx' */
	popq_cfi %rdx
	popq_cfi %r11
	CFI_RESTORE r11
	popq_cfi %r10
	CFI_RESTORE r10
	popq_cfi %r9
	CFI_RESTORE r9
	popq_cfi %r8
	CFI_RESTORE r8
	popq_cfi %rsi
	CFI_RESTORE rsi
	popq_cfi %rdi
	CFI_RESTORE rdi
	popq_cfi %rcx
	CFI_RESTORE rcx
	testl %eax,%eax
	jnz bad_get_user
	ret
no_ruaccess:
	CFI_RESTORE_STATE
	popq_cfi %rcx
	CFI_RESTORE rcx
	jmp bad_get_user
	CFI_ENDPROC
END(ruaccess_get_user)
#else /* CONFIG_X86_32 */
ruaccess_get_user:
	CFI_STARTPROC
	pushl %ecx
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET ecx,0
	CFI_REMEMBER_STATE
	GET_THREAD_INFO(%ecx)
	testl $_TIF_RUACCESS,TI_flags(%ecx)
	jz no_ruaccess
	cmpl $-1,TI_addr_limit(%ecx)
	je no_ruaccess
	/* %edx is zero-filled on success */
	xorl %ecx,%ecx
	pushl %ecx
	CFI_ADJUST_CFA_OFFSET 4
	/* C arg4 (zerorest) */
	pushl %ecx
	CFI_ADJUST_CFA_OFFSET 4
	movl %edx,%ecx
	movl %eax,%edx
	lea 4(%esp),%eax
	call krg_copy_user_generic
	addl $4,%esp
	/* shorter form of 'movl (%esp),%edx' */
	popl %edx
	CFI_ADJUST_CFA_OFFSET -4
	popl %ecx
	CFI_ADJUST_CFA_OFFSET -4
	CFI_RESTORE ecx
	testl %eax,%eax
	jnz bad_get_user
	ret
no_ruaccess:
	CFI_RESTORE_STATE
	popl %ecx
	CFI_ADJUST_CFA_OFFSET -4
	CFI_RESTORE ecx
	jmp bad_get_user
	CFI_ENDPROC
END(ruaccess_get_user)
#endif /* CONFIG_X86_32 */

#ifdef CONFIG_X86_64
/*
 * Inputs:	%rax contains the address to copy from
 *		24(%rsp) is the number of bytes to read
 *		16(%rsp) contains the remotely read value on success.
 *
 * All (possibly) clobbered registers but %rax are saved since we are called
 * from inline assembly, and don't want to slow down the fast path with added
 * clobbers.
 */
ENTRY(ruaccess_get_user_asm)
	CFI_STARTPROC
	pushq_cfi %rdi
	CFI_REL_OFFSET rdi,0
	pushq_cfi %rdx
	CFI_REL_OFFSET rdx,0
	CFI_REMEMBER_STATE
	GET_THREAD_INFO(%rdi)
	/* 24 + 2*8 = 40 */
	movq 40(%rsp),%rdx
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
	/* 16 + 2*8 + 6*8 = 80 */
	leaq 80(%rsp),%rdi
	movq %rax,%rsi
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
END(ruaccess_get_user_asm)
#else /* CONFIG_X86_32 */
/*
 * Inputs:	%eax contains the address to copy from
 *		20(%esp) is the number of bytes to read
 *		8(%esp) contains the remotely read value on success.
 *
 * All (possibly) clobbered registers but %eax are saved since we are called
 * from inline assembly, and don't want to slow down the fast path with added
 * clobbers.
 */
ENTRY(ruaccess_get_user_asm)
	CFI_STARTPROC
	pushl %edx
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET edx,0
	pushl %ecx
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET ecx,0
	CFI_REMEMBER_STATE
	GET_THREAD_INFO(%edx)
	/* C arg3 (n) */
	/* 20 + 2*4 = 28 */
	movl 28(%esp),%ecx
	testl $_TIF_RUACCESS,TI_flags(%edx)
	jz 6f
	cmpl $-1,TI_addr_limit(%edx)
	je 6f
	/* C arg4 (zerorest) */
	xorl %edx,%edx
	pushl %edx
	CFI_ADJUST_CFA_OFFSET 4
	movl %eax,%edx
	/* 8 + 2*4 + 4 = 20 */
	lea 20(%esp),%eax
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
END(ruaccess_get_user_asm)
#endif /* CONFIG_X86_32 */

#endif /* CONFIG_KRG_FAF */
