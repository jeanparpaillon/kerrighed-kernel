/*
 * Copyright 2008 Vitaly Mayatskikh <vmayatsk@redhat.com>
 * Copyright 2002 Andi Kleen, SuSE Labs.
 * Subject to the GNU Public License v2.
 *
 * Functions to copy from and to user space.
 */

#include <linux/linkage.h>
#include <asm/dwarf2.h>

#define FIX_ALIGNMENT 1

#include <asm/current.h>
#include <asm/asm-offsets.h>
#include <asm/thread_info.h>
#include <asm/cpufeature.h>

	.macro ALTERNATIVE_JUMP feature,orig,alt
0:
	.byte 0xe9	/* 32bit jump */
	.long \orig-1f	/* by default jump to orig */
1:
	.section .altinstr_replacement,"ax"
2:	.byte 0xe9			/* near jump with 32bit immediate */
	.long \alt-1b /* offset */   /* or alternatively to alt */
	.previous
	.section .altinstructions,"a"
	.align 8
	.quad  0b
	.quad  2b
	.byte  \feature			/* when feature is set */
	.byte  5
	.byte  5
	.previous
	.endm

	.macro ALIGN_DESTINATION
#ifdef FIX_ALIGNMENT
	/* check for bad alignment of destination */
	movl %edi,%ecx
	andl $7,%ecx
	jz 102f				/* already aligned */
	subl $8,%ecx
	negl %ecx
	subl %ecx,%edx
100:	movb (%rsi),%al
101:	movb %al,(%rdi)
	incq %rsi
	incq %rdi
	decl %ecx
	jnz 100b
102:
	.section .fixup,"ax"
103:	addl %ecx,%edx			/* ecx is zerorest also */
#ifdef CONFIG_KRG_FAF
	jmp copy_user_check_ruaccess
#else
	jmp copy_user_handle_tail
#endif
	.previous

	.section __ex_table,"a"
	.align 8
	.quad 100b,103b
	.quad 101b,103b
	.previous
#endif
	.endm

/* Standard copy_to_user with segment limit checking */
ENTRY(copy_to_user)
	CFI_STARTPROC
	GET_THREAD_INFO(%rax)
	movq %rdi,%rcx
	addq %rdx,%rcx
	jc bad_to_user
	cmpq TI_addr_limit(%rax),%rcx
	jae bad_to_user
	ALTERNATIVE_JUMP X86_FEATURE_REP_GOOD,copy_user_generic_unrolled,copy_user_generic_string
	CFI_ENDPROC

/* Standard copy_from_user with segment limit checking */
ENTRY(copy_from_user)
	CFI_STARTPROC
	GET_THREAD_INFO(%rax)
	movq %rsi,%rcx
	addq %rdx,%rcx
	jc bad_from_user
	cmpq TI_addr_limit(%rax),%rcx
	jae bad_from_user
	ALTERNATIVE_JUMP X86_FEATURE_REP_GOOD,copy_user_generic_unrolled,copy_user_generic_string
	CFI_ENDPROC
ENDPROC(copy_from_user)

ENTRY(copy_user_generic)
	CFI_STARTPROC
	ALTERNATIVE_JUMP X86_FEATURE_REP_GOOD,copy_user_generic_unrolled,copy_user_generic_string
	CFI_ENDPROC
ENDPROC(copy_user_generic)

ENTRY(__copy_from_user_inatomic)
	CFI_STARTPROC
	ALTERNATIVE_JUMP X86_FEATURE_REP_GOOD,copy_user_generic_unrolled,copy_user_generic_string
	CFI_ENDPROC
ENDPROC(__copy_from_user_inatomic)

	.section .fixup,"ax"
	/* must zero dest */
ENTRY(bad_from_user)
bad_from_user:
	CFI_STARTPROC
	movl %edx,%ecx
	xorl %eax,%eax
	rep
	stosb
bad_to_user:
	movl %edx,%eax
	ret
	CFI_ENDPROC
ENDPROC(bad_from_user)
	.previous

/*
 * copy_user_generic_unrolled - memory copy with exception handling.
 * This version is for CPUs like P4 that don't have efficient micro
 * code for rep movsq
 *
 * Input:
 * rdi destination
 * rsi source
 * rdx count
 *
 * Output:
 * eax uncopied bytes or 0 if successfull.
 */
ENTRY(copy_user_generic_unrolled)
	CFI_STARTPROC
#ifdef CONFIG_KRG_FAF
	pushq_cfi %rdx	/* save count */
	CFI_REL_OFFSET rdx,0
#endif
	cmpl $8,%edx
	jb 20f		/* less then 8 bytes, go to byte copy loop */
	ALIGN_DESTINATION
	movl %edx,%ecx
	andl $63,%edx
	shrl $6,%ecx
	jz 17f
1:	movq (%rsi),%r8
2:	movq 1*8(%rsi),%r9
3:	movq 2*8(%rsi),%r10
4:	movq 3*8(%rsi),%r11
5:	movq %r8,(%rdi)
6:	movq %r9,1*8(%rdi)
7:	movq %r10,2*8(%rdi)
8:	movq %r11,3*8(%rdi)
9:	movq 4*8(%rsi),%r8
10:	movq 5*8(%rsi),%r9
11:	movq 6*8(%rsi),%r10
12:	movq 7*8(%rsi),%r11
13:	movq %r8,4*8(%rdi)
14:	movq %r9,5*8(%rdi)
15:	movq %r10,6*8(%rdi)
16:	movq %r11,7*8(%rdi)
	leaq 64(%rsi),%rsi
	leaq 64(%rdi),%rdi
	decl %ecx
	jnz 1b
17:	movl %edx,%ecx
	andl $7,%edx
	shrl $3,%ecx
	jz 20f
18:	movq (%rsi),%r8
19:	movq %r8,(%rdi)
	leaq 8(%rsi),%rsi
	leaq 8(%rdi),%rdi
	decl %ecx
	jnz 18b
20:	andl %edx,%edx
	jz 23f
	movl %edx,%ecx
21:	movb (%rsi),%al
22:	movb %al,(%rdi)
	incq %rsi
	incq %rdi
	decl %ecx
	jnz 21b
23:	xor %eax,%eax
#ifdef CONFIG_KRG_FAF
	leaq 8(%rsp),%rsp
	CFI_ADJUST_CFA_OFFSET -8
#endif
	ret

	.section .fixup,"ax"
30:	shll $6,%ecx
	addl %ecx,%edx
	jmp 60f
40:	lea (%rdx,%rcx,8),%rdx
	jmp 60f
50:	movl %ecx,%edx
#ifdef CONFIG_KRG_FAF
60:	jmp copy_user_check_ruaccess
#else
60:	jmp copy_user_handle_tail /* ecx is zerorest also */
#endif
	.previous

	.section __ex_table,"a"
	.align 8
	.quad 1b,30b
	.quad 2b,30b
	.quad 3b,30b
	.quad 4b,30b
	.quad 5b,30b
	.quad 6b,30b
	.quad 7b,30b
	.quad 8b,30b
	.quad 9b,30b
	.quad 10b,30b
	.quad 11b,30b
	.quad 12b,30b
	.quad 13b,30b
	.quad 14b,30b
	.quad 15b,30b
	.quad 16b,30b
	.quad 18b,40b
	.quad 19b,40b
	.quad 21b,50b
	.quad 22b,50b
	.previous
	CFI_ENDPROC
ENDPROC(copy_user_generic_unrolled)

/* Some CPUs run faster using the string copy instructions.
 * This is also a lot simpler. Use them when possible.
 *
 * Only 4GB of copy is supported. This shouldn't be a problem
 * because the kernel normally only writes from/to page sized chunks
 * even if user space passed a longer buffer.
 * And more would be dangerous because both Intel and AMD have
 * errata with rep movsq > 4GB. If someone feels the need to fix
 * this please consider this.
 *
 * Input:
 * rdi destination
 * rsi source
 * rdx count
 *
 * Output:
 * eax uncopied bytes or 0 if successful.
 */
ENTRY(copy_user_generic_string)
	CFI_STARTPROC
	andl %edx,%edx
	jz 4f
#ifdef CONFIG_KRG_FAF
	pushq_cfi %rdx	/* save count */
	CFI_REL_OFFSET rdx,0
#endif
	cmpl $8,%edx
	jb 2f		/* less than 8 bytes, go to byte copy loop */
	ALIGN_DESTINATION
	movl %edx,%ecx
	shrl $3,%ecx
	andl $7,%edx
1:	rep
	movsq
2:	movl %edx,%ecx
3:	rep
	movsb
#ifdef CONFIG_KRG_FAF
	leaq 8(%rsp),%rsp
	CFI_ADJUST_CFA_OFFSET -8
#endif
4:	xorl %eax,%eax
	ret

	.section .fixup,"ax"
11:	lea (%rdx,%rcx,8),%rcx
12:	movl %ecx,%edx		/* ecx is zerorest also */
#ifdef CONFIG_KRG_FAF
	jmp copy_user_check_ruaccess
#else
	jmp copy_user_handle_tail
#endif
	.previous

	.section __ex_table,"a"
	.align 8
	.quad 1b,11b
	.quad 3b,12b
	.previous
	CFI_ENDPROC
ENDPROC(copy_user_generic_string)

#ifdef CONFIG_KRG_FAF
ENTRY(copy_user_check_ruaccess)
	CFI_STARTPROC
	cmpl %edx,(%rsp)
	leaq 8(%rsp),%rsp
	jne copy_user_handle_tail
	GET_THREAD_INFO(%rax)
	testl $_TIF_RUACCESS,TI_flags(%rax)
	jz copy_user_handle_tail
	cmpq $-1,TI_addr_limit(%rax)
	je copy_user_handle_tail
	jmp krg_copy_user_generic
	CFI_ENDPROC
ENDPROC(copy_user_check_ruaccess)

/*
 * Inputs: rax is the address of the hook to call
 *         the hook's arg (up to 4) are already passed in conventional order
 * Outputs: rax is 0 if the hook was called, non zero otherwise
 *	    if rax is 0, rdx is the hook's result.
 *
 * Called from inline assembly, so save all possibly clobbered registers
 */
ENTRY(usercopy_check_ruaccess)
	CFI_STARTPROC
	pushq_cfi %r8
	CFI_REL_OFFSET r8,0
	GET_THREAD_INFO(%r8)
	testl $_TIF_RUACCESS,TI_flags(%r8)
	jz back_to_local
	cmpq $-1,TI_addr_limit(%r8)
	je back_to_local
	pushq_cfi %rdi
	CFI_REL_OFFSET rdi,0
	pushq_cfi %rsi
	CFI_REL_OFFSET rsi,0
	pushq_cfi %rcx
	CFI_REL_OFFSET rcx,0
	pushq_cfi %r9
	CFI_REL_OFFSET r9,0
	pushq_cfi %r10
	CFI_REL_OFFSET r10,0
	pushq_cfi %r11
	CFI_REL_OFFSET r11,0
	call *%rax
	movq %rax,%rdx
	xorl %eax,%eax
	popq_cfi %r11
	CFI_RESTORE r11
	popq_cfi %r10
	CFI_RESTORE r10
	popq_cfi %r9
	CFI_RESTORE r9
	popq_cfi %rcx
	CFI_RESTORE rcx
	popq_cfi %rsi
	CFI_RESTORE rsi
	popq_cfi %rdi
	CFI_RESTORE rdi
back_to_local:
	popq_cfi %r8
	CFI_RESTORE r8
	ret
	CFI_ENDPROC
ENDPROC(usercopy_check_ruaccess)
#endif
