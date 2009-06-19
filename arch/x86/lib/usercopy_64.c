/* 
 * User address space access functions.
 *
 * Copyright 1997 Andi Kleen <ak@muc.de>
 * Copyright 1997 Linus Torvalds
 * Copyright 2002 Andi Kleen <ak@suse.de>
 */
#include <linux/module.h>
#ifdef CONFIG_KRG_FAF
#include <kerrighed/faf.h>
#endif
#include <asm/uaccess.h>

/*
 * Copy a null terminated string from userspace.
 */

#ifdef CONFIG_KRG_FAF

#define __do_strncpy_from_user(dst,src,count,res)			   \
do {									   \
	long __d0, __d1, __d2;						   \
	might_sleep();							   \
	__asm__ __volatile__(						   \
		"	testq %1,%1\n"					   \
		"	jz 2f\n"					   \
		"0:	lodsb\n"					   \
		"	stosb\n"					   \
		"	testb %%al,%%al\n"				   \
		"	jz 1f\n"					   \
		"	decq %1\n"					   \
		"	jnz 0b\n"					   \
		"1:	subq %1,%0\n"					   \
		"2:\n"							   \
		".section .fixup,\"ax\"\n"				   \
		"3:	cmpq %0,%1\n"					   \
		"	jne 5f\n"					   \
		"4: 	movq $krg___strncpy_from_user,%%rax\n"		   \
		"	call usercopy_check_ruaccess\n"			   \
		" 	testq %%rax,%%rax\n"				   \
		" 	jz 2b\n"					   \
		"5:	movq %5,%0\n"					   \
		"	jmp 2b\n"					   \
		".previous\n"						   \
		_ASM_EXTABLE(0b,3b)					   \
		: "=&d"(res), "=&c"(count), "=&a" (__d0), "=&S" (__d1),	   \
		  "=&D" (__d2)						   \
		: "i"(-EFAULT), "0"(count), "1"(count), "3"(src), "4"(dst) \
		: "memory");						   \
} while (0)

#else /* !CONFIG_KRG_FAF */

#define __do_strncpy_from_user(dst,src,count,res)			   \
do {									   \
	long __d0, __d1, __d2;						   \
	might_fault();							   \
	__asm__ __volatile__(						   \
		"	testq %1,%1\n"					   \
		"	jz 2f\n"					   \
		"0:	lodsb\n"					   \
		"	stosb\n"					   \
		"	testb %%al,%%al\n"				   \
		"	jz 1f\n"					   \
		"	decq %1\n"					   \
		"	jnz 0b\n"					   \
		"1:	subq %1,%0\n"					   \
		"2:\n"							   \
		".section .fixup,\"ax\"\n"				   \
		"3:	movq %5,%0\n"					   \
		"	jmp 2b\n"					   \
		".previous\n"						   \
		_ASM_EXTABLE(0b,3b)					   \
		: "=&r"(res), "=&c"(count), "=&a" (__d0), "=&S" (__d1),	   \
		  "=&D" (__d2)						   \
		: "i"(-EFAULT), "0"(count), "1"(count), "3"(src), "4"(dst) \
		: "memory");						   \
} while (0)

#endif /* !CONFIG_KRG_FAF */

long
__strncpy_from_user(char *dst, const char __user *src, long count)
{
	long res;
	__do_strncpy_from_user(dst, src, count, res);
	return res;
}
EXPORT_SYMBOL(__strncpy_from_user);

long
strncpy_from_user(char *dst, const char __user *src, long count)
{
	long res = -EFAULT;
	if (access_ok(VERIFY_READ, src, 1))
		return __strncpy_from_user(dst, src, count);
	return res;
}
EXPORT_SYMBOL(strncpy_from_user);

/*
 * Zero Userspace
 */

unsigned long __clear_user(void __user *addr, unsigned long size)
{
	long __d0;
#ifdef CONFIG_KRG_FAF
	long __d1;
#endif
	might_fault();
	/* no memory constraint because it doesn't change any memory gcc knows
	   about */
#ifdef CONFIG_KRG_FAF
	asm volatile(
		"	testq  %[size8],%[size8]\n"
		"	jz     4f\n"
		"0:	movq %[zero],(%[dst])\n"
		"	addq   %[eight],%[dst]\n"
		"	decl %%ecx ; jnz   0b\n"
		"4:	movq  %[size1],%%rcx\n"
		"	testl %%ecx,%%ecx\n"
		"	jz     2f\n"
		"1:	movb   %b[zero],(%[dst])\n"
		"	incq   %[dst]\n"
		"	decl %%ecx ; jnz  1b\n"
		"2:\n"
		".section .fixup,\"ax\"\n"
		"3:	lea 0(%[size1],%[size8],8),%[size8]\n"
		"4: 	cmpq %[dst],%[orig_dst]\n"
		"	jne 2b\n"
		"	pushq %%rax\n"
		"	pushq %%rdx\n"
		"	movq $krg___clear_user,%%rax\n"
		"	movq %[size8],%%rsi\n"
		"	call usercopy_check_ruaccess\n"
		"	testq %%rax,%%rax\n"
		"	jnz 5f\n"
		"	movq %%rdx,%[size8]\n"
		"5: 	popq %%rdx\n"
		"	popq %%rax\n"
		"	jmp 2b\n"
		".previous\n"
		_ASM_EXTABLE(0b,3b)
		_ASM_EXTABLE(1b,4b)
		: [size8] "=&c"(size), [dst] "=&D" (__d0), [orig_dst] "=&S" (__d1)
		: [size1] "r"(size & 7), "[size8]" (size / 8), "[dst]"(addr),
		  "[orig_dst]" (addr),
		  [zero] "r" (0UL), [eight] "r" (8UL));
#else /* !CONFIG_KRG_FAF */
	asm volatile(
		"	testq  %[size8],%[size8]\n"
		"	jz     4f\n"
		"0:	movq %[zero],(%[dst])\n"
		"	addq   %[eight],%[dst]\n"
		"	decl %%ecx ; jnz   0b\n"
		"4:	movq  %[size1],%%rcx\n"
		"	testl %%ecx,%%ecx\n"
		"	jz     2f\n"
		"1:	movb   %b[zero],(%[dst])\n"
		"	incq   %[dst]\n"
		"	decl %%ecx ; jnz  1b\n"
		"2:\n"
		".section .fixup,\"ax\"\n"
		"3:	lea 0(%[size1],%[size8],8),%[size8]\n"
		"	jmp 2b\n"
		".previous\n"
		_ASM_EXTABLE(0b,3b)
		_ASM_EXTABLE(1b,2b)
		: [size8] "=&c"(size), [dst] "=&D" (__d0)
		: [size1] "r"(size & 7), "[size8]" (size / 8), "[dst]"(addr),
		  [zero] "r" (0UL), [eight] "r" (8UL));
#endif /* !CONFIG_KRG_FAF */
	return size;
}
EXPORT_SYMBOL(__clear_user);

unsigned long clear_user(void __user *to, unsigned long n)
{
	if (access_ok(VERIFY_WRITE, to, n))
		return __clear_user(to, n);
	return n;
}
EXPORT_SYMBOL(clear_user);

/*
 * Return the size of a string (including the ending 0)
 *
 * Return 0 on exception, a value greater than N if too long
 */

long __strnlen_user(const char __user *s, long n)
{
	long res = 0;
	char c;

	while (1) {
		if (res>n)
			return n+1;
#ifdef CONFIG_KRG_FAF
		{
			long ret = 0;
			long local_access = 1;

			asm volatile(
				"1:	movb (%4),%b1\n"
				"2:\n"
				".section .fixup,\"ax\"\n"
				"3:	movq %5,%0\n"
				"	testq %2,%2\n"
				"	jnz 2b\n"
				"	movq $krg___strnlen_user,%%rax\n"
				"	call usercopy_check_ruaccess\n"
				"	jmp 2b\n"
				".previous\n"
				_ASM_EXTABLE(1b,3b)
				: "=&r"(ret), "=r"(c), "=d"(res), "=&a"(local_access)
				: "D"(s), "S"(n), "0"(ret), "2"(res), "3"(local_access));
			if (ret) {
				if (!local_access)
					return res;
				return 0;
			}
		}
#else /* !CONFIG_KRG_FAF */
		if (__get_user(c, s))
			return 0;
#endif /* !CONFIG_KRG_FAF */
		if (!c)
			return res+1;
		res++;
		s++;
	}
}
EXPORT_SYMBOL(__strnlen_user);

long strnlen_user(const char __user *s, long n)
{
	if (!access_ok(VERIFY_READ, s, n))
		return 0;
	return __strnlen_user(s, n);
}
EXPORT_SYMBOL(strnlen_user);

long strlen_user(const char __user *s)
{
	long res = 0;
	char c;

	for (;;) {
#ifdef CONFIG_KRG_FAF
		{
			long ret = 0;
			long local_access = 1;
			unsigned long fake_limit = ~0UL;

			asm volatile(
				"	cmpq %6,%4\n"
				"	jae 4f\n"
				"1:	movb (%4),%b1\n"
				"2:\n"
				".section .fixup,\"ax\"\n"
				"3:	movq %5,%0\n"
				"	testq %2,%2\n"
				"	jnz 2b\n"
				"	movq $krg___strnlen_user,%%rax\n"
				"	call usercopy_check_ruaccess\n"
				"	jmp 2b\n"
				"4:	movq %5,%0\n"
				"	jmp 2b\n"
				".previous\n"
				_ASM_EXTABLE(1b,3b)
				: "=&r"(ret), "=r"(c), "=d"(res), "=&a"(local_access)
				: "D"(s), "S"(fake_limit),
				  "g"(current_thread_info()->addr_limit.seg),
				  "0"(ret), "2"(res), "3"(local_access));
			if (ret) {
				if (!local_access)
					return res;
				return 0;
			}
		}
#else /* !CONFIG_KRG_FAF */
		if (get_user(c, s))
			return 0;
#endif /* !CONFIG_KRG_FAF */
		if (!c)
			return res+1;
		res++;
		s++;
	}
}
EXPORT_SYMBOL(strlen_user);

unsigned long copy_in_user(void __user *to, const void __user *from, unsigned len)
{
	if (access_ok(VERIFY_WRITE, to, len) && access_ok(VERIFY_READ, from, len)) { 
		return copy_user_generic((__force void *)to, (__force void *)from, len);
	} 
	return len;		
}
EXPORT_SYMBOL(copy_in_user);

/*
 * Try to copy last bytes and clear the rest if needed.
 * Since protection fault in copy_from/to_user is not a normal situation,
 * it is not necessary to optimize tail handling.
 */
unsigned long
copy_user_handle_tail(char *to, char *from, unsigned len, unsigned zerorest)
{
	char c;
	unsigned zero_len;

	for (; len; --len) {
		if (__get_user_nocheck(c, from++, sizeof(char)))
			break;
		if (__put_user_nocheck(c, to++, sizeof(char)))
			break;
	}

	for (c = 0, zero_len = len; zerorest && zero_len; --zero_len)
		if (__put_user_nocheck(c, to++, sizeof(char)))
			break;
	return len;
}
