/** Distributed management of the VMA structure.
 *  @file vma_struct.h
 *
 *  @author Renaud Lottiaux.
 */



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

void partial_init_vma(struct mm_struct *mm, struct vm_area_struct *vma);

int alloc_fake_vma(struct mm_struct *mm, unsigned long start,
		   unsigned long end);
