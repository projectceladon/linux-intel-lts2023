/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_IVSHM_H
#define _LINUX_IVSHM_H

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/fs.h>

#ifdef CONFIG_IVSHM

extern const struct file_operations ivshm_region_fops;

static inline bool is_ivshm_region(struct file *file)
{
	return (file->f_op == &ivshm_region_fops);
}

extern struct page *ivshm_region_offset_to_page(struct file *filep, pgoff_t pgoff);

#else /* !CONFIG_IVSHM */

#define is_ivshm_region(file)			false
#define ivshm_region_offset_to_page(filep, pgoff)	NULL

#endif /* !CONFIG_IVSHM */

#endif /* _LINUX_IVSHM_H */
