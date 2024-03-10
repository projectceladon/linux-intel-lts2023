/* SPDX-License-Identifier: GPL-2.0-or-later */

/**
 * @file
 * interfaces for guest shared memory device and ivshmem device
 */
#ifndef _DRIVERS_VIRTIO_SHMEM_H
#define _DRIVERS_VIRTIO_SHMEM_H

#ifdef CONFIG_VIRTIO_IVSHMEM
struct page *virtio_shmem_allocate_page(struct device *dev);
void virtio_shmem_free_page(struct device *dev, struct page *page);
#else
static inline struct page *virtio_shmem_allocate_page(struct device *dev)
{
	return ERR_PTR(-EINVAL);
}
static inline void virtio_shmem_free_page(struct device *dev, struct page *page)
{
}
#endif

#endif /* _DRIVERS_VIRTIO_SHMEM_H */
