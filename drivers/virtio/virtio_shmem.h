/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _DRIVERS_VIRTIO_VIRTIO_SHMEM_H
#define _DRIVERS_VIRTIO_VIRTIO_SHMEM_H

#include <linux/irqreturn.h>
#include <linux/types.h>
#include <linux/virtio.h>
#include <linux/virtio_pci.h>

struct virtio_shmem_header {
	__le32 revision;
	__le32 size;
	__le32 device_id;
	__le32 vendor_id;

	union {
		__le32 write_transaction;
		struct {
			__le16 write_offset;
			__le16 write_size;
		};
	};
	__u8 config_event;
	__u8 queue_event;
	__u8 __rsvd[2];
	union {
		__le32 frontend_status;
		struct {
			__le16 frontend_flags;
			__le16 frontend_id;
		};
	};
	union {
		__le32 backend_status;
		struct {
			__le16 backend_flags;
			__le16 backend_id;
		};
	};

	struct virtio_pci_common_cfg common_config;
	__u8 config[];
};

struct virtio_shmem_device {
	struct virtio_device vdev;
	struct pci_dev *pci_dev;

	unsigned int num_vectors;
	bool per_vq_vector;
	char *config_irq_name;
	char *queues_irq_name;

	u32 this_id;
	u32 peer_id;

	void *shmem;
	resource_size_t shmem_phys_base;
	resource_size_t shmem_sz;
	struct virtio_shmem_header *virtio_header;

	spinlock_t alloc_lock;
	unsigned long *alloc_bitmap;
	unsigned int alloc_shift;
	void **map_src_addr;

	/* a list of queues so we can dispatch IRQs */
	spinlock_t virtqueues_lock;
	struct list_head virtqueues;

	void (*notify_peer)(struct virtio_shmem_device *vi_dev, unsigned int vector);
	irqreturn_t (*early_irq_handler)(struct virtio_shmem_device *vi_dev);

	void *priv;
#ifdef CONFIG_VIRTIO_IVSHMEM_DEBUG
	resource_size_t shmem_sz_used;
	resource_size_t shmem_sz_max_used;
	u64 dma_alloc_cnt;
	u64 dma_map_cnt;
	u64 dma_map_sg_cnt;

#endif
};

int virtio_shmem_probe(struct virtio_shmem_device *vi_dev);

#endif /* _DRIVERS_VIRTIO_VIRTIO_SHMEM_H */
