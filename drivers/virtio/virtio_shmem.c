// SPDX-License-Identifier: GPL-2.0-only
/*
 * Virtio over shared memory front-end device driver
 *
 * Copyright (c) Siemens AG, 2019
 */

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/dma-map-ops.h>
#include <linux/memremap.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_pci.h>
#include <linux/guest_shm.h>
#include <asm/hypervisor.h>

#include "virtio_shmem.h"

#define VIRTIO_SHMEM_PREFERRED_ALLOC_CHUNKS	4096

#define VIRTIO_STATE_READY	cpu_to_le32(1)

#define FRONTEND_FLAG_PRESENT   cpu_to_le16(1)

#define VI_REG_OFFSET(reg)	offsetof(struct virtio_shmem_header, reg)
#define VI_CFG_REG_OFFSET(reg)  VI_REG_OFFSET(common_config.reg)

#define VIRTIO_SHMEM_BE_STATUS_ACTIVE 	1
#define VIRTIO_SHMEM_BE_STATUS_INACTIVE	2
#define VIRTIO_SHMEM_BE_STATUS_RESET	3

#define VIRTIO_SHMEM_HANDSHAKE_MASK	0xa69
#define VIRTIO_SHMEM_HANDSHAKE_ACK 0x0b69
#define VIRTIO_SHMEM_SYNC_TIMES 10000

struct virtio_shmem_vq_info {
	/* the actual virtqueue */
	struct virtqueue *vq;

	/* vector to use for signaling the device */
	unsigned int device_vector;
	/* vector used by the device for signaling the driver */
	unsigned int driver_vector;

	char *irq_name;

	/* the list node for the virtqueues list */
	struct list_head node;
};
#define VIRTIO_SHMEM_NAME	"virtio_shmem"
#define VIRTIO_SHMEM_MAX_DEVICES		(1U << MINORBITS)
static DEFINE_IDR(virtio_shmem_idr);
static DEFINE_MUTEX(minor_lock);
static int virtio_shmem_major;
static struct cdev *virtio_shmem_cdev;

static struct attribute *virtio_ivshmem_attrs[] = {
	NULL,
};
ATTRIBUTE_GROUPS(virtio_ivshmem);
static struct class virtio_ivshmem_class = {
	.name = "virtio_ivshmem",
	.dev_groups = virtio_ivshmem_groups,
};


static inline unsigned int get_custom_order(unsigned long size,
					    unsigned int shift)
{
	size--;
	size >>= shift;
#if BITS_PER_LONG == 32
	return fls(size);
#else
	return fls64(size);
#endif
}

static int virtio_shmem_reset_virtio_dev(struct virtio_shmem_device *vi_dev);
static void virtio_shmem_unregister_virtio_dev(struct virtio_shmem_device *vi_dev, int force);
static int virtio_shmem_register_virtio_dev(struct virtio_shmem_device *vi_dev);

static inline struct virtio_shmem_device *
to_virtio_shmem_device(struct virtio_device *vdev)
{
	return container_of(vdev, struct virtio_shmem_device, vdev);
}

static int virtio_shmem_be_status(struct virtio_shmem_device *vi_dev)
{
	uint32_t mask = READ_ONCE(vi_dev->virtio_header->handshake);

	if ((mask & 0xffff) != VIRTIO_SHMEM_HANDSHAKE_MASK)
		return VIRTIO_SHMEM_BE_STATUS_INACTIVE;
	if ((mask & 0xffff0000) >> 16 != vi_dev->backend_rand && vi_dev->virtio_registered == true)
		return VIRTIO_SHMEM_BE_STATUS_RESET;
	else
		return VIRTIO_SHMEM_BE_STATUS_ACTIVE;
}

static void vi_handshake_work(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct virtio_shmem_device *vi_dev =
		container_of(dwork, struct virtio_shmem_device, shmem_handshake_work);

	switch (virtio_shmem_be_status(vi_dev)) {
		case VIRTIO_SHMEM_BE_STATUS_ACTIVE:
			if(virtio_shmem_register_virtio_dev(vi_dev))
				put_device(&vi_dev->vdev.dev);
			break;
		case VIRTIO_SHMEM_BE_STATUS_RESET:
			if(virtio_shmem_reset_virtio_dev(vi_dev))
				put_device(&vi_dev->vdev.dev);
			break;
		default:
			virtio_shmem_unregister_virtio_dev(vi_dev, 0);
			break;
	}
	WRITE_ONCE(vi_dev->virtio_header->handshake, (vi_dev->peer_id << 16) | VIRTIO_SHMEM_HANDSHAKE_ACK);
	schedule_delayed_work(&vi_dev->shmem_handshake_work, HZ * 2);
}

static bool vi_synchronize_reg_write(struct virtio_shmem_device *vi_dev)
{
	int times = 0;
	while (READ_ONCE(vi_dev->virtio_header->write_transaction)) {
		cpu_relax();
		if(times++ > VIRTIO_SHMEM_SYNC_TIMES) {
			if (virtio_shmem_be_status(vi_dev) != VIRTIO_SHMEM_BE_STATUS_ACTIVE)
				break;
			else
				times = 0;
		}
	}
	return true;
}

static bool vi_reg_write(struct virtio_shmem_device *vi_dev, unsigned int reg,
			 u64 value, unsigned int size)
{
	u8 *reg_area = (u8 *)vi_dev->virtio_header;

	if (!vi_synchronize_reg_write(vi_dev))
		return false;

	if (size == 1)
		*(u8 *)(reg_area + reg) = (u8)value;
	else if (size == 2)
		*(u16 *)(reg_area + reg) = cpu_to_le16((u16)value);
	else if (size == 4)
		*(u32 *)(reg_area + reg) = cpu_to_le32((u32)value);
	else if (size == 8)
		*(u64 *)(reg_area + reg) = cpu_to_le64(value);
	else
		BUG();
	virt_wmb();

	vi_dev->virtio_header->write_transaction = cpu_to_le32(reg | (size << 16));
	virt_wmb();

	vi_dev->notify_peer(vi_dev, 0);
	/* delay a short time for BE to update config space */
	if (vi_dev->vdev.id.device == VIRTIO_ID_INPUT &&
		hypervisor_is_type(X86_HYPER_QNX)) {
		mdelay(1);
	}
	return true;
}

static bool vi_reg_write8(struct virtio_shmem_device *vi_dev,
			   unsigned int reg, u32 value)
{
	return vi_reg_write(vi_dev, reg, value, 1);
}

static bool vi_reg_write16(struct virtio_shmem_device *vi_dev,
			   unsigned int reg, u32 value)
{
	return vi_reg_write(vi_dev, reg, value, 2);
}

static bool vi_reg_write32(struct virtio_shmem_device *vi_dev,
			   unsigned int reg, u32 value)
{
	return vi_reg_write(vi_dev, reg, value, 4);
}

static bool vi_reg_write64(struct virtio_shmem_device *vi_dev,
			   unsigned int reg, u64 value)
{
	bool ret = true;

	ret &= vi_reg_write(vi_dev, reg, (u32)value, 4);
	ret &= vi_reg_write(vi_dev, reg + 4, (value >> 32), 4);

	return ret;
}

static void vi_get(struct virtio_device *vdev, unsigned int offset,
		   void *buf, unsigned int len)
{
	struct virtio_shmem_device *vi_dev = to_virtio_shmem_device(vdev);
	__le16 w;
	__le32 l;
	__le64 q;

	switch (len) {
	case 1:
		*(u8 *)buf = *(u8 *)(vi_dev->virtio_header->config + offset);
		break;
	case 2:
		w = *(u16 *)(vi_dev->virtio_header->config + offset);
		*(u16 *)buf = le16_to_cpu(w);
		break;
	case 4:
		l = *(u32 *)(vi_dev->virtio_header->config + offset);
		*(u32 *)buf = le32_to_cpu(l);
		break;
	case 8:
		q = *(u64 *)(vi_dev->virtio_header->config + offset);
		*(u64 *)buf = le64_to_cpu(q);
		break;
	default:
		BUG();
	}
}

static void vi_set(struct virtio_device *vdev, unsigned int offset,
		   const void *buf, unsigned int len)
{
	u64 value;

	switch (len) {
	case 1:
		value = *(u8 *)buf;
		break;
	case 2:
		value = *(u16 *)buf;
		break;
	case 4:
		value = *(u32 *)buf;
		break;
	case 8:
		value = *(u64 *)buf;
		break;
	default:
		BUG();
	}
	vi_reg_write(to_virtio_shmem_device(vdev),
		     offsetof(struct virtio_shmem_header, config) + offset,
		     value, len);
}

static u32 vi_generation(struct virtio_device *vdev)
{
	struct virtio_shmem_device *vi_dev = to_virtio_shmem_device(vdev);
	u32 gen  = READ_ONCE(vi_dev->virtio_header->common_config.config_generation);

	while (gen & 1) {
		cpu_relax();

		gen = READ_ONCE(vi_dev->virtio_header->common_config.config_generation);
	}
	return gen;
}

static u8 vi_get_status(struct virtio_device *vdev)
{
	struct virtio_shmem_device *vi_dev = to_virtio_shmem_device(vdev);

	return vi_dev->virtio_header->common_config.device_status;
}

static void vi_set_status(struct virtio_device *vdev, u8 status)
{
	struct virtio_shmem_device *vi_dev = to_virtio_shmem_device(vdev);

	/* We should never be setting status to 0. */
	BUG_ON(status == 0);

	vi_reg_write8(vi_dev, VI_CFG_REG_OFFSET(device_status), status);
}

static void vi_reset(struct virtio_device *vdev)
{
	struct virtio_shmem_device *vi_dev = to_virtio_shmem_device(vdev);

	/* 0 status means a reset. */
	vi_reg_write8(vi_dev, VI_CFG_REG_OFFSET(device_status), 0);
}

static u64 vi_get_features(struct virtio_device *vdev)
{
	struct virtio_shmem_device *vi_dev = to_virtio_shmem_device(vdev);
	u64 features;

	if (!vi_reg_write32(vi_dev, VI_CFG_REG_OFFSET(device_feature_select), 1) ||
	    !vi_synchronize_reg_write(vi_dev))
		return 0;
	features = le32_to_cpu(vi_dev->virtio_header->common_config.device_feature);
	features <<= 32;

	if (!vi_reg_write32(vi_dev, VI_CFG_REG_OFFSET(device_feature_select), 0) ||
	    !vi_synchronize_reg_write(vi_dev))
		return 0;
	features |= le32_to_cpu(vi_dev->virtio_header->common_config.device_feature);

	return features;
}

static int vi_finalize_features(struct virtio_device *vdev)
{
	struct virtio_shmem_device *vi_dev = to_virtio_shmem_device(vdev);

	/* Give virtio_ring a chance to accept features. */
	vring_transport_features(vdev);

	if (!__virtio_test_bit(vdev, VIRTIO_F_VERSION_1)) {
		dev_err(&vdev->dev,
			"virtio: device does not have VIRTIO_F_VERSION_1\n");
		return -EINVAL;
	}

	if (!vi_reg_write32(vi_dev, VI_CFG_REG_OFFSET(guest_feature_select), 1) ||
	    !vi_reg_write32(vi_dev, VI_CFG_REG_OFFSET(guest_feature),
			    (u32)(vdev->features >> 32)))
		return -ENODEV;

	if (!vi_reg_write32(vi_dev, VI_CFG_REG_OFFSET(guest_feature_select), 0) ||
	    !vi_reg_write32(vi_dev, VI_CFG_REG_OFFSET(guest_feature),
			    (u32)vdev->features))
		return -ENODEV;

	return 0;
}

/* the notify function used when creating a virt queue */
static bool vi_notify(struct virtqueue *vq)
{
	struct virtio_shmem_vq_info *info = vq->priv;
	struct virtio_shmem_device *vi_dev =
		to_virtio_shmem_device(vq->vdev);

	virt_wmb();
	vi_dev->notify_peer(vi_dev, info->device_vector);

	return true;
}

static irqreturn_t vi_config_interrupt(int irq, void *opaque)
{
	struct virtio_shmem_device *vi_dev = opaque;

	if (unlikely(READ_ONCE(vi_dev->virtio_header->config_event) & 1)) {
		vi_dev->virtio_header->config_event = 0;
		virt_wmb();
		virtio_config_changed(&vi_dev->vdev);
		return IRQ_HANDLED;
	}

	return IRQ_NONE;
}

static irqreturn_t vi_queues_interrupt(int irq, void *opaque)
{
	struct virtio_shmem_device *vi_dev = opaque;
	struct virtio_shmem_vq_info *info;
	irqreturn_t ret = IRQ_NONE;

	if (likely(READ_ONCE(vi_dev->virtio_header->queue_event) & 1)) {
		vi_dev->virtio_header->queue_event = 0;
		virt_wmb();
		spin_lock(&vi_dev->virtqueues_lock);
		list_for_each_entry(info, &vi_dev->virtqueues, node)
			ret |= vring_interrupt(irq, info->vq);
		spin_unlock(&vi_dev->virtqueues_lock);
	}

	return ret;
}

static irqreturn_t vi_interrupt(int irq, void *opaque)
{
	struct virtio_shmem_device *vi_dev = opaque;
	irqreturn_t ret;

	ret = vi_config_interrupt(irq, opaque) | vi_queues_interrupt(irq, opaque);
	if (ret != IRQ_HANDLED && vi_dev->early_irq_handler)
		ret = vi_dev->early_irq_handler(vi_dev);

	return ret;
}

static irqreturn_t vi_event(int irq, void *opaque)
{
	struct virtio_shmem_device *vi_dev = opaque;

	if (vi_dev->virtio_removed == false) {
		kobject_uevent(&vi_dev->dev.kobj, KOBJ_UNBIND);
		vi_dev->virtio_removed = true;
	}
	return IRQ_HANDLED;
}

static struct virtqueue *vi_setup_vq(struct virtio_device *vdev,
				     unsigned int index,
				     void (*callback)(struct virtqueue *vq),
				     const char *name,
				     bool ctx,
				     unsigned int irq_vector)
{
	struct virtio_shmem_device *vi_dev = to_virtio_shmem_device(vdev);
	struct virtio_shmem_vq_info *info;
	struct virtqueue *vq;
	unsigned long flags;
	unsigned int size;
	int irq, err;

	/* Select the queue we're interested in */
	if (!vi_reg_write16(vi_dev, VI_CFG_REG_OFFSET(queue_select), index) ||
	    !vi_synchronize_reg_write(vi_dev))
		return ERR_PTR(-ENODEV);

	/* Queue shouldn't already be set up. */
	if (vi_dev->virtio_header->common_config.queue_enable)
		return ERR_PTR(-ENOENT);

	/* Allocate and fill out our active queue description */
	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return ERR_PTR(-ENOMEM);

	size = vi_dev->virtio_header->common_config.queue_size;
	if (size == 0) {
		err = -ENOENT;
		goto error_new_virtqueue;
	}

	info->device_vector = 0;
	info->driver_vector = irq_vector;

	/* Create the vring */
	vq = vring_create_virtqueue(index, size, SMP_CACHE_BYTES, vdev, true,
				    true, ctx, vi_notify, callback, name);
	if (!vq) {
		err = -ENOMEM;
		goto error_new_virtqueue;
	}

	if (callback && vi_dev->per_vq_vector) {
		irq = pci_irq_vector(vi_dev->pci_dev, info->driver_vector);
		info->irq_name = kasprintf(GFP_KERNEL, "%s-%s",
					   dev_name(&vdev->dev), name);
		if (!info->irq_name) {
			err = -ENOMEM;
			goto error_setup_virtqueue;
		}

		err = request_irq(irq, vring_interrupt, 0, info->irq_name, vq);
		if (err)
			goto error_setup_virtqueue;
	}

	/* Activate the queue */
	if (!vi_reg_write16(vi_dev, VI_CFG_REG_OFFSET(queue_size),
			    virtqueue_get_vring_size(vq)) ||
	    !vi_reg_write16(vi_dev, VI_CFG_REG_OFFSET(queue_msix_vector),
			    info->driver_vector) ||
	    !vi_reg_write64(vi_dev, VI_CFG_REG_OFFSET(queue_desc_lo),
			    virtqueue_get_desc_addr(vq)) ||
	    !vi_reg_write64(vi_dev, VI_CFG_REG_OFFSET(queue_avail_lo),
			    virtqueue_get_avail_addr(vq)) ||
	    !vi_reg_write64(vi_dev, VI_CFG_REG_OFFSET(queue_used_lo),
			    virtqueue_get_used_addr(vq)) ||
	    !vi_reg_write16(vi_dev, VI_CFG_REG_OFFSET(queue_enable), 1)) {
		err = -ENODEV;
		goto error_setup_virtqueue;
	}

	vq->priv = info;
	info->vq = vq;

	spin_lock_irqsave(&vi_dev->virtqueues_lock, flags);
	list_add(&info->node, &vi_dev->virtqueues);
	spin_unlock_irqrestore(&vi_dev->virtqueues_lock, flags);

	return vq;

error_setup_virtqueue:
	vring_del_virtqueue(vq);

error_new_virtqueue:
	vi_reg_write16(vi_dev, VI_CFG_REG_OFFSET(queue_enable), 0);
	kfree(info);
	return ERR_PTR(err);
}

static void vi_del_vq(struct virtqueue *vq)
{
	struct virtio_shmem_device *vi_dev =
		to_virtio_shmem_device(vq->vdev);
	struct virtio_shmem_vq_info *info = vq->priv;
	unsigned long flags;

	spin_lock_irqsave(&vi_dev->virtqueues_lock, flags);
	list_del(&info->node);
	spin_unlock_irqrestore(&vi_dev->virtqueues_lock, flags);

	/* Select and deactivate the queue */
	vi_reg_write16(vi_dev, VI_CFG_REG_OFFSET(queue_select), vq->index);
	vi_reg_write16(vi_dev, VI_CFG_REG_OFFSET(queue_enable), 0);

	vring_del_virtqueue(vq);

	if (info->driver_vector) {
		free_irq(pci_irq_vector(vi_dev->pci_dev, info->driver_vector),
			 vq);
		kfree(info->irq_name);
	}

	kfree(info);
}

static void vi_del_vqs(struct virtio_device *vdev)
{
	struct virtio_shmem_device *vi_dev = to_virtio_shmem_device(vdev);
	struct virtqueue *vq, *n;

	list_for_each_entry_safe(vq, n, &vdev->vqs, list)
		vi_del_vq(vq);

	free_irq(pci_irq_vector(vi_dev->pci_dev, 0), vi_dev);
	if (!vi_dev->per_vq_vector && vi_dev->num_vectors > 1)
		free_irq(pci_irq_vector(vi_dev->pci_dev, 1), vi_dev);
	free_irq(pci_irq_vector(vi_dev->pci_dev, READ_ONCE(vi_dev->virtio_header->max_vector) -1), vi_dev);
	pci_free_irq_vectors(vi_dev->pci_dev);

	kfree(vi_dev->config_irq_name);
	vi_dev->config_irq_name = NULL;
	kfree(vi_dev->queues_irq_name);
	vi_dev->queues_irq_name = NULL;
	kfree(vi_dev->event_irq_name);
	vi_dev->event_irq_name = NULL;
}

static int vi_find_vqs(struct virtio_device *vdev, unsigned int nvqs,
		       struct virtqueue *vqs[],
		       vq_callback_t *callbacks[],
		       const char * const names[],
		       const bool *ctx,
		       struct irq_affinity *desc)
{
	struct virtio_shmem_device *vi_dev = to_virtio_shmem_device(vdev);
	unsigned int vq_vector, desired_vectors;
	int err, vectors, i, queue_idx = 0;

	desired_vectors = 2; /* one for config events, one for event */
	for (i = 0; i < nvqs; i++)
		if (callbacks[i])
			desired_vectors++;

	vectors = pci_alloc_irq_vectors(vi_dev->pci_dev, desired_vectors,
					desired_vectors, PCI_IRQ_MSIX);
	if (vectors != desired_vectors) {
		vectors = pci_alloc_irq_vectors(vi_dev->pci_dev, 1, 2,
						PCI_IRQ_LEGACY | PCI_IRQ_MSIX);
		if (vectors < 0)
			return vectors;
	}

	vi_dev->num_vectors = vectors;
	vi_dev->per_vq_vector = vectors == desired_vectors;

	if (vectors == 1) {
		vq_vector = 0;
		err = request_irq(pci_irq_vector(vi_dev->pci_dev, 0),
				  vi_interrupt, IRQF_SHARED,
				  dev_name(&vdev->dev), vi_dev);
		if (err)
			goto error_common_irq;
	} else {
		vq_vector = 1;
		vi_dev->config_irq_name = kasprintf(GFP_KERNEL, "%s-config",
						    dev_name(&vdev->dev));
		if (!vi_dev->config_irq_name) {
			err = -ENOMEM;
			goto error_common_irq;
		}

		err = request_irq(pci_irq_vector(vi_dev->pci_dev, 0),
				  vi_config_interrupt, 0,
				  vi_dev->config_irq_name, vi_dev);
		if (err)
			goto error_common_irq;
	}

	if (!vi_dev->per_vq_vector && vectors > 1) {
		vi_dev->queues_irq_name = kasprintf(GFP_KERNEL, "%s-virtqueues",
						    dev_name(&vdev->dev));
		if (!vi_dev->queues_irq_name) {
			err = -ENOMEM;
			goto error_queues_irq;
		}

		err = request_irq(pci_irq_vector(vi_dev->pci_dev, 1),
				  vi_queues_interrupt, 0,
				  vi_dev->queues_irq_name, vi_dev);
		if (err)
			goto error_queues_irq;
	}

	for (i = 0; i < nvqs; ++i) {
		if (!names[i]) {
			vqs[i] = NULL;
			continue;
		}

		vqs[i] = vi_setup_vq(vdev, queue_idx++, callbacks[i], names[i],
				     ctx ? ctx[i] : false, vq_vector);
		if (IS_ERR(vqs[i])) {
			vi_del_vqs(vdev);
			return PTR_ERR(vqs[i]);
		}

		if (vi_dev->per_vq_vector)
			vq_vector++;
	}

	WRITE_ONCE(vi_dev->virtio_header->max_vector, vectors);
	vi_dev->event_irq_name = kasprintf(GFP_KERNEL, "%s-event",
						dev_name(&vdev->dev));
	if (!vi_dev->event_irq_name) {
		err = -ENOMEM;
		goto error_event_irq;
	}
	err = request_irq(pci_irq_vector(vi_dev->pci_dev, desired_vectors - 1),
				vi_event, 0,
				vi_dev->event_irq_name, vi_dev);
	if (err)
		goto error_event_irq;

	return 0;

error_event_irq:
	free_irq(pci_irq_vector(vi_dev->pci_dev, desired_vectors - 1), vi_dev);
	kfree(vi_dev->event_irq_name);
	vi_dev->event_irq_name = NULL;
error_queues_irq:
	free_irq(pci_irq_vector(vi_dev->pci_dev, 0), vi_dev);
	kfree(vi_dev->config_irq_name);
	vi_dev->config_irq_name = NULL;

error_common_irq:
	kfree(vi_dev->queues_irq_name);
	vi_dev->queues_irq_name = NULL;
	pci_free_irq_vectors(vi_dev->pci_dev);

	return err;
}

static const char *vi_bus_name(struct virtio_device *vdev)
{
	struct virtio_shmem_device *vi_dev = to_virtio_shmem_device(vdev);

	return pci_name(vi_dev->pci_dev);
}

static const struct virtio_config_ops virtio_shmem_config_ops = {
	.get			= vi_get,
	.set			= vi_set,
	.generation		= vi_generation,
	.get_status		= vi_get_status,
	.set_status		= vi_set_status,
	.reset			= vi_reset,
	.find_vqs		= vi_find_vqs,
	.del_vqs		= vi_del_vqs,
	.get_features		= vi_get_features,
	.finalize_features	= vi_finalize_features,
	.bus_name		= vi_bus_name,
};

static void virtio_shmem_release_dev(struct device *_d)
{
	struct virtio_device *vdev = dev_to_virtio(_d);
	struct virtio_shmem_device *vi_dev = to_virtio_shmem_device(vdev);

	devm_kfree(&vi_dev->pci_dev->dev, vi_dev);
}

static struct page *dma_addr_to_page(struct virtio_shmem_device *vi_dev, dma_addr_t dma_handle)
{
	unsigned long pfn;

	if (dma_handle >= vi_dev->shmem_sz) {
		dev_warn(&vi_dev->pci_dev->dev, "DMA handle 0x%llx is out of shared memory region [0x%p, 0x%p)\n",
		     dma_handle, vi_dev->shmem, vi_dev->shmem + vi_dev->shmem_sz);
		return NULL;
	}

	pfn = PHYS_PFN(vi_dev->shmem_phys_base + dma_handle);
	return pfn_to_page(pfn);
}

static dma_addr_t page_to_dma_addr(struct virtio_shmem_device *vi_dev, struct page *page)
{
	unsigned long pfn;
	dma_addr_t dma_handle;

	pfn = page_to_pfn(page);
	dma_handle = PFN_PHYS(pfn) - vi_dev->shmem_phys_base;
	if (dma_handle >= vi_dev->shmem_sz) {
		dev_warn(&vi_dev->pci_dev->dev, "PFN 0x%lx is out of shared memory region [0x%p, 0x%p)\n",
		     pfn, vi_dev->shmem, vi_dev->shmem + vi_dev->shmem_sz);
		return 0;
	}

	return dma_handle;
}

dma_addr_t virtio_shmem_page_to_dma_addr(struct device *dev, struct page *page)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct virtio_shmem_device *vi_dev = pci_get_drvdata(pci_dev);

	return page_to_dma_addr(vi_dev, page);
}

static void *vi_dma_alloc(struct device *dev, size_t size,
			  dma_addr_t *dma_handle, gfp_t flag,
			  unsigned long attrs)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct virtio_shmem_device *vi_dev = pci_get_drvdata(pci_dev);
	int order = get_custom_order(size, vi_dev->alloc_shift);
	int chunk = -ENOMEM;
	unsigned long flags;
	void *addr;

	spin_lock_irqsave(&vi_dev->alloc_lock, flags);
	chunk = bitmap_find_free_region(vi_dev->alloc_bitmap,
					vi_dev->shmem_sz >> vi_dev->alloc_shift,
					order);
	spin_unlock_irqrestore(&vi_dev->alloc_lock, flags);

	if (chunk < 0) {
		if (!(attrs & DMA_ATTR_NO_WARN) && printk_ratelimit())
			dev_warn(dev,
				 "shared memory is full (size: %zd bytes)\n",
				 size);
		return NULL;
	}

	*dma_handle = chunk << vi_dev->alloc_shift;
	addr = vi_dev->shmem + *dma_handle;
	memset(addr, 0, size);

#ifdef CONFIG_VIRTIO_IVSHMEM_DEBUG
	vi_dev->shmem_sz_used += size;
	if (vi_dev->shmem_sz_used > vi_dev->shmem_sz_max_used)
		vi_dev->shmem_sz_max_used = vi_dev->shmem_sz_used;
	vi_dev->dma_alloc_cnt++;
#endif
	return addr;
}

static void vi_dma_free(struct device *dev, size_t size, void *vaddr,
			dma_addr_t dma_handle, unsigned long attrs)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct virtio_shmem_device *vi_dev = pci_get_drvdata(pci_dev);
	int order = get_custom_order(size, vi_dev->alloc_shift);
	int chunk = (int)(dma_handle >> vi_dev->alloc_shift);
	unsigned long flags;

	spin_lock_irqsave(&vi_dev->alloc_lock, flags);
	bitmap_release_region(vi_dev->alloc_bitmap, chunk, order);
	spin_unlock_irqrestore(&vi_dev->alloc_lock, flags);

#ifdef CONFIG_VIRTIO_IVSHMEM_DEBUG
	vi_dev->shmem_sz_used -= size;
#endif
}

static dma_addr_t vi_dma_map_page(struct device *dev, struct page *page,
				  unsigned long offset, size_t size,
				  enum dma_data_direction dir,
				  unsigned long attrs)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct virtio_shmem_device *vi_dev = pci_get_drvdata(pci_dev);
	void *buffer, *orig_addr;
	dma_addr_t dma_addr;

	buffer = vi_dma_alloc(dev, size, &dma_addr, 0, attrs);
	if (!buffer)
		return DMA_MAPPING_ERROR;

	orig_addr = page_address(page) + offset;
	vi_dev->map_src_addr[dma_addr >> vi_dev->alloc_shift] = orig_addr;

	if (!(attrs & DMA_ATTR_SKIP_CPU_SYNC) &&
	    (dir == DMA_TO_DEVICE || dir == DMA_BIDIRECTIONAL))
		memcpy(buffer, orig_addr, size);

#ifdef CONFIG_VIRTIO_IVSHMEM_DEBUG
	vi_dev->dma_map_cnt++;
#endif
	return dma_addr;
}

static void vi_dma_unmap_page(struct device *dev, dma_addr_t dma_addr,
			      size_t size, enum dma_data_direction dir,
			      unsigned long attrs)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct virtio_shmem_device *vi_dev = pci_get_drvdata(pci_dev);
	void *orig_addr = vi_dev->map_src_addr[dma_addr >> vi_dev->alloc_shift];
	void *buffer = vi_dev->shmem + dma_addr;

	if (!(attrs & DMA_ATTR_SKIP_CPU_SYNC) &&
		((dir == DMA_FROM_DEVICE) || (dir == DMA_BIDIRECTIONAL)))
		memcpy(orig_addr, buffer, size);

	vi_dma_free(dev, size, buffer, dma_addr, attrs);
}

static int vi_dma_map_sg(struct device *dev, struct scatterlist *sg, int nents,
			 enum dma_data_direction dir, unsigned long attrs)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct virtio_shmem_device *vi_dev = pci_get_drvdata(pci_dev);
	struct scatterlist *s;
	int i;

	for_each_sg(sg, s, nents, i) {
		sg_dma_address(s) = page_to_dma_addr(vi_dev, sg_page(s));
		sg_dma_len(s) = s->length;
		dev_dbg(dev, "Map page with PFN 0x%lx (size 0x%x) to dma_handle 0x%llx\n",
			 page_to_pfn(sg_page(s)), sg_dma_len(s), sg_dma_address(s));
	}

#ifdef CONFIG_VIRTIO_IVSHMEM_DEBUG
	vi_dev->dma_map_sg_cnt++;
#endif
	return nents;
}

static void vi_dma_unmap_sg(struct device *dev, struct scatterlist *sg, int nents,
			    enum dma_data_direction dir, unsigned long attrs)
{
	/* no op */
}

static void
vi_dma_sync_single_for_cpu(struct device *dev, dma_addr_t dma_addr,
			   size_t size, enum dma_data_direction dir)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct virtio_shmem_device *vi_dev = pci_get_drvdata(pci_dev);
	void *orig_addr = vi_dev->map_src_addr[dma_addr >> vi_dev->alloc_shift];
	void *buffer = vi_dev->shmem + dma_addr;

	memcpy(orig_addr, buffer, size);
}

static void
vi_dma_sync_single_for_device(struct device *dev, dma_addr_t dma_addr,
			      size_t size, enum dma_data_direction dir)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct virtio_shmem_device *vi_dev = pci_get_drvdata(pci_dev);
	void *orig_addr = vi_dev->map_src_addr[dma_addr >> vi_dev->alloc_shift];
	void *buffer = vi_dev->shmem + dma_addr;

	memcpy(buffer, orig_addr, size);
}

static const struct dma_map_ops virtio_shmem_dma_ops = {
	.alloc = vi_dma_alloc,
	.free = vi_dma_free,
	.map_page = vi_dma_map_page,
	.unmap_page = vi_dma_unmap_page,
	.map_sg = vi_dma_map_sg,
	.unmap_sg = vi_dma_unmap_sg,
	.sync_single_for_cpu = vi_dma_sync_single_for_cpu,
	.sync_single_for_device = vi_dma_sync_single_for_device,
};

struct page *virtio_shmem_allocate_page(struct device *dev)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct virtio_shmem_device *vi_dev = pci_get_drvdata(pci_dev);
	void *addr;
	dma_addr_t dma_handle;
	struct page *page;

	addr = vi_dma_alloc(dev, PAGE_SIZE, &dma_handle, 0, 0);
	if (!addr)
		return ERR_PTR(-ENOMEM);

	page = dma_addr_to_page(vi_dev, dma_handle);
	if (!page)
		return ERR_PTR(-EINVAL);

	return page;
}

void virtio_shmem_free_page(struct device *dev, struct page *page)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct virtio_shmem_device *vi_dev = pci_get_drvdata(pci_dev);
	void *addr;
	dma_addr_t dma_handle;

	dma_handle = page_to_dma_addr(vi_dev, page);
	addr = vi_dev->shmem + dma_handle;

	vi_dma_free(dev, PAGE_SIZE, addr, dma_handle, 0);
}

void *virtio_shmem_alloc(struct device *dev, size_t size)
{
	void *addr;
	dma_addr_t dma_handle;

	addr = vi_dma_alloc(dev, size, &dma_handle, 0, 0);
	if (!addr)
		return ERR_PTR(-ENOMEM);

	return addr;
}

void virtio_shmem_free(struct device *dev, void *addr, size_t size)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct virtio_shmem_device *vi_dev = pci_get_drvdata(pci_dev);
	dma_addr_t dma_handle;

	dma_handle = addr - vi_dev->shmem;
	vi_dma_free(dev, size, addr, dma_handle, 0);
}

#ifdef CONFIG_VIRTIO_IVSHMEM_DEBUG
static ssize_t perf_stat_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct pci_dev *pci_dev = container_of(dev, struct pci_dev, dev);
	struct virtio_shmem_device *vi_dev = pci_get_drvdata(pci_dev);

	return sprintf(buf, "max used: %lld, total: %lld, alloc: %lld, map: %lld, mag sg: %lld\n",
			vi_dev->shmem_sz_max_used, vi_dev->shmem_sz,
			vi_dev->dma_alloc_cnt - vi_dev->dma_map_cnt,
			vi_dev->dma_map_cnt, vi_dev->dma_map_sg_cnt);
}
static DEVICE_ATTR_RO(perf_stat);
#endif

static void virtio_shmem_region_page_free(struct page *page)
{
	/* No op here. Only to suppress the warning in free_zone_device_page(). */
}

static const struct dev_pagemap_ops virtio_shmem_region_pgmap_ops = {
	.page_free		= virtio_shmem_region_page_free,
};

static void virtio_shmem_device_release(struct device *dev)
{
	(void)dev;
}

static int
vi_register_virtio_dev(struct virtio_shmem_device *vi_dev)
{
	int ret, bitmap_size;

	if (vi_dev->virtio_header->revision < 1 || vi_dev->virtio_header->vendor_id != PCI_VENDOR_ID_REDHAT_QUMRANET) {
		dev_err(&vi_dev->pci_dev->dev, "virtio-shmem virtio invalid vendor id 0x%x, version %d\n",
			vi_dev->virtio_header->vendor_id, vi_dev->virtio_header->revision);
		return -EINVAL;
	}

	vi_dev->vdev.dev.parent = &vi_dev->pci_dev->dev;
	vi_dev->vdev.dev.release = virtio_shmem_release_dev;
	vi_dev->vdev.config = &virtio_shmem_config_ops;
	vi_dev->vdev.id.device = vi_dev->virtio_header->device_id;
	vi_dev->vdev.id.vendor = vi_dev->virtio_header->vendor_id;
	if (vi_dev->virtio_header->backend_flags == 0) {
		dev_err(&vi_dev->pci_dev->dev, "backend is not present\n");
		return -EINVAL;
	}
	vi_dev->peer_id = vi_dev->virtio_header->backend_id;
	vi_dev->virtio_header->frontend_status = (vi_dev->this_id << 16) | FRONTEND_FLAG_PRESENT;

	vi_dev->vdev.id.device = vi_dev->virtio_header->device_id;
	vi_dev->vdev.id.vendor = vi_dev->virtio_header->vendor_id;
	vi_dev->backend_rand = (vi_dev->virtio_header->handshake & 0xffff0000) >> 16;


	/* mark the header chunks used */
	bitmap_size = BITS_TO_LONGS(vi_dev->shmem_sz >> vi_dev->alloc_shift) * sizeof(long);
	memset(vi_dev->alloc_bitmap, 1, bitmap_size);
	bitmap_set(vi_dev->alloc_bitmap, 0,
		1 << get_custom_order(vi_dev->virtio_header->size,
				vi_dev->alloc_shift));
	ret = register_virtio_device(&vi_dev->vdev);
	if (!ret) {
		vi_dev->virtio_registered = true;
	}
	kobject_uevent(&vi_dev->dev.kobj, KOBJ_BIND);
	vi_dev->virtio_removed = false;
	return ret;
}

static void
vi_unregister_virtio_dev(struct virtio_shmem_device *vi_dev)
{
	unregister_virtio_device(&vi_dev->vdev);
	memset(&vi_dev->vdev, 0, sizeof(struct virtio_device));
	vi_dev->virtio_registered = false;
}

static int virtio_shmem_register_virtio_dev(struct virtio_shmem_device *vi_dev)
{
	if (vi_dev->virtio_registered == false) {
		return vi_register_virtio_dev(vi_dev);
	}
	return 0;
}

static void virtio_shmem_unregister_virtio_dev(struct virtio_shmem_device *vi_dev, int force)
{
	if (vi_dev->virtio_registered == true) {
		if (vi_dev->virtio_removed == false) {
			kobject_uevent(&vi_dev->dev.kobj, KOBJ_UNBIND);
			vi_dev->virtio_removed = true;
		}
		dev_dbg(&vi_dev->pci_dev->dev, "virtio shmem unregister virtio device\n");
		if (vi_dev->auto_unregister == true || force == 1)
			vi_unregister_virtio_dev(vi_dev);
	}
}

static int virtio_shmem_reset_virtio_dev(struct virtio_shmem_device *vi_dev)
{
	dev_dbg(&vi_dev->pci_dev->dev, "virtio shmem reset virtio device\n");
	if (vi_dev->virtio_removed == false) {
		kobject_uevent(&vi_dev->dev.kobj, KOBJ_UNBIND);
		vi_dev->virtio_removed = true;
	}
	if (vi_dev->virtio_registered == false || vi_dev->auto_unregister == true) {
		return 0;		
	}
	virtio_shmem_unregister_virtio_dev(vi_dev, 0);
	return virtio_shmem_register_virtio_dev(vi_dev);
}

static long virtio_shmem_ioctl(struct file *filp, unsigned int cmd,
			   unsigned long arg)
{
	int ret = 0;
	int data;
	struct virtio_shmem_user *user = filp->private_data;
	struct virtio_shmem_device *vi_dev = user->vi_dev;

	switch (cmd) {
		case VIRTIO_SHMEM_IOCTL_AUTO_REMOVE:
			if (copy_from_user(&data, (void __user *)arg, sizeof(data))) {
				ret = -EFAULT;
			} else {
				vi_dev->auto_unregister = data;
			}
			break;
		
		case VIRTIO_SHMEM_IOCTL_UNREGISTER:
			virtio_shmem_unregister_virtio_dev(vi_dev, 1);
			break;

		default:
			ret = -ENOTTY;
			break;
	}
	return ret;
}

static int virtio_ivshmem_open(struct inode *inode, struct file *filep)
{
	int err = 0;
	struct virtio_shmem_device *vi_dev;
	struct virtio_shmem_user *user;

	mutex_lock(&minor_lock);
	vi_dev = idr_find(&virtio_shmem_idr, iminor(inode));
	mutex_unlock(&minor_lock);
	if (!vi_dev) {
		err = -ENODEV;
		goto out;
	}

	get_device(&vi_dev->dev);

	if (!try_module_get(vi_dev->owner)) {
		err = -ENODEV;
		goto out_put_device;
	}

	user = kmalloc(sizeof(*user), GFP_KERNEL);
	if (!user) {
		err = -ENOMEM;
		goto out_put_module;
	}

	user->vi_dev = vi_dev;
	filep->private_data = user;

	return 0;

out_put_module:
	module_put(vi_dev->owner);
out_put_device:
	put_device(&vi_dev->dev);
out:
	return err;
}

static int virtio_ivshmem_release(struct inode *inode, struct file *filep)
{
	int err = 0;
	struct virtio_shmem_user *user = filep->private_data;
	struct virtio_shmem_device *vi_dev = user->vi_dev;

	kfree(user);
	module_put(vi_dev->owner);
	put_device(&vi_dev->dev);

	return err;
}

static const struct file_operations virtio_ivshmem_fops = {
	.owner		= THIS_MODULE,
	.open		= virtio_ivshmem_open,
	.release	= virtio_ivshmem_release,
	.unlocked_ioctl = virtio_shmem_ioctl,
};

int virtio_shmem_probe(struct virtio_shmem_device *vi_dev)
{
	unsigned int chunks, chunk_size, bitmap_size;
	struct pci_dev *pci_dev;
	struct dev_pagemap *pgmap;
	int ret = 0;

	pci_dev = vi_dev->pci_dev;

	spin_lock_init(&vi_dev->virtqueues_lock);
	INIT_LIST_HEAD(&vi_dev->virtqueues);

	pgmap = devm_kzalloc(&pci_dev->dev, sizeof(*pgmap), GFP_KERNEL);
	if (!pgmap)
		return -ENOMEM;

	pgmap->type = MEMORY_DEVICE_FS_DAX;

	pgmap->range = (struct range) {
		.start = (phys_addr_t) vi_dev->shmem_phys_base,
		.end = (phys_addr_t) vi_dev->shmem_phys_base + vi_dev->shmem_sz - 1,
	};
	pgmap->nr_range = 1;
	pgmap->ops = &virtio_shmem_region_pgmap_ops;

	vi_dev->shmem = devm_memremap_pages(&pci_dev->dev, pgmap);
	if (!vi_dev->shmem)
		return -ENOMEM;

	vi_dev->virtio_header = vi_dev->shmem;
	vi_dev->virtio_header->handshake = (vi_dev->this_id << 16) | VIRTIO_SHMEM_HANDSHAKE_ACK;

	spin_lock_init(&vi_dev->alloc_lock);

	chunk_size = vi_dev->shmem_sz / VIRTIO_SHMEM_PREFERRED_ALLOC_CHUNKS;
	if (chunk_size < SMP_CACHE_BYTES)
		chunk_size = SMP_CACHE_BYTES;
	if (chunk_size > PAGE_SIZE)
		chunk_size = PAGE_SIZE;
	vi_dev->alloc_shift = get_custom_order(chunk_size, 0);

	chunks = vi_dev->shmem_sz >> vi_dev->alloc_shift;
	bitmap_size = BITS_TO_LONGS(chunks) * sizeof(long);
	vi_dev->alloc_bitmap = devm_kzalloc(&pci_dev->dev,
					    bitmap_size,
					    GFP_KERNEL);
	if (!vi_dev->alloc_bitmap)
		return -ENOMEM;

	vi_dev->map_src_addr = devm_kzalloc(&pci_dev->dev,
					    chunks * sizeof(void *),
					    GFP_KERNEL);
	if (!vi_dev->map_src_addr)
		return -ENOMEM;

	set_dma_ops(&pci_dev->dev, &virtio_shmem_dma_ops);

	vi_dev->auto_unregister = 1;

	// /dev/virtio_shmemX
	vi_dev->owner = THIS_MODULE;
	mutex_lock(&minor_lock);
	vi_dev->minor = idr_alloc(&virtio_shmem_idr, vi_dev, 0, VIRTIO_SHMEM_MAX_DEVICES, GFP_KERNEL);
	mutex_unlock(&minor_lock);
	device_initialize(&vi_dev->dev);
	vi_dev->dev.devt = MKDEV(virtio_shmem_major, vi_dev->minor);
	vi_dev->dev.parent = &vi_dev->pci_dev->dev;
	vi_dev->dev.class = &virtio_ivshmem_class;
	vi_dev->dev.release = virtio_shmem_device_release;
	dev_set_drvdata(&vi_dev->dev, vi_dev);
	
	ret = dev_set_name(&vi_dev->dev, "virtio_shmem%d", vi_dev->minor);
	if (ret)
		goto err_device_create;

	ret = device_add(&vi_dev->dev);
	if (ret)
		goto err_device_create;

	INIT_DELAYED_WORK(&vi_dev->shmem_handshake_work, vi_handshake_work);
	schedule_delayed_work(&vi_dev->shmem_handshake_work, 2 * HZ);
	if (virtio_shmem_be_status(vi_dev) == VIRTIO_SHMEM_BE_STATUS_ACTIVE) {
		 if(virtio_shmem_register_virtio_dev(vi_dev)) {
			put_device(&vi_dev->vdev.dev);
			return -EINVAL;
		 }
	}

	return 0;
err_device_create:
	unregister_virtio_device(&vi_dev->vdev);
	vi_dev->virtio_registered = false;
	vi_dev->backend_rand = 0;

	mutex_lock(&minor_lock);
	idr_remove(&virtio_shmem_idr, vi_dev->minor);
	mutex_unlock(&minor_lock);

	put_device(&vi_dev->dev);
	return ret;
}

void virtio_shmem_remove(struct virtio_shmem_device *vi_dev)
{
	mutex_lock(&minor_lock);
	idr_remove(&virtio_shmem_idr, vi_dev->minor);
	mutex_unlock(&minor_lock);
	device_del(&vi_dev->dev);

	virtio_shmem_unregister_virtio_dev(vi_dev, 1);
}

static int __init virito_shmem_init(void)
{
	struct cdev *cdev = NULL;
	dev_t virtio_shmem_dev = 0;
	int result;

	result = alloc_chrdev_region(&virtio_shmem_dev, 0, VIRTIO_SHMEM_MAX_DEVICES, VIRTIO_SHMEM_NAME);
	if (result)
		return result;

	result = -ENOMEM;
	cdev = cdev_alloc();
	if (!cdev)
		goto err_cdev_alloc;

	cdev->owner = THIS_MODULE;
	cdev->ops = &virtio_ivshmem_fops;
	kobject_set_name(&cdev->kobj, "%s", VIRTIO_SHMEM_NAME);

	result = cdev_add(cdev, virtio_shmem_dev, VIRTIO_SHMEM_MAX_DEVICES);
	if (result)
		goto err_cdev_add;

	virtio_shmem_major = MAJOR(virtio_shmem_dev);
	virtio_shmem_cdev = cdev;

	result = class_register(&virtio_ivshmem_class);
	if (result) {
		goto err_class_register;
	}

	return 0;
err_class_register:
	class_unregister(&virtio_ivshmem_class);
err_cdev_add:
	kobject_put(&cdev->kobj);
	cdev_del(cdev);
err_cdev_alloc:
	unregister_chrdev_region(virtio_shmem_dev, VIRTIO_SHMEM_MAX_DEVICES);
	return result;

}

static void __exit virtio_ivshmem_exit(void)
{
	class_unregister(&virtio_ivshmem_class);
	unregister_chrdev_region(MKDEV(virtio_shmem_major, 0), VIRTIO_SHMEM_MAX_DEVICES);
	cdev_del(virtio_shmem_cdev);
	idr_destroy(&virtio_shmem_idr);
}

module_init(virito_shmem_init)
module_exit(virtio_ivshmem_exit)
MODULE_AUTHOR("Jan Kiszka <jan.kiszka@siemens.com>");
MODULE_DESCRIPTION("Driver for shared memory based virtio front-end devices");
MODULE_LICENSE("GPL v2");
