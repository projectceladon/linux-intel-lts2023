// SPDX-License-Identifier: GPL-2.0-only
/*
 * Virtio over ivshmem front-end device driver
 *
 */

#include <linux/delay.h>
#include <linux/module.h>
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

#include "virtio_shmem.h"

#define DRV_NAME "virtio-guest-shm"

struct virtio_guest_shm_data {
	struct guest_shm_factory __iomem *fact;
	struct guest_shm_control *ctrl;
	unsigned int attach_list;
};

static void virtio_guest_shm_notify_peer(struct virtio_shmem_device *vi_dev, unsigned int vector)
{
	struct virtio_guest_shm_data *vi_data = vi_dev->priv;

	writel(1 << vi_dev->peer_id, &vi_data->ctrl->notify);
}

static irqreturn_t virtio_guest_shm_early_irq_handler(struct virtio_shmem_device *vi_dev)
{
	struct virtio_guest_shm_data *vi_data = vi_dev->priv;
	unsigned const attach_list = vi_data->ctrl->status >> GUEST_SHM_MAX_CLIENTS;
	unsigned const attach_list_changes = attach_list ^ vi_data->attach_list;
	unsigned int i;

	for (i = 0; i < GUEST_SHM_MAX_CLIENTS; ++i) {
		if (attach_list_changes & (1u << i))
			dev_info(&vi_dev->pci_dev->dev, "client %2u %stached", i,
				(attach_list & (1u << i)) ? "at" : "de");
	}
	vi_data->attach_list = attach_list;
	return IRQ_HANDLED;
}

static int virtio_ivshmem_probe(struct pci_dev *pci_dev,
				const struct pci_device_id *pci_id)
{
	struct virtio_shmem_device *vi_dev;
	struct virtio_guest_shm_data *vi_data;
	resource_size_t section_sz;
	phys_addr_t section_addr, paddr;
	int ret;
	unsigned long min_align;
	long idx;

	vi_dev = kzalloc(sizeof(*vi_dev), GFP_KERNEL);
	if (!vi_dev)
		return -ENOMEM;

	pci_set_drvdata(pci_dev, vi_dev);
	vi_dev->vdev.dev.parent = &pci_dev->dev;
	vi_dev->pci_dev = pci_dev;

	ret = pcim_enable_device(pci_dev);
	if (ret)
		goto err;

	ret = pcim_iomap_regions(pci_dev, BIT(0), DRV_NAME);
	if (ret)
		goto err_enable;

	pci_set_master(pci_dev);

	vi_data = devm_kzalloc(&pci_dev->dev, sizeof(*vi_data), GFP_KERNEL);
	if (!vi_data) {
		ret = -ENOMEM;
		goto err_enable;
	}

	vi_data->fact = pcim_iomap_table(pci_dev)[0];

	if (vi_data->fact->signature != GUEST_SHM_SIGNATURE) {
		dev_err(&pci_dev->dev, "Signature incorrect. %llx != %llx",
			(unsigned long long)GUEST_SHM_SIGNATURE,
			(unsigned long long)vi_data->fact->signature);
		ret = -ENXIO;
		goto err_enable;
	}

	if (vi_data->fact->status != GSS_OK) {
		dev_err(&pci_dev->dev, "creating failed: %d", vi_data->fact->status);
		ret = -vi_data->fact->status;
		goto err_enable;
	}

	ret = kstrtol(vi_data->fact->name + strlen("virtio"), 10, &idx);
	if (ret)
		goto err_enable;

	paddr = vi_data->fact->shmem;
	dev_info(&pci_dev->dev, "virtio%ld creation size %x, paddr=%llx, irq: %d", idx,
		vi_data->fact->size, (unsigned long long)paddr, vi_data->fact->vector);

	vi_data->ctrl = memremap(paddr, 0x1000, MEMREMAP_WB);
	dev_info(&pci_dev->dev, "shared memory index %u", vi_data->ctrl->idx);
	vi_dev->this_id = vi_data->ctrl->idx;

	if (IS_ENABLED(CONFIG_SPARSEMEM_VMEMMAP))
		min_align = PAGES_PER_SUBSECTION;
	else
		min_align = PAGES_PER_SECTION;
	min_align = (min_align << PAGE_SHIFT);
	section_addr = (GUEST_SHM_PADDR + (idx << 32)) + 0x1000;
	section_addr = (section_addr + (min_align - 1)) & ~(min_align - 1);
	section_sz = vi_data->fact->size * 0x1000 - ((section_addr - (GUEST_SHM_PADDR + (idx << 32))
		- 0x1000 + (min_align - 1))  & ~(min_align - 1));
	dev_info(&pci_dev->dev, "section_addr=%llx, section_sz: 0x%llx", section_addr, section_sz);

	vi_dev->shmem_phys_base = section_addr;
	vi_dev->shmem_sz = section_sz;

	vi_dev->notify_peer = virtio_guest_shm_notify_peer;
	vi_dev->early_irq_handler = virtio_guest_shm_early_irq_handler;
	vi_dev->priv = vi_data;

	ret = virtio_shmem_probe(vi_dev);
	if (ret)
		goto err_enable;

	ret = register_virtio_device(&vi_dev->vdev);
	if (ret) {
		dev_err(&pci_dev->dev, "failed to register device\n");
		put_device(&vi_dev->vdev.dev);
		goto err_enable;
	}

#ifdef CONFIG_VIRTIO_IVSHMEM_DEBUG
	vi_dev->shmem_sz_used = (vi_dev->virtio_header->size
		+ (chunk_size - 1)) & ~(chunk_size - 1);
	vi_dev->shmem_sz_max_used = vi_dev->shmem_sz_used;
	vi_dev->dma_alloc_cnt = 0;
	vi_dev->dma_map_cnt = 0;
	vi_dev->dma_map_sg_cnt = 0;

	device_create_file(&vi_dev->pci_dev->dev, &dev_attr_perf_stat);
#endif
	return 0;

err_enable:
	pci_disable_device(pci_dev);
err:
	kfree(vi_dev);
	return ret;
}

static void virtio_ivshmem_remove(struct pci_dev *pci_dev)
{
	struct virtio_shmem_device *vi_dev = pci_get_drvdata(pci_dev);
	struct device *dev = get_device(&vi_dev->vdev.dev);

	unregister_virtio_device(&vi_dev->vdev);
	pci_disable_device(pci_dev);
	put_device(dev);
	kfree(vi_dev);
}

static const struct pci_device_id virtio_ivshmem_id_table[] = {
	{ PCI_DEVICE(PCI_VID_BlackBerry_QNX, PCI_DID_QNX_GUEST_SHM) },
	{ 0 }
};

MODULE_DEVICE_TABLE(pci, virtio_ivshmem_id_table);

static struct pci_driver virtio_ivshmem_driver = {
	.name		= DRV_NAME,
	.id_table	= virtio_ivshmem_id_table,
	.probe		= virtio_ivshmem_probe,
	.remove		= virtio_ivshmem_remove,
};

module_pci_driver(virtio_ivshmem_driver);

MODULE_AUTHOR("Jan Kiszka <jan.kiszka@siemens.com>");
MODULE_AUTHOR("Fei Li <fei1.li@intel.com>");
MODULE_AUTHOR("Junjie Mao <junjie.mao@intel.com>");
MODULE_DESCRIPTION("Driver for QNX guest-shm based virtio over shared memory devices");
MODULE_LICENSE("GPL v2");
