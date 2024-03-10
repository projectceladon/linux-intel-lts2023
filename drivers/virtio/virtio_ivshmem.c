// SPDX-License-Identifier: GPL-2.0-only
/*
 * Virtio over ivshmem front-end device driver
 *
 * Copyright (c) Siemens AG, 2019
 */

#include <linux/delay.h>
#include <linux/ivshmem.h>
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

#include "virtio_shmem.h"

#define DRV_NAME "virtio-ivshmem"
#define IVSHMEM_VENDOR_OFFSET		0x0C

struct virtio_ivshmem_data {
	struct ivshm_regs __iomem *ivshm_regs;
};

static void virtio_ivshmem_notify_peer(struct virtio_shmem_device *vi_dev, unsigned int vector)
{
	struct virtio_ivshmem_data *vi_data = vi_dev->priv;

	writel((vi_dev->peer_id << 16), &vi_data->ivshm_regs->doorbell);
}

static int virito_ivshmem_check_virtio_supports(struct pci_dev *pdev)
{
	unsigned long bar_start, bar_len;
	void __iomem *bar_addr;
	int vendor, err = -1;

	bar_start = pci_resource_start(pdev, 2);
	bar_len = pci_resource_len(pdev, 2);
	if (bar_start && bar_len) {
		if (pci_resource_flags(pdev, 2) & IORESOURCE_MEM) {
			bar_addr = pci_iomap(pdev, 2, bar_len);
			if (!bar_addr) {
				dev_err(&pdev->dev, "Could not map memory BAR #%d\n", 2);
				return -1;
			}
			vendor = readw(bar_addr + IVSHMEM_VENDOR_OFFSET);
			if (vendor == PCI_VENDOR_ID_REDHAT_QUMRANET)
				err = 0;
			pci_iounmap(pdev, bar_addr);
		}
	}
	return err;
}

static int virtio_ivshmem_probe(struct pci_dev *pci_dev,
				const struct pci_device_id *pci_id)
{
	struct virtio_shmem_device *vi_dev;
	struct virtio_ivshmem_data *vi_data;
	phys_addr_t section_addr;
	resource_size_t section_sz;
	int ret;

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

	vi_data->ivshm_regs = pcim_iomap_table(pci_dev)[0];

	vi_dev->this_id = readl(&vi_data->ivshm_regs->ivpos);

	ret = virito_ivshmem_check_virtio_supports(pci_dev);
	if (ret != 0) {
		dev_err(&pci_dev->dev, "not a virtio device\n");
		goto err_enable;
	}

	section_sz = pci_resource_len(pci_dev, 2);
	if (section_sz == 0) {
		dev_err(&pci_dev->dev, "missing shared memory\n");
		ret = -EINVAL;
		goto err_enable;
	}
	section_addr = pci_resource_start(pci_dev, 2);

	if (!devm_request_mem_region(&pci_dev->dev, section_addr, section_sz, DRV_NAME)) {
		ret = -EBUSY;
		goto err_enable;
	}

	vi_dev->shmem_phys_base = section_addr;
	vi_dev->shmem_sz = section_sz;
	vi_dev->notify_peer = virtio_ivshmem_notify_peer;
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
	vi_dev->shmem_sz_used = (vi_dev->virtio_header->size + (chunk_size - 1))
		& ~(chunk_size - 1);
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
	{ PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, 0x1110),
	  (PCI_CLASS_OTHERS << 16) | IVSHM_PROTO_VIRTIO_FRONT, 0xffff00 },
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
MODULE_DESCRIPTION("Driver for ivshmem-based virtio over shared memory devices");
MODULE_LICENSE("GPL v2");
