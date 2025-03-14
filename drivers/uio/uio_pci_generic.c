// SPDX-License-Identifier: GPL-2.0
/* uio_pci_generic - generic UIO driver for PCI 2.3 devices
 *
 * Copyright (C) 2009 Red Hat, Inc.
 * Author: Michael S. Tsirkin <mst@redhat.com>
 *
 * Since the driver does not declare any device ids, you must allocate
 * id and bind the device to the driver yourself.  For example:
 *
 * # echo "8086 10f5" > /sys/bus/pci/drivers/uio_pci_generic/new_id
 * # echo -n 0000:00:19.0 > /sys/bus/pci/drivers/e1000e/unbind
 * # echo -n 0000:00:19.0 > /sys/bus/pci/drivers/uio_pci_generic/bind
 * # ls -l /sys/bus/pci/devices/0000:00:19.0/driver
 * .../0000:00:19.0/driver -> ../../../bus/pci/drivers/uio_pci_generic
 *
 * Driver won't bind to devices which do not support the Interrupt Disable Bit
 * in the command register. All devices compliant to PCI 2.3 (circa 2002) and
 * all compliant PCI Express devices should support this bit.
 */

#include <linux/device.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/uio_driver.h>
#ifdef CONFIG_PCI_MSI
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/eventfd.h>
#endif

#define DRIVER_VERSION	"0.01.0"
#define DRIVER_AUTHOR	"Michael S. Tsirkin <mst@redhat.com>"
#define DRIVER_DESC	"Generic UIO driver for PCI 2.3 devices"

#ifdef CONFIG_PCI_MSI
struct uio_eventfd_info {
	unsigned long  user;
	struct         list_head list;
	struct         eventfd_ctx *evt;
};

struct  uio_msix_vector_event {
	int               irq;
	spinlock_t        list_lock;
	struct list_head  evt_list_head;
};

struct uio_msix_info {
	struct msix_entry *entries;
	struct uio_msix_vector_event *vector_evts;
	int nvecs;
};
#endif

struct uio_pci_generic_dev {
	struct uio_info info;
	struct pci_dev *pdev;
#ifdef CONFIG_PCI_MSI
	struct uio_msix_info msix_info;
#endif
};

#ifdef CONFIG_PCI_MSI
static irqreturn_t uio_msix_handler(int irq, void *arg)
{
	struct uio_eventfd_info *evt_info;
	struct  uio_msix_vector_event *vector_evt;

	vector_evt = (struct uio_msix_vector_event *)arg;
	spin_lock(&vector_evt->list_lock);
	list_for_each_entry(evt_info, &vector_evt->evt_list_head, list) {
		eventfd_signal(evt_info->evt, 1);
	}
	spin_unlock(&vector_evt->list_lock);
	return IRQ_HANDLED;
}

static int map_msix_eventfd(struct uio_pci_generic_dev *gdev,
		unsigned long user, int fd, int vector)
{
	struct eventfd_ctx *evt;
	struct uio_eventfd_info *evt_info;
	struct  uio_msix_vector_event *vector_evt;

	/* Passing -1 is used to disable interrupt */
	if (fd < 0) {
		pci_disable_msi(gdev->pdev);
		return 0;
	}

	if (vector >= gdev->msix_info.nvecs)
		return -EINVAL;

	evt = eventfd_ctx_fdget(fd);
	if (!evt)
		return -EINVAL;

	evt_info = kzalloc(sizeof(struct uio_eventfd_info), GFP_KERNEL);
	if (!evt_info) {
		eventfd_ctx_put(evt);
		return -ENOMEM;
	}

	evt_info->evt = evt;
	evt_info->user = user;

	vector_evt = &(gdev->msix_info.vector_evts[vector]);

	spin_lock(&vector_evt->list_lock);
	list_add(&evt_info->list, &vector_evt->evt_list_head);
	spin_unlock(&vector_evt->list_lock);

	return 0;
}

static int uio_msi_ioctl(struct uio_info *info, unsigned int cmd,
		unsigned long arg, unsigned long user)
{
	struct uio_pci_generic_dev *gdev;
	struct uio_msix_data data;
	int err = -EOPNOTSUPP;

	gdev = container_of(info, struct uio_pci_generic_dev, info);

	switch (cmd) {
	case UIO_MSIX_DATA: {
		if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
			return -EFAULT;

		err = map_msix_eventfd(gdev, user, data.fd, data.vector);
		break;
	}
	default:
		pr_warn("Not support ioctl cmd: 0x%x\n", cmd);
		break;
	}

	return err;
}

static int pci_generic_init_msix(struct uio_pci_generic_dev *gdev)
{
	unsigned char *buffer;
	int i, j, irq, nvecs, ret;
	struct uio_msix_vector_event *vector_evt;

	nvecs = pci_msix_vec_count(gdev->pdev);
	if (!nvecs)
		return -EINVAL;

	buffer = devm_kzalloc(&gdev->pdev->dev, nvecs * (sizeof(struct msix_entry) +
			sizeof(struct uio_msix_vector_event)), GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	gdev->msix_info.entries = (struct msix_entry *)buffer;
	gdev->msix_info.vector_evts = (struct uio_msix_vector_event *)
		((unsigned char *)buffer + nvecs * sizeof(struct msix_entry));
	gdev->msix_info.nvecs = nvecs;

	for (i = 0; i < nvecs; ++i)
		gdev->msix_info.entries[i].entry = i;

	ret = pci_enable_msix_exact(gdev->pdev, gdev->msix_info.entries, nvecs);
	if (ret) {
		pr_err("Failed to enable UIO MSI-X, ret = %d.\n", ret);
		kfree(buffer);
		return ret;
	}

	for (i = 0; i < nvecs; ++i) {
		irq = gdev->msix_info.entries[i].vector;
		vector_evt = &gdev->msix_info.vector_evts[i];
		vector_evt->irq = irq;
		INIT_LIST_HEAD(&vector_evt->evt_list_head);
		spin_lock_init(&vector_evt->list_lock);

		ret = request_irq(irq, uio_msix_handler, 0, "UIO IRQ", vector_evt);
		if (ret) {

			for (j = 0; j < i - 1; j++) {
				free_irq(gdev->msix_info.entries[j].vector,
					&gdev->msix_info.vector_evts[j]);
			}

			kfree(buffer);
			pci_disable_msix(gdev->pdev);
			return ret;
		}
	}
	return 0;
}
#endif

static inline struct uio_pci_generic_dev *
to_uio_pci_generic_dev(struct uio_info *info)
{
	return container_of(info, struct uio_pci_generic_dev, info);
}

static int release(struct uio_info *info, struct inode *inode)
{
	struct uio_pci_generic_dev *gdev = to_uio_pci_generic_dev(info);

#ifdef CONFIG_PCI_MSI
	int i;
	struct uio_eventfd_info *evt_info, *next;
	struct uio_msix_vector_event *vector_evt;

	for (i = 0; i < gdev->msix_info.nvecs; ++i) {
		vector_evt = &gdev->msix_info.vector_evts[i];
		spin_lock(&vector_evt->list_lock);
		list_for_each_entry_safe(evt_info, next, &vector_evt->evt_list_head, list) {
			if (evt_info->user == user) {
				list_del(&evt_info->list);
				eventfd_ctx_put(evt_info->evt);
				kfree(evt_info);
			}
		}
		spin_unlock(&vector_evt->list_lock);
	}
#endif
	/*
	 * This driver is insecure when used with devices doing DMA, but some
	 * people (mis)use it with such devices.
	 * Let's at least make sure DMA isn't left enabled after the userspace
	 * driver closes the fd.
	 * Note that there's a non-zero chance doing this will wedge the device
	 * at least until reset.
	 */
	pci_clear_master(gdev->pdev);
	return 0;
}

/* Interrupt handler. Read/modify/write the command register to disable
 * the interrupt. */
static irqreturn_t irqhandler(int irq, struct uio_info *info)
{
	struct uio_pci_generic_dev *gdev = to_uio_pci_generic_dev(info);

	if (!pci_check_and_mask_intx(gdev->pdev))
		return IRQ_NONE;

	/* UIO core will signal the user process. */
	return IRQ_HANDLED;
}

static int probe(struct pci_dev *pdev,
			   const struct pci_device_id *id)
{
	struct uio_pci_generic_dev *gdev;
	struct uio_mem *uiomem;
	int err;
	int i;

	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "%s: pci_enable_device failed: %d\n",
			__func__, err);
		return err;
	}

	if (pdev->irq && !pci_intx_mask_supported(pdev))
		return -ENODEV;

	gdev = devm_kzalloc(&pdev->dev, sizeof(struct uio_pci_generic_dev), GFP_KERNEL);
	if (!gdev)
		return -ENOMEM;

	gdev->info.name = "uio_pci_generic";
	gdev->info.version = DRIVER_VERSION;
	gdev->info.release = release;
#ifdef CONFIG_PCI_MSI
	gdev->info.ioctl = uio_msi_ioctl;
#endif
	gdev->pdev = pdev;
	if (pdev->irq && (pdev->irq != IRQ_NOTCONNECTED)) {
		gdev->info.irq = pdev->irq;
		gdev->info.irq_flags = IRQF_SHARED;
		gdev->info.handler = irqhandler;
	} else {
#ifdef CONFIG_PCI_MSI
		err = pci_generic_init_msix(gdev);
		if (!err)
			dev_notice(&pdev->dev, "MSIX is enabled for UIO device.\n");
#else
		dev_warn(&pdev->dev, "No IRQ assigned to device: "
			 "no support for interrupts?\n");
#endif
	}

	uiomem = &gdev->info.mem[0];
	for (i = 0; i < MAX_UIO_MAPS; ++i) {
		struct resource *r = &pdev->resource[i];

		if (r->flags != (IORESOURCE_SIZEALIGN | IORESOURCE_MEM))
			continue;

		if (uiomem >= &gdev->info.mem[MAX_UIO_MAPS]) {
			dev_warn(
				&pdev->dev,
				"device has more than " __stringify(
					MAX_UIO_MAPS) " I/O memory resources.\n");
			break;
		}

		uiomem->memtype = UIO_MEM_PHYS;
		uiomem->addr = r->start & PAGE_MASK;
		uiomem->offs = r->start & ~PAGE_MASK;
		uiomem->size =
			(uiomem->offs + resource_size(r) + PAGE_SIZE - 1) &
			PAGE_MASK;
		uiomem->name = r->name;
		++uiomem;
	}

	while (uiomem < &gdev->info.mem[MAX_UIO_MAPS]) {
		uiomem->size = 0;
		++uiomem;
	}

	err = devm_uio_register_device(&pdev->dev, &gdev->info);
	if (err)
		return err;

#ifdef CONFIG_PCI_MSI
	pci_set_drvdata(pdev, gdev);
#endif

	return 0;
}

#ifdef CONFIG_PCI_MSI
static void remove(struct pci_dev *pdev)
{
	int i;
	struct uio_eventfd_info *evt_info, *next;
	struct uio_msix_vector_event *vector_evt;
	struct uio_pci_generic_dev *gdev = pci_get_drvdata(pdev);

	if (gdev->msix_info.entries != NULL) {
		for (i = 0; i < gdev->msix_info.nvecs; i++) {
			vector_evt = &gdev->msix_info.vector_evts[i];
			spin_lock(&vector_evt->list_lock);
			list_for_each_entry_safe(evt_info, next, &vector_evt->evt_list_head, list) {
				list_del(&evt_info->list);
				eventfd_ctx_put(evt_info->evt);
				kfree(evt_info);
			}
			spin_unlock(&vector_evt->list_lock);
			free_irq(vector_evt->irq, vector_evt);
		}
		pci_disable_msix(pdev);
		kfree(gdev->msix_info.entries);
	}
}
#endif

static struct pci_driver uio_pci_driver = {
	.name = "uio_pci_generic",
	.id_table = NULL, /* only dynamic id's */
	.probe = probe,
#ifdef CONFIG_PCI_MSI
	.remove = remove,
#endif
};

module_pci_driver(uio_pci_driver);
MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
