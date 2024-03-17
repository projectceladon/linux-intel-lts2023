// SPDX-License-Identifier: GPL-2.0

#include <linux/device.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/guest_shm.h>

#include "ivshm.h"

#define DRIVER_VERSION	"0.01.0"
#define DRIVER_AUTHOR	"Junjie Mao <junjie.mao@intel.com>"
#define DRIVER_DESC	"Inter-VM shared memory driver for QEMU ivshmem devices"

struct ivshm_guest_shm_dev {
	struct ivshm_info  info;
	struct pci_dev    *pdev;

	struct guest_shm_factory __iomem *fact;
	struct guest_shm_control *ctrl;

	struct ivshm_region *iregion;
	int                  irq;
};

static irqreturn_t guest_shm_irq_handler(int irq, void *arg)
{
	struct ivshm_guest_shm_dev *idev = (struct ivshm_guest_shm_dev *)arg;
	irqreturn_t ret = IRQ_NONE;
	int i;

	if (idev->irq == irq) {
		/* Check the status ? Only when status == (1 << id) needs handle */
		if (idev->ctrl->status & GUEST_INTR_STATUS_MASK)
			ivshm_notify_listeners(idev->iregion, i);
		ret = IRQ_HANDLED;
	}

	return ret;
}

static int guest_shm_init_irq(struct ivshm_guest_shm_dev *idev)
{
	idev->irq = idev->fact->vector;
	return request_irq(idev->irq, guest_shm_irq_handler, 0, "guest_shm", idev);
}

static int probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct ivshm_guest_shm_dev *idev;
	struct ivshm_region *iregion;
	resource_size_t paddr;
	int err;
	unsigned long min_align;
	long idx;

	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "Failed to enable PCI device.\n");
		return err;
	}

	idev = devm_kzalloc(&pdev->dev, sizeof(struct ivshm_guest_shm_dev), GFP_KERNEL);
	if (!idev) {
		err = -ENOMEM;
		goto out_disable_device;
	}

	err = pcim_iomap_regions(pdev, BIT(0), "ivshm_guest_shm");
	if (err)
		goto out_disable_device;

	idev->fact = pcim_iomap_table(pdev)[0];
	pci_set_master(pdev);

	if (idev->fact->signature != GUEST_SHM_SIGNATURE) {
		dev_err(&pdev->dev, "Signature incorrect. %llx != %llx",
			(unsigned long long)GUEST_SHM_SIGNATURE,
			(unsigned long long) idev->fact->signature);
		err =  -ENXIO;
		goto out_disable_device;
	}

	if (idev->fact->status != GSS_OK) {
		dev_err(&pdev->dev, "creating failed: %d", idev->fact->status);
		err = -idev->fact->status;
		goto out_disable_device;
	}

	err = kstrtol(idev->fact->name + strlen("virtio"), 10, &idx);
	if (err)
		goto out_disable_device;

	paddr = idev->fact->shmem;
	dev_info(&pdev->dev, "virtio%ld creation size %x, paddr=%llx", idx,
		idev->fact->size, (unsigned long long)paddr);

	idev->ctrl = memremap(paddr, 0x1000, MEMREMAP_WB);
	dev_info(&pdev->dev, "shared memory index %u", idev->ctrl->idx);

	idev->pdev = pdev;
	idev->info.dev_ctrls = paddr;
	idev->info.dev_ctrls_len = 0x1000;
	err = devm_ivshm_register_device(&pdev->dev, &idev->info);
	if (err) {
		dev_err(&pdev->dev, "Failed to register ivshm device.\n");
		goto out_disable_device;
	}

	if (IS_ENABLED(CONFIG_SPARSEMEM_VMEMMAP))
		min_align = PAGES_PER_SUBSECTION;
	else
		min_align = PAGES_PER_SECTION;
	min_align = (min_align << PAGE_SHIFT);
	idev->info.dev_mmio = (paddr + (idx << 32)) + 0x1000;
	idev->info.dev_mmio = (idev->info.dev_mmio + (min_align - 1)) & ~(min_align - 1);
	idev->info.dev_mmio_len = idev->fact->size * 0x1000 -
		((idev->info.dev_mmio - (paddr + (idx << 32))
		- 0x1000 + (min_align - 1)) & ~(min_align - 1));
	dev_info(&pdev->dev, "min_align: 0x%lx, mmio: 0x%llx, mmio_len: 0x%llx", min_align,
		idev->info.dev_mmio, idev->info.dev_mmio_len);

	err = ivshm_register_region(idev->info.ivshm_dev, "default", idev->info.dev_mmio,
		idev->info.dev_mmio_len, 1 /* use INTx */, &iregion);
	if (err) {
		dev_err(&pdev->dev, "Failed to register ivshm region.\n");
		goto out_unregister_device;
	}

	idev->iregion = iregion;

	err = guest_shm_init_irq(idev);
	if (err) {
		dev_err(&pdev->dev, "Failed to enable interrupt.\n");
		goto out_unregister_device;
	}

	pci_set_master(pdev);
	pci_set_drvdata(pdev, idev);

	return 0;

out_unregister_device:
	ivshm_unregister_device(&idev->info);
out_disable_device:
	pci_disable_device(pdev);
	return err;
}

static void remove(struct pci_dev *pdev)
{
	struct ivshm_guest_shm_dev *idev = pci_get_drvdata(pdev);

	free_irq(idev->irq, idev);

	ivshm_unregister_device(&idev->info);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
}

static struct pci_driver guest_shm_pci_driver = {
	.name = "ivshm_guest_shm",
	.id_table = NULL, /* only dynamic id's */
	.probe = probe,
	.remove = remove,
};

module_pci_driver(guest_shm_pci_driver);
MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
