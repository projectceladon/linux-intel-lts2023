// SPDX-License-Identifier: GPL-2.0

#include <linux/device.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/interrupt.h>

#include "ivshm.h"

#define DRIVER_VERSION	"0.01.0"
#define DRIVER_AUTHOR	"Junjie Mao <junjie.mao@intel.com>"
#define DRIVER_DESC	"Inter-VM shared memory driver for QEMU ivshmem devices"

#define IVSHMEM_REG_BAR  0
#define IVSHMEM_MEM_BAR  2

struct ivshm_ivshmem_dev {
	struct ivshm_info  info;
	struct pci_dev    *pdev;

	struct ivshm_region *iregion;
	struct msix_entry   *msix_entries;
	int                  nvecs;
};

static irqreturn_t ivshmem_irq_handler(int irq, void *arg)
{
	struct ivshm_ivshmem_dev *idev = (struct ivshm_ivshmem_dev *)arg;
	irqreturn_t ret = IRQ_NONE;
	int i;

	for (i = 0; i < idev->nvecs; i++) {
		if (idev->msix_entries[i].vector == irq) {
			ivshm_notify_listeners(idev->iregion, i);
			ret = IRQ_HANDLED;
		}
	}

	return ret;
}

static int ivshmem_init_msix(struct ivshm_ivshmem_dev *idev)
{
	int i, j, nvecs;
	int err;

	nvecs = pci_msix_vec_count(idev->pdev);
	if (!nvecs)
		return -EINVAL;

	idev->msix_entries = devm_kcalloc(&idev->pdev->dev, nvecs,
					  sizeof(*idev->msix_entries), GFP_KERNEL);
	if (!idev->msix_entries)
		return -ENOMEM;

	for (i = 0; i < nvecs; i++)
		idev->msix_entries[i].entry = i;

	err = pci_enable_msix_exact(idev->pdev, idev->msix_entries, nvecs);
	if (err)
		return err;

	for (i = 0; i < nvecs; i++) {
		err = request_irq(idev->msix_entries[i].vector, ivshmem_irq_handler, 0,
			"ivshmem", idev);
		if (err) {
			for (j = 0; j < i; j++)
				free_irq(idev->msix_entries[i].vector, idev);

			pci_disable_msix(idev->pdev);
			return err;
		}
	}

	idev->nvecs = nvecs;
	return 0;
}

static int probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct ivshm_ivshmem_dev *idev;
	struct ivshm_region *iregion;
	resource_size_t start, len;
	int err;

	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "Failed to enable PCI device.\n");
		return err;
	}

	err = pci_request_regions(pdev, "ivshm_ivshmem");
	if (err) {
		dev_err(&pdev->dev, "Failed to request PCI resources.\n");
		goto out_disable_device;
	}

	idev = devm_kzalloc(&pdev->dev, sizeof(struct ivshm_ivshmem_dev), GFP_KERNEL);
	if (!idev) {
		err = -ENOMEM;
		goto out_release_region;
	}

	idev->pdev = pdev;
	idev->info.dev_ctrls = pci_resource_start(pdev, IVSHMEM_REG_BAR);
	idev->info.dev_ctrls_len = pci_resource_len(pdev, IVSHMEM_REG_BAR);
	err = devm_ivshm_register_device(&pdev->dev, &idev->info);
	if (err) {
		dev_err(&pdev->dev, "Failed to register ivshm device.\n");
		goto out_release_region;
	}

	start = pci_resource_start(pdev, IVSHMEM_MEM_BAR);
	len = pci_resource_len(pdev, IVSHMEM_MEM_BAR);
	idev->info.dev_mmio = start;
	idev->info.dev_mmio_len = len;
	err = ivshm_register_region(idev->info.ivshm_dev, "default", start, len,
		pci_msix_vec_count(pdev), &iregion);
	if (err) {
		dev_err(&pdev->dev, "Failed to register ivshm region.\n");
		goto out_unregister_device;
	}

	idev->iregion = iregion;

	err = ivshmem_init_msix(idev);
	if (err) {
		dev_err(&pdev->dev, "Failed to enable MSI-X.\n");
		goto out_unregister_device;
	}

	pci_set_master(pdev);
	pci_set_drvdata(pdev, idev);

	return 0;

out_unregister_device:
	ivshm_unregister_device(&idev->info);
out_release_region:
	pci_release_regions(pdev);
out_disable_device:
	pci_disable_device(pdev);
	return err;
}

static void remove(struct pci_dev *pdev)
{
	struct ivshm_ivshmem_dev *idev = pci_get_drvdata(pdev);
	int i;

	for (i = 0; i < idev->nvecs; i++)
		free_irq(idev->msix_entries[i].vector, idev);

	ivshm_unregister_device(&idev->info);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
}

static struct pci_driver ivshmem_pci_driver = {
	.name = "ivshm_ivshmem",
	.id_table = NULL, /* only dynamic id's */
	.probe = probe,
	.remove = remove,
};

module_pci_driver(ivshmem_pci_driver);
MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
