// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Virtio SPI Controller Driver
 *
 * The Virtio SPI Specification Patch this driver follows:
 * https://lore.kernel.org/all/20230901032933.32434-1-quic_haixcui@quicinc.com/
 * With some fixes in comments. bus_num is removed from config since it's
 * unnecessary.
 *
 * Copyright (c) 2023 Intel Corporation. All rights reserved.
 */

#include <linux/acpi.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/irq.h>
#include <linux/spi/spi.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_spi.h>
#include <linux/irqdomain.h>>

#define VIRTIO_MAX_XFER_SIZE		0xffffff

/**
 * struct virtio_spi_req - the virtio SPI request structure
 * @completion: completion of virtio SPI message
 * @head: the transfer header of the virtio SPI message
 * @tx_buf: the buffer from which it's written
 * @rx_buf: the buffer into which data is read
 * @result: the result of the virtio I2C message
 */
struct virtio_spi_req {
	struct completion completion;
	struct virtio_spi_transfer_head head;
	const void *tx_buf;
	void *rx_buf;
	struct virtio_spi_transfer_result result;
};

struct virtio_spi_event_req {
	struct virtio_spi_event_head head;
	struct virtio_spi_event_result result;
};

struct virtio_spi_device_irq {
	bool masked;
	bool queued;
	struct virtio_spi_event_req ireq;
};

struct virtio_spi_irq {
	struct irq_chip *chip;
	struct irq_domain *domain;
	struct virtio_spi_device_irq *device_irqs;
};

/**
 * struct virtio_spi - virtio SPI data
 * @vdev: virtio device for this controller
 * @master: spi master for the spi core
 * @vq: the virtio virtqueue for communication
 */
struct virtio_spi {
	struct virtio_device *vdev;
	struct spi_master *master;
	struct virtqueue *xferq, *evtq;
	struct virtio_spi_irq irq;
	raw_spinlock_t eventq_lock;	/* Protects queuing of the buffer */
};

static void virtio_spi_device_irq_prepare(struct virtio_spi *vspi, u16 cs);

static void virtio_spi_xfer_done(struct virtqueue *vq)
{
	struct virtio_spi_req *req;
	unsigned int len;

	while ((req = virtqueue_get_buf(vq, &len)))
		complete(&req->completion);
}

static bool ignore_irq(struct virtio_spi *vspi, int cs,
		struct virtio_spi_device_irq *dev_irq)
{
	bool ignore = false;

	raw_spin_lock(&vspi->eventq_lock);
	dev_irq->queued = false;

	if (dev_irq->masked) {
		ignore = true;
	}

	if (dev_irq->ireq.result.result == VIRTIO_SPI_IRQ_INVALID) {
		virtio_spi_device_irq_prepare(vspi, cs);
		ignore = true;
		goto unlock;
	}

	if (WARN_ON(dev_irq->ireq.result.result != VIRTIO_SPI_IRQ_VALID))
		ignore = true;

unlock:
	raw_spin_unlock(&vspi->eventq_lock);

	return ignore;
}

static void virtio_spi_handle_event(struct virtqueue *vq)
{
	struct virtio_spi *vspi = vq->vdev->priv;
	struct device *dev = &vspi->vdev->dev;
	struct virtio_spi_device_irq *dev_irq;
	int cs, ret;
	unsigned int len;

	while (true) {
		dev_irq = virtqueue_get_buf(vq, &len);
		if (!dev_irq)
			break;

		if (len != sizeof(struct virtio_spi_event_result)) {
			dev_err(dev, "irq with incorrect length	(%u : %u)\n",
				len, (unsigned int)sizeof(struct virtio_spi_event_result));
			continue;
		}

		cs = dev_irq - vspi->irq.device_irqs;
		WARN_ON(cs >= vspi->master->num_chipselect);

		if (unlikely(ignore_irq(vspi, cs, dev_irq)))
			continue;

		ret = generic_handle_domain_irq(vspi->irq.domain, cs);
		if (ret)
			dev_err(dev, "failed to handle interrupt: %d\n", ret);
	}
}

static void virtio_spi_del_vqs(struct virtio_device *vdev)
{
	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);
}

static int virtio_spi_setup_vqs(struct virtio_spi *vspi)
{
	static vq_callback_t *callbacks[] = {
		virtio_spi_xfer_done,
		virtio_spi_handle_event,
	};
	static const char * const names[] = { "xfer", "event" };
	struct virtqueue *vqs[2];
	int ret;

	ret = virtio_find_vqs(vspi->vdev, 2, vqs, callbacks, names, NULL);
	if (ret)
		return ret;

	vspi->xferq = vqs[0];
	vspi->evtq = vqs[1];

	return 0;
}

static size_t virtio_spi_max_transfer_size(struct spi_device *spi)
{
	return VIRTIO_MAX_XFER_SIZE;
}

static int virtio_spi_transfer_one(struct spi_master *master,
				  struct spi_device *spi,
				  struct spi_transfer *xfer)
{
	struct virtio_spi *vspi = spi_master_get_devdata(master);
	struct virtio_spi_req *req;
	struct scatterlist *sgs[4], head, tx_buf, rx_buf, res;
	int ret = 0;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	init_completion(&req->completion);
	req->head.slave_id = spi->chip_select;
	req->head.bits_per_word = spi->bits_per_word;
	req->head.cs_change = xfer->cs_change;
	req->head.tx_nbits = xfer->tx_nbits;
	req->head.rx_nbits = xfer->rx_nbits;
	req->head.mode = spi->mode;
	req->head.freq = xfer->speed_hz;
	req->head.word_delay_ns = spi_delay_to_ns(&xfer->word_delay, xfer);
	req->head.cs_setup_ns = spi_delay_to_ns(&spi->cs_setup, xfer);
	req->head.cs_delay_hold_ns = spi_delay_to_ns(&spi->cs_hold, xfer);
	req->head.cs_change_delay_inactive_ns = spi_delay_to_ns(&spi->cs_inactive, xfer) + spi_delay_to_ns(&xfer->cs_change_delay, xfer);
	sg_init_one(&head, &req->head, sizeof(req->head));
	sgs[0] = &head;

	req->tx_buf = xfer->tx_buf;
	sg_init_one(&tx_buf, req->tx_buf, xfer->len);
	sgs[1] = &tx_buf;
	req->rx_buf = xfer->rx_buf;
	sg_init_one(&rx_buf, req->rx_buf, xfer->len);
	sgs[2] = &rx_buf;

	sg_init_one(&res, &req->result, sizeof(req->result));
	sgs[3] = &res;

	ret = virtqueue_add_sgs(vspi->xferq, sgs, 2, 2, req, GFP_KERNEL);
	if (ret) {
		dev_err(&vspi->vdev->dev, "fail to add sgs to vq!\n");
		goto err_free;
	}

	virtqueue_kick(vspi->xferq);

	wait_for_completion(&req->completion);

	if (req->result.result != VIRTIO_SPI_TRANS_OK) {
		dev_err(&vspi->vdev->dev, "result is bad!\n");
		ret = -EIO;
	}

err_free:
	kfree(req);
	return ret;
}

static void virtio_spi_device_irq_prepare(struct virtio_spi *vspi, u16 cs)
{
	struct virtio_spi_device_irq *dev_irq = &vspi->irq.device_irqs[cs];
	struct virtio_spi_event_req *ireq = &dev_irq->ireq;
	struct scatterlist *sgs[2], req_sg, res_sg;
	int ret;

	if (WARN_ON(dev_irq->queued || dev_irq->masked))
		return;

	ireq->head.slave_id = cs;
	sg_init_one(&req_sg, &ireq->head, sizeof(ireq->head));
	sg_init_one(&res_sg, &ireq->result, sizeof(ireq->result));
	sgs[0] = &req_sg;
	sgs[1] = &res_sg;

	ret = virtqueue_add_sgs(vspi->evtq, sgs, 1, 1, dev_irq, GFP_ATOMIC);
	if (ret) {
		dev_err(&vspi->vdev->dev, "fail to add request to eventq\n");
		return;
	}

	dev_irq->queued = true;
	virtqueue_kick(vspi->evtq);
}

static void virtio_spi_irq_mask(struct irq_data *d)
{
	struct virtio_spi *vspi = irq_data_get_irq_chip_data(d);
	struct virtio_spi_device_irq *dev_irq = &vspi->irq.device_irqs[d->hwirq];

	raw_spin_lock(&vspi->eventq_lock);
	dev_irq->masked = true;
	raw_spin_unlock(&vspi->eventq_lock);
}

static void virtio_spi_irq_unmask(struct irq_data *d)
{
	struct virtio_spi *vspi = irq_data_get_irq_chip_data(d);
	struct virtio_spi_device_irq *dev_irq = &vspi->irq.device_irqs[d->hwirq];

	raw_spin_lock(&vspi->eventq_lock);
	dev_irq->masked = false;
	virtio_spi_device_irq_prepare(vspi, d->hwirq);
	raw_spin_unlock(&vspi->eventq_lock);
}

static void virtio_spi_irq_ack(struct irq_data *d)
{
	struct virtio_spi *vspi = irq_data_get_irq_chip_data(d);
	struct virtio_spi_device_irq *dev_irq = &vspi->irq.device_irqs[d->hwirq];

	raw_spin_lock(&vspi->eventq_lock);
	if (!dev_irq->masked)
		virtio_spi_device_irq_prepare(vspi, d->hwirq);
	raw_spin_unlock(&vspi->eventq_lock);
}

static struct irq_chip vspi_irqchip = {
	.name = "virtio-spi",
	.irq_mask	= virtio_spi_irq_mask,
	.irq_unmask	= virtio_spi_irq_unmask,
	.irq_ack	= virtio_spi_irq_ack,
};

int vspi_irq_map(struct irq_domain *d, unsigned int irq,
		     irq_hw_number_t hwirq)
{
	struct virtio_spi *vspi = d->host_data;

	if (hwirq >= vspi->master->num_chipselect)
		return -ENXIO;

	irq_set_chip_data(irq, vspi);
	irq_set_chip_and_handler(irq, vspi->irq.chip, handle_edge_irq);
	irq_set_noprobe(irq);
	irq_set_irq_type(irq, IRQ_TYPE_EDGE_RISING);

	return 0;
}

void vspi_irq_unmap(struct irq_domain *d, unsigned int irq)
{
	irq_set_chip_and_handler(irq, NULL, NULL);
	irq_set_chip_data(irq, NULL);
}

static const struct irq_domain_ops vspi_domain_ops = {
	.map	= vspi_irq_map,
	.unmap	= vspi_irq_unmap,
	.xlate	= irq_domain_xlate_twocell,
};

static int virtio_spi_probe(struct virtio_device *vdev)
{
	struct virtio_spi *vspi;
	struct spi_master *master;
	int ret = 0, i;

	master = spi_alloc_master(&vdev->dev, sizeof(struct virtio_spi));
	if (!master) {
		dev_err(&vdev->dev, "Unable to allocate SPI Master\n");
		return -ENOMEM;
	}
	vspi = spi_master_get_devdata(master);
	vdev->priv = vspi;
	vspi->vdev = vdev;
	vspi->master = master;

	ret = virtio_spi_setup_vqs(vspi);
	if (ret)
		goto err_free_master;

	master->transfer_one = virtio_spi_transfer_one;
	master->num_chipselect = virtio_cread16(vdev,
			offsetof(struct virtio_spi_config, num_cs));
	master->mode_bits = SPI_CPOL | SPI_CPHA | SPI_CS_HIGH | SPI_LSB_FIRST;
	master->bits_per_word_mask = SPI_BPW_MASK(8);
	master->max_transfer_size = virtio_spi_max_transfer_size;

	/*
	 * Setup ACPI node for controlled devices which will be probed through
	 * ACPI.
	 */
	ACPI_COMPANION_SET(&vdev->dev, ACPI_COMPANION(vdev->dev.parent));

	raw_spin_lock_init(&vspi->eventq_lock);
	vspi->irq.chip = &vspi_irqchip;
	vspi->irq.device_irqs = devm_kcalloc(&vdev->dev, master->num_chipselect,
			sizeof(struct virtio_spi_device_irq), GFP_KERNEL);
	if (!vspi->irq.device_irqs) {
		ret = -ENOMEM;
		goto err_free_master;
	}
	for (i = 0; i < master->num_chipselect; i++) {
		vspi->irq.device_irqs[i].masked = true;
		vspi->irq.device_irqs[i].queued = false;
	}
	vspi->irq.domain = irq_domain_create_simple(dev_fwnode(&vdev->dev),
			master->num_chipselect, 0, &vspi_domain_ops, vspi);
	if (!vspi->irq.domain) {
		ret = -EINVAL;
		goto err_free_master;
	}

	/* after registration, spi device driver may be probed and open
	 * interrupts */
	ret = devm_spi_register_master(&vdev->dev, master);
	if (ret) {
		dev_err(&vdev->dev, "cannot register SPI master\n");
		goto err_del_vqs;
	}

	return 0;

err_del_vqs:
	virtio_spi_del_vqs(vdev);
err_free_master:
	spi_master_put(master);
	return ret;
}

static void virtio_spi_remove(struct virtio_device *vdev)
{
	struct virtio_spi *vspi = vdev->priv;

	virtio_spi_del_vqs(vdev);
	spi_master_put(vspi->master);
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_SPI, VIRTIO_DEV_ANY_ID },
	{}
};

#ifdef CONFIG_PM_SLEEP
static int virtio_spi_freeze(struct virtio_device *vdev)
{
	virtio_spi_del_vqs(vdev);
	return 0;
}

static int virtio_spi_restore(struct virtio_device *vdev)
{
	return virtio_spi_setup_vqs(vdev->priv);
}
#endif

static struct virtio_driver virtio_spi_driver = {
	.id_table		= id_table,
	.probe			= virtio_spi_probe,
	.remove			= virtio_spi_remove,
	.driver			= {
		.name	= "virtio-spi",
	},
#ifdef CONFIG_PM_SLEEP
	.freeze = virtio_spi_freeze,
	.restore = virtio_spi_restore,
#endif
};
module_virtio_driver(virtio_spi_driver);

MODULE_AUTHOR("Qiang Zhang <qiang4.zhang@intel.com>");
MODULE_DESCRIPTION("Virtio SPI controller driver");
MODULE_LICENSE("GPL");
