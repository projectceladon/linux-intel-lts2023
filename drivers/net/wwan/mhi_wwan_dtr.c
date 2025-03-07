// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2023, Daniele Palmas <dnlplm@gmail.com> */
#include <linux/kernel.h>
#include <linux/mhi.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/wwan.h>

struct mhi_wwan_dev {
	struct mhi_device *mhi_dev;
};

int mhi_wwan_dtr_set(struct wwan_port *port, int dtr, int rts)
{
	struct mhi_wwan_dev *mhiwwan = wwan_port_get_drvdata(port);
	int ret;

	if (mhiwwan->mhi_dev->mhi_cntrl->mhi_dev_ip_ctrl) {
		struct __packed dtr_ctrl_msg {
			u32 preamble;
			u32 msg_id;
			u32 dest_id;
			u32 size;
			u32 msg;
		};

		struct dtr_ctrl_msg dtr_msg = {0};
		struct sk_buff *skb;

		dtr_msg.preamble = 0x4C525443;
		dtr_msg.msg_id = 0x10;
		dtr_msg.dest_id = mhiwwan->mhi_dev->ul_chan_id;
		dtr_msg.size = sizeof(u32);
		if (dtr)
			dtr_msg.msg |= BIT(0);
		if (rts)
			dtr_msg.msg |= BIT(1);
		skb = alloc_skb(sizeof(dtr_msg), GFP_KERNEL);
		skb_put_data(skb, &dtr_msg, sizeof(dtr_msg));
		dev_dbg(&mhiwwan->mhi_dev->mhi_cntrl->mhi_dev_ip_ctrl->dev, "Queuing DTR skb %u...\n", skb->len);
		ret = mhi_queue_skb(mhiwwan->mhi_dev->mhi_cntrl->mhi_dev_ip_ctrl, DMA_TO_DEVICE, skb, skb->len, MHI_EOT);
		if (ret) {
			dev_dbg(&mhiwwan->mhi_dev->mhi_cntrl->mhi_dev_ip_ctrl->dev, "Unable to send UART signals\n");
				kfree_skb(skb);
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(mhi_wwan_dtr_set);

static int mhi_wwan_dtr_start(struct wwan_port *port)
{
	return 0;
}

static void mhi_wwan_dtr_stop(struct wwan_port *port)
{
}

static int mhi_wwan_dtr_tx(struct wwan_port *port, struct sk_buff *skb)
{
	struct mhi_wwan_dev *mhiwwan = wwan_port_get_drvdata(port);

	/* Queue the packet for MHI transfer */
	return mhi_queue_skb(mhiwwan->mhi_dev, DMA_TO_DEVICE, skb, skb->len, MHI_EOT);
}

static const struct wwan_port_ops wwan_pops = {
	.start = mhi_wwan_dtr_start,
	.stop = mhi_wwan_dtr_stop,
	.tx = mhi_wwan_dtr_tx,
};

static void mhi_dtr_ul_xfer_cb(struct mhi_device *mhi_dev,
			   struct mhi_result *mhi_result)
{
	struct sk_buff *skb = mhi_result->buf_addr;

	dev_dbg(&mhi_dev->dev, "%s: status: %d xfer_len: %zu\n", __func__,
		mhi_result->transaction_status, mhi_result->bytes_xferd);

	/* MHI core has done with the buffer, release it */
	consume_skb(skb);
}

static void mhi_dtr_dl_xfer_cb(struct mhi_device *mhi_dev,
			   struct mhi_result *mhi_result)
{
	/* Currently we don't use the information provided by the modem */
	dev_dbg(&mhi_dev->dev, "%s: status: %d receive_len: %zu\n", __func__,
		mhi_result->transaction_status, mhi_result->bytes_xferd);
}

static int mhi_wwan_dtr_probe(struct mhi_device *mhi_dev,
			       const struct mhi_device_id *id)
{
	struct mhi_wwan_dev *mhiwwan;

	mhiwwan = kzalloc(sizeof(*mhiwwan), GFP_KERNEL);
	if (!mhiwwan)
		return -ENOMEM;

	mhiwwan->mhi_dev = mhi_dev;

	dev_set_drvdata(&mhi_dev->dev, mhiwwan);

	/* Start mhi device's channel(s) */
	return mhi_prepare_for_transfer_autoqueue(mhiwwan->mhi_dev);
};

static void mhi_wwan_dtr_remove(struct mhi_device *mhi_dev)
{
	struct mhi_wwan_dev *mhiwwan = dev_get_drvdata(&mhi_dev->dev);

	mhi_unprepare_from_transfer(mhiwwan->mhi_dev);

	kfree(mhiwwan);
}

static const struct mhi_device_id mhi_wwan_dtr_match_table[] = {
	{ .chan = "IP_CTRL", .driver_data = 0 },
	{}
};
MODULE_DEVICE_TABLE(mhi, mhi_wwan_dtr_match_table);

static struct mhi_driver mhi_wwan_dtr_simple_driver = {
	.id_table = mhi_wwan_dtr_match_table,
	.remove = mhi_wwan_dtr_remove,
	.probe = mhi_wwan_dtr_probe,
	.ul_xfer_cb = mhi_dtr_ul_xfer_cb,
	.dl_xfer_cb = mhi_dtr_dl_xfer_cb,
	.driver = {
		.name = "mhi_wwan_dtr_simple",
	},
};

module_mhi_driver(mhi_wwan_dtr_simple_driver);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("MHI WWAN DTR Simple Driver");
MODULE_AUTHOR("Daniele Palmas <dnlplm@gmail.com>");
