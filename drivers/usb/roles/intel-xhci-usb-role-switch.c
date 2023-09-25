// SPDX-License-Identifier: GPL-2.0+
/*
 * Intel XHCI (Cherry Trail, Broxton and others) USB OTG role switch driver
 *
 * Copyright (c) 2016-2017 Hans de Goede <hdegoede@redhat.com>
 *
 * Loosely based on android x86 kernel code which is:
 *
 * Copyright (C) 2014 Intel Corp.
 *
 * Author: Wu, Hao
 */

#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/property.h>
#include <linux/usb/role.h>

/* register definition */
#define DUAL_ROLE_CFG0			0x68
#define SW_VBUS_VALID			BIT(24)
#define SW_IDPIN_EN			BIT(21)
#define SW_IDPIN			BIT(20)
#define SW_SWITCH_EN			BIT(16)

#define DRD_CONFIG_DYNAMIC		0
#define DRD_CONFIG_STATIC_HOST		1
#define DRD_CONFIG_STATIC_DEVICE	2
#define DRD_CONFIG_MASK			3

#define DUAL_ROLE_CFG1			0x6c
#define HOST_MODE			BIT(29)

#define DUAL_ROLE_CFG1_POLL_TIMEOUT	1000

#define DRV_NAME			"intel_xhci_usb_sw"

/*
 * USBX DAP Private config registers
 * (PID:PID_XHCI)
 */
/* DAP USB common Control Register */
#define R_DAP_USB_COMMON_CONTROL_REG          0x04
/* Split Die xDCI PCH VBUS (SDXPCHVBUS) */
#define R_DAP_USB_SDXPCHVBUS                  0x01000000
/* DAP USB2 Port Control 0 Register */
#define R_DAP_USB2_PORT_CONTROL_0_REG_0       0xc4
/* In connector type aware flow, this field is used in SW mode only */
#define V_PCR_USB_CONNECTOR_EVENT_MASK        0x000000E0
/* host subscription. */
#define V_PCR_USB_CONNECTOR_EVENT_HOST        0x00000000
/* device subscription. */
#define V_PCR_USB_CONNECTOR_EVENT_DEVICE      0x00000060
/* un-subscription */
#define V_PCR_USB_DISCONNRCT_CONNECTOR_EVENT  0x00000020
/* DBC subscription. */
#define V_PCR_USB_CONNECTOR_EVENT_DBC         0x00000080
/* SW_VBUS */
#define V_PCR_USB_SW_VBUS                     0x00000100
/* DAP USB2 Port Control 1 Register */
#define R_DAP_USB2_PORT_CONTROL_1_REG_0       0xc8
/* DAP USB2 Port Status Register */
#define R_DAP_USB2_PORT_STATUS_REG_0          0xcc
/* This field reflects live value of the DRD operation states
 * with one-hot encodings
 */
#define V_PCR_USB_OP_STATUS_MASK              0x000000FF
/* host */
#define V_PCR_USB_OP_STATUS_HOST              0x00000001
/* disconnected */
#define V_PCR_USB_OP_STATUS_DISCONNECT        0x00000002
/* guest */
#define V_PCR_USB_OP_STATUS_GUEST             0x00000004
/* device */
#define V_PCR_USB_OP_STATUS_DEVICE            0x00000008
/* PHY initialization. (default, dummy) */
#define V_PCR_USB_OP_STATUS_PHY_INIT          0x00000010
/* EXI BSSB adapter connected. */
#define V_PCR_USB_OP_STATUS_EXI_BSSB          0x00000020
/* DBC */
#define V_PCR_USB_OP_STATUS_DBC               0x00000040
/* over-subscribed device. */
#define V_PCR_USB_OP_STATUS_OV_SUB_DEV        0x00000080
/* Hardware VBUS */
#define V_PCR_USB_OP_STATUS_HW_VBUS           0x00010000
/* SPR program max count */
#define V_PCR_USB_OP_MAX_TIMEOUT_COUNT        0x00001000
/* DAP eSS Port Control 0 Register */
#define R_DAP_ESS_PORT_CONTROL_0_REG_0        0x600
/*  DAP eSS Port Status Register */
#define R_DAP_ESS_PORT_STATUS_REG_0           0x608
/* Port0 is configured as usb device mode */
#define DEVICE_PORT_NUM                       0x00
/* Enable USB DAP FEATURE */
#define USB_DAP_ENABLED

struct intel_xhci_usb_data {
	struct device *dev;
	struct usb_role_switch *role_sw;
	void __iomem *base;
	bool enable_sw_switch;
};

static const struct software_node intel_xhci_usb_node = {
	"intel-xhci-usb-sw",
};

static enum usb_role intel_xhci_get_dap_port_status(unsigned int portnum,
		struct intel_xhci_usb_data *data)
{
	unsigned int val;
	unsigned int portoffset;
	enum usb_role role;

	portoffset = portnum * 0x10;
	val = readl(data->base + (portoffset +
				R_DAP_USB2_PORT_STATUS_REG_0));
	if (val == V_PCR_USB_OP_STATUS_HOST)
		role = USB_ROLE_HOST;
	else if (val == V_PCR_USB_OP_STATUS_DEVICE ||
		val == V_PCR_USB_OP_STATUS_OV_SUB_DEV)
		role = USB_ROLE_DEVICE;
	else
		role = USB_ROLE_NONE;
	return role;
}


void intel_xhci_force_port_xhci(unsigned int  portnum,
		struct intel_xhci_usb_data *data)
{
	unsigned int portoffset;
	unsigned int count;
	unsigned int val;

	portoffset = portnum * 0x10;
	/* SDXPCHVBUS Set by CPU xDCI as USB2 connection in PCH is desired */
	val = readl(data->base + (R_DAP_USB_COMMON_CONTROL_REG));
	val &= ~R_DAP_USB_SDXPCHVBUS;
	writel(val, data->base + (R_DAP_USB_COMMON_CONTROL_REG));
	/* Initiate disconnect event */
	val = readl(data->base + (portoffset +
				R_DAP_USB2_PORT_CONTROL_0_REG_0));
	val &= (unsigned int)(~V_PCR_USB_CONNECTOR_EVENT_MASK);
	val |= V_PCR_USB_DISCONNRCT_CONNECTOR_EVENT;
	writel(val, data->base + (R_DAP_USB2_PORT_CONTROL_0_REG_0 +
				portoffset));
	/* Poll USB2 OP Status */
	for (count = 0x00; count < V_PCR_USB_OP_MAX_TIMEOUT_COUNT; count++) {
		val = readl(data->base +
				(portoffset + R_DAP_USB2_PORT_STATUS_REG_0));
		val &= V_PCR_USB_OP_STATUS_MASK;
		/*
		 * Device:  Poll 0x08 || 0x80 || 0x20
		 * HOST:    Poll 0x01 || 0x20
		 * DBC:     Poll 0x40
		 * Discon:  Poll 0x02 || 0x10
		 */
		if (val == V_PCR_USB_OP_STATUS_DISCONNECT)
			break;
	}
	val = readl(data->base + (portoffset + R_DAP_USB2_PORT_CONTROL_0_REG_0));
	val &= ~(V_PCR_USB_CONNECTOR_EVENT_MASK);
	val |= V_PCR_USB_CONNECTOR_EVENT_HOST;
	writel(val, data->base + (R_DAP_USB2_PORT_CONTROL_0_REG_0 + portoffset));
	/* Poll USB2 OP Status */
	for (count = 0x00; count < V_PCR_USB_OP_MAX_TIMEOUT_COUNT; count++) {
		val = readl(data->base +
				(portoffset + R_DAP_USB2_PORT_STATUS_REG_0));
		val &= V_PCR_USB_OP_STATUS_MASK;
		/*
		 * Device:  Poll 0x08 || 0x80 || 0x20
		 * HOST:    Poll 0x01 || 0x20
		 * DBC:     Poll 0x40
		 * Discon:  Poll 0x02 || 0x10
		 */
		if ((val == V_PCR_USB_OP_STATUS_HOST) ||
				(val == V_PCR_USB_OP_STATUS_EXI_BSSB))
			break;
	}
}

void intel_xhci_force_port_xdci(unsigned int  portnum,
		struct intel_xhci_usb_data *data)
{
	unsigned int portoffset;
	unsigned int count;
	unsigned int val;

	portoffset = portnum * 0x10; /* Each Port has 0x10 bytes register */
	/* SDXPCHVBUS Set by CPU xDCI as USB2 connection in PCH is desired */
	val = readl(data->base + (R_DAP_USB_COMMON_CONTROL_REG));
	val |= R_DAP_USB_SDXPCHVBUS;
	writel(val, data->base + (R_DAP_USB_COMMON_CONTROL_REG));
	/* Initiate disconnect event */
	val = readl(data->base + (portoffset + R_DAP_USB2_PORT_CONTROL_0_REG_0));
	val &= (unsigned int)(~V_PCR_USB_CONNECTOR_EVENT_MASK);
	val |= V_PCR_USB_DISCONNRCT_CONNECTOR_EVENT;
	writel(val, data->base + (R_DAP_USB2_PORT_CONTROL_0_REG_0 + portoffset));
	/* Poll USB2 OP Status */
	for (count = 0x00; count < V_PCR_USB_OP_MAX_TIMEOUT_COUNT; count++) {
		val = readl(data->base +
				(portoffset + R_DAP_USB2_PORT_STATUS_REG_0));
		val &= V_PCR_USB_OP_STATUS_MASK;
		/*
		 * Device:  Poll 0x08 || 0x80 || 0x20
		 * HOST:    Poll 0x01 || 0x20
		 * DBC:     Poll 0x40
		 * Discon:  Poll 0x02 || 0x10
		 */
		if (val == V_PCR_USB_OP_STATUS_DISCONNECT)
			break;
	}
	val = readl(data->base + (portoffset +
				R_DAP_USB2_PORT_CONTROL_0_REG_0));
	val &= ~(V_PCR_USB_CONNECTOR_EVENT_MASK);
	val |= V_PCR_USB_CONNECTOR_EVENT_DEVICE;
	writel(val, data->base + (R_DAP_USB2_PORT_CONTROL_0_REG_0 +
				portoffset));
	/* Poll USB2 OP Status */
	for (count = 0x00; count < V_PCR_USB_OP_MAX_TIMEOUT_COUNT; count++) {
		val = readl(data->base +
				(portoffset + R_DAP_USB2_PORT_STATUS_REG_0));
		val &= V_PCR_USB_OP_STATUS_MASK;
		/*
		 * Device:  Poll 0x08 || 0x80 || 0x20
		 * HOST:    Poll 0x01 || 0x20
		 * DBC:     Poll 0x40
		 * Discon:  Poll 0x02 || 0x10
		 */
		if ((val == V_PCR_USB_OP_STATUS_DEVICE) ||
		(val == V_PCR_USB_OP_STATUS_OV_SUB_DEV) ||
		(val == V_PCR_USB_OP_STATUS_EXI_BSSB))
			break;
	}
	val = readl(data->base + (R_DAP_USB2_PORT_CONTROL_0_REG_0 +
				portoffset));
	val &= (unsigned int)(~V_PCR_USB_SW_VBUS);
	val |= V_PCR_USB_SW_VBUS;
	/* Write VBUS bit */
	writel(val, data->base + (R_DAP_USB2_PORT_CONTROL_0_REG_0 +
				portoffset));
	/* status */
	val = readl(data->base + (portoffset +
				R_DAP_USB2_PORT_STATUS_REG_0));
}

static int intel_xhci_usb_set_role(struct usb_role_switch *sw,
				   enum usb_role role)
{
	struct intel_xhci_usb_data *data = usb_role_switch_get_drvdata(sw);
	unsigned long timeout;
	acpi_status status;
	u32 glk, val;
	u32 drd_config = DRD_CONFIG_DYNAMIC;

	#ifdef USB_DAP_ENABLED
	if (role == USB_ROLE_HOST)
		intel_xhci_force_port_xhci(DEVICE_PORT_NUM, data);
	else if (role == USB_ROLE_DEVICE)
		intel_xhci_force_port_xdci(DEVICE_PORT_NUM, data);
	else
		return -1;
	return 0;
	#else
	/*
	 * On many CHT devices ACPI event (_AEI) handlers read / modify /
	 * write the cfg0 register, just like we do. Take the ACPI lock
	 * to avoid us racing with the AML code.
	 */
	status = acpi_acquire_global_lock(ACPI_WAIT_FOREVER, &glk);
	if (ACPI_FAILURE(status) && status != AE_NOT_CONFIGURED) {
		dev_err(data->dev, "Error could not acquire lock\n");
		return -EIO;
	}

	pm_runtime_get_sync(data->dev);

	/*
	 * Set idpin value as requested.
	 * Since some devices rely on firmware setting DRD_CONFIG and
	 * SW_SWITCH_EN bits to be zero for role switch,
	 * do not set these bits for those devices.
	 */
	val = readl(data->base + DUAL_ROLE_CFG0);
	switch (role) {
	case USB_ROLE_NONE:
		val |= SW_IDPIN;
		val &= ~SW_VBUS_VALID;
		drd_config = DRD_CONFIG_DYNAMIC;
		break;
	case USB_ROLE_HOST:
		val &= ~SW_IDPIN;
		val &= ~SW_VBUS_VALID;
		drd_config = DRD_CONFIG_STATIC_HOST;
		break;
	case USB_ROLE_DEVICE:
		val |= SW_IDPIN;
		val |= SW_VBUS_VALID;
		drd_config = DRD_CONFIG_STATIC_DEVICE;
		break;
	}
	val |= SW_IDPIN_EN;
	if (data->enable_sw_switch) {
		val &= ~DRD_CONFIG_MASK;
		val |= SW_SWITCH_EN | drd_config;
	}
	writel(val, data->base + DUAL_ROLE_CFG0);

	acpi_release_global_lock(glk);

	/* In most case it takes about 600ms to finish mode switching */
	timeout = jiffies + msecs_to_jiffies(DUAL_ROLE_CFG1_POLL_TIMEOUT);

	/* Polling on CFG1 register to confirm mode switch.*/
	do {
		val = readl(data->base + DUAL_ROLE_CFG1);
		if (!!(val & HOST_MODE) == (role == USB_ROLE_HOST)) {
			pm_runtime_put(data->dev);
			return 0;
		}

		/* Interval for polling is set to about 5 - 10 ms */
		usleep_range(5000, 10000);
	} while (time_before(jiffies, timeout));

	pm_runtime_put(data->dev);

	dev_warn(data->dev, "Timeout waiting for role-switch\n");
	return -ETIMEDOUT;
	#endif
}

static enum usb_role intel_xhci_usb_get_role(struct usb_role_switch *sw)
{
	struct intel_xhci_usb_data *data = usb_role_switch_get_drvdata(sw);
	enum usb_role role;
	u32 val;

	#ifdef USB_DAP_ENABLED
	return intel_xhci_get_dap_port_status(DEVICE_PORT_NUM, data);
	#else

	pm_runtime_get_sync(data->dev);
	val = readl(data->base + DUAL_ROLE_CFG0);
	pm_runtime_put(data->dev);

	if (!(val & SW_IDPIN))
		role = USB_ROLE_HOST;
	else if (val & SW_VBUS_VALID)
		role = USB_ROLE_DEVICE;
	else
		role = USB_ROLE_NONE;

	return role;
	#endif
}

static int intel_xhci_usb_probe(struct platform_device *pdev)
{
	struct usb_role_switch_desc sw_desc = { };
	struct device *dev = &pdev->dev;
	struct intel_xhci_usb_data *data;
	struct resource *res;
	int ret;

	data = devm_kzalloc(dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -EINVAL;
	data->base = devm_ioremap(dev, res->start, resource_size(res));
	if (!data->base)
		return -ENOMEM;

	platform_set_drvdata(pdev, data);

	ret = software_node_register(&intel_xhci_usb_node);
	if (ret)
		return ret;

	sw_desc.set = intel_xhci_usb_set_role,
	sw_desc.get = intel_xhci_usb_get_role,
	sw_desc.allow_userspace_control = true,
	sw_desc.fwnode = software_node_fwnode(&intel_xhci_usb_node);
	sw_desc.driver_data = data;

	data->dev = dev;
	data->enable_sw_switch = !device_property_read_bool(dev,
						"sw_switch_disable");

	data->role_sw = usb_role_switch_register(dev, &sw_desc);
	if (IS_ERR(data->role_sw)) {
		fwnode_handle_put(sw_desc.fwnode);
		return PTR_ERR(data->role_sw);
	}

	pm_runtime_set_active(dev);
	pm_runtime_enable(dev);

	return 0;
}

static void intel_xhci_usb_remove(struct platform_device *pdev)
{
	struct intel_xhci_usb_data *data = platform_get_drvdata(pdev);

	pm_runtime_disable(&pdev->dev);

	usb_role_switch_unregister(data->role_sw);
	fwnode_handle_put(software_node_fwnode(&intel_xhci_usb_node));
}

static const struct platform_device_id intel_xhci_usb_table[] = {
	{ .name = DRV_NAME },
	{}
};
MODULE_DEVICE_TABLE(platform, intel_xhci_usb_table);

static struct platform_driver intel_xhci_usb_driver = {
	.driver = {
		.name = DRV_NAME,
	},
	.id_table = intel_xhci_usb_table,
	.probe = intel_xhci_usb_probe,
	.remove_new = intel_xhci_usb_remove,
};

module_platform_driver(intel_xhci_usb_driver);

MODULE_AUTHOR("Hans de Goede <hdegoede@redhat.com>");
MODULE_DESCRIPTION("Intel XHCI USB role switch driver");
MODULE_LICENSE("GPL");
