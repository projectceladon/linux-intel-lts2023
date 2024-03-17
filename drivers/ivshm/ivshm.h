/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _IVSHM_DRIVER_H_
#define _IVSHM_DRIVER_H_

#include <linux/device.h>
#include <linux/cdev.h>

/*
 * Ioctl APIs
 */

struct ivshm_listener_data {
	int vector;
	int evt_fd;
};

#define IVSHM_ADD_LISTENER	_IOW('u', 100, struct ivshm_listener_data)
#define IVSHM_GET_MMIO_SZ	_IOR('u', 101, unsigned long long)

/*
 * Internal data structures
 */

#define IVSHM_REGION_NAME_LEN   16

struct ivshm_device {
	struct module      *owner;
	struct device       dev;
	struct ivshm_info  *info;

	int                 minor;
	struct list_head    regions;
};

struct ivshm_region {
	struct module         *owner;
	struct device          dev;

	char                   name[IVSHM_REGION_NAME_LEN];
	struct list_head       list;
	struct ivshm_device   *idev;

	resource_size_t        base;
	resource_size_t        len;
	void                  *mem;
	struct {
		struct list_head       list;
		spinlock_t             list_lock;
	} *listeners;
	size_t                 nr_vectors;

	int                    minor;
};

struct ivshm_user {
	struct ivshm_device   *idev;
};

struct ivshm_region_user {
	struct ivshm_region   *iregion;
	struct list_head       listeners;
	spinlock_t             listeners_list_lock;
};

struct ivshm_listener {
	struct list_head       region_user_list;
	struct list_head       region_list;

	int vector;
	struct eventfd_ctx *evt;
};

struct ivshm_info {
	resource_size_t        dev_ctrls;
	resource_size_t        dev_ctrls_len;

	resource_size_t        dev_mmio;
	resource_size_t        dev_mmio_len;
	struct ivshm_device   *ivshm_dev;
};

extern int __must_check
__devm_ivshm_register_device(struct module *owner,
			     struct device *parent,
			     struct ivshm_info *info);
#define devm_ivshm_register_device(parent, info) \
	__devm_ivshm_register_device(THIS_MODULE, parent, info)

extern void ivshm_unregister_device(struct ivshm_info *info);

extern int ivshm_register_region(struct ivshm_device *dev, const char *name,
				 resource_size_t base, resource_size_t size,
				 size_t nr_vectors, struct ivshm_region **out);

extern void ivshm_notify_listeners(struct ivshm_region *iregion, int vector);

#endif
