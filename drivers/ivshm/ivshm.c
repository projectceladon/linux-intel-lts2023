// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/device.h>
#include <linux/string.h>
#include <linux/kobject.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/memremap.h>
#include <linux/eventfd.h>
#include <linux/slab.h>

#include "ivshm.h"

#define IVSHM_MAX_DEVICES		(1U << MINORBITS)

static int ivshm_major, ivshm_region_major;
static struct cdev *ivshm_cdev, *ivshm_region_cdev;
static DEFINE_IDR(ivshm_idr);
static DEFINE_IDR(ivshm_region_idr);

/* Protect idr accesses */
static DEFINE_MUTEX(minor_lock);

static const struct file_operations ivshm_fops;

/**
 * Class declaration
 */
static struct attribute *ivshm_attrs[] = {
	NULL,
};
ATTRIBUTE_GROUPS(ivshm);

static bool ivshm_class_registered;

static struct class ivshm_class = {
	.name = "ivshm",
	.dev_groups = ivshm_groups,
};

static struct attribute *ivshm_region_attrs[] = {
	NULL,
};
ATTRIBUTE_GROUPS(ivshm_region);

static struct class ivshm_region_class = {
	.name = "ivshm_region",
	.dev_groups = ivshm_region_groups,
};

/**
 * Device major/minor initialization
 */

static int ivshm_major_init(const char *name, const struct file_operations *fops,
	int *major, struct cdev **dev)
{
	struct cdev *cdev = NULL;
	dev_t ivshm_dev = 0;
	int result;

	result = alloc_chrdev_region(&ivshm_dev, 0, IVSHM_MAX_DEVICES, name);
	if (result)
		return result;

	result = -ENOMEM;
	cdev = cdev_alloc();
	if (!cdev)
		goto err_cdev_alloc;

	cdev->owner = THIS_MODULE;
	cdev->ops = fops;
	kobject_set_name(&cdev->kobj, "%s", name);

	result = cdev_add(cdev, ivshm_dev, IVSHM_MAX_DEVICES);
	if (result)
		goto err_cdev_add;

	*major = MAJOR(ivshm_dev);
	*dev = cdev;

	return 0;

err_cdev_add:
	kobject_put(&cdev->kobj);
	cdev_del(cdev);
err_cdev_alloc:
	unregister_chrdev_region(ivshm_dev, IVSHM_MAX_DEVICES);
	return result;
}

static void ivshm_major_cleanup(int major, struct cdev *cdev)
{
	unregister_chrdev_region(MKDEV(major, 0), IVSHM_MAX_DEVICES);
	cdev_del(cdev);
}

static int ivshm_get_minor(struct idr *idr, void *ptr)
{
	int retval;

	mutex_lock(&minor_lock);
	retval = idr_alloc(idr, ptr, 0, IVSHM_MAX_DEVICES, GFP_KERNEL);
	mutex_unlock(&minor_lock);
	return retval;
}

static void ivshm_free_minor(struct idr *idr, unsigned long minor)
{
	mutex_lock(&minor_lock);
	idr_remove(idr, minor);
	mutex_unlock(&minor_lock);
}

/**
 * Char device operations
 */

static const struct vm_operations_struct ivshm_vm_ops = {
#ifdef CONFIG_HAVE_IOREMAP_PROT
	.access = generic_access_phys,
#endif
};

static int ivshm_open(struct inode *inode, struct file *filep)
{
	struct ivshm_device *idev;
	struct ivshm_user *user;
	int err = 0;

	mutex_lock(&minor_lock);
	idev = idr_find(&ivshm_idr, iminor(inode));
	mutex_unlock(&minor_lock);
	if (!idev) {
		err = -ENODEV;
		goto out;
	}

	get_device(&idev->dev);

	if (!try_module_get(idev->owner)) {
		err = -ENODEV;
		goto out_put_device;
	}

	user = kmalloc(sizeof(*user), GFP_KERNEL);
	if (!user) {
		err = -ENOMEM;
		goto out_put_module;
	}

	user->idev = idev;
	filep->private_data = user;

	return 0;

out_put_module:
	module_put(idev->owner);
out_put_device:
	put_device(&idev->dev);
out:
	return err;
}

static int ivshm_release(struct inode *inode, struct file *filep)
{
	struct ivshm_user *user = filep->private_data;
	struct ivshm_device *idev = user->idev;
	int err = 0;

	kfree(user);
	module_put(idev->owner);
	put_device(&idev->dev);

	return err;
}

static int ivshm_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct ivshm_user *user = filep->private_data;
	struct ivshm_device *idev = user->idev;
	int err = 0;

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;

	vma->vm_ops = &ivshm_vm_ops;
	err = vm_iomap_memory(vma, idev->info->dev_ctrls, idev->info->dev_ctrls_len);

	return err;
}

static const struct file_operations ivshm_fops = {
	.owner		= THIS_MODULE,
	.open		= ivshm_open,
	.release	= ivshm_release,
	.mmap		= ivshm_mmap,
	.llseek		= noop_llseek,
};

static int ivshm_region_open(struct inode *inode, struct file *filep)
{
	struct ivshm_region *iregion;
	struct ivshm_region_user *user;
	int err = 0;

	mutex_lock(&minor_lock);
	iregion = idr_find(&ivshm_region_idr, iminor(inode));
	mutex_unlock(&minor_lock);
	if (!iregion) {
		err = -ENODEV;
		goto out;
	}

	get_device(&iregion->dev);

	if (!try_module_get(iregion->owner)) {
		err = -ENODEV;
		goto out_put_device;
	}

	user = kmalloc(sizeof(*user), GFP_KERNEL);
	if (!user) {
		err = -ENOMEM;
		goto out_put_module;
	}

	INIT_LIST_HEAD(&user->listeners);
	spin_lock_init(&user->listeners_list_lock);
	user->iregion = iregion;
	filep->private_data = user;

	i_size_write(inode, iregion->len);

	return 0;

out_put_module:
	module_put(iregion->owner);
out_put_device:
	put_device(&iregion->dev);
out:
	return err;
}

static int ivshm_region_release(struct inode *inode, struct file *filep)
{
	struct ivshm_region_user *user = filep->private_data;
	struct ivshm_region *iregion = user->iregion;
	struct ivshm_listener *listener, *next;
	int err = 0;

	spin_lock(&user->listeners_list_lock);
	list_for_each_entry_safe(listener, next, &user->listeners, region_user_list) {
		spin_lock(&iregion->listeners[listener->vector].list_lock);
		list_del(&iregion->listeners[listener->vector].list);
		spin_unlock(&iregion->listeners[listener->vector].list_lock);
		eventfd_ctx_put(listener->evt);
		kfree(listener);
	}
	spin_unlock(&user->listeners_list_lock);

	kfree(user);
	module_put(iregion->owner);
	put_device(&iregion->dev);

	return err;
}

static ssize_t ivshm_region_read(struct file *filep, char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct ivshm_region_user *user = filep->private_data;
	struct ivshm_region *iregion = user->iregion;
	ssize_t ret = 0;

	if (count == 0)
		return 0;

	if (*ppos > iregion->len || count > iregion->len)
		return 0;

	if ((*ppos + count) > iregion->len)
		count = iregion->len - *ppos;

	if (copy_to_user(buf, iregion->mem + *ppos, count))
		return -EFAULT;

	*ppos += count;

	return count;
}

static ssize_t ivshm_region_write(struct file *filep, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct ivshm_region_user *user = filep->private_data;
	struct ivshm_region *iregion = user->iregion;
	ssize_t ret = 0;

	if (count == 0)
		return 0;

	if (*ppos > iregion->len || count > iregion->len)
		return 0;

	if ((*ppos + count) > iregion->len)
		count = iregion->len - *ppos;

	if (copy_from_user(iregion->mem + *ppos, buf, count))
		return -EFAULT;

	*ppos += count;

	return count;
}

static int ivshm_region_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct ivshm_region_user *user = filep->private_data;
	struct ivshm_region *iregion = user->iregion;
	unsigned long pfn;
	int err = 0;

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;

	vma->vm_ops = &ivshm_vm_ops;

	pfn = PHYS_PFN(iregion->base);
	if (pfn_valid(pfn)) {
		err = remap_pfn_range(vma, vma->vm_start, pfn, vma->vm_end - vma->vm_start,
			vma->vm_page_prot);
	} else {
		WARN_ONCE(1, "Shared memory region at 0x%llx won't integrate with udmabuf.",
			iregion->base);
		err = vm_iomap_memory(vma, iregion->base, iregion->len);
	}

	return err;
}

static int ivshm_region_add_listener(struct ivshm_region_user *user,
	struct ivshm_region *iregion, unsigned long arg)
{
	struct ivshm_listener_data args;
	struct ivshm_listener *listener;
	struct eventfd_ctx *evt;

	if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
		return -EFAULT;

	if (args.vector >= iregion->nr_vectors)
		return -EINVAL;

	evt = eventfd_ctx_fdget(args.evt_fd);
	if (!evt)
		return -EINVAL;

	listener = kzalloc(sizeof(*listener), GFP_KERNEL);
	if (!listener)
		return -ENOMEM;

	INIT_LIST_HEAD(&listener->region_user_list);
	INIT_LIST_HEAD(&listener->region_list);

	listener->vector = args.vector;
	listener->evt = evt;

	spin_lock(&user->listeners_list_lock);
	spin_lock(&iregion->listeners[args.vector].list_lock);
	list_add(&iregion->listeners[args.vector].list, &listener->region_list);
	list_add(&user->listeners, &listener->region_user_list);
	spin_unlock(&iregion->listeners[args.vector].list_lock);
	spin_unlock(&user->listeners_list_lock);

	return 0;
}

static long ivshm_region_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct ivshm_region_user *user = filep->private_data;
	struct ivshm_region *iregion = user->iregion;
	int err;

	switch (cmd) {
	case IVSHM_ADD_LISTENER:
		err = ivshm_region_add_listener(user, iregion, arg);
		break;
	case IVSHM_GET_MMIO_SZ:
		return put_user(iregion->idev->info->dev_mmio_len,
			(unsigned long long __user *)arg) ? -EFAULT : 0;
	default:
		dev_err(&iregion->dev, "Unsupported ioctl command: 0x%x.\n", cmd);
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

const struct file_operations ivshm_region_fops = {
	.owner		= THIS_MODULE,
	.open		= ivshm_region_open,
	.release	= ivshm_region_release,
	.read		= ivshm_region_read,
	.write		= ivshm_region_write,
	.mmap		= ivshm_region_mmap,
	.poll		= NULL,
	.unlocked_ioctl	= ivshm_region_ioctl,
	.fasync		= NULL,
	.llseek		= default_llseek,
};

struct page *ivshm_region_offset_to_page(struct file *filep, pgoff_t pgoff)
{
	struct ivshm_region_user *user = filep->private_data;
	struct ivshm_region *iregion = user->iregion;
	unsigned long pfn;
	int err;

	pfn = PHYS_PFN(iregion->base) + pgoff;
	if (!pfn_valid(pfn)) {
		err = -EINVAL;
		goto err;
	}

	return pfn_to_page(pfn);

err:
	return ERR_PTR(err);
}

static void ivshm_region_page_free(struct page *page)
{
	/* No op here. Only to suppress the warning in free_zone_device_page(). */
}

static const struct dev_pagemap_ops ivshm_region_pgmap_ops = {
	.page_free		= ivshm_region_page_free,
};

/**
 * Interrupt notifier
 */
void ivshm_notify_listeners(struct ivshm_region *iregion, int vector)
{
	struct ivshm_listener *listener;

	spin_lock(&iregion->listeners[vector].list_lock);
	list_for_each_entry(listener, &iregion->listeners[vector].list, region_list) {
		eventfd_signal(listener->evt, 1);
	}
	spin_unlock(&iregion->listeners[vector].list_lock);
}

/**
 * Device registration
 */

static void devm_ivshm_unregister_device(struct device *dev, void *res)
{
	ivshm_unregister_device(*(struct ivshm_info **)res);
}

static void ivshm_device_release(struct device *dev)
{
	struct ivshm_device *idev = dev_get_drvdata(dev);

	kfree(idev);
}

static void ivshm_region_dev_release(struct device *dev)
{
	struct ivshm_region *iregion = dev_get_drvdata(dev);

	kfree(iregion);
}

int __ivshm_register_device(struct module *owner,
			    struct device *parent,
			    struct ivshm_info *info)
{
	struct ivshm_device *idev;
	int ret;

	idev = kzalloc(sizeof(*idev), GFP_KERNEL);
	if (!idev)
		return -ENOMEM;

	idev->owner = owner;
	idev->info = info;
	INIT_LIST_HEAD(&idev->regions);

	idev->minor = ivshm_get_minor(&ivshm_idr, idev);
	if (idev->minor < 0) {
		ret = idev->minor;
		kfree(idev);
		return ret;
	}

	device_initialize(&idev->dev);
	idev->dev.devt = MKDEV(ivshm_major, idev->minor);
	idev->dev.class = &ivshm_class;
	idev->dev.parent = parent;
	idev->dev.release = ivshm_device_release;
	dev_set_drvdata(&idev->dev, idev);

	ret = dev_set_name(&idev->dev, "ivshm%d", idev->minor);
	if (ret)
		goto err_device_create;

	ret = device_add(&idev->dev);
	if (ret)
		goto err_device_create;

	info->ivshm_dev = idev;

	return 0;

err_device_create:
	ivshm_free_minor(&ivshm_idr, idev->minor);
	put_device(&idev->dev);
	return ret;
}

int __devm_ivshm_register_device(struct module *owner,
				 struct device *parent,
				 struct ivshm_info *info)
{
	struct ivshm_info **ptr;
	int ret;

	ptr = devres_alloc(devm_ivshm_unregister_device, sizeof(struct ivshm_info *),
			   GFP_KERNEL);
	if (!ptr)
		return -ENOMEM;

	*ptr = info;
	ret = __ivshm_register_device(owner, parent, info);
	if (ret) {
		devres_free(ptr);
		return ret;
	}

	devres_add(parent, ptr);

	return 0;
}
EXPORT_SYMBOL_GPL(__devm_ivshm_register_device);

void ivshm_unregister_device(struct ivshm_info *info)
{
	struct ivshm_device *idev;
	struct ivshm_region *iregion, *next;

	if (!info || !info->ivshm_dev)
		return;

	idev = info->ivshm_dev;

	list_for_each_entry_safe(iregion, next, &idev->regions, list) {
		kfree(iregion->listeners);
		device_unregister(&iregion->dev);
		ivshm_free_minor(&ivshm_region_idr, iregion->minor);
		list_del(&iregion->list);
		kfree(iregion);
	}

	device_unregister(&idev->dev);

	ivshm_free_minor(&ivshm_idr, idev->minor);
}
EXPORT_SYMBOL_GPL(ivshm_unregister_device);

int
ivshm_register_region(struct ivshm_device *idev, const char *name,
		      resource_size_t base, resource_size_t len,
		      size_t nr_vectors, struct ivshm_region **out)
{
	struct ivshm_region *iregion;
	struct dev_pagemap *pgmap;
	int ret, i;

	iregion = kzalloc(sizeof(*iregion), GFP_KERNEL);
	if (!iregion)
		return -ENOMEM;

	strncpy(iregion->name, name, IVSHM_REGION_NAME_LEN);
	iregion->owner = THIS_MODULE;
	iregion->idev = idev;
	INIT_LIST_HEAD(&iregion->list);

	iregion->minor = ivshm_get_minor(&ivshm_region_idr, iregion);
	if (iregion->minor < 0) {
		ret = iregion->minor;
		goto err_get_minor;
	}

	iregion->listeners = kcalloc(nr_vectors, sizeof(*iregion->listeners), GFP_KERNEL);
	if (!iregion->listeners) {
		ret = -ENOMEM;
		goto err_alloc_lists;
	}

	for (i = 0; i < nr_vectors; i++) {
		INIT_LIST_HEAD(&iregion->listeners[i].list);
		spin_lock_init(&iregion->listeners[i].list_lock);
	}

	device_initialize(&iregion->dev);
	iregion->dev.devt = MKDEV(ivshm_region_major, iregion->minor);
	iregion->dev.class = &ivshm_region_class;
	iregion->dev.parent = idev->dev.parent;
	iregion->dev.release = ivshm_region_dev_release;
	dev_set_drvdata(&iregion->dev, iregion);

	ret = dev_set_name(&iregion->dev, "ivshm%d.%s", idev->minor, iregion->name);
	if (ret)
		goto err_device_create;

	ret = device_add(&iregion->dev);
	if (ret)
		goto err_device_create;

	iregion->base = base;
	iregion->len = len;
	iregion->nr_vectors = nr_vectors;

	pgmap = devm_kzalloc(&iregion->dev, sizeof(*pgmap), GFP_KERNEL);
	if (!pgmap)
		goto err_memremap;

	pgmap->type = MEMORY_DEVICE_FS_DAX;

	pgmap->range = (struct range) {
		.start = (phys_addr_t) iregion->base,
		.end = (phys_addr_t) iregion->base + iregion->len - 1,
	};
	pgmap->nr_range = 1;
	pgmap->ops = &ivshm_region_pgmap_ops;

	iregion->mem = devm_memremap_pages(&iregion->dev, pgmap);
	if (IS_ERR(iregion->mem)) {
		ret = PTR_ERR(iregion->mem);
		goto err_memremap;
	}

	list_add(&iregion->list, &idev->regions);
	if (out)
		*out = iregion;

	return 0;

err_memremap:
	device_del(&iregion->dev);
err_device_create:
	put_device(&iregion->dev);
	kfree(iregion->listeners);
err_alloc_lists:
	ivshm_free_minor(&ivshm_region_idr, iregion->minor);
err_get_minor:
	kfree(iregion);
	return ret;
}


/**
 * Module and class initialization
 */

static int init_ivshm_class(void)
{
	int ret;

	/* This is the first time in here, set everything up properly */
	ret = ivshm_major_init("ivshm", &ivshm_fops, &ivshm_major, &ivshm_cdev);
	if (ret)
		goto exit;

	ret = ivshm_major_init("ivshm_region", &ivshm_region_fops,
		&ivshm_region_major, &ivshm_region_cdev);
	if (ret)
		goto err_ivshm_region_init;

	ret = class_register(&ivshm_class);
	if (ret) {
		printk(KERN_ERR "class_register failed for ivshm\n");
		goto err_class_register;
	}

	ret = class_register(&ivshm_region_class);
	if (ret) {
		printk(KERN_ERR "class_register failed for ivshm_region\n");
		goto err_region_class_register;
	}

	ivshm_class_registered = true;

	return 0;

err_region_class_register:
	class_unregister(&ivshm_class);
err_class_register:
	ivshm_major_cleanup(ivshm_region_major, ivshm_region_cdev);
err_ivshm_region_init:
	ivshm_major_cleanup(ivshm_major, ivshm_cdev);
exit:
	return ret;
}

static void release_ivshm_class(void)
{
	ivshm_class_registered = false;
	class_unregister(&ivshm_class);
	class_unregister(&ivshm_region_class);
	ivshm_major_cleanup(ivshm_major, ivshm_cdev);
	ivshm_major_cleanup(ivshm_region_major, ivshm_region_cdev);
}

static int __init ivshm_init(void)
{
	return init_ivshm_class();
}

static void __exit ivshm_exit(void)
{
	release_ivshm_class();
	idr_destroy(&ivshm_region_idr);
	idr_destroy(&ivshm_idr);
}

module_init(ivshm_init)
module_exit(ivshm_exit)
MODULE_LICENSE("GPL v2");
