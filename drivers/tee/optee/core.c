// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015, Linaro Limited
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/arm-smccc.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#if defined(CONFIG_OPTEE_IVSHMEM)
#include <linux/pci.h>
#include <linux/pci_regs.h>
#endif
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/tee_drv.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#if defined(CONFIG_OPTEE_VSOCK)
#include <linux/semaphore.h>
#include <net/sock.h>
#include <uapi/linux/vm_sockets.h>
#endif
#include "optee_bench.h"
#include "optee_private.h"
#include "optee_smc.h"
#include "shm_pool.h"

#define DRIVER_NAME "optee"

#define OPTEE_SHM_NUM_PRIV_PAGES	CONFIG_OPTEE_SHM_NUM_PRIV_PAGES

#if defined(CONFIG_OPTEE_HV_IKGT)
#define OPTEE_VMCALL_SMC       0x6F707400
#endif

#if defined(CONFIG_OPTEE_VSOCK)
#define VIRTIO_SHM_COPY_REQ 	0x5a5a5a5a
#define VIRTIO_SMC_BUFFER_LEN	0x40
#define VIRTIO_VSOCK_BUFF_LEN	0x10000
#define VIRTIO_VSOCK_TEE_PORT	1234

static struct socket *host_smc_sock = NULL;
static struct socket *tee_sock = NULL;
unsigned long optee_shm_offset = 0;

static DEFINE_SEMAPHORE(optee_smc_lock);
#endif

#if defined(CONFIG_OPTEE_IVSHMEM)
#define PCI_DRV_NAME	"optee-ivshmem"

#define IVPOSITION_OFF	0x08
#define DOORBELL_OFF	0x0C

#define OPTEE_SHM_QUEUE_SIZE	64

#define OPTEE_HANDLE_DONE	0xa5a5a5a5

#define OPTEE_SHM_SMC_SIZE	0x200000

struct ivshmem_private {
	struct pci_dev *dev;

	u8                  revision;
	u32                 ivposition;

	u8 __iomem          *regs_addr;
	u8                  *base_addr;
	u32                 *msix_addr;

	unsigned long       bar0_addr;
	unsigned long       bar0_len;
	unsigned long       bar1_addr;
	unsigned long       bar1_len;
	unsigned long       bar2_addr;
	unsigned long       bar2_len;

	char                (*msix_names)[256];
	struct msix_entry   *msix_entries;
	int                 nvectors;
};

static struct ivshmem_private g_ivshmem_dev;

static struct pci_device_id ivshmem_id_table[] = {
    { 0x1af4, 0x1110, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
    { 0 },
};
MODULE_DEVICE_TABLE(pci, ivshmem_id_table);

struct optee_smc_args {
	u64 a0;
	u64 a1;
	u64 a2;
	u64 a3;
	u64 a4;
	u64 a5;
	u64 a6;
	u64 a7;
	u64 a8;
} __packed;

struct optee_vm_ids {
	u32 ree_id;
	u32 tee_id;
} __packed;

struct optee_smc_ring {
	u16 head;
	u16 tail;
	u16 ring[OPTEE_SHM_QUEUE_SIZE];
} __packed;

static struct optee_smc_args *g_smc_args = NULL;
static struct optee_smc_ring *g_smc_avail_ring = NULL;
static struct optee_smc_ring *g_smc_used_ring = NULL;
static struct optee_vm_ids *g_smc_vm_ids = NULL;

unsigned long optee_shm_offset = 0;

//spinlock used to protect SMC ring operations
static DEFINE_SPINLOCK(smc_ring_lock);

//SMC wait queue, waiting for interrupt from TEE
static DECLARE_WAIT_QUEUE_HEAD(optee_smc_queue);
#endif

/**
 * optee_from_msg_param() - convert from OPTEE_MSG parameters to
 *			    struct tee_param
 * @params:	subsystem internal parameter representation
 * @num_params:	number of elements in the parameter arrays
 * @msg_params:	OPTEE_MSG parameters
 * Returns 0 on success or <0 on failure
 */
int optee_from_msg_param(struct tee_param *params, size_t num_params,
			 const struct optee_msg_param *msg_params)
{
	int rc;
	size_t n;
	struct tee_shm *shm;
	phys_addr_t pa;
#if defined(CONFIG_OPTEE_VSOCK)
	void *va = NULL;
#endif

	for (n = 0; n < num_params; n++) {
		struct tee_param *p = params + n;
		const struct optee_msg_param *mp = msg_params + n;
		u32 attr = mp->attr & OPTEE_MSG_ATTR_TYPE_MASK;

		switch (attr) {
		case OPTEE_MSG_ATTR_TYPE_NONE:
			p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
			memset(&p->u, 0, sizeof(p->u));
			break;
		case OPTEE_MSG_ATTR_TYPE_VALUE_INPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_INOUT:
			p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT +
				  attr - OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
			p->u.value.a = mp->u.value.a;
			p->u.value.b = mp->u.value.b;
			p->u.value.c = mp->u.value.c;
			break;
		case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
			p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT +
				  attr - OPTEE_MSG_ATTR_TYPE_TMEM_INPUT;
			p->u.memref.size = mp->u.tmem.size;
			shm = (struct tee_shm *)(unsigned long)
				mp->u.tmem.shm_ref;
			if (!shm) {
				p->u.memref.shm_offs = 0;
				p->u.memref.shm = NULL;
				break;
			}
			rc = tee_shm_get_pa(shm, 0, &pa);
			if (rc)
				return rc;
#if defined(CONFIG_OPTEE_VSOCK)
			pa = pa - optee_shm_offset;
			//Here we don't distinguish output or input attribute, just copy
			if (mp->u.tmem.size < VIRTIO_VSOCK_BUFF_LEN) {
				va = tee_shm_get_va(shm, mp->u.tmem.buf_ptr - pa);
				if (!va)
					return -EINVAL;
				rc = copy_shm(va, mp->u.tmem.buf_ptr, mp->u.tmem.size);
				if (rc < 0) {
					pr_err("%s: copy_shm 0x%llx/0x%llx failed\n", __func__,
						mp->u.tmem.buf_ptr, mp->u.tmem.size);
					return -EINVAL;
				}
			}
#elif defined(CONFIG_OPTEE_IVSHMEM)
			pa = pa - optee_shm_offset;
#endif
			p->u.memref.shm_offs = mp->u.tmem.buf_ptr - pa;
			p->u.memref.shm = shm;
			break;
		case OPTEE_MSG_ATTR_TYPE_RMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_RMEM_INOUT:
			p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT +
				  attr - OPTEE_MSG_ATTR_TYPE_RMEM_INPUT;
			p->u.memref.size = mp->u.rmem.size;
			shm = (struct tee_shm *)(unsigned long)
				mp->u.rmem.shm_ref;

			if (!shm) {
				p->u.memref.shm_offs = 0;
				p->u.memref.shm = NULL;
				break;
			}
			p->u.memref.shm_offs = mp->u.rmem.offs;
			p->u.memref.shm = shm;

			break;

		default:
			return -EINVAL;
		}
	}
	return 0;
}

static int to_msg_param_tmp_mem(struct optee_msg_param *mp,
				const struct tee_param *p)
{
	int rc;
	phys_addr_t pa;

	mp->attr = OPTEE_MSG_ATTR_TYPE_TMEM_INPUT + p->attr -
		   TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;

	mp->u.tmem.shm_ref = (unsigned long)p->u.memref.shm;
	mp->u.tmem.size = p->u.memref.size;

	if (!p->u.memref.shm) {
		mp->u.tmem.buf_ptr = 0;
		return 0;
	}

	rc = tee_shm_get_pa(p->u.memref.shm, p->u.memref.shm_offs, &pa);
	if (rc)
		return rc;
#if defined(CONFIG_OPTEE_VSOCK) || defined(CONFIG_OPTEE_IVSHMEM)
	pa = pa - optee_shm_offset;
#endif

	mp->u.tmem.buf_ptr = pa;
	mp->attr |= OPTEE_MSG_ATTR_CACHE_PREDEFINED <<
		    OPTEE_MSG_ATTR_CACHE_SHIFT;

	return 0;
}

static int to_msg_param_reg_mem(struct optee_msg_param *mp,
				const struct tee_param *p)
{
	mp->attr = OPTEE_MSG_ATTR_TYPE_RMEM_INPUT + p->attr -
		   TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;

	mp->u.rmem.shm_ref = (unsigned long)p->u.memref.shm;
	mp->u.rmem.size = p->u.memref.size;
	mp->u.rmem.offs = p->u.memref.shm_offs;
	return 0;
}

/**
 * optee_to_msg_param() - convert from struct tee_params to OPTEE_MSG parameters
 * @msg_params:	OPTEE_MSG parameters
 * @num_params:	number of elements in the parameter arrays
 * @params:	subsystem itnernal parameter representation
 * Returns 0 on success or <0 on failure
 */
int optee_to_msg_param(struct optee_msg_param *msg_params, size_t num_params,
		       const struct tee_param *params)
{
	int rc;
	size_t n;

	for (n = 0; n < num_params; n++) {
		const struct tee_param *p = params + n;
		struct optee_msg_param *mp = msg_params + n;

		switch (p->attr) {
		case TEE_IOCTL_PARAM_ATTR_TYPE_NONE:
			mp->attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
			memset(&mp->u, 0, sizeof(mp->u));
			break;
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT:
			mp->attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT + p->attr -
				   TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
			mp->u.value.a = p->u.value.a;
			mp->u.value.b = p->u.value.b;
			mp->u.value.c = p->u.value.c;
			break;
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
			if (tee_shm_is_registered(p->u.memref.shm))
				rc = to_msg_param_reg_mem(mp, p);
			else
				rc = to_msg_param_tmp_mem(mp, p);
			if (rc)
				return rc;
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

static void optee_get_version(struct tee_device *teedev,
			      struct tee_ioctl_version_data *vers)
{
	struct tee_ioctl_version_data v = {
		.impl_id = TEE_IMPL_ID_OPTEE,
		.impl_caps = TEE_OPTEE_CAP_TZ,
		.gen_caps = TEE_GEN_CAP_GP,
	};
	struct optee *optee = tee_get_drvdata(teedev);

	if (optee->sec_caps & OPTEE_SMC_SEC_CAP_DYNAMIC_SHM)
		v.gen_caps |= TEE_GEN_CAP_REG_MEM;
	if (optee->sec_caps & OPTEE_SMC_SEC_CAP_MEMREF_NULL)
		v.gen_caps |= TEE_GEN_CAP_MEMREF_NULL;
	*vers = v;
}

static void optee_bus_scan(struct work_struct *work)
{
	WARN_ON(optee_enumerate_devices(PTA_CMD_GET_DEVICES_SUPP));
}

static int optee_open(struct tee_context *ctx)
{
	struct optee_context_data *ctxdata;
	struct tee_device *teedev = ctx->teedev;
	struct optee *optee = tee_get_drvdata(teedev);

	ctxdata = kzalloc(sizeof(*ctxdata), GFP_KERNEL);
	if (!ctxdata)
		return -ENOMEM;

	if (teedev == optee->supp_teedev) {
		bool busy = true;

		mutex_lock(&optee->supp.mutex);
		if (!optee->supp.ctx) {
			busy = false;
			optee->supp.ctx = ctx;
		}
		mutex_unlock(&optee->supp.mutex);
		if (busy) {
			kfree(ctxdata);
			return -EBUSY;
		}

		if (!optee->scan_bus_done) {
			INIT_WORK(&optee->scan_bus_work, optee_bus_scan);
			optee->scan_bus_wq = create_workqueue("optee_bus_scan");
			if (!optee->scan_bus_wq) {
				kfree(ctxdata);
				return -ECHILD;
			}
			queue_work(optee->scan_bus_wq, &optee->scan_bus_work);
			optee->scan_bus_done = true;
		}
	}
	mutex_init(&ctxdata->mutex);
	INIT_LIST_HEAD(&ctxdata->sess_list);

	if (optee->sec_caps & OPTEE_SMC_SEC_CAP_MEMREF_NULL)
		ctx->cap_memref_null  = true;
	else
		ctx->cap_memref_null = false;

	ctx->data = ctxdata;
	return 0;
}

static void optee_release(struct tee_context *ctx)
{
	struct optee_context_data *ctxdata = ctx->data;
	struct tee_device *teedev = ctx->teedev;
	struct optee *optee = tee_get_drvdata(teedev);
	struct tee_shm *shm;
	struct optee_msg_arg *arg = NULL;
	phys_addr_t parg;
	struct optee_session *sess;
	struct optee_session *sess_tmp;

	if (!ctxdata)
		return;

	shm = tee_shm_alloc(ctx, sizeof(struct optee_msg_arg), TEE_SHM_MAPPED);
	if (!IS_ERR(shm)) {
		arg = tee_shm_get_va(shm, 0);
		/*
		 * If va2pa fails for some reason, we can't call into
		 * secure world, only free the memory. Secure OS will leak
		 * sessions and finally refuse more sessions, but we will
		 * at least let normal world reclaim its memory.
		 */
		if (!IS_ERR(arg))
			if (tee_shm_va2pa(shm, arg, &parg))
				arg = NULL; /* prevent usage of parg below */
	}

	list_for_each_entry_safe(sess, sess_tmp, &ctxdata->sess_list,
				 list_node) {
		list_del(&sess->list_node);
		if (!IS_ERR_OR_NULL(arg)) {
			memset(arg, 0, sizeof(*arg));
			arg->cmd = OPTEE_MSG_CMD_CLOSE_SESSION;
			arg->session = sess->session_id;
#if defined(CONFIG_OPTEE_VSOCK)
			arg->num_params = 0;
#endif
			optee_do_call_with_arg(ctx, parg);
		}
		kfree(sess);
	}
	kfree(ctxdata);

	if (!IS_ERR(shm))
		tee_shm_free(shm);

	ctx->data = NULL;

	if (teedev == optee->supp_teedev) {
		if (optee->scan_bus_wq) {
			destroy_workqueue(optee->scan_bus_wq);
			optee->scan_bus_wq = NULL;
		}
		optee_supp_release(&optee->supp);
	}
}

static const struct tee_driver_ops optee_ops = {
	.get_version = optee_get_version,
	.open = optee_open,
	.release = optee_release,
	.open_session = optee_open_session,
	.close_session = optee_close_session,
	.invoke_func = optee_invoke_func,
	.cancel_req = optee_cancel_req,
	.shm_register = optee_shm_register,
	.shm_unregister = optee_shm_unregister,
};

static const struct tee_desc optee_desc = {
	.name = DRIVER_NAME "-clnt",
	.ops = &optee_ops,
	.owner = THIS_MODULE,
};

static const struct tee_driver_ops optee_supp_ops = {
	.get_version = optee_get_version,
	.open = optee_open,
	.release = optee_release,
	.supp_recv = optee_supp_recv,
	.supp_send = optee_supp_send,
	.shm_register = optee_shm_register_supp,
	.shm_unregister = optee_shm_unregister_supp,
};

static const struct tee_desc optee_supp_desc = {
	.name = DRIVER_NAME "-supp",
	.ops = &optee_supp_ops,
	.owner = THIS_MODULE,
	.flags = TEE_DESC_PRIVILEGED,
};

static bool optee_msg_api_uid_is_optee_api(optee_invoke_fn *invoke_fn)
{
	struct arm_smccc_res res;

	invoke_fn(OPTEE_SMC_CALLS_UID, 0, 0, 0, 0, 0, 0, 0, &res);

	if (res.a0 == OPTEE_MSG_UID_0 && res.a1 == OPTEE_MSG_UID_1 &&
	    res.a2 == OPTEE_MSG_UID_2 && res.a3 == OPTEE_MSG_UID_3)
		return true;
	return false;
}

static void optee_msg_get_os_revision(optee_invoke_fn *invoke_fn)
{
	union {
		struct arm_smccc_res smccc;
		struct optee_smc_call_get_os_revision_result result;
	} res = {
		.result = {
			.build_id = 0
		}
	};

	invoke_fn(OPTEE_SMC_CALL_GET_OS_REVISION, 0, 0, 0, 0, 0, 0, 0,
		  &res.smccc);

	if (res.result.build_id)
		pr_info("revision %lu.%lu (%08lx)", res.result.major,
			res.result.minor, res.result.build_id);
	else
		pr_info("revision %lu.%lu", res.result.major, res.result.minor);
}

static bool optee_msg_api_revision_is_compatible(optee_invoke_fn *invoke_fn)
{
	union {
		struct arm_smccc_res smccc;
		struct optee_smc_calls_revision_result result;
	} res;

	invoke_fn(OPTEE_SMC_CALLS_REVISION, 0, 0, 0, 0, 0, 0, 0, &res.smccc);

	if (res.result.major == OPTEE_MSG_REVISION_MAJOR &&
	    (int)res.result.minor >= OPTEE_MSG_REVISION_MINOR)
		return true;
	return false;
}

static bool optee_msg_exchange_capabilities(optee_invoke_fn *invoke_fn,
					    u32 *sec_caps)
{
	union {
		struct arm_smccc_res smccc;
		struct optee_smc_exchange_capabilities_result result;
	} res;
	u32 a1 = 0;

	/*
	 * TODO This isn't enough to tell if it's UP system (from kernel
	 * point of view) or not, is_smp() returns the the information
	 * needed, but can't be called directly from here.
	 */
	if (!IS_ENABLED(CONFIG_SMP) || nr_cpu_ids == 1)
		a1 |= OPTEE_SMC_NSEC_CAP_UNIPROCESSOR;

	invoke_fn(OPTEE_SMC_EXCHANGE_CAPABILITIES, a1, 0, 0, 0, 0, 0, 0,
		  &res.smccc);

	if (res.result.status != OPTEE_SMC_RETURN_OK)
		return false;

	*sec_caps = res.result.capabilities;
	return true;
}

static struct tee_shm_pool *optee_config_dyn_shm(void)
{
	struct tee_shm_pool_mgr *priv_mgr;
	struct tee_shm_pool_mgr *dmabuf_mgr;
	void *rc;

	rc = optee_shm_pool_alloc_pages();
	if (IS_ERR(rc))
		return rc;
	priv_mgr = rc;

	rc = optee_shm_pool_alloc_pages();
	if (IS_ERR(rc)) {
		tee_shm_pool_mgr_destroy(priv_mgr);
		return rc;
	}
	dmabuf_mgr = rc;

	rc = tee_shm_pool_alloc(priv_mgr, dmabuf_mgr);
	if (IS_ERR(rc)) {
		tee_shm_pool_mgr_destroy(priv_mgr);
		tee_shm_pool_mgr_destroy(dmabuf_mgr);
	}

	return rc;
}

static struct tee_shm_pool *
optee_config_shm_memremap(optee_invoke_fn *invoke_fn, void **memremaped_shm)
{
	union {
		struct arm_smccc_res smccc;
		struct optee_smc_get_shm_config_result result;
	} res;
	unsigned long vaddr;
	phys_addr_t paddr;
	size_t size;
	phys_addr_t begin;
	phys_addr_t end;
	void *va;
	struct tee_shm_pool_mgr *priv_mgr;
	struct tee_shm_pool_mgr *dmabuf_mgr;
	void *rc;
	const int sz = OPTEE_SHM_NUM_PRIV_PAGES * PAGE_SIZE;

	invoke_fn(OPTEE_SMC_GET_SHM_CONFIG, 0, 0, 0, 0, 0, 0, 0, &res.smccc);
	if (res.result.status != OPTEE_SMC_RETURN_OK) {
		pr_err("static shm service not available\n");
		return ERR_PTR(-ENOENT);
	}

	if (res.result.settings != OPTEE_SMC_SHM_CACHED) {
		pr_err("only normal cached shared memory supported\n");
		return ERR_PTR(-EINVAL);
	}

	begin = roundup(res.result.start, PAGE_SIZE);
	end = rounddown(res.result.start + res.result.size, PAGE_SIZE);
	size = end - begin;

#if defined(CONFIG_OPTEE_VSOCK)
	va = kmalloc(size, GFP_KERNEL);
	if (!va) {
		pr_err("shared memory 0x%lx kmalloc failed\n", size);
		return ERR_PTR(-EINVAL);
	}
	paddr = virt_to_phys(va);
	optee_shm_offset = paddr - begin;
#elif defined(CONFIG_OPTEE_IVSHMEM)
	paddr = g_ivshmem_dev.bar2_addr + OPTEE_SHM_SMC_SIZE;
	optee_shm_offset = paddr - begin;
	pr_info("shared memory from tee 0x%llx/0x%lx/0x%llx/0x%lx\n",
		begin, size, paddr, optee_shm_offset);
#else
	paddr = begin;
#endif

	if (size < 2 * OPTEE_SHM_NUM_PRIV_PAGES * PAGE_SIZE) {
		pr_err("too small shared memory area\n");
		return ERR_PTR(-EINVAL);
	}

#if !defined(CONFIG_OPTEE_VSOCK)
	va = memremap(paddr, size, MEMREMAP_WB);
	if (!va) {
		pr_err("shared memory ioremap failed\n");
		return ERR_PTR(-EINVAL);
	}
#endif
	vaddr = (unsigned long)va;

	rc = tee_shm_pool_mgr_alloc_res_mem(vaddr, paddr, sz,
					    3 /* 8 bytes aligned */);
	if (IS_ERR(rc))
		goto err_memunmap;
	priv_mgr = rc;

	vaddr += sz;
	paddr += sz;
	size -= sz;

	rc = tee_shm_pool_mgr_alloc_res_mem(vaddr, paddr, size, PAGE_SHIFT);
	if (IS_ERR(rc))
		goto err_free_priv_mgr;
	dmabuf_mgr = rc;

	rc = tee_shm_pool_alloc(priv_mgr, dmabuf_mgr);
	if (IS_ERR(rc))
		goto err_free_dmabuf_mgr;

	*memremaped_shm = va;

	return rc;

err_free_dmabuf_mgr:
	tee_shm_pool_mgr_destroy(dmabuf_mgr);
err_free_priv_mgr:
	tee_shm_pool_mgr_destroy(priv_mgr);
err_memunmap:
	memunmap(va);
	return rc;
}

/* Simple wrapper functions to be able to use a function pointer */

#if defined(CONFIG_OPTEE_HV_IKGT)
struct optee_smc_interface {
    unsigned long args[5];
};

static long optee_smc(void *args)
{
    struct optee_smc_interface *p_args = args;
    __asm__ __volatile__(
	"vmcall;"
	: "=D"(p_args->args[0]), "=S"(p_args->args[1]),
	"=d"(p_args->args[2]), "=b"(p_args->args[3])
	: "a"(OPTEE_VMCALL_SMC), "D"(p_args->args[0]), "S"(p_args->args[1]),
	"d"(p_args->args[2]), "b"(p_args->args[3]), "c"(p_args->args[4])
	);

	return 0;
}

/* Simple wrapper functions to be able to use a function pointer */
static void optee_smccc_smc(unsigned long a0, unsigned long a1,
			    unsigned long a2, unsigned long a3,
			    unsigned long a4, unsigned long a5,
			    unsigned long a6, unsigned long a7,
			    struct arm_smccc_res *res)
{
	int ret = 0;
	struct optee_smc_interface s;

	s.args[0] = a0;
	s.args[1] = a1;
	s.args[2] = a2;
	s.args[3] = a3;
	//TODO: use two registers to save a4 and a5 seperately later.
	s.args[4] = a5 << 32 | a4;

	ret = work_on_cpu(0, optee_smc, (void *)&s);
	if (ret) {
		pr_err("%s: work_on_cpu failed: %d\n", __func__, ret);
	}

	res->a0 = s.args[0];
	res->a1 = s.args[1];
	res->a2 = s.args[2];
	res->a3 = s.args[3];
}
#elif defined(CONFIG_OPTEE_VSOCK)
static void optee_smccc_smc(unsigned long a0, unsigned long a1,
			    unsigned long a2, unsigned long a3,
			    unsigned long a4, unsigned long a5,
			    unsigned long a6, unsigned long a7,
			    struct arm_smccc_res *res)
{
	struct msghdr msg;
	unsigned long buffer[8];
	struct kvec iov[2];
	int rc;

	if (down_interruptible(&optee_smc_lock)) {
		pr_warn("optee_smccc_smc not get lock\n");
		return;
	}

	buffer[0] = a0;
	buffer[1] = a1;
	buffer[2] = a2;
	buffer[3] = a3;
	buffer[4] = a4;
	buffer[5] = a5;
	buffer[6] = a6;
	buffer[7] = a7;

	memset(&msg, 0, sizeof(msg));
	iov[0].iov_base = buffer;
	iov[0].iov_len = VIRTIO_SMC_BUFFER_LEN;
	if (a0 == OPTEE_SMC_RETURN_RPC_COPY_SHM) {
		iov[1].iov_base = phys_to_virt(a1 + optee_shm_offset);
		iov[1].iov_len = a2;
		buffer[0] = OPTEE_SMC_CALL_RETURN_FROM_RPC;
		rc = kernel_sendmsg(tee_sock, &msg, iov, 2, (a2 + VIRTIO_SMC_BUFFER_LEN));
	} else {
		rc = kernel_sendmsg(tee_sock, &msg, iov, 1, VIRTIO_SMC_BUFFER_LEN);
	}

	memset(&msg, 0, sizeof(msg));
	iov[0].iov_base = buffer;
	iov[0].iov_len = VIRTIO_SMC_BUFFER_LEN;
	rc = kernel_recvmsg(tee_sock, &msg, iov, 1, VIRTIO_SMC_BUFFER_LEN, MSG_WAITFORONE);

	memcpy(res, buffer, sizeof(struct arm_smccc_res));

	up(&optee_smc_lock);
}

int copy_shm(void* data, phys_addr_t paddr, size_t size)
{
	struct msghdr msg;
	unsigned long buffer[8];
	struct kvec iov[2];
	int rc;

	if (down_interruptible(&optee_smc_lock)) {
		pr_warn("copy_shm not get lock\n");
		return -EINVAL;
	}

	buffer[0] = VIRTIO_SHM_COPY_REQ;
	buffer[1] = paddr;
	buffer[2] = size;
	buffer[3] = 0;
	buffer[4] = 0;
	buffer[5] = 0;
	buffer[6] = 0;
	buffer[7] = 0;

	memset(&msg, 0, sizeof(msg));
	iov[0].iov_base = buffer;
	iov[0].iov_len = VIRTIO_SMC_BUFFER_LEN;
	rc = kernel_sendmsg(tee_sock, &msg, iov, 1, VIRTIO_SMC_BUFFER_LEN);
	if (rc < 0)
		goto err;

	memset(&msg, 0, sizeof(msg));
	iov[1].iov_base = data;
	iov[1].iov_len = size;
	rc = kernel_recvmsg(tee_sock, &msg, iov, 2, (size + VIRTIO_SMC_BUFFER_LEN), MSG_WAITFORONE);

err:
	up(&optee_smc_lock);
	return rc;
}
#elif defined(CONFIG_OPTEE_IVSHMEM)
static void optee_smccc_smc(unsigned long a0, unsigned long a1,
			    unsigned long a2, unsigned long a3,
			    unsigned long a4, unsigned long a5,
			    unsigned long a6, unsigned long a7,
			    struct arm_smccc_res *res)
{
	u16 index = 0;

	spin_lock(&smc_ring_lock);

	index = g_smc_avail_ring->ring[g_smc_avail_ring->head];
	if (index == OPTEE_SHM_QUEUE_SIZE) {
		//avail ring is empty
		spin_unlock(&smc_ring_lock);
		res->a0 = OPTEE_SMC_RETURN_ETHREAD_LIMIT;
		return;
	}

	g_smc_avail_ring->ring[g_smc_avail_ring->head] = OPTEE_SHM_QUEUE_SIZE;

	g_smc_avail_ring->head = (g_smc_avail_ring->head + 1) % OPTEE_SHM_QUEUE_SIZE;

	spin_unlock(&smc_ring_lock);

	g_smc_args[index].a0  = a0;
	g_smc_args[index].a1  = a1;
	g_smc_args[index].a2  = a2;
	g_smc_args[index].a3  = a3;
	g_smc_args[index].a4  = a4;
	g_smc_args[index].a5  = a5;
	g_smc_args[index].a6  = a6;
	g_smc_args[index].a7  = a7;
	g_smc_args[index].a8  = 0x0;

	spin_lock(&smc_ring_lock);
	g_smc_used_ring->ring[g_smc_used_ring->tail] = index;
	g_smc_used_ring->tail = (g_smc_used_ring->tail + 1) % OPTEE_SHM_QUEUE_SIZE;
	spin_unlock(&smc_ring_lock);

	writel(g_smc_vm_ids->tee_id << 16, g_ivshmem_dev.regs_addr + DOORBELL_OFF);

	wait_event_interruptible(optee_smc_queue, (g_smc_args[index].a8 == OPTEE_HANDLE_DONE));

	g_smc_args[index].a8 = 0x0;
	res->a0 = g_smc_args[index].a0;
	res->a1 = g_smc_args[index].a1;
	res->a2 = g_smc_args[index].a2;
	res->a3 = g_smc_args[index].a3;

	spin_lock(&smc_ring_lock);
	g_smc_avail_ring->ring[g_smc_avail_ring->tail] = index;
	g_smc_avail_ring->tail = (g_smc_avail_ring->tail + 1) % OPTEE_SHM_QUEUE_SIZE;
	spin_unlock(&smc_ring_lock);
}
#else
static void optee_smccc_smc(unsigned long a0, unsigned long a1,
			    unsigned long a2, unsigned long a3,
			    unsigned long a4, unsigned long a5,
			    unsigned long a6, unsigned long a7,
			    struct arm_smccc_res *res)
{
	arm_smccc_smc(a0, a1, a2, a3, a4, a5, a6, a7, res);
}

static void optee_smccc_hvc(unsigned long a0, unsigned long a1,
			    unsigned long a2, unsigned long a3,
			    unsigned long a4, unsigned long a5,
			    unsigned long a6, unsigned long a7,
			    struct arm_smccc_res *res)
{
	arm_smccc_hvc(a0, a1, a2, a3, a4, a5, a6, a7, res);
}

static optee_invoke_fn *get_invoke_func(struct device *dev)
{
	const char *method;

	pr_info("probing for conduit method.\n");

	if (device_property_read_string(dev, "method", &method)) {
		pr_warn("missing \"method\" property\n");
		return ERR_PTR(-ENXIO);
	}

	if (!strcmp("hvc", method))
		return optee_smccc_hvc;
	else if (!strcmp("smc", method))
		return optee_smccc_smc;

	pr_warn("invalid \"method\" property: %s\n", method);
	return ERR_PTR(-EINVAL);
}
#endif

static int optee_remove(struct platform_device *pdev)
{
	struct optee *optee = platform_get_drvdata(pdev);

	/*
	 * Ask OP-TEE to free all cached shared memory objects to decrease
	 * reference counters and also avoid wild pointers in secure world
	 * into the old shared memory range.
	 */
	optee_disable_shm_cache(optee);

	/*
	 * The two devices have to be unregistered before we can free the
	 * other resources.
	 */
	tee_device_unregister(optee->supp_teedev);
	tee_device_unregister(optee->teedev);

	tee_shm_pool_free(optee->pool);
	if (optee->memremaped_shm)
#if defined(CONFIG_OPTEE_VSOCK)
		kfree(optee->memremaped_shm);
#else
		memunmap(optee->memremaped_shm);
#endif
	optee_wait_queue_exit(&optee->wait_queue);
	optee_supp_uninit(&optee->supp);
	mutex_destroy(&optee->call_queue.mutex);

	kfree(optee);

	optee_bm_disable();

#if defined(CONFIG_OPTEE_VSOCK)
	sock_release(tee_sock);
	sock_release(host_smc_sock);
#endif

	return 0;
}

static int optee_probe(struct platform_device *pdev)
{
	optee_invoke_fn *invoke_fn;
	struct tee_shm_pool *pool = ERR_PTR(-EINVAL);
	struct optee *optee = NULL;
	void *memremaped_shm = NULL;
	struct tee_device *teedev;
	u32 sec_caps;
	int rc;

#if defined(CONFIG_X86_64)
#if defined(CONFIG_OPTEE_VSOCK)
	union {
		struct sockaddr sa;
		struct sockaddr_vm svm;
	} smc_addr = {
		.svm = {
			.svm_family = AF_VSOCK,
			.svm_port = VIRTIO_VSOCK_TEE_PORT,
			.svm_cid = VMADDR_CID_ANY,
		},
	};

	rc = sock_create_kern(&init_net, AF_VSOCK, SOCK_STREAM, 0, &host_smc_sock);
	if (rc) {
		pr_warn("host_smc_sock create failed\n");
		goto err_release_sock;
	}

	rc = kernel_bind(host_smc_sock, &smc_addr.sa, sizeof(smc_addr));
	if (rc) {
		pr_warn("host_smc_sock bind failed 0x%x\n", rc);
		goto err_release_sock;
	}

	rc = kernel_listen(host_smc_sock, 32); 
	if (rc) {
		pr_warn("host_smc_sock listen failed 0x%x\n", rc);
		goto err_release_sock;
	}

	rc = kernel_accept(host_smc_sock, &tee_sock, 0); 
	if (rc) {
		pr_warn("host_smc_sock accept failed 0x%x\n", rc);
		goto err_release_sock;
	}
#elif defined(CONFIG_OPTEE_IVSHMEM)
	if (g_ivshmem_dev.dev == NULL) {
		pr_warn("ivshmem not found\n");
		return -EINVAL;
	}
#endif
	invoke_fn = optee_smccc_smc;
#else
	invoke_fn = get_invoke_func(&pdev->dev);
#endif

	if (IS_ERR(invoke_fn))
		return PTR_ERR(invoke_fn);

	if (!optee_msg_api_uid_is_optee_api(invoke_fn)) {
		pr_warn("api uid mismatch\n");
		return -EINVAL;
	}

	optee_msg_get_os_revision(invoke_fn);

	if (!optee_msg_api_revision_is_compatible(invoke_fn)) {
		pr_warn("api revision mismatch\n");
		return -EINVAL;
	}

	if (!optee_msg_exchange_capabilities(invoke_fn, &sec_caps)) {
		pr_warn("capabilities mismatch\n");
		return -EINVAL;
	}

	/*
	 * Try to use dynamic shared memory if possible
	 */
	if (sec_caps & OPTEE_SMC_SEC_CAP_DYNAMIC_SHM)
		pool = optee_config_dyn_shm();

	/*
	 * If dynamic shared memory is not available or failed - try static one
	 */
	if (IS_ERR(pool) && (sec_caps & OPTEE_SMC_SEC_CAP_HAVE_RESERVED_SHM))
		pool = optee_config_shm_memremap(invoke_fn, &memremaped_shm);

	if (IS_ERR(pool))
		return PTR_ERR(pool);

	optee = kzalloc(sizeof(*optee), GFP_KERNEL);
	if (!optee) {
		rc = -ENOMEM;
		goto err;
	}

	optee->invoke_fn = invoke_fn;
	optee->sec_caps = sec_caps;

	teedev = tee_device_alloc(&optee_desc, NULL, pool, optee);
	if (IS_ERR(teedev)) {
		rc = PTR_ERR(teedev);
		goto err;
	}
	optee->teedev = teedev;

	teedev = tee_device_alloc(&optee_supp_desc, NULL, pool, optee);
	if (IS_ERR(teedev)) {
		rc = PTR_ERR(teedev);
		goto err;
	}
	optee->supp_teedev = teedev;

	rc = tee_device_register(optee->teedev);
	if (rc)
		goto err;

	rc = tee_device_register(optee->supp_teedev);
	if (rc)
		goto err;

	mutex_init(&optee->call_queue.mutex);
	INIT_LIST_HEAD(&optee->call_queue.waiters);
	optee_wait_queue_init(&optee->wait_queue);
	optee_supp_init(&optee->supp);
	optee->memremaped_shm = memremaped_shm;
	optee->pool = pool;

	optee_enable_shm_cache(optee);

	if (optee->sec_caps & OPTEE_SMC_SEC_CAP_DYNAMIC_SHM)
		pr_info("dynamic shared memory is enabled\n");

	platform_set_drvdata(pdev, optee);

	rc = optee_enumerate_devices(PTA_CMD_GET_DEVICES);
	if (rc) {
		optee_remove(pdev);
		return rc;
	}

	pr_info("initialized driver\n");
	optee_bm_enable();
	return 0;
err:
	if (optee) {
		/*
		 * tee_device_unregister() is safe to call even if the
		 * devices hasn't been registered with
		 * tee_device_register() yet.
		 */
		tee_device_unregister(optee->supp_teedev);
		tee_device_unregister(optee->teedev);
		kfree(optee);
	}
	if (pool) {
		pr_warn("tee_shm_pool_free start\n");
		tee_shm_pool_free(pool);
	}
	if (memremaped_shm)
#if defined(CONFIG_OPTEE_VSOCK)
		kfree(memremaped_shm);
#else
		memunmap(memremaped_shm);
#endif
#if defined(CONFIG_OPTEE_VSOCK)
err_release_sock:
	if (tee_sock)
		sock_release(tee_sock);
	if (host_smc_sock)
		sock_release(host_smc_sock);
#endif
	return rc;
}

#if defined(CONFIG_X86_64)
void optee_dev_release(struct device *dev)
{
	return;
}

static struct platform_device optee_platform_dev = {
		.name = "optee-tz",
		.id = -1,
		.dev = {
			.release = optee_dev_release,
	},
};

static struct platform_driver optee_driver = {
	.probe  = optee_probe,
	.remove = optee_remove,
	.driver = {
		.name = "optee-tz",
		.owner = THIS_MODULE,
	},
};

#if defined(CONFIG_OPTEE_IVSHMEM)
static irqreturn_t ivshmem_interrupt(int irq, void *dev_id)
{
	struct ivshmem_private *ivshmem_dev = dev_id;

	if (unlikely(ivshmem_dev == NULL)) {
		return IRQ_NONE;
	}

	wake_up_interruptible(&optee_smc_queue);

	return IRQ_HANDLED;
}

static int ivshmem_request_msix_vectors(struct ivshmem_private *ivshmem_dev, int n)
{
	int ret = -EINVAL, i = 0;

	pr_info("ivshmem request msi-x vectors: %d\n", n);

	ivshmem_dev->nvectors = n;

	ivshmem_dev->msix_entries = kmalloc(n * sizeof(struct msix_entry),
			GFP_KERNEL);
	if (ivshmem_dev->msix_entries == NULL) {
		ret = -ENOMEM;
		goto error;
	}
	
	ivshmem_dev->msix_names = kmalloc(n * sizeof(*ivshmem_dev->msix_names),
			GFP_KERNEL);
	if (ivshmem_dev->msix_names == NULL) {
		ret = -ENOMEM;
		goto free_entries;
	}

	for (i = 0; i < n; i++) {
		ivshmem_dev->msix_entries[i].entry = i;
	}

	ret = pci_enable_msix_exact(ivshmem_dev->dev, ivshmem_dev->msix_entries, n);
	if (ret) {
		pr_err("ivshmem unable to enable msix: %d\n", ret);
		goto free_names;
	}

	for (i = 0; i < ivshmem_dev->nvectors; i++) {
		snprintf(ivshmem_dev->msix_names[i], sizeof(*ivshmem_dev->msix_names),
				"%s-%d", PCI_DRV_NAME, i);

		ret = request_irq(ivshmem_dev->msix_entries[i].vector,
				ivshmem_interrupt, 0, ivshmem_dev->msix_names[i], ivshmem_dev);

		if (ret) {
			pr_err("ivshmem unable to allocate irq for msix entry %d with vector %d\n",
					i, ivshmem_dev->msix_entries[i].vector);
			goto release_irqs;
		}

		pr_info("ivshmem irq for msix entry: %d, vector: %d\n",
				i, ivshmem_dev->msix_entries[i].vector);
	}

    return 0;

release_irqs:
	for ( ; i > 0; i--) {
		free_irq(ivshmem_dev->msix_entries[i - 1].vector, ivshmem_dev);
	}
	pci_disable_msix(ivshmem_dev->dev);

free_names:
	kfree(ivshmem_dev->msix_names);

free_entries:
	kfree(ivshmem_dev->msix_entries);

error:
	return ret;
}

static void ivshmem_free_msix_vectors(struct ivshmem_private *ivshmem_dev)
{
	int i;

	for (i = ivshmem_dev->nvectors; i > 0; i--) {
		free_irq(ivshmem_dev->msix_entries[i - 1].vector, ivshmem_dev);
	}
	pci_disable_msix(ivshmem_dev->dev);

	kfree(ivshmem_dev->msix_names);
	kfree(ivshmem_dev->msix_entries);
}

static int ivshmem_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int ret;
	int i;

	pr_info("probing for ivshmem device: %s\n", pci_name(pdev));

	ret = pci_enable_device(pdev);
	if (ret < 0) {
		pr_err("unable to enable ivshmem device: %d\n", ret);
		goto out;
	}

	ret = pci_request_regions(pdev, PCI_DRV_NAME);
	if (ret < 0) {
		pr_err("unable to reserve resources for ivshmem: %d\n", ret);
		goto disable_device;
	}

	pci_read_config_byte(pdev, PCI_REVISION_ID, &g_ivshmem_dev.revision);

	pr_info("ivshmem device revision: %d\n", g_ivshmem_dev.revision);

	g_ivshmem_dev.bar0_addr = pci_resource_start(pdev, 0);
	g_ivshmem_dev.bar0_len = pci_resource_len(pdev, 0);
	g_ivshmem_dev.bar1_addr = pci_resource_start(pdev, 1);
	g_ivshmem_dev.bar1_len = pci_resource_len(pdev, 1);
	g_ivshmem_dev.bar2_addr = pci_resource_start(pdev, 2);
	g_ivshmem_dev.bar2_len = pci_resource_len(pdev, 2);

	pr_info("ivshmem BAR0: 0x%lx, %ld\n", g_ivshmem_dev.bar0_addr,
			g_ivshmem_dev.bar0_len);
	pr_info("ivshmem BAR1: 0x%lx, %ld\n", g_ivshmem_dev.bar1_addr,
			g_ivshmem_dev.bar1_len);
	pr_info("ivshmem BAR2: 0x%lx, %ld\n", g_ivshmem_dev.bar2_addr,
			g_ivshmem_dev.bar2_len);

	g_ivshmem_dev.regs_addr = ioremap(g_ivshmem_dev.bar0_addr, g_ivshmem_dev.bar0_len);
	if (!g_ivshmem_dev.regs_addr) {
		pr_err("ivshmem unable to ioremap bar0, size: %ld\n", g_ivshmem_dev.bar0_len);
		goto release_regions;
	}

	g_ivshmem_dev.msix_addr = (u32 *)memremap(g_ivshmem_dev.bar1_addr,
		g_ivshmem_dev.bar1_len, MEMREMAP_WT);
	if (!g_ivshmem_dev.msix_addr) {
		pr_err("msix memory ioremap failed\n");
		goto iounmap_bar0;
	}
	pr_info("ivshmem msix entry 0 1st: 0x%x/0x%x/0x%x/0x%x\n",
		*(g_ivshmem_dev.msix_addr), *(g_ivshmem_dev.msix_addr+1),
		*(g_ivshmem_dev.msix_addr+2), *(g_ivshmem_dev.msix_addr+3));

	g_ivshmem_dev.base_addr = (u8 *)memremap(g_ivshmem_dev.bar2_addr,
		OPTEE_SHM_SMC_SIZE, MEMREMAP_WT);
	if (!g_ivshmem_dev.base_addr) {
		pr_err("base memory ioremap failed\n");
		goto iounmap_bar1;
	}
	pr_info("ivshmem BAR2 map: 0x%llx\n", (u64)g_ivshmem_dev.base_addr);

	g_smc_vm_ids = (struct optee_vm_ids *)g_ivshmem_dev.base_addr;
	g_smc_avail_ring = (struct optee_smc_ring *)(g_ivshmem_dev.base_addr +
		sizeof(struct optee_vm_ids));
	g_smc_used_ring = (struct optee_smc_ring *)(g_ivshmem_dev.base_addr +
		sizeof(struct optee_vm_ids) + sizeof(struct optee_smc_ring));
	g_smc_args = (struct optee_smc_args *)(g_ivshmem_dev.base_addr +
		sizeof(struct optee_vm_ids) + sizeof(struct optee_smc_ring) +
		sizeof(struct optee_smc_ring));
	g_smc_avail_ring->head = 0;
	g_smc_avail_ring->tail = 0;
	for (i = 0; i < OPTEE_SHM_QUEUE_SIZE; i++) {
		g_smc_avail_ring->ring[i] = i;
	}
	g_smc_used_ring->head = 0;
	g_smc_used_ring->tail = 0;
	for (i = 0; i < OPTEE_SHM_QUEUE_SIZE; i++) {
		g_smc_used_ring->ring[i] = OPTEE_SHM_QUEUE_SIZE;
	}
	memset(g_smc_args, 0, sizeof(struct optee_smc_args) * OPTEE_SHM_QUEUE_SIZE);

	g_ivshmem_dev.dev = pdev;

	if (g_ivshmem_dev.revision == 1) {
		g_ivshmem_dev.ivposition = ioread32(g_ivshmem_dev.regs_addr + IVPOSITION_OFF);
		g_smc_vm_ids->ree_id = g_ivshmem_dev.ivposition;
		pr_info("ivshmem device ree id=%d, tee id=%d\n",
				g_smc_vm_ids->ree_id, g_smc_vm_ids->tee_id);

		pr_info("ivshmem device ivposition: %u, MSI-X: %s\n", g_ivshmem_dev.ivposition,
				(g_ivshmem_dev.ivposition == 0) ? "no": "yes");

		if (g_ivshmem_dev.ivposition != 0) {
			ret = ivshmem_request_msix_vectors(&g_ivshmem_dev, 1);
			if (ret != 0) {
				goto destroy_device;
			}
		}
		pr_info("ivshmem msix entry 0 2nd: 0x%x/0x%x/0x%x/0x%x\n",
		*(g_ivshmem_dev.msix_addr), *(g_ivshmem_dev.msix_addr+1),
		*(g_ivshmem_dev.msix_addr+2), *(g_ivshmem_dev.msix_addr+3));
	}

	pr_info("ivshmem device probed: %s\n", pci_name(pdev));
	return 0;

destroy_device:
	g_ivshmem_dev.dev = NULL;
	memunmap(g_ivshmem_dev.base_addr);

iounmap_bar1:
	memunmap(g_ivshmem_dev.msix_addr);

iounmap_bar0:
	iounmap(g_ivshmem_dev.regs_addr);

release_regions:
	pci_release_regions(pdev);

disable_device:
	pci_disable_device(pdev);

out:
    return ret;
}

static void ivshmem_remove(struct pci_dev *pdev)
{
	pr_info("removing for ivshmem device: %s\n", pci_name(pdev));

	ivshmem_free_msix_vectors(&g_ivshmem_dev);

	g_ivshmem_dev.dev = NULL;

	memunmap(g_ivshmem_dev.base_addr);
	memunmap(g_ivshmem_dev.msix_addr);
	iounmap(g_ivshmem_dev.regs_addr);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
}

static struct pci_driver ivshmem_driver = {
	.name       = PCI_DRV_NAME,
	.id_table   = ivshmem_id_table,
	.probe      = ivshmem_probe,
	.remove     = ivshmem_remove,
};
#endif

static int __init optee_drv_init(void)
{
	int ret = 0;

#if defined(CONFIG_OPTEE_IVSHMEM)
	ret = pci_register_driver(&ivshmem_driver);
	if (ret) {
		pr_err("pci_register_driver() failed, ret %d\n", ret);
		return ret;
	}
#endif

	ret = platform_device_register(&optee_platform_dev);
	if (ret) {
		pr_err("platform_device_register() failed, ret %d\n", ret);
		return ret;
	}

	ret = platform_driver_probe(&optee_driver, optee_probe);
	if (ret)
		pr_err("platform_driver_probe() failed, ret %d\n", ret);

	return ret;
}

static void __exit optee_drv_exit(void)
{
	platform_driver_unregister(&optee_driver);

	platform_device_unregister(&optee_platform_dev);

#if defined(CONFIG_OPTEE_IVSHMEM)
	pci_unregister_driver(&ivshmem_driver);
#endif
}

module_init(optee_drv_init);
module_exit(optee_drv_exit);
#else
static const struct of_device_id optee_dt_match[] = {
	{ .compatible = "linaro,optee-tz" },
	{},
};
MODULE_DEVICE_TABLE(of, optee_dt_match);

static struct platform_driver optee_driver = {
	.probe  = optee_probe,
	.remove = optee_remove,
	.driver = {
		.name = "optee",
		.of_match_table = optee_dt_match,
	},
};
module_platform_driver(optee_driver);
#endif

MODULE_AUTHOR("Linaro");
MODULE_DESCRIPTION("OP-TEE driver");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:optee");
