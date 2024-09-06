/*
 * Copyright 2014 Canonical
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: Andreas Pokorny
 */

#include <drm/drm_prime.h>
#include <linux/virtio_dma_buf.h>

#include "virtgpu_drv.h"

static int virtgpu_virtio_get_uuid(struct dma_buf *buf,
				   uuid_t *uuid)
{
	struct drm_gem_object *obj = buf->priv;
	struct virtio_gpu_object *bo = gem_to_virtio_gpu_obj(obj);
	struct virtio_gpu_device *vgdev = obj->dev->dev_private;

	wait_event(vgdev->resp_wq, bo->uuid_state != STATE_INITIALIZING);
	if (bo->uuid_state != STATE_OK)
		return -ENODEV;

	uuid_copy(uuid, &bo->uuid);

	return 0;
}

static struct sg_table *
virtgpu_gem_map_dma_buf(struct dma_buf_attachment *attach,
			enum dma_data_direction dir)
{
	struct drm_gem_object *obj = attach->dmabuf->priv;
	struct virtio_gpu_object *bo = gem_to_virtio_gpu_obj(obj);

	if (virtio_gpu_is_vram(bo))
		return virtio_gpu_vram_map_dma_buf(bo, attach->dev, dir);

	return drm_gem_map_dma_buf(attach, dir);
}

static void virtgpu_gem_unmap_dma_buf(struct dma_buf_attachment *attach,
				      struct sg_table *sgt,
				      enum dma_data_direction dir)
{
	struct drm_gem_object *obj = attach->dmabuf->priv;
	struct virtio_gpu_object *bo = gem_to_virtio_gpu_obj(obj);

	if (virtio_gpu_is_vram(bo)) {
		virtio_gpu_vram_unmap_dma_buf(attach->dev, sgt, dir);
		return;
	}

	drm_gem_unmap_dma_buf(attach, sgt, dir);
}

static const struct virtio_dma_buf_ops virtgpu_dmabuf_ops =  {
	.ops = {
		.cache_sgt_mapping = true,
		.attach = virtio_dma_buf_attach,
		.detach = drm_gem_map_detach,
		.map_dma_buf = virtgpu_gem_map_dma_buf,
		.unmap_dma_buf = virtgpu_gem_unmap_dma_buf,
		.release = drm_gem_dmabuf_release,
		.mmap = drm_gem_dmabuf_mmap,
		.vmap = drm_gem_dmabuf_vmap,
		.vunmap = drm_gem_dmabuf_vunmap,
	},
	.device_attach = drm_gem_map_attach,
	.get_uuid = virtgpu_virtio_get_uuid,
};

int virtio_gpu_resource_assign_uuid(struct virtio_gpu_device *vgdev,
				    struct virtio_gpu_object *bo)
{
	struct virtio_gpu_object_array *objs;

	objs = virtio_gpu_array_alloc(1);
	if (!objs)
		return -ENOMEM;

	virtio_gpu_array_add_obj(objs, &bo->base.base);

	return virtio_gpu_cmd_resource_assign_uuid(vgdev, objs);
}

struct dma_buf *virtgpu_gem_prime_export(struct drm_gem_object *obj,
					 int flags)
{
	struct dma_buf *buf;
	struct drm_device *dev = obj->dev;
	struct virtio_gpu_device *vgdev = dev->dev_private;
	struct virtio_gpu_object *bo = gem_to_virtio_gpu_obj(obj);
	int ret = 0;
	bool blob = bo->host3d_blob || bo->guest_blob;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);

	if (!blob) {
		if (vgdev->has_resource_assign_uuid) {
			ret = virtio_gpu_resource_assign_uuid(vgdev, bo);
			if (ret)
				return ERR_PTR(ret);

			virtio_gpu_notify(vgdev);
		} else {
			bo->uuid_state = STATE_ERR;
		}
	} else if (!(bo->blob_flags & VIRTGPU_BLOB_FLAG_USE_CROSS_DEVICE)) {
		bo->uuid_state = STATE_ERR;
	}

	exp_info.ops = &virtgpu_dmabuf_ops.ops;
	exp_info.size = obj->size;
	exp_info.flags = flags;
	exp_info.priv = obj;
	exp_info.resv = obj->resv;

	buf = virtio_dma_buf_export(&exp_info);
	if (IS_ERR(buf))
		return buf;

	drm_dev_get(dev);
	drm_gem_object_get(obj);

	return buf;
}

struct drm_gem_object *virtgpu_gem_prime_import(struct drm_device *dev,
						struct dma_buf *dma_buf)
{
	struct drm_gem_object *obj;
	struct dma_buf_attachment *attach;
	struct sg_table *sgt;
	struct device *attach_dev = dev->dev;
	struct virtio_gpu_device *vgdev = dev->dev_private;
	int ret;

	if (dma_buf->ops == &virtgpu_dmabuf_ops.ops) {
		obj = dma_buf->priv;
		if (obj->dev == dev) {
			/*
			 * Importing dmabuf exported from our own gem increases
			 * refcount on gem itself instead of f_count of dmabuf.
			 */
			drm_gem_object_get(obj);
			return obj;
		}
	}

	if (strcmp(dev->dev->driver->name, "virtio-ivshmem") == 0 ||
			strcmp(dev->dev->driver->name, "virtio-guest-shm") == 0)
		return ERR_PTR(-EINVAL);

	if (!dev->driver->gem_prime_import_sg_table)
		return ERR_PTR(-EINVAL);
	attach = ____dma_buf_dynamic_attach(dma_buf, attach_dev, NULL, NULL,
					    vgdev->has_allow_p2p);
	if (IS_ERR(attach))
		return ERR_CAST(attach);

	get_dma_buf(dma_buf);

	sgt = dma_buf_map_attachment(attach, DMA_BIDIRECTIONAL);
	if (IS_ERR(sgt)) {
		ret = PTR_ERR(sgt);
		goto fail_detach;
	}

	obj = dev->driver->gem_prime_import_sg_table(dev, attach, sgt);
	if (IS_ERR(obj)) {
		ret = PTR_ERR(obj);
		goto fail_unmap;
	}

	obj->import_attach = attach;
	obj->resv = dma_buf->resv;

	return obj;

fail_unmap:
	dma_buf_unmap_attachment(attach, sgt, DMA_BIDIRECTIONAL);
fail_detach:
	dma_buf_detach(dma_buf, attach);
	dma_buf_put(dma_buf);

	return ERR_PTR(ret);
}

static int virtio_gpu_sgt_to_mem_entry(struct virtio_gpu_device *vgdev,
				       struct sg_table *table,
				       struct virtio_gpu_mem_entry **ents,
				       unsigned int *nents)
{
	struct scatterlist *sg;
	int si;

	/**
	 * TODO: We must always use DMA addresses for the following two reasons:
	 *
	 * 1. By design we are not allowed to access the struct page backing a
	 *    scatter list, especially when config DMABUF_DEBUG is turned on in
	 *    which case the addresses will be mangled by the core.
	 * 2. DMA addresses are required for dGPU local memory sharing between
	 *    host and guest.
	 */
	const bool use_dma_api = true;
	if (use_dma_api)
		*nents = table->nents;
	else
		*nents = table->orig_nents;

	*ents = kvmalloc_array(*nents,
			       sizeof(struct virtio_gpu_mem_entry),
			       GFP_KERNEL);
	if (!(*ents)) {
		DRM_ERROR("failed to allocate ent list\n");
		return -ENOMEM;
	}

	if (use_dma_api) {
		for_each_sgtable_dma_sg(table, sg, si) {
			(*ents)[si].addr = cpu_to_le64(sg_dma_address(sg));
			(*ents)[si].length = cpu_to_le32(sg_dma_len(sg));
			(*ents)[si].padding = 0;
		}
	} else {
		for_each_sgtable_sg(table, sg, si) {
			(*ents)[si].addr = cpu_to_le64(sg_phys(sg));
			(*ents)[si].length = cpu_to_le32(sg->length);
			(*ents)[si].padding = 0;
		}
	}

	return 0;

}

struct drm_gem_object *virtgpu_gem_prime_import_sg_table(
	struct drm_device *dev, struct dma_buf_attachment *attach,
	struct sg_table *table)
{
	size_t size = PAGE_ALIGN(attach->dmabuf->size);
	struct virtio_gpu_device *vgdev = dev->dev_private;
	struct virtio_gpu_object_params params = { 0 };
	struct virtio_gpu_object *bo;
	struct drm_gem_object *obj;
	struct virtio_gpu_mem_entry *ents;
	unsigned int nents;
	int ret;

	if (!vgdev->has_resource_blob || vgdev->has_virgl_3d) {
		return ERR_PTR(-ENODEV);
	}

	drm_info(dev, "%s: table = %p, orig_nents = %u, nents = %u\n",
		__func__, table, table->orig_nents, table->nents);
	obj = drm_gem_shmem_prime_import_sg_table(dev, attach, table);
	if (IS_ERR(obj)) {
		return ERR_CAST(obj);
	}

	bo = gem_to_virtio_gpu_obj(obj);
	ret = virtio_gpu_resource_id_get(vgdev, &bo->hw_res_handle);
	if (ret < 0) {
		return ERR_PTR(ret);
	}

	ret = virtio_gpu_sgt_to_mem_entry(vgdev, table, &ents, &nents);
	if (ret != 0) {
		goto err_put_id;
	}

	bo->guest_blob = true;
	params.blob_mem = VIRTGPU_BLOB_MEM_GUEST;
	params.blob_flags = VIRTGPU_BLOB_FLAG_USE_SHAREABLE;
	params.blob = true;
	params.size = size;

	virtio_gpu_cmd_resource_create_blob(vgdev, bo, &params,
					    ents, nents);
	virtio_gpu_object_save_restore_list(vgdev, bo, &params);

	return obj;

err_put_id:
	virtio_gpu_resource_id_put(vgdev, bo->hw_res_handle);
	return ERR_PTR(ret);
}
