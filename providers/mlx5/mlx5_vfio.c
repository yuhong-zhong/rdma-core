// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#define _GNU_SOURCE
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/param.h>
#include <linux/vfio.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>

#include "mlx5dv.h"
#include "mlx5_vfio.h"
#include "mlx5.h"

static void mlx5_vfio_free_cmd_msg(struct mlx5_vfio_context *ctx,
				   struct mlx5_cmd_msg *msg);

static int mlx5_vfio_alloc_cmd_msg(struct mlx5_vfio_context *ctx,
				   uint32_t size, struct mlx5_cmd_msg *msg);

static int mlx5_vfio_register_mem(struct mlx5_vfio_context *ctx,
				  void *vaddr, uint64_t iova, uint64_t size)
{
	struct vfio_iommu_type1_dma_map dma_map = { .argsz = sizeof(dma_map) };

	dma_map.vaddr = (uintptr_t)vaddr;
	dma_map.size = size;
	dma_map.iova = iova;
	dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;

	return ioctl(ctx->container_fd, VFIO_IOMMU_MAP_DMA, &dma_map);
}

static void mlx5_vfio_unregister_mem(struct mlx5_vfio_context *ctx,
				     uint64_t iova, uint64_t size)
{
	struct vfio_iommu_type1_dma_unmap dma_unmap = {};

	dma_unmap.argsz = sizeof(struct vfio_iommu_type1_dma_unmap);
	dma_unmap.size = size;
	dma_unmap.iova = iova;

	if (ioctl(ctx->container_fd, VFIO_IOMMU_UNMAP_DMA, &dma_unmap))
		assert(false);
}

static struct page_block *mlx5_vfio_new_block(struct mlx5_vfio_context *ctx)
{
	struct page_block *page_block;
	int err;

	page_block = calloc(1, sizeof(*page_block));
	if (!page_block) {
		errno = ENOMEM;
		return NULL;
	}

	err = posix_memalign(&page_block->page_ptr, MLX5_VFIO_BLOCK_SIZE,
			     MLX5_VFIO_BLOCK_SIZE);
	if (err) {
		errno = err;
		goto err;
	}

	err = iset_alloc_range(ctx->iova_alloc, MLX5_VFIO_BLOCK_SIZE, &page_block->iova);
	if (err)
		goto err_range;

	bitmap_fill(page_block->free_pages, MLX5_VFIO_BLOCK_NUM_PAGES);
	err = mlx5_vfio_register_mem(ctx, page_block->page_ptr, page_block->iova,
				     MLX5_VFIO_BLOCK_SIZE);
	if (err)
		goto err_reg;

	list_add(&ctx->mem_alloc.block_list, &page_block->next_block);
	return page_block;

err_reg:
	iset_insert_range(ctx->iova_alloc, page_block->iova,
			  MLX5_VFIO_BLOCK_SIZE);
err_range:
	free(page_block->page_ptr);
err:
	free(page_block);
	return NULL;
}

static void mlx5_vfio_free_block(struct mlx5_vfio_context *ctx,
				 struct page_block *page_block)
{
	mlx5_vfio_unregister_mem(ctx, page_block->iova, MLX5_VFIO_BLOCK_SIZE);
	iset_insert_range(ctx->iova_alloc, page_block->iova, MLX5_VFIO_BLOCK_SIZE);
	list_del(&page_block->next_block);
	free(page_block->page_ptr);
	free(page_block);
}

static int mlx5_vfio_alloc_page(struct mlx5_vfio_context *ctx, uint64_t *iova)
{
	struct page_block *page_block;
	unsigned long pg;
	int ret = 0;

	pthread_mutex_lock(&ctx->mem_alloc.block_list_mutex);
	while (true) {
		list_for_each(&ctx->mem_alloc.block_list, page_block, next_block) {
			pg = bitmap_ffs(page_block->free_pages, 0, MLX5_VFIO_BLOCK_NUM_PAGES);
			if (pg != MLX5_VFIO_BLOCK_NUM_PAGES) {
				bitmap_clear_bit(page_block->free_pages, pg);
				*iova = page_block->iova + pg * MLX5_ADAPTER_PAGE_SIZE;
				goto end;
			}
		}
		if (!mlx5_vfio_new_block(ctx)) {
			ret = -1;
			goto end;
		}
	}
end:
	pthread_mutex_unlock(&ctx->mem_alloc.block_list_mutex);
	return ret;
}

static void mlx5_vfio_free_page(struct mlx5_vfio_context *ctx, uint64_t iova)
{
	struct page_block *page_block;
	unsigned long pg;

	pthread_mutex_lock(&ctx->mem_alloc.block_list_mutex);
	list_for_each(&ctx->mem_alloc.block_list, page_block, next_block) {
		if (page_block->iova > iova ||
		    (page_block->iova + MLX5_VFIO_BLOCK_SIZE <= iova))
			continue;

		pg = (iova - page_block->iova) / MLX5_ADAPTER_PAGE_SIZE;
		assert(!bitmap_test_bit(page_block->free_pages, pg));
		bitmap_set_bit(page_block->free_pages, pg);
		if (bitmap_full(page_block->free_pages, MLX5_VFIO_BLOCK_NUM_PAGES))
			mlx5_vfio_free_block(ctx, page_block);

		goto end;
	}

	assert(false);
end:
	pthread_mutex_unlock(&ctx->mem_alloc.block_list_mutex);
}

static int mlx5_vfio_enable_pci_cmd(struct mlx5_vfio_context *ctx)
{
	struct vfio_region_info pci_config_reg = {};
	uint16_t pci_com_buf = 0x6;
	char buffer[4096];

	pci_config_reg.argsz = sizeof(pci_config_reg);
	pci_config_reg.index = VFIO_PCI_CONFIG_REGION_INDEX;

	if (ioctl(ctx->device_fd, VFIO_DEVICE_GET_REGION_INFO, &pci_config_reg))
		return -1;

	if (pwrite(ctx->device_fd, &pci_com_buf, 2, pci_config_reg.offset + 0x4) != 2)
		return -1;

	if (pread(ctx->device_fd, buffer, pci_config_reg.size, pci_config_reg.offset)
			!= pci_config_reg.size)
		return -1;

	return 0;
}

static void free_cmd_box(struct mlx5_vfio_context *ctx,
			 struct mlx5_cmd_mailbox *mailbox)
{
	mlx5_vfio_unregister_mem(ctx, mailbox->iova, MLX5_ADAPTER_PAGE_SIZE);
	iset_insert_range(ctx->iova_alloc, mailbox->iova, MLX5_ADAPTER_PAGE_SIZE);
	free(mailbox->buf);
	free(mailbox);
}

static struct mlx5_cmd_mailbox *alloc_cmd_box(struct mlx5_vfio_context *ctx)
{
	struct mlx5_cmd_mailbox *mailbox;
	int ret;

	mailbox = calloc(1, sizeof(*mailbox));
	if (!mailbox) {
		errno = ENOMEM;
		return NULL;
	}

	ret = posix_memalign(&mailbox->buf, MLX5_ADAPTER_PAGE_SIZE,
			     MLX5_ADAPTER_PAGE_SIZE);
	if (ret) {
		errno = ret;
		goto err_free;
	}

	memset(mailbox->buf, 0, MLX5_ADAPTER_PAGE_SIZE);

	ret = iset_alloc_range(ctx->iova_alloc, MLX5_ADAPTER_PAGE_SIZE, &mailbox->iova);
	if (ret)
		goto err_tree;

	ret = mlx5_vfio_register_mem(ctx, mailbox->buf, mailbox->iova,
				     MLX5_ADAPTER_PAGE_SIZE);
	if (ret)
		goto err_reg;

	return mailbox;

err_reg:
	iset_insert_range(ctx->iova_alloc, mailbox->iova,
			  MLX5_ADAPTER_PAGE_SIZE);
err_tree:
	free(mailbox->buf);
err_free:
	free(mailbox);
	return NULL;
}

static int mlx5_calc_cmd_blocks(uint32_t msg_len)
{
	int size = msg_len;
	int blen = size - min_t(int, 16, size);

	return DIV_ROUND_UP(blen, MLX5_CMD_DATA_BLOCK_SIZE);
}

static void mlx5_vfio_free_cmd_msg(struct mlx5_vfio_context *ctx,
				   struct mlx5_cmd_msg *msg)
{
	struct mlx5_cmd_mailbox *head = msg->next;
	struct mlx5_cmd_mailbox *next;

	while (head) {
		next = head->next;
		free_cmd_box(ctx, head);
		head = next;
	}
	msg->len = 0;
}

static int mlx5_vfio_alloc_cmd_msg(struct mlx5_vfio_context *ctx,
				   uint32_t size, struct mlx5_cmd_msg *msg)
{
	struct mlx5_cmd_mailbox *tmp, *head = NULL;
	struct mlx5_cmd_block *block;
	int i, num_blocks;

	msg->len = size;
	num_blocks = mlx5_calc_cmd_blocks(size);

	for (i = 0; i < num_blocks; i++) {
		tmp = alloc_cmd_box(ctx);
		if (!tmp)
			goto err_alloc;

		block = tmp->buf;
		tmp->next = head;
		block->next = htobe64(tmp->next ? tmp->next->iova : 0);
		block->block_num = htobe32(num_blocks - i - 1);
		head = tmp;
	}
	msg->next = head;
	return 0;

err_alloc:
	while (head) {
		tmp = head->next;
		free_cmd_box(ctx, head);
		head = tmp;
	}
	msg->len = 0;
	return -1;
}

static void mlx5_vfio_free_cmd_slot(struct mlx5_vfio_context *ctx, int slot)
{
	struct mlx5_vfio_cmd_slot *cmd_slot = &ctx->cmd.cmds[slot];

	mlx5_vfio_free_cmd_msg(ctx, &cmd_slot->in);
	mlx5_vfio_free_cmd_msg(ctx, &cmd_slot->out);
	close(cmd_slot->completion_event_fd);
}

static int mlx5_vfio_setup_cmd_slot(struct mlx5_vfio_context *ctx, int slot)
{
	struct mlx5_vfio_cmd *cmd = &ctx->cmd;
	struct mlx5_vfio_cmd_slot *cmd_slot = &cmd->cmds[slot];
	struct mlx5_cmd_layout *cmd_lay;
	int ret;

	ret = mlx5_vfio_alloc_cmd_msg(ctx, 4096, &cmd_slot->in);
	if (ret)
		return ret;

	ret = mlx5_vfio_alloc_cmd_msg(ctx, 4096, &cmd_slot->out);
	if (ret)
		goto err;

	cmd_lay = cmd->vaddr + (slot * (1 << cmd->log_stride));
	cmd_lay->type = MLX5_PCI_CMD_XPORT;
	cmd_lay->iptr = htobe64(cmd_slot->in.next->iova);
	cmd_lay->optr = htobe64(cmd_slot->out.next->iova);

	cmd_slot->lay = cmd_lay;
	cmd_slot->completion_event_fd = eventfd(0, EFD_CLOEXEC);
	if (cmd_slot->completion_event_fd < 0) {
		ret = -1;
		goto err_fd;
	}

	pthread_mutex_init(&cmd_slot->lock, NULL);

	return 0;

err_fd:
	mlx5_vfio_free_cmd_msg(ctx, &cmd_slot->out);
err:
	mlx5_vfio_free_cmd_msg(ctx, &cmd_slot->in);
	return ret;
}

static int mlx5_vfio_init_cmd_interface(struct mlx5_vfio_context *ctx)
{
	struct mlx5_init_seg *init_seg = ctx->bar_map;
	struct mlx5_vfio_cmd *cmd = &ctx->cmd;
	uint16_t cmdif_rev;
	uint32_t cmd_h, cmd_l;
	int ret;

	cmdif_rev = be32toh(init_seg->cmdif_rev_fw_sub) >> 16;

	if (cmdif_rev != 5) {
		errno = EINVAL;
		return -1;
	}

	cmd_l = be32toh(init_seg->cmdq_addr_l_sz) & 0xff;
	ctx->cmd.log_sz = cmd_l >> 4 & 0xf;
	ctx->cmd.log_stride = cmd_l & 0xf;
	if (1 << ctx->cmd.log_sz > MLX5_MAX_COMMANDS) {
		errno = EINVAL;
		return -1;
	}

	if (ctx->cmd.log_sz + ctx->cmd.log_stride > MLX5_ADAPTER_PAGE_SHIFT) {
		errno = EINVAL;
		return -1;
	}

	/* The initial address must be 4K aligned */
	ret = posix_memalign(&cmd->vaddr, MLX5_ADAPTER_PAGE_SIZE,
			     MLX5_ADAPTER_PAGE_SIZE);
	if (ret) {
		errno = ret;
		return -1;
	}

	memset(cmd->vaddr, 0, MLX5_ADAPTER_PAGE_SIZE);

	ret = iset_alloc_range(ctx->iova_alloc, MLX5_ADAPTER_PAGE_SIZE, &cmd->iova);
	if (ret)
		goto err_free;

	ret = mlx5_vfio_register_mem(ctx, cmd->vaddr, cmd->iova, MLX5_ADAPTER_PAGE_SIZE);
	if (ret)
		goto err_reg;

	cmd_h = (uint32_t)((uint64_t)(cmd->iova) >> 32);
	cmd_l = (uint32_t)(uint64_t)(cmd->iova);

	init_seg->cmdq_addr_h = htobe32(cmd_h);
	init_seg->cmdq_addr_l_sz = htobe32(cmd_l);

	/* Make sure firmware sees the complete address before we proceed */
	udma_to_device_barrier();

	ret = mlx5_vfio_setup_cmd_slot(ctx, 0);
	if (ret)
		goto err_slot_0;

	ret = mlx5_vfio_setup_cmd_slot(ctx, MLX5_MAX_COMMANDS - 1);
	if (ret)
		goto err_slot_1;

	ret = mlx5_vfio_enable_pci_cmd(ctx);
	if (!ret)
		return 0;

	mlx5_vfio_free_cmd_slot(ctx, MLX5_MAX_COMMANDS - 1);
err_slot_1:
	mlx5_vfio_free_cmd_slot(ctx, 0);
err_slot_0:
	mlx5_vfio_unregister_mem(ctx, cmd->iova, MLX5_ADAPTER_PAGE_SIZE);
err_reg:
	iset_insert_range(ctx->iova_alloc, cmd->iova, MLX5_ADAPTER_PAGE_SIZE);
err_free:
	free(cmd->vaddr);
	return ret;
}

static void mlx5_vfio_clean_cmd_interface(struct mlx5_vfio_context *ctx)
{
	struct mlx5_vfio_cmd *cmd = &ctx->cmd;

	mlx5_vfio_free_cmd_slot(ctx, 0);
	mlx5_vfio_free_cmd_slot(ctx, MLX5_MAX_COMMANDS - 1);
	mlx5_vfio_unregister_mem(ctx, cmd->iova, MLX5_ADAPTER_PAGE_SIZE);
	iset_insert_range(ctx->iova_alloc, cmd->iova, MLX5_ADAPTER_PAGE_SIZE);
	free(cmd->vaddr);
}

static void set_iova_min_page_size(struct mlx5_vfio_context *ctx,
				   uint64_t iova_pgsizes)
{
	int i;

	for (i = MLX5_ADAPTER_PAGE_SHIFT; i < 64; i++) {
		if (iova_pgsizes & (1 << i)) {
			ctx->iova_min_page_size = 1 << i;
			return;
		}
	}

	assert(false);
}

/* if the kernel does not report usable IOVA regions, choose the legacy region */
#define MLX5_VFIO_IOVA_MIN1 0x10000ULL
#define MLX5_VFIO_IOVA_MAX1 0xFEDFFFFFULL
#define MLX5_VFIO_IOVA_MIN2 0xFEF00000ULL
#define MLX5_VFIO_IOVA_MAX2 ((1ULL << 39) - 1)

static int mlx5_vfio_get_iommu_info(struct mlx5_vfio_context *ctx)
{
	struct vfio_iommu_type1_info *info;
	int ret, i;
	void *ptr;
	uint32_t offset;

	info = calloc(1, sizeof(*info));
	if (!info) {
		errno = ENOMEM;
		return -1;
	}

	info->argsz = sizeof(*info);
	ret = ioctl(ctx->container_fd, VFIO_IOMMU_GET_INFO, info);
	if (ret)
		goto end;

	if (info->argsz > sizeof(*info)) {
		info = realloc(info, info->argsz);
		if (!info) {
			errno = ENOMEM;
			ret = -1;
			goto end;
		}

		ret = ioctl(ctx->container_fd, VFIO_IOMMU_GET_INFO, info);
		if (ret)
			goto end;
	}

	set_iova_min_page_size(ctx, (info->flags & VFIO_IOMMU_INFO_PGSIZES) ?
			       info->iova_pgsizes : 4096);

	if (!(info->flags & VFIO_IOMMU_INFO_CAPS))
		goto set_legacy;

	offset = info->cap_offset;
	while (offset) {
		struct vfio_iommu_type1_info_cap_iova_range *iova_range;
		struct vfio_info_cap_header *header;

		ptr = (void *)info + offset;
		header = ptr;

		if (header->id != VFIO_IOMMU_TYPE1_INFO_CAP_IOVA_RANGE) {
			offset = header->next;
			continue;
		}

		iova_range = (struct vfio_iommu_type1_info_cap_iova_range *)header;

		for (i = 0; i < iova_range->nr_iovas; i++) {
			ret = iset_insert_range(ctx->iova_alloc, iova_range->iova_ranges[i].start,
						iova_range->iova_ranges[i].end -
						iova_range->iova_ranges[i].start + 1);
			if (ret)
				goto end;
		}

		goto end;
	}

set_legacy:
	ret = iset_insert_range(ctx->iova_alloc, MLX5_VFIO_IOVA_MIN1,
				MLX5_VFIO_IOVA_MAX1 - MLX5_VFIO_IOVA_MIN1 + 1);
	if (!ret)
		ret = iset_insert_range(ctx->iova_alloc, MLX5_VFIO_IOVA_MIN2,
					MLX5_VFIO_IOVA_MAX2 - MLX5_VFIO_IOVA_MIN2 + 1);

end:
	free(info);
	return ret;
}

static void mlx5_vfio_clean_device_dma(struct mlx5_vfio_context *ctx)
{
	struct page_block *page_block, *tmp;

	list_for_each_safe(&ctx->mem_alloc.block_list, page_block,
			   tmp, next_block)
		mlx5_vfio_free_block(ctx, page_block);

	iset_destroy(ctx->iova_alloc);
}

static int mlx5_vfio_init_device_dma(struct mlx5_vfio_context *ctx)
{
	ctx->iova_alloc = iset_create();
	if (!ctx->iova_alloc)
		return -1;

	list_head_init(&ctx->mem_alloc.block_list);
	pthread_mutex_init(&ctx->mem_alloc.block_list_mutex, NULL);

	if (mlx5_vfio_get_iommu_info(ctx))
		goto err;

	/* create an initial block of DMA memory ready to be used */
	if (!mlx5_vfio_new_block(ctx))
		goto err;

	return 0;
err:
	iset_destroy(ctx->iova_alloc);
	return -1;
}

static void mlx5_vfio_uninit_bar0(struct mlx5_vfio_context *ctx)
{
	munmap(ctx->bar_map, ctx->bar_map_size);
}

static int mlx5_vfio_init_bar0(struct mlx5_vfio_context *ctx)
{
	struct vfio_region_info reg = { .argsz = sizeof(reg) };
	void *base;
	int err;

	reg.index = 0;
	err = ioctl(ctx->device_fd, VFIO_DEVICE_GET_REGION_INFO, &reg);
	if (err)
		return err;

	base = mmap(NULL, reg.size, PROT_READ | PROT_WRITE, MAP_SHARED,
		    ctx->device_fd, reg.offset);
	if (base == MAP_FAILED)
		return -1;

	ctx->bar_map = (struct mlx5_init_seg *)base;
	ctx->bar_map_size = reg.size;
	return 0;
}

#define MLX5_VFIO_MAX_INTR_VEC_ID 1
#define MSIX_IRQ_SET_BUF_LEN (sizeof(struct vfio_irq_set) + \
			      sizeof(int) * (MLX5_VFIO_MAX_INTR_VEC_ID))

/* enable MSI-X interrupts */
static int
mlx5_vfio_enable_msix(struct mlx5_vfio_context *ctx)
{
	char irq_set_buf[MSIX_IRQ_SET_BUF_LEN];
	struct vfio_irq_set *irq_set;
	int len;
	int *fd_ptr;

	len = sizeof(irq_set_buf);

	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = len;
	irq_set->count = 1;
	irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = VFIO_PCI_MSIX_IRQ_INDEX;
	irq_set->start = 0;
	fd_ptr = (int *)&irq_set->data;
	fd_ptr[0] = ctx->cmd_comp_fd;

	return ioctl(ctx->device_fd, VFIO_DEVICE_SET_IRQS, irq_set);
}

static int mlx5_vfio_init_async_fd(struct mlx5_vfio_context *ctx)
{
	struct vfio_irq_info irq = { .argsz = sizeof(irq) };

	irq.index = VFIO_PCI_MSIX_IRQ_INDEX;
	if (ioctl(ctx->device_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq))
		return -1;

	/* fail if this vector cannot be used with eventfd */
	if ((irq.flags & VFIO_IRQ_INFO_EVENTFD) == 0)
		return -1;

	/* set up an eventfd for command completion interrupts */
	ctx->cmd_comp_fd = eventfd(0, EFD_CLOEXEC);
	if (ctx->cmd_comp_fd < 0)
		return -1;

	if (mlx5_vfio_enable_msix(ctx))
		goto err_msix;

	return 0;

err_msix:
	close(ctx->cmd_comp_fd);
	return -1;
}

static void mlx5_vfio_close_fds(struct mlx5_vfio_context *ctx)
{
	close(ctx->device_fd);
	close(ctx->container_fd);
	close(ctx->group_fd);
	close(ctx->cmd_comp_fd);
}

static int mlx5_vfio_open_fds(struct mlx5_vfio_context *ctx,
			      struct mlx5_vfio_device *mdev)
{
	struct vfio_group_status group_status = { .argsz = sizeof(group_status) };

	/* Create a new container */
	ctx->container_fd = open("/dev/vfio/vfio", O_RDWR);

	if (ctx->container_fd < 0)
		return -1;

	if (ioctl(ctx->container_fd, VFIO_GET_API_VERSION) != VFIO_API_VERSION)
		goto close_cont;

	if (!ioctl(ctx->container_fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU))
		/* Doesn't support the IOMMU driver we want. */
		goto close_cont;

	/* Open the group */
	ctx->group_fd = open(mdev->vfio_path, O_RDWR);
	if (ctx->group_fd < 0)
		goto close_cont;

	/* Test the group is viable and available */
	if (ioctl(ctx->group_fd, VFIO_GROUP_GET_STATUS, &group_status))
		goto close_group;

	if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		/* Group is not viable (ie, not all devices bound for vfio) */
		errno = EINVAL;
		goto close_group;
	}

	/* Add the group to the container */
	if (ioctl(ctx->group_fd, VFIO_GROUP_SET_CONTAINER, &ctx->container_fd))
		goto close_group;

	/* Enable the IOMMU model we want */
	if (ioctl(ctx->container_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU))
		goto close_group;

	/* Get a file descriptor for the device */
	ctx->device_fd = ioctl(ctx->group_fd, VFIO_GROUP_GET_DEVICE_FD,
			       mdev->pci_name);
	if (ctx->device_fd < 0)
		goto close_group;

	if (mlx5_vfio_init_async_fd(ctx))
		goto close_group;

	return 0;

close_group:
	close(ctx->group_fd);
close_cont:
	close(ctx->container_fd);
	return -1;
}

static void mlx5_vfio_uninit_context(struct mlx5_vfio_context *ctx)
{
	mlx5_close_debug_file(ctx->dbg_fp);

	verbs_uninit_context(&ctx->vctx);
	free(ctx);
}

static void mlx5_vfio_free_context(struct ibv_context *ibctx)
{
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(ibctx);

	mlx5_vfio_clean_cmd_interface(ctx);
	mlx5_vfio_clean_device_dma(ctx);
	mlx5_vfio_uninit_bar0(ctx);
	mlx5_vfio_close_fds(ctx);
	mlx5_vfio_uninit_context(ctx);
}

static const struct verbs_context_ops mlx5_vfio_common_ops = {
	.free_context = mlx5_vfio_free_context,
};

static struct verbs_context *
mlx5_vfio_alloc_context(struct ibv_device *ibdev,
			int cmd_fd, void *private_data)
{
	struct mlx5_vfio_device *mdev = to_mvfio_dev(ibdev);
	struct mlx5_vfio_context *mctx;

	cmd_fd = -1;

	mctx = verbs_init_and_alloc_context(ibdev, cmd_fd, mctx, vctx,
					    RDMA_DRIVER_UNKNOWN);
	if (!mctx)
		return NULL;

	mlx5_open_debug_file(&mctx->dbg_fp);
	mlx5_set_debug_mask();

	if (mlx5_vfio_open_fds(mctx, mdev))
		goto err;

	if (mlx5_vfio_init_bar0(mctx))
		goto close_fds;

	if (mlx5_vfio_init_device_dma(mctx))
		goto err_bar;

	if (mlx5_vfio_init_cmd_interface(mctx))
		goto err_dma;

	verbs_set_ops(&mctx->vctx, &mlx5_vfio_common_ops);
	return &mctx->vctx;

err_dma:
	mlx5_vfio_clean_device_dma(mctx);
err_bar:
	mlx5_vfio_uninit_bar0(mctx);
close_fds:
	mlx5_vfio_close_fds(mctx);
err:
	mlx5_vfio_uninit_context(mctx);
	return NULL;
}

static void mlx5_vfio_uninit_device(struct verbs_device *verbs_device)
{
	struct mlx5_vfio_device *dev = to_mvfio_dev(&verbs_device->device);

	free(dev->pci_name);
	free(dev);
}

static const struct verbs_device_ops mlx5_vfio_dev_ops = {
	.name = "mlx5_vfio",
	.alloc_context = mlx5_vfio_alloc_context,
	.uninit_device = mlx5_vfio_uninit_device,
};

static bool is_mlx5_pci(const char *pci_path)
{
	const struct verbs_match_ent *ent;
	uint16_t vendor_id, device_id;
	char pci_info_path[256];
	char buff[128];
	int fd;

	snprintf(pci_info_path, sizeof(pci_info_path), "%s/vendor", pci_path);
	fd = open(pci_info_path, O_RDONLY);
	if (fd < 0)
		return false;

	if (read(fd, buff, sizeof(buff)) <= 0)
		goto err;

	vendor_id = strtoul(buff, NULL, 0);
	close(fd);

	snprintf(pci_info_path, sizeof(pci_info_path), "%s/device", pci_path);
	fd = open(pci_info_path, O_RDONLY);
	if (fd < 0)
		return false;

	if (read(fd, buff, sizeof(buff)) <= 0)
		goto err;

	device_id = strtoul(buff, NULL, 0);
	close(fd);

	for (ent = mlx5_hca_table; ent->kind != VERBS_MATCH_SENTINEL; ent++) {
		if (ent->kind != VERBS_MATCH_PCI)
			continue;
		if (ent->device == device_id && ent->vendor == vendor_id)
			return true;
	}

	return false;

err:
	close(fd);
	return false;
}

static int mlx5_vfio_get_iommu_group_id(const char *pci_name)
{
	int seg, bus, slot, func;
	int ret, groupid;
	char path[128], iommu_group_path[128], *group_name;
	struct stat st;
	ssize_t len;

	ret = sscanf(pci_name, "%04x:%02x:%02x.%d", &seg, &bus, &slot, &func);
	if (ret != 4)
		return -1;

	snprintf(path, sizeof(path),
		 "/sys/bus/pci/devices/%04x:%02x:%02x.%01x/",
		 seg, bus, slot, func);

	ret = stat(path, &st);
	if (ret < 0)
		return -1;

	if (!is_mlx5_pci(path))
		return -1;

	strncat(path, "iommu_group", sizeof(path) - strlen(path) - 1);

	len = readlink(path, iommu_group_path, sizeof(iommu_group_path));
	if (len <= 0)
		return -1;

	iommu_group_path[len] = 0;
	group_name = basename(iommu_group_path);

	if (sscanf(group_name, "%d", &groupid) != 1)
		return -1;

	snprintf(path, sizeof(path), "/dev/vfio/%d", groupid);
	ret = stat(path, &st);
	if (ret < 0)
		return -1;

	return groupid;
}

static int mlx5_vfio_get_handle(struct mlx5_vfio_device *vfio_dev,
			 struct mlx5dv_vfio_context_attr *attr)
{
	int iommu_group;

	iommu_group = mlx5_vfio_get_iommu_group_id(attr->pci_name);
	if (iommu_group < 0)
		return -1;

	sprintf(vfio_dev->vfio_path, "/dev/vfio/%d", iommu_group);
	vfio_dev->pci_name = strdup(attr->pci_name);

	return 0;
}

struct ibv_device **
mlx5dv_get_vfio_device_list(struct mlx5dv_vfio_context_attr *attr)
{
	struct mlx5_vfio_device *vfio_dev;
	struct ibv_device **list = NULL;
	int err;

	if (!check_comp_mask(attr->comp_mask, 0) ||
	    !check_comp_mask(attr->flags, MLX5DV_VFIO_CTX_FLAGS_INIT_LINK_DOWN)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	list = calloc(1, sizeof(struct ibv_device *));
	if (!list) {
		errno = ENOMEM;
		return NULL;
	}

	vfio_dev = calloc(1, sizeof(*vfio_dev));
	if (!vfio_dev) {
		errno = ENOMEM;
		goto end;
	}

	vfio_dev->vdev.ops = &mlx5_vfio_dev_ops;
	atomic_init(&vfio_dev->vdev.refcount, 1);

	/* Find the vfio handle for attrs, store in mlx5_vfio_device */
	err = mlx5_vfio_get_handle(vfio_dev, attr);
	if (err)
		goto err_get;

	vfio_dev->flags = attr->flags;
	vfio_dev->page_size = sysconf(_SC_PAGESIZE);

	list[0] = &vfio_dev->vdev.device;
	return list;

err_get:
	free(vfio_dev);
end:
	free(list);
	return NULL;
}
