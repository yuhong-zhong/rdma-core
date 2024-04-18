/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

#include "hns_roce_u.h"
#include "hns_roce_u_abi.h"

static void hns_roce_free_context(struct ibv_context *ibctx);

#ifndef PCI_VENDOR_ID_HUAWEI
#define PCI_VENDOR_ID_HUAWEI			0x19E5
#endif

static const struct verbs_match_ent hca_table[] = {
	VERBS_MODALIAS_MATCH("acpi*:HISI00D1:*", &hns_roce_u_hw_v1),
	VERBS_MODALIAS_MATCH("of:N*T*Chisilicon,hns-roce-v1C*", &hns_roce_u_hw_v1),
	VERBS_MODALIAS_MATCH("of:N*T*Chisilicon,hns-roce-v1", &hns_roce_u_hw_v1),
	VERBS_PCI_MATCH(PCI_VENDOR_ID_HUAWEI, 0xA222, &hns_roce_u_hw_v2),
	VERBS_PCI_MATCH(PCI_VENDOR_ID_HUAWEI, 0xA223, &hns_roce_u_hw_v2),
	VERBS_PCI_MATCH(PCI_VENDOR_ID_HUAWEI, 0xA224, &hns_roce_u_hw_v2),
	VERBS_PCI_MATCH(PCI_VENDOR_ID_HUAWEI, 0xA225, &hns_roce_u_hw_v2),
	VERBS_PCI_MATCH(PCI_VENDOR_ID_HUAWEI, 0xA226, &hns_roce_u_hw_v2),
	VERBS_PCI_MATCH(PCI_VENDOR_ID_HUAWEI, 0xA227, &hns_roce_u_hw_v2),
	{}
};

static const struct verbs_context_ops hns_common_ops = {
	.alloc_mw = hns_roce_u_alloc_mw,
	.alloc_pd = hns_roce_u_alloc_pd,
	.bind_mw = hns_roce_u_bind_mw,
	.cq_event = hns_roce_u_cq_event,
	.create_cq = hns_roce_u_create_cq,
	.create_qp = hns_roce_u_create_qp,
	.dealloc_mw = hns_roce_u_dealloc_mw,
	.dealloc_pd = hns_roce_u_free_pd,
	.dereg_mr = hns_roce_u_dereg_mr,
	.destroy_cq = hns_roce_u_destroy_cq,
	.modify_cq = hns_roce_u_modify_cq,
	.query_device = hns_roce_u_query_device,
	.query_port = hns_roce_u_query_port,
	.query_qp = hns_roce_u_query_qp,
	.reg_mr = hns_roce_u_reg_mr,
	.rereg_mr = hns_roce_u_rereg_mr,
	.create_srq = hns_roce_u_create_srq,
	.modify_srq = hns_roce_u_modify_srq,
	.query_srq = hns_roce_u_query_srq,
	.destroy_srq = hns_roce_u_destroy_srq,
	.free_context = hns_roce_free_context,
};

static uint32_t calc_table_shift(uint32_t entry_count, uint32_t size_shift)
{
	uint32_t count_shift = hr_ilog32(entry_count);

	return count_shift > size_shift ? count_shift - size_shift : 0;
}

static int hns_roce_init_context_lock(struct hns_roce_context *context)
{
	int ret;

	ret = pthread_spin_init(&context->uar_lock, PTHREAD_PROCESS_PRIVATE);
	if (ret)
		return ret;

	ret = pthread_mutex_init(&context->qp_table_mutex, NULL);
	if (ret)
		goto destroy_uar_lock;

	ret = pthread_mutex_init(&context->db_list_mutex, NULL);
	if (ret)
		goto destroy_qp_mutex;

	return 0;

destroy_qp_mutex:
	pthread_mutex_destroy(&context->qp_table_mutex);

destroy_uar_lock:
	pthread_spin_destroy(&context->uar_lock);
	return ret;
}

static void hns_roce_destroy_context_lock(struct hns_roce_context *context)
{
	pthread_spin_destroy(&context->uar_lock);
	pthread_mutex_destroy(&context->qp_table_mutex);
	pthread_mutex_destroy(&context->db_list_mutex);
}

static struct verbs_context *hns_roce_alloc_context(struct ibv_device *ibdev,
						    int cmd_fd,
						    void *private_data)
{
	struct hns_roce_device *hr_dev = to_hr_dev(ibdev);
	struct hns_roce_alloc_ucontext_resp resp = {};
	struct ibv_device_attr dev_attrs;
	struct hns_roce_context *context;
	struct ibv_get_context cmd;
	int offset = 0;
	int i;

	context = verbs_init_and_alloc_context(ibdev, cmd_fd, context, ibv_ctx,
					       RDMA_DRIVER_HNS);
	if (!context)
		return NULL;

	if (ibv_cmd_get_context(&context->ibv_ctx, &cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp)))
		goto err_ibv_cmd;

	if (hns_roce_init_context_lock(context))
		goto err_ibv_cmd;

	context->qp_table_shift = calc_table_shift(resp.qp_tab_size,
						   HNS_ROCE_QP_TABLE_BITS);
	context->qp_table_mask = (1 << context->qp_table_shift) - 1;

	for (i = 0; i < HNS_ROCE_QP_TABLE_SIZE; ++i)
		context->qp_table[i].refcnt = 0;

	context->uar = mmap(NULL, hr_dev->page_size, PROT_READ | PROT_WRITE,
			    MAP_SHARED, cmd_fd, offset);
	if (context->uar == MAP_FAILED)
		goto err_set_attr;

	offset += hr_dev->page_size;

	if (hr_dev->hw_version == HNS_ROCE_HW_VER1) {
		/*
		 * when vma->vm_pgoff is 1, the cq_tptr_base includes 64K CQ,
		 * a pointer of CQ need 2B size
		 */
		context->cq_tptr_base = mmap(NULL, HNS_ROCE_CQ_DB_BUF_SIZE,
					     PROT_READ | PROT_WRITE, MAP_SHARED,
					     cmd_fd, offset);
		if (context->cq_tptr_base == MAP_FAILED)
			goto db_free;
	}

	if (!resp.cqe_size)
		context->cqe_size = HNS_ROCE_CQE_SIZE;
	else if (resp.cqe_size <= HNS_ROCE_V3_CQE_SIZE)
		context->cqe_size = resp.cqe_size;
	else
		context->cqe_size = HNS_ROCE_V3_CQE_SIZE;


	verbs_set_ops(&context->ibv_ctx, &hns_common_ops);
	verbs_set_ops(&context->ibv_ctx, &hr_dev->u_hw->hw_ops);

	if (hns_roce_u_query_device(&context->ibv_ctx.context, &dev_attrs))
		goto tptr_free;

	context->max_qp_wr = dev_attrs.max_qp_wr;
	context->max_sge = dev_attrs.max_sge;
	context->max_cqe = dev_attrs.max_cqe;

	return &context->ibv_ctx;

tptr_free:
	if (hr_dev->hw_version == HNS_ROCE_HW_VER1) {
		if (munmap(context->cq_tptr_base, HNS_ROCE_CQ_DB_BUF_SIZE))
			fprintf(stderr, PFX "Warning: Munmap tptr failed.\n");
		context->cq_tptr_base = NULL;
	}

db_free:
	munmap(context->uar, hr_dev->page_size);
	context->uar = NULL;

err_set_attr:
	hns_roce_destroy_context_lock(context);
err_ibv_cmd:
	verbs_uninit_context(&context->ibv_ctx);
	free(context);
	return NULL;
}

static void hns_roce_free_context(struct ibv_context *ibctx)
{
	struct hns_roce_device *hr_dev = to_hr_dev(ibctx->device);
	struct hns_roce_context *context = to_hr_ctx(ibctx);

	munmap(context->uar, hr_dev->page_size);
	if (hr_dev->hw_version == HNS_ROCE_HW_VER1)
		munmap(context->cq_tptr_base, HNS_ROCE_CQ_DB_BUF_SIZE);

	hns_roce_destroy_context_lock(context);
	verbs_uninit_context(&context->ibv_ctx);
	free(context);
}

static void hns_uninit_device(struct verbs_device *verbs_device)
{
	struct hns_roce_device *dev = to_hr_dev(&verbs_device->device);

	free(dev);
}

static struct verbs_device *hns_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct hns_roce_device *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	dev->u_hw = sysfs_dev->match->driver_data;
	dev->hw_version = dev->u_hw->hw_version;
	dev->page_size = sysconf(_SC_PAGESIZE);
	return &dev->ibv_dev;
}

static const struct verbs_device_ops hns_roce_dev_ops = {
	.name = "hns",
	.match_min_abi_version = 0,
	.match_max_abi_version = INT_MAX,
	.match_table = hca_table,
	.alloc_device = hns_device_alloc,
	.uninit_device = hns_uninit_device,
	.alloc_context = hns_roce_alloc_context,
};
PROVIDER_DRIVER(hns, hns_roce_dev_ops);
