#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/param.h>
#include <linux/vfio.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <util/mmio.h>

#include <ccan/array_size.h>

#include "mlx5dv.h"
#include "mlx5_vfio.h"
#include "mlx5.h"
#include "mlx5_ifc.h"

static int mlx5_port_type_to_verbs(int port_type_cap)
{
    switch (port_type_cap) {
    case MLX5_CAP_PORT_TYPE_IB:
        return IBV_LINK_LAYER_INFINIBAND;
    case MLX5_CAP_PORT_TYPE_ETH:
        return IBV_LINK_LAYER_ETHERNET;
    default:
        return IBV_LINK_LAYER_UNSPECIFIED;
    }
}

// For now we only return the value of link_layer
int mlx5_vfio_query_port(struct ibv_context *ibctx, uint8_t port,
		     struct ibv_port_attr *attr)
{
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(ibctx);

	assert(port == 1);

	attr->link_layer = mlx5_port_type_to_verbs(
		MLX5_VFIO_CAP_GEN(ctx, port_type));
	return 0;
}

// For now we only return:
// orig_attr.fw_ver
// phys_port_cnt_ex
int mlx5_vfio_query_device_ex(struct ibv_context *ibctx,
			 const struct ibv_query_device_ex_input *input,
			 struct ibv_device_attr_ex *attr,
			 size_t attr_size)
{
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(ibctx);
	struct mlx5_init_seg *iseg = ctx->bar_map;
	struct ibv_device_attr *a;

	a = &attr->orig_attr;

	snprintf(a->fw_ver, sizeof(a->fw_ver), "%d.%d.%04d",
		be32toh(mmio_read32_be(&iseg->fw_rev)) & 0xffff,
		be32toh(mmio_read32_be(&iseg->fw_rev)) >> 16,
		be32toh(mmio_read32_be(&iseg->cmdif_rev_fw_sub)) & 0xffff);

	attr->phys_port_cnt_ex = max(MLX5_VFIO_CAP_GEN(ctx, num_ports),
                        MLX5_VFIO_CAP_GEN(ctx, num_vhca_ports));

	return 0;
}

struct ibv_cq *mlx5_vfio_create_cq(struct ibv_context *ibctx, int cqe,
			     struct ibv_comp_channel *channel,
			     int comp_vector)
{
	int i, ret;
	uint32_t in[DEVX_ST_SZ_DW(create_cq_in)] = {0};
	uint32_t out[DEVX_ST_SZ_DW(create_cq_out)] = {0};
	uint64_t cqe_cnt = roundup_pow_of_two(cqe);
	void *cq_ctx;
	void *bufs = NULL;
	struct mlx5_vfio_cq *vcq = NULL;
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(ibctx);

	vcq = calloc(1, sizeof(*vcq));
	if (!vcq) {
		errno = ENOMEM;
		return NULL;
	}

	size_t alloc_len = cqe_cnt * sizeof(struct mlx5_cqe64) + 64;
	ret = posix_memalign(&bufs, 4096, alloc_len);
	if (ret) {
		errno = ENOMEM;
		goto err;
	}

	vcq->cq.buf = bufs;
	vcq->cq.dbrec = bufs + cqe_cnt * sizeof(struct mlx5_cqe64);
	vcq->cq.cqe_cnt = cqe_cnt;
	vcq->cq.cqe_size = sizeof(struct mlx5_cqe64);
	vcq->cq.cq_uar = NULL;

	vcq->mem_reg = mlx5dv_devx_umem_reg(ibctx, bufs, alloc_len, IBV_ACCESS_LOCAL_WRITE);
	if (!vcq->mem_reg)
		goto err;

	DEVX_SET(create_cq_in, in, opcode, MLX5_CMD_OP_CREATE_CQ);
	cq_ctx = DEVX_ADDR_OF(create_cq_in, in, cq_context);

	for (i = 0; i < cqe_cnt; i++)
		mlx5dv_set_cqe_owner((struct mlx5_cqe64 *)bufs + i, 1);

	DEVX_SET(cqc, cq_ctx, log_cq_size, ilog32(cqe_cnt - 1));
	DEVX_SET(cqc, cq_ctx, uar_page, ctx->eqs_uar.uarn);

	DEVX_SET(cqc, cq_ctx, c_eqn, ctx->async_eq.eqn);

	DEVX_SET(create_cq_in, in, cq_umem_valid, 1);
	DEVX_SET(create_cq_in, in, cq_umem_id, vcq->mem_reg->umem_id);
	DEVX_SET64(create_cq_in, in, cq_umem_offset, 0);

	DEVX_SET(cqc, cq_ctx, dbr_umem_valid, 1);
	DEVX_SET(cqc, cq_ctx, dbr_umem_id, vcq->mem_reg->umem_id);
	DEVX_SET64(cqc, cq_ctx, dbr_addr, cqe_cnt * sizeof(struct mlx5_cqe64));

	vcq->obj = ctx->dv_ctx_ops->devx_obj_create(ibctx, in, sizeof(in), out, sizeof(out));
	if (!vcq->obj)
		goto err;

	vcq->cq.cqn = DEVX_GET(create_cq_out, out, cqn);

	return &vcq->cq_handle;

err:

	if (vcq->obj)
		ctx->dv_ctx_ops->devx_obj_destroy(vcq->obj);

	if (vcq->mem_reg)
		ctx->dv_ctx_ops->devx_umem_dereg(vcq->mem_reg);

	if (vcq->cq.buf)
		free(vcq->cq.buf);

	free(vcq);

	return NULL;
}

