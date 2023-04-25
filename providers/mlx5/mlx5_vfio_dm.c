
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

#define MLX5_LOG_SW_ICM_BLOCK_SIZE(ctx) \
	(MLX5_VFIO_CAP_DEV_MEM(ctx, log_sw_icm_alloc_granularity))
#define MLX5_SW_ICM_BLOCK_SIZE(ctx) (1UL << MLX5_LOG_SW_ICM_BLOCK_SIZE(ctx))
#define DIV_ROUND_UP_ULL(x, y) \
	((unsigned long long)(((unsigned long long)x + (unsigned long long)y - 1) / (unsigned long long)y))



int mlx5_vfio_dm_init(struct mlx5_vfio_context *ctx)
{
	uint64_t header_modify_pattern_icm_blocks = 0;
	uint64_t header_modify_icm_blocks = 0;
	uint64_t steering_icm_blocks = 0;
	struct mlx5_dm_internal *dm = &ctx->dm;
	bool support_v2;
	int ret;

	if (!(MLX5_VFIO_CAP_GEN_64(ctx, general_obj_types) &
		  MLX5_GENERAL_OBJ_TYPES_CAP_SW_ICM))
		return -ENOTSUP;

	pthread_mutex_init(&ctx->dm.lock, NULL);

	ret = mlx5_vfio_get_caps(ctx, MLX5_CAP_DEV_MEM);
	if (ret)
		return ret;

	ret = mlx5_vfio_get_caps(ctx, MLX5_CAP_FLOW_TABLE);
	if (ret)
		return ret;

	if (MLX5_VFIO_CAP64_DEV_MEM(ctx, steering_sw_icm_start_address)) {
		steering_icm_blocks =
			BIT(MLX5_VFIO_CAP_DEV_MEM(ctx, log_steering_sw_icm_size) -
			    MLX5_LOG_SW_ICM_BLOCK_SIZE(ctx));

		dm->steering_sw_icm_alloc_blocks =
			bitmap_alloc0(steering_icm_blocks);
		if (!dm->steering_sw_icm_alloc_blocks)
			goto err_steering;
	}

	if (MLX5_VFIO_CAP64_DEV_MEM(ctx, header_modify_sw_icm_start_address)) {
		header_modify_icm_blocks =
			BIT(MLX5_VFIO_CAP_DEV_MEM(ctx, log_header_modify_sw_icm_size) -
			    MLX5_LOG_SW_ICM_BLOCK_SIZE(ctx));

		dm->header_modify_sw_icm_alloc_blocks =
			bitmap_alloc0(header_modify_icm_blocks);
		if (!dm->header_modify_sw_icm_alloc_blocks)
			goto err_modify_hdr;
	}

	support_v2 = MLX5_VFIO_CAP_FLOWTABLE_NIC_RX(ctx, sw_owner_v2) &&
		     MLX5_VFIO_CAP_FLOWTABLE_NIC_TX(ctx, sw_owner_v2) &&
		     MLX5_VFIO_CAP64_DEV_MEM(ctx, header_modify_pattern_sw_icm_start_address);

	if (support_v2) {
		header_modify_pattern_icm_blocks =
			BIT(MLX5_VFIO_CAP_DEV_MEM(ctx, log_header_modify_pattern_sw_icm_size) -
			    MLX5_LOG_SW_ICM_BLOCK_SIZE(ctx));

		dm->header_modify_pattern_sw_icm_alloc_blocks =
			bitmap_alloc0(header_modify_pattern_icm_blocks);
		if (!dm->header_modify_pattern_sw_icm_alloc_blocks)
			goto err_pattern;
	}

	return 0;

err_pattern:
	free(dm->header_modify_sw_icm_alloc_blocks);

err_modify_hdr:
	free(dm->steering_sw_icm_alloc_blocks);

err_steering:
	return -ENOMEM;
}

static int mlx5_dm_sw_icm_alloc(struct mlx5_vfio_context *ctx, int type,
			 uint64_t length, uint32_t log_alignment,
			 uintptr_t *addr, uint32_t *obj_id)
{
	uint32_t num_blocks = DIV_ROUND_UP_ULL(length, MLX5_SW_ICM_BLOCK_SIZE(ctx));
	uint32_t out[DEVX_ST_SZ_DW(general_obj_out_cmd_hdr)] = {};
	uint32_t in[DEVX_ST_SZ_DW(create_sw_icm_in)] = {};
	struct mlx5_dm_internal *dm = &ctx->dm;
	unsigned long *block_map;
	uint64_t icm_start_addr;
	uint32_t log_icm_size;
	uint64_t align_mask;
	uint32_t max_blocks;
	uint64_t block_idx;
	void *sw_icm;
	int ret;

	if (!length || (length & (length - 1)) ||
	    length & (MLX5_SW_ICM_BLOCK_SIZE(ctx) - 1))
		return -EINVAL;

	DEVX_SET(general_obj_in_cmd_hdr, in, opcode,
		 MLX5_CMD_OP_CREATE_GENERAL_OBJECT);
	DEVX_SET(general_obj_in_cmd_hdr, in, obj_type, MLX5_OBJ_TYPE_SW_ICM);

	switch (type) {
	case MLX5DV_DM_TYPE_STEERING_SW_ICM:
		icm_start_addr = MLX5_VFIO_CAP64_DEV_MEM(ctx, steering_sw_icm_start_address);
		log_icm_size = MLX5_VFIO_CAP_DEV_MEM(ctx, log_steering_sw_icm_size);
		block_map = dm->steering_sw_icm_alloc_blocks;
		break;
	case MLX5DV_DM_TYPE_HEADER_MODIFY_SW_ICM:
		icm_start_addr = MLX5_VFIO_CAP64_DEV_MEM(ctx, header_modify_sw_icm_start_address);
		log_icm_size = MLX5_VFIO_CAP_DEV_MEM(ctx,
						log_header_modify_sw_icm_size);
		block_map = dm->header_modify_sw_icm_alloc_blocks;
		break;
	case MLX5DV_DM_TYPE_HEADER_MODIFY_PATTERN_SW_ICM:
		icm_start_addr = MLX5_VFIO_CAP64_DEV_MEM(ctx,
						    header_modify_pattern_sw_icm_start_address);
		log_icm_size = MLX5_VFIO_CAP_DEV_MEM(ctx,
						log_header_modify_pattern_sw_icm_size);
		block_map = dm->header_modify_pattern_sw_icm_alloc_blocks;
		break;
	default:
		return -EINVAL;
	}

	if (!block_map)
		return -EOPNOTSUPP;

	max_blocks = BIT(log_icm_size - MLX5_LOG_SW_ICM_BLOCK_SIZE(ctx));

	if (log_alignment < MLX5_LOG_SW_ICM_BLOCK_SIZE(ctx))
		log_alignment = MLX5_LOG_SW_ICM_BLOCK_SIZE(ctx);
	align_mask = BIT(log_alignment - MLX5_LOG_SW_ICM_BLOCK_SIZE(ctx)) - 1;

	pthread_mutex_lock(&dm->lock);


	unsigned long start = 0;
again:
	block_idx = bitmap_find_free_region_start(block_map, start, max_blocks, num_blocks);
	block_idx = (block_idx + align_mask) & ~align_mask;
	if (block_idx < max_blocks &&
		bitmap_find_free_region_start(block_map, block_idx, max_blocks, num_blocks) != block_idx) {
		start = block_idx;
		goto again;
	}

	if (block_idx < max_blocks)
		bitmap_set_bit(block_map, block_idx);

	pthread_mutex_unlock(&dm->lock);

	if (block_idx >= max_blocks)
		return -ENOMEM;

	sw_icm = DEVX_ADDR_OF(create_sw_icm_in, in, sw_icm);
	icm_start_addr += block_idx << MLX5_LOG_SW_ICM_BLOCK_SIZE(ctx);
	DEVX_SET64(sw_icm, sw_icm, sw_icm_start_addr,
		   icm_start_addr);
	DEVX_SET(sw_icm, sw_icm, log_sw_icm_size, ilog32(length));

	ret = mlx5_vfio_cmd_exec(ctx, (void *)in, sizeof(in), out, sizeof(out), 0);
	if (ret) {
		pthread_mutex_lock(&dm->lock);
		bitmap_clear_bit(block_map,
			     block_idx);
		pthread_mutex_unlock(&dm->lock);

		return ret;
	}

	*addr = icm_start_addr;
	*obj_id = DEVX_GET(general_obj_out_cmd_hdr, out, obj_id);

	return 0;
}

struct ibv_dm *mlx5_vfio_alloc_dm(struct ibv_context *ibctx,
				   struct ibv_alloc_dm_attr *dm_attr,
				   struct mlx5dv_alloc_dm_attr *mlx5_dm_attr)
{
	struct mlx5_dm *dm;
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(ibctx);
	uint32_t obj_id;
	int ret;

	dm = calloc(1, sizeof(*dm));
	if (!dm) {
		errno = ENOMEM;
		return NULL;
	}

	ret = mlx5_dm_sw_icm_alloc(ctx, mlx5_dm_attr->type, dm_attr->length,
		                       dm_attr->log_align_req, &dm->remote_va, &obj_id);
	if (ret) {
		free(dm);
		errno = ret;
		return NULL;
	}

	dm->verbs_dm.dm.context = ibctx;
	dm->length = dm_attr->length;
	dm->verbs_dm.handle = obj_id;
	return &dm->verbs_dm.dm;
}

enum {
	MLX5_DM_ALLOWED_ACCESS = IBV_ACCESS_LOCAL_WRITE		|
				 IBV_ACCESS_REMOTE_WRITE	|
				 IBV_ACCESS_REMOTE_READ		|
				 IBV_ACCESS_REMOTE_ATOMIC	|
				 IBV_ACCESS_ZERO_BASED		|
				 IBV_ACCESS_OPTIONAL_RANGE
};

static void set_mkc_access_pd_addr_fields(void *mkc, int acc, uint64_t start_addr,
					  struct ibv_pd *pd)
{
	struct mlx5_pd *mpd = to_mpd(pd);

	DEVX_SET(mkc, mkc, a, !!(acc & IBV_ACCESS_REMOTE_ATOMIC));
	DEVX_SET(mkc, mkc, rw, !!(acc & IBV_ACCESS_REMOTE_WRITE));
	DEVX_SET(mkc, mkc, rr, !!(acc & IBV_ACCESS_REMOTE_READ));
	DEVX_SET(mkc, mkc, lw, !!(acc & IBV_ACCESS_LOCAL_WRITE));
	DEVX_SET(mkc, mkc, lr, 1);
	/* Application is responsible to set based on caps */
	DEVX_SET(mkc, mkc, relaxed_ordering_write,
		 !!(acc & IBV_ACCESS_RELAXED_ORDERING));
	DEVX_SET(mkc, mkc, relaxed_ordering_read,
		 !!(acc & IBV_ACCESS_RELAXED_ORDERING));
	DEVX_SET(mkc, mkc, pd, mpd->pdn);
	DEVX_SET(mkc, mkc, qpn, 0xffffff);
	DEVX_SET64(mkc, mkc, start_addr, start_addr);
}

static inline uint32_t mlx5_idx_to_mkey(uint32_t mkey_idx)
{
	return mkey_idx << 8;
}


static int mlx5_core_create_mkey(struct mlx5_vfio_context *ctx, uint32_t *mkey, uint32_t *in,
			  int inlen)
{
	uint32_t lout[DEVX_ST_SZ_DW(create_mkey_out)] = {};
	uint32_t mkey_index;
	int err;

	DEVX_SET(create_mkey_in, in, opcode, MLX5_CMD_OP_CREATE_MKEY);

	err = mlx5_vfio_cmd_exec(ctx, in, inlen, lout, sizeof(lout), 0);
	if (err)
		return err;

	mkey_index = DEVX_GET(create_mkey_out, lout, mkey_index);
	*mkey = DEVX_GET(create_mkey_in, in, memory_key_mkey_entry.mkey_7_0) |
		mlx5_idx_to_mkey(mkey_index);

	return 0;
}


static void assign_mkey_variant(struct mlx5_vfio_context *ctx, uint32_t *mkey, uint32_t *in)
{
	struct mlx5_vfio_device *dev = to_mvfio_dev(ctx->vctx.context.device);

	uint8_t key = atomic_fetch_add(&dev->mkey_var, 1);
	void *mkc;

	mkc = DEVX_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	DEVX_SET(mkc, mkc, mkey_7_0, key);
	*mkey = key;
}


static int mlx5_ib_create_mkey(struct mlx5_vfio_context *ctx,
			       uint32_t *mkey, uint32_t *in, int inlen)
{
	int ret;

	assign_mkey_variant(ctx, mkey, in);
	ret = mlx5_core_create_mkey(ctx, mkey, in, inlen);

	return ret;
}

static int mlx5_ib_get_dm_mr(struct ibv_pd *pd, uint64_t start_addr,
				       uint64_t length, int acc, int mode, uint32_t *mkey_out)
{
	struct mlx5_vfio_context *ctx = to_mvfio_ctx(pd->context);

	int inlen = DEVX_ST_SZ_BYTES(create_mkey_in);
	// struct mlx5_ib_mr *mr;
	void *mkc;
	uint32_t *in;
	int err;

	uint32_t mkey;

	// mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	// if (!mr)
	// 	return ERR_PTR(-ENOMEM);

	in = calloc(1, inlen);
	if (!in) {
		err = -ENOMEM;
		goto err_free;
	}

	mkc = DEVX_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);

	DEVX_SET(mkc, mkc, access_mode_1_0, mode & 0x3);
	DEVX_SET(mkc, mkc, access_mode_4_2, (mode >> 2) & 0x7);
	DEVX_SET64(mkc, mkc, len, length);
	set_mkc_access_pd_addr_fields(mkc, acc, start_addr, pd);

	err = mlx5_ib_create_mkey(ctx, &mkey, in, inlen);
	if (err)
		goto err_in;

	free(in);

	// set_mr_fields(dev, mr, length, acc, start_addr);
	*mkey_out = mkey;
	return 0;

err_in:
	free(in);

err_free:
// 	kfree(mr);

	return err;
}

static int ibv_cmd_reg_dm_mr_internal(struct ibv_pd *pd, struct mlx5_dm *dm,
		      uint64_t offset, size_t length,
		      unsigned int access, struct verbs_mr *vmr)
{

	uint32_t lkey;
	int ret;

	/*
	 * DM MRs are always 0 based since the mmap pointer, if it exists, is
	 * hidden from the user.
	 */
	if (!(access & IBV_ACCESS_ZERO_BASED)) {
		errno = EINVAL;
		return errno;
	}

	ret = mlx5_ib_get_dm_mr(pd, dm->remote_va, length,
				 access, MLX5_MKC_ACCESS_MODE_SW_ICM, &lkey);
	if (ret)
		return errno;

	vmr->ibv_mr.context = pd->context;
	vmr->ibv_mr.lkey = lkey;
	vmr->ibv_mr.rkey = lkey;
	vmr->ibv_mr.length = length;
	vmr->ibv_mr.pd = pd;
	vmr->ibv_mr.addr = NULL;
	vmr->mr_type  = IBV_MR_TYPE_MR;

	return 0;
}


struct ibv_mr *mlx5_vfio_reg_dm_mr(struct ibv_pd *pd, struct ibv_dm *ibdm,
			      uint64_t dm_offset, size_t length,
			      unsigned int acc)
{
	struct mlx5_dm *dm = container_of(ibdm, struct mlx5_dm, verbs_dm.dm);
	struct mlx5_mr *mr;
	int ret;

	if (acc & ~MLX5_DM_ALLOWED_ACCESS) {
		errno = EINVAL;
		return NULL;
	}

	mr = calloc(1, sizeof(*mr));
	if (!mr) {
		errno = ENOMEM;
		return NULL;
	}

	ret = ibv_cmd_reg_dm_mr_internal(pd, dm, dm_offset, length, acc,
				&mr->vmr);
	if (ret) {
		free(mr);
		return NULL;
	}

	mr->alloc_flags = acc;
	mr->vmr.ibv_mr.context = pd->context;

	return &mr->vmr.ibv_mr;
}
