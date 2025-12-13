#define EXODUS_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct exodus_pbkdf2_sha256_aes
{
  u32 ipad[8];
  u32 opad[8];
  u32 dgst[32];
  u32 out[32];
} exodus_pbkdf2_sha256_aes_t;

DECLSPEC void hmac_sha256_run_V (
  PRIVATE_AS u32x *w0,
  PRIVATE_AS u32x *w1,
  PRIVATE_AS u32x *w2,
  PRIVATE_AS u32x *w3,
  PRIVATE_AS u32x *ipad,
  PRIVATE_AS u32x *opad,
  PRIVATE_AS u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = digest[5];
  w1[2] = digest[6];
  w1[3] = digest[7];
  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 32) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);
}

KERNEL_FQ void exodus_init (KERN_ATTR_TMPS (exodus_pbkdf2_sha256_aes_t))
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  sha256_hmac_ctx_t ctx;
  sha256_hmac_init_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  tmps[gid].ipad[0] = ctx.ipad.h[0];
  tmps[gid].ipad[1] = ctx.ipad.h[1];
  tmps[gid].ipad[2] = ctx.ipad.h[2];
  tmps[gid].ipad[3] = ctx.ipad.h[3];
  tmps[gid].ipad[4] = ctx.ipad.h[4];
  tmps[gid].ipad[5] = ctx.ipad.h[5];
  tmps[gid].ipad[6] = ctx.ipad.h[6];
  tmps[gid].ipad[7] = ctx.ipad.h[7];

  tmps[gid].opad[0] = ctx.opad.h[0];
  tmps[gid].opad[1] = ctx.opad.h[1];
  tmps[gid].opad[2] = ctx.opad.h[2];
  tmps[gid].opad[3] = ctx.opad.h[3];
  tmps[gid].opad[4] = ctx.opad.h[4];
  tmps[gid].opad[5] = ctx.opad.h[5];
  tmps[gid].opad[6] = ctx.opad.h[6];
  tmps[gid].opad[7] = ctx.opad.h[7];

  sha256_hmac_update_global_swap (&ctx,
    esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf,
    esalt_bufs[DIGESTS_OFFSET_HOST].salt_len);

  sha256_hmac_ctx_t ctx2 = ctx;

  u32 w0[4] = { 1, 0, 0, 0 };
  u32 w1[4] = { 0, 0, 0, 0 };
  u32 w2[4] = { 0, 0, 0, 0 };
  u32 w3[4] = { 0, 0, 0, 0 };

  sha256_hmac_update_64 (&ctx2, w0, w1, w2, w3, 4);
  sha256_hmac_final (&ctx2);

  tmps[gid].out[0] = ctx2.opad.h[0];
  tmps[gid].out[1] = ctx2.opad.h[1];
  tmps[gid].out[2] = ctx2.opad.h[2];
  tmps[gid].out[3] = ctx2.opad.h[3];
  tmps[gid].out[4] = ctx2.opad.h[4];
  tmps[gid].out[5] = ctx2.opad.h[5];
  tmps[gid].out[6] = ctx2.opad.h[6];
  tmps[gid].out[7] = ctx2.opad.h[7];
}

KERNEL_FQ void exodus_loop (KERN_ATTR_TMPS (exodus_pbkdf2_sha256_aes_t))
{
  const u64 gid = get_global_id (0);
  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u32x ipad[8];
  u32x opad[8];

  for (int i = 0; i < 8; i++)
  {
    ipad[i] = packv (tmps, ipad, gid, i);
    opad[i] = packv (tmps, opad, gid, i);
  }

  u32x dgst[8];
  u32x out[8];

  for (int i = 0; i < 8; i++)
  {
    dgst[i] = packv (tmps, dgst, gid, i);
    out[i]  = packv (tmps, out,  gid, i);
  }

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = dgst[0];
    w0[1] = dgst[1];
    w0[2] = dgst[2];
    w0[3] = dgst[3];
    w1[0] = dgst[4];
    w1[1] = dgst[5];
    w1[2] = dgst[6];
    w1[3] = dgst[7];
    w2[0] = 0x80000000;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = (64 + 32) * 8;

    hmac_sha256_run_V (w0, w1, w2, w3, ipad, opad, dgst);

    for (int i = 0; i < 8; i++) out[i] ^= dgst[i];
  }

  for (int i = 0; i < 8; i++)
  {
    unpackv (tmps, dgst, gid, i, dgst[i]);
    unpackv (tmps, out,  gid, i, out[i]);
  }
}

KERNEL_FQ void exodus_comp (KERN_ATTR_TMPS (exodus_pbkdf2_sha256_aes_t))
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  const u32 r0 = tmps[gid].out[0];
  const u32 r1 = tmps[gid].out[1];
  const u32 r2 = tmps[gid].out[2];
  const u32 r3 = tmps[gid].out[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}