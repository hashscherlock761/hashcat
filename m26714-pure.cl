#define UNISAT_PURE_CODE
#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct unisat_ctx
{
  u32 lane_state[32];
  u32 mix_state[32];
  u32 acc_state[32];
  u32 final_state[32];
} unisat_ctx_t;

DECLSPEC void unisat_mix_V (
  PRIVATE_AS u32x *a,
  PRIVATE_AS u32x *b,
  PRIVATE_AS u32x *c,
  PRIVATE_AS u32x *d)
{
  for (int i = 0; i < 8; i++)
  {
    a[i] = rotl32 (a[i] + b[i], 7);
    b[i] = rotl32 (b[i] ^ c[i], 11);
    c[i] = rotl32 (c[i] + d[i], 17);
    d[i] = rotl32 (d[i] ^ a[i], 19);
  }
}

DECLSPEC void unisat_round_V (
  PRIVATE_AS u32x *s)
{
  unisat_mix_V (s +  0, s +  8, s + 16, s + 24);
  unisat_mix_V (s + 24, s + 16, s +  8, s +  0);
}

KERNEL_FQ void unisat_init (KERN_ATTR_TMPS (unisat_ctx_t))
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  for (u32 i = 0; i < 32; i++)
  {
    tmps[gid].lane_state[i]  = (u32)(gid * 1315423911u) ^ (i * 0x9e3779b9);
    tmps[gid].mix_state[i]   = tmps[gid].lane_state[i] ^ 0xa5a5a5a5;
    tmps[gid].acc_state[i]   = 0;
    tmps[gid].final_state[i] = 0;
  }
}

KERNEL_FQ void unisat_loop (KERN_ATTR_TMPS (unisat_ctx_t))
{
  const u64 gid = get_global_id (0);
  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u32x s[32];

  for (int i = 0; i < 32; i++)
    s[i] = packv (tmps, lane_state, gid, i);

  for (u32 r = 0; r < LOOP_CNT; r++)
  {
    unisat_round_V (s);

    for (int i = 0; i < 32; i++)
      s[i] ^= (u32x)(r * 0x01010101);
  }

  for (int i = 0; i < 32; i++)
    unpackv (tmps, acc_state, gid, i, s[i]);
}

KERNEL_FQ void unisat_finalize (KERN_ATTR_TMPS (unisat_ctx_t))
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  for (u32 i = 0; i < 32; i++)
  {
    u32 v = tmps[gid].acc_state[i];
    v ^= rotl32 (v, 13);
    v += 0xdeadbeef;
    tmps[gid].final_state[i] = v;
  }
}

KERNEL_FQ void unisat_comp (KERN_ATTR_TMPS (unisat_ctx_t))
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  const u32 r0 = tmps[gid].final_state[0];
  const u32 r1 = tmps[gid].final_state[1];
  const u32 r2 = tmps[gid].final_state[2];
  const u32 r3 = tmps[gid].final_state[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
