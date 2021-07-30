#ifdef KAT
#include <stdio.h>
#endif

#include <stdlib.h> /* for abort() in case of OpenSSL failures */
#include "params.h"

#include "randombytes.h"
#include "crypto_hash_sha512.h"
#ifdef LPR
#include "crypto_stream_aes256ctr.h"
#endif

#include "int8.h"
#include "int16.h"
#include "int32.h"
#include "uint16.h"
#include "uint32.h"
#include "crypto_sort_uint32.h"
#include "Encode.h"
#include "Decode.h"
#include <math.h>

/* ----- crypto_kem API */

#include "crypto_kem.h"

static int shift_lfsr(unsigned int *lfsr, unsigned int polynomial_mask)
{
    int feedback;

    feedback = *lfsr & 1;
    *lfsr >>= 1;
    if(feedback == 1)
        *lfsr ^= polynomial_mask;
    return *lfsr;
}

static int get_random(void)
{
    int temp;
    unsigned int POLY_MASK_HERE_1 = 0xAB65879A;
    unsigned int POLY_MASK_HERE_2 = 0x56637263;
    static unsigned int lfsr_1 = 0x9FAB54EB;
    static unsigned int lfsr_2 = 0x5DEC9221;
    shift_lfsr(&lfsr_1, POLY_MASK_HERE_1);
    shift_lfsr(&lfsr_2, POLY_MASK_HERE_2);
    temp = (shift_lfsr(&lfsr_1, POLY_MASK_HERE_1) ^ shift_lfsr(&lfsr_2, POLY_MASK_HERE_2)) & 0XFF;
    return (temp);
}

/* ----- masks */


#ifndef LPR

/* return -1 if x!=0; else return 0 */
static int int16_nonzero_mask(int16 x)
{
  uint16 u = x; /* 0, else 1...65535 */
  uint32 v = u; /* 0, else 1...65535 */
  v = -v; /* 0, else 2^32-65535...2^32-1 */
  v >>= 31; /* 0, else 1 */
  return -v; /* 0, else -1 */
}

#endif

/* return -1 if x<0; otherwise return 0 */
static int int16_negative_mask(int16 x)
{
  uint16 u = x;
  u >>= 15;
  return -(int) u;
  /* alternative with gcc -fwrapv: */
  /* x>>15 compiles to CPU's arithmetic right shift */
}

/* ----- arithmetic mod 3 */


extern int intended_function;
extern int sec_index;
extern int collision_array_pos[count_threshold];
extern int collision_array_neg[count_threshold];

extern int succ_flag;
extern int count_ones;
extern int count_plus_ones;
extern int count_minus_ones;
extern int non_zero_f_coeff;
extern int non_zero_g_coeff;
extern int c_value;
extern int c_value_1;
extern int c_value_2;
extern int c_value_for_attack_1;
extern int c_value_for_attack_2;
extern int global_mask;


int c_value_for_attack_1_1;
int c_value_for_attack_1_2;
int c_value_for_attack_1_3;

int c_value_for_attack_2_1;
int c_value_for_attack_2_2;
int c_value_for_attack_2_3;

int c1_value_1, c1_value_2, c1_value_3;
int c2_value_1, c2_value_2, c2_value_3;

extern int c_value_for_leakage;
extern int collision_index;
extern int collision_value;

extern int error_now;

extern int m;
extern int n;

extern small er[p];
extern small er_decrypt[p];
extern small global_f[p];
extern small global_g[p];
/* ----- arithmetic mod q */

extern Fq global_c_in_encrypt[p];
extern Fq global_c_in_decrypt[p];
extern Fq global_valid_hr[p];

extern Fq x_f_array[p];
extern Fq x_g_array[p];
extern Fq cf3[p];
extern Fq c_copy[p];
extern Fq f_diff_3[p];
extern Fq cf[p];
extern small e[p];
extern small ev[p];

/* F3 is always represented as -1,0,1 */
/* so ZZ_fromF3 is a no-op */

/* x must not be close to top int16 */
static small F3_freeze(int16 x)
{
  return int32_mod_uint14(x+1,3)-1;
}

/* always represented as -q12...q12 */
/* so ZZ_fromFq is a no-op */

/* x must not be close to top int32 */
static Fq Fq_freeze(int32 x)
{
  return int32_mod_uint14(x+q12,q)-q12;
}

#ifndef LPR

static Fq Fq_recip(Fq a1)
{
  int i = 1;
  Fq ai = a1;

  while (i < q-2) {
    ai = Fq_freeze(a1*(int32)ai);
    i += 1;
  }
  return ai;
}

#endif

/* ----- Top and Right */

#ifdef LPR
#define tau 16

static int8 Top(Fq C)
{
  return (tau1*(int32)(C+tau0)+16384)>>15;
}

static Fq Right(int8 T)
{
  return Fq_freeze(tau3*(int32)T-tau2);
}
#endif

/* ----- small polynomials */

#ifndef LPR

/* 0 if Weightw_is(r), else -1 */
static int Weightw_mask(small *r)
{
  int weight = 0;
  int i;

  for (i = 0;i < p;++i) weight += r[i]&1;
  // printf("weight: %d\n", weight);
  return int16_nonzero_mask(weight-w);
}

/* R3_fromR(R_fromRq(r)) */
static void R3_fromRq(small *out,const Fq *r)
{
  int i;
  for (i = 0;i < p;++i) out[i] = F3_freeze(r[i]);
}

/* h = f*g in the ring R3 */
static void R3_mult(small *h,const small *f,const small *g)
{
  small fg[p+p-1];
  small result;
  int i,j;

  for (i = 0;i < p;++i) {
    result = 0;
    for (j = 0;j <= i;++j) result = F3_freeze(result+f[j]*g[i-j]);
    fg[i] = result;
  }
  for (i = p;i < p+p-1;++i) {
    result = 0;
    for (j = i-p+1;j < p;++j) result = F3_freeze(result+f[j]*g[i-j]);
    fg[i] = result;
  }

  for (i = p+p-2;i >= p;--i) {
    fg[i-p] = F3_freeze(fg[i-p]+fg[i]);
    fg[i-p+1] = F3_freeze(fg[i-p+1]+fg[i]);
  }

  for (i = 0;i < p;++i) h[i] = fg[i];
}

/* returns 0 if recip succeeded; else -1 */
static int R3_recip(small *out,const small *in)
{
  small f[p+1],g[p+1],v[p+1],r[p+1];
  int i,loop,delta;
  int sign,swap,t;

  for (i = 0;i < p+1;++i) v[i] = 0;
  for (i = 0;i < p+1;++i) r[i] = 0;
  r[0] = 1;
  for (i = 0;i < p;++i) f[i] = 0;
  f[0] = 1; f[p-1] = f[p] = -1;
  for (i = 0;i < p;++i) g[p-1-i] = in[i];
  g[p] = 0;

  delta = 1;

  for (loop = 0;loop < 2*p-1;++loop) {
    for (i = p;i > 0;--i) v[i] = v[i-1];
    v[0] = 0;

    sign = -g[0]*f[0];
    swap = int16_negative_mask(-delta) & int16_nonzero_mask(g[0]);
    delta ^= swap&(delta^-delta);
    delta += 1;

    for (i = 0;i < p+1;++i) {
      t = swap&(f[i]^g[i]); f[i] ^= t; g[i] ^= t;
      t = swap&(v[i]^r[i]); v[i] ^= t; r[i] ^= t;
    }

    for (i = 0;i < p+1;++i) g[i] = F3_freeze(g[i]+sign*f[i]);
    for (i = 0;i < p+1;++i) r[i] = F3_freeze(r[i]+sign*v[i]);

    for (i = 0;i < p;++i) g[i] = g[i+1];
    g[p] = 0;
  }

  sign = f[0];
  for (i = 0;i < p;++i) out[i] = sign*v[p-1-i];

  return int16_nonzero_mask(delta);
}

#endif

/* ----- polynomials mod q */

/* h = f*g in the ring Rq */
static void Rq_mult_small(Fq *h,const Fq *f,const small *g)
{
  Fq fg[p+p-1];
  Fq result;
  int i,j;

  for (i = 0;i < p;++i) {
    result = 0;
    for (j = 0;j <= i;++j) result = Fq_freeze(result+f[j]*(int32)g[i-j]);
    fg[i] = result;
  }
  for (i = p;i < p+p-1;++i) {
    result = 0;
    for (j = i-p+1;j < p;++j) result = Fq_freeze(result+f[j]*(int32)g[i-j]);
    fg[i] = result;
  }

  for (i = p+p-2;i >= p;--i) {
    fg[i-p] = Fq_freeze(fg[i-p]+fg[i]);
    fg[i-p+1] = Fq_freeze(fg[i-p+1]+fg[i]);
  }

  for (i = 0;i < p;++i) h[i] = fg[i];
}

#ifndef LPR

/* h = 3f in Rq */
static void Rq_mult3(Fq *h,const Fq *f)
{
  int i;

  for (i = 0;i < p;++i) h[i] = Fq_freeze(3*f[i]);
}

/* out = 1/(3*in) in Rq */
/* returns 0 if recip succeeded; else -1 */
static int Rq_recip3(Fq *out,const small *in)
{
  Fq f[p+1],g[p+1],v[p+1],r[p+1];
  int i,loop,delta;
  int swap,t;
  int32 f0,g0;
  Fq scale;

  for (i = 0;i < p+1;++i) v[i] = 0;
  for (i = 0;i < p+1;++i) r[i] = 0;
  r[0] = Fq_recip(3);
  for (i = 0;i < p;++i) f[i] = 0;
  f[0] = 1; f[p-1] = f[p] = -1;
  for (i = 0;i < p;++i) g[p-1-i] = in[i];
  g[p] = 0;

  delta = 1;

  for (loop = 0;loop < 2*p-1;++loop) {
    for (i = p;i > 0;--i) v[i] = v[i-1];
    v[0] = 0;

    swap = int16_negative_mask(-delta) & int16_nonzero_mask(g[0]);
    delta ^= swap&(delta^-delta);
    delta += 1;

    for (i = 0;i < p+1;++i) {
      t = swap&(f[i]^g[i]); f[i] ^= t; g[i] ^= t;
      t = swap&(v[i]^r[i]); v[i] ^= t; r[i] ^= t;
    }

    f0 = f[0];
    g0 = g[0];
    for (i = 0;i < p+1;++i) g[i] = Fq_freeze(f0*g[i]-g0*f[i]);
    for (i = 0;i < p+1;++i) r[i] = Fq_freeze(f0*r[i]-g0*v[i]);

    for (i = 0;i < p;++i) g[i] = g[i+1];
    g[p] = 0;
  }

  scale = Fq_recip(f[0]);
  for (i = 0;i < p;++i) out[i] = Fq_freeze(scale*(int32)v[p-1-i]);

  return int16_nonzero_mask(delta);
}

#endif

/* ----- rounded polynomials mod q */

static void Round(Fq *out,const Fq *a)
{
  int i;
  for (i = 0;i < p;++i) out[i] = a[i]-F3_freeze(a[i]);
}

/* ----- sorting to generate short polynomial */

static void Short_fromlist(small *out,const uint32 *in)
{
  uint32 L[p];
  int i;

  for (i = 0;i < w;++i) L[i] = in[i]&(uint32)-2;
  for (i = w;i < p;++i) L[i] = (in[i]&(uint32)-3)|1;
  crypto_sort_uint32(L,p);
  for (i = 0;i < p;++i) out[i] = (L[i]&3)-1;
}

/* ----- underlying hash function */

#define Hash_bytes 32

/* e.g., b = 0 means out = Hash0(in) */
static void Hash_prefix(unsigned char *out,int b,const unsigned char *in,int inlen)
{
  unsigned char x[inlen+1];
  unsigned char h[64];
  int i;

  x[0] = b;
  for (i = 0;i < inlen;++i) x[i+1] = in[i];
  crypto_hash_sha512(h,x,inlen+1);
  for (i = 0;i < 32;++i) out[i] = h[i];
}

/* ----- higher-level randomness */

static uint32 urandom32(void)
{
  unsigned char c[4];
  uint32 out[4];

  randombytes(c,4);
  out[0] = (uint32)c[0];
  out[1] = ((uint32)c[1])<<8;
  out[2] = ((uint32)c[2])<<16;
  out[3] = ((uint32)c[3])<<24;
  return out[0]+out[1]+out[2]+out[3];
}

static void Short_random(small *out)
{
  uint32 L[p];
  int i;

  uint32 r_value;

  // for (i = 0;i < p;++i) L[i] = urandom32();

  for (i = 0;i < p;++i)
  {
    r_value = ((get_random()*256 + get_random())<<16) + (get_random()*256 + get_random());
    L[i] = r_value;
  }

  Short_fromlist(out,L);
}

#ifndef LPR

static void Small_random(small *out)
{
  int i;

  // for (i = 0;i < p;++i) out[i] = (((urandom32()&0x3fffffff)*3)>>30)-1;

  uint32 r_value;
  for (i = 0;i < p;++i)
  {
    r_value = ((get_random()*256 + get_random())<<16) + (get_random()*256 + get_random());
    out[i] = (((r_value&0x3fffffff)*3)>>30)-1;
  }

}

#endif

/* ----- Streamlined NTRU Prime Core */

#ifndef LPR

/* h,(f,ginv) = KeyGen() */
static void KeyGen(Fq *h,small *f,small *ginv)
{
  small g[p];
  Fq finv[p];

  for (;;)
  {
    Small_random(g);
    if (R3_recip(ginv,g) == 0) break;
  }
  Short_random(f);
  Rq_recip3(finv,f); /* always works */

  printf("Printing f...\n");
  for(int i = 0; i < p; i++)
  {
    global_f[i] = f[i];
    printf("%d, ", f[i]);
  }
  printf("\n");

  for(int i = 0; i < p; i++)
  {
    global_g[i] = g[i];
  }

  Rq_mult_small(h,finv,g);
}

#if (DO_ATTACK_COLLISION_NEW == 1)

/* c = Encrypt(r,h) */

// Procedure to Create Malformed Ciphertexts.... This encryption procedure can operate in different modes depending upon the
// value of the variable "intended_function"...

static void Encrypt(Fq *c,const small *r,const Fq *h)
{
  Fq hr[p];

  small x_f_array_copy[p];
  small x_g_array_copy[p];

  Fq x_f_prod[p];
  Fq x_g_prod[p];

  double result;

  // If intended_function == 0, then we are trying to create ciphertexts for single collision... we are randomly choosing polynomials d1 and d2 for
  // the ciphertext c...

  if(intended_function == 0)
  {

      // Construct d1 = (x^i1 + x^i2 + .... + x^im)...

      for(int we1 = 0; we1 < p; we1++)
      {
        x_f_array[we1] = 0;
      }

      for(int we1 = 0; we1 < m; we1++)
      {
        int found = 0;
        int index;
        while(found == 0)
        {
          int rand_value = (get_random()*256 + get_random());
          index = rand_value%p;
          if(index < 0)
            index = index + p;

          if(index >= 0 && index < p)
            found = 1;

        }
        x_f_array[index] = 1;
        non_zero_f_coeff = index;
      }

      // Construct d2 = (x^j1 + x^j2 + .... + x^jn)...


      for(int we1 = 0; we1 < p; we1++)
      {
        x_g_array[we1] = 0;
      }
      for(int we1 = 0; we1 < n; we1++)
      {
        int found = 0;
        int index;
        while(found == 0)
        {
          int rand_value = (get_random()*256 + get_random());
          index = rand_value%p;
          if(index < 0)
            index = index + p;


          if(index >= 0 && index < p)
            found = 1;
        }

        x_g_array[index] = 1;
        non_zero_g_coeff = index;
      }

      for(int yr = 0; yr < p; yr++)
      {
        x_f_array_copy[yr] = x_f_array[yr];
        x_g_array_copy[yr] = x_g_array[yr];
      }

      // Construct ciphertext c = k1 . d1 + k2 . d2 . h where k1 = c_value_1 and k2 = c_value_2...

      Fq x_f_int[p];
      Fq x_g_int[p];

      Rq_mult_small(x_g_int,h,x_g_array_copy);

      int32 temp_value;
      for(int sd = 0; sd < p; sd++)
      {
        temp_value = (x_f_array[sd]*c_value_1) + (x_g_int[sd]*c_value_2);
        hr[sd] = Fq_freeze(temp_value);
      }

      for(int i = 0; i < p; i++)
        global_c_in_encrypt[i] = hr[i];

      Round(c,hr);

  }

  // Here, we build attack ciphertexts as c = (l1 . d1 + l2 . d2 . h + l3 . x^u) where d1 and d2 are from the base ciphertext...

  if(intended_function == 1)
  {

    // Get d1 and d2 from x_f_array and x_g_array variables...

    for(int yr = 0; yr < p; yr++)
    {
      x_f_array_copy[yr] = x_f_array[yr];
      x_g_array_copy[yr] = x_g_array[yr];
    }

    Fq x_f_int[p];
    Fq x_g_int[p];

    // Construct ciphertext c = l1 . d1 + l2 . d2 . h + l3 . x^u

    Rq_mult_small(x_g_int,h,x_g_array_copy);


    Fq x_f_attack_array[p];

    for(int gd = 0; gd<p; gd++)
      x_f_attack_array[gd] = 0;

    x_f_attack_array[sec_index] = 1;

    int c_value_for_now;

    if(check_for_value == 1)
    {
      c_value_for_now = c_value_for_attack_1;
    }
    else if(check_for_value == -1)
    {
      c_value_for_now = c_value_for_attack_1;
    }
    else if(check_for_value == 2)
    {
      c_value_for_now = c_value_for_attack_2;
    }
    else if(check_for_value == -2)
    {
      c_value_for_now = c_value_for_attack_2;
    }

    int c_value_for_now_1;
    int c_value_for_now_2;
    int c_value_for_now_3;

    if(check_for_value == 1)
    {
      c_value_for_now_1 = c_value_for_attack_1_1;
      c_value_for_now_2 = c_value_for_attack_1_2;
      c_value_for_now_3 = c_value_for_attack_1_3;
    }
    else if(check_for_value == -1)
    {
      c_value_for_now_1 = c_value_for_attack_1_1;
      c_value_for_now_2 = c_value_for_attack_1_2;
      c_value_for_now_3 = c_value_for_attack_1_3;
    }
    else if(check_for_value == 2)
    {
      c_value_for_now_1 = c_value_for_attack_2_1;
      c_value_for_now_2 = c_value_for_attack_2_2;
      c_value_for_now_3 = c_value_for_attack_2_3;
    }
    else if(check_for_value == -2)
    {
      c_value_for_now_1 = c_value_for_attack_2_1;
      c_value_for_now_2 = c_value_for_attack_2_2;
      c_value_for_now_3 = c_value_for_attack_2_3;
    }


    int temp_value;
    int mul_const;

    if(check_for_value < 0)
      mul_const = -1;
    else
      mul_const = 1;

    for(int sd = 0; sd < p; sd++)
    {
      temp_value = (x_f_array[sd])*c_value_for_now_1 + (x_g_int[sd])*c_value_for_now_3 + (x_f_attack_array[sd]*mul_const*c_value_for_now_2);
      temp_value = temp_value + global_valid_hr[sd];
      hr[sd] = Fq_freeze(temp_value);
    }

    for(int i = 0; i < p; i++)
      global_c_in_encrypt[i] = hr[i];

    Round(c,hr);

  }


  //
  // if(intended_function == 6)
  // {
  //
  //   for(int yr = 0; yr < p; yr++)
  //   {
  //     x_f_array_copy[yr] = x_f_array[yr];
  //     x_g_array_copy[yr] = x_g_array[yr];
  //   }
  //
  //   // Construct ciphertext c = c . x_f_array + c . x_g_array . h
  //
  //   Fq x_f_int[p];
  //   Fq x_g_int[p];
  //
  //   Rq_mult_small(x_g_int,h,x_g_array_copy);
  //
  //   // Should define the additional polynomial factor here...
  //
  //   Fq x_f_attack_array[p];
  //
  //   for(int gd = 0; gd<p; gd++)
  //     x_f_attack_array[gd] = 0;
  //
  //   x_f_attack_array[sec_index] = 1;
  //
  //
  //   int c_value_for_now;
  //
  //   if(check_for_value == 1)
  //   {
  //     c_value_for_now = c_value_for_attack_1;
  //   }
  //   else if(check_for_value == -1)
  //   {
  //     c_value_for_now = c_value_for_attack_1;
  //   }
  //   else if(check_for_value == 2)
  //   {
  //     c_value_for_now = c_value_for_attack_2;
  //   }
  //   else if(check_for_value == -2)
  //   {
  //     c_value_for_now = c_value_for_attack_2;
  //   }
  //
  //   int c_value_for_now_1;
  //   int c_value_for_now_2;
  //   int c_value_for_now_3;
  //
  //   if(check_for_value == 1)
  //   {
  //     c_value_for_now_1 = c_value_for_attack_1_1;
  //     c_value_for_now_2 = c_value_for_attack_1_2;
  //     c_value_for_now_3 = c_value_for_attack_1_3;
  //   }
  //   else if(check_for_value == -1)
  //   {
  //     c_value_for_now_1 = c_value_for_attack_1_1;
  //     c_value_for_now_2 = c_value_for_attack_1_2;
  //     c_value_for_now_3 = c_value_for_attack_1_3;
  //   }
  //   else if(check_for_value == 2)
  //   {
  //     c_value_for_now_1 = c_value_for_attack_2_1;
  //     c_value_for_now_2 = c_value_for_attack_2_2;
  //     c_value_for_now_3 = c_value_for_attack_2_3;
  //   }
  //   else if(check_for_value == -2)
  //   {
  //     c_value_for_now_1 = c_value_for_attack_2_1;
  //     c_value_for_now_2 = c_value_for_attack_2_2;
  //     c_value_for_now_3 = c_value_for_attack_2_3;
  //   }
  //
  //
  //   int temp_value;
  //   int mul_const;
  //
  //   if(check_for_value < 0)
  //     mul_const = -1;
  //   else
  //     mul_const = 1;
  //
  //   for(int sd = 0; sd < p; sd++)
  //   {
  //     temp_value = (x_f_array[sd])*c_value_for_now_1 + (x_g_int[sd])*c_value_for_now_3 + (x_f_attack_array[sd]*mul_const*c_value_for_now_2);
  //     hr[sd] = Fq_freeze(temp_value);
  //   }
  //
  //   for(int i = 0; i < p; i++)
  //     global_c_in_encrypt[i] = hr[i];
  //
  //   Round(c,hr);
  //
  // }



  // if(intended_function == 2)
  // {
  //   int c_value_for_now;
  //   c_value_for_now = c_value_for_leakage;
  //
  //   for(int sd = 0; sd < p; sd++)
  //   {
  //     hr[sd] = 0;
  //   }
  //   hr[0] = c_value_for_now;
  //
  //   for(int i = 0; i < p; i++)
  //     global_c_in_encrypt[i] = hr[i];
  //
  //   Round(c,hr);
  //
  // }

  // Here, we generate valid ciphertexts...

  if(intended_function == 3)
  {

    Rq_mult_small(hr,h,r);

    for(int i = 0; i < p; i++)
      global_valid_hr[i] = hr[i];

    Round(c,hr);

  }


  // Here, we generate the perturbed ciphertexts for the pre-processing phase, using the polynomials d1 and d2 generated for
  // intended_function = 0...

  if(intended_function == 4)
  {

      for(int yr = 0; yr < p; yr++)
      {
        x_f_array_copy[yr] = x_f_array[yr];
        x_g_array_copy[yr] = x_g_array[yr];
      }


      Fq x_f_int[p];
      Fq x_g_int[p];

      Rq_mult_small(x_g_int,h,x_g_array_copy);

      int32 temp_value;
      for(int sd = 0; sd < p; sd++)
      {
        temp_value = (x_f_array[sd]*c_value_1_trimming) + (x_g_int[sd]*c_value_2_trimming);
        // Adding the valid ciphertext to chosen ciphertext...
        temp_value = temp_value + global_valid_hr[sd];
        hr[sd] = Fq_freeze(temp_value);
      }

      for(int i = 0; i < p; i++)
        global_c_in_encrypt[i] = hr[i];

      Round(c,hr);

  }



  // if(intended_function == 5)
  // {
  //
  //     for(int yr = 0; yr < p; yr++)
  //     {
  //       x_f_array_copy[yr] = x_f_array[yr];
  //       x_g_array_copy[yr] = x_g_array[yr];
  //     }
  //
  //
  //     Fq x_f_int[p];
  //     Fq x_g_int[p];
  //
  //     Rq_mult_small(x_g_int,h,x_g_array_copy);
  //
  //     int32 temp_value;
  //     for(int sd = 0; sd < p; sd++)
  //     {
  //       temp_value = (x_f_array[sd]*c_value_1_trimming) + (x_g_int[sd]*c_value_2_trimming);
  //       hr[sd] = Fq_freeze(temp_value);
  //     }
  //
  //
  //     for(int i = 0; i < p; i++)
  //       global_c_in_encrypt[i] = hr[i];
  //
  //     Round(c,hr);
  // }



}

#endif

/* c = Encrypt(r,h) */
static void Encrypt_cmp(Fq *c,const small *r,const Fq *h)
{
  Fq hr[p];
  Rq_mult_small(hr,h,r);
  Round(c,hr);
}

/* r = Decrypt(c,(f,ginv)) */
static void Decrypt(small *r,const Fq *c,const small *f,const small *ginv)
{
  int mask;
  int i;

  Rq_mult_small(cf,c,f);
  Rq_mult3(cf3,cf);
  R3_fromRq(e,cf3);

  for(i = 0; i < p; i++)
  {
    er_decrypt[i] = e[i];
  }

  R3_mult(ev,e,ginv);
  mask = Weightw_mask(ev); /* 0 if weight w, else -1 */
  global_mask = mask;
  for (i = 0;i < w;++i) r[i] = ((ev[i]^1)&~mask)^1;
  for (i = w;i < p;++i) r[i] = ev[i]&~mask;
}

#endif

/* ----- NTRU LPRime Core */

#ifdef LPR

/* (G,A),a = KeyGen(G); leaves G unchanged */
static void KeyGen(Fq *A,small *a,const Fq *G)
{
  Fq aG[p];

  Short_random(a);
  Rq_mult_small(aG,G,a);
  Round(A,aG);
}

/* B,T = Encrypt(r,(G,A),b) */
static void Encrypt(Fq *B,int8 *T,const int8 *r,const Fq *G,const Fq *A,const small *b)
{
  Fq bG[p];
  Fq bA[p];
  int i;

  Rq_mult_small(bG,G,b);
  Round(B,bG);
  Rq_mult_small(bA,A,b);
  for (i = 0;i < I;++i) T[i] = Top(Fq_freeze(bA[i]+r[i]*q12));
}

/* r = Decrypt((B,T),a) */
static void Decrypt(int8 *r,const Fq *B,const int8 *T,const small *a)
{
  Fq aB[p];
  int i;

  Rq_mult_small(aB,B,a);
  for (i = 0;i < I;++i)
    r[i] = -int16_negative_mask(Fq_freeze(Right(T[i])-aB[i]+4*w+1));
}

#endif

/* ----- encoding I-bit inputs */

#ifdef LPR

#define Inputs_bytes (I/8)
typedef int8 Inputs[I]; /* passed by reference */

static void Inputs_encode(unsigned char *s,const Inputs r)
{
  int i;
  for (i = 0;i < Inputs_bytes;++i) s[i] = 0;
  for (i = 0;i < I;++i) s[i>>3] |= r[i]<<(i&7);
}

#endif

/* ----- Expand */

#ifdef LPR

static const unsigned char aes_nonce[16] = {0};

static void Expand(uint32 *L,const unsigned char *k)
{
  int i;
  if (crypto_stream_aes256ctr((unsigned char *) L,4*p,aes_nonce,k) != 0) abort();
  for (i = 0;i < p;++i) {
    uint32 L0 = ((unsigned char *) L)[4*i];
    uint32 L1 = ((unsigned char *) L)[4*i+1];
    uint32 L2 = ((unsigned char *) L)[4*i+2];
    uint32 L3 = ((unsigned char *) L)[4*i+3];
    L[i] = L0+(L1<<8)+(L2<<16)+(L3<<24);
  }
}

#endif

/* ----- Seeds */

#ifdef LPR

#define Seeds_bytes 32

static void Seeds_random(unsigned char *s)
{
  randombytes(s,Seeds_bytes);
}

#endif

/* ----- Generator, HashShort */

#ifdef LPR

/* G = Generator(k) */
static void Generator(Fq *G,const unsigned char *k)
{
  uint32 L[p];
  int i;

  Expand(L,k);
  for (i = 0;i < p;++i) G[i] = uint32_mod_uint14(L[i],q)-q12;
}

/* out = HashShort(r) */
static void HashShort(small *out,const Inputs r)
{
  unsigned char s[Inputs_bytes];
  unsigned char h[Hash_bytes];
  uint32 L[p];

  Inputs_encode(s,r);
  Hash_prefix(h,5,s,sizeof s);
  Expand(L,h);
  Short_fromlist(out,L);
}

#endif

/* ----- NTRU LPRime Expand */

#ifdef LPR

/* (S,A),a = XKeyGen() */
static void XKeyGen(unsigned char *S,Fq *A,small *a)
{
  Fq G[p];

  Seeds_random(S);
  Generator(G,S);
  KeyGen(A,a,G);
}

/* B,T = XEncrypt(r,(S,A)) */
static void XEncrypt(Fq *B,int8 *T,const int8 *r,const unsigned char *S,const Fq *A)
{
  Fq G[p];
  small b[p];

  Generator(G,S);
  HashShort(b,r);
  Encrypt(B,T,r,G,A,b);
}

#define XDecrypt Decrypt

#endif

/* ----- encoding small polynomials (including short polynomials) */

#define Small_bytes ((p+3)/4)

/* these are the only functions that rely on p mod 4 = 1 */

static void Small_encode(unsigned char *s,const small *f)
{
  small x;
  int i;

  for (i = 0;i < p/4;++i) {
    x = *f++ + 1;
    x += (*f++ + 1)<<2;
    x += (*f++ + 1)<<4;
    x += (*f++ + 1)<<6;
    *s++ = x;
  }
  x = *f++ + 1;
  *s++ = x;
}

static void Small_decode(small *f,const unsigned char *s)
{
  unsigned char x;
  int i;

  for (i = 0;i < p/4;++i) {
    x = *s++;
    *f++ = ((small)(x&3))-1; x >>= 2;
    *f++ = ((small)(x&3))-1; x >>= 2;
    *f++ = ((small)(x&3))-1; x >>= 2;
    *f++ = ((small)(x&3))-1;
  }
  x = *s++;
  *f++ = ((small)(x&3))-1;
}

/* ----- encoding general polynomials */

#ifndef LPR

static void Rq_encode(unsigned char *s,const Fq *r)
{
  uint16 R[p],M[p];
  int i;

  for (i = 0;i < p;++i) R[i] = r[i]+q12;
  for (i = 0;i < p;++i) M[i] = q;
  Encode(s,R,M,p);
}

static void Rq_decode(Fq *r,const unsigned char *s)
{
  uint16 R[p],M[p];
  int i;

  for (i = 0;i < p;++i) M[i] = q;
  Decode(R,s,M,p);
  for (i = 0;i < p;++i) r[i] = ((Fq)R[i])-q12;
}

#endif

/* ----- encoding rounded polynomials */

static void Rounded_encode(unsigned char *s,const Fq *r)
{
  uint16 R[p],M[p];
  int i;

  for (i = 0;i < p;++i) R[i] = ((r[i]+q12)*10923)>>15;
  for (i = 0;i < p;++i) M[i] = (q+2)/3;
  Encode(s,R,M,p);
}

static void Rounded_decode(Fq *r,const unsigned char *s)
{
  uint16 R[p],M[p];
  int i;

  for (i = 0;i < p;++i) M[i] = (q+2)/3;
  Decode(R,s,M,p);
  for (i = 0;i < p;++i) r[i] = R[i]*3-q12;
}

/* ----- encoding top polynomials */

#ifdef LPR

#define Top_bytes (I/2)

static void Top_encode(unsigned char *s,const int8 *T)
{
  int i;
  for (i = 0;i < Top_bytes;++i)
    s[i] = T[2*i]+(T[2*i+1]<<4);
}

static void Top_decode(int8 *T,const unsigned char *s)
{
  int i;
  for (i = 0;i < Top_bytes;++i) {
    T[2*i] = s[i]&15;
    T[2*i+1] = s[i]>>4;
  }
}

#endif

/* ----- Streamlined NTRU Prime Core plus encoding */

#ifndef LPR

typedef small Inputs[p]; /* passed by reference */
#define Inputs_random Short_random
#define Inputs_encode Small_encode
#define Inputs_bytes Small_bytes

#define Ciphertexts_bytes Rounded_bytes
#define SecretKeys_bytes (2*Small_bytes)
#define PublicKeys_bytes Rq_bytes

/* pk,sk = ZKeyGen() */
static void ZKeyGen(unsigned char *pk,unsigned char *sk)
{
  Fq h[p];
  small f[p],v[p];

  KeyGen(h,f,v);
  Rq_encode(pk,h);
  Small_encode(sk,f); sk += Small_bytes;
  Small_encode(sk,v);
}

/* C = ZEncrypt(r,pk) */
static void ZEncrypt(unsigned char *C,const Inputs r,const unsigned char *pk)
{
  Fq h[p];
  Fq c[p];

  Rq_decode(h,pk);
  Encrypt(c,r,h);
  Rounded_encode(C,c);
}

/* C = ZEncrypt(r,pk) */
static void ZEncrypt_cmp(unsigned char *C,const Inputs r,const unsigned char *pk)
{
  Fq h[p];
  Fq c[p];

  Rq_decode(h,pk);
  Encrypt_cmp(c,r,h);
  Rounded_encode(C,c);
}

/* r = ZDecrypt(C,sk) */
static void ZDecrypt(Inputs r,const unsigned char *C,const unsigned char *sk)
{
  small f[p],v[p];
  Fq c[p];

  Small_decode(f,sk); sk += Small_bytes;
  Small_decode(v,sk);
  Rounded_decode(c,C);
  Decrypt(r,c,f,v);
}

#endif

/* ----- NTRU LPRime Expand plus encoding */

#ifdef LPR

#define Ciphertexts_bytes (Rounded_bytes+Top_bytes)
#define SecretKeys_bytes Small_bytes
#define PublicKeys_bytes (Seeds_bytes+Rounded_bytes)

static void Inputs_random(Inputs r)
{
  unsigned char s[Inputs_bytes];
  int i;

  randombytes(s,sizeof s);
  for (i = 0;i < I;++i) r[i] = 1&(s[i>>3]>>(i&7));
}

/* pk,sk = ZKeyGen() */
static void ZKeyGen(unsigned char *pk,unsigned char *sk)
{
  Fq A[p];
  small a[p];

  XKeyGen(pk,A,a); pk += Seeds_bytes;
  Rounded_encode(pk,A);
  Small_encode(sk,a);
}

/* c = ZEncrypt(r,pk) */
static void ZEncrypt(unsigned char *c,const Inputs r,const unsigned char *pk)
{
  Fq A[p];
  Fq B[p];
  int8 T[I];

  Rounded_decode(A,pk+Seeds_bytes);
  XEncrypt(B,T,r,pk,A);
  Rounded_encode(c,B); c += Rounded_bytes;
  Top_encode(c,T);
}

/* r = ZDecrypt(C,sk) */
static void ZDecrypt(Inputs r,const unsigned char *c,const unsigned char *sk)
{
  small a[p];
  Fq B[p];
  int8 T[I];

  Small_decode(a,sk);
  Rounded_decode(B,c);
  Top_decode(T,c+Rounded_bytes);
  XDecrypt(r,B,T,a);
}

#endif

/* ----- confirmation hash */

#define Confirm_bytes 32

/* h = HashConfirm(r,pk,cache); cache is Hash4(pk) */
static void HashConfirm(unsigned char *h,const unsigned char *r,const unsigned char *pk,const unsigned char *cache)
{
#ifndef LPR
  unsigned char x[Hash_bytes*2];
  int i;

  Hash_prefix(x,3,r,Inputs_bytes);
  for (i = 0;i < Hash_bytes;++i) x[Hash_bytes+i] = cache[i];
#else
  unsigned char x[Inputs_bytes+Hash_bytes];
  int i;

  for (i = 0;i < Inputs_bytes;++i) x[i] = r[i];
  for (i = 0;i < Hash_bytes;++i) x[Inputs_bytes+i] = cache[i];
#endif
  Hash_prefix(h,2,x,sizeof x);
}

/* ----- session-key hash */

/* k = HashSession(b,y,z) */
static void HashSession(unsigned char *k,int b,const unsigned char *y,const unsigned char *z)
{
#ifndef LPR
  unsigned char x[Hash_bytes+Ciphertexts_bytes+Confirm_bytes];
  int i;

  Hash_prefix(x,3,y,Inputs_bytes);
  for (i = 0;i < Ciphertexts_bytes+Confirm_bytes;++i) x[Hash_bytes+i] = z[i];
#else
  unsigned char x[Inputs_bytes+Ciphertexts_bytes+Confirm_bytes];
  int i;

  for (i = 0;i < Inputs_bytes;++i) x[i] = y[i];
  for (i = 0;i < Ciphertexts_bytes+Confirm_bytes;++i) x[Inputs_bytes+i] = z[i];
#endif
  Hash_prefix(k,b,x,sizeof x);
}

/* ----- Streamlined NTRU Prime and NTRU LPRime */

/* pk,sk = KEM_KeyGen() */
static void KEM_KeyGen(unsigned char *pk,unsigned char *sk)
{
  int i;

  ZKeyGen(pk,sk); sk += SecretKeys_bytes;
  for (i = 0;i < PublicKeys_bytes;++i) *sk++ = pk[i];
  randombytes(sk,Inputs_bytes); sk += Inputs_bytes;
  Hash_prefix(sk,4,pk,PublicKeys_bytes);
}

/* c,r_enc = Hide(r,pk,cache); cache is Hash4(pk) */
static void Hide(unsigned char *c,unsigned char *r_enc,const Inputs r,const unsigned char *pk,const unsigned char *cache)
{
  Inputs_encode(r_enc,r);
#ifdef KAT
  {
    int j;
    printf("Hide r_enc: ");
    for (j = 0;j < Inputs_bytes;++j) printf("%02x",r_enc[j]);
    printf("\n");
  }
#endif
  ZEncrypt(c,r,pk); c += Ciphertexts_bytes;
  HashConfirm(c,r_enc,pk,cache);
}


/* c,r_enc = Hide(r,pk,cache); cache is Hash4(pk) */
static void Hide_cmp(unsigned char *c,unsigned char *r_enc,const Inputs r,const unsigned char *pk,const unsigned char *cache)
{
  Inputs_encode(r_enc,r);
#ifdef KAT
  {
    int j;
    printf("Hide r_enc: ");
    for (j = 0;j < Inputs_bytes;++j) printf("%02x",r_enc[j]);
    printf("\n");
  }
#endif
  ZEncrypt_cmp(c,r,pk); c += Ciphertexts_bytes;
  HashConfirm(c,r_enc,pk,cache);
}


/* c,k = Encap(pk) */
static void Encap(unsigned char *c,unsigned char *k,const unsigned char *pk)
{
  Inputs r;
  unsigned char r_enc[Inputs_bytes];
  unsigned char cache[Hash_bytes];

  Hash_prefix(cache,4,pk,PublicKeys_bytes);
  Inputs_random(r);
  Hide(c,r_enc,r,pk,cache);
  HashSession(k,1,r_enc,c);
}

/* 0 if matching ciphertext+confirm, else -1 */
static int Ciphertexts_diff_mask(const unsigned char *c,const unsigned char *c2)
{
  uint16 differentbits = 0;
  int len = Ciphertexts_bytes+Confirm_bytes;

  while (len-- > 0) differentbits |= (*c++)^(*c2++);
  return (1&((differentbits-1)>>8))-1;
}

/* k = Decap(c,sk) */
static void Decap(unsigned char *k,const unsigned char *c,const unsigned char *sk)
{
  const unsigned char *pk = sk + SecretKeys_bytes;
  const unsigned char *rho = pk + PublicKeys_bytes;
  const unsigned char *cache = rho + Inputs_bytes;
  Inputs r;
  unsigned char r_enc[Inputs_bytes];
  unsigned char cnew[Ciphertexts_bytes+Confirm_bytes];
  int mask;
  int i;

  ZDecrypt(r,c,sk);
  Hide_cmp(cnew,r_enc,r,pk,cache);
  mask = Ciphertexts_diff_mask(c,cnew);
  for (i = 0;i < Inputs_bytes;++i) r_enc[i] ^= mask&(r_enc[i]^rho[i]);
  HashSession(k,1+mask,r_enc,c);
}

int crypto_kem_keypair(unsigned char *pk,unsigned char *sk)
{
  KEM_KeyGen(pk,sk);
  return 0;
}

int crypto_kem_enc(unsigned char *c,unsigned char *k,const unsigned char *pk)
{
  Encap(c,k,pk);
  return 0;
}

int crypto_kem_dec(unsigned char *k,const unsigned char *c,const unsigned char *sk)
{
  int i;
  Decap(k,c,sk);
  return 0;

}
