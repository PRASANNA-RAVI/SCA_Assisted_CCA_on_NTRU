#include "owcpa.h"
#include "poly.h"
#include "sample.h"
#include <stdio.h>

extern poly y_extern_mf;
extern poly y1, y2;
extern poly x7, x8;

extern uint32_t intended_function;

extern uint32_t c_value_1;
extern uint32_t c_value_2;

extern uint32_t c1_value_1;
extern uint32_t c1_value_2;
extern uint32_t c1_value_3;

extern uint32_t m_attack;
extern uint32_t n_attack;

extern int check_for_value;
extern uint32_t sec_index;

extern int collision_index;
extern int collision_value;

uint32_t correct_f_value;

poly *extern_mf = &y_extern_mf;
poly *x_f_array_copy = &y1;
poly *x_g_array_copy = &y2;
poly *global_f = &x7;
poly *global_g = &x8;

poly x9,x10;
poly *x_f_array = &x9;
poly *x_g_array = &x10;

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



static int owcpa_check_ciphertext(const unsigned char *ciphertext)
{
  /* A ciphertext is log2(q)*(n-1) bits packed into bytes.  */
  /* Check that any unused bits of the final byte are zero. */

  uint16_t t = 0;

  t = ciphertext[NTRU_CIPHERTEXTBYTES-1];
  t &= 0xff << (8-(7 & (NTRU_LOGQ*NTRU_PACK_DEG)));

  /* We have 0 <= t < 256 */
  /* Return 0 on success (t=0), 1 on failure */
  return (int) (1&((~t + 1) >> 15));
}

static int owcpa_check_r(const poly *r)
{
  /* A valid r has coefficients in {0,1,q-1} and has r[N-1] = 0 */
  /* Note: We may assume that 0 <= r[i] <= q-1 for all i        */

  int i;
  uint32_t t = 0;
  uint16_t c;
  for(i=0; i<NTRU_N-1; i++)
  {
    c = r->coeffs[i];
    t |= (c + 1) & (NTRU_Q-4);  /* 0 iff c is in {-1,0,1,2} */
    t |= (c + 2) & 4;  /* 1 if c = 2, 0 if c is in {-1,0,1} */
  }
  t |= r->coeffs[NTRU_N-1]; /* Coefficient n-1 must be zero */

  /* We have 0 <= t < 2^16. */
  /* Return 0 on success (t=0), 1 on failure */
  return (int) (1&((~t + 1) >> 31));
}

#ifdef NTRU_HPS
static int owcpa_check_m(const poly *m)
{
  /* Check that m is in message space, i.e.                  */
  /*  (1)  |{i : m[i] = 1}| = |{i : m[i] = 2}|, and          */
  /*  (2)  |{i : m[i] != 0}| = NTRU_WEIGHT.                  */
  /* Note: We may assume that m has coefficients in {0,1,2}. */

  int i;
  uint32_t t = 0;
  uint16_t ps = 0;
  uint16_t ms = 0;
  for(i=0; i<NTRU_N; i++)
  {
    ps += m->coeffs[i] & 1;
    ms += m->coeffs[i] & 2;
  }
  t |= ps ^ (ms >> 1);   /* 0 if (1) holds */
  t |= ms ^ NTRU_WEIGHT; /* 0 if (1) and (2) hold */

  /* We have 0 <= t < 2^16. */
  /* Return 0 on success (t=0), 1 on failure */
  return (int) (1&((~t + 1) >> 31));
}
#endif

void owcpa_keypair(unsigned char *pk,
                   unsigned char *sk,
                   const unsigned char seed[NTRU_SAMPLE_FG_BYTES])
{
  int i;

  poly x1, x2, x3, x4, x5;

  poly *f=&x1, *g=&x2, *invf_mod3=&x3;
  poly *gf=&x3, *invgf=&x4, *tmp=&x5;
  poly *invh=&x3, *h=&x3;

  sample_fg(f,g,seed);

  poly_S3_inv(invf_mod3, f);
  poly_S3_tobytes(sk, f);
  poly_S3_tobytes(sk+NTRU_PACK_TRINARY_BYTES, invf_mod3);

  /* Lift coeffs of f and g from Z_p to Z_q */
  poly_Z3_to_Zq(f);
  poly_Z3_to_Zq(g);

  printf("Printing Secret Key f...\n");
  for(int hfh = 0; hfh < NTRU_N; hfh++)
  {
    global_f->coeffs[hfh] = f->coeffs[hfh];
    // printf("[%d]: %d, ", hfh, f->coeffs[hfh]);
    printf("%d, ", f->coeffs[hfh]);

  }
  printf("\n");

  for(int hfh = 0; hfh < NTRU_N; hfh++)
  {
    global_g->coeffs[hfh] = g->coeffs[hfh];
  }


#ifdef NTRU_HRSS
  /* g = 3*(x-1)*g */
  for(i=NTRU_N-1; i>0; i--)
    g->coeffs[i] = 3*(g->coeffs[i-1] - g->coeffs[i]);
  g->coeffs[0] = -(3*g->coeffs[0]);
#endif

#ifdef NTRU_HPS
  /* g = 3*g */
  for(i=0; i<NTRU_N; i++)
    g->coeffs[i] = 3 * g->coeffs[i];
#endif

  poly_Rq_mul(gf, g, f);

  poly_Rq_inv(invgf, gf);

  poly_Rq_mul(tmp, invgf, f);

  poly_Sq_mul(invh, tmp, f);

  poly_Sq_tobytes(sk+2*NTRU_PACK_TRINARY_BYTES, invh);

  poly_Rq_mul(tmp, invgf, g);
  poly_Rq_mul(h, tmp, g);
  poly_Rq_sum_zero_tobytes(pk, h);
}


// Procedure to Create Malformed Ciphertexts.... This encryption procedure can operate in different modes depending upon the
// value of the variable "intended_function"...

void owcpa_enc(unsigned char *c,
               const poly *r,
               const poly *m,
               const unsigned char *pk)
{
  int i;
  poly x1, x2;
  poly *h = &x1, *liftm = &x1;
  poly *ct = &x2;

  poly_Rq_sum_zero_frombytes(h, pk);

  poly x3, x4, yry1;
  poly *x_f_prod = &x3;
  poly *x_g_prod = &x4;
  poly *x_f_attack_prod = &yry1;

  poly x5,x6;
  poly *x_f_int = &x5;
  poly *x_g_int = &x6;

  uint32_t mul_const;

  // If intended_function == 0, then we are trying to create ciphertexts for single collision...

  if(intended_function == 0)
  {
    rej0:

    // Construct d1 = (x^i1 + x^i2 + .... + x^im)...

    for(int we1 = 0; we1 < NTRU_N; we1++)
    {
      x_f_array->coeffs[we1] = 0;
    }

    for(int we1 = 0; we1 < m_attack; we1++)
    {
      int index;

      int rand_value = (get_random()*256 + get_random());
      index = rand_value % (NTRU_N);
      if(index < 0)
        index = index + NTRU_N;

      if(we1%2 == 0)
        x_f_array->coeffs[index] = 1;
      else
        x_f_array->coeffs[index] = NTRU_Q - 1;
    }

    // Construct d2 = (x^j1 + x^j2 + .... + x^jn)...

    for(int we1 = 0; we1 < NTRU_N; we1++)
    {
      x_g_array->coeffs[we1] = 0;
    }
    for(int we1 = 0; we1 < n_attack; we1++)
    {
      int index;

      int rand_value = (get_random()*256 + get_random());
      index = rand_value%NTRU_N;
      if(index < 0)
        index = index + NTRU_N;

      x_g_array->coeffs[index] = 1;
    }

    for(int yr = 0; yr < NTRU_N; yr++)
    {
      x_f_array_copy->coeffs[yr] = x_f_array->coeffs[yr];
      x_g_array_copy->coeffs[yr] = x_g_array->coeffs[yr];
    }

    // Construct ciphertext c = k1 . d1 + k2 . d2 . h where k1 = c_value_1 and k2 = c_value_2...

    poly_Rq_mul(x_g_int, x_g_array_copy, h);

    uint32_t temp_value;
    for(int sd = 0; sd < NTRU_N; sd++)
    {
      temp_value = (x_f_array->coeffs[sd]*c_value_1) + (x_g_int->coeffs[sd]*c_value_2);
      ct->coeffs[sd] = MODQ(temp_value);
    }

  }


  // If intended_function == 1, then we are trying to create attack ciphertexts using the base ciphertext...
  // More concretely, as shown in the paper, we are creating the ciphertext c = l1 . d1 + l2 . d2. h - l3 . x^u . (x - 1)

  if(intended_function == 1)
  {
    rej1:
    for(int yr = 0; yr < NTRU_N; yr++)
    {
      x_f_array_copy->coeffs[yr] = x_f_array->coeffs[yr];
      x_g_array_copy->coeffs[yr] = x_g_array->coeffs[yr];
    }

    poly xx1;
    poly *x_f_attack_array = &xx1;

    // Here we are trying to create the term x^u . (x - 1) where u = sec_index... This term is nothing but x_f_attack_array...

    for(int gd = 0; gd<NTRU_N; gd++)
      x_f_attack_array->coeffs[gd] = 0;

    x_f_attack_array->coeffs[sec_index] = 1;
    if(sec_index < (NTRU_N-1))
      x_f_attack_array->coeffs[sec_index+1] = NTRU_Q - 1;
    else
      x_f_attack_array->coeffs[0] = NTRU_Q - 1;

    // Here we construct the terms c = l1 . d1 + l2 . d2. h - l3 . x^u . (x - 1)
    // x_f_array holds the value of d1, x_g_array holds the value of d2 and x_f_arrack_array holds the value of x^u . (x - 1)...

    poly_Rq_mul(x_g_int, x_g_array_copy, h);

    int k_value_1, k_value_2, k_value_3;

    if(check_for_value == 1)
    {
      mul_const = 1;
      k_value_1 = c1_value_1;
      k_value_2 = c1_value_2;
      k_value_3 = c1_value_3;
    }
    else if(check_for_value == 2)
    {
      mul_const = 1;
      k_value_1 = c2_value_1;
      k_value_2 = c2_value_2;
      k_value_3 = c2_value_3;
    }
    else if(check_for_value == -1)
    {
      mul_const = NTRU_Q - 1;
      k_value_1 = c1_value_1;
      k_value_2 = c1_value_2;
      k_value_3 = c1_value_3;
    }
    else if(check_for_value == -2)
    {
      mul_const = NTRU_Q - 1;
      k_value_1 = c2_value_1;
      k_value_2 = c2_value_2;
      k_value_3 = c2_value_3;
    }

    // Here we construct the coefficients of c one by one... l1 = k_value_1, l2 = k_value_3 and l3 = k_value_2...

    uint32_t temp_value;
    for(int sd = 0; sd < NTRU_N; sd++)
    {
      temp_value = (x_f_array->coeffs[sd]*k_value_1) + (x_g_int->coeffs[sd]*k_value_3) + (x_f_attack_array->coeffs[sd]*mul_const*k_value_2);
      ct->coeffs[sd] = MODQ(temp_value);
    }

  }

  // Here, we are checking whether sum of coefficients of c equate to 0... because c should be a multiple of (x - 1)

  int summ = 0;
  for(int hfh = 0; hfh < NTRU_N; hfh++)
  {
    summ = MODQ(summ + ct->coeffs[hfh]);
  }

  // If not, reject it and start again...

  if(summ != 0)
  {
    if(intended_function == 0)
      goto rej0;
    else if(intended_function == 1)
      printf("Attack Failed...\n");
  }

  poly_Rq_sum_zero_tobytes(c, ct);

}

int owcpa_dec(unsigned char *rm,
              const unsigned char *ciphertext,
              const unsigned char *secretkey)
{
  int i;
  int fail;
  poly x1, x2, x3, x4;

  poly *c = &x1, *f = &x2, *cf = &x3;
  poly *mf = &x2, *finv3 = &x3, *m = &x4;
  poly *liftm = &x2, *invh = &x3, *r = &x4;
  poly *b = &x1;

  poly_Rq_sum_zero_frombytes(c, ciphertext);

  // printf("Printing c in decrypt...\n");
  // for(int hfh = 0; hfh < NTRU_N; hfh++)
  // {
  //   printf("%d, ", c->coeffs[hfh]);
  // }
  // printf("\n");

  poly_S3_frombytes(f, secretkey);

  // printf("Printing Secret Key g...\n");
  // for(int hfh = 0; hfh < NTRU_N; hfh++)
  // {
  //   printf("%d, ", g->coeffs[hfh]);
  // }
  // printf("\n");

  poly_Z3_to_Zq(f);

  // printf("Printing Secret Key f...\n");
  // for(int hfh = 0; hfh < NTRU_N; hfh++)
  // {
  //   printf("%d, ", f->coeffs[hfh]);
  // }
  // printf("\n");

  poly_Rq_mul(cf, c, f);

  // printf("Printing cf...\n");
  // for(int hfh = 0; hfh < NTRU_N; hfh++)
  // {
  //   printf("%d, ", cf->coeffs[hfh]);
  // }
  // printf("\n");

  poly_Rq_to_S3(mf, cf);

  for(int jhj = 0; jhj < NTRU_N; jhj++)
    extern_mf->coeffs[jhj] = mf->coeffs[jhj];

  // printf("Printing extern_mf...\n");
  // for(int hfh = 0; hfh < NTRU_N; hfh++)
  // {
  //   printf("%d, ", extern_mf->coeffs[hfh]);
  // }
  // printf("\n");

  // printf("Printing mf...\n");
  // for(int hfh = 0; hfh < NTRU_N; hfh++)
  // {
  //   printf("%d, ", mf->coeffs[hfh]);
  // }
  // printf("\n");

  poly_S3_frombytes(finv3, secretkey+NTRU_PACK_TRINARY_BYTES);
  poly_S3_mul(m, mf, finv3);
  poly_S3_tobytes(rm+NTRU_PACK_TRINARY_BYTES, m);

  fail = 0;

  /* Check that the unused bits of the last byte of the ciphertext are zero */
  fail |= owcpa_check_ciphertext(ciphertext);

  /* For the IND-CCA2 KEM we must ensure that c = Enc(h, (r,m)).             */
  /* We can avoid re-computing r*h + Lift(m) as long as we check that        */
  /* r (defined as b/h mod (q, Phi_n)) and m are in the message space.       */
  /* (m can take any value in S3 in NTRU_HRSS) */
#ifdef NTRU_HPS
  fail |= owcpa_check_m(m);
#endif

  /* b = c - Lift(m) mod (q, x^n - 1) */
  poly_lift(liftm, m);
  for(i=0; i<NTRU_N; i++)
    b->coeffs[i] = c->coeffs[i] - liftm->coeffs[i];

  /* r = b / h mod (q, Phi_n) */
  poly_Sq_frombytes(invh, secretkey+2*NTRU_PACK_TRINARY_BYTES);
  poly_Sq_mul(r, b, invh);

  /* NOTE: Our definition of r as b/h mod (q, Phi_n) follows Figure 4 of     */
  /*   [Sch18] https://eprint.iacr.org/2018/1174/20181203:032458.            */
  /* This differs from Figure 10 of Saito--Xagawa--Yamakawa                  */
  /*   [SXY17] https://eprint.iacr.org/2017/1005/20180516:055500             */
  /* where r gets a final reduction modulo p.                                */
  /* We need this change to use Proposition 1 of [Sch18].                    */

  /* Proposition 1 of [Sch18] shows that re-encryption with (r,m) yields c.  */
  /* if and only if fail==0 after the following call to owcpa_check_r        */
  /* The procedure given in Fig. 8 of [Sch18] can be skipped because we have */
  /* c(1) = 0 due to the use of poly_Rq_sum_zero_{to,from}bytes.             */
  fail |= owcpa_check_r(r);

  poly_trinary_Zq_to_Z3(r);
  poly_S3_tobytes(rm, r);

  return fail;
}
