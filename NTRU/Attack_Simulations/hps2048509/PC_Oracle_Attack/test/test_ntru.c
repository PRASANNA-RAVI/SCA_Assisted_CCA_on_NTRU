#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "../params.h"
#include "../kem.h"
#include "../poly.h"

#define CALC_VALUES 1

#define DO_PRINT 0

extern uint32_t m_attack;
extern uint32_t n_attack;
extern uint32_t intended_function;
extern poly *extern_mf;
extern uint32_t correct_f_value;

extern poly *global_f;
extern poly *global_g;

uint32_t sec_index;
int check_for_value;

int collision_index;
int collision_value;

/* returns 0 for equal strings, 1 for non-equal strings */
static unsigned char verify(const unsigned char *a, const unsigned char *b, size_t len)
{
  uint64_t r;
  size_t i;

  r = 0;
  for(i=0;i<len;i++)
    r |= a[i] ^ b[i];

  r = (~r + 1); // Two's complement
  r >>= 63;
  return (unsigned char)r;
}

#define TRIALS 5

int main(void)
{

  uint32_t i,c;
  unsigned char* pk = (unsigned char*) malloc(NTRU_PUBLICKEYBYTES);
  unsigned char* sk = (unsigned char*) malloc(NTRU_SECRETKEYBYTES);
  unsigned char* ct = (unsigned char*) malloc(NTRU_CIPHERTEXTBYTES);
  unsigned char* k1 = (unsigned char*) malloc(NTRU_SHAREDKEYBYTES);
  unsigned char* k2 = (unsigned char*) malloc(NTRU_SHAREDKEYBYTES);

  m_attack = 4;
  n_attack = 3;

  uint32_t q12 = (NTRU_Q/2);

  uint32_t max_distance = 1000000;
  uint32_t max_distance2 = 0;
  uint32_t found_c, found_c_for_attack_1, found_c_for_attack_2;

  int sample_3, sample_1, sample_2;

  uint32_t limit_hg = 500;
  uint32_t limig_hg_1 = 500;

  unsigned char temp_temp_char;


  FILE * f2;
  FILE * f3;

  char ct_file_basic[30];
  char ct_file_basic_failed[50];
  char ct_file[30];
  char keypair_file[30];
  char oracle_responses_file_name[30];

  #if (DO_PRINT == 1)

  sprintf(oracle_responses_file_name,"oracle_resp_sntrup761.bin");
  f2 = fopen(oracle_responses_file_name, "w+");
  fclose(f2);

  sprintf(ct_file,"ct_file_sntrup761.bin");
  f2 = fopen(ct_file, "w+");
  fclose(f2);

  sprintf(ct_file_basic,"ct_file_basic_sntrup761.bin");
  f2 = fopen(ct_file_basic, "w+");
  fclose(f2);

  sprintf(keypair_file,"keypair_file_sntrup761.bin");
  f2 = fopen(keypair_file, "w+");
  fclose(f2);

  #endif

  #if (CALC_VALUES == 1)

  for(uint32_t hg = 3; hg < limit_hg; hg=hg+3)
  {
    // printf("hg: %d\n", hg);
    for(uint32_t hg1 = 3; hg1 < limit_hg; hg1=hg1+3)
    {

          uint32_t value1 = hg * (m_attack) + hg1 * (3*n_attack);

          uint32_t touch_np = 0;

          max_distance = 1000000;

          if(value1 > q12 && (abs(q12 - value1) > C_VALUE_THRESHOLD_1))
          {
            // printf("hg__ = %d, hg1__ = %d\n", hg, hg1);
            for(uint32_t poss = 0; poss <= m_attack; poss++)
            {
              for(uint32_t poss1 = 0; poss1 <= n_attack; poss1++)
              {
                    if(!(poss == m_attack && poss1 == n_attack))
                    {
                      uint32_t value2 = (hg * (poss) + hg1*(3*poss1));

                      if(max_distance > (abs(q12 - value2)))
                        max_distance = (abs(q12 - value2));

                      if((value2 > q12) || (hg%3 != 0) || (hg1%3 != 0) || (abs(q12 - value2) < C_VALUE_THRESHOLD_2))
                      {
                        touch_np = 1;
                      }
                    }
              }
            }

            // printf("hg = %d, hg1 = %d, max_distance:%d, max_distance2 = %d, touch_np = %d\n", hg, hg1, max_distance, max_distance2, touch_np);

            if(touch_np == 0)
            {
              found_c = 1;

              if(max_distance > max_distance2)
              {
                c_value_1 = hg;
                c_value_2 = hg1;
                max_distance2 = max_distance;
                printf("hg = %d, hg1 = %d, Diff1: %d, Diff2: %d\n", hg, hg1, abs(q12 - value1), max_distance2);

                // printf("Printing Progression...\n");
                // for(uint32_t poss = 0; poss <= m_attack; poss++)
                // {
                //   for(uint32_t poss1 = 0; poss1 <= n_attack; poss1++)
                //   {
                //     uint32_t value2 = (c_value_1 * (poss) + c_value_2*(3*poss1));
                //     printf("%d, ", value2);
                //   }
                // }
                // printf("\n");
              }

              // break;
            }
          }

    }
  }

  printf("Found k1, k2 for collision\n");

  #else

  // hg = 129, hg1 = 45
  c_value_1 = 129;
  c_value_2 = 45;

  #endif

  max_distance = 1000000;
  max_distance2 = 0;

  int limit_value = 1000;

  found_c_for_attack_1 = 0;

  #if (CALC_VALUES == 1)

  while(found_c_for_attack_1 == 0)
  {
    for(int hg = 3; hg < limit_value; hg = hg+3)
    {
      // printf("hg:%d\n",hg);
      for(int hg1 = 3; hg1 < limit_value; hg1 = hg1+3)
      {
        // printf("hg1:%d\n",hg1);
        for(int hg2 = 3; hg2 < limit_value; hg2 = hg2+3)
        {
          // printf("hg2:%d\n",hg2);

          sample_1 = hg;
          sample_2 = hg1;
          sample_3 = hg2;

          // int value1 = sample_1 * (3*2*m + 2*n) + sample_2 * (1*3);
          int value1 = sample_1 * (m_attack) + sample_3 * (3*n_attack) + sample_2 * (1);
          int value2;

          int touch_np = 0;

          max_distance = 1000000;

          if((value1 > q12) && (abs(value1 - q12) > GAP_THRESHOLD_1_1))
          {
            for(int poss = 0; poss <= m_attack; poss++)
            {
              for(int poss1 = 0; poss1 <= n_attack; poss1++)
              {
                for(int poss2 = 0; poss2 <= 2; poss2++)
                {

                  if(!((poss == m_attack) && (poss1 == n_attack) && ((poss2 == 1) || (poss2 == 2))))
                  {
                    // value2 = sample_1 * (3*poss+poss1) + sample_2 * (3*poss2);

                    value2 = sample_1 * (poss) + sample_3 * (3*poss1) + sample_2 * (poss2);

                    if(max_distance > (abs(q12 - value2)))
                      max_distance = (abs(q12 - value2));

                    // if((value1 < q12) || (value2 > q12)
                    //   || (abs(value1 - q12) < GAP_THRESHOLD_1_1) || (abs(value2 - q12) < GAP_THRESHOLD_1_2))
                    if((value2 > q12) || (abs(value2 - q12) < GAP_THRESHOLD_1_2))
                    {
                      touch_np = 1;
                    }
                  }

                }
              }
            }

            if(touch_np == 0)
            {
              found_c_for_attack_1 = 1;
              // list_of_c1_values[no_c1_values][0] = hg;
              // list_of_c1_values[no_c1_values][1] = hg1;
              // no_c1_values = no_c1_values + 1;
              // printf("hg1: %d, hg2: %d\n", hg, hg1);

              if(max_distance > max_distance2)
              {
                c1_value_1 = hg;
                c1_value_2 = hg1;
                c1_value_3 = hg2;
                // list_of_c1_values[no_c1_values][0] = hg;
                // list_of_c1_values[no_c1_values][1] = hg1;
                // list_of_c1_values[no_c1_values][2] = hg2;
                // no_c1_values = no_c1_values + 1;
                max_distance2 = max_distance;
                printf("hg = %d, hg1 = %d, hg2 = %d, Diff1: %d, Diff2: %d\n", hg, hg1, hg2, abs(q12 - value1), max_distance2);

                // printf("Printing Progression...\n");
                // for(uint32_t poss = 0; poss <= m_attack; poss++)
                // {
                //   for(uint32_t poss1 = 0; poss1 <= n_attack; poss1++)
                //   {
                //     for(uint32_t poss2 = 0; poss2 <= 2; poss2++)
                //     {
                //     uint32_t value2 = (c1_value_1 * (poss) + c1_value_3*(3*poss1) + c1_value_2*(poss2));
                //     printf("%d, ", value2);
                //     }
                //   }
                // }
                // printf("\n");

              }

              // break;
            }
          }
        }
      }
      // if(found_c_for_attack_1 == 1)
      //   break;
    }
    // if(found_c_for_attack_1 == 1)
    //   break;
  }

  printf("Found k1, k2 for +1\n");

  #else

  // hg = 120, hg1 = 63, hg2 = 42
  c1_value_1 = 120;
  c1_value_2 = 63;
  c1_value_3 = 42;

  #endif

  found_c_for_attack_2 = 0;

  #if (CALC_VALUES == 1)

  while(found_c_for_attack_2 == 0)
  {
    for(int hg = 3; hg < limit_value; hg = hg+3)
    {
      // printf("hg:%d\n",hg);
      for(int hg1 = 3; hg1 < limit_value; hg1 = hg1+3)
      {
        // printf("hg1:%d\n",hg1);
        for(int hg2 = 3; hg2 < limit_value; hg2 = hg2+3)
        {
          // printf("hg2:%d\n",hg2);

          sample_1 = hg;
          sample_2 = hg1;
          sample_3 = hg2;

          // int value1 = sample_1 * (3*2*m + 2*n) + sample_2 * (1*3);
          int value1 = sample_1 * (m_attack) + sample_3 * (3*n_attack) + sample_2 * (2);
          int value2;

          int touch_np = 0;

          max_distance = 1000000;

          if((value1 > q12) && (abs(value1 - q12) > GAP_THRESHOLD_1_1))
          {
            for(int poss = 0; poss <= m_attack; poss++)
            {
              for(int poss1 = 0; poss1 <= n_attack; poss1++)
              {
                for(int poss2 = 0; poss2 <= 2; poss2++)
                {

                  if(!((poss == m_attack) && (poss1 == n_attack) && (poss2 == 2)))
                  {
                    // value2 = sample_1 * (3*poss+poss1) + sample_2 * (3*poss2);

                    value2 = sample_1 * (poss) + sample_3 * (3*poss1) + sample_2 * (poss2);

                    if(max_distance > (abs(q12 - value2)))
                      max_distance = (abs(q12 - value2));

                    // if((value1 < q12) || (value2 > q12)
                    //   || (abs(value1 - q12) < GAP_THRESHOLD_1_1) || (abs(value2 - q12) < GAP_THRESHOLD_1_2))
                    if((value2 > q12) || (abs(value2 - q12) < GAP_THRESHOLD_1_2))
                    {
                      touch_np = 1;
                    }
                  }

                }
              }
            }

            if(touch_np == 0)
            {
              found_c_for_attack_2 = 1;
              // list_of_c1_values[no_c1_values][0] = hg;
              // list_of_c1_values[no_c1_values][1] = hg1;
              // no_c1_values = no_c1_values + 1;
              // printf("hg1: %d, hg2: %d\n", hg, hg1);

              if(max_distance > max_distance2)
              {
                c2_value_1 = hg;
                c2_value_2 = hg1;
                c2_value_3 = hg2;

                // list_of_c1_values[no_c1_values][0] = hg;
                // list_of_c1_values[no_c1_values][1] = hg1;
                // list_of_c1_values[no_c1_values][2] = hg2;
                // no_c1_values = no_c1_values + 1;
                max_distance2 = max_distance;
                printf("hg = %d, hg1 = %d, hg2 = %d, value_1 : %d, Diff1: %d, Diff2: %d\n", hg, hg1, hg2, value1, abs(q12 - value1), max_distance2);

                // printf("Printing Progression...\n");
                // for(uint32_t poss = 0; poss <= m_attack; poss++)
                // {
                //   for(uint32_t poss1 = 0; poss1 <= n_attack; poss1++)
                //   {
                //     for(uint32_t poss2 = 0; poss2 <= 2; poss2++)
                //     {
                //     uint32_t value2 = (c2_value_1 * (poss) + c2_value_3*(3*poss1) + c2_value_2*(poss2));
                //     printf("%d, ", value2);
                //     }
                //   }
                // }
                // printf("\n");
              }

              // break;
            }
          }
        }
      }
      // if(found_c_for_attack_1 == 1)
      //   break;
    }
    // if(found_c_for_attack_1 == 1)
    //   break;
  }

  printf("Found k1, k2 for +2\n");

  #else
  // hg = 102, hg1 = 105, hg2 = 36
  c2_value_1 = 102;
  c2_value_2 = 105;
  c2_value_3 = 36;

  #endif


  // printf("Values...\n");
  // for(int bv = 0; bv < no_c1_values; bv++)
  // {
  //   printf("%d, %d, %d\n", list_of_c1_values[bv][0],list_of_c1_values[bv][1],list_of_c1_values[bv][2]);
  // }

  // printf("Found c_1\n");

  int got_secret = 0;

  int no_queries = 0;
  int weight_hh;
  int profile_trials = 0;

  for (int pq=0; pq<NO_TESTS; pq++)
  {

    printf("************************************************************************************************************\n");
    //
    // c = 0;
    // for(i=0; i<TRIALS; i++)
    // {
    //   crypto_kem_enc(ct, k1, pk);
    //   crypto_kem_dec(k2, ct, sk);
    //
    //   // printf("Printing k1...\n");
    //   // for(uint32_t hfh = 0; hfh < NTRU_SHAREDKEYBYTES; hfh++)
    //   // {
    //   //   printf("%d, ", k1[hfh]);
    //   // }
    //   // printf("\n");
    //   //
    //   // printf("Printing k2...\n");
    //   // for(uint32_t hfh = 0; hfh < NTRU_SHAREDKEYBYTES; hfh++)
    //   // {
    //   //   printf("%d, ", k2[hfh]);
    //   // }
    //   // printf("\n");
    //
    //   c += verify(k1, k2, NTRU_SHAREDKEYBYTES);
    // }
    // if (c > 0)
    //   printf("ERRORS: %d/%d\n\n", c, TRIALS);
    // else
    //   printf("success\n\n");

    crypto_kem_keypair(pk, sk);


    #if (DO_PRINT == 1)

    f2 = fopen(keypair_file, "a");
    // fprintf(f2,"******************************************************************************\n");

    for(int pp1=0;pp1<NTRU_PUBLICKEYBYTES;pp1++)
    {
      fprintf(f2,"%02x", pk[pp1]);
    }
    // fprintf(f2,"\n");

    for(int pp1=0;pp1<NTRU_SECRETKEYBYTES;pp1++)
    {
      fprintf(f2,"%02x", sk[pp1]);
    }
    // fprintf(f2,"\n");
    fclose(f2);

    #endif

    int success_trial = 0;
    int rejected = 0;

    int reached = 0;

    got_secret = 0;


    while(got_secret == 0)
    {

      rejected = 0;
      success_trial = 0;

      if(reached == 1 && got_secret == 0)
      {

        #if (DO_PRINT == 1)

        printf("Deleting...\n");
        f2 = fopen(ct_file, "w+");
        fclose(f2);

        f2 = fopen(ct_file_basic, "w+");
        fclose(f2);

        f2 = fopen(oracle_responses_file_name, "w+");
        fclose(f2);

        #endif

      }

    rej:
    // To test number of -1s...
    // profile_trials = profile_trials + 1;

    // int got_minus_one = 0;
    // int got_zero = 0;

    if(rejected == 1)
    {
      rejected = 0;
      success_trial = 0;

      printf("Deleting...\n");

      #if (DO_PRINT == 1)

      f2 = fopen(ct_file, "w+");
      fclose(f2);

      f2 = fopen(ct_file_basic, "w+");
      fclose(f2);

      f2 = fopen(oracle_responses_file_name, "w+");
      fclose(f2);

      #endif
    }

    int failed_attempts = 0;

    while(success_trial == 0)
    {

      // Try to find a collision...
      intended_function = 0;
      crypto_kem_enc(ct, k1, pk);
      crypto_kem_dec(k2, ct, sk);

      profile_trials = profile_trials+1;

      // printf("Printing extern_mf...\n");
      int flag = 0;
      for(int hfh = 0; hfh < NTRU_N; hfh++)
      {
        if(extern_mf->coeffs[hfh] != 0)
        {
          collision_index = hfh;
          collision_value = extern_mf->coeffs[hfh];
          flag = flag+1;
        }
        // printf("%d, ", extern_mf->coeffs[hfh]);
      }
      // printf("mf_flag = %d\n", flag);

      if(flag > 0)
      {
        // got_minus_one = 1;
        // printf("Found Single Collision at %d\n", collision_array_index[0]);

        // int index_ones = 0;
        // for(int i = 0; i < p; i++)
        // {
        //   // hw_value = hw_calc(er_decrypt[i]);
        //   // if(hw_value == 8 || hw_value == 1)
        //   // {
        //   if(extern_mf->coeffs[i] == 1 || extern_mf->coeffs[i] == -1)
        //   {
        //     collision_array_index[index_ones] = i;
        //     collision_array_value[index_ones] = er_decrypt[i];
        //     index_ones = index_ones+1;
        //   }
        // }

        printf("Printing mf...\n");
        for(int hfh = 0; hfh < NTRU_N; hfh++)
        {
          if(extern_mf->coeffs[hfh] != 0)
            printf("[%d]: %d, ", hfh, extern_mf->coeffs[hfh]);
          // printf("%d, ", extern_mf->coeffs[hfh]);
        }
        printf("\n");

        success_trial = 1;

        #if (DO_PRINT == 1)

        f2 = fopen(ct_file_basic, "w+");
        for(int pp1=0;pp1<NTRU_CIPHERTEXTBYTES;pp1++)
        {
          fprintf(f2,"%02x", ct[pp1]);
        }
        fclose(f2);

        #endif

        // printf("Found Collision...\n");
        // printf("Found Single Collision at %d\n", collision_array_index[0]);
      }
      else
      {

        failed_attempts = failed_attempts+1;

        #if (DO_PRINT == 1)

        sprintf(ct_file_basic_failed,"ct_file_basic_failed_sntrup761_%d.bin",failed_attempts);
        f2 = fopen(ct_file_basic_failed, "w+");
        for(int pp1=0;pp1<NTRU_CIPHERTEXTBYTES;pp1++)
        {
          fprintf(f2,"%02x", ct[pp1]);
        }
        fclose(f2);

        #endif

      }
    }

    printf("Collision Index: %d, Collision Value: %d\n", collision_index,collision_value);

    intended_function = 1;

    int get_er_decrypt_array[2];

    int check_value_whether_correct = 0;
    int no_coeffs_gone = 0;

    int found_secret_coeff;
    poly vv1;
    poly *final_secret_coeffs = &vv1;

    int success_rate = 0;

    int oracle_values[4*NTRU_N];
    int oracle_count = 0;

    int touch_0 = 0;
    int touch_1 = 0;
    int touch_2 = 0;

    for(sec_index = 0;  sec_index < NTRU_N; sec_index++)
    {
      // printf("sec_index: %d\n", sec_index);

      int zero_indication = 0;
      int finding_secret_coeff = 0;

      for(int check1 = 0; check1 < 2; check1++)
      {
        int mul_value;

        if(check1 == 0)
          mul_value = 1;
        else
          mul_value = -1;

        check_for_value = mul_value * 1;

        crypto_kem_enc(ct, k1, pk);
        crypto_kem_dec(k2, ct, sk);
        no_queries = no_queries+1;

        #if (DO_PRINT == 1)


        f2 = fopen(ct_file, "a");
        for(int pp1=0;pp1<NTRU_CIPHERTEXTBYTES;pp1++)
        {
          fprintf(f2,"%02x", ct[pp1]);
        }
        fclose(f2);

        #endif

        // f2 = fopen(ct_file_now, "a");
        // for(int pp1=0;pp1<crypto_kem_CIPHERTEXTBYTES;pp1++)
        // {
        //   fprintf(f2,"%02x", ct[pp1]);
        // }
        // fclose(f2);

        // printf("ct_values are: %d, %d, %d, %d\n",ct[0],ct[1],ct[2],ct[3]);

        weight_hh = 0;
        for(int jh = 0; jh < NTRU_N; jh++)
        {
          if(abs(extern_mf->coeffs[jh]) > 0)
            weight_hh = weight_hh + 1;
        }

        if(weight_hh != 0)
          get_er_decrypt_array[0] = -1;
        else
          get_er_decrypt_array[0] = 0;

        oracle_values[oracle_count] = get_er_decrypt_array[0];
        oracle_count = oracle_count+1;

        temp_temp_char = get_er_decrypt_array[0] & 0xFF;

        #if (DO_PRINT == 1)

        f2 = fopen(oracle_responses_file_name, "a");
        fprintf(f2,"%02x", temp_temp_char);
        fclose(f2);

        #endif

        check_for_value = mul_value * 2;

        crypto_kem_enc(ct, k1, pk);
        crypto_kem_dec(k2, ct, sk);
        no_queries = no_queries+1;

        #if (DO_PRINT == 1)

        f2 = fopen(ct_file, "a");
        for(int pp1=0;pp1<NTRU_CIPHERTEXTBYTES;pp1++)
        {
          fprintf(f2,"%02x", ct[pp1]);
        }
        fclose(f2);

        #endif

        // printf("ct_values are: %d, %d, %d, %d\n",ct[0],ct[1],ct[2],ct[3]);

        weight_hh = 0;
        for(int jh = 0; jh < NTRU_N; jh++)
        {
          if(abs(extern_mf->coeffs[jh]) > 0)
            weight_hh = weight_hh + 1;
        }

        if(weight_hh != 0)
          get_er_decrypt_array[1] = -1;
        else
          get_er_decrypt_array[1] = 0;

        oracle_values[oracle_count] = get_er_decrypt_array[1];
        oracle_count = oracle_count+1;

        temp_temp_char = get_er_decrypt_array[1] & 0xFF;

        #if (DO_PRINT == 1)

        f2 = fopen(oracle_responses_file_name, "a");
        fprintf(f2,"%02x", temp_temp_char);
        fclose(f2);

        #endif

        if(get_er_decrypt_array[0] == 0 && get_er_decrypt_array[1] == 0)
        {
          // printf("Here 0...\n");
          zero_indication = zero_indication + 1;
          touch_0 += 1;
        }
        else if(get_er_decrypt_array[0] == -1 && get_er_decrypt_array[1] == 0)
        {
          if(zero_indication == 0 && check1 == 0)
          {
            if(collision_value == 1)
            {
              touch_1 += 1;
              // printf("Here one first 1...\n");
              found_secret_coeff = 1;
              finding_secret_coeff = 1;
              oracle_count = oracle_count + 2;
              break;
            }
            else if(collision_value == 2)
            {
              touch_1 += 1;
              // printf("Here one first 2...\n");
              // found_secret_coeff = 2047;
              found_secret_coeff = NTRU_Q - 1;
              finding_secret_coeff = 1;
              oracle_count = oracle_count + 2;
              break;
            }
            // found_secret_coeff = -1*collision_value;
          }
          else if(zero_indication == 1)
          {
            if(collision_value == 1)
            {
              touch_1 += 1;
              // printf("Here one second 1...\n");
              // found_secret_coeff = 2047;
              found_secret_coeff = NTRU_Q - 1;
              finding_secret_coeff = 1;
              // oracle_count = oracle_count + 2;
              break;
            }
            else if(collision_value == 2)
            {
              touch_1 += 1;
              // printf("Here one second 2...\n");
              found_secret_coeff = 1;
              finding_secret_coeff = 1;
              // oracle_count = oracle_count + 2;
              break;
            }
            // found_secret_coeff = 1*collision_value;
          }
          else
          {
            rejected = 1;
            printf("Rejected...\n");
            goto rej;
          }


        }
        else if(get_er_decrypt_array[0] == -1 && get_er_decrypt_array[1] == -1)
        {
          if(zero_indication == 0 && check1 == 0)
          {
            if(collision_value == 1)
            {
              touch_2 += 1;
              // printf("Here two first 1...\n");
              found_secret_coeff = 2;
              finding_secret_coeff = 1;
              oracle_count = oracle_count + 2;
              break;
            }
            else if(collision_value == 2)
            {
              touch_2 += 1;
              // printf("Here two first 2...\n");
              // found_secret_coeff = 2046;
              found_secret_coeff = NTRU_Q - 2;
              finding_secret_coeff = 1;
              oracle_count = oracle_count + 2;
              break;
            }
            // found_secret_coeff = -2*collision_value;
          }
          else if(zero_indication == 1)
          {
            if(collision_value == 1)
            {
              touch_2 += 1;
              // printf("Here two second 1...\n");
              // found_secret_coeff = 2046;
              found_secret_coeff = NTRU_Q - 2;
              finding_secret_coeff = 1;
              // oracle_count = oracle_count + 2;
              break;
            }
            else if(collision_value == 2)
            {
              touch_2 += 1;
              // printf("Here two second 2...\n");
              found_secret_coeff = 2;
              finding_secret_coeff = 1;
              // oracle_count = oracle_count + 2;
              break;
            }
            // found_secret_coeff = 2*collision_value;
          }
          else
          {
            rejected = 1;
            printf("Rejected...\n");
            goto rej;
          }

          finding_secret_coeff = 1;
        }
        else
        {
          rejected = 1;
          printf("Rejected...\n");
          goto rej;
        }

        // if(finding_secret_coeff == 1)
        //   break;
      }

      if(finding_secret_coeff == 0)
        found_secret_coeff = 0;

      // if(sec_index == 100 && ((touch_0 == 0) || (touch_1 == 0) || (touch_2 == 0)))
      // {
      //   rejected = 1;
      //   printf("Rejected ***********************...\n");
      //   goto rej;
      // }


      if(sec_index == 100)
      {
        printf("touch_0: %d, touch_1: %d, touch_2: %d\n", touch_0, touch_1, touch_2);
        if((touch_0 < 10) || (touch_1 < 5) || (touch_2 < 2) || (abs(touch_0 - touch_1) < 30))
        {
          rejected = 1;
          printf("Only zeros guessed...\n");
          goto rej;
        }
      }


      // printf("printing oracle_values...\n");
      // for(int sds = 0; sds < 4; sds++)
      //   printf("%d, ", oracle_values[sds]);
      // printf("\n");

      // printf("f_guessed = %d, correct_f_value = %d\n", found_secret_coeff, correct_f_value);

      if(correct_f_value == found_secret_coeff)
        success_rate = success_rate+1;
    }

    printf("success = %d/%d\n", success_rate, (sec_index));

    reached = 1;

    int f_combined[NTRU_N];
    int guessed_f_combined_value;

    poly vxv;
    poly *guessed_secret_f_poly = &vxv;

    got_secret = 0;
    // while(got_secret == 0)
    // {
    for(int coll_value = 1; coll_value <= 2; coll_value++)
    // for(int coll_value = collision_value; coll_value <= collision_value; coll_value++)
    {
      // printf("I am here\n");
      for(sec_index = 0;  sec_index < NTRU_N; sec_index++)
      {
        if(coll_value == 1)
        {
          // if(oracle_values[4*sec_index+0] == 0 && oracle_values[4*sec_index+1] == 0 && oracle_values[4*sec_index+2] == 0 && oracle_values[4*sec_index+3] == 0)
          //   guessed_f_combined_value = 0;
          // else if(oracle_values[4*sec_index+0] == -1 && oracle_values[4*sec_index+1] == 0 && oracle_values[4*sec_index+2] == 0 && oracle_values[4*sec_index+3] == 0)
          //   guessed_f_combined_value = 1;
          // else if(oracle_values[4*sec_index+0] == 0 && oracle_values[4*sec_index+1] == 0 && oracle_values[4*sec_index+2] == -1 && oracle_values[4*sec_index+3] == 0)
          //   guessed_f_combined_value = NTRU_Q - 1;
          // else if(oracle_values[4*sec_index+0] == -1 && oracle_values[4*sec_index+1] == -1 && oracle_values[4*sec_index+2] == 0 && oracle_values[4*sec_index+3] == 0)
          //   guessed_f_combined_value = 2;
          // else if(oracle_values[4*sec_index+0] == 0 && oracle_values[4*sec_index+1] == 0 && oracle_values[4*sec_index+2] == -1 && oracle_values[4*sec_index+3] == -1)
          //   guessed_f_combined_value = NTRU_Q - 2;
          // else
          //   guessed_f_combined_value = 999;


          if(oracle_values[4*sec_index+0] == 0 && oracle_values[4*sec_index+1] == 0 && oracle_values[4*sec_index+2] == 0 && oracle_values[4*sec_index+3] == 0)
            guessed_f_combined_value = 0;
          else if(oracle_values[4*sec_index+0] == -1 && oracle_values[4*sec_index+1] == 0)
            guessed_f_combined_value = 1;
          else if(oracle_values[4*sec_index+0] == 0 && oracle_values[4*sec_index+1] == 0 && oracle_values[4*sec_index+2] == -1 && oracle_values[4*sec_index+3] == 0)
            guessed_f_combined_value = NTRU_Q - 1;
          else if(oracle_values[4*sec_index+0] == -1 && oracle_values[4*sec_index+1] == -1)
            guessed_f_combined_value = 2;
          else if(oracle_values[4*sec_index+0] == 0 && oracle_values[4*sec_index+1] == 0 && oracle_values[4*sec_index+2] == -1 && oracle_values[4*sec_index+3] == -1)
            guessed_f_combined_value = NTRU_Q - 2;
          else
            guessed_f_combined_value = 999;

        }

        if(coll_value == 2)
        {
          // if(oracle_values[4*sec_index+0] == 0 && oracle_values[4*sec_index+1] == 0 && oracle_values[4*sec_index+2] == 0 && oracle_values[4*sec_index+3] == 0)
          //   guessed_f_combined_value = 0;
          // else if(oracle_values[4*sec_index+0] == -1 && oracle_values[4*sec_index+1] == 0 && oracle_values[4*sec_index+2] == 0 && oracle_values[4*sec_index+3] == 0)
          //   guessed_f_combined_value = NTRU_Q - 1;
          // else if(oracle_values[4*sec_index+0] == 0 && oracle_values[4*sec_index+1] == 0 && oracle_values[4*sec_index+2] == -1 && oracle_values[4*sec_index+3] == 0)
          //   guessed_f_combined_value = 1;
          // else if(oracle_values[4*sec_index+0] == -1 && oracle_values[4*sec_index+1] == -1 && oracle_values[4*sec_index+2] == 0 && oracle_values[4*sec_index+3] == 0)
          //   guessed_f_combined_value = NTRU_Q - 2;
          // else if(oracle_values[4*sec_index+0] == 0 && oracle_values[4*sec_index+1] == 0 && oracle_values[4*sec_index+2] == -1 && oracle_values[4*sec_index+3] == -1)
          //   guessed_f_combined_value = 2;
          // else
          //   guessed_f_combined_value = 999;

          if(oracle_values[4*sec_index+0] == 0 && oracle_values[4*sec_index+1] == 0 && oracle_values[4*sec_index+2] == 0 && oracle_values[4*sec_index+3] == 0)
            guessed_f_combined_value = 0;
          else if(oracle_values[4*sec_index+0] == -1 && oracle_values[4*sec_index+1] == 0)
            guessed_f_combined_value = NTRU_Q - 1;
          else if(oracle_values[4*sec_index+0] == 0 && oracle_values[4*sec_index+1] == 0 && oracle_values[4*sec_index+2] == -1 && oracle_values[4*sec_index+3] == 0)
            guessed_f_combined_value = 1;
          else if(oracle_values[4*sec_index+0] == -1 && oracle_values[4*sec_index+1] == -1)
            guessed_f_combined_value = NTRU_Q - 2;
          else if(oracle_values[4*sec_index+0] == 0 && oracle_values[4*sec_index+1] == 0 && oracle_values[4*sec_index+2] == -1 && oracle_values[4*sec_index+3] == -1)
            guessed_f_combined_value = 2;
          else
            guessed_f_combined_value = 999;
        }

        f_combined[sec_index] = guessed_f_combined_value;
      }

      // printf("F Combined...\n");
      // for(int lfl = 0; lfl < NTRU_N; lfl++)
      // {
      //   printf("%d, ", f_combined[lfl]);
      // }
      // printf("\n");

      for(int iter = 0; iter <= 2; iter++)
      {

        int g_coll_secret;
        if(iter == 0)
          g_coll_secret = 0;
        else if(iter == 1)
          g_coll_secret = 1;
        else if(iter == 2)
          g_coll_secret = NTRU_Q - 1;

        // for(int coll_index = 0; coll_index < NTRU_N; coll_index++)
        for(int coll_index = 0; coll_index <= 0; coll_index++)
        {
            // printf("******************coll_index: %d******************\n",coll_index);
            int two_indices_1, two_indices_2, prev_value;
            for(sec_index = 0; sec_index < (NTRU_N-1); sec_index++)
            {
              // I have oracle_count here...

              if(coll_index > sec_index)
              {
                two_indices_1 = coll_index-sec_index;
                two_indices_2 = coll_index-sec_index-1;
              }
              else if(coll_index == sec_index)
              {
                two_indices_1 = 0;
                two_indices_2 = NTRU_N-1;
              }
              else
              {
                two_indices_1 = NTRU_N - (sec_index - coll_index);
                two_indices_2 = NTRU_N - ((sec_index - coll_index) + 1);
              }

              if(sec_index == 0)
              {
                guessed_secret_f_poly->coeffs[two_indices_1] = g_coll_secret;
                guessed_secret_f_poly->coeffs[two_indices_2] = MODQ(g_coll_secret - f_combined[sec_index]);
                prev_value = guessed_secret_f_poly->coeffs[two_indices_2];
              }
              else
              {
                guessed_secret_f_poly->coeffs[two_indices_2] = MODQ(prev_value - f_combined[sec_index]);
                prev_value = guessed_secret_f_poly->coeffs[two_indices_2];
              }
              // printf("f[%d]: %d, %d, f[%d] - f[%d]: %d, f[%d]: %d, f[%d]: %d\n",collision_index,global_f->coeffs[collision_index],g_coll_secret,two_indices_1,two_indices_2,f_combined[sec_index],two_indices_1,guessed_secret_f_poly->coeffs[two_indices_1],two_indices_2,guessed_secret_f_poly->coeffs[two_indices_2]);
            }

            int incorrect_flag = 0;
            for(int lfl = 0; lfl < NTRU_N; lfl++)
            {
              int f_value_now;
              if(guessed_secret_f_poly->coeffs[lfl] > NTRU_Q/2)
              {
                f_value_now = MODQ(NTRU_Q - guessed_secret_f_poly->coeffs[lfl]);
                if(abs(f_value_now) > 1)
                {
                  incorrect_flag = 1;
                  break;
                }
              }
              else
              {
                f_value_now = guessed_secret_f_poly->coeffs[lfl];
                if(abs(f_value_now) > 1)
                {
                  incorrect_flag = 1;
                  break;
                }
              }
            }

            if(incorrect_flag == 0)
            {
              // printf("I am here in incorrect_flag == 0\n");
              // Checking against correct secret key....

              poly xx1, xx2;
              poly *x_f_attack_array = &xx1;
              poly *rot_f_guess_array = &xx1;

              for(int rot = 0; rot < NTRU_N; rot++)
              {
                // printf("Correct Secret Found at collision index: %d, collision_value: %d\n", coll_index, coll_value);
                //
                // printf("rot: %d\n", rot);
                // printf("Guessed Array...\n");
                // for(int lfl = 0; lfl < NTRU_N; lfl++)
                // {
                //   printf("%d, ", guessed_secret_f_poly->coeffs[lfl]);
                // }
                // printf("\n");

                for(int gd = 0; gd<NTRU_N; gd++)
                  x_f_attack_array->coeffs[gd] = 0;

                x_f_attack_array->coeffs[rot] = 1;

                poly_Rq_mul(rot_f_guess_array, x_f_attack_array, guessed_secret_f_poly);

                // printf("rot_f_guess Array...\n");
                for(int lfl = 0; lfl < NTRU_N; lfl++)
                {
                  rot_f_guess_array->coeffs[lfl] = MODQ(rot_f_guess_array->coeffs[lfl]);
                  // printf("%d, ", rot_f_guess_array->coeffs[lfl]);
                }
                // printf("\n");

                int same_no = 0;
                for(int lfl = 0; lfl < NTRU_N; lfl++)
                {
                  if(rot_f_guess_array->coeffs[lfl] == global_f->coeffs[lfl])
                    same_no = same_no+1;
                }

                if(same_no == NTRU_N)
                {
                  printf("Correct Secret Found at collision index: %d, collision_value: %d\n", coll_index, coll_value);

                  int avg_traces = (no_queries + profile_trials * 10)/(pq+1);
                  printf("Average Traces: %d, profile = %d\n", avg_traces,profile_trials);

                  for(int lfl = 0; lfl < NTRU_N; lfl++)
                  {
                    printf("%d, ", rot_f_guess_array->coeffs[lfl]);
                  }
                  printf("\n");
                  got_secret = 1;
                  break;
                }
                if(got_secret == 1)
                  break;
              }
            }
            if(got_secret == 1)
              break;
          }
          if(got_secret == 1)
            break;
        }
        if(got_secret == 1)
          break;
      }
    }
  }


  free(sk);
  free(pk);
  free(ct);
  free(k1);
  free(k2);

  return 0;
}







// uint32_t main(void)
// {
//   uint32_t i,c;
//   unsigned char* pk = (unsigned char*) malloc(NTRU_PUBLICKEYBYTES);
//   unsigned char* sk = (unsigned char*) malloc(NTRU_SECRETKEYBYTES);
//   unsigned char* ct = (unsigned char*) malloc(NTRU_CIPHERTEXTBYTES);
//   unsigned char* k1 = (unsigned char*) malloc(NTRU_SHAREDKEYBYTES);
//   unsigned char* k2 = (unsigned char*) malloc(NTRU_SHAREDKEYBYTES);
//
//   crypto_kem_keypair(pk, sk);
//
//   c = 0;
//   for(i=0; i<TRIALS; i++)
//   {
//     crypto_kem_enc(ct, k1, pk);
//     crypto_kem_dec(k2, ct, sk);
//     c += verify(k1, k2, NTRU_SHAREDKEYBYTES);
//   }
//   if (c > 0)
//     printf("ERRORS: %d/%d\n\n", c, TRIALS);
//   else
//     printf("success\n\n");
//
//   free(sk);
//   free(pk);
//   free(ct);
//   free(k1);
//   free(k2);
//
//   return 0;
// }
