#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "../params.h"
#include "../kem.h"
#include "../poly.h"

// This setting is used to write the data to a text file for analysis... This need not be turned on to run attack simulations...

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

  m_attack = M_VALUE;
  n_attack = N_VALUE;

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
  char ct_file[30];
  char keypair_file[30];
  char oracle_responses_file_name[30];
  char ct_file_basic_failed[50];

  #if (DO_PRINT == 1)

  // We can store the data of a single iteration in files...
  // Please note that these files will be overwritten for every iteration...
  // We store the oracle responses in oracle_resp.bin...

  sprintf(oracle_responses_file_name,"oracle_resp.bin");

  // Here, we store the attack ciphertexts...

  sprintf(ct_file,"ct_file.bin");

  // Here, we store the base ciphertext...

  sprintf(ct_file_basic,"ct_file_basic.bin");

  // Here, we store the public and private key pair...

  sprintf(keypair_file,"keypair_file.bin");

  // Here, we store the failed ciphertexts which do not correspond to any collision...

  sprintf(ct_file_basic_failed,"ct_file_basic_failed_%d.bin");

  #endif

  // This is used to calculate k1 and k2 for the base ciphertext cbase, as described in the paper...

  for(uint32_t hg = 3; hg < limit_hg; hg=hg+3)
  {

    for(uint32_t hg1 = 3; hg1 < limit_hg; hg1=hg1+3)
    {

          uint32_t value1 = hg * (m_attack) + hg1 * (3*n_attack);

          uint32_t touch_np = 0;

          max_distance = 1000000;

          if(value1 > q12 && (abs(q12 - value1) > C_VALUE_THRESHOLD_1))
          {
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

            if(touch_np == 0)
            {
              found_c = 1;

              if(max_distance > max_distance2)
              {
                c_value_1 = hg;
                c_value_2 = hg1;
                max_distance2 = max_distance;
                printf("hg = %d, hg1 = %d, Diff1: %d, Diff2: %d\n", hg, hg1, abs(q12 - value1), max_distance2);

              }
            }
          }

    }
  }

  printf("Found k1, k2 for collision\n");

  // Here, we are trying to compute l1, l2 and l3 for the attack ciphertexts as shown in the paper...
  // We compute l1, l2, l3 is used to distinguish 1...

  max_distance = 1000000;
  max_distance2 = 0;

  int limit_value = 1000;

  found_c_for_attack_1 = 0;


  while(found_c_for_attack_1 == 0)
  {
    for(int hg = 3; hg < limit_value; hg = hg+3)
    {
      for(int hg1 = 3; hg1 < limit_value; hg1 = hg1+3)
      {
        for(int hg2 = 3; hg2 < limit_value; hg2 = hg2+3)
        {

          sample_1 = hg;
          sample_2 = hg1;
          sample_3 = hg2;

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

                    value2 = sample_1 * (poss) + sample_3 * (3*poss1) + sample_2 * (poss2);

                    if(max_distance > (abs(q12 - value2)))
                      max_distance = (abs(q12 - value2));

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

              if(max_distance > max_distance2)
              {
                c1_value_1 = hg;
                c1_value_2 = hg1;
                c1_value_3 = hg2;
                max_distance2 = max_distance;
                printf("hg = %d, hg1 = %d, hg2 = %d, Diff1: %d, Diff2: %d\n", hg, hg1, hg2, abs(q12 - value1), max_distance2);


              }
            }
          }
        }
      }
    }
  }

  printf("Found k1, k2 for +1\n");

  // Here, we are trying to compute l1, l2 and l3 for the attack ciphertexts as shown in the paper...
  // We compute l1, l2, l3 is used to distinguish 2...

  found_c_for_attack_2 = 0;

  while(found_c_for_attack_2 == 0)
  {
    for(int hg = 3; hg < limit_value; hg = hg+3)
    {
      for(int hg1 = 3; hg1 < limit_value; hg1 = hg1+3)
      {
        for(int hg2 = 3; hg2 < limit_value; hg2 = hg2+3)
        {

          sample_1 = hg;
          sample_2 = hg1;
          sample_3 = hg2;

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

                    value2 = sample_1 * (poss) + sample_3 * (3*poss1) + sample_2 * (poss2);

                    if(max_distance > (abs(q12 - value2)))
                      max_distance = (abs(q12 - value2));

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

              if(max_distance > max_distance2)
              {
                c2_value_1 = hg;
                c2_value_2 = hg1;
                c2_value_3 = hg2;

                max_distance2 = max_distance;
                printf("hg = %d, hg1 = %d, hg2 = %d, value_1 : %d, Diff1: %d, Diff2: %d\n", hg, hg1, hg2, value1, abs(q12 - value1), max_distance2);

              }

            }
          }
        }
      }
    }
  }

  printf("Found k1, k2 for +2\n");

  // So, we basically get two values for the (l1, l2, l3)... Let us denote them as (l11, l12, l13) and (l21, l22, l23)...
  // The attack ciphertexts are c = l1. d1 + l2. d2 . h + l3. x^u. (x-1)...

  //       (l11,l12,l13)     (l21,l22,l23)      (l11,l12,-l13)      (l21,l22,-l23)
  // 2         O                  O                   X                  X
  // 1         O                  O                   X                  O
  // 0         O                  O                   O                  O
  // -1        X                  O                   O                  O
  // -2        X                  X                   O                  O

  int got_secret = 0;

  int no_queries = 0;
  int weight_hh;
  int profile_trials = 0;

  // Iterate over the number of tests you want to run... The NO_TESTS variable is defined in params.h header file...

  for (int pq=0; pq<NO_TESTS; pq++)
  {

    #if (DO_PRINT == 1)

    f2 = fopen(oracle_responses_file_name, "w+");
    fclose(f2);

    f2 = fopen(ct_file_basic_failed, "w+");
    fclose(f2);

    f2 = fopen(keypair_file, "w+");
    fclose(f2);

    f2 = fopen(ct_file_basic, "w+");
    fclose(f2);

    f2 = fopen(ct_file, "w+");
    fclose(f2);

    #endif

    int current_profile_trial = 0;

    printf("************************************************************************************************************\n");

    // Generate new key pair ...

    crypto_kem_keypair(pk, sk);


    #if (DO_PRINT == 1)

    f2 = fopen(keypair_file, "a");

    for(int pp1=0;pp1<NTRU_PUBLICKEYBYTES;pp1++)
    {
      fprintf(f2,"%02x", pk[pp1]);
    }

    for(int pp1=0;pp1<NTRU_SECRETKEYBYTES;pp1++)
    {
      fprintf(f2,"%02x", sk[pp1]);
    }
    fclose(f2);

    #endif

    int success_trial = 0;
    int rejected = 0;

    int reached = 0;

    got_secret = 0;

    // Iterate till you get the correct keys...

    while(got_secret == 0)
    {

      rejected = 0;
      success_trial = 0;

      // The reached variable basically tells if you have finished the attack phase...
      // If reached = 1 and got_secret == 0, then it means key recovery has failed...So, we need to try again...

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

        f2 = fopen(ct_file_basic_failed, "w+");
        fclose(f2);

        #endif

      }

    rej:

    // The rejected variable tells whether the attack phase was aborted half way, maybe due to bad oracle responses.... Bad oracle responses are possible when
    // the base ciphertext is wrong...

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

      f2 = fopen(ct_file_basic_failed, "w+");
      fclose(f2);

      #endif
    }

    int failed_attempts = 0;

    current_profile_trial = 0;

    // Success_trial tells whether we have got the base ciphertext or not... This is for the pre-processing phase....
    // So, keep trying until you have got the base ciphertext...

    while(success_trial == 0)
    {

      // Build a base ciphertext c = k1 . d1 + k2. d2. h... Try to see if you can identify a collision...

      intended_function = 0;
      crypto_kem_enc(ct, k1, pk);
      crypto_kem_dec(k2, ct, sk);

      profile_trials = profile_trials+1;
      current_profile_trial = current_profile_trial + 1;

      // We realize an oracle using the variable mf... Refer line 433 in the decryption procedure in owcpa.c file...
      // We simple copy the mf variable to the extern_mf variable and this acts as our oracle...

      // In particular, we are only interested in the weight of the mf variable... Whether weight is 0 or non-zero... which is reflected in the flag variable...

      int flag = 0;
      for(int hfh = 0; hfh < NTRU_N; hfh++)
      {
        if(extern_mf->coeffs[hfh] != 0)
        {
          flag = flag+1;
        }
      }

      // If flag > 0, then you have got a ciphertext whose weight is greater than 0... Thus, we have got the base ciphertext cbase...

      if(flag > 0)
      {

        success_trial = 1;

        #if (DO_PRINT == 1)

        f2 = fopen(ct_file_basic, "w+");
        for(int pp1=0;pp1<NTRU_CIPHERTEXTBYTES;pp1++)
        {
          fprintf(f2,"%02x", ct[pp1]);
        }
        fclose(f2);

        #endif

      }

      // Else, we have not yet got the base ciphertext... We simply need to try again... to get the base ciphertext....

      else
      {
        #if (DO_PRINT == 1)

        f2 = fopen(ct_file_basic_failed, "a");
        for(int pp1=0;pp1<NTRU_CIPHERTEXTBYTES;pp1++)
        {
          fprintf(f2,"%02x", ct[pp1]);
        }
        fclose(f2);

        #endif

      }
    }

    // We have now got the base ciphertext... Now, we can do the attack phase...

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

    // Here, we are iterating over all the indices of the secret polynomial from 0 to (N-1)...

    for(sec_index = 0;  sec_index < NTRU_N; sec_index++)
    {

      int zero_indication = 0;
      int finding_secret_coeff = 0;

      // Here, we get oracle responses for attack ciphertexts corresponding to (l11,l12,l13), (l11,l12,-l13), (l21,l22,l23), (l11,l12,-l13)...

      for(int check1 = 0; check1 < 2; check1++)
      {
        int mul_value;

        // (l11,l12,l13) if check1 = 0, else (l11,l12,-l13)

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

        // Getting oracle response... whether weight of mf = 0 (Class O) or not equal to 0 (Class X)...

        weight_hh = 0;
        for(int jh = 0; jh < NTRU_N; jh++)
        {
          if(abs(extern_mf->coeffs[jh]) > 0)
            weight_hh = weight_hh + 1;
        }

        // We store the current oracle responses...in the get_er_decrypt_array... This is to see if the current oracle respones are good...Wehther atleast matches
        // one of the entries in the table...

        if(weight_hh != 0)
          get_er_decrypt_array[0] = -1;
        else
          get_er_decrypt_array[0] = 0;

        // We store the all the oracle responses...in the oracle_values...

        oracle_values[oracle_count] = get_er_decrypt_array[0];
        oracle_count = oracle_count+1;

        temp_temp_char = get_er_decrypt_array[0] & 0xFF;

        #if (DO_PRINT == 1)

        f2 = fopen(oracle_responses_file_name, "a");
        fprintf(f2,"%02x", temp_temp_char);
        fclose(f2);

        #endif

        // (l21,l22,l23) if check1 = 0, else (l21,l22,-l23)

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

        // Getting oracle response...

        weight_hh = 0;
        for(int jh = 0; jh < NTRU_N; jh++)
        {
          if(abs(extern_mf->coeffs[jh]) > 0)
            weight_hh = weight_hh + 1;
        }

        // Storing the oracle's response...

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

        // Now, we are simply checking the current oracle's response... If it does not match, then we simply reject and restart attack... Else, we carry on...

        if(get_er_decrypt_array[0] == 0 && get_er_decrypt_array[1] == 0)
        {
          zero_indication = zero_indication + 1;
          touch_0 += 1;
        }
        else if(get_er_decrypt_array[0] == -1 && get_er_decrypt_array[1] == 0)
        {
          if(zero_indication == 0 && check1 == 0)
          {
            touch_1 += 1;
            finding_secret_coeff = 1;
            oracle_count = oracle_count + 2;
            break;

          }
          else if(zero_indication == 1)
          {
            touch_1 += 1;
            finding_secret_coeff = 1;
            break;

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
            touch_2 += 1;
            finding_secret_coeff = 1;
            oracle_count = oracle_count + 2;
            break;

          }
          else if(zero_indication == 1)
          {
            touch_2 += 1;
            finding_secret_coeff = 1;
            break;

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

      }

      // Here, we are doing an additional check to see if the oracle's response are very skewed...
      // For example, only returning O for all ciphertexts... or X...
      // Or, it could return responses that correspond to abnormally high number of 1s or 2s... Then, you simply reject it...

      if(sec_index == 100)
      {
        if((touch_0 < 10) || (touch_1 < 5) || (touch_2 < 2) || (abs(touch_0 - touch_1) < 30))
        {
          rejected = 1;
          printf("Only zeros guessed...\n");
          goto rej;
        }
      }

    }

    // Here we are done with the attack phase... Now, we use the collected oracle's responses and then try to retrieve the secret key...
    // We do not know the collision value or the collision index... So, we iterate over the collision value...

    reached = 1;

    int f_combined[NTRU_N];
    int guessed_f_combined_value;

    poly vxv;
    poly *guessed_secret_f_poly = &vxv;

    got_secret = 0;

    // We iterate over the collision value...1 or 2...

    for(int coll_value = 1; coll_value <= 2; coll_value++)
    {

      // We iterate over all the colliding indices...

      for(sec_index = 0;  sec_index < NTRU_N; sec_index++)
      {

        if(coll_value == 1)
        {

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

      for(int iter = 0; iter <= 2; iter++)
      {

        int g_coll_secret;
        if(iter == 0)
          g_coll_secret = 0;
        else if(iter == 1)
          g_coll_secret = 1;
        else if(iter == 2)
          g_coll_secret = NTRU_Q - 1;

        for(int coll_index = 0; coll_index <= 0; coll_index++)
        {

            int two_indices_1, two_indices_2, prev_value;
            for(sec_index = 0; sec_index < (NTRU_N-1); sec_index++)
            {

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

              poly xx1, xx2;
              poly *x_f_attack_array = &xx1;
              poly *rot_f_guess_array = &xx1;

              for(int rot = 0; rot < NTRU_N; rot++)
              {

                for(int gd = 0; gd<NTRU_N; gd++)
                  x_f_attack_array->coeffs[gd] = 0;

                x_f_attack_array->coeffs[rot] = 1;

                poly_Rq_mul(rot_f_guess_array, x_f_attack_array, guessed_secret_f_poly);

                for(int lfl = 0; lfl < NTRU_N; lfl++)
                {
                  rot_f_guess_array->coeffs[lfl] = MODQ(rot_f_guess_array->coeffs[lfl]);
                }

                int same_no = 0;
                for(int lfl = 0; lfl < NTRU_N; lfl++)
                {
                  if(rot_f_guess_array->coeffs[lfl] == global_f->coeffs[lfl])
                    same_no = same_no+1;
                }

                if(same_no == NTRU_N)
                {
                  printf("Correct Secret Found...\n");

                  int avg_traces = (no_queries + profile_trials * 10)/(pq+1);

                  printf("Average Traces: %d, profile = %d\n", avg_traces,profile_trials*10);

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
