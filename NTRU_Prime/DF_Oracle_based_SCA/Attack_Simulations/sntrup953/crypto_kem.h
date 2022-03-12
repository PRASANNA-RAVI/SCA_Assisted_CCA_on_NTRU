#ifndef crypto_kem_H
#define crypto_kem_H

#include "crypto_kem_sntrup953.h"
#include "int8.h"
#include "int16.h"
#include "int32.h"
#include "uint16.h"
#include "uint32.h"
#include "crypto_sort_uint32.h"
#include "Encode.h"
#include "Decode.h"
#include <math.h>
#include "params.h"

#define crypto_kem_keypair crypto_kem_sntrup953_keypair
#define crypto_kem_enc crypto_kem_sntrup953_enc
#define crypto_kem_dec crypto_kem_sntrup953_dec
#define crypto_kem_PUBLICKEYBYTES crypto_kem_sntrup953_PUBLICKEYBYTES
#define crypto_kem_SECRETKEYBYTES crypto_kem_sntrup953_SECRETKEYBYTES
#define crypto_kem_BYTES crypto_kem_sntrup953_BYTES
#define crypto_kem_CIPHERTEXTBYTES crypto_kem_sntrup953_CIPHERTEXTBYTES
#define crypto_kem_PRIMITIVE "sntrup953"

#define count_threshold 1
#define index_threshold 0
#define NO_COEFFS 10

int intended_function;
int sec_index;
int no_leakage_trials;

#define DO_ATTACK_COLLISION_NEW 1

#define TRIALS_FOR_SHUFFLING 1
#define TOTAL_COEFFS_TO_FIND (p-2)

int error_now;

int succ_flag;
int count_ones;
int count_plus_ones;
int count_minus_ones;
int non_zero_f_coeff;
int non_zero_g_coeff;
int check_for_value;
int c_value;
int c_value_1;
int c_value_2;
int c_value_1_trimming;
int c_value_2_trimming;
int c_value_for_attack_1;
int c_value_for_attack_2;

int c_value_for_leakage;
int collision_index;
int collision_value;
int hw_value;
int weight_hh;
int global_mask;

int m;
int n;

int sign_cf3_value;
int sign_cf3_value_chosen_ciphertext;

typedef int8 small;

small er[p];
small er_decrypt[p];
small er_decrypt_in_focus[p];
small global_f[p];
small global_g[p];

/* ----- arithmetic mod q */

#define q12 ((q-1)/2)

typedef int16 Fq;

Fq global_c_in_encrypt[p];
Fq global_c_in_decrypt[p];
Fq global_valid_hr[p];

Fq x_f_array[p];
Fq x_g_array[p];
Fq cf3[p];
Fq cf3_in_focus[p];
Fq cf3_in_chosen_ciphertext[p];
Fq f_diff_in_chosen_ciphertext[p];
Fq f_diff_3[p];
Fq error_polynomial[p];

Fq final_secret_coeffs_3[p];
Fq final_g_secret_coeffs[p];

Fq cf[p];
small e[p];
small ev[p];
Fq c_copy[p];

#endif
