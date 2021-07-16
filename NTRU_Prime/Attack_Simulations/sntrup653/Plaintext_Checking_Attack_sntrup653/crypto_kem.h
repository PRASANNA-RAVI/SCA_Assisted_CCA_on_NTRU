#ifndef crypto_kem_H
#define crypto_kem_H

#include "crypto_kem_sntrup653.h"
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

#define crypto_kem_keypair crypto_kem_sntrup653_keypair
#define crypto_kem_enc crypto_kem_sntrup653_enc
#define crypto_kem_dec crypto_kem_sntrup653_dec
#define crypto_kem_PUBLICKEYBYTES crypto_kem_sntrup653_PUBLICKEYBYTES
#define crypto_kem_SECRETKEYBYTES crypto_kem_sntrup653_SECRETKEYBYTES
#define crypto_kem_BYTES crypto_kem_sntrup653_BYTES
#define crypto_kem_CIPHERTEXTBYTES crypto_kem_sntrup653_CIPHERTEXTBYTES
#define crypto_kem_PRIMITIVE "sntrup653"

#define count_threshold 1
#define index_threshold 0
#define NO_COEFFS 10
#define NO_TESTS 100

int intended_function;
int sec_index;
int no_leakage_trials;

#define DO_ATTACK_COLLISION_NEW 1

// m = 1, n = 1...
// #define GAP_THRESHOLD_1 133
// #define GAP_THRESHOLD_2 116
// #define C_VALUE_THRESHOLD 200

// // m = 1, n = 2...
// #define GAP_THRESHOLD_1 108
// #define GAP_THRESHOLD_2 95
// #define C_VALUE_THRESHOLD 200

// m = 1, n = 3...
#define GAP_THRESHOLD_1_1 60
#define GAP_THRESHOLD_1_2 60
#define GAP_THRESHOLD_2_1 120
#define GAP_THRESHOLD_2_2 120
#define C_VALUE_THRESHOLD_1 130
#define C_VALUE_THRESHOLD_2 130

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
int c_value_for_attack_1;
int c_value_for_attack_2;

int c_value_for_leakage;
int collision_index;
int collision_value;
int hw_value;
int weight_hh;

int m;
int n;

typedef int8 small;

small er[p];
small er_decrypt[p];
small global_f[p];
small global_g[p];

/* ----- arithmetic mod q */

#define q12 ((q-1)/2)

typedef int16 Fq;

Fq global_c_in_encrypt[p];
Fq global_c_in_decrypt[p];
Fq x_f_array[p];
Fq x_g_array[p];
Fq cf3[p];
Fq f_diff_3[p];

Fq cf[p];
small e[p];
small ev[p];
Fq c_copy[p];

#endif
