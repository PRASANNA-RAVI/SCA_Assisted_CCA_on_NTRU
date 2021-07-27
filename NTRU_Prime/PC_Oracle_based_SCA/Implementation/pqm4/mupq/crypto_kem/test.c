#include "api.h"
#include "randombytes.h"
#include "hal.h"
#include <libopencm3/stm32/gpio.h>
#include <string.h>

#define NTESTS 10

int global_function;

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
    unsigned int POLY_MASK_HERE_1 = 0x12431234;
    unsigned int POLY_MASK_HERE_2 = 0xABBBEECD;
    static unsigned int lfsr_1 = 0x55AAEEFF;
    static unsigned int lfsr_2 = 0xFFAA8844;
    shift_lfsr(&lfsr_1, POLY_MASK_HERE_1);
    shift_lfsr(&lfsr_2, POLY_MASK_HERE_2);
    temp = (shift_lfsr(&lfsr_1, POLY_MASK_HERE_1) ^ shift_lfsr(&lfsr_2, POLY_MASK_HERE_2)) & 0XFF;
    return (temp);
}

// https://stackoverflow.com/a/1489985/1711232
#define PASTER(x, y) x####y
#define EVALUATOR(x, y) PASTER(x, y)
#define NAMESPACE(fun) EVALUATOR(MUPQ_NAMESPACE, fun)

// use different names so we can have empty namespaces
#define MUPQ_CRYPTO_BYTES           NAMESPACE(CRYPTO_BYTES)
#define MUPQ_CRYPTO_PUBLICKEYBYTES  NAMESPACE(CRYPTO_PUBLICKEYBYTES)
#define MUPQ_CRYPTO_SECRETKEYBYTES  NAMESPACE(CRYPTO_SECRETKEYBYTES)
#define MUPQ_CRYPTO_CIPHERTEXTBYTES NAMESPACE(CRYPTO_CIPHERTEXTBYTES)
#define MUPQ_CRYPTO_ALGNAME NAMESPACE(CRYPTO_ALGNAME)

#define MUPQ_crypto_kem_keypair NAMESPACE(crypto_kem_keypair)
#define MUPQ_crypto_kem_enc NAMESPACE(crypto_kem_enc)
#define MUPQ_crypto_kem_dec NAMESPACE(crypto_kem_dec)

const uint8_t canary[8] = {
  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
};

/* allocate a bit more for all keys and messages and
 * make sure it is not touched by the implementations.
 */
static void write_canary(uint8_t *d) {
  for (size_t i = 0; i < 8; i++) {
    d[i] = canary[i];
  }
}

static int check_canary(const uint8_t *d) {
  for (size_t i = 0; i < 8; i++) {
    if (d[i] != canary[i]) {
      return -1;
    }
  }
  return 0;
}

static int test_keys(void)
{
  unsigned char key_a[MUPQ_CRYPTO_BYTES+16], key_b[MUPQ_CRYPTO_BYTES+16];
  unsigned char pk[MUPQ_CRYPTO_PUBLICKEYBYTES+16];
  unsigned char sendb[MUPQ_CRYPTO_CIPHERTEXTBYTES+16];
  unsigned char sk_a[MUPQ_CRYPTO_SECRETKEYBYTES+16];

  write_canary(key_a); write_canary(key_a+sizeof(key_a)-8);
  write_canary(key_b); write_canary(key_b+sizeof(key_b)-8);
  write_canary(pk); write_canary(pk+sizeof(pk)-8);
  write_canary(sendb); write_canary(sendb+sizeof(sendb)-8);
  write_canary(sk_a); write_canary(sk_a+sizeof(sk_a)-8);


  int i;

  for(i=0; i<NTESTS; i++)
  {
    //Alice generates a public key
    MUPQ_crypto_kem_keypair(pk+8, sk_a+8);
    hal_send_str("DONE key pair generation!");

    //Bob derives a secret key and creates a response
    MUPQ_crypto_kem_enc(sendb+8, key_b+8, pk+8);
    hal_send_str("DONE encapsulation!");

    //Alice uses Bobs response to get her secret key
    MUPQ_crypto_kem_dec(key_a+8, sendb+8, sk_a+8);
    hal_send_str("DONE decapsulation!");

    if(memcmp(key_a+8, key_b+8, MUPQ_CRYPTO_BYTES))
    {
      hal_send_str("ERROR KEYS\n");
    }
    else if(check_canary(key_a) || check_canary(key_a+sizeof(key_a)-8) ||
            check_canary(key_b) || check_canary(key_b+sizeof(key_b)-8) ||
            check_canary(pk) || check_canary(pk+sizeof(pk)-8) ||
            check_canary(sendb) || check_canary(sendb+sizeof(sendb)-8) ||
            check_canary(sk_a) || check_canary(sk_a+sizeof(sk_a)-8))
    {
      hal_send_str("ERROR canary overwritten\n");
    }
    else
    {
      hal_send_str("OK KEYS\n");
    }
  }

  return 0;
}



static int test_attack(void)
{
  unsigned char key_a[MUPQ_CRYPTO_BYTES+16], key_b[MUPQ_CRYPTO_BYTES+16];
  unsigned char pk[MUPQ_CRYPTO_PUBLICKEYBYTES+16];
  unsigned char sendb[MUPQ_CRYPTO_CIPHERTEXTBYTES+16];
  unsigned char sk_a[MUPQ_CRYPTO_SECRETKEYBYTES+16];

  write_canary(key_a); write_canary(key_a+sizeof(key_a)-8);
  write_canary(key_b); write_canary(key_b+sizeof(key_b)-8);
  write_canary(pk); write_canary(pk+sizeof(pk)-8);
  write_canary(sendb); write_canary(sendb+sizeof(sendb)-8);
  write_canary(sk_a); write_canary(sk_a+sizeof(sk_a)-8);


  int profiling, attacking;

  unsigned char recv_byte_start;
  unsigned char send_byte;

  int count_Os = 0;

  while(1)
  {
      recv_USART_bytes(&recv_byte_start,1);

      // In first attack, we will have to first do a profiling... between all zeros and non-zero...

      if(recv_byte_start == 'O')
      {
        // We are Profiling... First N traces will be zeros... Second N traces will be random valid ciphertexts...

        // Generate ciphertexts for e = 0....

        if(count_Os == 0)
        {

          global_function = 1;

          //Bob derives a secret key and creates a response
          MUPQ_crypto_kem_enc(sendb+8, key_b+8, pk+8);

        }

        //Alice uses Bobs response to get her secret key
        MUPQ_crypto_kem_dec(key_a+8, sendb+8, sk_a+8);
        count_Os = count_Os + 1;

        send_byte = 0x4F;
        send_USART_bytes(&send_byte,1);

      }


      else if(recv_byte_start == 'B')
      {
        // We are Attacking... Read ciphertext from the serial port and simply call decapsulation....

        send_byte = 0x5A;
        send_USART_bytes(&send_byte,1);

        for(int pp1 = 0; pp1 < CRYPTO_CIPHERTEXTBYTES; pp1++)
        {
          recv_USART_bytes(sendb+8+pp1,1);
          // send_byte = 0x46;
          // send_USART_bytes(&send_byte,1);
        }

        // //Alice uses Bobs response to get her secret key
        // MUPQ_crypto_kem_dec(key_a+8, sendb+8, sk_a+8);

        // send_byte = 0x5A;
        // send_USART_bytes(&send_byte,1);
      }

      if(recv_byte_start == 'X')
      {
        // Generate ciphertexts for e = random...

        // global_function = 0;
        //
        // //Bob derives a secret key and creates a response
        // MUPQ_crypto_kem_enc(sendb+8, key_b+8, pk+8);

        // for(int gf = 0; gf < CRYPTO_CIPHERTEXTBYTES; gf++)
        //   sendb[gf+8] = get_random()&0xFF;

        //Alice uses Bobs response to get her secret key
        MUPQ_crypto_kem_dec(key_a+8, sendb+8, sk_a+8);

        send_byte = 0x58;
        send_USART_bytes(&send_byte,1);

      }

      else if(recv_byte_start == 'Z')
      {
        // We are Attacking... Read ciphertext from the serial port and simply call decapsulation....

        // send_byte = 0x5A;
        // send_USART_bytes(&send_byte,1);
        //
        // for(int pp1 = 0; pp1 < CRYPTO_CIPHERTEXTBYTES; pp1++)
        // {
        //   recv_USART_bytes(sendb+8+pp1,1);
        //   // send_byte = 0x46;
        //   // send_USART_bytes(&send_byte,1);
        // }

        //Alice uses Bobs response to get her secret key
        MUPQ_crypto_kem_dec(key_a+8, sendb+8, sk_a+8);

        send_byte = 0x5A;
        send_USART_bytes(&send_byte,1);
      }


      else if(recv_byte_start == 'A')
      {
        // We are Attacking... Read ciphertext from the serial port and simply call decapsulation....

        send_byte = 0x5A;
        send_USART_bytes(&send_byte,1);

        for(int pp1 = 0; pp1 < CRYPTO_CIPHERTEXTBYTES; pp1++)
        {
          recv_USART_bytes(sendb+8+pp1,1);
          // send_byte = 0x46;
          // send_USART_bytes(&send_byte,1);
        }

        // //Alice uses Bobs response to get her secret key
        // MUPQ_crypto_kem_dec(key_a+8, sendb+8, sk_a+8);

        // send_byte = 0x5A;
        // send_USART_bytes(&send_byte,1);
      }

      // Here, we configure the device with public key and secret key that we use for our attack...
      else if(recv_byte_start == 'C')
      {

        send_byte = 0x43;
        send_USART_bytes(&send_byte,1);

        for(int pp1 = 0; pp1 < CRYPTO_PUBLICKEYBYTES; pp1++)
        {
          recv_USART_bytes(pk+pp1+8,1);

          // send_byte = 0x44;
          // send_USART_bytes(&send_byte,1);
        }

        for(int pp1 = 0; pp1 < CRYPTO_SECRETKEYBYTES; pp1++)
        {
          recv_USART_bytes(sk_a+pp1+8,1);

          // send_byte = 0x45;
          // send_USART_bytes(&send_byte,1);
        }

        // //Bob derives a secret key and creates a response
        // MUPQ_crypto_kem_enc(sendb+8, key_b+8, pk+8);
        // // hal_send_str("DONE encapsulation!");
        //
        // //Alice uses Bobs response to get her secret key
        // MUPQ_crypto_kem_dec(key_a+8, sendb+8, sk_a+8);
        // // hal_send_str("DONE decapsulation!");
        //
        // if(memcmp(key_a+8, key_b+8, MUPQ_CRYPTO_BYTES))
        // {
        //   // hal_send_str("ERROR KEYS\n");
        //   send_byte = 0x50;
        //   send_USART_bytes(&send_byte,1);
        //
        // }
        // else if(check_canary(key_a) || check_canary(key_a+sizeof(key_a)-8) ||
        //         check_canary(key_b) || check_canary(key_b+sizeof(key_b)-8) ||
        //         check_canary(pk) || check_canary(pk+sizeof(pk)-8) ||
        //         check_canary(sendb) || check_canary(sendb+sizeof(sendb)-8) ||
        //         check_canary(sk_a) || check_canary(sk_a+sizeof(sk_a)-8))
        // {
        //   // hal_send_str("ERROR canary overwritten\n");
        //   send_byte = 0x50;
        //   send_USART_bytes(&send_byte,1);
        // }
        // else
        // {
        //   // hal_send_str("OK KEYS\n");
        //   send_byte = 0x40;
        //   send_USART_bytes(&send_byte,1);
        // }

      }

  }

  int i;

  for(i=0; i<NTESTS; i++)
  {
    //Alice generates a public key
    MUPQ_crypto_kem_keypair(pk+8, sk_a+8);
    hal_send_str("DONE key pair generation!");

    //Bob derives a secret key and creates a response
    MUPQ_crypto_kem_enc(sendb+8, key_b+8, pk+8);
    hal_send_str("DONE encapsulation!");

    //Alice uses Bobs response to get her secret key
    MUPQ_crypto_kem_dec(key_a+8, sendb+8, sk_a+8);
    hal_send_str("DONE decapsulation!");

    if(memcmp(key_a+8, key_b+8, MUPQ_CRYPTO_BYTES))
    {
      hal_send_str("ERROR KEYS\n");
    }
    else if(check_canary(key_a) || check_canary(key_a+sizeof(key_a)-8) ||
            check_canary(key_b) || check_canary(key_b+sizeof(key_b)-8) ||
            check_canary(pk) || check_canary(pk+sizeof(pk)-8) ||
            check_canary(sendb) || check_canary(sendb+sizeof(sendb)-8) ||
            check_canary(sk_a) || check_canary(sk_a+sizeof(sk_a)-8))
    {
      hal_send_str("ERROR canary overwritten\n");
    }
    else
    {
      hal_send_str("OK KEYS\n");
    }
  }

  return 0;
}

static int test_invalid_sk_a(void)
{
  unsigned char sk_a[MUPQ_CRYPTO_SECRETKEYBYTES];
  unsigned char key_a[MUPQ_CRYPTO_BYTES], key_b[MUPQ_CRYPTO_BYTES];
  unsigned char pk[MUPQ_CRYPTO_PUBLICKEYBYTES];
  unsigned char sendb[MUPQ_CRYPTO_CIPHERTEXTBYTES];
  int i;

  for(i=0; i<NTESTS; i++)
  {
    //Alice generates a public key
    MUPQ_crypto_kem_keypair(pk, sk_a);

    //Bob derives a secret key and creates a response
    MUPQ_crypto_kem_enc(sendb, key_b, pk);

    //Replace secret key with random values
    randombytes(sk_a, MUPQ_CRYPTO_SECRETKEYBYTES);

    //Alice uses Bobs response to get her secre key
    MUPQ_crypto_kem_dec(key_a, sendb, sk_a);

    if(!memcmp(key_a, key_b, MUPQ_CRYPTO_BYTES))
    {
      hal_send_str("ERROR invalid sk_a\n");
    }
    else
    {
      hal_send_str("OK invalid sk_a\n");
    }
  }

  return 0;
}


static int test_invalid_ciphertext(void)
{
  unsigned char sk_a[MUPQ_CRYPTO_SECRETKEYBYTES];
  unsigned char key_a[MUPQ_CRYPTO_BYTES], key_b[MUPQ_CRYPTO_BYTES];
  unsigned char pk[MUPQ_CRYPTO_PUBLICKEYBYTES];
  unsigned char sendb[MUPQ_CRYPTO_CIPHERTEXTBYTES];
  int i;
  size_t pos;

  for(i=0; i<NTESTS; i++)
  {
    randombytes((unsigned char *)&pos, sizeof(size_t));

    //Alice generates a public key
    MUPQ_crypto_kem_keypair(pk, sk_a);

    //Bob derives a secret key and creates a response
    MUPQ_crypto_kem_enc(sendb, key_b, pk);

    // Change ciphertext to random value
    randombytes(sendb, sizeof(sendb));

    //Alice uses Bobs response to get her secret key
    MUPQ_crypto_kem_dec(key_a, sendb, sk_a);

    if(!memcmp(key_a, key_b, MUPQ_CRYPTO_BYTES))
    {
      hal_send_str("ERROR invalid ciphertext\n");
    }
    else
    {
      hal_send_str("OK invalid ciphertext\n");
    }
  }

  return 0;
}

int main(void)
{
  hal_setup(CLOCK_FAST);

  // marker for automated testing
  // hal_send_str("==========================");
  // test_keys();


  test_attack();





  // test_invalid_sk_a();
  // test_invalid_ciphertext();
  // hal_send_str("#");

  while(1);

  return 0;
}
