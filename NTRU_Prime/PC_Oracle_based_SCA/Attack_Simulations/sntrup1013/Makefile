# kat_kem.rsp: kat
# 	./run
#

# kat: Makefile nist/kat_kem.c nist/rng.c nist/rng.h randombytes.h Decode.c Encode.c int32.c kem.c uint32.c     subroutines/crypto_hash_sha512.c subroutines/crypto_sort_uint32.c subroutines/crypto_stream_aes256ctr.c
# 	./build

test_ex: Makefile nist/test.c nist/rng.c nist/rng.h randombytes.h crypto_kem.h attack_parameters.h Decode.c Encode.c int32.c kem_mod.c uint32.c     subroutines/crypto_hash_sha512.c subroutines/crypto_sort_uint32.c subroutines/crypto_stream_aes256ctr.c
	gcc -O3 -march=native -std=c99 -mtune=native -Wall -I. -Isubroutines "-DCRYPTO_NAMESPACE(x)=x" -o test_ex nist/test.c nist/rng.c Decode.c Encode.c int32.c kem_mod.c uint32.c     subroutines/crypto_hash_sha512.c subroutines/crypto_sort_uint32.c subroutines/crypto_stream_aes256ctr.c  -lcrypto -ldl -lm

clean:
	rm -rf test_ex
