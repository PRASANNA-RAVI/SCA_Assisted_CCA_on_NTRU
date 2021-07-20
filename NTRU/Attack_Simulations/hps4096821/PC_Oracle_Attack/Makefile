NTRU_NAMESPACE ?= ntru_

CC ?= /usr/bin/cc
CFLAGS = -O3 -fomit-frame-pointer -march=native -fPIC -fPIE -pie -g
CFLAGS += -Wall -Wextra -Wpedantic
CFLAGS += -DCRYPTO_NAMESPACE\(s\)=${NTRU_NAMESPACE}\#\#s

SRC = cmov.c \
      crypto_sort_int32.c \
      fips202.c \
      kem.c \
      owcpa.c \
      pack3.c \
      packq.c \
      poly.c \
      poly_lift.c \
      poly_mod.c \
      poly_r2_inv.c \
      poly_rq_mul.c \
      poly_s3_inv.c \
      sample.c \
      sample_iid.c

HDR = cmov.h \
      crypto_hash_sha3256.h \
      crypto_sort_int32.h \
      kem.h \
      owcpa.h \
      params.h \
      poly.h \
      sample.h

SRC_URAND = $(SRC) randombytes.c
HDR_URAND = $(HDR) randombytes.h

SRC_KAT = $(SRC) rng.c PQCgenKAT_kem.c
HDR_KAT = $(HDR) rng.h api.h

all: test/test_ntru

test/test_ntru: $(SRC_URAND) $(HDR_URAND) test/test_ntru.c
	$(CC) $(CFLAGS) -o $@ $(SRC_URAND) test/test_ntru.c

.PHONY: clean test

test: all
	./test/test_ntru

clean:
	-$(RM) *.o
	-$(RM) -r test/test_ntru
