# Chosen Ciphertext Attack on Streamlined NTRU Prime:

This contains a chosen ciphertext attack on Streamlined NTRU Prime (parameter set: sntrup761).
h is the public key, while g and f form the secret key. The attack works as follows:

We construct ciphertexts of the form:
```
C = K . (x^i + x^j . h)
```
K is a constant and the value of K is pre-computed. We query the decryption device with C and observe the coefficients of e.
We try different values for i and j such that we want to find a case when exactly a single coefficient of e is -1. So, this requires
us to distinguish between HW(-1) = 8 or HW(0) = 0.

Once, we identify a -1 at the k^{th} coefficient of e, then we construct new chosen ciphertexts of the form
```
C' = K' . (x^i + x^j . h) + x^t
```
We query the decryption device with C' and identify whether the k^{th} coefficient of e is -1 or not (HW = 8 or HW = 0). This information can be used to build a distinguisher for different values of the secret coefficients of f and the complete secret
polynomial f can be recovered by simply changing the value of t.

# Compile Instructions:

The OpenSSL library (1.1.1, or later) must be installed. Use `sudo apt-get install libssl-dev` for most Linux distributions.
On a Mac, an easy way is to use [brew](https://brew.sh), install it with `brew install openssl@1.1` and then add it to the
`CPATH` and `LIBRARY_PATH` environment variables:
  ```
  export CPATH=${CPATH+$CPATH:}/usr/local/opt/openssl@1.1/include
  export LIBRARY_PATH=${LIBRARY_PATH+$LIBRARY_PATH:}/usr/local/opt/openssl@1.1/lib
  ```

```
make
```

# Run Instructions:

```
./test_ex
```

This run will basically run the attack for NO_TESTS number of times (NO_TESTS is set in crypto_kem.h file) and in each time, we
generate a valid public-private key pair and try to recover it. In each trial, we query the decapsulation device with our chosen ciphertexts and based on information about the component e in decryption (line 829 in kem_mod.c), we recover the secret key.

# Implementation Details:

The main attack is implemented in nist/test.c. The number of trialso
