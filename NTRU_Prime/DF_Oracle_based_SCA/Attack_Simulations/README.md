# Attack_Simulations (NTRU Prime)

This directory contains attack simulation scripts written in C, to perform the DF oracle-based attack on all the parameters of Streamlined NTRU Prime.
The scripts are commented for better code readability. The main attack script is implemented in the test.c file in the directory "nist" of respective parameter set. You can check that script for implementation of the attack. You need OpenSSL to actually compile this script, as the implementation of NTRU utilizes OpenSSL library. You can add the OpenSSL directory your PATH, using the following commands:
```
export CPATH=${CPATH+$CPATH:}/usr/local/opt/openssl@1.1/include
export LIBRARY_PATH=${LIBRARY_PATH+$LIBRARY_PATH:}/usr/local/opt/openssl@1.1/lib
```

# To Compile

First, you need to go to the directory of the parameter set and run:
```
make
```

# To Run
```
./test_ex
```
