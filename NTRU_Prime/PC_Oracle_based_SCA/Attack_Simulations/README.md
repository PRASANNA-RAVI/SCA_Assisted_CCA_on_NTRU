# Attack_Simulations (NTRU Prime)

This directory contains attack simulation scripts written in C, to perform the PC oracle-based attack on all the parameters of Streamlined NTRU Prime.
The scripts are commented for better code readability. The main attack script is implemented in the test.c file in the directory "nist" of respective parameter set. You can check that script for implementation of the attack. You need OpenSSL to actually compile this script, as the implementation of NTRU utilizes OpenSSL library. You can add the OpenSSL directory your PATH, using the following commands:
```
export CPATH=${CPATH+$CPATH:}/usr/local/opt/openssl@1.1/include
export LIBRARY_PATH=${LIBRARY_PATH+$LIBRARY_PATH:}/usr/local/opt/openssl@1.1/lib
```

# Configuring the Script:

There are several parameters available to configure the attack script. Firstly, there are several parameters for the attack, which can be found in the `attack_parameters.h` file in the directory of the respective parameter sets. We have several additional options for debug purposes and running the attack. The parameters for running the attack can be set in the `attack_parameters.h` file.

* `DO_PRINT`: This option when turned on, prints the ciphertexts, keys, oracle responses onto the text file which will be useful while performing practical attacks. It generates five different files for a single attack iteration:

- `keypair_file.bin` - Contains public-private key pair
- `ct_file_basic.bin` - Contains the base ciphertext used for the attack which do not have a collision
- `ct_file_basic_failed.bin` - Contains the failed ciphertexts which have a single collision
- `valid_ct_file.bin` - Contains valid ciphertext
- `ct_file_basic.bin` - Contains the attack ciphertexts

These files are generated within the same directory after the run. We pre-generated files for a single attack iteration for `sntrup761` and stored in the `SCA/Data_Files` folder.

* `COLL_CHECK`: This option when turned on, runs the attack in a debug style mode, by printing out the progress of the attack. The attack does not utilize any additional information for key recovery when run in this mode, but it just puts out more information on the terminal for the user to see.

* `DO_ATTACK`: This option when turned off, only runs the pre-processing phase of the attack (i.e.) to identify the collision. This can be used to collect some statistics on the number of single collisions, multiple collisions, false positive and false negative collisions. This information is printed on the terminal.

* `NO_TESTS`: Denotes the number of attack iterations to be run.

These options can be turned on/off in the `attack_parameters.h` file in the folder of each parameter set.

# To Compile

First, you need to go to the directory of the target parameter set and run:
```
make
```

# To Run
```
./test_ex
```
