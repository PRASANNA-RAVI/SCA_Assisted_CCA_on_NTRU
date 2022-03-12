# Attack_Simulations (NTRU Prime)

This directory contains attack simulation scripts written in C, to perform the DF oracle-based attack on all the parameters of Streamlined NTRU Prime.
The scripts are commented for better code readability. The main attack script is implemented in the test.c file in the directory "nist" of respective parameter set. You can check that script for implementation of the attack. You need OpenSSL to actually compile this script, as the implementation of NTRU utilizes OpenSSL library.

If OpenSSL is not available, it can be installed using the following instructions. The OpenSSL library (1.1.1, or later) must be installed. Use `sudo apt-get install libssl-dev` for most Linux distributions.
On a Mac, an easy way is to use [brew](https://brew.sh), install it with `brew install openssl@1.1` and then add it to the
`CPATH` and `LIBRARY_PATH` environment variables:
  ```
  export CPATH=${CPATH+$CPATH:}/usr/local/opt/openssl@1.1/include
  export LIBRARY_PATH=${LIBRARY_PATH+$LIBRARY_PATH:}/usr/local/opt/openssl@1.1/lib
  ```

Please refer https://itectec.com/ubuntu/ubuntu-how-to-install-openssl-1-1-1-and-libssl-package/ for installation of OpenSSL 1.1.1 for Ubuntu. Please refer https://stackoverflow.com/questions/56639315/updating-openssl-to-1-1-1-on-macos for installation of OpenSSL 1.1.1 for MacOS.

# Configuring the Script:

There are several parameters available to configure the attack script. Firstly, there are several parameters for the attack, which can be found in the `attack_parameters.h` file in the directory of the respective parameter sets. We have several additional options for debug purposes and running the attack. The parameters for running the attack can be set in the `attack_parameters.h` file.

* `DO_PRINT`: This option when turned on, prints the ciphertexts, keys, oracle responses onto the text file which will be useful while performing practical attacks. It generates five different files for a single attack iteration:

- `keypair_file.bin` - Contains public-private key pair
- `ct_file_basic.bin` - Contains the base ciphertext used for the attack which induce decryption failure
- `ct_file_basic_failed.bin` - Contains the failed ciphertexts which do not induce decryption failure
- `valid_ct_file.bin` - Contains valid ciphertext
- `ct_file_basic.bin` - Contains the attack ciphertexts

These files are generated within the same directory after the run. We pre-generated files for a single attack iteration for `sntrup761` and stored in the `SCA/Data_Files` folder.

* `COLL_CHECK`: This option when turned on, runs the attack in a debug style mode, by printing out the progress of the attack. The attack does not utilize any additional information for key recovery when run in this mode, but it just puts out more information on the terminal for the user to see.

* `DO_ATTACK`: This option when turned off, only runs the pre-processing phase of the attack (i.e.) to identify the collision. This can be used to collect some statistics on the number of single collisions, multiple collisions, false positive and false negative collisions. This information is printed on the terminal.

* `NO_TESTS`: Denotes the number of attack iterations to be run.

These options can be turned on/off in the `attack_parameters.h` file in the folder of each parameter set.

# To Compile

You need to go to the directory of the target parameter set:

* To clean the directory:
```
make clean
```

* To compile:
```
make
```

* Our attack simulations might run into segmentation faults due to want of more space. We would suggest to use the ulimit option available on Unix based machines to increase the available memory to run the attack simulation scripts. Please refer https://www.ibm.com/docs/en/cdfsp/7.6.1.1?topic=begin-setting-ulimit for more information. Please also refer https://wilsonmar.github.io/maximum-limits/ for setting ulimit on MacOS.

# To Run
```
./test_ex
```
