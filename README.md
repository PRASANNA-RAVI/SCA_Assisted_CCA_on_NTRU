# Generic Side-Channel Assisted Chosen-Ciphertext Attacks on NTRU-based KEMs:

This project contains the implementation and attack scripts required to perform
generic side-channel assisted chosen-ciphertext attacks over NTRU-based KEMs. The particular schemes that have been targeted are:
NTRU (main finalist candidate) and NTRU Prime (alternate finalist candidate) of the NIST standardization process for post-quantum cryptography. The attack is based on the paper available in this [link](). The repository is split into two parts, one each for NTRU and NTRU Prime. For NTRU, we include code for Plaintext-Checking (PC) Oracle-based SCA and for NTRU-Prime, we include code for Plaintext-Checking (PC) Oracle-based SCA and Decryption-Failure (DF) Oracle-based SCA. The scripts for each attack is divided into three directories:

## Attack_Simulations

This directory contains scripts that perform attack simulations (implemented in C) of the respective attacks. We report attack on all parameter sets of the targeted scheme, NTRU and NTRU Prime.

## Implementation

This directory contains the implementations of the targeted scheme, which can be utilized for trace acquisition to perform side-channel attacks. The implementation is taken from the **pqm4** library , which can be run on the ARM Cortex-M4 microcontroller.
We have included a wrapper which can help carry out the entire attack. This can be integrated with your custom side-channel attack setup to carry out trace acquisition.

## SCA (Side-Channel Analysis)

This directory includes practical side-channel traces (taken from the EM side-channel from the ARM Cortex-M4 microcontroller) as well as attack scripts (written in MATLAB) to analyze the traces for key recovery.

## License
All code in this repository is released under the conditions of [CC0](http://creativecommons.org/publicdomain/zero/1.0/).
