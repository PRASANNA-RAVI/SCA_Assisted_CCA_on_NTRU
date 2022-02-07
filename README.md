# Generic Side-Channel Assisted Chosen-Ciphertext Attacks on NTRU-based KEMs:

This project contains the implementation and attack scripts required to perform
generic side-channel assisted chosen-ciphertext attacks over NTRU-based KEMs. The particular schemes that have been targeted are:
NTRU (main finalist candidate) and NTRU Prime (alternate finalist candidate) of the NIST standardization process for post-quantum cryptography. The repository is split into two parts, one each for NTRU and NTRU Prime. For NTRU, we include code for Plaintext-Checking (PC) Oracle-based SCA and for NTRU-Prime, we include code for Plaintext-Checking (PC) Oracle-based SCA and Decryption-Failure (DF) Oracle-based SCA. The scripts for each attack is divided into three directories:

## Attack_Simulations

This directory contains scripts that perform attack simulations (implemented in C) of the respective attacks. We report attack on all parameter sets of the targeted scheme, NTRU and NTRU Prime.

## Implementation

This directory contains the implementations of the targeted scheme, which can be utilized for trace acquisition to perform side-channel attacks. The implementation is taken from the **pqm4** library , which can be run on the ARM Cortex-M4 microcontroller.
We have included a wrapper which can help carry out the entire attack. This can be integrated with your custom side-channel attack setup to carry out trace acquisition.

## SCA (Side-Channel Analysis)

This directory includes practical side-channel traces (taken from the EM side-channel from the ARM Cortex-M4 microcontroller) as well as attack scripts (written in MATLAB) to analyze the traces for key recovery.

## Availability of Software:

For scrutiny and reproducibility, we have made our implementation softwares available  at \url{https://github.com/PRASANNA-RAVI/SCA_Assisted_CCA_on_NTRU}.

## Hardware and Software Required for Experiments:

  * `Operating system` version : MacBook Pro with 2.3 GHz Intel Core i5 processor running MacOS High Sierra (10.13.6).
  * `x86_64 GCC Compiler` version: Apple LLVM version 10.0.0 (clang-1000.10.44.4)
  * `ARM GCC Compiler` (arm-none-eabi-gcc) version: (GNU Tools for Arm Embedded Processors 7-2018-q2-update) 7.3.1 20180622 (release) [ARM/embedded-7-branch revision 261907]
  * `OpenSSL` version: LibreSSL 2.2.7 (OpenSSL 1.1.1 required for running attack simulations)
  * `Matlab` version: R2020a
  * `Python` version: 2.7.10
  * `Python packages` used: copy, gc, time, serial, random, struct, shlex, numpy, scipy.io, os, copy, sys, subprocess, datetime
  * `OpenOCD` tool: To flash the binary onto the STM32F407VG microcontroller on the STM32F4 Discovery board.
  * `pqm4` commit version: 6841a6bc3cc5bc0b0e01e5ee33567882e9bca8d3

## License
All code in this repository is released under the conditions of [CC0](http://creativecommons.org/publicdomain/zero/1.0/).
