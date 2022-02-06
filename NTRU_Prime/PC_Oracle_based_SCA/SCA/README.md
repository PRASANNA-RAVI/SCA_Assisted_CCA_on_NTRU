# Attack_scripts

This directory contains attack traces and scripts to carry out attack on NTRU. We have included practical EM side-channel traces captured from the STM32F407VG MCU running at 168 MHz. The target implementation is `sntrup761`. There are three directories:

* `Data_Files`: It contains the ciphertext files, key files and the oracle files for which the traces have been collected...
* `Pre_Processing_Phase`: It contains traces used in the pre-processing phase. `traces_0` corresponds to the zero ciphertext and the remaining trace sets corresponds to that of either a failed base ciphertext and a correct base ciphertext. The file corresponding to the highest number is the correct base ciphertext (single collision). Others are failed base ciphertexts (no collision).
* `Attack_Phase`: It contains traces corresponding to the attack ciphertexts. For each coefficient, we have four attack ciphertexts and thus four attack trace sets. The corresponding oracle responses are present in the `oracle_responses.mat` file.

# How to Run:

* `tvla_simple_only.m` - This is used to compute the t-test on the traces from the pre-processing phase.
* `attack_traces.m` - This is used to carry out the attack phase for key recovery.

# Comments to Run:

* MATLAB should be run from the SCA folder (folder can also be changed within MATLAB using cd command), because the paths used within the MATLAB file are referenced based on this.
