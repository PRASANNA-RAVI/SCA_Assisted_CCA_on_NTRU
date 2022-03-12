# Implementation_scripts:

This directory contains the implementation scripts for running the target implementation of NTRU Prime on the STM32F407VG microcontroller to obtain side-channel traces. This setup can be directly used with your side-channel setup for trace acquisition and subsequently performing key recovery. The implementation runs on the STM32F407VG microcontroller based on the ARM Cortex-M4 microcontroller and the flow follows that of the **pqm4** library.

# Compilation Commands:

- `sh script.sh` : This script is present inside the pqm4 folder which compiles the `sntrup761` parameter set for the STM32F407VG microcontroller. It uses the `ARM GCC` compiler toolchain and uses `openocd` to flash the binary onto the target STM32F4 microcontroller. The respective binaries are present in the `pqm4/bin` folder.

## Attack Setup:

We have included a small python script `test_attack.py` (uses Python2) which can be used to carry out, both the pre-processing phase as well as the attack phase. It utilizes the key files, ciphertext files and oracle files in the `SCA/Data_Files` directory. The target implementation outputs the weight of the anchor variable as the oracle response and the python attack script uses the oracle response to retrieve the secret key.

## Comments to Run:

User should change the serial port within the python script in Line 20 of `test_attack.py`.

## Run Command:

- `python test_attack.py`
