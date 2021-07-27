make IMPLEMENTATION_PATH=crypto_kem/sntrup761/m4f bin/crypto_kem_sntrup761_m4f_test.bin
openocd -f interface/stlink-v2-1.cfg -f target/stm32f4x.cfg -c "program bin/crypto_kem_sntrup761_m4f_test.bin 0x08000000 verify reset exit"
