#!/usr/bin/python

import copy
import gc
import time
import serial
import random
import struct
import shlex
import numpy as np
import scipy.io as spio
import os
import copy
import sys
import subprocess
import datetime

if __name__ == "__main__":

	ser = serial.Serial(port='/dev/tty.usbserial-FTBNZ0TN',baudrate=115200,timeout=None)

	CRYPTO_SECRETKEYBYTES = 1763
	CRYPTO_PUBLICKEYBYTES = 1158
	CRYPTO_CIPHERTEXTBYTES = 1039
	CRYPTO_BYTES = 32
	P = 761

	ser.write(chr(0x43))
	rcv_char = ord(ser.read())
	print rcv_char

	# main_path = "/Users/pace/Dropbox/Key_Trial_1/"
	# key_pair_file = main_path + "keypair_file_sntrup761.bin"
	# ct_file_basic = main_path + "ct_file_basic_sntrup761.bin"
	# ct_attack_file = main_path + "ct_file_sntrup761.bin"
	# oracle_response_file = main_path + "oracle_resp_sntrup761.bin"

	main_path = "/Users/pace/Dropbox/NTU/Programs/Lattice_programs/My_codes/NTRU_work/SCACCAONNTRU/NTRU_Prime/PC_Oracle_based_SCA/SCA/Data_Files/"
	key_pair_file = main_path + "keypair_file.bin"
	ct_file_basic = main_path + "ct_file_basic.bin"
	ct_attack_file = main_path + "ct_file_attack.bin"

	# This file contains the correct oracle responses which will lead to recovery of secret key.. We check if the oracle response
	# received from device matches the oracle responses in this file...
	oracle_response_file = main_path + "oracle_resp_sntrup761.bin"

	# Sending Key Pair to device (Public, Private Key Pair to device)...

	f = open(key_pair_file,"r")

	print "Sending Key Pair to device..."

	for i in range(0,CRYPTO_PUBLICKEYBYTES):
		nibble1 = ord(f.read(1))
		nibble2 = ord(f.read(1))

		if(nibble1 >= 0x60):
			nibble1 = nibble1 - 0x60 + 0xA - 1
		else:
			nibble1 = nibble1 - 0x30

		if(nibble2 >= 0x60):
			nibble2 = nibble2 - 0x60 + 0xA - 1
		else:
			nibble2 = nibble2 - 0x30

		byte_value = (nibble1<<4)|nibble2

		ser.write(chr(byte_value))


	for i in range(0,CRYPTO_SECRETKEYBYTES):
		nibble1 = ord(f.read(1))
		nibble2 = ord(f.read(1))

		if(nibble1 >= 0x60):
			nibble1 = nibble1 - 0x60 + 0xA - 1
		else:
			nibble1 = nibble1 - 0x30

		if(nibble2 >= 0x60):
			nibble2 = nibble2 - 0x60 + 0xA - 1
		else:
			nibble2 = nibble2 - 0x30

		byte_value = (nibble1<<4)|nibble2

		ser.write(chr(byte_value))

	f.close()

	f2 = open(ct_file_basic,"r")

	f = open(ct_attack_file,"r")

	f1 = open(oracle_response_file,"r")

	NUM_TRIALS = 200

	ct_zero = [0]*(2*P)
	ct_zero_poly = [0]*(2*P)
	ct_coll_poly = [0]*(2*P)

	# Asking device to decrypt zero ciphertext... zero ciphertext is generated internally within the target device by an encapsulation procedure...

	print "Querying the decapsulation device with zero ciphertext 200 times..."

	for i in range(0,NUM_TRIALS):
		ser.write(chr(0x4F))

		rcv_char1 = ord(ser.read())
		rcv_char2 = ord(ser.read())

		weight = rcv_char1*256 + rcv_char2
		print weight

		rcv_char = ord(ser.read())


	# Sending Base Ciphertext to device ...

	ser.write(chr(0x42))
	rcv_char = ord(ser.read())

	for i in range(0,CRYPTO_CIPHERTEXTBYTES):

		nibble1 = ord(f2.read(1))
		nibble2 = ord(f2.read(1))

		if(nibble1 >= 0x60):
			nibble1 = nibble1 - 0x60 + 0xA - 1
		else:
			nibble1 = nibble1 - 0x30

		if(nibble2 >= 0x60):
			nibble2 = nibble2 - 0x60 + 0xA - 1
		else:
			nibble2 = nibble2 - 0x30

		byte_value = (nibble1<<4)|nibble2

		ser.write(chr(byte_value))


	print "Querying the decapsulation device with invalid base ciphertext 200 times..."

	for i in range(0,NUM_TRIALS):
		ser.write(chr(0x58))

		rcv_char1 = ord(ser.read())
		rcv_char2 = ord(ser.read())

		weight = rcv_char1*256 + rcv_char2
		print weight

		rcv_char = ord(ser.read())

	# Take t-test, get leakage points, then try to classify the attack traces...

	# Sending Attack Ciphertexts to device ...


	print ("Starting Attack Phase...")


	oracle_response_array = [0]*(4*P)

	for n_bytes in range(0,4*P):

		ser.write(chr(0x42))
		rcv_char = ord(ser.read())
		print hex(rcv_char)

		for i in range(0,CRYPTO_CIPHERTEXTBYTES):

			nibble1 = ord(f.read(1))
			nibble2 = ord(f.read(1))

			if(nibble1 >= 0x60):
				nibble1 = nibble1 - 0x60 + 0xA - 1
			else:
				nibble1 = nibble1 - 0x30

			if(nibble2 >= 0x60):
				nibble2 = nibble2 - 0x60 + 0xA - 1
			else:
				nibble2 = nibble2 - 0x30

			byte_value = (nibble1<<4)|nibble2

			ser.write(chr(byte_value))


		ser.write(chr(0x58))

		rcv_char1 = ord(ser.read())
		rcv_char2 = ord(ser.read())

		weight = rcv_char1*256 + rcv_char2
		print hex(weight)

		if(weight == 0):
			oracle_response_array[n_bytes] = 0
		else:
			oracle_response_array[n_bytes] = -1

		nibble1 = ord(f1.read(1))
		nibble2 = ord(f1.read(1))

		if(nibble1 >= 0x60):
			nibble1 = nibble1 - 0x60 + 0xA - 1
		else:
			nibble1 = nibble1 - 0x30

		if(nibble2 >= 0x60):
			nibble2 = nibble2 - 0x60 + 0xA - 1
		else:
			nibble2 = nibble2 - 0x30

		byte_value = (nibble1<<4)|nibble2

		if(byte_value == 0xFF):
			c_value = -1
		else:
			c_value = 0

		if(c_value == oracle_response_array[n_bytes]):
			print "Success..."
		else:
			print "Failure..."


		rcv_char_z = ord(ser.read())



	f1.close()
	f.close()
