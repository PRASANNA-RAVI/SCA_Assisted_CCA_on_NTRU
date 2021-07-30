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

	ser = serial.Serial(port='/dev/tty.usbserial-FTBNZ0TN',baudrate=115200,timeout=10)

	CRYPTO_SECRETKEYBYTES = 1763
	CRYPTO_PUBLICKEYBYTES = 1158
	CRYPTO_CIPHERTEXTBYTES = 1039
	CRYPTO_BYTES = 32
	P = 761

	# Sending Key Pair to device (Public, Private Key Pair to device)...

	ser.write(chr(0x43))
	rcv_char = ord(ser.read())
	print rcv_char

	main_path = "/Users/pace/Dropbox/NTU/Programs/Lattice_programs/My_codes/NTRU_work/SCACCAONNTRU/NTRU_Prime/DF_Oracle_based_SCA/SCA/Data_Files/"

	key_pair_file = main_path + "keypair_file.bin"

	print "Sending Key Pair to device..."

	f = open(key_pair_file,"r")

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

	# Sending Valid Ciphertext to device ...

	send_byte_value = 0x4F
	ser.write(chr(send_byte_value))
	rcv_char = ord(ser.read())
	print rcv_char

	valid_ct_file = main_path + "valid_ct_file.bin"

	f = open(valid_ct_file,"r")
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

	f.close()

	# Sending Valid Ciphertext to device ...
	print "Querying the decapsulation device with valid ciphertext 200 times..."

	rep_count = 200
	for j in range(0,rep_count):
		send_byte_value = 0x58
		ser.write(chr(send_byte_value))

		mask = ord(ser.read())
		print mask

	# Sending Base Ciphertext to device ...

	send_byte_value = 0x42
	ser.write(chr(send_byte_value))
	rcv_char = ord(ser.read())

	ct_file_basic = main_path + "ct_file_basic.bin"

	f = open(ct_file_basic,"r")
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

	f.close()

	print "Querying the decapsulation device with invalid ciphertext (valid ciphertext + base ciphertext) ciphertext 200 times..."


	rep_count = 200
	for j in range(0,rep_count):
		send_byte_value = 0x58
		ser.write(chr(send_byte_value))

		mask = ord(ser.read())
		print mask

	# Take t-test, get leakage points, then try to classify the attack traces...

	# Sending Attack Ciphertexts to device ...

	ct_attack_file = main_path + "ct_file_attack.bin"

	f = open(ct_attack_file,"r")

	# This file contains the correct oracle responses which will lead to recovery of secret key.. We check if the oracle response
	# received from device matches the oracle responses in this file...

	oracle_response_file = main_path + "oracle_resp_sntrup761.bin"

	f1 = open(oracle_response_file,"r")

	oracle_response_array = [0]*(4*P)

	print ("Starting Attack Phase...")

	for n_bytes in range(0,4*P):

		ser.write(chr(0x41))
		rcv_char = ord(ser.read())

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

		ser.write(chr(0x5A))
		mask = ord(ser.read())

		print mask

		if(mask == 0):
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

	f1.close()
	f.close()
