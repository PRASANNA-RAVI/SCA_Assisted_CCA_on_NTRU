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

	ser = serial.Serial(port='/dev/cu.usbserial-FTBNZ0TN',baudrate=115200,timeout=10)

	CRYPTO_SECRETKEYBYTES = 1234
	CRYPTO_PUBLICKEYBYTES = 930
	CRYPTO_CIPHERTEXTBYTES = 930
	P = 677

	main_path = "/Users/pace/Dropbox/NTU/Programs/Lattice_programs/My_codes/NTRU_work/SCACCAONNTRU/NTRU/PC_Oracle_based_SCA/SCA/Data_Files/"
	key_pair_file = main_path + "keypair_file.bin"
	ct_file_basic = main_path + "ct_file_basic.bin"
	ct_attack_file = main_path + "ct_file_attack.bin"

	# This file contains the correct oracle responses which will lead to recovery of secret key.. We check if the oracle response
	# received from device matches the oracle responses in this file...

	oracle_response_file = main_path + "oracle_resp.bin"

	# Sending Key Pair to device (Public, Private Key Pair to device)...

	print "Sending Key Pair to device..."

	ser.write(chr(0x43))
	rcv_char = ord(ser.read())
	print rcv_char

	f = open(key_pair_file)

	for i in range(0,CRYPTO_PUBLICKEYBYTES):
		print i
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
		print i
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

	f = open(ct_attack_file,"r")
	f1 = open(oracle_response_file,"r")
	f2 = open(ct_file_basic,"r")

	NUM_TRIALS = 100


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

		print i
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

		rcv_char1 = ord(ser.read())
		rcv_char2 = ord(ser.read())

		weight = rcv_char1*256 + rcv_char2
		print weight

		rcv_char = ord(ser.read())

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

	f1.close()
	f.close()
















































	# # Read from file and then push to serial port...
	#
	#
	#
	#
    # global TMPDIR
    # TMPDIR = TemporaryDirectory(prefix="crccrack-")
	#
    # ser = serial.Serial(port='/dev/tty.usbserial-FTBNZ0TN',baudrate=115200,timeout=10)
    # ser_relay = serial.Serial(port='/dev/tty.usbmodem141431',baudrate=9600,timeout=10)
	#
    # pulse_width_final = 0x00200000
	#
    # for uu in range(0,10):
    #     ser.reset_input_buffer()
	#
    # for uu in range(0,10):
    #     ser_relay.reset_input_buffer()
	#
    # for rt in range(0,5):
    #     ser_relay.write(chr(0x54).encode('ascii')) #T
    #     time.sleep(0.5)
	#
    # for trials in range(0,trial_count):
	#
    #     ser_relay.write(chr(0x54).encode('ascii')) #T
    #     time.sleep(0.15)
	#
    #     send_init_commands(pulse_width_initial)
    #     time.sleep(0.15)
	#
    #     ser.write(chr(0x46).encode('ascii')) #F
    #     ser.write(chr(0x0A).encode('ascii'))
    #     time.sleep(0.01)
	#
    #     data_array = [0]*data_count
	#
    #     ciphertext_array = [0x3ad77bb4,0x0d7a3660,0xa89ecaf3,0x2466ef97]
    #     plaintext_array = [0x6bc1bee2,0x2e409f96,0xe93d7e11,0x7393172a]
    #     key_array = [0x2B7E1516,0x28AED2A6,0xABF71588,0x09CF4F3C]
	#
    #     # print "Printing AES REGISTER Data..."
	#
    #     for yu in range(0,data_count):
    #         data_received_1 = 0
    #         for i in range(0,4):
    #             rcv_char = ord(ser.read())
    #             data_received_1 = (rcv_char<<8*(3-i))|data_received_1
    #         data_array[yu] = data_received_1
	#
    #         touch_flag = 0
	#
    #         for tr in range(0,4):
    #             if(data_received_1 == ciphertext_array[tr]):
    #                 print("Ciphertext")
    #                 touch_flag = 1
    #             elif(data_received_1 == plaintext_array[tr]):
    #                 print("Plaintext")
    #                 touch_flag = 1
    #             elif(data_received_1 == key_array[tr]):
    #                 print("Key")
    #                 touch_flag = 1
	#
    #         if(data_received_1 == 0x00000000):
    #             print("Zero")
    #             touch_flag = 1
	#
    #         if(touch_flag == 0):
    #             print("Random Data")
    #             print('0x%08x') % data_received_1
	#
    #     # Turn on relay to disconnect attack debugger from SWD...
	#
    #     ser_relay.write(chr(0x53).encode('ascii')) #S
    #     time.sleep(0.15)
	#
    #     arg_passed = read_registers
    #     r3_value, r2_value = dump_ram(arg_passed)
	#
    #     if(r3_value == favourable_r3_value):
    #         print("Success")
    #         print(hex(r2_value))
	#
    #         arg_passed = ramdump
    #         dump_ram(arg_passed)
	#
    #         print("Ram Dumped...")
	#
	# 		print("Searching for Matching Data in RAM...")
	# 	    no_of_seek_positions = int(size_of_mem_dump/4)
	#
	# 	    for seek_position_cur in range(0,no_of_seek_positions):
	# 	        got_word = get_one_word(local_filename,4*seek_position_cur)
	# 			if(got_word == r2_value):
	# 				print "Found Data in RAM..."
	# 				print "Searching Around Locality for Random Data that can be AES Key..."
    #         sys.exit()
    #     else:
    #         print("Failure")
