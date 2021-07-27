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

# from datetime import datetime as dt
# from subprocess import Popen, PIPE, STDOUT
# from subprocess import Popen, PIPE, STDOUT, TimeoutExpired
# from tempfile import TemporaryDirectory

data_count = 1
trial_count = 1000
pulse_width_initial = 0x0000003E0
favourable_r3_value = 0x50060000
read_registers = 0
ramdump = 1
size_of_mem_dump = 8192

ocd_args =  '-f ''interface/stlink-v2-1.cfg ''-f ''target/stm32wbx.cfg '
local_filename = 'RAM_Dump/memdump.bin'

def string_to_hex(input_string):
	char_list = list(input_string)
	num = 0
	for i in range(0,len(char_list)):
		num = ord(char_list[i]) | (num << (8))
	return num

def hex_to_string(input_hex,length):
	str = ""
	for i in range(0,length):
		# print type(input_hex)
		byte_focus = (input_hex >> (8*i)) & 0xFF
		character = chr(byte_focus)
		str = character + str
	return str

def reverse_string(input_string,length):
	str = ""
	char_list = list(input_string)
	for i in range(0,length):
		str = char_list[i] + str
	return str


def bitswap(input_text,length):
	for i in range(0,length):
		bit = (input_text >> i)&1
		if(i == 0):
			temp = bit
		else:
			temp = (temp << 1)|bit
	return temp

def only_bitswap(input_text,length):
	for i in range(0,length):
		temp = input_text >> (32*i) & 0xFFFFFFFF
		temp = bitswap(temp,32)
		if (i == 0):
			temp2 = temp
		else:
			temp2 = temp << (32*i) | temp2
	return temp2

def byteswap_within_word(input_text,length):
	for i in range(0,length):
		bite = (input_text >> (8*i))&0xFF
		if(i == 0):
			temp = bite
		else:
			temp = (temp << 8)|bite
	return temp

def only_byteswap(input_text,length):
	for i in range(0,length):
		temp = input_text >> (32*i) & 0xFFFFFFFF
		#print hex(temp)
		temp = byteswap_within_word(temp,4)
		#print hex(temp)
		if (i == 0):
			temp2 = temp
		else:
			temp2 = temp << (32*i) | temp2
		#print hex(temp2)
	return temp2

def convert_array_to_num(array,no_words):
    a = 0
    for i in range(0,no_words*4):
        a = a | (array[i] & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) << (120 - 8*i)
    return a

def get_one_word(string,seek_position_cur):
    with open(string, "r", encoding = "ISO-8859-1") as binary_file:
        binary_file.seek(seek_position_cur,0)
        word_string = binary_file.read(4)

    return (byteswap_within_word(string_to_hex(word_string),4))

def read_image(string,seek_position_cur,length):
    with open(string, "r", encoding = "ISO-8859-1") as binary_file:
        binary_file.seek(seek_position_cur,0)
        word_string = binary_file.read(length)

    return word_string

def dump_ram(todo_argument):
    """
    Start openocd and dump the RAM of the STM32 chip. When openocd
    times out, it is killed and an exception is raised.

    returns:
        filename        The filename containing the RAM dump.

    raises:
        TimeoutExpired  When openocd timeout out.
    """

    print('Starting openocd...')
    openocd_proc = subprocess.Popen(
        ['openocd'] + shlex.split(ocd_args),
        stdout=PIPE,
        stderr=STDOUT,
    )

    time.sleep(0.05)

    nc_proc = Popen(
        ['nc', 'localhost', '4444'],
        stdout=PIPE,
        stdin=PIPE,
        stderr=PIPE,
    )

    if(todo_argument == read_registers):

        nc_input = 'halt\nreg r2\nreg r3\nshutdown\n'
        nc_input = nc_input.encode('ascii')
        get_output = nc_proc.communicate(input=nc_input)
        get_output = str(get_output[0])
        # print(get_output)

        # Getting R2...
        r2_value = 0
        for rt in range(243,251):
            index = rt - 243
            if(ord(get_output[rt])-0x30 <= 9):
                num = ord(get_output[rt])-0x30
            else:
                num = ord(get_output[rt])-0x40+9

            r2_value = r2_value + (num << (28-4*index))

        r3_value = 0
        for rt in range(289,297):
            index = rt - 289
            if(ord(get_output[rt])-0x30 <= 9):
                num = ord(get_output[rt])-0x30
            else:
                num = ord(get_output[rt])-0x40+9

            r3_value = r3_value + (num << (28-4*index))

        try:
            openocd_proc.wait(timeout=5)
        except TimeoutExpired:
            print('Timeout! Killing openocd process "{}"'.format(openocd_proc.pid))
            openocd_proc.kill()
            raise

        return r3_value, r2_value

    elif(todo_argument == ramdump):

        filename = 'memdump.bin'

        st = 'RAM_Dump/'
        if not os.path.exists(st):
            os.makedirs(st)
            os.chdir(st)

        filename = os.path.join(st,filename)
        global global_filename
        global_filename = filename

        nc_input = ('sleep 1000\ndump_image {} 0x20000000 8192\n'
                    'shutdown\n').format(filename)

        nc_input = nc_input.encode('ascii')
        get_output = nc_proc.communicate(input=nc_input)
        get_output = str(get_output[0])
        # nc_proc.communicate(input=nc_input)

        try:
            openocd_proc.wait(timeout=5)
        except TimeoutExpired:
            print('Timeout! Killing openocd process "{}"'.format(openocd_proc.pid))
            openocd_proc.kill()
            raise

        return 0

def crc_calc(crc, data):
    crc = crc ^ data

    for i in range(0,32):
        if((crc & 0x80000000)>>31 == 0x1):
            crc = ((crc << 1)&0xFFFFFFFF)^0x04C11DB7
        else:
            crc = (crc << 1)&0xFFFFFFFF

    return crc


def send_init_commands(pulse_width):

    # # to toggle reset...
    #
    # ser.write(chr(0x5A)) #Z
    # ser.write(chr(0x0A))
    # time.sleep(0.01)
    # rcv_char = ser.read()
    # # print rcv_char

    ser.write(chr(0x73).encode('ascii')) #s
    ser.write(chr(0x0A).encode('ascii'))
    time.sleep(0.01)
    rcv_char = ser.read()
    # print rcv_char

    # time.sleep(0.1)

    ser.write(chr(0x72).encode('ascii')) #r
    ser.write(chr(0x0A).encode('ascii'))
    time.sleep(0.01)
    rcv_char = ser.read()
    # print rcv_char

    # time.sleep(0.1)

    ser.write(chr(0x54).encode('ascii')) #T
    time.sleep(0.01)
    # ser.write(chr(0x0A))
    # time.sleep(0.001)
    # rcv_char = ser.read()
    # print rcv_char
    for i in range(0,8): #pulse width setting...
        nibble = (pulse_width >> (4*(7-i)))&0xF;
        if(nibble <= 9):
            ser.write(chr(0x30+nibble).encode('ascii'))
            time.sleep(0.005)
        else:
            ser.write(chr(0x40+nibble-9).encode('ascii'))
            time.sleep(0.005)

    ser.write(chr(0x0A).encode('ascii'))
    time.sleep(0.01)
    rcv_char = ser.read()
    # print rcv_char

    # time.sleep(0.1)

    ser.write(chr(0x53).encode('ascii')) #S
    ser.write(chr(0x0A).encode('ascii'))
    time.sleep(0.01)
    rcv_char = ser.read()
    # print rcv_char

    # time.sleep(0.1)

    ser.write(chr(0x49).encode('ascii')) #I
    ser.write(chr(0x0A).encode('ascii'))
    time.sleep(0.01)
    rcv_char = ser.read()
    # print rcv_char

    # time.sleep(0.1)

    ser.write(chr(0x50).encode('ascii')) #P
    ser.write(chr(0x0A).encode('ascii'))
    time.sleep(0.01)
    rcv_char = ser.read()
    # print rcv_char

    # time.sleep(0.1)


    # data_array = [0]*2
    # # print "I am here....\n"
    #
    # for yu in range(0,2):
    #     print yu
    #     data_received_1 = 0
    #     for i in range(0,4):
    #         rcv_char = ord(ser.read())
    #         data_received_1 = (rcv_char<<8*(3-i))|data_received_1
    #     print hex(data_received_1)
    #     data_array[yu] = data_received_1
    #
    # PKA_CR_in = data_array[0]
    # PKA_SR_in = data_array[1]

    # return data_array;

if __name__ == "__main__":
    # crc_list = []
    # max_attempts = 1000

	# ser = serial.Serial(port='/dev/tty.usbserial-FTBNZ0TN',baudrate=115200,timeout=10)
	# data = 0xAB

	CRYPTO_SECRETKEYBYTES = 1763
	CRYPTO_PUBLICKEYBYTES = 1158
	CRYPTO_CIPHERTEXTBYTES = 1039
	CRYPTO_BYTES = 32
	P = 761

	# ser.write(chr(0x43))
	# rcv_char = ord(ser.read())
	# print rcv_char
	#
	# f = open("keypair_file_sntrup761.bin","r")
	#
	# for i in range(0,CRYPTO_PUBLICKEYBYTES):
	# 	nibble1 = ord(f.read(1))
	# 	nibble2 = ord(f.read(1))
	#
	# 	if(nibble1 >= 0x60):
	# 		nibble1 = nibble1 - 0x60 + 0xA - 1
	# 	else:
	# 		nibble1 = nibble1 - 0x30
	#
	# 	if(nibble2 >= 0x60):
	# 		nibble2 = nibble2 - 0x60 + 0xA - 1
	# 	else:
	# 		nibble2 = nibble2 - 0x30
	#
	# 	byte_value = (nibble1<<4)|nibble2
	#
	# 	ser.write(chr(byte_value))
	# 	# rcv_char = ord(ser.read())
	#
	#
	# for i in range(0,CRYPTO_SECRETKEYBYTES):
	# 	nibble1 = ord(f.read(1))
	# 	nibble2 = ord(f.read(1))
	#
	# 	if(nibble1 >= 0x60):
	# 		nibble1 = nibble1 - 0x60 + 0xA - 1
	# 	else:
	# 		nibble1 = nibble1 - 0x30
	#
	# 	if(nibble2 >= 0x60):
	# 		nibble2 = nibble2 - 0x60 + 0xA - 1
	# 	else:
	# 		nibble2 = nibble2 - 0x30
	#
	# 	byte_value = (nibble1<<4)|nibble2
	#
	# 	ser.write(chr(byte_value))
	# 	# rcv_char = ord(ser.read())
	#
	# f.close()
	#
	# f = open("ct_file_sntrup761.bin","r")

	f1 = open("oracle_resp_sntrup761.bin","r")

	oracle_response_array = np.array([0]*(4*P))
	for n_bytes in range(0,4*P):

		# ser.write(chr(0x5A))
		# rcv_char = ord(ser.read())
		#
		# for i in range(0,CRYPTO_CIPHERTEXTBYTES):
		#
		# 	nibble1 = ord(f.read(1))
		# 	nibble2 = ord(f.read(1))
		#
		# 	if(nibble1 >= 0x60):
		# 		nibble1 = nibble1 - 0x60 + 0xA - 1
		# 	else:
		# 		nibble1 = nibble1 - 0x30
		#
		# 	if(nibble2 >= 0x60):
		# 		nibble2 = nibble2 - 0x60 + 0xA - 1
		# 	else:
		# 		nibble2 = nibble2 - 0x30
		#
		# 	byte_value = (nibble1<<4)|nibble2
		#
		# 	ser.write(chr(byte_value))


		# rcv_char1 = ord(ser.read())
		# rcv_char2 = ord(ser.read())

		# weight = rcv_char1*256 + rcv_char2

		# if(weight == 0):
		# 	oracle_response_array[n_bytes] = 0
		# else:
		# 	oracle_response_array[n_bytes] = -1

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
			oracle_response_array[n_bytes] = 1
		else:
			oracle_response_array[n_bytes] = 0

	f1.close()
	# oracle_response_array = np.array(oracle_response_array)
	spio.savemat("oracle_response",{'oracle_response_array': oracle_response_array}, do_compression = True, oned_as='row')
	# f.close()































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
