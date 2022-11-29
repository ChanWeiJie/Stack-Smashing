.PHONY: all clean

all: rop

rop: rop.c
	gcc rop.c -o rop -g -fno-stack-protector -no-pie

clean:
	rm rop

