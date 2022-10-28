CC=gcc
LOCAL_CFLAGS=-Wall -Werror

obj-m += kdsinsp.o

all: kdsinsp.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

load:
	sudo insmod kdsinsp.ko

unload:
	sudo rmmod kdsinsp

clear:
	sudo dmesg -c

view:
	sudo dmesg
