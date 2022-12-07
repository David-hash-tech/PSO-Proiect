CC=gcc
LOCAL_CFLAGS=-Wall -Werror

obj-m += kds.o

KVERSION = $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

load:
	sudo insmod kds.ko

unload:
	sudo rmmod kds

clear:
	sudo dmesg -c

view:
	sudo dmesg

