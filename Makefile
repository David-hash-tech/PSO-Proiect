CC=gcc
LOCAL_CFLAGS=-Wall -Werror

obj-m += kdsinsp.o

KVERSION = $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

load:
	sudo insmod kdsinsp.ko param='"11 44 22 33 5"'

unload:
	sudo rmmod kdsinsp

clear:
	sudo dmesg -c

view:
	sudo dmesg