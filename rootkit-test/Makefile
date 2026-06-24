# Makefile for sentinel_test_rootkit
# Kali 6.18 / Ubuntu 24.04 6.8

obj-m += sentinel_test_rootkit.o

KDIR  ?= /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Load stages individually for testing
load:
	sudo insmod sentinel_test_rootkit.ko

stage1:
	sudo insmod sentinel_test_rootkit.ko stage=1

stage2:
	sudo insmod sentinel_test_rootkit.ko stage=2

stage3:
	sudo insmod sentinel_test_rootkit.ko stage=3

stage6:
	sudo insmod sentinel_test_rootkit.ko stage=6

stage7:
	sudo insmod sentinel_test_rootkit.ko stage=7

stage8:
	sudo insmod sentinel_test_rootkit.ko stage=8



unload:
	sudo rmmod sentinel_test_rootkit 2>/dev/null || echo "Already unloaded or hidden"

watch:
	sudo dmesg -w | grep -E "krt:|sentinelx:"

# Show last 50 lines of dmesg filtered to our modules
check:
	sudo dmesg | grep -E "krt:|sentinelx:" | tail -50

.PHONY: all clean load stage1 stage2 stage3 stage4 unload watch check
