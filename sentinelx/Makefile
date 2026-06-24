# Makefile for sentinelx
# Tested on Kali 6.18 / Ubuntu 24.04 6.8

obj-m += sentinelx.o

KDIR  ?= /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)

# Suppress frame-size warning (build_watchlist uses large local buffers by design)
ccflags-y += -Wno-frame-larger-than

all: key
	$(MAKE) -C $(KDIR) M=$(PWD) modules

key:
	@if [ ! -f sentinelx_key.h ]; then \
		KEY=$$(cat /dev/urandom | tr -dc 'a-f0-9' | head -c 32); \
		echo "#define UNLOCK_KEY \"$$KEY\"" > sentinelx_key.h; \
		echo ""; \
		echo "╔══════════════════════════════════════╗"; \
		echo "║  UNLOCK KEY GENERATED — WRITE DOWN  ║"; \
		echo "║  $$KEY  ║"; \
		echo "╚══════════════════════════════════════╝"; \
		echo ""; \
	else \
		echo "[sentinelx] sentinelx_key.h already exists, skipping key generation"; \
	fi

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load:
	sudo insmod sentinelx.ko anti_unload=0

load-protected:
	sudo insmod sentinelx.ko

unload:
	sudo rmmod sentinelx 2>/dev/null || true

watch:
	sudo dmesg -w | grep --line-buffered "sentinelx:"

status:
	@if [ -e /proc/.ksctl ]; then \
		echo "sentinelx: LOADED and HIDDEN (protected)"; \
	elif lsmod | grep -q sentinelx; then \
		echo "sentinelx: LOADED and VISIBLE"; \
	else \
		echo "sentinelx: NOT LOADED"; \
	fi

.PHONY: all key clean load load-protected unload watch status
