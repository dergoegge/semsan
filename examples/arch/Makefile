CROSS_CC ?= aarch64-linux-gnu-gcc

all:
	$(CROSS_CC) -DQEMU -O0 -o arch-arm64 fuzz.c
	afl-clang-fast -fsanitize=fuzzer -O0 -o arch-host fuzz.c
