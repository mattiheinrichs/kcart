CLANG ?= clang
ARCH := $(shell uname -m)
BPF_CFLAGS := -O2 -g -target bpf -Wall -Werror -I bpf
ifneq ($(wildcard /usr/include/$(ARCH)-linux-gnu),)
BPF_CFLAGS += -I/usr/include/$(ARCH)-linux-gnu
endif

.PHONY: all bpf test-bpf bench-bpf build release test clean

all: release

build/kcart.bpf.o: bpf/kcart.bpf.c bpf/kcart.h
	@mkdir -p build
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

bpf: build/kcart.bpf.o

# Needs root, bpftool and a mounted bpffs; drives the program with BPF_PROG_TEST_RUN.
test-bpf: build/kcart.bpf.o
	python3 tests/prog_run.py $<

bench-bpf: build/kcart.bpf.o
	python3 tests/prog_run.py $< --bench

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

clean:
	rm -rf build
	cargo clean
