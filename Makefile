# Makefile for npm-ebpf-monitor
# eBPF-based network packet monitoring tool

BINARY_NAME := npm-ebpf-monitor
BINARY_PATH := ./$(BINARY_NAME)
CMD_DIR := ./cmd/monitor
BPF_DIR := ./bpf

GO := go
CLANG := clang-14
LLVM_STRIP := llvm-strip-14
VMLINUX_BTF := /sys/kernel/btf/vmlinux

.PHONY: generate build run run-only clean help

generate:
	@echo ">>> Generating eBPF bytecode and Go bindings..."
	$(GO) generate ./...

build: generate
	@echo ">>> Building $(BINARY_NAME)..."
	$(GO) build -o $(BINARY_PATH) $(CMD_DIR)
	@echo ">>> Build complete: $(BINARY_PATH)"

run: build
	@echo ">>> Running $(BINARY_NAME) (requires sudo)..."
	@echo ">>> Please enter your sudo password below (it will be cached for this session):"
	sudo -v
	sudo $(BINARY_PATH)

run-only:
	@echo ">>> Running pre-built $(BINARY_NAME) (requires sudo)..."
	@echo ">>> Please enter your sudo password below:"
	sudo -v
	sudo $(BINARY_PATH)

clean:
	@echo ">>> Cleaning build artifacts..."
	rm -f $(BINARY_PATH)
	rm -f $(BPF_DIR)/*.o
	rm -f $(BPF_DIR)/*_bpf*.go
	$(GO) clean
	@echo ">>> Clean complete"

help:
	@echo "npm-ebpf-monitor - eBPF Network Packet Monitor"
	@echo ""
	@echo "Available targets:"
	@echo "  make generate  - Compile eBPF programs and generate Go code"
	@echo "  make build     - Build the binary (includes generate)"
	@echo "  make run       - Build and run with sudo (prompts for password first)"
	@echo "  make run-only  - Run pre-built binary with sudo (skip rebuild)"
	@echo "  make clean     - Remove all build artifacts"
	@echo "  make help      - Display this help message"
