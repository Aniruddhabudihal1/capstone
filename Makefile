# Makefile for npm-ebpf-monitor
# eBPF-based network packet monitoring tool

BINARY_NAME := npm-ebpf-monitor
BINARY_PATH := ./$(BINARY_NAME)
CMD_DIR := ./cmd/monitor
BPF_DIR := ./bpf
OUTPUT_DIR := ./output

# Go settings for cross-compilation and eBPF builds
GO := go
CLANG := clang-14
LLVM_STRIP := llvm-strip-14
VMLINUX_BTF := /sys/kernel/btf/vmlinux

.PHONY: generate build run clean help

# ---------------------------------------------------------------
# generate: Compile eBPF C programs to bytecode and generate
# Go bindings using bpf2go. Must be run before build.
# ---------------------------------------------------------------
generate:
@echo ">>> Generating eBPF bytecode and Go bindings..."
$(GO) generate ./...

# ---------------------------------------------------------------
# build: Compile the Go binary with embedded eBPF bytecode.
# ---------------------------------------------------------------
build: generate
@echo ">>> Building $(BINARY_NAME)..."
$(GO) build -o $(BINARY_PATH) $(CMD_DIR)
@echo ">>> Build complete: $(BINARY_PATH)"

# ---------------------------------------------------------------
# run: Execute the compiled binary with root privileges.
# Requires sudo; prompts for password if needed.
# ---------------------------------------------------------------
run: build
@echo ">>> Running $(BINARY_NAME) (requires sudo)..."
sudo $(BINARY_PATH)

# ---------------------------------------------------------------
# clean: Remove build artifacts and generated files.
# ---------------------------------------------------------------
clean:
@echo ">>> Cleaning build artifacts..."
rm -f $(BINARY_PATH)
rm -f $(BPF_DIR)/*.o
rm -f $(BPF_DIR)/*_bpf*.go
$(GO) clean
@echo ">>> Clean complete"

# ---------------------------------------------------------------
# help: Display build targets and their descriptions.
# ---------------------------------------------------------------
help:
@echo "npm-ebpf-monitor - eBPF Network Packet Monitor"
@echo ""
@echo "Available targets:"
@echo "  make generate  - Compile eBPF programs and generate Go code"
@echo "  make build     - Build the binary (includes generate)"
@echo "  make run       - Build and run with sudo"
@echo "  make clean     - Remove all build artifacts"
@echo "  make help      - Display this help message"
