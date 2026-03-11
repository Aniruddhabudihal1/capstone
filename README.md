# npm-ebpf-monitor

eBPF-based Network Packet Monitoring tool for Linux.

## Overview

`npm-ebpf-monitor` is a real-time network packet monitor that uses eBPF (extended Berkeley Packet Filter) to trace system calls and network events at kernel level with minimal overhead.

## Features (Planned)

- **Syscall Tracing** — Monitor process-level system calls
- **Process Tracking** — Track process creation and termination
- **File Monitoring** — Monitor file I/O operations
- **TCP Monitoring** — Track TCP connection state changes

## Project Structure

```
npm-ebpf-monitor/
├── cmd/monitor/          # Entry point
├── internal/
│   ├── collector/        # eBPF map readers
│   ├── session/          # Session tracking
│   ├── features/         # Feature aggregation
│   └── output/           # Output writers
├── bpf/                  # eBPF C programs
│   ├── syscall_tracer.bpf.c
│   ├── process_tracer.bpf.c
│   ├── file_monitor.bpf.c
│   └── tcp_monitor.bpf.c
└── Makefile
```

## Requirements

- Linux 5.8+ with BPF support
- clang-14 & llvm-14
- Go 1.21+
- libbpf-dev

## Build

```bash
make build
```

## Run

```bash
sudo make run
```

## License

Dual BSD/GPL
