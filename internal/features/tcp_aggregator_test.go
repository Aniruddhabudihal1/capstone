package features

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestTCPAggregator_AddAndCounts(t *testing.T) {
	agg := NewTCPAggregator()

	events := []TCPEvent{
		{
			Saddr:    ipToKernelEventUint32(t, "10.0.0.5"),
			Daddr:    ipToKernelEventUint32(t, "104.16.25.35"),
			Sport:    51111,
			Dport:    443,
			OldState: 2,
			NewState: 1,
		},
		{
			Saddr:    ipToKernelEventUint32(t, "10.0.0.5"),
			Daddr:    ipToKernelEventUint32(t, "104.16.25.35"),
			Sport:    51111,
			Dport:    443,
			OldState: 1,
			NewState: 8,
		},
		{
			Saddr:    ipToKernelEventUint32(t, "10.0.0.5"),
			Daddr:    ipToKernelEventUint32(t, "151.101.65.227"),
			Sport:    51112,
			Dport:    443,
			OldState: 2,
			NewState: 1,
		},
	}

	for _, evt := range events {
		agg.Add(evt)
	}

	counts := agg.Counts()
	if counts.StateTransitions != 3 {
		t.Fatalf("StateTransitions = %d, want 3", counts.StateTransitions)
	}
	if counts.LocalIPs != 1 {
		t.Fatalf("LocalIPs = %d, want 1", counts.LocalIPs)
	}
	if counts.RemoteIPs != 2 {
		t.Fatalf("RemoteIPs = %d, want 2", counts.RemoteIPs)
	}
	if counts.LocalPorts != 2 {
		t.Fatalf("LocalPorts = %d, want 2", counts.LocalPorts)
	}
	if counts.RemotePorts != 1 {
		t.Fatalf("RemotePorts = %d, want 1", counts.RemotePorts)
	}

	if !agg.RemotePorts[443] {
		t.Fatalf("RemotePorts should contain 443")
	}
	if !agg.RemoteIPs["104.16.25.35"] {
		t.Fatalf("RemoteIPs should contain 104.16.25.35")
	}
}

func TestKernelBEU32ToIPv4(t *testing.T) {
	got := kernelBEU32ToIPv4(ipToKernelEventUint32(t, "1.2.3.4"))
	if got != "1.2.3.4" {
		t.Fatalf("kernelBEU32ToIPv4(...) = %q, want %q", got, "1.2.3.4")
	}
}

func ipToKernelEventUint32(t *testing.T, ip string) uint32 {
	t.Helper()
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		t.Fatalf("invalid ipv4: %s", ip)
	}
	// Ring-buffer bytes are in network order, but userspace currently decodes
	// the struct with binary.LittleEndian, so the uint32 value seen in Go is the
	// little-endian interpretation of those four bytes.
	return binary.LittleEndian.Uint32(v4)
}
