package features

import (
	"encoding/binary"
	"net"
)

// TCPEvent is a feature-layer view of one TCP state transition event.
//
// Saddr and Daddr carry IPv4 addresses emitted by the kernel as 32-bit values
// in network byte order. Sport and Dport are host-order ports.
type TCPEvent struct {
	Pid         uint32
	Saddr       uint32
	Daddr       uint32
	Sport       uint16
	Dport       uint16
	OldState    uint8
	NewState    uint8
	TimestampNs uint64
}

// TCPCounts is a compact summary of unique per-session TCP attributes.
type TCPCounts struct {
	StateTransitions int
	LocalIPs         int
	RemoteIPs        int
	LocalPorts       int
	RemotePorts      int
}

// TCPAggregator tracks deduplicated IP/port information for one session.
type TCPAggregator struct {
	StateTransitions int
	LocalIPs         map[string]bool
	RemoteIPs        map[string]bool
	LocalPorts       map[uint16]bool
	RemotePorts      map[uint16]bool
}

// NewTCPAggregator creates an initialized TCPAggregator.
func NewTCPAggregator() *TCPAggregator {
	return &TCPAggregator{
		LocalIPs:    make(map[string]bool),
		RemoteIPs:   make(map[string]bool),
		LocalPorts:  make(map[uint16]bool),
		RemotePorts: make(map[uint16]bool),
	}
}

// Add updates transition count and deduplicated endpoint sets.
func (a *TCPAggregator) Add(event TCPEvent) {
	if a.LocalIPs == nil {
		a.LocalIPs = make(map[string]bool)
	}
	if a.RemoteIPs == nil {
		a.RemoteIPs = make(map[string]bool)
	}
	if a.LocalPorts == nil {
		a.LocalPorts = make(map[uint16]bool)
	}
	if a.RemotePorts == nil {
		a.RemotePorts = make(map[uint16]bool)
	}

	a.StateTransitions++
	a.LocalIPs[kernelBEU32ToIPv4(event.Saddr)] = true
	a.RemoteIPs[kernelBEU32ToIPv4(event.Daddr)] = true
	a.LocalPorts[event.Sport] = true
	a.RemotePorts[event.Dport] = true
}

// Counts returns cardinalities of tracked transition/IP/port sets.
func (a *TCPAggregator) Counts() TCPCounts {
	if a == nil {
		return TCPCounts{}
	}

	return TCPCounts{
		StateTransitions: a.StateTransitions,
		LocalIPs:         len(a.LocalIPs),
		RemoteIPs:        len(a.RemoteIPs),
		LocalPorts:       len(a.LocalPorts),
		RemotePorts:      len(a.RemotePorts),
	}
}

// kernelBEU32ToIPv4 converts a kernel-provided big-endian IPv4 u32 into
// dotted-decimal form through net.IP.
//
// The event payload is decoded into a host-order uint32. Converting via ntohl
// semantics restores network-order bytes so net.IP prints correctly.
func kernelBEU32ToIPv4(addr uint32) string {
	networkOrder := ntohl(addr)
	ipBytes := make([]byte, net.IPv4len)
	binary.BigEndian.PutUint32(ipBytes, networkOrder)
	return net.IP(ipBytes).String()
}

// ntohl converts a 32-bit value from network byte order to host byte order.
func ntohl(v uint32) uint32 {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return binary.BigEndian.Uint32(b[:])
}
