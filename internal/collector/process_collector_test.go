package collector

import (
	"testing"
	"unsafe"
)

func TestProcessEventLayoutMatchesBPFStruct(t *testing.T) {
	var evt ProcessEvent

	if got, want := unsafe.Sizeof(evt), uintptr(296); got != want {
		t.Fatalf("unsafe.Sizeof(ProcessEvent{}) = %d, want %d", got, want)
	}

	tests := []struct {
		name   string
		offset uintptr
		want   uintptr
	}{
		{name: "Pid", offset: unsafe.Offsetof(evt.Pid), want: 0},
		{name: "Ppid", offset: unsafe.Offsetof(evt.Ppid), want: 4},
		{name: "Comm", offset: unsafe.Offsetof(evt.Comm), want: 8},
		{name: "Args", offset: unsafe.Offsetof(evt.Args), want: 24},
		{name: "TimestampNs", offset: unsafe.Offsetof(evt.TimestampNs), want: 280},
		{name: "IsNpmRelated", offset: unsafe.Offsetof(evt.IsNpmRelated), want: 288},
		{name: "EventType", offset: unsafe.Offsetof(evt.EventType), want: 292},
	}

	for _, tt := range tests {
		if tt.offset != tt.want {
			t.Fatalf("unsafe.Offsetof(ProcessEvent.%s) = %d, want %d", tt.name, tt.offset, tt.want)
		}
	}
}
