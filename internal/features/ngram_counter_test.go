package features

import "testing"

func TestNGramCounterPush(t *testing.T) {
	tests := []struct {
		name      string
		sequence  []uint32
		want      PatternCounts
		wantPanic bool
	}{
		{
			name:     "pattern1_only_once_with_nonmatching_tail",
			sequence: []uint32{262, 257, 5, 257, 5, 262},
			want: PatternCounts{
				P1: 1,
			},
		},
		{
			name:     "pattern5_process_create",
			sequence: []uint32{57, 59, 61},
			want: PatternCounts{
				P5: 1,
			},
		},
		{
			name:     "pattern1_twice_overlapping_continuous_stream",
			sequence: []uint32{262, 257, 5, 262, 257, 5},
			want: PatternCounts{
				P1: 2,
			},
		},
		{
			name:     "sliding_window_discards_old_syscalls_without_false_match",
			sequence: []uint32{99, 98, 97, 96, 95, 262, 257},
			want:     PatternCounts{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			counter := NewNGramCounter()

			defer func() {
				if r := recover(); r != nil {
					if !tt.wantPanic {
						t.Fatalf("Push panicked: %v", r)
					}
					return
				}
				if tt.wantPanic {
					t.Fatal("Push did not panic, want panic")
				}
			}()

			for _, syscallID := range tt.sequence {
				counter.Push(syscallID)
			}

			got := counter.Snapshot()
			if got != tt.want {
				t.Fatalf("Snapshot() = %+v, want %+v", got, tt.want)
			}

			if len(counter.window) > 5 {
				t.Fatalf("window length = %d, want at most 5", len(counter.window))
			}
		})
	}
}
