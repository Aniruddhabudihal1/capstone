// Package features provides higher-level analysis on top of raw eBPF events.
package features

var (
	pattern1FileMetadata  = []uint32{262, 257, 5}
	pattern2ReadData      = []uint32{0, 17, 8}
	pattern3WriteData     = []uint32{1, 18, 74}
	pattern4SocketCreate  = []uint32{41, 49, 50}
	pattern5ProcessCreate = []uint32{57, 59, 61}
	pattern6MemoryMap     = []uint32{9, 10, 11}
	pattern7FDManage      = []uint32{32, 33, 3}
	pattern8IPC           = []uint32{22, 1, 0}
	pattern9FileLock      = []uint32{72, 73, 3}
	pattern10ErrorHandle  = []uint32{257, 0, 3}
)

// PatternCounts stores counts for the QUT-DV25 syscall n-gram patterns.
type PatternCounts struct {
	P1  int `json:"p1_file_metadata"`
	P2  int `json:"p2_read_data"`
	P3  int `json:"p3_write_data"`
	P4  int `json:"p4_socket_create"`
	P5  int `json:"p5_process_create"`
	P6  int `json:"p6_memory_map"`
	P7  int `json:"p7_fd_manage"`
	P8  int `json:"p8_ipc"`
	P9  int `json:"p9_file_lock"`
	P10 int `json:"p10_error_handle"`
}

// NGramCounter tracks a rolling syscall window and pattern counts.
type NGramCounter struct {
	window []uint32
	counts PatternCounts
}

// NewNGramCounter creates an initialized NGramCounter.
func NewNGramCounter() *NGramCounter {
	return &NGramCounter{
		window: make([]uint32, 0, 5),
	}
}

// Push adds one syscall to the rolling window and updates matching pattern
// counts based on the current suffix.
func (c *NGramCounter) Push(syscallID uint32) {
	c.window = append(c.window, syscallID)
	if len(c.window) > 5 {
		c.window = c.window[len(c.window)-5:]
	}

	c.matchAndCount(pattern1FileMetadata, &c.counts.P1)
	c.matchAndCount(pattern2ReadData, &c.counts.P2)
	c.matchAndCount(pattern3WriteData, &c.counts.P3)
	c.matchAndCount(pattern4SocketCreate, &c.counts.P4)
	c.matchAndCount(pattern5ProcessCreate, &c.counts.P5)
	c.matchAndCount(pattern6MemoryMap, &c.counts.P6)
	c.matchAndCount(pattern7FDManage, &c.counts.P7)
	c.matchAndCount(pattern8IPC, &c.counts.P8)
	c.matchAndCount(pattern9FileLock, &c.counts.P9)
	c.matchAndCount(pattern10ErrorHandle, &c.counts.P10)
}

// Snapshot returns a copy of the current pattern counts.
func (c *NGramCounter) Snapshot() PatternCounts {
	return c.counts
}

func (c *NGramCounter) matchAndCount(pattern []uint32, count *int) {
	if len(c.window) < len(pattern) {
		return
	}

	suffix := c.window[len(c.window)-len(pattern):]
	for i := range pattern {
		if suffix[i] != pattern[i] {
			return
		}
	}

	(*count)++
}
