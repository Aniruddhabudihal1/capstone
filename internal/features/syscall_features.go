package features

// SyscallFeatures is the JSON-facing summary of per-category syscall counts.
type SyscallFeatures struct {
	IoOps       int `json:"io_ops"`
	FileOps     int `json:"file_ops"`
	NetworkOps  int `json:"network_ops"`
	TimeOps     int `json:"time_ops"`
	SecurityOps int `json:"security_ops"`
	ProcessOps  int `json:"process_ops"`
	UnknownOps  int `json:"unknown_ops"`
}
