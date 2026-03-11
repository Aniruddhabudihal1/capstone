package output

// Writer outputs monitoring results in various formats.
type Writer struct {
format string // "json", "text", etc.
}

// NewWriter creates a new output writer.
func NewWriter(format string) *Writer {
return &Writer{format: format}
}

// WriteResults outputs the collected data.
func (w *Writer) WriteResults(data interface{}) error {
return nil
}
