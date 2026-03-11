package features

// Aggregator combines data from multiple eBPF programs.
type Aggregator struct {
// TODO: Add aggregation state
}

// NewAggregator creates a new feature aggregator.
func NewAggregator() *Aggregator {
return &Aggregator{}
}

// Aggregate processes collected events.
func (a *Aggregator) Aggregate() error {
return nil
}
