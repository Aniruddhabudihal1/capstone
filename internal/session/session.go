package session

// Session tracks network packet monitoring session state.
type Session struct {
// TODO: Add session tracking fields
}

// NewSession creates a new monitoring session.
func NewSession() *Session {
return &Session{}
}

// Close ends the session.
func (s *Session) Close() error {
return nil
}
