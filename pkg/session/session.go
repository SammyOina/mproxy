package session

import (
	"context"
	"crypto/x509"
)

// The ctxKey type is unexported to prevent collisions with context keys defined in
// other packages.
type ctxKey int

// SessionKey is the context key for the session client.  Its value of one is
// arbitrary.  If this package defined other context keys, they would have
// different integer values.
const sessionKey ctxKey = 1

// Session stores MQTT client data.
type Session struct {
	ID       string
	Username string
	Password []byte
	Cert     x509.Certificate
}

// ToContext stores Session in context.Context values.
func (s Session) ToContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, sessionKey, s)
}

// FromContext retrieve Session from context.Context.
func FromContext(ctx context.Context) (Session, bool) {
	if s, ok := ctx.Value(sessionKey).(Session); ok {
		return s, true
	}
	return Session{}, false
}
