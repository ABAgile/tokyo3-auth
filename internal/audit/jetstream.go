package audit

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	// Subject is the NATS subject for all audit events. The publisher mTLS
	// credential (authd-publisher identity) has PUBLISH-only permission here.
	Subject = "auth.audit.events"

	// StreamName is the JetStream stream that captures Subject.
	StreamName = "auth_audit"

	// StreamMaxAge is the stream retention floor for PCI-DSS 10.5 (12 months).
	// Set to 13 months so operations have a comfortable roll-over buffer.
	StreamMaxAge = 400 * 24 * time.Hour
)

// JetStreamSink publishes audit entries to a NATS JetStream stream via mTLS.
// The NATS user identity (derived from the TLS cert subject or SPIFFE URI SAN
// via verify_and_map) must have PUBLISH-only permission on auth.audit.events
// with no subscribe or stream-management rights.
type JetStreamSink struct {
	nc *nats.Conn
	js jetstream.JetStream
}

// NewJetStreamSink dials NATS and returns a ready JetStreamSink. When tlsCfg
// is non-nil the connection uses mTLS — the NATS server uses verify_and_map to
// derive the publisher identity from the cert subject or SPIFFE URI SAN. When
// tlsCfg is nil the connection is plaintext (development only). Close must be
// called on shutdown.
func NewJetStreamSink(url string, tlsCfg *tls.Config) (*JetStreamSink, error) {
	var opts []nats.Option
	if tlsCfg != nil {
		opts = append(opts, nats.Secure(tlsCfg))
	}
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream client: %w", err)
	}
	return &JetStreamSink{nc: nc, js: js}, nil
}

// Log marshals e to JSON and publishes it synchronously to the auth_audit stream.
// Returns an error if the publish times out or NATS rejects the message.
// Because this is synchronous, callers receive the JetStream server-ack before
// the method returns — the event is durable once Log returns nil.
func (s *JetStreamSink) Log(ctx context.Context, e Entry) error {
	payload, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}
	if _, err = s.js.Publish(ctx, Subject, payload); err != nil {
		return fmt.Errorf("jetstream publish: %w", err)
	}
	return nil
}

// Close drains the NATS connection, flushing any buffered messages before
// closing the underlying TCP connection.
func (s *JetStreamSink) Close() error {
	return s.nc.Drain()
}
