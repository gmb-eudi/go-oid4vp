package oid4vp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// MemStore is the in-memory reference SessionStore: single-process, for
// tests and development. Sessions are stored as JSON snapshots, which (a)
// gives Load copy semantics identical to a networked store and (b) proves
// every Session is serializable exactly as a persistent (Valkey) store needs.
type MemStore struct {
	mu       sync.Mutex
	clock    func() time.Time
	sessions map[string][]byte
}

// NewMemStore returns an empty MemStore. clock nil defaults to time.Now.
func NewMemStore(clock func() time.Time) *MemStore {
	if clock == nil {
		clock = time.Now
	}
	return &MemStore{clock: clock, sessions: map[string][]byte{}}
}

// Save stores a JSON snapshot of s.
func (m *MemStore) Save(_ context.Context, s *Session) error {
	if s == nil || s.ID == "" {
		return ErrSessionInvalid
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSessionInvalid, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.ID] = raw
	return nil
}

// Load returns an independent copy of the stored session. Expired sessions
// are evicted and reported as not found (store contract; the Engine also
// checks ExpiresAt itself — fail closed).
func (m *MemStore) Load(_ context.Context, id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.load(id)
}

// load must be called with m.mu held.
func (m *MemStore) load(id string) (*Session, error) {
	raw, ok := m.sessions[id]
	if !ok {
		return nil, ErrSessionNotFound
	}
	var s Session
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSessionInvalid, err)
	}
	if !m.clock().Before(s.ExpiresAt) {
		delete(m.sessions, id)
		return nil, ErrSessionNotFound
	}
	return &s, nil
}

// ConsumeOnce atomically hands the session to exactly one caller
// ([OID4VP §8.2] one-time response consumption; [OID4VP §14.2] replay defense).
// The Consumed marker is sticky: it survives later Save calls, so a
// replayed wallet POST fails even after the service persisted
// post-processing state.
func (m *MemStore) ConsumeOnce(_ context.Context, id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.load(id)
	if err != nil {
		return nil, err
	}
	if s.Consumed {
		return nil, ErrSessionConsumed
	}
	s.Consumed = true
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSessionInvalid, err)
	}
	m.sessions[id] = raw
	return s, nil
}
