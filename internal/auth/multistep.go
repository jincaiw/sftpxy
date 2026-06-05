package auth

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type PartialAuthState struct {
	SessionID string
	Username  string
	RemoteIP  string
	Completed map[string]bool
	Required  []string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type MultiStepAuthTracker struct {
	states map[string]*PartialAuthState
	mu     sync.RWMutex
	ttl    time.Duration
}

func NewMultiStepAuthTracker(ttlSeconds int) *MultiStepAuthTracker {
	if ttlSeconds <= 0 {
		ttlSeconds = 300
	}
	tracker := &MultiStepAuthTracker{
		states: make(map[string]*PartialAuthState),
		ttl:    time.Duration(ttlSeconds) * time.Second,
	}
	go tracker.cleanupLoop()
	return tracker
}

func (t *MultiStepAuthTracker) RecordPartialSuccess(sessionID, username, remoteIP, method string, required []string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := t.stateKey(sessionID, username)
	state, exists := t.states[key]
	if !exists {
		state = &PartialAuthState{
			SessionID: sessionID,
			Username:  username,
			RemoteIP:  remoteIP,
			Completed: make(map[string]bool),
			Required:  required,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(t.ttl),
		}
		t.states[key] = state
	}

	state.Completed[method] = true
	state.ExpiresAt = time.Now().Add(t.ttl)
}

func (t *MultiStepAuthTracker) GetPartialState(sessionID, username string) *PartialAuthState {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key := t.stateKey(sessionID, username)
	state, exists := t.states[key]
	if !exists {
		return nil
	}
	if time.Now().After(state.ExpiresAt) {
		return nil
	}
	return state
}

func (t *MultiStepAuthTracker) IsAuthComplete(sessionID, username string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key := t.stateKey(sessionID, username)
	state, exists := t.states[key]
	if !exists {
		return false
	}
	if time.Now().After(state.ExpiresAt) {
		return false
	}
	for _, method := range state.Required {
		if !state.Completed[method] {
			return false
		}
	}
	return true
}

func (t *MultiStepAuthTracker) GetPendingMethods(sessionID, username string) []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key := t.stateKey(sessionID, username)
	state, exists := t.states[key]
	if !exists {
		return nil
	}
	if time.Now().After(state.ExpiresAt) {
		return nil
	}

	var pending []string
	for _, method := range state.Required {
		if !state.Completed[method] {
			pending = append(pending, method)
		}
	}
	return pending
}

func (t *MultiStepAuthTracker) ClearState(sessionID, username string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := t.stateKey(sessionID, username)
	delete(t.states, key)
}

func (t *MultiStepAuthTracker) HasPartialSuccess(sessionID, username string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key := t.stateKey(sessionID, username)
	state, exists := t.states[key]
	if !exists {
		return false
	}
	return time.Now().Before(state.ExpiresAt) && len(state.Completed) > 0
}

func (t *MultiStepAuthTracker) stateKey(sessionID, username string) string {
	return fmt.Sprintf("%s:%s", sessionID, strings.ToLower(username))
}

func (t *MultiStepAuthTracker) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		t.cleanup()
	}
}

func (t *MultiStepAuthTracker) cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	for key, state := range t.states {
		if now.After(state.ExpiresAt) {
			delete(t.states, key)
		}
	}
}
