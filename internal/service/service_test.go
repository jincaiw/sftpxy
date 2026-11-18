// SPDX-License-Identifier: MIT

package service

import (
	"errors"
	"sync"
	"testing"
)

// TestSetErrorIsRaceFree verifies that concurrent writers (the goroutines
// started by startServices) and readers (Wait callers and the Windows service
// handler) can access the service error without a data race. Run with -race.
func TestSetErrorIsRaceFree(t *testing.T) {
	s := &Service{Shutdown: make(chan bool, 1)}

	var wg sync.WaitGroup
	const writers = 8
	const reads = 200

	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.setError(errors.New("failure"))
		}()
	}

	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range reads {
				_ = s.GetError()
			}
		}()
	}

	wg.Wait()

	if err := s.GetError(); err == nil {
		t.Fatal("expected an error to be recorded")
	}
}

// TestSetErrorKeepsFirstError verifies that the first failure is the one
// reported on exit, so operators see the root cause and not a follow-up error.
func TestSetErrorKeepsFirstError(t *testing.T) {
	s := &Service{Shutdown: make(chan bool, 1)}
	first := errors.New("first failure")
	second := errors.New("second failure")

	s.setError(first)
	s.setError(second)

	if got := s.GetError(); !errors.Is(got, first) {
		t.Fatalf("expected the first error to be preserved, got %v", got)
	}
}

// TestGetErrorNilWhenNoFailure verifies that a clean shutdown reports success.
func TestGetErrorNilWhenNoFailure(t *testing.T) {
	s := &Service{Shutdown: make(chan bool, 1)}
	if err := s.GetError(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}
