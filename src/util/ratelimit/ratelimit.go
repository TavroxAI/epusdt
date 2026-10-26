// Package ratelimit provides a small in-memory failure limiter for endpoints
// that must not be brute-forced, such as the admin login.
//
// It is process-local on purpose: this gateway targets a single-instance
// deployment, so an in-memory counter has no external dependency and cannot drift
// from the request that is being limited.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter counts failures per key inside a window and refuses the key once the
// failure budget is spent, until the window that started with the first failure
// expires.
type Limiter struct {
	mu      sync.Mutex
	now     func() time.Time
	max     int
	window  time.Duration
	entries map[string]*entry
}

type entry struct {
	failures int
	first    time.Time
}

// New returns a limiter that blocks a key after max failures inside window.
func New(max int, window time.Duration) *Limiter {
	return NewWithClock(max, window, time.Now)
}

// NewWithClock is New with an injectable clock, for tests.
func NewWithClock(max int, window time.Duration, now func() time.Time) *Limiter {
	if max <= 0 {
		max = 1
	}
	if window <= 0 {
		window = time.Minute
	}
	if now == nil {
		now = time.Now
	}
	return &Limiter{
		now:     now,
		max:     max,
		window:  window,
		entries: make(map[string]*entry),
	}
}

// Allow reports whether key may attempt now, and for how long it is blocked when
// it may not. An empty key is never limited (there is nothing to count against).
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	if key == "" {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	e := l.entries[key]
	if e == nil {
		return true, 0
	}
	now := l.now()
	if now.Sub(e.first) >= l.window {
		delete(l.entries, key)
		return true, 0
	}
	if e.failures >= l.max {
		return false, e.first.Add(l.window).Sub(now)
	}
	return true, 0
}

// Fail records one failed attempt for key, starting a fresh window when the
// previous one has elapsed.
func (l *Limiter) Fail(key string) {
	if key == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	e := l.entries[key]
	if e == nil || now.Sub(e.first) >= l.window {
		l.entries[key] = &entry{failures: 1, first: now}
		l.pruneLocked(now)
		return
	}
	e.failures++
}

// Reset forgets key, called after a successful login so a legitimate operator
// does not inherit a blocked window from earlier mistyped passwords.
func (l *Limiter) Reset(key string) {
	if key == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// maxTrackedKeys bounds the map so distinct client addresses cannot grow it
// without limit. Expired windows are dropped first; if that is not enough the map
// is reset, which trades a rare loss of existing blocks for a bounded footprint.
const maxTrackedKeys = 4096

func (l *Limiter) pruneLocked(now time.Time) {
	if len(l.entries) < maxTrackedKeys {
		return
	}
	for key, e := range l.entries {
		if now.Sub(e.first) >= l.window {
			delete(l.entries, key)
		}
	}
	if len(l.entries) >= maxTrackedKeys {
		l.entries = make(map[string]*entry, maxTrackedKeys/2)
	}
}
