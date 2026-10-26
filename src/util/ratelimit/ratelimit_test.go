package ratelimit

import (
	"strconv"
	"testing"
	"time"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func TestLimiterBlocksAfterBudget(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	l := NewWithClock(3, 10*time.Minute, clock.Now)
	const key = "203.0.113.7"

	for i := 0; i < 3; i++ {
		if allowed, _ := l.Allow(key); !allowed {
			t.Fatalf("attempt %d blocked before the budget was spent", i+1)
		}
		l.Fail(key)
	}

	allowed, retry := l.Allow(key)
	if allowed {
		t.Fatal("attempt past the budget was allowed")
	}
	if retry <= 0 || retry > 10*time.Minute {
		t.Fatalf("retry-after = %v, want within the window", retry)
	}

	// Another client is unaffected.
	if allowed, _ := l.Allow("198.51.100.9"); !allowed {
		t.Fatal("a different key was blocked by someone else's failures")
	}

	// The window expires and the budget is restored.
	clock.Advance(10 * time.Minute)
	if allowed, _ := l.Allow(key); !allowed {
		t.Fatal("key still blocked after the window elapsed")
	}
}

func TestLimiterResetOnSuccess(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	l := NewWithClock(2, time.Minute, clock.Now)
	const key = "203.0.113.7"

	l.Fail(key)
	l.Fail(key)
	if allowed, _ := l.Allow(key); allowed {
		t.Fatal("expected the key to be blocked")
	}

	l.Reset(key)
	if allowed, _ := l.Allow(key); !allowed {
		t.Fatal("reset did not clear the block")
	}
}

func TestLimiterIgnoresEmptyKey(t *testing.T) {
	l := New(1, time.Minute)
	if allowed, _ := l.Allow(""); !allowed {
		t.Fatal("empty key was limited")
	}
	l.Fail("")
	if allowed, _ := l.Allow(""); !allowed {
		t.Fatal("empty key was limited after a failure")
	}
}

func TestLimiterPrunesExpiredEntries(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	l := NewWithClock(1, time.Minute, clock.Now)

	for i := 0; i < maxTrackedKeys; i++ {
		l.Fail("client-" + strconv.Itoa(i))
	}
	clock.Advance(2 * time.Minute)
	l.Fail("fresh-key")

	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) > maxTrackedKeys {
		t.Fatalf("limiter kept %d entries, want a bounded map", len(l.entries))
	}
}
