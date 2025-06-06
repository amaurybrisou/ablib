package ablimit

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClient implements the Client interface for testing.
type fakeClient struct {
	data map[string][]byte
	err  error // an error to be returned from Get if set non-nil (for testing)
	mu   sync.Mutex
	// invalidKeys holds keys that should return invalid JSON data.
	invalidKeys map[string]bool
}

func newFakeClient() *fakeClient {
	return &fakeClient{
		data:        make(map[string][]byte),
		invalidKeys: make(map[string]bool),
	}
}

func (fc *fakeClient) Get(ctx context.Context, key string, value any) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	// if testing a forced error, return it.
	if fc.err != nil {
		return fc.err
	}

	v, ok := fc.data[key]
	if !ok {
		return errors.New("key not found")
	}

	// If key is marked invalid, store non-JSON data.
	if fc.invalidKeys[key] {
		// set value as raw bytes that will fail unmarshal if attempted
		switch dest := value.(type) {
		case *[]byte:
			*dest = []byte("invalid json")
		default:
			return errors.New("invalid destination type")
		}
		return nil
	}

	// Set the pointer value to the stored data.
	switch dest := value.(type) {
	case *[]byte:
		*dest = v
	default:
		return errors.New("invalid destination type")
	}
	return nil
}

func (fc *fakeClient) Set(ctx context.Context, key string, value any, expiration time.Duration) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	switch v := value.(type) {
	case []byte:
		fc.data[key] = v
	default:
		return errors.New("invalid value type")
	}
	return nil
}

func TestAllow_NewUser(t *testing.T) {
	ctx := context.Background()
	client := newFakeClient()
	rl := NewRateLimiter(client, 1, 1, "test")

	// For a new user, the key won't exist so it should allow and create new state
	allowed := rl.Allow(ctx, "user1")
	if !allowed {
		t.Errorf("expected Allow to return true for a new user, got false")
	}

	// A second immediate call should be false (since burst is 1 and one token was consumed)
	allowed = rl.Allow(ctx, "user1")
	if allowed {
		t.Errorf("expected Allow to return false when token not refilled, got true")
	}
}

func TestAllow_ReplenishToken(t *testing.T) {
	ctx := context.Background()
	client := newFakeClient()
	// Use a burst of 5 tokens and a rate of 1 token per second.
	rl := NewRateLimiter(client, 1, 5, "test")

	// Set a pre-populated state for user2: 1 token remaining, but last timestamp 3 seconds ago.
	now := time.Now()
	initialState := RateLimiterState{
		Tokens:        1,
		LastTimestamp: now.Add(-3 * time.Second),
	}
	data, err := json.Marshal(initialState)
	if err != nil {
		t.Fatalf("failed to marshal initial state: %v", err)
	}
	// Pre-populate the key.
	key := rl.getKey("user2")
	client.data[key] = data

	// Now, because 3 seconds have passed, tokens should be replenished by 3 tokens.
	// But max tokens is 5 so new token count: min(1+3, 5) = 4 tokens.
	// First call should use one token and return true.
	allowed := rl.Allow(ctx, "user2")
	if !allowed {
		t.Errorf("expected Allow to return true after replenishment, got false")
	}

	// Call three more times, should be allowed.
	for i := 0; i < 3; i++ {
		allowed = rl.Allow(ctx, "user2")
		if !allowed {
			t.Errorf("expected Allow to return true on call %d after replenishment, got false", i+2)
		}
	}

	// After 4 calls, tokens should be 4-4 = 0.
	// Next call should return false.
	allowed = rl.Allow(ctx, "user2")
	if allowed {
		t.Errorf("expected Allow to return false when tokens are exhausted, got true")
	}
}

func TestAllow_InvalidJSON(t *testing.T) {
	ctx := context.Background()
	client := newFakeClient()
	rl := NewRateLimiter(client, 1, 2, "test")

	// Pre-populate key for user3 with invalid JSON.
	key := rl.getKey("user3")
	client.data[key] = []byte("not a valid json")
	// Mark key as invalid so that Get doesn't override our data.
	client.invalidKeys[key] = true

	allowed := rl.Allow(ctx, "user3")
	if allowed {
		t.Errorf("expected Allow to return false when stored state is invalid, got true")
	}
}

func TestAllow_ForcedGetError(t *testing.T) {
	ctx := context.Background()
	// Simulate Get error by forcing an error in fakeClient.
	client := newFakeClient()
	client.err = errors.New("simulated get error")
	rl := NewRateLimiter(client, 1, 1, "test")

	// In our Allow implementation, if Get returns error, it creates a new state.
	// So Allow should return true for a new token.
	allowed := rl.Allow(ctx, "user4")
	if !allowed {
		t.Errorf("expected Allow to return true when Get returns error (treated as new state), got false")
	}
}

func TestAllow_ExhaustTokens(t *testing.T) {
	ctx := context.Background()
	client := newFakeClient()
	rl := NewRateLimiter(client, 0.5, 3, "test") // refill rate 0.5 token per second, burst 3 tokens

	// Exhaust tokens.
	if !rl.Allow(ctx, "user5") {
		t.Fatalf("expected first call to Allow to return true")
	}
	if !rl.Allow(ctx, "user5") {
		t.Fatalf("expected second call to Allow to return true")
	}
	if !rl.Allow(ctx, "user5") {
		t.Fatalf("expected third call to Allow to return true")
	}
	if rl.Allow(ctx, "user5") {
		t.Errorf("expected Allow to return false when tokens are exhausted")
	}

	// Instead of waiting, simulate passage of 4 seconds by adjusting the stored timestamp.
	key := rl.getKey("user5")
	client.mu.Lock()
	if data, ok := client.data[key]; ok {
		var state RateLimiterState
		if err := json.Unmarshal(data, &state); err == nil {
			// Simulate that 4 seconds have passed.
			state.LastTimestamp = state.LastTimestamp.Add(-4 * time.Second)
			if newData, err := json.Marshal(state); err == nil {
				client.data[key] = newData
			}
		}
	}
	client.mu.Unlock()

	if !rl.Allow(ctx, "user5") {
		t.Errorf("expected Allow to return true after simulated token replenishment")
	}
}
func TestAllow_Concurrent(t *testing.T) {
	ctx := context.Background()
	client := newFakeClient()
	rl := NewRateLimiter(client, 1, 5, "test")

	const goroutines = 10
	var wg sync.WaitGroup
	successCount := int32(0)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if rl.Allow(ctx, "concurrent-user") {
				atomic.AddInt32(&successCount, 1)
			}
		}()
	}
	wg.Wait()

	// Only 5 should succeed (burst size)
	if atomic.LoadInt32(&successCount) != 5 {
		t.Errorf("expected 5 successful calls, got %d", successCount)
	}
}

func TestAllow_EdgeCases(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name      string
		rate      float64
		burst     float64
		wantAllow bool
	}{
		{"zero_rate", 0, 1, true},   // First call should work due to burst
		{"zero_burst", 1, 0, false}, // No tokens available
		{"high_values", 1000000, 1000000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newFakeClient()
			rl := NewRateLimiter(client, tt.rate, tt.burst, "test")
			if got := rl.Allow(ctx, "test-user"); got != tt.wantAllow {
				t.Errorf("Allow() = %v, want %v", got, tt.wantAllow)
			}
		})
	}
}
func TestAllow_FractionalTokens(t *testing.T) {
	ctx := context.Background()
	client := newFakeClient()
	// 0.1 tokens per second, max 1 token
	rl := NewRateLimiter(client, 0.1, 1, "test")

	// Helper to simulate advancing time by modifying the stored state.
	advanceUserTime := func(duration time.Duration) {
		key := rl.getKey("user-frac")
		client.mu.Lock()
		defer client.mu.Unlock()
		data, ok := client.data[key]
		if !ok {
			return
		}
		var state RateLimiterState
		if err := json.Unmarshal(data, &state); err != nil {
			t.Fatalf("failed to unmarshal state: %v", err)
		}
		state.LastTimestamp = state.LastTimestamp.Add(-duration)
		newData, err := json.Marshal(state)
		if err != nil {
			t.Fatalf("failed to marshal state: %v", err)
		}
		client.data[key] = newData
	}

	// First call should succeed (initial burst token)
	if !rl.Allow(ctx, "user-frac") {
		t.Fatal("expected first call to succeed")
	}

	// Second call should fail immediately
	if rl.Allow(ctx, "user-frac") {
		t.Fatal("expected immediate second call to fail")
	}

	// Simulate passage of 5 seconds = 0.5 tokens
	advanceUserTime(5 * time.Second)
	if rl.Allow(ctx, "user-frac") {
		t.Error("expected call to fail with 0.5 tokens")
	}

	// Simulate passage of 5 more seconds = 1.0 tokens total
	advanceUserTime(5 * time.Second)
	if !rl.Allow(ctx, "user-frac") {
		t.Error("expected call to succeed with 1.0 tokens")
	}
}

func TestAllow_EmptyUserID(t *testing.T) {
	ctx := context.Background()
	client := newFakeClient()
	rl := NewRateLimiter(client, 1, 1, "test")

	// Empty userID should still work with prefix
	if !rl.Allow(ctx, "") {
		t.Error("expected Allow to work with empty userID")
	}

	// Second call should fail due to rate limit
	if rl.Allow(ctx, "") {
		t.Error("expected second call to fail for empty userID")
	}
}
