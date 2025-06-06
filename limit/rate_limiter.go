package ablimit

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type RateLimiterState struct {
	Tokens        float64   `json:"tokens"`
	LastTimestamp time.Time `json:"last_timestamp"`
}

type RateLimiter struct {
	df        Client
	maxTokens float64
	tokenRate float64
	keyPrefix string
	mu        sync.Mutex
}

type Client interface {
	Get(ctx context.Context, key string, value any) error
	Set(ctx context.Context, key string, value any, expiration time.Duration) error
}

func NewRateLimiter(dfClient Client, rate float64, burst float64, keyPrefix string) *RateLimiter {
	return &RateLimiter{
		df:        dfClient,
		maxTokens: burst,
		tokenRate: rate,
		keyPrefix: keyPrefix,
	}
}

func (rl *RateLimiter) getKey(userID string) string {
	return fmt.Sprintf("%s:%s", rl.keyPrefix, userID)
}

func (rl *RateLimiter) Allow(ctx context.Context, userID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	key := rl.getKey(userID)
	now := time.Now()

	// Get current state from Dragonfly
	var state RateLimiterState
	var data []byte
	err := rl.df.Get(ctx, key, &data)
	if err != nil {
		// If key doesn't exist, create new state
		state = RateLimiterState{
			Tokens:        rl.maxTokens,
			LastTimestamp: now,
		}
	} else {
		if err := json.Unmarshal(data, &state); err != nil {
			return false
		}
	}

	// Calculate new token count
	elapsed := now.Sub(state.LastTimestamp).Seconds()
	state.Tokens += elapsed * rl.tokenRate

	if state.Tokens > rl.maxTokens {
		state.Tokens = rl.maxTokens
	}

	state.LastTimestamp = now

	if state.Tokens >= 1 {
		state.Tokens--
		// Save updated state
		if data, err := json.Marshal(state); err == nil {
			// Store with TTL of 1 hour to prevent stale data
			rl.df.Set(ctx, key, data, time.Hour)
		}
		return true
	}

	// Save updated state
	if data, err := json.Marshal(state); err == nil {
		rl.df.Set(ctx, key, data, time.Hour)
	}
	return false
}
