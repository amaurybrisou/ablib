package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-redis/redismock/v8"
)

func TestSetSuccess(t *testing.T) {
	ctx := context.Background()

	// Create a redis mock client and assign it to our RedisClient.
	db, mock := redismock.NewClientMock()
	redisClient := &RedisClient{
		addr:   "localhost",
		port:   6379,
		Client: db,
	}

	// Prepare expected key and set command.
	key := fmt.Sprintf("%s:%s", "testdb", "testcol")
	mock.ExpectSet(key, "test-value", 5*time.Second).SetVal("OK")

	result, err := redisClient.Set(ctx, "testdb", "testcol", "test-value", 5*time.Second)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != "OK" {
		t.Errorf("Expected 'OK', got: %s", result)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestSetWithoutInitialization(t *testing.T) {
	ctx := context.Background()

	// Create a RedisClient with a nil Client.
	redisClient := &RedisClient{
		addr:   "localhost",
		port:   6379,
		Client: nil,
	}

	_, err := redisClient.Set(ctx, "testdb", "testcol", "test-value", 5*time.Second)
	if err == nil {
		t.Error("Expected an error when client is not initialized, got nil")
	}
}

func TestClose(t *testing.T) {
	ctx := context.Background()

	// Test Close when Client is nil.
	redisClient := &RedisClient{
		addr:   "localhost",
		port:   6379,
		Client: nil,
	}
	if err := redisClient.Close(ctx); err != nil {
		t.Errorf("Expected no error for nil client, got: %v", err)
	}

	// Test Close with a valid (mock) redis client.
	db, mock := redismock.NewClientMock()
	redisClient = &RedisClient{
		addr:   "localhost",
		port:   6379,
		Client: db,
	}
	if err := redisClient.Close(ctx); err != nil {
		t.Errorf("Unexpected error on close: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestNewRedisClient_InvalidAddress(t *testing.T) {
	ctx := context.Background()

	// Using an invalid address, NewRedisClient should return an error.
	client, err := NewRedisClient(ctx, "invalid-address", 1234)
	if err == nil {
		t.Error("Expected error for invalid address, got nil")
	}
	if client != nil {
		t.Error("Expected nil client on error")
	}
}
