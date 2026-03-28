package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
)

type RedisClient struct {
	client *redis.Client
	ctx    context.Context
}

type CacheConfig struct {
	Host     string
	Port     string
	Password string
	DB       int
}

func NewRedisClient(config CacheConfig) (*RedisClient, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", config.Host, config.Port),
		Password: config.Password,
		DB:       config.DB,
		PoolSize: 100,
	})

	ctx := context.Background()

	// Test connection
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %v", err)
	}

	log.Println("✅ Redis connected successfully")

	return &RedisClient{
		client: rdb,
		ctx:    ctx,
	}, nil
}

// Basic operations
func (r *RedisClient) Set(key string, value interface{}, expiration time.Duration) error {
	return r.client.Set(r.ctx, key, value, expiration).Err()
}

func (r *RedisClient) Get(key string) (string, error) {
	return r.client.Get(r.ctx, key).Result()
}

func (r *RedisClient) Del(key string) error {
	return r.client.Del(r.ctx, key).Err()
}

func (r *RedisClient) Exists(key string) bool {
	result, err := r.client.Exists(r.ctx, key).Result()
	return err == nil && result > 0
}

func (r *RedisClient) Expire(key string, expiration time.Duration) error {
	return r.client.Expire(r.ctx, key, expiration).Err()
}

// JSON operations
func (r *RedisClient) SetJSON(key string, value interface{}, expiration time.Duration) error {
	jsonData, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return r.Set(key, jsonData, expiration)
}

func (r *RedisClient) GetJSON(key string, dest interface{}) error {
	data, err := r.Get(key)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(data), dest)
}

// Hash operations
func (r *RedisClient) HSet(key string, values map[string]interface{}) error {
	return r.client.HSet(r.ctx, key, values).Err()
}

func (r *RedisClient) HGet(key, field string) (string, error) {
	return r.client.HGet(r.ctx, key, field).Result()
}

func (r *RedisClient) HGetAll(key string) (map[string]string, error) {
	return r.client.HGetAll(r.ctx, key).Result()
}

// List operations
func (r *RedisClient) LPush(key string, values ...interface{}) error {
	return r.client.LPush(r.ctx, key, values...).Err()
}

func (r *RedisClient) RPop(key string) (string, error) {
	return r.client.RPop(r.ctx, key).Result()
}

func (r *RedisClient) LRange(key string, start, stop int64) ([]string, error) {
	return r.client.LRange(r.ctx, key, start, stop).Result()
}

// Set operations
func (r *RedisClient) SAdd(key string, members ...interface{}) error {
	return r.client.SAdd(r.ctx, key, members...).Err()
}

func (r *RedisClient) SIsMember(key string, member interface{}) bool {
	result, err := r.client.SIsMember(r.ctx, key, member).Result()
	return err == nil && result
}

func (r *RedisClient) SMembers(key string) ([]string, error) {
	return r.client.SMembers(r.ctx, key).Result()
}

// Sorted set operations for rate limiting
func (r *RedisClient) ZAdd(key string, members ...*redis.Z) error {
	return r.client.ZAdd(r.ctx, key, members...).Err()
}

func (r *RedisClient) ZCount(key, min, max string) (int64, error) {
	return r.client.ZCount(r.ctx, key, min, max).Result()
}

func (r *RedisClient) ZRemRangeByScore(key, min, max string) error {
	return r.client.ZRemRangeByScore(r.ctx, key, min, max).Err()
}

// Atomic operations
func (r *RedisClient) Incr(key string) (int64, error) {
	return r.client.Incr(r.ctx, key).Result()
}

func (r *RedisClient) IncrBy(key string, value int64) (int64, error) {
	return r.client.IncrBy(r.ctx, key, value).Result()
}

// Pattern matching
func (r *RedisClient) Keys(pattern string) ([]string, error) {
	return r.client.Keys(r.ctx, pattern).Result()
}

// Pipeline operations for batch processing
func (r *RedisClient) Pipeline() redis.Pipeliner {
	return r.client.Pipeline()
}

// Pub/Sub for real-time notifications
func (r *RedisClient) Publish(channel string, message interface{}) error {
	jsonMsg, err := json.Marshal(message)
	if err != nil {
		return err
	}
	return r.client.Publish(r.ctx, channel, jsonMsg).Err()
}

func (r *RedisClient) Subscribe(channels ...string) *redis.PubSub {
	return r.client.Subscribe(r.ctx, channels...)
}

// Rate limiting implementation
func (r *RedisClient) IsRateLimited(identifier string, limit int, window time.Duration) (bool, error) {
	key := fmt.Sprintf("rate_limit:%s", identifier)
	now := time.Now().UnixNano()
	windowMicro := window.Microseconds()

	// Remove old entries
	oldest := now - windowMicro
	r.ZRemRangeByScore(key, "0", fmt.Sprintf("%d", oldest))

	// Count current requests
	count, err := r.ZCount(key, fmt.Sprintf("%d", now-windowMicro), fmt.Sprintf("%d", now))
	if err != nil {
		return true, err
	}

	if count >= int64(limit) {
		return true, nil
	}

	// Add current request
	r.ZAdd(key, &redis.Z{
		Score:  float64(now),
		Member: float64(now),
	})
	r.Expire(key, window)

	return false, nil
}

// Cache management
func (r *RedisClient) FlushPattern(pattern string) error {
	keys, err := r.Keys(pattern)
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		return r.client.Del(r.ctx, keys...).Err()
	}

	return nil
}

func (r *RedisClient) GetMemoryUsage() (int64, error) {
	_, err := r.client.Info(r.ctx, "memory").Result()
	if err != nil {
		return 0, err
	}

	// Parse used_memory from info string
	// This is a simplified parsing
	return 0, nil
}

// Health check
func (r *RedisClient) Health() error {
	return r.client.Ping(r.ctx).Err()
}

// Close connection
func (r *RedisClient) Close() error {
	return r.client.Close()
}
