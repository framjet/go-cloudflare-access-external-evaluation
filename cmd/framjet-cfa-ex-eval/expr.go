package main

import (
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/framjet/go-cloudflare-access-external-evaluation/cmd/framjet-cfa-ex-eval/metrics"
	lru "github.com/hashicorp/golang-lru"
	"sync"
	"time"
)

type compiledProgramCache struct {
	mu    sync.RWMutex
	cache *lru.Cache
}

type CompiledProgramCache interface {
	GetOrCompile(exprStr string) (*vm.Program, error)
}

func NewCompiledProgramCache(size int) (CompiledProgramCache, error) {
	lruCache, err := lru.New(size)
	if err != nil {
		return nil, err
	}
	return &compiledProgramCache{cache: lruCache}, nil
}

func (c *compiledProgramCache) GetOrCompile(exprStr string) (*vm.Program, error) {
	c.mu.RLock()
	if val, found := c.cache.Get(exprStr); found {
		c.mu.RUnlock()
		return val.(*vm.Program), nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	start := time.Now()

	// Double-check after acquiring write lock
	if val, found := c.cache.Get(exprStr); found {
		metrics.CacheOperationsTotal.WithLabelValues("hit", "success").Inc()
		return val.(*vm.Program), nil
	}

	// Compile the expression
	program, err := expr.Compile(exprStr)
	if err != nil {
		metrics.CacheOperationsTotal.WithLabelValues("compile", "error").Inc()
		return nil, err
	}

	// Store in cache
	c.cache.Add(exprStr, program)

	metrics.ExpressionCacheSize.Set(float64(c.cache.Len()))

	metrics.ExpressionEvalDuration.WithLabelValues("success").Observe(time.Since(start).Seconds())

	return program, nil
}
