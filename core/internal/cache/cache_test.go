package cache

import (
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTTLExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := New[string, int](10, time.Minute)
		c.Set("a", 1)
		v, ok := c.Get("a")
		assert.True(t, ok)
		assert.Equal(t, 1, v)

		time.Sleep(time.Minute)
		_, ok = c.Get("a")
		assert.False(t, ok, "an entry outlived its time")
		assert.True(t, c.SetNX("a", 2), "an expired entry blocks a new one")
	})
}

// A full cache drops its oldest entry and keeps taking new ones. Refusing would let a flood lock everyone out.
func TestTTLDropsTheOldestWhenFull(t *testing.T) {
	c := New[int, struct{}](3, time.Hour)
	for i := range 5 {
		assert.True(t, c.SetNX(i, struct{}{}), "a full cache refused entry %d", i)
	}
	for i, want := range []bool{false, false, true, true, true} {
		_, ok := c.Get(i)
		assert.Equal(t, want, ok, "entry %d", i)
	}
}

func TestTTLSetNX(t *testing.T) {
	c := New[string, string](10, time.Hour)
	assert.True(t, c.SetNX("k", "first"))
	assert.False(t, c.SetNX("k", "second"))
	v, _ := c.Get("k")
	assert.Equal(t, "first", v)
}

// One-time state is consumed by exactly one of many callers at once.
func TestTTLGetDelIsSingleUse(t *testing.T) {
	c := New[string, int](10, time.Hour)
	c.Set("ticket", 7)
	var won atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if _, ok := c.GetDel("ticket"); ok {
				won.Add(1)
			}
		})
	}
	wg.Wait()
	assert.EqualValues(t, 1, won.Load())
}

func TestTTLDelete(t *testing.T) {
	c := New[string, int](10, time.Hour)
	c.Set("k", 1)
	c.Delete("k")
	_, ok := c.Get("k")
	assert.False(t, ok)
	c.Delete("never there")
}
