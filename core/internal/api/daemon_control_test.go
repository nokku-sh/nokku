package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/config"
)

func TestUploadSlotsLimitOneDaemon(t *testing.T) {
	s := &daemonControlService{uploads: map[string]int{}}
	var releases []func()
	for i := range maxOpenUploads {
		release, ok := s.takeUploadSlot("daemon")
		require.True(t, ok, "slot %d was refused", i)
		releases = append(releases, release)
	}
	_, ok := s.takeUploadSlot("daemon")
	assert.False(t, ok, "a daemon went past its limit")

	_, ok = s.takeUploadSlot("another")
	assert.True(t, ok, "a full daemon held back another one")

	releases[0]()
	_, ok = s.takeUploadSlot("daemon")
	assert.True(t, ok, "a released slot stayed taken")
}

// Memory is what runs out, so a quiet upload must cost nothing and a full one must be refused.
func TestUploadMemoryIsBounded(t *testing.T) {
	fill := func(s *daemonControlService, workspace string, total int64) {
		t.Helper()
		for range total / maxUploadMemory {
			held, ok := s.holdUploadMemory(workspace, 0, maxUploadMemory)
			require.True(t, ok, "refused under the limit")
			require.Equal(t, int64(maxUploadMemory), held)
		}
	}

	hosted := &daemonControlService{cfg: &config.Config{SaaS: true}, held: map[string]int64{}}
	held, ok := hosted.holdUploadMemory("a", maxUploadMemory, 1<<20)
	assert.True(t, ok, "an upload past what it can hold costs nothing more")
	assert.Equal(t, int64(maxUploadMemory), held)

	fill(hosted, "a", maxWorkspaceUploadMemory)
	_, ok = hosted.holdUploadMemory("a", 0, maxUploadMemory)
	assert.False(t, ok, "a workspace went past its share")
	_, ok = hosted.holdUploadMemory("b", 0, 1)
	assert.True(t, ok, "a full workspace held back another one")

	hosted.releaseUploadMemory("a", hosted.held["a"])
	hosted.releaseUploadMemory("b", 1)
	assert.Empty(t, hosted.held, "the counts of finished uploads stayed behind")
	assert.Zero(t, hosted.heldTotal)

	// One self-hosted workspace has the whole core.
	selfHosted := &daemonControlService{cfg: &config.Config{}, held: map[string]int64{}}
	fill(selfHosted, "only", maxCoreUploadMemory)
	_, ok = selfHosted.holdUploadMemory("only", 0, maxUploadMemory)
	assert.False(t, ok, "the core went past its limit")
}
