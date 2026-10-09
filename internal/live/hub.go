// Package live tells the open consoles of a workspace when to read again. It carries no data.
package live

import (
	"context"
	"log/slog"
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"
)

const (
	// settle lets the writes of one action land in one hint.
	settle = 250 * time.Millisecond
	// minGap is the least time between two hints on one stream, however often the workspace changes.
	minGap = 2 * time.Second
	// spread is the random wait per open console, so a big workspace does not read again all at once.
	spread    = 10 * time.Millisecond
	maxSpread = 15 * time.Second
	// idle is how long a stream says nothing. Proxies cut one that is silent for a minute.
	idle = 20 * time.Second
)

// readers names the services that read a table that changes with nobody clicking. Any other table refetches everything.
var readers = map[string][]string{
	"daemons": {
		nokkuv1connect.DaemonServiceName,
		nokkuv1connect.TargetServiceName,
		nokkuv1connect.DashboardServiceName,
	},
	"recordings": {
		nokkuv1connect.RecordingServiceName,
		nokkuv1connect.DashboardServiceName,
	},
}

// Change is what a console hears. The zero value says nothing changed.
type Change struct {
	Services   []string
	Everything bool
}

type Hub struct {
	mu   sync.Mutex
	subs map[string]map[*Sub]struct{}
}

// Sub is one open stream. Its pending change is guarded by the hub's lock.
type Sub struct {
	hub        *Hub
	workspace  string
	wake       chan struct{}
	services   map[string]struct{}
	everything bool
	// Only Next reads and writes it.
	sent time.Time
}

func New() *Hub {
	return &Hub{subs: make(map[string]map[*Sub]struct{})}
}

// Listen turns the notifications of the notify_change triggers into hints.
func (h *Hub) Listen(ctx context.Context, cfg *pgx.ConnConfig) {
	for ctx.Err() == nil {
		if err := h.listen(ctx, cfg); err != nil && ctx.Err() == nil {
			slog.Warn("change listener disconnected", "error", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
}

func (h *Hub) listen(ctx context.Context, cfg *pgx.ConnConfig) error {
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	if _, err := conn.Exec(ctx, "LISTEN nokku_change"); err != nil {
		return err
	}
	// Anything that changed while we were not listening went unheard.
	h.missed()
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		if workspaceID, table, ok := strings.Cut(n.Payload, ":"); ok {
			h.Changed(workspaceID, table)
		}
	}
}

func (h *Hub) Changed(workspaceID, table string) {
	services, known := readers[table]
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs[workspaceID] {
		if !known {
			s.everything = true
		}
		for _, name := range services {
			s.services[name] = struct{}{}
		}
		s.poke()
	}
}

func (h *Hub) missed() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, subs := range h.subs {
		for s := range subs {
			s.everything = true
			s.poke()
		}
	}
}

// Subscribe starts collecting the changes of a workspace. Close it when the stream ends.
func (h *Hub) Subscribe(workspaceID string) *Sub {
	s := &Sub{
		hub:       h,
		workspace: workspaceID,
		wake:      make(chan struct{}, 1),
		services:  make(map[string]struct{}),
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.subs[workspaceID] == nil {
		h.subs[workspaceID] = make(map[*Sub]struct{})
	}
	h.subs[workspaceID][s] = struct{}{}
	return s
}

func (s *Sub) Close() {
	h := s.hub
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.subs[s.workspace], s)
	if len(h.subs[s.workspace]) == 0 {
		delete(h.subs, s.workspace)
	}
}

// Next returns the zero Change after a quiet while, so the caller can show the stream is alive.
func (s *Sub) Next(ctx context.Context) (Change, error) {
	select {
	case <-ctx.Done():
		return Change{}, ctx.Err()
	case <-time.After(idle):
		return Change{}, nil
	case <-s.wake:
	}
	select {
	case <-ctx.Done():
		return Change{}, ctx.Err()
	case <-time.After(s.delay()):
	}
	s.sent = time.Now()
	return s.take(), nil
}

func (s *Sub) delay() time.Duration {
	s.hub.mu.Lock()
	consoles := len(s.hub.subs[s.workspace])
	s.hub.mu.Unlock()
	wait := max(settle, minGap-time.Since(s.sent))
	return wait + rand.N(min(time.Duration(consoles+1)*spread, maxSpread)) //nolint:gosec // jitter, not a secret
}

func (s *Sub) take() Change {
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	c := Change{Everything: s.everything}
	if !c.Everything {
		c.Services = slices.Sorted(maps.Keys(s.services))
	}
	clear(s.services)
	s.everything = false
	// What woke the stream during the wait is in c already.
	select {
	case <-s.wake:
	default:
	}
	return c
}

// poke needs the hub's lock, so take never drops a change it did not return.
func (s *Sub) poke() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
