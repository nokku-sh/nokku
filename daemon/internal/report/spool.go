// Package report keeps the daemon's connection events until the core has them.
package report

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"
)

const (
	// Batch is how many events one report carries, the core takes no more.
	Batch = 100
	// maxEvents is what the spool holds while the core is away, a few megabytes. Past it new events are dropped
	// and counted, the server's own log still has them.
	maxEvents = 10_000
)

// Event is one end of an SSH connection, its open or its close.
type Event struct {
	// The same for both ends of a connection.
	ConnectionID string    `json:"connection_id"`
	Closed       bool      `json:"closed,omitzero"`
	Time         time.Time `json:"time"`
	Principal    string    `json:"principal"`
	KeyID        string    `json:"key_id,omitzero"`
	Remote       string    `json:"remote,omitzero"`
	Client       string    `json:"client,omitzero"`
	Relayed      bool      `json:"relayed,omitzero"`
}

// Spool holds events in memory and in a file with one event per line, so a restart loses none. It is not synced
// to disk on every event. A machine that loses power can lose its last few.
type Spool struct {
	path string

	mu      sync.Mutex
	events  []Event
	dropped uint32
	// ready holds a token after an Add.
	ready chan struct{}
}

// Open reads what an earlier run left. A file it cannot read starts the spool empty, a login never waits on this.
func Open(path string) *Spool {
	s := &Spool{path: path, ready: make(chan struct{}, 1)}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Warn("connection reports of the last run not read", "error", err)
	}
	for line := range bytes.Lines(data) {
		var e Event
		if json.Unmarshal(line, &e) == nil && len(s.events) < maxEvents {
			s.events = append(s.events, e)
		}
	}
	return s
}

// Add never blocks on the core and never fails a login.
func (s *Spool) Add(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) >= maxEvents {
		s.dropped++
		return
	}
	s.events = append(s.events, e)
	if err := s.appendLine(e); err != nil {
		slog.Warn("connection report not saved, a restart would lose it", "error", err)
	}
	select {
	case s.ready <- struct{}{}:
	default:
	}
}

// Ready fires after an Add.
func (s *Spool) Ready() <-chan struct{} { return s.ready }

// Next is the oldest events, a report's worth at most, and how many were dropped so far. They stay until Done.
func (s *Spool) Next() ([]Event, uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.events[:min(len(s.events), Batch)]), s.dropped
}

// Done forgets the n oldest events and that many drops, once the core has them.
func (s *Spool) Done(n int, dropped uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = slices.Delete(s.events, 0, min(n, len(s.events)))
	s.dropped -= min(dropped, s.dropped)
	var rest bytes.Buffer
	for _, e := range s.events {
		line, err := json.Marshal(e)
		if err != nil {
			continue
		}
		rest.Write(line)
		rest.WriteByte('\n')
	}
	// Renamed into place, so a crash leaves the old file or the new one. An event that is in the old file and with
	// the core already is sent again, and the core stores it once.
	tmp := s.path + ".tmp"
	err := os.WriteFile(tmp, rest.Bytes(), 0o600)
	if err == nil {
		err = os.Rename(tmp, s.path)
	}
	if err != nil {
		slog.Warn("connection reports not saved, a restart sends some again", "error", err)
	}
}

func (s *Spool) appendLine(e Event) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
