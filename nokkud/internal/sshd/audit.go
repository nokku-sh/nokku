package sshd

import "golang.org/x/crypto/ssh"

// Operators filter the "audit" log lines on the type, keep the names stable.
type eventType string

const (
	eventAuthSuccess       eventType = "auth_success"
	eventAuthFailure       eventType = "auth_failure"
	eventSessionStart      eventType = "session_start"
	eventSessionEnd        eventType = "session_end"
	eventCommand           eventType = "command"
	eventSubsystem         eventType = "subsystem"
	eventForward           eventType = "forward"
	eventRemoteForward     eventType = "remote_forward"
	eventRecordingDegraded eventType = "recording_degraded"
)

type auditEvent struct {
	Type      eventType
	User      string
	Remote    string
	Client    string
	Principal string
	SessionID string
	Command   string
	// What the client asked for when a force-command replaced it.
	OriginalCommand string
	Target          string
	Error           string
	ExitCode        int
}

func connEvent(conn ssh.ConnMetadata, typ eventType) auditEvent {
	return auditEvent{
		Type:   typ,
		User:   conn.User(),
		Remote: conn.RemoteAddr().String(),
		Client: string(conn.ClientVersion()),
	}
}

func (s *Server) emit(ev auditEvent) {
	args := []any{"type", string(ev.Type)}
	for _, field := range [][2]string{
		{"user", ev.User},
		{"remote", ev.Remote},
		{"client", ev.Client},
		{"principal", ev.Principal},
		{"session_id", ev.SessionID},
		{"command", ev.Command},
		{"original_command", ev.OriginalCommand},
		{"target", ev.Target},
		{"error", ev.Error},
	} {
		if field[1] != "" {
			args = append(args, field[0], field[1])
		}
	}
	if ev.Type == eventSessionEnd {
		args = append(args, "exit_code", ev.ExitCode)
	}
	s.log.Info("audit", args...)
}
