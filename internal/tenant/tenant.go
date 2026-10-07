// Package tenant resolves the workspace a request runs in. A self-hosted
// server has one, created at boot. The hosted service (NOKKU_SAAS) reads it
// off the subdomain. Either way the workspace is on the context before
// anything authenticates, so nothing downstream ever guesses it.
package tenant

import (
	"context"
	_ "embed"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"uuid"

	"github.com/caarlos0/env/v11"
	"github.com/jackc/pgx/v5"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/cache"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/ssh"
)

var ErrUnknownWorkspace = errors.New("no such workspace")

// reserved slugs never resolve to a workspace, so nobody can sign up as
// app.nokku.sh.
var reserved = map[string]bool{
	"www": true, "app": true, "api": true, "admin": true, "mail": true, "static": true, "status": true,
}

//go:embed denylist.txt
var denylistFile string

// denylist holds brand names and phishing words. A slug containing one of
// them is refused at signup, see Forbidden.
var denylist = func() []string {
	var out []string
	for line := range strings.SplitSeq(denylistFile, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}()

const (
	slugCacheTTL = time.Minute
	// unclaimedAfter is how long a signup may sit without its owner ever
	// signing in before it is purged, so a squatted slug frees itself.
	unclaimedAfter = 24 * time.Hour
	purgeEvery     = time.Hour
)

type envConfig struct {
	WorkspaceName string `env:"NOKKU_WORKSPACE_NAME" envDefault:"Nokku"`
}

type Resolver struct {
	conn   *db.Connection
	saas   bool
	scheme string
	host   string // the root host without port
	port   string
	single actor.Workspace
	slugs  *cache.Local[actor.Workspace]
}

// New in self-host mode makes sure the one workspace exists.
func New(ctx context.Context, conn *db.Connection, baseURL string, saas bool) (*Resolver, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return nil, errors.New("tenant: base url needs a scheme and host")
	}
	r := &Resolver{conn: conn, saas: saas, scheme: u.Scheme, host: strings.ToLower(u.Hostname()), port: u.Port()}
	if saas {
		r.slugs = cache.NewLocal[actor.Workspace](slugCacheTTL)
		go r.purgeUnclaimed(ctx)
		return r, nil
	}

	cfg, err := env.ParseAs[envConfig]()
	if err != nil {
		return nil, err
	}
	ws, err := conn.Sys().GetFirstWorkspace(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		ws, err = Create(ctx, conn, "default", cfg.WorkspaceName)
	}
	if err != nil {
		return nil, err
	}
	r.single = r.workspace(ws)
	return r, nil
}

// Single is the self-host workspace, empty on the hosted service.
func (r *Resolver) Single() actor.Workspace { return r.single }

// BaseURL is where a workspace lives. Self-host ignores the slug.
func (r *Resolver) BaseURL(slug string) string {
	host := r.host
	if r.saas {
		host = slug + "." + r.host
	}
	if r.port != "" {
		host += ":" + r.port
	}
	return r.scheme + "://" + host
}

// FromHost returns an empty workspace for the hosted service's root host,
// the only host that serves anything outside a workspace.
func (r *Resolver) FromHost(ctx context.Context, host string) (actor.Workspace, error) {
	if !r.saas {
		return r.single, nil
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	if host == r.host {
		return actor.Workspace{}, nil
	}
	slug, ok := strings.CutSuffix(host, "."+r.host)
	if !ok || slug == "" || strings.Contains(slug, ".") || reserved[slug] {
		return actor.Workspace{}, ErrUnknownWorkspace
	}
	if ws, ok := r.slugs.Get(slug); ok {
		return ws, nil
	}
	row, err := r.conn.Sys().GetWorkspaceBySlug(ctx, slug)
	if errors.Is(err, pgx.ErrNoRows) {
		return actor.Workspace{}, ErrUnknownWorkspace
	}
	if err != nil {
		return actor.Workspace{}, err
	}
	ws := r.workspace(row)
	r.slugs.Put(slug, ws)
	return ws, nil
}

// Middleware puts the workspace on the context. It runs before every
// handler but the health check and provider webhooks.
func (r *Resolver) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ws, err := r.FromHost(req.Context(), req.Host)
		if errors.Is(err, ErrUnknownWorkspace) {
			http.Error(w, "no such workspace", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if ws.ID != "" {
			req = req.WithContext(actor.WithWorkspace(req.Context(), ws))
		}
		next.ServeHTTP(w, req)
	})
}

func (r *Resolver) workspace(row *db.Workspace) actor.Workspace {
	return actor.Workspace{ID: row.ID, Slug: row.Slug, BaseURL: r.BaseURL(row.Slug)}
}

// Forbidden reports whether a slug may not be signed up with: a reserved
// host, or one that contains a brand or a phishing word from denylist.txt.
func Forbidden(slug string) bool {
	if reserved[slug] {
		return true
	}
	for _, word := range denylist {
		if strings.Contains(slug, word) {
			return true
		}
	}
	return false
}

// purgeUnclaimed deletes hosted signups whose owner never signed in. It
// runs hourly, the signup link itself lives for a day.
func (r *Resolver) purgeUnclaimed(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(purgeEvery):
		}
		if err := r.PurgeUnclaimed(ctx, time.Now().Add(-unclaimedAfter)); err != nil {
			slog.Error("purging unclaimed workspaces failed", "error", err)
		}
	}
}

// PurgeUnclaimed deletes every workspace created before cutoff that nobody
// ever signed in to.
func (r *Resolver) PurgeUnclaimed(ctx context.Context, cutoff time.Time) error {
	return r.conn.WithTx(ctx, func(q *db.Queries) error {
		rows, err := q.ListUnclaimedWorkspaces(ctx, cutoff)
		if err != nil {
			return err
		}
		for _, ws := range rows {
			if err := q.DeleteWorkspace(ctx, ws.ID); err != nil {
				return err
			}
			r.slugs.Delete(ws.Slug)
		}
		return nil
	})
}

// Create makes a workspace with its subscription row and default SSH CA. The
// transaction is pinned to the id the workspace is about to get, so even this
// runs under RLS and needs no system role.
func Create(ctx context.Context, conn *db.Connection, slug, name string) (*db.Workspace, error) {
	ca, err := ssh.NewCA(nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519, 0, 0)
	if err != nil {
		return nil, err
	}
	id := uuid.NewV7().String()
	ctx = actor.WithWorkspace(ctx, actor.Workspace{ID: id})

	var ws *db.Workspace
	err = conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		ws, err = q.CreateWorkspace(ctx, &db.CreateWorkspaceParams{
			ID:       id,
			Slug:     slug,
			Name:     name,
			Settings: &nokkuv1.WorkspaceSettings{DefaultDaemonConfig: db.DefaultDaemonConfig()},
		})
		if err != nil {
			return err
		}
		if err := q.InitSubscription(ctx); err != nil {
			return err
		}
		_, err = q.CreateCA(ctx, &db.CreateCAParams{
			Name:         "Default CA",
			Description:  new("Default CA for " + ws.Name),
			Certificate:  string(ca.Certificate),
			PrivateKey:   ca.PrivateKey,
			PublicKey:    ca.PublicKey,
			SerialNumber: ca.SerialNumber,
			Subject:      ca.Subject,
			IsDefault:    true,
			NotBefore:    ca.NotBefore,
			NotAfter:     ca.NotAfter,
			KeyType:      ca.KeyType,
			KeyBits:      ca.KeyBits,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return ws, nil
}
