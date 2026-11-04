// Package tenant puts the workspace on the context before auth runs.
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

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/cache"
	"github.com/nokku-sh/nokku/core/internal/crypto/kms"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
	"github.com/nokku-sh/nokku/core/internal/ssh"
)

const (
	slugCacheTTL     = time.Minute
	slugCacheEntries = 10_000
	// unclaimedAfter frees a squatted slug whose signup nobody signed in to.
	unclaimedAfter = 24 * time.Hour
	purgeEvery     = time.Hour
)

var ErrUnknownWorkspace = errors.New("no such workspace")

// reserved slugs never resolve, so nobody can sign up as app.nokku.sh.
var reserved = map[string]bool{
	"www":     true,
	"app":     true,
	"api":     true,
	"nokku":   true,
	"mizuchi": true,
	"admin":   true,
	"main":    true,
	"mail":    true,
	"static":  true,
	"status":  true,
	"cdn":     true,
	"docs":    true,
}

//go:embed denylist.txt
var denylistFile string

// denylist holds brand and phishing words, refused in a slug at signup.
var denylist = func() []string {
	var out []string
	for line := range strings.SplitSeq(denylistFile, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}()

type envConfig struct {
	WorkspaceName string `env:"NOKKU_WORKSPACE_NAME" envDefault:"Nokku"`
}

type Resolver struct {
	conn   *db.Connection
	saas   bool
	scheme string
	host   string
	port   string
	single actor.Workspace
	slugs  *cache.TTL[string, actor.Workspace]
}

func New(ctx context.Context, conn *db.Connection, keys *kms.Keyset, baseURL string, saas bool) (*Resolver, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return nil, errors.New("tenant: base url needs a scheme and host")
	}
	r := &Resolver{conn: conn, saas: saas, scheme: u.Scheme, host: strings.ToLower(u.Hostname()), port: u.Port()}
	if saas {
		r.slugs = cache.New[string, actor.Workspace](slugCacheEntries, slugCacheTTL)
		go r.purgeUnclaimed(ctx)
		return r, nil
	}

	cfg, err := env.ParseAs[envConfig]()
	if err != nil {
		return nil, err
	}
	ws, err := conn.Sys().GetFirstWorkspace(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		ws, err = Create(ctx, conn, keys, "default", cfg.WorkspaceName)
	}
	if err != nil {
		return nil, err
	}
	r.single = r.workspace(ws)
	return r, nil
}

// Single is the self-host workspace, empty on the hosted service.
func (r *Resolver) Single() actor.Workspace { return r.single }

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

// FromHost returns an empty workspace for the hosted root host, and only it.
func (r *Resolver) FromHost(ctx context.Context, host string) (actor.Workspace, error) {
	if !r.saas {
		return r.single, nil
	}
	host = hostname(host)
	if host == r.host {
		return actor.Workspace{}, nil
	}
	slug, ok := r.slug(host)
	if !ok {
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
	r.slugs.Set(slug, ws)
	return ws, nil
}

// Known is whether FromHost can answer host without the database.
func (r *Resolver) Known(host string) bool {
	if !r.saas {
		return true
	}
	slug, ok := r.slug(hostname(host))
	if !ok {
		return true
	}
	_, cached := r.slugs.Get(slug)
	return cached
}

func hostname(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(host)
}

// slug is false for the root host and for any name no workspace can have.
func (r *Resolver) slug(host string) (string, bool) {
	slug, ok := strings.CutSuffix(host, "."+r.host)
	if !ok || slug == "" || strings.Contains(slug, ".") || reserved[slug] {
		return "", false
	}
	return slug, true
}

// Middleware runs before every handler but health and provider webhooks.
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

// Forget uncaches a deleted workspace, so its name is free at once.
func (r *Resolver) Forget(slug string) {
	if r.slugs != nil {
		r.slugs.Delete(slug)
	}
}

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

// purgeUnclaimed runs hourly, the signup link itself lives for a day.
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

func (r *Resolver) PurgeUnclaimed(ctx context.Context, cutoff time.Time) error {
	return r.conn.SysTx(ctx, func(q *db.Queries) error {
		rows, err := q.ListUnclaimedWorkspaces(ctx, cutoff)
		if err != nil {
			return err
		}
		for _, ws := range rows {
			gone, err := q.DeleteUnclaimedWorkspace(ctx, ws.ID)
			if err != nil {
				return err
			}
			if gone > 0 {
				r.Forget(ws.Slug)
			}
		}
		return nil
	})
}

// Create pins the tx to the new id, so it runs under RLS with no system role.
func Create(ctx context.Context, conn *db.Connection, keys *kms.Keyset, slug, name string) (*db.Workspace, error) {
	id := uuid.NewV7().String()
	ctx = actor.WithWorkspace(ctx, actor.Workspace{ID: id})

	var ws *db.Workspace
	err := conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		ws, err = q.CreateWorkspace(ctx, &db.CreateWorkspaceParams{
			ID:       id,
			Slug:     slug,
			Name:     name,
			Settings: &nokkuv1.WorkspaceSettings{DefaultDaemonConfig: db.DefaultDaemonConfig()},
		})
		if err != nil {
			return err
		}
		if err := q.StartTrial(ctx, &db.StartTrialParams{
			Plan: entitlement.PlanPro,
			Days: entitlement.TrialDays,
		}); err != nil {
			return err
		}
		_, err = ssh.CreateCA(ctx, q, keys, ssh.NewCA())
		return err
	})
	if err != nil {
		return nil, err
	}
	return ws, nil
}
