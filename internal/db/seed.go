package db

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed schema/seed/*.sql
var seedFS embed.FS

func (c *Connection) seed(ctx context.Context) error {
	queries, err := loadSeedFiles(seedFS)
	if err != nil {
		return fmt.Errorf("loading seed files: %w", err)
	}

	tx, err := c.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, q := range queries {
		if _, err := tx.Exec(ctx, q); err != nil {
			return fmt.Errorf("executing seed: %w", err)
		}
	}

	return tx.Commit(ctx)
}

func loadSeedFiles(fsys embed.FS) ([]string, error) {
	var files []string

	err := fs.WalkDir(fsys, "schema/seed", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".sql") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Strings(files)

	var queries []string
	for _, f := range files {
		content, err := fsys.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f, err)
		}
		queries = append(queries, string(content))
	}

	return queries, nil
}
