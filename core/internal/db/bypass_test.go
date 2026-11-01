package db

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every query past workspace isolation, as nokku_system, in one reviewed list.
// A new one fails here until someone looked at it. UPDATE_GOLDEN=1 writes the
// file.
func TestEveryIsolationBypassIsReviewed(t *testing.T) {
	var lines, loose []string
	for _, root := range []string{"..", "../../cmd"} {
		require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			reviewed, handles := bypasses(t, path)
			lines, loose = append(lines, reviewed...), append(loose, handles...)
			return nil
		}))
	}
	assert.Empty(t, loose, "call Sys and SysTx on the spot, this list can't see what a kept handle runs")
	slices.Sort(lines)
	got := strings.Join(lines, "\n") + "\n"
	golden := filepath.Join("testdata", "bypass.golden")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.MkdirAll("testdata", 0o750))
		require.NoError(t, os.WriteFile(golden, []byte(got), 0o600))
	}
	want, err := os.ReadFile(golden)
	require.NoError(t, err, "no golden file yet, run with UPDATE_GOLDEN=1")
	assert.Equal(
		t,
		string(want),
		got,
		"a query runs past workspace isolation, review it and rerun with UPDATE_GOLDEN=1",
	)
}

// bypasses scans one file of the core, named by its path from there.
func bypasses(t *testing.T, path string) (lines, loose []string) {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	require.NoError(t, err)
	core, err := filepath.Abs("../..")
	require.NoError(t, err)
	abs, err := filepath.Abs(path)
	require.NoError(t, err)
	name, err := filepath.Rel(core, abs)
	require.NoError(t, err)
	lines, loose = scanBypasses(file, name)
	return lines, loose
}

// scanBypasses lists the Sys() queries of file, and for each SysTx the queries
// its closure runs. Any other use of Sys or SysTx comes back as loose, a handle
// that is kept or passed on would run queries this list can't see.
func scanBypasses(file *ast.File, name string) (lines, loose []string) {
	for _, decl := range file.Decls {
		where := name
		if fn, ok := decl.(*ast.FuncDecl); ok {
			where += " " + funcName(fn)
		}
		onTheSpot := map[ast.Expr]bool{}
		ast.Inspect(decl, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				sel, ok := n.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if inner, ok := sel.X.(*ast.CallExpr); ok && selectorName(inner.Fun) == "Sys" {
					onTheSpot[inner.Fun] = true
					lines = append(lines, fmt.Sprintf("%s Sys %s", where, sel.Sel.Name))
				}
				if sel.Sel.Name == "SysTx" && len(n.Args) == 2 {
					onTheSpot[sel] = true
					lines = append(lines, fmt.Sprintf("%s SysTx %s", where, strings.Join(txQueries(n.Args[1]), ",")))
				}
			case *ast.SelectorExpr:
				if (n.Sel.Name == "Sys" || n.Sel.Name == "SysTx") && !onTheSpot[n] {
					loose = append(loose, fmt.Sprintf("%s %s", where, n.Sel.Name))
				}
			}
			return true
		})
	}
	return lines, loose
}

// The scan is a security gate, so it is tested too. Each loose form runs a real
// bypass the list above would not show.
func TestBypassScan(t *testing.T) {
	for name, tc := range map[string]struct {
		src   string
		lines []string
		loose []string
	}{
		"on the spot": {
			src:   `func f() { conn.Sys().GetX(ctx) }`,
			lines: []string{"p.go f Sys GetX"},
		},
		"a transaction": {
			src:   `func f() { conn.SysTx(ctx, func(q *Queries) error { return q.GetY(ctx) }) }`,
			lines: []string{"p.go f SysTx GetY"},
		},
		"kept in a variable": {
			src:   `func f() { q := conn.Sys(); q.GetX(ctx) }`,
			loose: []string{"p.go f Sys"},
		},
		"kept in a field": {
			src:   `func (s *S) f() { s.q = conn.Sys() }`,
			loose: []string{"p.go S.f Sys"},
		},
		"handed to a helper": {
			src:   `func f() { helper(conn.Sys()) }`,
			loose: []string{"p.go f Sys"},
		},
		"a method value": {
			src:   `func f() { sys := conn.Sys; sys().GetX(ctx) }`,
			loose: []string{"p.go f Sys"},
		},
		"a transaction as a method value": {
			src:   `func f() { tx := conn.SysTx; tx(ctx, nil) }`,
			loose: []string{"p.go f SysTx"},
		},
		"in parentheses": {
			src:   `func f() { (conn.Sys()).GetX(ctx) }`,
			loose: []string{"p.go f Sys"},
		},
		"at package level": {
			src:   `var q = conn.Sys()`,
			loose: []string{"p.go Sys"},
		},
		"a query at package level": {
			src:   `var x, _ = conn.Sys().GetX(ctx)`,
			lines: []string{"p.go Sys GetX"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "p.go", "package p\n"+tc.src, 0)
			require.NoError(t, err)
			lines, loose := scanBypasses(file, "p.go")
			assert.Equal(t, tc.lines, lines)
			assert.Equal(t, tc.loose, loose)
		})
	}
}

func funcName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	typ := fn.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	if ident, ok := typ.(*ast.Ident); ok {
		return ident.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}

func selectorName(e ast.Expr) string {
	if sel, ok := e.(*ast.SelectorExpr); ok {
		return sel.Sel.Name
	}
	return ""
}

// txQueries is what a SysTx closure calls on its *Queries, or "?" for a
// function passed by name. A helper the closure hands its *Queries to shows as
// helper(q), its queries are the reviewer's to look up.
func txQueries(arg ast.Expr) []string {
	lit, ok := arg.(*ast.FuncLit)
	if !ok || len(lit.Type.Params.List) == 0 || len(lit.Type.Params.List[0].Names) == 0 {
		return []string{"?"}
	}
	q := lit.Type.Params.List[0].Names[0].Name
	var names []string
	add := func(name string) {
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := n.X.(*ast.Ident); ok && id.Name == q {
				add(n.Sel.Name)
			}
		case *ast.CallExpr:
			for _, a := range n.Args {
				if id, ok := a.(*ast.Ident); ok && id.Name == q {
					add(types.ExprString(n.Fun) + "(q)")
				}
			}
		}
		return true
	})
	slices.Sort(names)
	return names
}
