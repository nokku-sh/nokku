package safe

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The packages that run code for a connection, a session or a recording. A goroutine that starts bare there takes
// the daemon down with its panic, and every session on the host with it.
var guarded = []string{"../sshd", "../recording"}

func TestFuncContainsAPanic(t *testing.T) {
	var wg sync.WaitGroup
	wg.Go(Func("test", func() { panic("one goroutine fails") }))
	wg.Wait()

	ran := false
	Func("test", func() { ran = true })()
	assert.True(t, ran, "a function that does not panic must still run")
}

// Every go statement, WaitGroup.Go and AfterFunc in those packages runs a safe.Func.
func TestEveryGoroutineIsGuarded(t *testing.T) {
	isSafe := func(e ast.Expr) bool {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		pkg, _ := sel.X.(*ast.Ident)
		return ok && pkg != nil && pkg.Name == "safe" && sel.Sel.Name == "Func"
	}
	for _, dir := range guarded {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		require.NoError(t, err)
		require.NotEmpty(t, files, "%s has no Go files, was it moved?", dir)
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			fset := token.NewFileSet()
			f, parseErr := parser.ParseFile(fset, file, nil, 0)
			require.NoError(t, parseErr)
			ast.Inspect(f, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.GoStmt:
					assert.True(t, isSafe(n.Call.Fun), "%s: a bare go statement", fset.Position(n.Pos()))
				case *ast.CallExpr:
					sel, ok := n.Fun.(*ast.SelectorExpr)
					if !ok || (sel.Sel.Name != "Go" && sel.Sel.Name != "AfterFunc") {
						return true
					}
					fn := n.Args[len(n.Args)-1]
					assert.True(t, isSafe(fn), "%s: %s runs a bare function", fset.Position(n.Pos()), sel.Sel.Name)
				}
				return true
			})
		}
	}
}
