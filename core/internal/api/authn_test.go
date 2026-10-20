package api

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"

	"github.com/nokku-sh/nokku/core/internal/iam"
)

// Clients end their session on Unauthenticated, so only a refused credential may answer with it.
func TestAuthFailureCodes(t *testing.T) {
	a := &authNInterceptor{}

	err := a.fail(t.Context(), nil, fmt.Errorf("load token: %w", iam.ErrInactive))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "a refused credential")

	err = a.fail(t.Context(), nil, fmt.Errorf("load token: %w", context.DeadlineExceeded))
	assert.Equal(t, connect.CodeDeadlineExceeded, connect.CodeOf(err), "a slow database")

	err = a.fail(t.Context(), nil, errors.New("failed to connect to `user=nokku database=nokku`"))
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err), "a database that is away")
	assert.NotContains(t, err.Error(), "user=nokku", "the driver error reached the caller")
}
