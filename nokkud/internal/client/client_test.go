package client

import (
	"errors"
	"fmt"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
)

// The code is read through the way UploadPending wraps it.
func TestUploadRetryWait(t *testing.T) {
	full := connect.NewError(connect.CodeResourceExhausted, errors.New("the workspace is full"))
	down := connect.NewError(connect.CodeUnavailable, errors.New("backend down"))

	assert.Equal(t, retryUploadsEvery, uploadRetryWait(nil), "nothing left to upload")
	assert.Equal(t, retryUploadsEvery, uploadRetryWait(fmt.Errorf("upload a.cast.gz: %w", down)))
	assert.Equal(t, retryUploadsWhenFull,
		uploadRetryWait(fmt.Errorf("upload a.cast.gz: %w", errors.Join(errors.New("EOF"), full))))
}
