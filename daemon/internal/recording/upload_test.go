package recording

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

// The upload follows the file while the session writes it. Once the session ends, the core has the whole file and
// the local copy goes.
func TestLiveUploadFollowsTheFile(t *testing.T) {
	dir := newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)
	core := newFakeCore(t, nil)

	rec := newRecorder(t, Options{Principal: "principal-of-alice", Uploads: startUploads(t, core)})
	rec.RecordOutput([]byte("typed during the session"))
	core.waitReceived(t, "typed during the session")
	is.Nil(core.snapshot()[0].final, "the upload finished while the session ran")
	rec.RecordExit(0)
	rec.Close()

	uploads := core.waitFinal(t, 1)
	up := uploads[0]
	is.Equal(rec.header.SessionID, up.meta.GetRecordingId())
	is.Equal("alice", up.meta.GetUsername())
	is.Equal("principal-of-alice", up.meta.GetPrincipal())
	is.WithinDuration(time.Now(), up.meta.GetStartedAt().AsTime(), time.Minute)
	is.True(up.complete(), "a whole recording did not go up complete: %v", up.final)
	text, err := unzipCast(up.data)
	must.NoError(err, "the upload is a whole gzip stream")
	is.Contains(text, `"x", "0"`)
	require.Eventually(t, func() bool {
		left, _ := os.ReadDir(dir)
		return len(left) == 0
	}, 5*time.Second, 10*time.Millisecond, "the uploaded recording stayed on disk")
}

// A daemon that dies mid-session leaves the file flushed up to the last tick, with no gzip footer, under its .part
// name. The next start sends it as a cut recording.
func TestDaemonCrashMidSessionSendsTheLeftoverCut(t *testing.T) {
	dir := newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)
	core := newFakeCore(t, nil)

	child := exec.Command(os.Args[0], "-test.run=^TestRecordingProcess$")
	child.Env = append(os.Environ(), "NOKKU_TEST_CORE="+core.url)
	must.NoError(child.Start())
	t.Cleanup(func() { _ = child.Process.Kill() })
	core.waitReceived(t, "typed before the crash")
	must.NoError(child.Process.Kill())
	_ = child.Wait()
	require.Eventually(t, func() bool {
		uploads := core.snapshot()
		return len(uploads) == 1 && uploads[0].err != nil
	}, 5*time.Second, 10*time.Millisecond, "the core never saw the live stream break")
	files, err := filepath.Glob(filepath.Join(dir, "*"+partSuffix))
	must.NoError(err)
	must.Len(files, 1, "the crash left no .part file")
	leftover, err := os.ReadFile(files[0])
	must.NoError(err)

	startUploads(t, core)
	uploads := core.waitFinal(t, 2)
	live, retry := uploads[0], uploads[1]
	is.Nil(live.final)
	is.Equal(live.meta.GetRecordingId(), retry.meta.GetRecordingId(), "the retry names the same recording")
	is.Equal(leftover, retry.data, "the leftover is sent byte for byte")
	is.False(retry.complete(), "a crash leftover went up complete")
	is.Equal(leftoverReason, retry.final.GetCutReason())
	is.EqualValues(len(leftover), retry.final.GetSizeBytes())
	text, err := unzipCast(retry.data)
	must.ErrorIs(err, io.ErrUnexpectedEOF, "the leftover has no gzip footer")
	is.Contains(text, "typed before the crash")
	is.NotContains(text, `"x"`)
	require.Eventually(t, func() bool {
		left, _ := os.ReadDir(dir)
		return len(left) == 0
	}, 5*time.Second, 10*time.Millisecond, "the core holds all of the leftover, yet it stayed on disk")
}

// Not a test: the daemon TestDaemonCrashMidSessionSendsTheLeftoverCut kills mid-session.
func TestRecordingProcess(t *testing.T) {
	url := os.Getenv("NOKKU_TEST_CORE")
	if url == "" {
		t.Skip("only runs as the daemon of the crash test")
	}
	rec, err := New(Options{
		Width: 80, Height: 24, SessionID: testID, User: "alice",
		Uploads: NewUploads(t.Context(), coreClient(url)),
	})
	require.NoError(t, err)
	rec.RecordOutput([]byte("typed before the crash"))
	time.Sleep(time.Minute)
}

// A deploy breaks the live upload. The upload comes back while the session still runs and ends whole.
func TestCoreRestartMidSessionEndsWhole(t *testing.T) {
	dir := newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)
	fastRetries(t)
	core := newFakeCore(t, nil)

	rec := newRecorder(t, Options{Uploads: startUploads(t, core)})
	rec.RecordOutput([]byte("before the restart"))
	core.waitReceived(t, "before the restart")
	core.restart(t)
	rec.RecordOutput([]byte("after the restart"))
	core.waitReceived(t, "after the restart")
	is.GreaterOrEqual(len(core.snapshot()), 2, "the upload did not come back during the session")
	rec.RecordExit(0)
	rec.Close()

	uploads := core.snapshot()
	last := core.waitFinal(t, len(uploads))[len(uploads)-1]
	must.Error(uploads[0].err, "the core saw the first stream break")
	is.True(last.complete(), "the recording did not end whole: %v", last.final)
	text, err := unzipCast(last.data)
	must.NoError(err)
	is.Contains(text, "before the restart", "the new stream starts at the first byte")
	is.Contains(text, `"x", "0"`)
	require.Eventually(t, func() bool {
		left, _ := os.ReadDir(dir)
		return len(left) == 0
	}, 5*time.Second, 10*time.Millisecond)
}

// The disk fills mid-session. The recording stops where the disk did, the session hears of it, and the core gets
// what is on disk as a cut recording.
func TestFullDiskMidSessionSendsWhatIsOnDisk(t *testing.T) {
	dir := newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)
	core := newFakeCore(t, nil)
	cuts := make(chan error, 2)

	rec := newRecorder(t, Options{Uploads: startUploads(t, core), OnCut: func(err error) { cuts <- err }})
	rec.RecordOutput([]byte("before the disk filled"))
	waitOnDisk(t, rec.path, "before the disk filled")

	const fileLimit = 64 << 10
	var limit syscall.Rlimit
	must.NoError(syscall.Getrlimit(syscall.RLIMIT_FSIZE, &limit))
	lowered := limit
	lowered.Cur = fileLimit
	// A write past RLIMIT_FSIZE fails with EFBIG like on a full disk. Go ignores the SIGXFSZ that comes with it.
	must.NoError(syscall.Setrlimit(syscall.RLIMIT_FSIZE, &lowered))
	for range 20 {
		rec.RecordOutput(noiseLine(8 << 10))
	}
	select {
	case err := <-cuts:
		must.ErrorContains(err, "write failed")
	case <-time.After(5 * time.Second):
		t.Fatal("the session never heard that the recording stopped")
	}
	must.NoError(syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit))
	rec.RecordOutput([]byte("after the disk filled"))
	rec.RecordExit(0)
	rec.Close()
	is.Empty(cuts, "a cut was reported twice")

	up := core.waitFinal(t, 1)[0]
	is.False(up.complete(), "a cut recording went up complete")
	is.True(strings.HasPrefix(up.final.GetCutReason(), "write failed: "), "reason %q", up.final.GetCutReason())
	is.EqualValues(len(up.data), up.final.GetSizeBytes(), "the core got all that is on disk")
	is.LessOrEqual(len(up.data), fileLimit)
	text, err := unzipCast(up.data)
	must.ErrorIs(err, io.ErrUnexpectedEOF, "the cut file has no gzip footer")
	is.Contains(text, "before the disk filled")
	is.NotContains(text, "after the disk filled")
	require.Eventually(t, func() bool {
		left, _ := os.ReadDir(dir)
		return len(left) == 0
	}, 5*time.Second, 10*time.Millisecond)
}

// The daemon's own size cap closes the gzip stream, but the recording is still cut.
func TestSizeCapSendsTheRecordingCut(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	newRecordsDir(t)
	core := newFakeCore(t, nil)
	cuts := make(chan error, 1)

	rec := newRecorder(t, Options{
		Uploads: startUploads(t, core),
		MaxSize: 1024,
		OnCut:   func(err error) { cuts <- err },
	})
	must.Eventually(func() bool {
		rec.RecordOutput(noiseLine(4 << 10))
		return len(cuts) > 0
	}, 5*time.Second, 5*time.Millisecond, "the cap never fired")
	must.ErrorIs(<-cuts, ErrSizeLimit)

	up := core.waitFinal(t, 1)[0]
	text, err := unzipCast(up.data)
	must.NoError(err, "the capped recording is a whole gzip stream")
	is.NotContains(text, `"x"`, "a capped recording has no exit event")
	is.False(up.complete(), "a capped recording went up complete")
	is.Equal(ErrSizeLimit.Error(), up.final.GetCutReason())
}

// A core that stalls the live upload never costs the recording a byte, the upload reads the file at its own pace.
func TestStalledCoreGetsTheWholeFile(t *testing.T) {
	newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)
	release := make(chan struct{})
	core := newFakeCore(t, func(ctx context.Context, _ *nokkuv1.RecordingMeta) error {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	})

	rec := newRecorder(t, Options{Uploads: startUploads(t, core)})
	for range 200 {
		rec.RecordOutput(noiseLine(24 << 10))
	}
	rec.RecordExit(0)
	path := rec.path
	rec.Close()
	must.NotEqual(path, rec.path, "a whole recording kept its .part name")
	file, err := os.ReadFile(rec.path)
	must.NoError(err)
	close(release)

	up := core.waitFinal(t, 1)[0]
	is.Equal(file, up.data, "the core did not get the file byte for byte")
	is.True(up.complete())
}

// A file without a readable header cannot be named to the core. It stays on disk for someone to look at.
func TestUnreadableLeftoverStaysOnDisk(t *testing.T) {
	for name, content := range map[string][]byte{
		"empty, a crash before the header": nil,
		"not gzip":                         []byte("not a recording"),
		"no session id":                    gzipText(t, `{"version":3,"term":{"cols":80,"rows":24}}`+"\n"),
	} {
		t.Run(name, func(t *testing.T) {
			dir := newRecordsDir(t)
			core := newFakeCore(t, nil)
			path := filepath.Join(dir, testID+partSuffix)
			require.NoError(t, os.WriteFile(path, content, 0o600))

			startUploads(t, core).Wait(time.Second)
			assert.Empty(t, core.snapshot(), "the core heard of it")
			assert.FileExists(t, path)
		})
	}
}

// The last message says when the session ended, a late upload does not move that. A leftover has its last write.
func TestFinalNamesWhenTheSessionEnded(t *testing.T) {
	dir := newRecordsDir(t)
	core := newFakeCore(t, nil)
	path := filepath.Join(dir, testID+partSuffix)
	require.NoError(t, os.WriteFile(path, gzipText(t, `{"version":3,"session_id":"`+testID+`"}`+"\n"), 0o600))
	lastWrite := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	require.NoError(t, os.Chtimes(path, lastWrite, lastWrite))

	uploads := startUploads(t, core)
	leftover := core.waitFinal(t, 1)[0]
	assert.WithinDuration(t, lastWrite, leftover.final.GetEndedAt().AsTime(), time.Second)

	before := time.Now()
	rec := newRecorder(t, Options{Uploads: uploads})
	rec.Close()
	live := core.waitFinal(t, 2)[1]
	assert.WithinDuration(t, before, live.final.GetEndedAt().AsTime(), 5*time.Second)
}

// A file the daemon cannot open now is tried again later, and never deleted for it.
func TestLeftoverThatCannotBeOpenedIsTriedAgain(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens a file whatever its mode")
	}
	dir := newRecordsDir(t)
	fastRetries(t)
	rec := newRecorder(t, Options{})
	rec.RecordExit(0)
	rec.Close()
	require.NoError(t, os.Chmod(rec.path, 0))
	core := newFakeCore(t, nil)

	startUploads(t, core)
	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, core.snapshot())
	assert.FileExists(t, rec.path)
	require.NoError(t, os.Chmod(rec.path, 0o600))
	assert.True(t, core.waitFinal(t, 1)[0].complete(), "a whole leftover went up cut")
	require.Eventually(t, func() bool {
		left, _ := os.ReadDir(dir)
		return len(left) == 0
	}, 5*time.Second, 10*time.Millisecond)
}

// The answer decides, not where the stream broke: a big file gets the same answer as a small one.
func TestCoreAnswerDecidesWhatHappensToTheFile(t *testing.T) {
	fastRetries(t)
	big := make([][]byte, 200)
	for i := range big {
		big[i] = noiseLine(24 << 10)
	}
	for name, tc := range map[string]struct {
		answer   error
		size     [][]byte
		keep     bool
		attempts int
	}{
		"refused small":                {connect.NewError(connect.CodeInvalidArgument, "the principal does not match"), nil, true, 1},
		"refused big":                  {connect.NewError(connect.CodeInvalidArgument, "the principal does not match"), big, true, 1},
		"whole already, small":         {connect.NewError(connect.CodeAlreadyExists, "recording is already finalized"), nil, false, 1},
		"whole already, big":           {connect.NewError(connect.CodeAlreadyExists, "recording is already finalized"), big, false, 1},
		"core trouble is tried again":  {connect.NewError(connect.CodeInternal, "internal error"), nil, false, 3},
		"a full workspace waits, then": {connect.NewError(connect.CodeResourceExhausted, "the workspace is full"), nil, false, 3},
		"a stale nonce is tried again": {connect.NewError(connect.CodeUnauthenticated, "dpop: nonce required"), nil, false, 3},
	} {
		t.Run(name, func(t *testing.T) {
			dir := newRecordsDir(t)
			rec := newRecorder(t, Options{})
			for _, line := range tc.size {
				rec.RecordOutput(line)
			}
			rec.RecordExit(0)
			rec.Close()
			var calls atomic.Int32
			core := newFakeCore(t, func(context.Context, *nokkuv1.RecordingMeta) error {
				if int(calls.Add(1)) < tc.attempts {
					return tc.answer
				}
				if tc.attempts == 1 {
					return tc.answer
				}
				return nil
			})

			startUploads(t, core)
			require.Eventually(t, func() bool { return int(calls.Load()) >= tc.attempts },
				5*time.Second, 10*time.Millisecond, "the core never got %d tries", tc.attempts)
			if tc.keep {
				time.Sleep(200 * time.Millisecond)
				assert.FileExists(t, rec.path, "a refused file was deleted, its only copy")
				assert.EqualValues(t, 1, calls.Load(), "a refused file was sent again")
				return
			}
			require.Eventually(t, func() bool {
				left, _ := os.ReadDir(dir)
				return len(left) == 0
			}, 5*time.Second, 10*time.Millisecond, "the file stayed, the core holds it")
		})
	}
}

// Stopping the daemon ends the retries. The file stays for the next start.
func TestShutdownEndsTheRetries(t *testing.T) {
	newRecordsDir(t)
	rec := newRecorder(t, Options{})
	rec.RecordExit(0)
	rec.Close()
	core := newFakeCore(t, func(context.Context, *nokkuv1.RecordingMeta) error {
		return connect.NewError(connect.CodeUnavailable, "core restarting")
	})

	ctx, cancel := context.WithCancel(t.Context())
	u := NewUploads(ctx, core.client)
	require.Eventually(t, func() bool { return len(core.snapshot()) == 1 }, 5*time.Second, 10*time.Millisecond)
	cancel()
	assert.True(t, u.Wait(time.Second), "an upload kept retrying past shutdown")
	assert.FileExists(t, rec.path)
}
