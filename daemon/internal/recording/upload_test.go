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

// Once the session ends, the core has the whole file and the local copy goes.
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

// A crash leaves a .part file flushed to the last tick, with no gzip footer.
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

// Not a test: the daemon that the crash test above kills mid-session.
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

// A deploy breaks the live upload. It returns while the session still runs.
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

// The recording stops where the disk did and the session hears of it.
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
	// Past RLIMIT_FSIZE writes fail like a full disk. Go ignores the SIGXFSZ.
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

// The size cap closes the gzip stream, but the recording is still cut.
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

// A stalled upload costs the recording nothing, it reads the file at its pace.
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

// Without a readable header a file cannot be named to the core, so it stays.
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

// The final message has the session's end, a leftover's is its last write.
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

// A file that cannot be opened now is tried again later, and is not deleted.
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

// The answer decides, not where the stream broke. Big files get the same one.
func TestCoreAnswerDecidesWhatHappensToTheFile(t *testing.T) {
	fastRetries(t)
	big := make([][]byte, 200)
	for i := range big {
		big[i] = noiseLine(24 << 10)
	}

	refused := connect.NewError(connect.CodeInvalidArgument, "the principal does not match")
	for name, lines := range map[string][][]byte{"refused small": nil, "refused big": big} {
		t.Run(name, func(t *testing.T) {
			newRecordsDir(t)
			rec, calls := uploadAnswered(t, lines, []error{refused})
			time.Sleep(200 * time.Millisecond)
			assert.FileExists(t, rec.path, "a refused file was deleted, its only copy")
			assert.EqualValues(t, 1, calls.Load(), "a refused file was sent again")
		})
	}

	// No error code deletes the only copy, whatever layer of the core sent it.
	exists := connect.NewError(connect.CodeAlreadyExists, "a record with this value already exists")
	t.Run("an error that reads like success", func(t *testing.T) {
		newRecordsDir(t)
		rec, _ := uploadAnswered(t, nil, []error{exists, exists, exists})
		assert.FileExists(t, rec.path, "an error deleted the file")
	})

	// Big: the answer comes while the daemon still sends.
	whole := errWhole
	trouble := connect.NewError(connect.CodeInternal, "internal error")
	full := connect.NewError(connect.CodeResourceExhausted, "the workspace is full")
	nonce := connect.NewError(connect.CodeUnauthenticated, "dpop: nonce required")
	for name, tc := range map[string]struct {
		lines   [][]byte
		answers []error
	}{
		"whole already, small":         {nil, []error{whole}},
		"whole already, big":           {big, []error{whole}},
		"core trouble is tried again":  {nil, []error{trouble, trouble, nil}},
		"a full workspace waits, then": {nil, []error{full, full, nil}},
		"a stale nonce is tried again": {nil, []error{nonce, nonce, nil}},
	} {
		t.Run(name, func(t *testing.T) {
			dir := newRecordsDir(t)
			uploadAnswered(t, tc.lines, tc.answers)
			require.Eventually(t, func() bool {
				left, _ := os.ReadDir(dir)
				return len(left) == 0
			}, 5*time.Second, 10*time.Millisecond, "the file stayed, the core holds it")
		})
	}
}

// "Whole already" about a session that still writes can't be true. The file
// stays and the upload stops, the next start sends it.
func TestWholeAlreadyKeepsAFileStillWritten(t *testing.T) {
	dir := newRecordsDir(t)
	fastRetries(t)
	calls := new(atomic.Int32)
	core := newFakeCore(t, func(context.Context, *nokkuv1.RecordingMeta) error {
		calls.Add(1)
		return errWhole
	})

	rec := newRecorder(t, Options{Uploads: startUploads(t, core)})
	require.Eventually(t, func() bool { return calls.Load() == 1 }, 5*time.Second, 10*time.Millisecond)
	// The answer shows on the next send, which a flush sets off.
	rec.RecordOutput([]byte("typed after the answer"))
	waitOnDisk(t, rec.path, "typed after the answer")
	time.Sleep(200 * time.Millisecond)
	rec.RecordExit(0)
	rec.Close()

	time.Sleep(200 * time.Millisecond)
	left, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, left, 1, "the file of a session that still wrote was deleted")
	assert.EqualValues(t, 1, calls.Load(), "the upload went on after the core's answer")
}

// uploadAnswered sends a closed recording to a core that answers each try from
// answers, repeating the last, and waits for all of them.
func uploadAnswered(t *testing.T, lines [][]byte, answers []error) (*Recorder, *atomic.Int32) {
	t.Helper()
	rec := newRecorder(t, Options{})
	for _, line := range lines {
		rec.RecordOutput(line)
	}
	rec.RecordExit(0)
	rec.Close()
	calls := new(atomic.Int32)
	core := newFakeCore(t, func(context.Context, *nokkuv1.RecordingMeta) error {
		return answers[min(int(calls.Add(1)), len(answers))-1]
	})

	startUploads(t, core)
	require.Eventually(t, func() bool { return int(calls.Load()) >= len(answers) },
		5*time.Second, 10*time.Millisecond, "the core never got %d tries", len(answers))
	return rec, calls
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
