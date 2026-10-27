package toolingfuzz

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const toolingInputLimit = 4096

type toolingOutput struct{ body bytes.Buffer }

func (b *toolingOutput) Write(value []byte) (int, error) {
	if b.body.Len()+len(value) > 32<<10 {
		return 0, errors.New("tooling property output budget exceeded")
	}
	return b.body.Write(value)
}

type toolingResult struct {
	Owner    string `json:"owner"`
	Status   string `json:"status"`
	Accepted bool   `json:"accepted"`
	Seed     string `json:"seed,omitempty"`
}

type toolingWorker struct {
	owner      string
	command    *exec.Cmd
	input      io.WriteCloser
	output     *bufio.Reader
	diagnostic toolingOutput
	cancel     context.CancelFunc
	callMu     sync.Mutex
	stopOnce   sync.Once
	stopErr    error
	closed     atomic.Bool
}

// One owned interpreter serves synchronous requests inside the foreground
// native target. Every request reconstructs its fixtures and executes the same
// assertions; importing Python anew must not consume the mutation budget.
func newToolingWorker(t testing.TB, owner string) *toolingWorker {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("the project-required Python interpreter is unavailable")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "tooling_fuzz.py"))
	if err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	// The test context cancels before Cleanup. Keep only bounded teardown
	// independent of that cancellation; each request watches its own test
	// context and promptly stops the process when the request is cancelled.
	ctx, cancel := context.WithCancel(context.WithoutCancel(t.Context()))
	command := exec.CommandContext(ctx, python, "-I", "-B", script, "--owner", owner, "--stream")
	command.Dir = scratch
	command.Env = []string{"PATH=" + filepath.Dir(python), "TMPDIR=" + scratch, "LANG=C.UTF-8"}
	input, err := command.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		_ = input.Close()
		cancel()
		t.Fatal(err)
	}
	worker := &toolingWorker{owner: owner, command: command, input: input,
		output: bufio.NewReaderSize(output, 32<<10+1), cancel: cancel}
	command.Stderr = &worker.diagnostic
	if err := command.Start(); err != nil {
		_ = input.Close()
		_ = output.Close()
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := worker.close(); err != nil && !t.Failed() {
			t.Errorf("tooling worker did not exit cleanly: %v\n%s", err, worker.diagnostic.body.String())
		}
	})
	return worker
}

func (w *toolingWorker) close() error {
	w.stopOnce.Do(func() {
		defer w.closed.Store(true)
		defer w.cancel()
		_ = w.input.Close()
		finished := make(chan error, 1)
		go func() { finished <- w.command.Wait() }()
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case w.stopErr = <-finished:
		case <-timer.C:
			w.cancel()
			w.stopErr = <-finished
			if w.stopErr == nil {
				w.stopErr = errors.New("tooling worker exceeded its shutdown budget")
			}
		}
	})
	return w.stopErr
}

func (w *toolingWorker) call(t testing.TB, raw []byte, mode uint8, seed bool) toolingResult {
	t.Helper()
	w.callMu.Lock()
	defer w.callMu.Unlock()
	if w.closed.Load() {
		// A previous probe already failed and stopped its interpreter. Run
		// each later minimization candidate independently; never retry the
		// failed probe or interpret a closed pipe as a property counterexample.
		return newToolingWorker(t, w.owner).call(t, raw, mode, seed)
	}
	request, err := json.Marshal(struct {
		Raw  string `json:"raw"`
		Mode uint8  `json:"mode"`
		Seed bool   `json:"seed"`
	}{base64.StdEncoding.EncodeToString(raw), mode, seed})
	if err != nil {
		t.Fatal(err)
	}
	type reply struct {
		body []byte
		err  error
	}
	completed := make(chan reply, 1)
	go func() {
		if _, err := w.input.Write(append(request, '\n')); err != nil {
			completed <- reply{err: err}
			return
		}
		body, err := w.output.ReadSlice('\n')
		if len(body) > 32<<10 {
			err = errors.New("tooling response exceeds its output budget")
		}
		completed <- reply{body: append([]byte(nil), body...), err: err}
	}()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	var response reply
	select {
	case response = <-completed:
	case <-timer.C:
		_ = w.close()
		<-completed
		t.Fatal("tooling request exceeded its deadline")
	case <-t.Context().Done():
		_ = w.close()
		<-completed
		t.Fatal("tooling request cancelled")
	}
	if response.err != nil {
		_ = w.close()
		t.Fatalf("%s property failed: %v\n%s", w.owner, response.err, w.diagnostic.body.String())
	}
	decoder := json.NewDecoder(bytes.NewReader(response.body))
	decoder.DisallowUnknownFields()
	var result toolingResult
	if err := decoder.Decode(&result); err != nil || result.Owner != w.owner || result.Status != "passed" {
		t.Fatal("incomplete or invalid tooling property report", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatal("trailing tooling property report")
	}
	return result
}

func toolingSeed(f *testing.F, worker *toolingWorker) []byte {
	f.Helper()
	seed := worker.call(f, nil, 0, true)
	raw, err := base64.StdEncoding.DecodeString(seed.Seed)
	if err != nil || len(raw) == 0 || len(raw) > toolingInputLimit {
		f.Fatal("missing or oversized public/synthetic tooling seed", err)
	}
	for mode := uint8(1); mode < 8; mode++ {
		f.Add(raw, mode)
	}
	extra := worker.call(f, nil, 1, true)
	second, err := base64.StdEncoding.DecodeString(extra.Seed)
	if err != nil || len(second) == 0 || len(second) > toolingInputLimit {
		f.Fatal("missing or oversized secondary tooling seed", err)
	}
	if !bytes.Equal(raw, second) {
		f.Add(second, uint8(1))
	}
	for _, invalid := range []string{"", "null", "[]", `"synthetic"`, "{}"} {
		f.Add([]byte(invalid), uint8(0))
	}
	f.Add([]byte(strings.Repeat("[", 1100)+strings.Repeat("]", 1100)), uint8(0))
	return raw
}

func toolingProperty(t *testing.T, worker *toolingWorker, raw []byte, mode uint8) {
	t.Helper()
	if len(raw) > toolingInputLimit {
		return
	}
	result := worker.call(t, raw, mode, false)
	if result.Accepted && len(raw) == 0 {
		t.Fatal("empty tooling input acquired an accepted interpretation")
	}
}

func FuzzReleaseEvidenceProfile(f *testing.F) {
	worker := newToolingWorker(f, "evidence")
	f.Add(toolingSeed(f, worker), uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) { toolingProperty(t, worker, raw, mode) })
}

func FuzzReleaseChecksums(f *testing.F) {
	worker := newToolingWorker(f, "checksums")
	f.Add(toolingSeed(f, worker), uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) { toolingProperty(t, worker, raw, mode) })
}

func FuzzReleaseArchiveSubjects(f *testing.F) {
	worker := newToolingWorker(f, "archives")
	f.Add(toolingSeed(f, worker), uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) { toolingProperty(t, worker, raw, mode) })
}

func FuzzReleaseSigningPolicy(f *testing.F) {
	worker := newToolingWorker(f, "signing")
	f.Add(toolingSeed(f, worker), uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) { toolingProperty(t, worker, raw, mode) })
}

func FuzzPairedBackupManifest(f *testing.F) {
	worker := newToolingWorker(f, "backup")
	f.Add(toolingSeed(f, worker), uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) { toolingProperty(t, worker, raw, mode) })
}

func FuzzPublicReleaseVerificationBinding(f *testing.F) {
	worker := newToolingWorker(f, "public-release")
	f.Add(toolingSeed(f, worker), uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) { toolingProperty(t, worker, raw, mode) })
}

func TestToolingOutputBudgetCoversCopyFallback(t *testing.T) {
	var output toolingOutput
	_, err := io.Copy(&output, struct{ io.Reader }{bytes.NewReader(make([]byte, 33<<10))})
	if err == nil || output.body.Len() > 32<<10 {
		t.Fatal("copy bypassed the property output budget")
	}
}

func TestToolingWorkerReusesInterpreterAndWaitsAtShutdown(t *testing.T) {
	worker := newToolingWorker(t, "backup")
	first := worker.call(t, nil, 0, true)
	second := worker.call(t, nil, 3, true)
	if first.Seed == "" || first.Seed != second.Seed {
		t.Fatal("shared interpreter changed its fixture identity")
	}
	if err := worker.close(); err != nil {
		t.Fatal(err)
	}
	if worker.command.ProcessState == nil || !worker.command.ProcessState.Exited() {
		t.Fatal("tooling interpreter was not synchronously waited")
	}
}

func TestToolingWorkerRunsLaterProbeAfterInterpreterStops(t *testing.T) {
	worker := newToolingWorker(t, "backup")
	first := worker.call(t, nil, 0, true)
	if err := worker.close(); err != nil {
		t.Fatal(err)
	}
	// Go's minimizer reuses the callback closure after a failed probe. A
	// stopped interpreter must not make unrelated later candidates fail.
	second := worker.call(t, nil, 0, true)
	if first.Seed == "" || first.Seed != second.Seed {
		t.Fatal("later probe did not execute the real property")
	}
}
