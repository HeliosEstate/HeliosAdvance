// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The approved tests for issue #13, written by the QA session from the issue's behaviour
// lines against the lrzsz oracle (oracle/README.md). Every row names the line it proves.
// The oracle is required, not optional: a missing docker is a failure, never a skip,
// because a skipped oracle is a vacuous pass.
package transfer_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/transfer"
)

const image = "heliosestate/lrzsz-oracle:0.1"

// oracle runs one lrzsz command in the container with dir mounted as /data and the
// working directory, and returns the far end of the line plus a wait that reports the
// command's exit and stderr. Closing the writer is how a test hangs up.
func oracle(t *testing.T, dir string, args ...string) (*line, func() (string, error)) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is required: the oracle is lrzsz in a container, and a skipped oracle is a vacuous pass")
	}
	full := append([]string{"run", "--rm", "-i", "-v", dir + ":/data", "-w", "/data", image}, args...)
	cmd := exec.CommandContext(t.Context(), "docker", full...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the oracle: %v", err)
	}
	l := &line{Reader: stdout, WriteCloser: stdin}
	wait := func() (string, error) {
		_ = stdin.Close()
		err := cmd.Wait()
		return stderr.String(), err
	}
	t.Cleanup(func() { _ = stdin.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return l, wait
}

// line is the far end as the module sees it: one reader, one writer.
type line struct {
	io.Reader
	io.WriteCloser
}

// mustWriteRandom writes size random bytes to dir/name with the given mtime.
func mustWriteRandom(t *testing.T, dir, name string, size int, mtime time.Time) string {
	t.Helper()
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustSum(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("reading %s: %v", p, err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func mustStat(t *testing.T, p string) os.FileInfo {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat %s: %v", p, err)
	}
	return fi
}

// A moment with no sub-second part: ZMODEM carries seconds.
var mtime = time.Date(2024, 3, 9, 14, 5, 6, 0, time.UTC)

var sizes = []int{0, 1, 127, 128, 1023, 1024, 1025, 100_000, 1_000_000}

// Line 1: receive from sz, byte-identical, with name, size and modification time.
func TestReceive(t *testing.T) {
	t.Parallel()
	for _, size := range sizes {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			t.Parallel()
			far, recv := t.TempDir(), t.TempDir()
			src := mustWriteRandom(t, far, "payload.bin", size, mtime)
			l, wait := oracle(t, far, "sz", "-b", "-q", "payload.bin")
			got, err := transfer.Receive(t.Context(), l, recv, transfer.Options{})
			if err != nil {
				t.Fatalf("Receive: %v", err)
			}
			if stderr, err := wait(); err != nil {
				t.Fatalf("sz exited %v: %s", err, stderr)
			}
			if len(got) != 1 || got[0].Name != "payload.bin" || got[0].Size != int64(size) {
				t.Fatalf("got %+v, want one file payload.bin of %d bytes", got, size)
			}
			if !got[0].ModTime.Truncate(time.Second).Equal(mtime) {
				t.Fatalf("mtime %v, want %v", got[0].ModTime, mtime)
			}
			if mustSum(t, got[0].Path) != mustSum(t, src) {
				t.Fatal("received bytes differ from the sent file")
			}
			if !mustStat(t, got[0].Path).ModTime().Truncate(time.Second).Equal(mtime) {
				t.Fatal("the stored file's mtime was not set from the header")
			}
		})
	}
}

// Line 2: send to rz, which stores it byte-identical with name, size and mtime.
func TestSend(t *testing.T) {
	t.Parallel()
	for _, size := range sizes {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			t.Parallel()
			ours, far := t.TempDir(), t.TempDir()
			src := mustWriteRandom(t, ours, "payload.bin", size, mtime)
			l, wait := oracle(t, far, "rz", "-b", "-q", "-y")
			if err := transfer.Send(t.Context(), l, []string{src}, transfer.Options{}); err != nil {
				t.Fatalf("Send: %v", err)
			}
			if stderr, err := wait(); err != nil {
				t.Fatalf("rz exited %v: %s", err, stderr)
			}
			dst := filepath.Join(far, "payload.bin")
			if mustSum(t, dst) != mustSum(t, src) {
				t.Fatal("rz stored bytes that differ from the sent file")
			}
			fi := mustStat(t, dst)
			if fi.Size() != int64(size) || !fi.ModTime().Truncate(time.Second).Equal(mtime) {
				t.Fatalf("rz stored size %d mtime %v, want %d %v", fi.Size(), fi.ModTime(), size, mtime)
			}
		})
	}
}

// Line 3: a batch, every file in order, and a clean end after the last.
func TestBatch(t *testing.T) {
	t.Parallel()
	names := []string{"first.bin", "second.bin", "third.bin"}
	t.Run("receive", func(t *testing.T) {
		t.Parallel()
		far, recv := t.TempDir(), t.TempDir()
		for i, n := range names {
			mustWriteRandom(t, far, n, 3000*(i+1), mtime)
		}
		l, wait := oracle(t, far, append([]string{"sz", "-b", "-q"}, names...)...)
		got, err := transfer.Receive(t.Context(), l, recv, transfer.Options{})
		if err != nil {
			t.Fatalf("Receive: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("sz did not end cleanly: %v: %s", err, stderr)
		}
		if len(got) != len(names) {
			t.Fatalf("received %d files, want %d", len(got), len(names))
		}
		for i, n := range names {
			if got[i].Name != n {
				t.Fatalf("file %d is %q, want %q: order not kept", i, got[i].Name, n)
			}
			if mustSum(t, got[i].Path) != mustSum(t, filepath.Join(far, n)) {
				t.Fatalf("%s differs", n)
			}
		}
	})
	t.Run("send", func(t *testing.T) {
		t.Parallel()
		ours, far := t.TempDir(), t.TempDir()
		var paths []string
		for i, n := range names {
			paths = append(paths, mustWriteRandom(t, ours, n, 3000*(i+1), mtime))
		}
		l, wait := oracle(t, far, "rz", "-b", "-q", "-y")
		if err := transfer.Send(t.Context(), l, paths, transfer.Options{}); err != nil {
			t.Fatalf("Send: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("rz did not end cleanly: %v: %s", err, stderr)
		}
		for _, n := range names {
			if mustSum(t, filepath.Join(far, n)) != mustSum(t, filepath.Join(ours, n)) {
				t.Fatalf("%s differs", n)
			}
		}
	})
}

// Line 4: 16-bit CRC where that is what the far end speaks. sz -o sends 16-bit frames;
// our Receive must take them. rz accepts either, so the send half is proved by sending
// with CRC16 set and the file arriving whole; the "32-bit when allowed" half is not
// observable through lrzsz and is listed in the sexyz issue.
func TestCRC16(t *testing.T) {
	t.Parallel()
	t.Run("receive", func(t *testing.T) {
		t.Parallel()
		far, recv := t.TempDir(), t.TempDir()
		src := mustWriteRandom(t, far, "crc.bin", 50_000, mtime)
		l, wait := oracle(t, far, "sz", "-b", "-q", "-o", "crc.bin")
		got, err := transfer.Receive(t.Context(), l, recv, transfer.Options{})
		if err != nil {
			t.Fatalf("Receive with 16-bit CRC frames: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("sz: %v: %s", err, stderr)
		}
		if len(got) != 1 || mustSum(t, got[0].Path) != mustSum(t, src) {
			t.Fatal("file differs")
		}
	})
	t.Run("send", func(t *testing.T) {
		t.Parallel()
		ours, far := t.TempDir(), t.TempDir()
		src := mustWriteRandom(t, ours, "crc.bin", 50_000, mtime)
		l, wait := oracle(t, far, "rz", "-b", "-q", "-y")
		if err := transfer.Send(t.Context(), l, []string{src}, transfer.Options{CRC16: true}); err != nil {
			t.Fatalf("Send with CRC16: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("rz: %v: %s", err, stderr)
		}
		if mustSum(t, filepath.Join(far, "crc.bin")) != mustSum(t, src) {
			t.Fatal("file differs")
		}
	})
}

// everyByte is every byte value, repeated, so every control character and every ZDLE
// crosses the line.
func everyByte(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// Line 5: escaping. sz -e escapes all control characters; rz -e asks us to.
func TestEscape(t *testing.T) {
	t.Parallel()
	t.Run("receive", func(t *testing.T) {
		t.Parallel()
		far, recv := t.TempDir(), t.TempDir()
		src := filepath.Join(far, "ctl.bin")
		if err := os.WriteFile(src, everyByte(64_000), 0o600); err != nil {
			t.Fatal(err)
		}
		l, wait := oracle(t, far, "sz", "-b", "-q", "-e", "ctl.bin")
		got, err := transfer.Receive(t.Context(), l, recv, transfer.Options{Escape: true})
		if err != nil {
			t.Fatalf("Receive escaped: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("sz: %v: %s", err, stderr)
		}
		if len(got) != 1 || mustSum(t, got[0].Path) != mustSum(t, src) {
			t.Fatal("file differs")
		}
	})
	t.Run("send", func(t *testing.T) {
		t.Parallel()
		ours, far := t.TempDir(), t.TempDir()
		src := filepath.Join(ours, "ctl.bin")
		if err := os.WriteFile(src, everyByte(64_000), 0o600); err != nil {
			t.Fatal(err)
		}
		l, wait := oracle(t, far, "rz", "-b", "-q", "-y", "-e")
		if err := transfer.Send(t.Context(), l, []string{src}, transfer.Options{Escape: true}); err != nil {
			t.Fatalf("Send escaped: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("rz: %v: %s", err, stderr)
		}
		if mustSum(t, filepath.Join(far, "ctl.bin")) != mustSum(t, src) {
			t.Fatal("file differs")
		}
	})
}

// Line 6: 8K subpackets. sz --try-8k offers them; we must take them. We offer them to rz.
func Test8K(t *testing.T) {
	t.Parallel()
	t.Run("receive", func(t *testing.T) {
		t.Parallel()
		far, recv := t.TempDir(), t.TempDir()
		src := mustWriteRandom(t, far, "big.bin", 300_000, mtime)
		l, wait := oracle(t, far, "sz", "-b", "-q", "--try-8k", "big.bin")
		got, err := transfer.Receive(t.Context(), l, recv, transfer.Options{})
		if err != nil {
			t.Fatalf("Receive 8K: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("sz: %v: %s", err, stderr)
		}
		if len(got) != 1 || mustSum(t, got[0].Path) != mustSum(t, src) {
			t.Fatal("file differs")
		}
	})
	t.Run("send", func(t *testing.T) {
		t.Parallel()
		ours, far := t.TempDir(), t.TempDir()
		src := mustWriteRandom(t, ours, "big.bin", 300_000, mtime)
		l, wait := oracle(t, far, "rz", "-b", "-q", "-y")
		if err := transfer.Send(t.Context(), l, []string{src}, transfer.Options{SubpacketSize: 8192}); err != nil {
			t.Fatalf("Send 8K: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("rz: %v: %s", err, stderr)
		}
		if mustSum(t, filepath.Join(far, "big.bin")) != mustSum(t, src) {
			t.Fatal("file differs")
		}
	})
}

// corrupting flips one bit in every nth byte it reads, after the first skip bytes so
// the handshake survives. The far end never sees the damage; we do, and must recover.
type corrupting struct {
	io.Reader
	io.WriteCloser
	every, skip int
	n           int
}

func (c *corrupting) Read(p []byte) (int, error) {
	n, err := c.Reader.Read(p)
	for i := 0; i < n; i++ {
		c.n++
		if c.n > c.skip && c.n%c.every == 0 {
			p[i] ^= 0x01
		}
	}
	return n, err
}

// Line 7: a corrupted frame is retransmitted from the last good position.
func TestCorruption(t *testing.T) {
	t.Parallel()
	t.Run("send to a receiver that reports errors", func(t *testing.T) {
		t.Parallel()
		ours, far := t.TempDir(), t.TempDir()
		src := mustWriteRandom(t, ours, "noisy.bin", 200_000, mtime)
		l, wait := oracle(t, far, "rz", "-b", "-q", "-y", "--errors", "7000")
		if err := transfer.Send(t.Context(), l, []string{src}, transfer.Options{}); err != nil {
			t.Fatalf("Send over errors: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("rz: %v: %s", err, stderr)
		}
		if mustSum(t, filepath.Join(far, "noisy.bin")) != mustSum(t, src) {
			t.Fatal("file differs after retransmissions")
		}
	})
	t.Run("receive through a line that corrupts", func(t *testing.T) {
		t.Parallel()
		far, recv := t.TempDir(), t.TempDir()
		src := mustWriteRandom(t, far, "noisy.bin", 200_000, mtime)
		l, wait := oracle(t, far, "sz", "-b", "-q", "noisy.bin")
		bad := &corrupting{Reader: l, WriteCloser: l, every: 9000, skip: 200}
		got, err := transfer.Receive(t.Context(), bad, recv, transfer.Options{})
		if err != nil {
			t.Fatalf("Receive over corruption: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("sz: %v: %s", err, stderr)
		}
		if len(got) != 1 || mustSum(t, got[0].Path) != mustSum(t, src) {
			t.Fatal("file differs after retransmissions")
		}
	})
}

// Line 8: resume from the bytes the receiver already holds.
func TestResume(t *testing.T) {
	t.Parallel()
	t.Run("send to rz -r", func(t *testing.T) {
		t.Parallel()
		ours, far := t.TempDir(), t.TempDir()
		src := mustWriteRandom(t, ours, "part.bin", 150_000, mtime)
		whole, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(far, "part.bin"), whole[:60_000], 0o600); err != nil {
			t.Fatal(err)
		}
		l, wait := oracle(t, far, "rz", "-b", "-q", "-r")
		var reports []transfer.Progress
		var mu sync.Mutex
		opt := transfer.Options{Resume: true, Progress: func(p transfer.Progress) { mu.Lock(); reports = append(reports, p); mu.Unlock() }}
		if err := transfer.Send(t.Context(), l, []string{src}, opt); err != nil {
			t.Fatalf("Send resume: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("rz: %v: %s", err, stderr)
		}
		if mustSum(t, filepath.Join(far, "part.bin")) != mustSum(t, src) {
			t.Fatal("file differs after resume")
		}
		mu.Lock()
		defer mu.Unlock()
		if len(reports) == 0 || reports[0].Done < 60_000 {
			t.Fatalf("the first progress report was %+v; a resume starts at the receiver's position", reports)
		}
	})
	t.Run("receive from sz -r", func(t *testing.T) {
		t.Parallel()
		far, recv := t.TempDir(), t.TempDir()
		src := mustWriteRandom(t, far, "part.bin", 150_000, mtime)
		whole, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(recv, "part.bin"), whole[:60_000], 0o600); err != nil {
			t.Fatal(err)
		}
		l, wait := oracle(t, far, "sz", "-b", "-q", "-r", "part.bin")
		got, err := transfer.Receive(t.Context(), l, recv, transfer.Options{Resume: true})
		if err != nil {
			t.Fatalf("Receive resume: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("sz: %v: %s", err, stderr)
		}
		if len(got) != 1 || got[0].Size != 150_000 || mustSum(t, got[0].Path) != mustSum(t, src) {
			t.Fatal("file differs after resume")
		}
	})
}

// throttled lets through at most n bytes per tick, so a transfer lasts long enough for
// the far end's timed stop to land in the middle of it.
type throttled struct {
	io.Reader
	io.WriteCloser
	n    int
	tick *time.Ticker
}

func (th *throttled) Read(p []byte) (int, error) {
	<-th.tick.C
	if len(p) > th.n {
		p = p[:th.n]
	}
	return th.Reader.Read(p)
}

// Line 9: cancel, from either side.
func TestCancel(t *testing.T) {
	t.Parallel()
	t.Run("ours", func(t *testing.T) {
		t.Parallel()
		ours, far := t.TempDir(), t.TempDir()
		src := mustWriteRandom(t, ours, "long.bin", 2_000_000, mtime)
		l, wait := oracle(t, far, "rz", "-b", "-q", "-y")
		ctx, cancel := context.WithCancel(t.Context())
		var once sync.Once
		opt := transfer.Options{Progress: func(transfer.Progress) { once.Do(cancel) }}
		err := transfer.Send(ctx, l, []string{src}, opt)
		if !errors.Is(err, transfer.ErrCancelled) {
			t.Fatalf("Send after our cancel returned %v, want ErrCancelled", err)
		}
		done := make(chan struct{})
		go func() { _, _ = wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("rz did not stop within five seconds of our cancel sequence")
		}
	})
	t.Run("theirs", func(t *testing.T) {
		t.Parallel()
		far, recv := t.TempDir(), t.TempDir()
		mustWriteRandom(t, far, "long.bin", 2_000_000, mtime)
		l, wait := oracle(t, far, "sz", "-b", "-q", "-s", "+1", "long.bin")
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		slow := &throttled{Reader: l, WriteCloser: l, n: 4096, tick: tick}
		_, err := transfer.Receive(t.Context(), slow, recv, transfer.Options{Timeout: 30 * time.Second})
		if !errors.Is(err, transfer.ErrCancelled) {
			t.Fatalf("Receive after the far end's cancel returned %v, want ErrCancelled", err)
		}
		_, _ = wait()
	})
}

// Line 10: silence past the timeout is an error, never a hang.
func TestTimeout(t *testing.T) {
	t.Parallel()
	far, recv := t.TempDir(), t.TempDir()
	mustWriteRandom(t, far, "late.bin", 1000, mtime)
	l, wait := oracle(t, far, "sz", "-b", "-q", "--delay-startup", "20", "late.bin")
	start := time.Now()
	_, err := transfer.Receive(t.Context(), l, recv, transfer.Options{Timeout: 1 * time.Second})
	if !errors.Is(err, transfer.ErrTimeout) {
		t.Fatalf("Receive from a silent far end returned %v, want ErrTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Receive took %v to time out with a one-second timeout", elapsed)
	}
	_, _ = wait()
}

// Line 11: progress, bytes done of total, per file, monotonic, reaching total.
func TestProgress(t *testing.T) {
	t.Parallel()
	ours, far := t.TempDir(), t.TempDir()
	a := mustWriteRandom(t, ours, "a.bin", 40_000, mtime)
	b := mustWriteRandom(t, ours, "b.bin", 70_000, mtime)
	l, wait := oracle(t, far, "rz", "-b", "-q", "-y")
	var mu sync.Mutex
	last := map[string]transfer.Progress{}
	opt := transfer.Options{Progress: func(p transfer.Progress) {
		mu.Lock()
		defer mu.Unlock()
		if prev, ok := last[p.Name]; ok && p.Done < prev.Done {
			t.Errorf("%s: progress went backwards, %d after %d", p.Name, p.Done, prev.Done)
		}
		last[p.Name] = p
	}}
	if err := transfer.Send(t.Context(), l, []string{a, b}, opt); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if stderr, err := wait(); err != nil {
		t.Fatalf("rz: %v: %s", err, stderr)
	}
	mu.Lock()
	defer mu.Unlock()
	for name, total := range map[string]int64{"a.bin": 40_000, "b.bin": 70_000} {
		p, ok := last[name]
		if !ok {
			t.Fatalf("no progress reported for %s", name)
		}
		if p.Total != total || p.Done != total {
			t.Fatalf("%s: last report %+v, want Done=Total=%d", name, p, total)
		}
	}
}

// Line 12: a ZCOMMAND frame is refused and nothing runs.
func TestRemoteCommandRefused(t *testing.T) {
	t.Parallel()
	far, recv := t.TempDir(), t.TempDir()
	marker := filepath.Join(recv, "pwned")
	l, wait := oracle(t, far, "sz", "-b", "-q", "-c", "touch "+marker)
	_, err := transfer.Receive(t.Context(), l, recv, transfer.Options{})
	if !errors.Is(err, transfer.ErrRemoteCommand) {
		t.Fatalf("Receive of a ZCOMMAND returned %v, want ErrRemoteCommand", err)
	}
	_, _ = wait()
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the remote command ran")
	}
	entries, err := os.ReadDir(recv)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the receive directory is not empty after a refused command: %v", entries)
	}
}

// Line 13: hadv-transfer stands in for sz or rz over stdin and stdout.
func TestCommand(t *testing.T) {
	t.Parallel()
	bin := filepath.Join(t.TempDir(), "hadv-transfer")
	if runtime.GOOS == "windows" {
		bin += ".exe" // exec refuses a path with no extension on Windows
	}
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "../../cmd/hadv-transfer")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building hadv-transfer: %v\n%s", err, out)
	}
	t.Run("as sz", func(t *testing.T) {
		t.Parallel()
		ours, far := t.TempDir(), t.TempDir()
		src := mustWriteRandom(t, ours, "cli.bin", 80_000, mtime)
		l, wait := oracle(t, far, "rz", "-b", "-q", "-y")
		cmd := exec.CommandContext(t.Context(), bin, "-b", "-q", src)
		bridge(t, cmd, l)
		if stderr, err := wait(); err != nil {
			t.Fatalf("rz: %v: %s", err, stderr)
		}
		if mustSum(t, filepath.Join(far, "cli.bin")) != mustSum(t, src) {
			t.Fatal("file differs")
		}
	})
	t.Run("as rz", func(t *testing.T) {
		t.Parallel()
		far, recv := t.TempDir(), t.TempDir()
		src := mustWriteRandom(t, far, "cli.bin", 80_000, mtime)
		l, wait := oracle(t, far, "sz", "-b", "-q", "cli.bin")
		cmd := exec.CommandContext(t.Context(), bin, "-r", "-b", "-q")
		cmd.Dir = recv
		bridge(t, cmd, l)
		if stderr, err := wait(); err != nil {
			t.Fatalf("sz: %v: %s", err, stderr)
		}
		if mustSum(t, filepath.Join(recv, "cli.bin")) != mustSum(t, src) {
			t.Fatal("file differs")
		}
	})
}

// bridge runs cmd with its stdin and stdout joined to the far end, and fails on a
// non-zero exit.
func bridge(t *testing.T, cmd *exec.Cmd, far *line) {
	t.Helper()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = io.Copy(far, stdout); _ = far.Close() }()
	go func() { _, _ = io.Copy(stdin, far); _ = stdin.Close() }()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("hadv-transfer exited %v: %s", err, stderr.String())
	}
}
