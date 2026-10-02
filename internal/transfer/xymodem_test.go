// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The approved tests for issue #14, written by the QA session from the issue's behaviour
// lines against the lrzsz oracle (oracle/README.md), beside the ZMODEM tests whose helpers
// they share. Every row names the line it proves. What lrzsz cannot drive is named where
// the row would be: sx does not honour a receiver's G, sb sends only 1K data blocks, and
// no lrzsz sender refuses C.
package transfer_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/transfer"
)

// xmodemVariants are the issue's three XMODEM variants. The receiver chooses checksum or
// CRC by what it opens with; the sender chooses the block size. sx and rx take the
// matching flags, so each variant is driven from both ends.
var xmodemVariants = []struct {
	name     string
	senderOf []string // sx flags that make it send this variant to our receiver
	receiver []string // rx flags that make it ask our sender for this variant
	opt      transfer.Options
}{
	{"checksum", nil, nil, transfer.Options{Protocol: transfer.XMODEM, Checksum: true, SubpacketSize: 128}},
	{"crc", nil, []string{"-c"}, transfer.Options{Protocol: transfer.XMODEM, SubpacketSize: 128}},
	{"1k", []string{"-k"}, []string{"-c"}, transfer.Options{Protocol: transfer.XMODEM}},
}

// xmodemSizes are multiples of both block sizes, so the stored file is the sent one
// exactly: XMODEM carries no size and pads the last block. oddSize proves the padding.
var xmodemSizes = []int{1024, 9216, 100_352}

const oddSize = 1000

// mustBePadded asserts that path holds src followed by 0x1A up to a block boundary,
// which is all XMODEM can store of a file whose size is not a multiple of the block.
func mustBePadded(t *testing.T, path, src string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(got)%128 != 0 || len(got) < len(want) || !bytes.Equal(got[:len(want)], want) {
		t.Fatalf("stored %d bytes, want %d bytes of the file then padding to a block", len(got), len(want))
	}
	if tail := got[len(want):]; !bytes.Equal(tail, bytes.Repeat([]byte{0x1A}, len(tail))) {
		t.Fatalf("padding is not 0x1A: % x", tail)
	}
}

func withArgs(command []string, extra []string, last ...string) []string {
	args := append([]string{}, command...)
	args = append(args, extra...)
	return append(args, last...)
}

// Line 1, receive: XMODEM checksum, CRC and 1K from sx, byte-identical, under the name
// the caller gives. Line 5: 128-byte and 1K blocks arrive through the same options. sx
// answers whichever byte it is given, so a receiver that opened with C when asked for
// checksum would still get its file; which byte the receiver opens with is observable
// only on the send side, where rx chooses, and for G through the error row of line 4.
func TestXMODEMReceive(t *testing.T) {
	t.Parallel()
	for _, variant := range xmodemVariants {
		for _, size := range append(xmodemSizes, oddSize) {
			t.Run(fmt.Sprintf("%s/%d", variant.name, size), func(t *testing.T) {
				t.Parallel()
				far, recv := t.TempDir(), t.TempDir()
				src := mustWriteRandom(t, far, "payload.bin", size, mtime)
				farEnd, wait := oracle(t, far, withArgs([]string{"sx", "-b", "-q"}, variant.senderOf, "payload.bin")...)
				opt := variant.opt
				opt.Name = "stored.bin"
				got, err := transfer.Receive(t.Context(), farEnd, recv, opt)
				if err != nil {
					t.Fatalf("Receive: %v", err)
				}
				if stderr, err := wait(); err != nil {
					t.Fatalf("sx exited %v: %s", err, stderr)
				}
				if len(got) != 1 || got[0].Name != "stored.bin" || got[0].Path != filepath.Join(recv, "stored.bin") {
					t.Fatalf("got %+v, want one file stored.bin in %s", got, recv)
				}
				if got[0].Size != mustStat(t, got[0].Path).Size() {
					t.Fatalf("reported size %d, stored %d", got[0].Size, mustStat(t, got[0].Path).Size())
				}
				if size == oddSize {
					mustBePadded(t, got[0].Path, src)
					return
				}
				if got[0].Size != int64(size) || mustSum(t, got[0].Path) != mustSum(t, src) {
					t.Fatal("received bytes differ from the sent file")
				}
			})
		}
	}
}

// Line 1, send: XMODEM checksum, CRC and 1K to rx, which stores it byte-identical. rx
// decides checksum or CRC by what it opens with; our sender must follow.
func TestXMODEMSend(t *testing.T) {
	t.Parallel()
	for _, variant := range xmodemVariants {
		for _, size := range append(xmodemSizes, oddSize) {
			t.Run(fmt.Sprintf("%s/%d", variant.name, size), func(t *testing.T) {
				t.Parallel()
				ours, far := t.TempDir(), t.TempDir()
				src := mustWriteRandom(t, ours, "payload.bin", size, mtime)
				farEnd, wait := oracle(t, far, withArgs([]string{"rx", "-b", "-q"}, variant.receiver, "stored.bin")...)
				if err := transfer.Send(t.Context(), farEnd, []string{src}, variant.opt); err != nil {
					t.Fatalf("Send: %v", err)
				}
				if stderr, err := wait(); err != nil {
					t.Fatalf("rx exited %v: %s", err, stderr)
				}
				dst := filepath.Join(far, "stored.bin")
				if size == oddSize {
					mustBePadded(t, dst, src)
					return
				}
				if mustSum(t, dst) != mustSum(t, src) {
					t.Fatal("rx stored bytes that differ from the sent file")
				}
			})
		}
	}
}

var ymodemSizes = []int{1, 127, 128, 1023, 1024, 1025, 100_000, 1_000_000}

var batch = []string{"first.bin", "second.bin", "third.bin"}

// mustMatchBatch asserts that got is the batch in order, each with the name, size and
// modification time from its header and the bytes of the file in dir.
func mustMatchBatch(t *testing.T, got []transfer.Received, dir string) {
	t.Helper()
	if len(got) != len(batch) {
		t.Fatalf("received %d files, want %d", len(got), len(batch))
	}
	for i, name := range batch {
		src := filepath.Join(dir, name)
		if got[i].Name != name {
			t.Fatalf("file %d is %q, want %q: order not kept", i, got[i].Name, name)
		}
		if got[i].Size != mustStat(t, src).Size() || !got[i].ModTime.Truncate(time.Second).Equal(mtime) {
			t.Fatalf("%s: size %d mtime %v, want %d %v", name, got[i].Size, got[i].ModTime, mustStat(t, src).Size(), mtime)
		}
		if mustSum(t, got[i].Path) != mustSum(t, src) {
			t.Fatalf("%s differs", name)
		}
	}
}

// Line 3: YMODEM, batch, with the name, size and modification time from the header. sb
// sends only 1K data blocks, so the 128-byte variant is proved on send alone; rb takes
// either. Line 5: 1K blocks from sb arrive through the same options as 128-byte ones
// from sx.
func TestYMODEM(t *testing.T) {
	t.Parallel()
	t.Run("receive batch from sb", func(t *testing.T) {
		t.Parallel()
		far, recv := t.TempDir(), t.TempDir()
		for i, name := range batch {
			mustWriteRandom(t, far, name, 3000*(i+1)+i, mtime)
		}
		farEnd, wait := oracle(t, far, withArgs([]string{"sb", "-b", "-q"}, batch)...)
		got, err := transfer.Receive(t.Context(), farEnd, recv, transfer.Options{Protocol: transfer.YMODEM})
		if err != nil {
			t.Fatalf("Receive: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("sb did not end cleanly: %v: %s", err, stderr)
		}
		mustMatchBatch(t, got, far)
	})
	for _, block := range []int{128, 1024} {
		for _, size := range ymodemSizes {
			t.Run(fmt.Sprintf("send to rb/%d/%d", block, size), func(t *testing.T) {
				t.Parallel()
				ours, far := t.TempDir(), t.TempDir()
				src := mustWriteRandom(t, ours, "payload.bin", size, mtime)
				farEnd, wait := oracle(t, far, "rb", "-b", "-q", "-y")
				opt := transfer.Options{Protocol: transfer.YMODEM, SubpacketSize: block}
				if err := transfer.Send(t.Context(), farEnd, []string{src}, opt); err != nil {
					t.Fatalf("Send: %v", err)
				}
				if stderr, err := wait(); err != nil {
					t.Fatalf("rb exited %v: %s", err, stderr)
				}
				dst := filepath.Join(far, "payload.bin")
				if mustSum(t, dst) != mustSum(t, src) {
					t.Fatal("rb stored bytes that differ from the sent file")
				}
				info := mustStat(t, dst)
				if info.Size() != int64(size) || !info.ModTime().Truncate(time.Second).Equal(mtime) {
					t.Fatalf("rb stored size %d mtime %v, want %d %v", info.Size(), info.ModTime(), size, mtime)
				}
			})
		}
	}
	t.Run("send batch to rb", func(t *testing.T) {
		t.Parallel()
		ours, far := t.TempDir(), t.TempDir()
		var paths []string
		for i, name := range batch {
			paths = append(paths, mustWriteRandom(t, ours, name, 3000*(i+1)+i, mtime))
		}
		farEnd, wait := oracle(t, far, "rb", "-b", "-q", "-y")
		if err := transfer.Send(t.Context(), farEnd, paths, transfer.Options{Protocol: transfer.YMODEM}); err != nil {
			t.Fatalf("Send: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("rb did not end cleanly: %v: %s", err, stderr)
		}
		for _, name := range batch {
			if mustSum(t, filepath.Join(far, name)) != mustSum(t, filepath.Join(ours, name)) {
				t.Fatalf("%s differs", name)
			}
		}
	})
}

// Line 4: YMODEM-G receive from sb, batch and streaming, and a single error ends the
// transfer. sb streams only when asked, so the error row is what proves G was requested:
// the same corruption under plain YMODEM is repaired by retransmission and the file
// arrives whole.
func TestYMODEMG(t *testing.T) {
	t.Parallel()
	t.Run("receive batch from sb", func(t *testing.T) {
		t.Parallel()
		far, recv := t.TempDir(), t.TempDir()
		for i, name := range batch {
			mustWriteRandom(t, far, name, 30_000*(i+1)+i, mtime)
		}
		farEnd, wait := oracle(t, far, withArgs([]string{"sb", "-b", "-q"}, batch)...)
		opt := transfer.Options{Protocol: transfer.YMODEM, Streaming: true}
		got, err := transfer.Receive(t.Context(), farEnd, recv, opt)
		if err != nil {
			t.Fatalf("Receive: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("sb did not end cleanly: %v: %s", err, stderr)
		}
		mustMatchBatch(t, got, far)
	})
	t.Run("one error ends a streaming receive", func(t *testing.T) {
		t.Parallel()
		far, recv := t.TempDir(), t.TempDir()
		mustWriteRandom(t, far, "noisy.bin", 200_000, mtime)
		farEnd, _ := oracle(t, far, "sb", "-b", "-q", "noisy.bin")
		bad := &corrupting{Reader: farEnd, WriteCloser: farEnd, every: 50_000, skip: 2000}
		opt := transfer.Options{Protocol: transfer.YMODEM, Streaming: true}
		_, err := transfer.Receive(t.Context(), bad, recv, opt)
		if !errors.Is(err, transfer.ErrProtocol) {
			t.Fatalf("Receive over corruption: %v, want ErrProtocol: G has no retransmission", err)
		}
	})
	t.Run("the same error under plain YMODEM is retransmitted", func(t *testing.T) {
		t.Parallel()
		far, recv := t.TempDir(), t.TempDir()
		src := mustWriteRandom(t, far, "noisy.bin", 200_000, mtime)
		farEnd, wait := oracle(t, far, "sb", "-b", "-q", "noisy.bin")
		bad := &corrupting{Reader: farEnd, WriteCloser: farEnd, every: 50_000, skip: 2000}
		got, err := transfer.Receive(t.Context(), bad, recv, transfer.Options{Protocol: transfer.YMODEM})
		if err != nil {
			t.Fatalf("Receive over corruption: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("sb: %v: %s", err, stderr)
		}
		if len(got) != 1 || mustSum(t, got[0].Path) != mustSum(t, src) {
			t.Fatal("file differs after retransmissions")
		}
	})
}

// Line 6: hadv-xyz takes the options of sx, sb, rx and rb: -X, --ymodem, -k, -c, and
// the file name as its argument on an XMODEM receive.
func TestCommandXY(t *testing.T) {
	t.Parallel()
	bin := filepath.Join(t.TempDir(), "hadv-xyz")
	if runtime.GOOS == "windows" {
		bin += ".exe" // exec refuses a path with no extension on Windows
	}
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "../../cmd/hadv-xyz")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building hadv-xyz: %v\n%s", err, out)
	}
	t.Run("as sx -k", func(t *testing.T) {
		t.Parallel()
		ours, far := t.TempDir(), t.TempDir()
		src := mustWriteRandom(t, ours, "cli.bin", 102_400, mtime)
		farEnd, wait := oracle(t, far, "rx", "-b", "-q", "-c", "stored.bin")
		bridge(t, exec.CommandContext(t.Context(), bin, "-X", "-k", "-b", "-q", src), farEnd)
		if stderr, err := wait(); err != nil {
			t.Fatalf("rx: %v: %s", err, stderr)
		}
		if mustSum(t, filepath.Join(far, "stored.bin")) != mustSum(t, src) {
			t.Fatal("file differs")
		}
	})
	t.Run("as rx -c", func(t *testing.T) {
		t.Parallel()
		far, recv := t.TempDir(), t.TempDir()
		src := mustWriteRandom(t, far, "cli.bin", 102_400, mtime)
		farEnd, wait := oracle(t, far, "sx", "-b", "-q", "-k", "cli.bin")
		cmd := exec.CommandContext(t.Context(), bin, "-r", "-X", "-c", "-b", "-q", "stored.bin")
		cmd.Dir = recv
		bridge(t, cmd, farEnd)
		if stderr, err := wait(); err != nil {
			t.Fatalf("sx: %v: %s", err, stderr)
		}
		if mustSum(t, filepath.Join(recv, "stored.bin")) != mustSum(t, src) {
			t.Fatal("file differs")
		}
	})
	t.Run("as sb", func(t *testing.T) {
		t.Parallel()
		ours, far := t.TempDir(), t.TempDir()
		src := mustWriteRandom(t, ours, "cli.bin", 80_000, mtime)
		farEnd, wait := oracle(t, far, "rb", "-b", "-q", "-y")
		bridge(t, exec.CommandContext(t.Context(), bin, "--ymodem", "-b", "-q", src), farEnd)
		if stderr, err := wait(); err != nil {
			t.Fatalf("rb: %v: %s", err, stderr)
		}
		if mustSum(t, filepath.Join(far, "cli.bin")) != mustSum(t, src) {
			t.Fatal("file differs")
		}
	})
	t.Run("as rb", func(t *testing.T) {
		t.Parallel()
		far, recv := t.TempDir(), t.TempDir()
		src := mustWriteRandom(t, far, "cli.bin", 80_000, mtime)
		farEnd, wait := oracle(t, far, "sb", "-b", "-q", "cli.bin")
		cmd := exec.CommandContext(t.Context(), bin, "-r", "--ymodem", "-b", "-q")
		cmd.Dir = recv
		bridge(t, cmd, farEnd)
		if stderr, err := wait(); err != nil {
			t.Fatalf("sb: %v: %s", err, stderr)
		}
		if mustSum(t, filepath.Join(recv, "cli.bin")) != mustSum(t, src) {
			t.Fatal("file differs")
		}
	})
}
