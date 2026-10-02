// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The approved tests for issue #15: every behaviour line of the ZMODEM (#13) and X/YMODEM
// (#14) issues that sexyz can drive, proved against it as well, plus the lines only sexyz
// can drive: ZMODEM-8K and segmented ZMODEM both ways, and G on send. The helpers are the
// locked files' own; this file adds only the sexyz far end.
//
// Lines sexyz cannot drive, by its usage text, stay proved by lrzsz alone: a receiver that
// reports errors (--errors), a sender that goes silent (--delay-startup), a far end that
// stops mid-transfer (-s +N), resume (-r), and a remote command (-c). sexyz sends no
// modification time it did not get, and stores a file under the path it is given with its
// trailing slash; a batch is a list file.
package transfer_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/transfer"
)

const (
	sexyzImage = "heliosestate/sexyz-oracle:0.1"
	// The names the rows store under: an XMODEM receive names its own file, so the stored
	// name differs from the sent one on purpose.
	storedName = "stored.bin"
	cliName    = "cli.bin"
)

// sexyz runs one sexyz command in its container with dir mounted as /data and the working
// directory, in stdio mode with Telnet off, and returns the far end of the line plus a
// wait that reports the exit and stderr. The shape is oracle's; only the image differs.
func sexyz(t *testing.T, dir string, args ...string) (*line, func() (string, error)) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is required: the oracle is sexyz in a container, and a skipped oracle is a vacuous pass")
	}
	full := []string{"run", "--rm", "-i", "-v", dir + ":/data", "-w", "/data"}
	if uid := os.Getuid(); uid >= 0 {
		// On Unix the container would otherwise write as root into our temp dir. Windows
		// mounts are open and Getuid is -1 there.
		full = append(full, "--user", fmt.Sprintf("%d:%d", uid, os.Getgid()))
	}
	full = append(append(full, sexyzImage, "sexyz", "-raw"), args...)
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
		t.Fatalf("starting sexyz: %v", err)
	}
	farEnd := &line{Reader: stdout, WriteCloser: stdin}
	wait := func() (string, error) {
		_ = stdin.Close()
		err := cmd.Wait()
		return stderr.String(), err
	}
	t.Cleanup(func() { _ = stdin.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return farEnd, wait
}

// within bounds one transfer to ninety seconds, ten times what the largest row needs at
// speed: a far end that disagrees with us on the wire can crawl rather than stop (sexyz
// halves its block size on every ZRPOS and keeps going at tens of bytes a second), and a
// crawl must fail the row, not the run.
func within(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// mustWriteList writes a sexyz batch list naming files in dir and returns its argument.
func mustWriteList(t *testing.T, dir string, names ...string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "list.txt"), []byte(strings.Join(names, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return "@list.txt"
}

var sexyzSizes = []int{1, 1023, 1024, 1025, 100_000, 1_000_000}

// #13 line 1: receive from sexyz sz, byte-identical, with name, size and modification time.
// #13 line 2: send to sexyz rz, which stores it byte-identical with name and size.
func TestSexyzZMODEM(t *testing.T) {
	t.Parallel()
	for _, size := range sexyzSizes {
		t.Run(fmt.Sprintf("receive/%d", size), func(t *testing.T) {
			t.Parallel()
			far, recv := t.TempDir(), t.TempDir()
			src := mustWriteRandom(t, far, "payload.bin", size, mtime)
			farEnd, wait := sexyz(t, far, "sz", "payload.bin")
			got, err := transfer.Receive(within(t), farEnd, recv, transfer.Options{})
			if err != nil {
				t.Fatalf("Receive: %v", err)
			}
			if stderr, err := wait(); err != nil {
				t.Fatalf("sexyz sz exited %v: %s", err, stderr)
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
		})
		t.Run(fmt.Sprintf("send/%d", size), func(t *testing.T) {
			t.Parallel()
			ours, far := t.TempDir(), t.TempDir()
			src := mustWriteRandom(t, ours, "payload.bin", size, mtime)
			farEnd, wait := sexyz(t, far, "-y", "rz", "/data/")
			if err := transfer.Send(within(t), farEnd, []string{src}, transfer.Options{}); err != nil {
				t.Fatalf("Send: %v", err)
			}
			if stderr, err := wait(); err != nil {
				t.Fatalf("sexyz rz exited %v: %s", err, stderr)
			}
			dst := filepath.Join(far, "payload.bin")
			if mustSum(t, dst) != mustSum(t, src) || mustStat(t, dst).Size() != int64(size) {
				t.Fatal("sexyz stored bytes that differ from the sent file")
			}
		})
	}
}

// #13 line 3: a batch, every file in order, and a clean end after the last.
func TestSexyzZMODEMBatch(t *testing.T) {
	t.Parallel()
	t.Run("receive", func(t *testing.T) {
		t.Parallel()
		far, recv := t.TempDir(), t.TempDir()
		for i, name := range batch {
			mustWriteRandom(t, far, name, 3000*(i+1)+i, mtime)
		}
		farEnd, wait := sexyz(t, far, "sz", mustWriteList(t, far, batch...))
		got, err := transfer.Receive(within(t), farEnd, recv, transfer.Options{})
		if err != nil {
			t.Fatalf("Receive: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("sexyz sz did not end cleanly: %v: %s", err, stderr)
		}
		mustMatchBatch(t, got, far)
	})
	t.Run("send", func(t *testing.T) {
		t.Parallel()
		ours, far := t.TempDir(), t.TempDir()
		var paths []string
		for i, name := range batch {
			paths = append(paths, mustWriteRandom(t, ours, name, 3000*(i+1)+i, mtime))
		}
		farEnd, wait := sexyz(t, far, "-y", "rz", "/data/")
		if err := transfer.Send(within(t), farEnd, paths, transfer.Options{}); err != nil {
			t.Fatalf("Send: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("sexyz rz did not end cleanly: %v: %s", err, stderr)
		}
		for _, name := range batch {
			if mustSum(t, filepath.Join(far, name)) != mustSum(t, filepath.Join(ours, name)) {
				t.Fatalf("%s differs", name)
			}
		}
	})
}

// sexyzOption is one far-end flag and the option on our side that answers it, run both
// ways: the flag on a sexyz sender into our receiver, and our option sent into a sexyz
// receiver carrying the same flag.
type sexyzOption struct {
	name string
	flag string
	opt  transfer.Options
	line string
}

var sexyzOptions = []sexyzOption{
	// #13 line 4: 16-bit CRC where that is what the far end speaks.
	{"crc16", "-o", transfer.Options{CRC16: true}, "#13 line 4"},
	// #13 line 5: escaping, asked for by either side.
	{"escape", "-e", transfer.Options{Escape: true}, "#13 line 5"},
	// #13 line 6: 8K subpackets, offered and accepted, against sexyz -8 rather than lrzsz's
	// --try-8k; the one named in #15 as ZMODEM-8K.
	{"8k", "-8", transfer.Options{SubpacketSize: 8192}, "#13 line 6, #15"},
	// #15: segmented ZMODEM. sexyz -s turns streaming off both ways: every subpacket is
	// ZCRCW and waits for its ZACK. Our sender must wait when the receiver says so; our
	// receiver must answer.
	{"segmented", "-s", transfer.Options{}, "#15"},
}

func TestSexyzZMODEMOptions(t *testing.T) {
	t.Parallel()
	for _, option := range sexyzOptions {
		t.Run(option.name+"/receive", func(t *testing.T) {
			t.Parallel()
			far, recv := t.TempDir(), t.TempDir()
			src := mustWriteRandom(t, far, "opt.bin", 200_000, mtime)
			farEnd, wait := sexyz(t, far, option.flag, "sz", "opt.bin")
			got, err := transfer.Receive(within(t), farEnd, recv, option.opt)
			if err != nil {
				t.Fatalf("Receive (%s): %v", option.line, err)
			}
			if stderr, err := wait(); err != nil {
				t.Fatalf("sexyz %s sz: %v: %s", option.flag, err, stderr)
			}
			if len(got) != 1 || mustSum(t, got[0].Path) != mustSum(t, src) {
				t.Fatalf("file differs (%s)", option.line)
			}
		})
		t.Run(option.name+"/send", func(t *testing.T) {
			t.Parallel()
			ours, far := t.TempDir(), t.TempDir()
			src := mustWriteRandom(t, ours, "opt.bin", 200_000, mtime)
			farEnd, wait := sexyz(t, far, option.flag, "-y", "rz", "/data/")
			if err := transfer.Send(within(t), farEnd, []string{src}, option.opt); err != nil {
				t.Fatalf("Send (%s): %v", option.line, err)
			}
			if stderr, err := wait(); err != nil {
				t.Fatalf("sexyz %s rz: %v: %s", option.flag, err, stderr)
			}
			if mustSum(t, filepath.Join(far, "opt.bin")) != mustSum(t, src) {
				t.Fatalf("file differs (%s)", option.line)
			}
		})
	}
}

// #13 line 7, the half sexyz can drive: a frame corrupted on the way to us is
// retransmitted from the last good position when we ask. sexyz has no --errors. One flip
// every 30,000 bytes, six errors, where the lrzsz row has one every 9,000: sexyz takes
// about two seconds to recover from each error by its own design (lrzsz's own rz needs
// 142 seconds for the 9,000 shape against it, measured 2026-10-01), so twenty-two errors
// never fit the bound and six do, with room. A receiver that stalls sexyz still fails here.
func TestSexyzCorruption(t *testing.T) {
	t.Parallel()
	far, recv := t.TempDir(), t.TempDir()
	src := mustWriteRandom(t, far, "noisy.bin", 200_000, mtime)
	farEnd, wait := sexyz(t, far, "sz", "noisy.bin")
	bad := &corrupting{Reader: farEnd, WriteCloser: farEnd, every: 30_000, skip: 200}
	got, err := transfer.Receive(within(t), bad, recv, transfer.Options{})
	if err != nil {
		t.Fatalf("Receive over corruption: %v", err)
	}
	if stderr, err := wait(); err != nil {
		t.Fatalf("sexyz sz: %v: %s", err, stderr)
	}
	if len(got) != 1 || mustSum(t, got[0].Path) != mustSum(t, src) {
		t.Fatal("file differs after retransmissions")
	}
}

// #13 line 9, the half sexyz can drive: our cancel stops sexyz within a frame.
// #13 line 11: progress, bytes done of total, reaching total, against a sexyz receiver.
func TestSexyzCancelAndProgress(t *testing.T) {
	t.Parallel()
	t.Run("our cancel ends sexyz", func(t *testing.T) {
		t.Parallel()
		ours, far := t.TempDir(), t.TempDir()
		src := mustWriteRandom(t, ours, "long.bin", 5_000_000, mtime)
		farEnd, wait := sexyz(t, far, "-y", "rz", "/data/")
		ctx, cancel := context.WithCancel(t.Context())
		opt := transfer.Options{Progress: func(report transfer.Progress) {
			if report.Done > 100_000 {
				cancel()
			}
		}}
		err := transfer.Send(ctx, farEnd, []string{src}, opt)
		if !errors.Is(err, transfer.ErrCancelled) {
			t.Fatalf("Send after our cancel: %v, want ErrCancelled", err)
		}
		if _, err := wait(); err == nil {
			t.Fatal("sexyz rz exited 0 after our cancel; it should report the abort")
		}
	})
	t.Run("progress reaches total", func(t *testing.T) {
		t.Parallel()
		ours, far := t.TempDir(), t.TempDir()
		src := mustWriteRandom(t, ours, "progress.bin", 300_000, mtime)
		farEnd, wait := sexyz(t, far, "-y", "rz", "/data/")
		var last transfer.Progress
		opt := transfer.Options{Progress: func(report transfer.Progress) {
			if report.Done < last.Done || report.Total != 300_000 {
				t.Errorf("progress went backwards or total wrong: %+v after %+v", report, last)
			}
			last = report
		}}
		if err := transfer.Send(within(t), farEnd, []string{src}, opt); err != nil {
			t.Fatalf("Send: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("sexyz rz: %v: %s", err, stderr)
		}
		if last.Done != last.Total || last.Name != "progress.bin" {
			t.Fatalf("last progress %+v, want done == total for progress.bin", last)
		}
	})
}

// sexyzXMODEM is one XMODEM variant in sexyz's terms: the sender command that produces it
// into our receiver, the receiver command that asks our sender for it.
var sexyzXMODEM = []struct {
	name     string
	sender   string // sexyz send command: sx is 128-byte, sX is 1K
	receiver string // sexyz receive command: rx asks checksum, rc asks CRC
	opt      transfer.Options
}{
	{"checksum", "sx", "rx", transfer.Options{Protocol: transfer.XMODEM, Checksum: true, SubpacketSize: 128}},
	{"crc", "sx", "rc", transfer.Options{Protocol: transfer.XMODEM, SubpacketSize: 128}},
	{"1k", "sX", "rc", transfer.Options{Protocol: transfer.XMODEM}},
}

// #14 line 1: XMODEM checksum, CRC and 1K, send and receive. Line 5: the receiver opens
// with what it was asked for; sexyz rx and rc choose on the send side.
func TestSexyzXMODEM(t *testing.T) {
	t.Parallel()
	for _, variant := range sexyzXMODEM {
		for _, size := range append(xmodemSizes, oddSize) {
			t.Run(fmt.Sprintf("receive/%s/%d", variant.name, size), func(t *testing.T) {
				t.Parallel()
				far, recv := t.TempDir(), t.TempDir()
				src := mustWriteRandom(t, far, "payload.bin", size, mtime)
				farEnd, wait := sexyz(t, far, variant.sender, "payload.bin")
				opt := variant.opt
				opt.Name = storedName
				got, err := transfer.Receive(within(t), farEnd, recv, opt)
				if err != nil {
					t.Fatalf("Receive: %v", err)
				}
				if stderr, err := wait(); err != nil {
					t.Fatalf("sexyz %s exited %v: %s", variant.sender, err, stderr)
				}
				if len(got) != 1 || got[0].Name != storedName {
					t.Fatalf("got %+v, want one file stored.bin", got)
				}
				if size == oddSize {
					mustBePadded(t, got[0].Path, src)
					return
				}
				if got[0].Size != int64(size) || mustSum(t, got[0].Path) != mustSum(t, src) {
					t.Fatal("received bytes differ from the sent file")
				}
			})
			t.Run(fmt.Sprintf("send/%s/%d", variant.name, size), func(t *testing.T) {
				t.Parallel()
				ours, far := t.TempDir(), t.TempDir()
				src := mustWriteRandom(t, ours, "payload.bin", size, mtime)
				farEnd, wait := sexyz(t, far, "-y", variant.receiver, storedName)
				if err := transfer.Send(within(t), farEnd, []string{src}, variant.opt); err != nil {
					t.Fatalf("Send: %v", err)
				}
				if stderr, err := wait(); err != nil {
					t.Fatalf("sexyz %s exited %v: %s", variant.receiver, err, stderr)
				}
				dst := filepath.Join(far, storedName)
				if size == oddSize {
					mustBePadded(t, dst, src)
					return
				}
				if mustSum(t, dst) != mustSum(t, src) {
					t.Fatal("sexyz stored bytes that differ from the sent file")
				}
			})
		}
	}
}

// #14 line 2, both directions, deferred here from #14: XMODEM-G. Receive from sexyz sX,
// which streams when asked; a single error must end it, and the same error under plain
// XMODEM is retransmitted, which is what shows G was asked for. Send to sexyz -g rx,
// which asks for G, the one thing lrzsz cannot.
func TestSexyzXMODEMG(t *testing.T) {
	t.Parallel()
	streaming := transfer.Options{Protocol: transfer.XMODEM, Streaming: true, Name: storedName}
	t.Run("receive streaming from sX", func(t *testing.T) {
		t.Parallel()
		far, recv := t.TempDir(), t.TempDir()
		src := mustWriteRandom(t, far, "payload.bin", 102_400, mtime)
		farEnd, wait := sexyz(t, far, "sX", "payload.bin")
		got, err := transfer.Receive(within(t), farEnd, recv, streaming)
		if err != nil {
			t.Fatalf("Receive: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("sexyz sX: %v: %s", err, stderr)
		}
		if len(got) != 1 || mustSum(t, got[0].Path) != mustSum(t, src) {
			t.Fatal("received bytes differ from the sent file")
		}
	})
	t.Run("one error ends a streaming receive", func(t *testing.T) {
		t.Parallel()
		far, recv := t.TempDir(), t.TempDir()
		mustWriteRandom(t, far, "noisy.bin", 204_800, mtime)
		farEnd, _ := sexyz(t, far, "sX", "noisy.bin")
		bad := &corrupting{Reader: farEnd, WriteCloser: farEnd, every: 50_000, skip: 2000}
		_, err := transfer.Receive(within(t), bad, recv, streaming)
		if !errors.Is(err, transfer.ErrProtocol) {
			t.Fatalf("Receive over corruption: %v, want ErrProtocol: G has no retransmission", err)
		}
	})
	t.Run("the same error under plain XMODEM is retransmitted", func(t *testing.T) {
		t.Parallel()
		far, recv := t.TempDir(), t.TempDir()
		// A multiple of the block, since XMODEM stores the padding of the last one.
		src := mustWriteRandom(t, far, "noisy.bin", 204_800, mtime)
		farEnd, wait := sexyz(t, far, "sX", "noisy.bin")
		bad := &corrupting{Reader: farEnd, WriteCloser: farEnd, every: 50_000, skip: 2000}
		got, err := transfer.Receive(within(t), bad, recv, transfer.Options{Protocol: transfer.XMODEM, Name: storedName})
		if err != nil {
			t.Fatalf("Receive over corruption: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("sexyz sX: %v: %s", err, stderr)
		}
		if len(got) != 1 || mustSum(t, got[0].Path) != mustSum(t, src) {
			t.Fatal("file differs after retransmissions")
		}
	})
	t.Run("send streaming to -g rx", func(t *testing.T) {
		t.Parallel()
		ours, far := t.TempDir(), t.TempDir()
		src := mustWriteRandom(t, ours, "payload.bin", 102_400, mtime)
		farEnd, wait := sexyz(t, far, "-y", "-g", "rx", storedName)
		if err := transfer.Send(within(t), farEnd, []string{src}, transfer.Options{Protocol: transfer.XMODEM}); err != nil {
			t.Fatalf("Send: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("sexyz -g rx: %v: %s", err, stderr)
		}
		if mustSum(t, filepath.Join(far, storedName)) != mustSum(t, src) {
			t.Fatal("sexyz stored bytes that differ from the sent file")
		}
	})
}

// #14 line 3: YMODEM with 128-byte blocks and 1K, batch, name, size and modification
// time from the header. sexyz sy sends 128-byte blocks, which lrzsz's sb could not, so
// the 128-byte receive is proved here. Line 5: both block sizes through the same options.
func TestSexyzYMODEM(t *testing.T) {
	t.Parallel()
	for _, sender := range []string{"sy", "sY"} {
		t.Run("receive batch from "+sender, func(t *testing.T) {
			t.Parallel()
			far, recv := t.TempDir(), t.TempDir()
			for i, name := range batch {
				mustWriteRandom(t, far, name, 3000*(i+1)+i, mtime)
			}
			farEnd, wait := sexyz(t, far, sender, mustWriteList(t, far, batch...))
			got, err := transfer.Receive(within(t), farEnd, recv, transfer.Options{Protocol: transfer.YMODEM})
			if err != nil {
				t.Fatalf("Receive: %v", err)
			}
			if stderr, err := wait(); err != nil {
				t.Fatalf("sexyz %s did not end cleanly: %v: %s", sender, err, stderr)
			}
			mustMatchBatch(t, got, far)
		})
	}
	for _, block := range []int{128, 1024} {
		t.Run(fmt.Sprintf("send batch to ry/%d", block), func(t *testing.T) {
			t.Parallel()
			ours, far := t.TempDir(), t.TempDir()
			var paths []string
			for i, name := range batch {
				paths = append(paths, mustWriteRandom(t, ours, name, 3000*(i+1)+i, mtime))
			}
			farEnd, wait := sexyz(t, far, "-y", "ry", "/data/")
			opt := transfer.Options{Protocol: transfer.YMODEM, SubpacketSize: block}
			if err := transfer.Send(within(t), farEnd, paths, opt); err != nil {
				t.Fatalf("Send: %v", err)
			}
			if stderr, err := wait(); err != nil {
				t.Fatalf("sexyz ry did not end cleanly: %v: %s", err, stderr)
			}
			for _, name := range batch {
				dst := filepath.Join(far, name)
				if mustSum(t, dst) != mustSum(t, filepath.Join(ours, name)) {
					t.Fatalf("%s differs", name)
				}
				if info := mustStat(t, dst); !info.ModTime().Truncate(time.Second).Equal(mtime) {
					t.Fatalf("%s: sexyz stored mtime %v, want %v", name, info.ModTime(), mtime)
				}
			}
		})
	}
}

// #14 line 4: YMODEM-G. Receive, batch and streaming, from sexyz sY; send, deferred here
// from #14, to sexyz rg, which asks for G.
func TestSexyzYMODEMG(t *testing.T) {
	t.Parallel()
	t.Run("receive batch streaming from sY", func(t *testing.T) {
		t.Parallel()
		far, recv := t.TempDir(), t.TempDir()
		for i, name := range batch {
			mustWriteRandom(t, far, name, 30_000*(i+1)+i, mtime)
		}
		farEnd, wait := sexyz(t, far, "sY", mustWriteList(t, far, batch...))
		opt := transfer.Options{Protocol: transfer.YMODEM, Streaming: true}
		got, err := transfer.Receive(within(t), farEnd, recv, opt)
		if err != nil {
			t.Fatalf("Receive: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("sexyz sY did not end cleanly: %v: %s", err, stderr)
		}
		mustMatchBatch(t, got, far)
	})
	t.Run("send batch streaming to rg", func(t *testing.T) {
		t.Parallel()
		ours, far := t.TempDir(), t.TempDir()
		var paths []string
		for i, name := range batch {
			paths = append(paths, mustWriteRandom(t, ours, name, 30_000*(i+1)+i, mtime))
		}
		farEnd, wait := sexyz(t, far, "-y", "rg", "/data/")
		if err := transfer.Send(within(t), farEnd, paths, transfer.Options{Protocol: transfer.YMODEM}); err != nil {
			t.Fatalf("Send: %v", err)
		}
		if stderr, err := wait(); err != nil {
			t.Fatalf("sexyz rg did not end cleanly: %v: %s", err, stderr)
		}
		for _, name := range batch {
			if mustSum(t, filepath.Join(far, name)) != mustSum(t, filepath.Join(ours, name)) {
				t.Fatalf("%s differs", name)
			}
		}
	})
}

// #13 line 13 and #14 line 6: hadv-xyz stands in for the lrzsz commands against sexyz.
func TestSexyzCommand(t *testing.T) {
	t.Parallel()
	bin := mustBuildCommand(t)
	rows := []struct {
		name  string
		ours  []string // hadv-xyz flags; a send gets the source path appended
		far   []string // sexyz arguments
		send  bool
		check string // the file to compare, in the far dir for a send, ours for a receive
	}{
		{"as sz", []string{"-b", "-q"}, []string{"-y", "rz", "/data/"}, true, cliName},
		{"as rz", []string{"-r", "-b", "-q"}, []string{"sz", cliName}, false, cliName},
		{"as sx -k", []string{"-X", "-k", "-b", "-q"}, []string{"-y", "rc", storedName}, true, storedName},
		{"as rx -c", []string{"-r", "-X", "-c", "-b", "-q", storedName}, []string{"sX", cliName}, false, storedName},
		{"as sb", []string{"--ymodem", "-b", "-q"}, []string{"-y", "ry", "/data/"}, true, cliName},
		{"as rb", []string{"-r", "--ymodem", "-b", "-q"}, []string{"sY", cliName}, false, cliName},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			ours, far := t.TempDir(), t.TempDir()
			srcDir := far
			if row.send {
				srcDir = ours
			}
			src := mustWriteRandom(t, srcDir, cliName, 102_400, mtime)
			farEnd, wait := sexyz(t, far, row.far...)
			args := row.ours
			if row.send {
				args = append(append([]string{}, args...), src)
			}
			cmd := exec.CommandContext(t.Context(), bin, args...)
			cmd.Dir = ours
			bridge(t, cmd, farEnd)
			if stderr, err := wait(); err != nil {
				t.Fatalf("sexyz: %v: %s", err, stderr)
			}
			stored := filepath.Join(ours, row.check)
			if row.send {
				stored = filepath.Join(far, row.check)
			}
			if mustSum(t, stored) != mustSum(t, src) {
				t.Fatal("file differs")
			}
		})
	}
}

// mustBuildCommand builds hadv-xyz into a temp dir and returns its path.
func mustBuildCommand(t *testing.T) string {
	t.Helper()
	const windowsOS, exeSuffix = "windows", ".exe"
	bin := filepath.Join(t.TempDir(), "hadv-xyz")
	if runtime.GOOS == windowsOS {
		bin += exeSuffix // exec refuses a path with no extension on Windows
	}
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "../../cmd/hadv-xyz")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building hadv-xyz: %v: %s", err, out)
	}
	return bin
}
