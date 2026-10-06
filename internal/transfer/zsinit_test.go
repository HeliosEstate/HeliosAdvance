// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The approved tests for issue #108, written by the QA session from the issue's line against
// the lrzsz oracle (oracle/README.md). sz -e sends a ZSINIT asking for control characters
// escaped; our receiver is set without Escape. The line's second half, escaping from then on,
// has no row: a receiver sends only hex headers, whose control bytes the reference sends as
// they are, so the line looks the same either way. The review proves it by reading.
package transfer_test

import (
	"bytes"
	"io"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/transfer"
)

const (
	zsinitZDLE        = 0x18
	zsinitTypeZSINIT  = 2
	zsinitTypeZACK    = 3
	zsinitTypeZFILE   = 4
	zsinitHeaderTypes = 2 // hex digits of a hex header's type
)

// zsinitTap records what crosses the line, our writes and the far end's bytes as the module
// reads them, in the order they do.
type zsinitTap struct {
	io.Reader
	io.WriteCloser
	mutex  sync.Mutex
	chunks []zsinitChunk
}

type zsinitChunk struct {
	fromUs bool
	data   []byte
}

func (tap *zsinitTap) Read(buffer []byte) (int, error) {
	n, err := tap.Reader.Read(buffer)
	if n > 0 {
		tap.record(false, buffer[:n])
	}
	return n, err
}

func (tap *zsinitTap) Write(buffer []byte) (int, error) {
	tap.record(true, buffer)
	return tap.WriteCloser.Write(buffer)
}

func (tap *zsinitTap) record(fromUs bool, data []byte) {
	tap.mutex.Lock()
	defer tap.mutex.Unlock()
	tap.chunks = append(tap.chunks, zsinitChunk{fromUs: fromUs, data: bytes.Clone(data)})
}

// firstHeader is the index of the chunk that completes the first header of kind sent by us
// (fromUs) or by the far end, at or after chunk from, or -1. Hex headers are ZPAD ZDLE B and
// the type in hex; binary ones ZPAD ZDLE A or C and the type, perhaps escaped. Under sz -e a
// data byte can escape to ZDLE A, B or C, but only after the ZFILE, the last header sought.
func (tap *zsinitTap) firstHeader(fromUs bool, kind byte, from int) int {
	tap.mutex.Lock()
	defer tap.mutex.Unlock()
	var stream []byte
	var ends []int // the stream's length after each chunk of this direction, by chunk index
	for _, chunk := range tap.chunks {
		if chunk.fromUs == fromUs {
			stream = append(stream, chunk.data...)
		}
		ends = append(ends, len(stream))
	}
	for i := 1; i+2 < len(stream); i++ {
		if stream[i] != zsinitZDLE || stream[i-1] != '*' {
			continue
		}
		typ, last := -1, 0
		switch stream[i+1] {
		case 'B':
			if i+2+zsinitHeaderTypes <= len(stream) {
				if parsed, err := strconv.ParseUint(string(stream[i+2:i+2+zsinitHeaderTypes]), 16, 8); err == nil {
					typ, last = int(parsed), i+1+zsinitHeaderTypes
				}
			}
		case 'A', 'C':
			typ, last = int(stream[i+2]), i+2
			if stream[i+2] == zsinitZDLE && i+3 < len(stream) {
				typ, last = int(stream[i+3]^0x40), i+3
			}
		}
		if typ != int(kind) {
			continue
		}
		for chunk, end := range ends {
			if last < end && chunk >= from {
				return chunk
			}
		}
	}
	return -1
}

func TestZSINIT(t *testing.T) {
	t.Parallel()
	far, recv := t.TempDir(), t.TempDir()
	src := mustWriteRandom(t, far, "escaped.bin", 20_000, mtime)
	farEnd, wait := oracle(t, far, "sz", "-b", "-q", "-e", "escaped.bin")
	tap := &zsinitTap{Reader: farEnd, WriteCloser: farEnd}
	got, receiveErr := transfer.Receive(t.Context(), tap, recv, transfer.Options{})
	stderr, waitErr := wait()

	t.Run("When a ZMODEM sender sends a ZSINIT, the receiver shall answer with a ZACK, and where the ZSINIT asks for control characters escaped, the receiver shall escape them from then on.", func(t *testing.T) {
		t.Parallel()
		t.Run("the transfer completes", func(t *testing.T) {
			t.Parallel()
			if receiveErr != nil {
				t.Fatalf("Receive from sz -e: %v", receiveErr)
			}
			if waitErr != nil {
				t.Fatalf("sz -e: %v: %s", waitErr, stderr)
			}
			if len(got) != 1 || mustSum(t, got[0].Path) != mustSum(t, src) {
				t.Fatalf("received %d files, want escaped.bin whole", len(got))
			}
			if filepath.Base(got[0].Path) != "escaped.bin" {
				t.Fatalf("stored as %s, want escaped.bin", filepath.Base(got[0].Path))
			}
		})
		t.Run("a ZACK answers the ZSINIT before the ZFILE comes", func(t *testing.T) {
			t.Parallel()
			offered := tap.firstHeader(false, zsinitTypeZSINIT, 0)
			if offered < 0 {
				t.Fatal("sz -e sent no ZSINIT, so there is nothing to judge")
			}
			acknowledged := tap.firstHeader(true, zsinitTypeZACK, offered)
			if acknowledged < 0 {
				t.Fatal("no ZACK of ours followed sz's ZSINIT")
			}
			if file := tap.firstHeader(false, zsinitTypeZFILE, offered); file >= 0 && file < acknowledged {
				t.Fatal("sz's ZFILE arrived before our ZACK answered its ZSINIT")
			}
		})
	})
}
