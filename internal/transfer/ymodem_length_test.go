// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The approved tests for issue #106, written by the QA session from the issue's line against
// the lrzsz oracle (oracle/README.md). No lrzsz or sexyz sender leaves the length out of
// block 0, so the rows edit sb's block 0 on the line: the pathname kept, the optional fields
// after it cleared, as the YMODEM reference allows ("The pathname and file length may be sent
// alone"), and its CRC made again. Everything else on the line is sb's own.
package transfer_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/transfer"
)

// The YMODEM reference's block starts.
const (
	blockStartShort = 0x01 // SOH: a 128-byte block
	blockStartLong  = 0x02 // STX: a 1024-byte block
	endOfTransfer   = 0x04 // EOT
)

// lengthStripper is the line from sb as our receiver reads it, with the first block 0's
// optional fields cleared, recording each data block's payload as it passes, until the first
// file's EOT; from there every byte goes through untouched.
type lengthStripper struct {
	io.Reader
	io.WriteCloser
	pending  []byte // read from sb, not yet a whole block
	ready    []byte // passed, for the receiver
	passing  bool
	mutex    sync.Mutex
	stripped bool
	payloads map[byte][]byte // by block number, from 1
}

func (stripper *lengthStripper) Read(buffer []byte) (int, error) {
	for len(stripper.ready) == 0 {
		if stripper.passing && len(stripper.pending) == 0 {
			return stripper.Reader.Read(buffer)
		}
		chunk := make([]byte, 4096)
		n, err := stripper.Reader.Read(chunk)
		stripper.pending = append(stripper.pending, chunk[:n]...)
		stripper.pass()
		if err != nil && len(stripper.ready) == 0 {
			return 0, err
		}
	}
	n := copy(buffer, stripper.ready)
	stripper.ready = stripper.ready[n:]
	return n, nil
}

// pass moves every whole block, and every byte outside a block, from pending to ready.
func (stripper *lengthStripper) pass() {
	for len(stripper.pending) > 0 {
		if stripper.passing {
			stripper.ready = append(stripper.ready, stripper.pending...)
			stripper.pending = nil
			return
		}
		size := 0
		switch stripper.pending[0] {
		case blockStartShort:
			size = 128
		case blockStartLong:
			size = 1024
		case endOfTransfer:
			stripper.passing = true
			fallthrough
		default:
			stripper.ready = append(stripper.ready, stripper.pending[0])
			stripper.pending = stripper.pending[1:]
			continue
		}
		whole := 3 + size + 2 // start, number, its complement, data, CRC-16
		if len(stripper.pending) < whole {
			return
		}
		block := stripper.pending[:whole]
		number, data := block[1], block[3:3+size]
		stripper.mutex.Lock()
		switch {
		case number == 0 && !stripper.stripped:
			name, _, _ := bytes.Cut(data, []byte{0})
			clear(data[len(name)+1:])
			binary.BigEndian.PutUint16(block[3+size:], blockCRC(data)) // the reference sends it high byte first
			stripper.stripped = true
		case number != 0:
			stripper.payloads[number] = bytes.Clone(data)
		}
		stripper.mutex.Unlock()
		stripper.ready = append(stripper.ready, block...)
		stripper.pending = stripper.pending[whole:]
	}
}

// arrived is every data block's payload, in block order: every byte of the file that crossed
// the line, padding included.
func (stripper *lengthStripper) arrived() []byte {
	stripper.mutex.Lock()
	defer stripper.mutex.Unlock()
	var all []byte
	for number := 1; number <= len(stripper.payloads); number++ {
		all = append(all, stripper.payloads[byte(number)]...)
	}
	return all
}

// blockCRC is the reference's CRC-16 over a block's data: polynomial 0x1021, starting at 0.
func blockCRC(data []byte) uint16 {
	var crc uint16
	for _, value := range data {
		crc ^= uint16(value) << 8
		for range 8 {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

func TestYMODEMWithoutLength(t *testing.T) {
	t.Parallel()
	t.Run("If a YMODEM block 0 gives no file length, then the receiver shall keep every byte that arrived.", func(t *testing.T) {
		t.Parallel()
		rows := []struct {
			name string
			size int
		}{
			{"a file that is not a block multiple keeps the padding that arrived", 1000},
			{"a file that is a block multiple keeps every block", 3072},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				far, recv := t.TempDir(), t.TempDir()
				mustWriteRandom(t, far, "unsized.bin", row.size, mtime)
				farEnd, wait := oracle(t, far, "sb", "-b", "-q", "unsized.bin")
				stripper := &lengthStripper{Reader: farEnd, WriteCloser: farEnd, payloads: map[byte][]byte{}}
				got, err := transfer.Receive(t.Context(), stripper, recv, transfer.Options{Protocol: transfer.YMODEM})
				if err != nil {
					t.Fatalf("Receive: %v", err)
				}
				if stderr, err := wait(); err != nil {
					t.Fatalf("sb: %v: %s", err, stderr)
				}
				stripper.mutex.Lock()
				stripped := stripper.stripped
				stripper.mutex.Unlock()
				if !stripped {
					t.Fatal("no block 0 crossed the line to clear")
				}
				want := stripper.arrived()
				if len(want) < row.size {
					t.Fatalf("%d bytes of data blocks crossed the line, fewer than the file's %d", len(want), row.size)
				}
				if len(got) != 1 {
					t.Fatalf("received %d files, want 1", len(got))
				}
				stored, err := os.ReadFile(got[0].Path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(stored, want) {
					t.Fatalf("stored %d bytes, want the %d bytes that arrived", len(stored), len(want))
				}
			})
		}
	})
}
