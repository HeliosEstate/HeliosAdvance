// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The approved tests for issue #107, written by the QA session from the issue's line against
// the lrzsz oracle (oracle/README.md). sb and sz send a date of 0 for a file dated at the
// epoch, so those rows are theirs alone. No oracle sender leaves the date out, so the other
// rows cut sb's block 0, or sz's ZFILE subpacket, on the line to the pathname and the length,
// with its CRC made again; everything else on the line is the sender's own.
package transfer_test

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/transfer"
)

const (
	dateCutZDLE  = 0x18
	dateCutZFILE = 4
)

// dateCutter is the line from the sender as our receiver reads it, with every named block 0,
// or every ZFILE subpacket, cut to the pathname and the length.
type dateCutter struct {
	io.Reader
	io.WriteCloser
	cut     func(*dateCutter) // moves what it can from pending to ready
	pending []byte
	ready   []byte
	mutex   sync.Mutex
	cuts    int
	fault   string // why a cut could not be made
}

func (cutter *dateCutter) Read(buffer []byte) (int, error) {
	for len(cutter.ready) == 0 {
		chunk := make([]byte, 4096)
		n, err := cutter.Reader.Read(chunk)
		cutter.pending = append(cutter.pending, chunk[:n]...)
		cutter.cut(cutter)
		if err != nil && len(cutter.ready) == 0 {
			cutter.ready, cutter.pending = cutter.pending, nil
			if len(cutter.ready) == 0 {
				return 0, err
			}
		}
	}
	n := copy(buffer, cutter.ready)
	cutter.ready = cutter.ready[n:]
	return n, nil
}

func (cutter *dateCutter) record(fault string) {
	cutter.mutex.Lock()
	defer cutter.mutex.Unlock()
	if fault != "" {
		cutter.fault = fault
		return
	}
	cutter.cuts++
}

func (cutter *dateCutter) result() (int, string) {
	cutter.mutex.Lock()
	defer cutter.mutex.Unlock()
	return cutter.cuts, cutter.fault
}

// nameAndLength is the file information cut to the pathname, its NUL and the length.
func nameAndLength(information []byte) []byte {
	name, rest, _ := bytes.Cut(information, []byte{0})
	fields := bytes.Fields(bytes.TrimRight(rest, "\x00"))
	cut := append(bytes.Clone(name), 0)
	if len(fields) > 0 {
		cut = append(cut, fields[0]...)
	}
	return cut
}

// cutBlockZero passes YMODEM blocks whole, cutting each block 0 that names a file. A block
// starts with SOH (128 bytes) or STX (1024); any other byte goes through on its own.
func cutBlockZero(cutter *dateCutter) {
	for len(cutter.pending) > 0 {
		size := map[byte]int{0x01: 128, 0x02: 1024}[cutter.pending[0]]
		if size == 0 {
			cutter.ready = append(cutter.ready, cutter.pending[0])
			cutter.pending = cutter.pending[1:]
			continue
		}
		whole := 3 + size + 2 // start, number, its complement, data, CRC-16
		if len(cutter.pending) < whole {
			return
		}
		block := cutter.pending[:whole]
		if data := block[3 : 3+size]; block[1] == 0 && data[0] != 0 {
			cut := nameAndLength(data)
			clear(data)
			copy(data, cut)
			binary.BigEndian.PutUint16(block[3+size:], dateCutCRC16(data)) // high byte first
			cutter.record("")
		}
		cutter.ready = append(cutter.ready, block...)
		cutter.pending = cutter.pending[whole:]
	}
}

// cutZFILE passes the ZMODEM stream, cutting the subpacket after each ZFILE header. A data
// byte never escapes to ZDLE followed by A or C, so ZPAD ZDLE A or C starts a binary header.
func cutZFILE(cutter *dateCutter) {
	for {
		start := -1
		for i := 0; i+2 < len(cutter.pending); i++ {
			if cutter.pending[i] == '*' && cutter.pending[i+1] == dateCutZDLE && (cutter.pending[i+2] == 'A' || cutter.pending[i+2] == 'C') {
				start = i
				break
			}
		}
		if start < 0 {
			keep := min(len(cutter.pending), 2) // a header's start may be split across reads
			cutter.ready = append(cutter.ready, cutter.pending[:len(cutter.pending)-keep]...)
			cutter.pending = cutter.pending[len(cutter.pending)-keep:]
			return
		}
		cutter.ready = append(cutter.ready, cutter.pending[:start]...)
		cutter.pending = cutter.pending[start:]
		crcLength := 2
		if cutter.pending[2] == 'C' {
			crcLength = 4
		}
		header, afterHeader, ok := dateCutUnescape(cutter.pending, 3, 5+crcLength)
		if !ok {
			return
		}
		if header[0] != dateCutZFILE {
			cutter.ready = append(cutter.ready, cutter.pending[:afterHeader]...)
			cutter.pending = cutter.pending[afterHeader:]
			continue
		}
		data, end, afterData, ok := dateCutSubpacket(cutter.pending, afterHeader)
		if !ok {
			return
		}
		sent, afterCRC, ok := dateCutUnescape(cutter.pending, afterData, crcLength)
		if !ok {
			return
		}
		if !bytes.Equal(dateCutSubpacketCRC(data, end, crcLength), sent) {
			cutter.record("the CRC made from sz's own ZFILE subpacket is not the one sz sent")
		} else {
			cutter.record("")
		}
		cut := nameAndLength(data)
		rebuilt := append(bytes.Clone(cutter.pending[:afterHeader]), dateCutEscape(cut)...)
		rebuilt = append(rebuilt, dateCutZDLE, end)
		rebuilt = append(rebuilt, dateCutEscape(dateCutSubpacketCRC(cut, end, crcLength))...)
		cutter.ready = append(cutter.ready, rebuilt...)
		cutter.pending = cutter.pending[afterCRC:]
	}
}

// dateCutSubpacket reads a subpacket's data from start up to its end, ZDLE and h to k.
func dateCutSubpacket(stream []byte, start int) (data []byte, end byte, after int, ok bool) {
	for i := start; i+1 < len(stream); i++ {
		if stream[i] != dateCutZDLE {
			data = append(data, stream[i])
			continue
		}
		switch escaped := stream[i+1]; {
		case escaped >= 'h' && escaped <= 'k':
			return data, escaped, i + 2, true
		case escaped == 'l':
			data = append(data, 0x7f)
		case escaped == 'm':
			data = append(data, 0xff)
		default:
			data = append(data, escaped^0x40)
		}
		i++
	}
	return nil, 0, 0, false
}

// dateCutUnescape reads count bytes from start, undoing ZDLE escapes.
func dateCutUnescape(stream []byte, start, count int) (decoded []byte, after int, ok bool) {
	i := start
	for len(decoded) < count {
		if i >= len(stream) || (stream[i] == dateCutZDLE && i+1 >= len(stream)) {
			return nil, i, false
		}
		if stream[i] != dateCutZDLE {
			decoded = append(decoded, stream[i])
			i++
			continue
		}
		switch escaped := stream[i+1]; escaped {
		case 'l':
			decoded = append(decoded, 0x7f)
		case 'm':
			decoded = append(decoded, 0xff)
		default:
			decoded = append(decoded, escaped^0x40)
		}
		i += 2
	}
	return decoded, i, true
}

// dateCutEscape escapes what the ZMODEM reference says a sender must: ZDLE, DLE, XON and
// XOFF, with or without the high bit, and CR, which may follow an @.
func dateCutEscape(data []byte) []byte {
	var escaped []byte
	for _, value := range data {
		switch value {
		case dateCutZDLE, 0x10, 0x11, 0x13, 0x90, 0x91, 0x93, 0x0d, 0x8d:
			escaped = append(escaped, dateCutZDLE, value^0x40)
		default:
			escaped = append(escaped, value)
		}
	}
	return escaped
}

// dateCutSubpacketCRC is a subpacket's CRC over its data and its end byte: CRC-32, low byte
// first, or CRC-16, high byte first, as the header's A or C said.
func dateCutSubpacketCRC(data []byte, end byte, crcLength int) []byte {
	covered := append(bytes.Clone(data), end)
	if crcLength == 4 {
		return binary.LittleEndian.AppendUint32(nil, crc32.ChecksumIEEE(covered))
	}
	return binary.BigEndian.AppendUint16(nil, dateCutCRC16(covered))
}

// dateCutCRC16 is the reference's CRC-16: polynomial 0x1021, starting at 0.
func dateCutCRC16(data []byte) uint16 {
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

func TestDateUnknown(t *testing.T) {
	t.Parallel()
	t.Run("If the sender gives a modification date of 0, or none, then the receiver shall leave the file dated when it was received.", func(t *testing.T) {
		t.Parallel()
		rows := []struct {
			name   string
			sender string
			cut    func(*dateCutter) // nil: the sender's line as it is, its date 0
			opt    transfer.Options
		}{
			{"YMODEM, a date of 0", "sb", nil, transfer.Options{Protocol: transfer.YMODEM}},
			{"ZMODEM, a date of 0", "sz", nil, transfer.Options{}},
			{"YMODEM, no date", "sb", cutBlockZero, transfer.Options{Protocol: transfer.YMODEM}},
			{"ZMODEM, no date", "sz", cutZFILE, transfer.Options{}},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				far, recv := t.TempDir(), t.TempDir()
				mustWriteRandom(t, far, "undated.bin", 3000, time.Unix(0, 0))
				farEnd, wait := oracle(t, far, row.sender, "-b", "-q", "undated.bin")
				var far2us io.Reader = farEnd
				cutter := &dateCutter{Reader: farEnd, WriteCloser: farEnd, cut: row.cut}
				if row.cut != nil {
					far2us = cutter
				}
				// A coarse file-system clock can put the stored time a little either side.
				from := time.Now().Add(-2 * time.Second)
				got, err := transfer.Receive(t.Context(), &line{Reader: far2us, WriteCloser: farEnd}, recv, row.opt)
				until := time.Now().Add(2 * time.Second)
				if err != nil {
					t.Fatalf("Receive: %v", err)
				}
				if stderr, err := wait(); err != nil {
					t.Fatalf("%s: %v: %s", row.sender, err, stderr)
				}
				if row.cut != nil {
					cuts, fault := cutter.result()
					if fault != "" {
						t.Fatal(fault)
					}
					if cuts == 0 {
						t.Fatal("no file information crossed the line to cut")
					}
				}
				if len(got) != 1 {
					t.Fatalf("received %d files, want 1", len(got))
				}
				stat, err := os.Stat(got[0].Path)
				if err != nil {
					t.Fatal(err)
				}
				if stored := stat.ModTime(); stored.Before(from) || stored.After(until) {
					t.Fatalf("the file is dated %v, want the time it was received, %v to %v", stored.UTC(), from.UTC(), until.UTC())
				}
			})
		}
	})
}
