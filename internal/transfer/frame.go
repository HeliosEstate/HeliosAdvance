// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package transfer

import (
	"context"
	"fmt"
	"time"
)

// Frame types (header's first byte). Names follow the ZMODEM protocol reference.
const (
	zrqinit = iota
	zrinit
	zsinit
	zack
	zfile
	zskip
	znak
	zabort
	zfin
	zrpos
	zdata
	zeof
	zfererr
	zcrc
	zchallenge
	zcompl
	zcan
	zfreecnt
	zcommand
	zstderr
)

// header is one ZMODEM header: a frame type and four data bytes. For ZRPOS, ZDATA,
// ZEOF and ZACK the four bytes are a little-endian file position; for ZRINIT they are
// buffer size (unused) and a protocol level and flags byte.
type header struct {
	typ  byte
	data [4]byte
}

func posHeader(typ byte, pos int64) header {
	var head header
	head.typ = typ
	raw := uint32(pos)                                                                                             //nolint:gosec // G115: a ZMODEM position is a protocol-defined 32-bit field
	head.data[0], head.data[1], head.data[2], head.data[3] = byte(raw), byte(raw>>8), byte(raw>>16), byte(raw>>24) //nolint:gosec // G115: serializing the 32-bit field byte by byte
	return head
}

func (head header) position() int64 {
	return int64(uint32(head.data[0]) | uint32(head.data[1])<<8 | uint32(head.data[2])<<16 | uint32(head.data[3])<<24)
}

var hexDigits = "0123456789abcdef"

// writeHex sends a hex header: always CRC-16, used only during the handshake before a
// binary encoding is in play.
func writeHex(writer *zwriter, head header) error {
	if err := writer.raw([]byte{zpad, zpad, zdle, zhex}); err != nil {
		return err
	}
	buf := append([]byte{head.typ}, head.data[:]...)
	crc := crc16(buf)
	buf = append(buf, byte(crc>>8), byte(crc)) //nolint:gosec // G115: serializing a 16-bit CRC byte by byte
	hex := make([]byte, 0, len(buf)*2)
	for _, value := range buf {
		hex = append(hex, hexDigits[value>>4], hexDigits[value&0xf])
	}
	if err := writer.raw(hex); err != nil {
		return err
	}
	trailer := []byte{'\r', 0x8a}
	if head.typ != zfin && head.typ != zack {
		trailer = append(trailer, 0x11) // XON
	}
	return writer.raw(trailer)
}

// writeBinary sends a binary header, ZDLE-escaped, with CRC-16 or CRC-32 per crc32 mode.
func writeBinary(writer *zwriter, head header, useCRC32 bool) error {
	ind := byte(zbin)
	if useCRC32 {
		ind = zbin32
	}
	if err := writer.raw([]byte{zpad, zdle, ind}); err != nil {
		return err
	}
	buf := append([]byte{head.typ}, head.data[:]...)
	if useCRC32 {
		crc := crc32sum(buf)
		buf = append(buf, byte(crc), byte(crc>>8), byte(crc>>16), byte(crc>>24)) //nolint:gosec // G115: serializing a 32-bit CRC byte by byte
	} else {
		crc := crc16(buf)
		buf = append(buf, byte(crc>>8), byte(crc)) //nolint:gosec // G115: serializing a 16-bit CRC byte by byte
	}
	return writer.putAll(buf)
}

func hexVal(digit byte) (byte, bool) {
	switch {
	case digit >= '0' && digit <= '9':
		return digit - '0', true
	case digit >= 'a' && digit <= 'f':
		return digit - 'a' + 10, true
	case digit >= 'A' && digit <= 'F':
		return digit - 'A' + 10, true
	default:
		return 0, false
	}
}

// readFrame scans the stream for the next header, skipping noise before the ZPAD/ZDLE
// lead-in (sz and rz both pad with extra ZPAD and junk between frames). It reports the
// header, whether it arrived with a CRC-32 trailer, and whether the CRC validated.
func readFrame(ctx context.Context, src *byteSource, timeout time.Duration) (head header, crc32mode, ok bool, err error) {
	for {
		value, err := src.readByte(ctx, timeout)
		if err != nil {
			return header{}, false, false, err
		}
		if value != zdle {
			continue // ZPAD and anything else before the lead-in is noise.
		}
		value, err = src.readByte(ctx, timeout)
		if err != nil {
			return header{}, false, false, err
		}
		switch value {
		case zbin, zbin32:
			return readBinaryHeader(ctx, src, timeout, value == zbin32)
		case zhex:
			return readHexHeader(ctx, src, timeout)
		default:
			continue // not a header lead-in; keep scanning.
		}
	}
}

func readBinaryHeader(ctx context.Context, src *byteSource, timeout time.Duration, crc32mode bool) (header, bool, bool, error) {
	reader := newZReader(ctx, src, timeout)
	n := 7
	if crc32mode {
		n = 9
	}
	buf, err := reader.readN(n)
	if err != nil {
		return header{}, false, false, err
	}
	var head header
	head.typ = buf[0]
	copy(head.data[:], buf[1:5])
	var ok bool
	if crc32mode {
		want := uint32(buf[5]) | uint32(buf[6])<<8 | uint32(buf[7])<<16 | uint32(buf[8])<<24
		ok = crc32sum(buf[:5]) == want
	} else {
		want := uint16(buf[5])<<8 | uint16(buf[6])
		ok = crc16(buf[:5]) == want
	}
	return head, crc32mode, ok, nil
}

func readHexHeader(ctx context.Context, src *byteSource, timeout time.Duration) (header, bool, bool, error) {
	raw := make([]byte, 14) // type + 4 data bytes + 2 crc bytes, each as 2 hex digits
	for i := range raw {
		value, err := src.readByte(ctx, timeout)
		if err != nil {
			return header{}, false, false, err
		}
		raw[i] = value
	}
	buf := make([]byte, 7)
	for i := range buf {
		high, ok1 := hexVal(raw[i*2])
		low, ok2 := hexVal(raw[i*2+1])
		if !ok1 || !ok2 {
			return header{}, false, false, nil
		}
		buf[i] = high<<4 | low
	}
	// A hex header is followed by CR, an LF variant and often an XON; readFrame's noise
	// scan skips those before the next header, so there is nothing to drain here.
	var head header
	head.typ = buf[0]
	copy(head.data[:], buf[1:5])
	want := uint16(buf[5])<<8 | uint16(buf[6])
	ok := crc16(buf[:5]) == want
	return head, false, ok, nil
}

// subpacket writing and reading.

func writeSubpacket(writer *zwriter, data []byte, term byte, useCRC32 bool) error {
	if err := writer.putAll(data); err != nil {
		return err
	}
	if err := writer.raw([]byte{zdle, term}); err != nil {
		return err
	}
	buf := append(append([]byte{}, data...), term)
	if useCRC32 {
		crc := crc32sum(buf)
		return writer.putAll([]byte{byte(crc), byte(crc >> 8), byte(crc >> 16), byte(crc >> 24)}) //nolint:gosec // G115: serializing a 32-bit CRC byte by byte
	}
	crc := crc16(buf)
	return writer.putAll([]byte{byte(crc >> 8), byte(crc)}) //nolint:gosec // G115: serializing a 16-bit CRC byte by byte
}

// readSubpacket reads one data subpacket up to max bytes, returning the data, the
// terminator and whether the trailing CRC validated.
func readSubpacket(ctx context.Context, src *byteSource, timeout time.Duration, max int, useCRC32 bool) (data []byte, term byte, ok bool, err error) {
	reader := newZReader(ctx, src, timeout)
	data = make([]byte, 0, max)
	for {
		value, isTerm, t, err := reader.next()
		if err != nil {
			return nil, 0, false, err
		}
		if isTerm {
			term = t
			break
		}
		data = append(data, value)
		if len(data) > max+16 {
			return nil, 0, false, fmt.Errorf("%w: subpacket exceeds %d bytes", ErrProtocol, max)
		}
	}
	n := 2
	if useCRC32 {
		n = 4
	}
	crcBytes, err := reader.readN(n)
	if err != nil {
		return nil, 0, false, err
	}
	buf := append(append([]byte{}, data...), term)
	if useCRC32 {
		want := uint32(crcBytes[0]) | uint32(crcBytes[1])<<8 | uint32(crcBytes[2])<<16 | uint32(crcBytes[3])<<24
		ok = crc32sum(buf) == want
	} else {
		want := uint16(crcBytes[0])<<8 | uint16(crcBytes[1])
		ok = crc16(buf) == want
	}
	return data, term, ok, nil
}
