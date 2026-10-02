// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package transfer

import (
	"context"
	"io"
	"time"
)

// Protocol bytes. Names follow Chuck Forsberg's ZMODEM Protocol Reference.
const (
	zpad   = '*'
	zdle   = 0x18 // CAN; starts an escape sequence or, repeated, a cancel.
	zdlee  = zdle ^ 0x40
	zbin   = 'A' // binary header, CRC-16
	zhex   = 'B' // hex header, always CRC-16
	zbin32 = 'C' // binary header, CRC-32
)

// Subpacket terminators: the byte following ZDLE that ends a data subpacket.
const (
	zcrce = 'h' // CRC follows, frame ends, a header follows
	zcrcg = 'i' // CRC follows, frame continues, no ZACK expected
	zcrcq = 'j' // CRC follows, frame continues, ZACK expected
	zcrcw = 'k' // CRC follows, frame ends, ZACK expected
)

// ZRINIT flags byte (header data[3]): what a receiver can do.
const (
	canfdx  = 0x01
	canovio = 0x02
	canfc32 = 0x20
	escctl  = 0x40
)

// byteSource reads one byte at a time from an io.Reader on a background goroutine, so a
// read against the far end can be bounded by a timeout or a context even though
// io.Reader itself offers no way to cancel an in-flight Read. The goroutine exits when
// the underlying stream errors; until then it is read-only and leaks harmlessly if the
// caller stops waiting first, same as any blocking read on a stream nobody closes.
type byteSource struct {
	queue  chan byte
	errc   chan error
	canRun int // consecutive raw ZDLE bytes just read, to tell a real cancel from noise
}

// cancelRun is how many consecutive raw ZDLE (CAN) bytes mean a real cancel rather than
// corruption that happened to flip a data byte to 0x18: a validly escaped stream never
// emits two in a row (every escape pair's second byte differs from ZDLE itself), so even
// two is already unusual, but the far end's real cancel string is much longer (lrzsz
// sends eight) and a short run is cheap to produce by accident out of 200,000 random bytes.
const cancelRun = 5

func newByteSource(input io.Reader) *byteSource {
	source := &byteSource{queue: make(chan byte, 4096), errc: make(chan error, 1)}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := input.Read(buf)
			for i := range n {
				source.queue <- buf[i]
			}
			if err != nil {
				source.errc <- err
				return
			}
		}
	}()
	return source
}

func (source *byteSource) readByte(ctx context.Context, timeout time.Duration) (byte, error) {
	value, err := source.readRawByte(ctx, timeout)
	if err != nil {
		return 0, err
	}
	if value == zdle {
		source.canRun++
		if source.canRun >= cancelRun {
			return 0, errGotCancel
		}
	} else {
		source.canRun = 0
	}
	return value, nil
}

// readRawByte reads one byte with no cancel-run detection, for a caller that knows the
// byte comes from unescaped protocol data rather than a position where the far end could
// legitimately send its cancel sequence. XMODEM and YMODEM block bodies are such data: a
// run of 0x18 inside a block is ordinary file content, not a cancel, and lrzsz's receiver
// agrees, checking for CAN only between blocks.
func (source *byteSource) readRawByte(ctx context.Context, timeout time.Duration) (byte, error) {
	// A cancelled ctx must win even over a byte already queued: this is how a frame
	// watcher hands a still-open stream back to the session's own sequential reads, and a
	// watcher that kept consuming queued bytes after being told to stop would steal them
	// from the read the session makes next.
	select {
	case <-ctx.Done():
		return 0, ErrCancelled
	default:
	}
	// A byte already queued must win over an errc that became ready at the same instant:
	// Go picks at random between two ready cases, and the reader goroutine always queues
	// every byte before it sends the end, so draining queue first here preserves that order.
	select {
	case value := <-source.queue:
		return value, nil
	default:
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case value := <-source.queue:
		return value, nil
	case err := <-source.errc:
		return 0, err
	case <-timer.C:
		return 0, ErrTimeout
	case <-ctx.Done():
		return 0, ErrCancelled
	}
}

// errGotCancel signals that the far end sent the cancel sequence.
var errGotCancel = errCancelSentinel{}

type errCancelSentinel struct{}

func (errCancelSentinel) Error() string { return "transfer: cancel sequence received" }

// zreader decodes the ZDLE layer: literal bytes pass through, and it unescapes
// ZDLE-prefixed sequences. isTerm reports a subpacket terminator (ZCRCE/G/Q/W), which
// only means something to a subpacket reader; a header reader never sees one because it
// reads a fixed number of bytes.
type zreader struct {
	src     *byteSource
	ctx     context.Context
	timeout time.Duration
}

func newZReader(ctx context.Context, src *byteSource, timeout time.Duration) *zreader {
	return &zreader{src: src, ctx: ctx, timeout: timeout}
}

func (reader *zreader) next() (literal byte, isTerm bool, term byte, err error) {
	literal, err = reader.src.readByte(reader.ctx, reader.timeout)
	if err != nil {
		return 0, false, 0, err
	}
	if literal != zdle {
		return literal, false, 0, nil
	}
	escaped, err := reader.src.readByte(reader.ctx, reader.timeout)
	if err != nil {
		return 0, false, 0, err
	}
	switch escaped {
	case zcrce, zcrcg, zcrcq, zcrcw:
		return 0, true, escaped, nil
	default:
		return escaped ^ 0x40, false, 0, nil
	}
}

// readN reads exactly n decoded bytes, erroring on a terminator (which a fixed-length
// read never expects) or a cancel.
func (reader *zreader) readN(n int) ([]byte, error) {
	out := make([]byte, 0, n)
	for range n {
		value, isTerm, _, err := reader.next()
		if err != nil {
			return nil, err
		}
		if isTerm {
			return nil, ErrProtocol
		}
		out = append(out, value)
	}
	return out, nil
}

// zwriter encodes the ZDLE layer. full escapes every control character (0x00-0x1F and
// 0x80-0x9F); otherwise only what the protocol always requires: ZDLE itself, XON/XOFF
// and DLE (which a modem or terminal could act on), and a CR that follows an '@' (which
// some transports turn into CR LF).
type zwriter struct {
	target io.Writer
	full   bool
	last   byte
}

func newZWriter(target io.Writer, full bool) *zwriter {
	return &zwriter{target: target, full: full}
}

func (writer *zwriter) raw(data []byte) error {
	_, err := writer.target.Write(data)
	return err
}

func (writer *zwriter) put(value byte) error {
	var out [2]byte
	n := 1
	switch {
	case value == zdle:
		out[0], out[1], n = zdle, zdlee, 2
	case (value == 0x0d || value == 0x8d) && (writer.last == 0x40 || writer.last == 0xc0):
		out[0], out[1], n = zdle, value^0x40, 2
	case value == 0x10 || value == 0x90 || value == 0x11 || value == 0x91 || value == 0x13 || value == 0x93:
		out[0], out[1], n = zdle, value^0x40, 2
	case writer.full && value&0x60 == 0:
		out[0], out[1], n = zdle, value^0x40, 2
	default:
		out[0] = value
	}
	writer.last = value
	return writer.raw(out[:n])
}

func (writer *zwriter) putAll(data []byte) error {
	for _, value := range data {
		if err := writer.put(value); err != nil {
			return err
		}
	}
	return nil
}
