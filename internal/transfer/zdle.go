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
	ch     chan byte
	errc   chan error
	canRun int // consecutive raw ZDLE bytes just read, to tell a real cancel from noise
}

// cancelRun is how many consecutive raw ZDLE (CAN) bytes mean a real cancel rather than
// corruption that happened to flip a data byte to 0x18: a validly escaped stream never
// emits two in a row (every escape pair's second byte differs from ZDLE itself), so even
// two is already unusual, but the far end's real cancel string is much longer (lrzsz
// sends eight) and a short run is cheap to produce by accident out of 200,000 random bytes.
const cancelRun = 5

func newByteSource(r io.Reader) *byteSource {
	s := &byteSource{ch: make(chan byte, 4096), errc: make(chan error, 1)}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			for i := range n {
				s.ch <- buf[i]
			}
			if err != nil {
				s.errc <- err
				return
			}
		}
	}()
	return s
}

func (s *byteSource) readByte(ctx context.Context, timeout time.Duration) (byte, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case b := <-s.ch:
		if b == zdle {
			s.canRun++
			if s.canRun >= cancelRun {
				return 0, errGotCancel
			}
		} else {
			s.canRun = 0
		}
		return b, nil
	case err := <-s.errc:
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

func (z *zreader) next() (b byte, isTerm bool, term byte, err error) {
	b, err = z.src.readByte(z.ctx, z.timeout)
	if err != nil {
		return 0, false, 0, err
	}
	if b != zdle {
		return b, false, 0, nil
	}
	v, err := z.src.readByte(z.ctx, z.timeout)
	if err != nil {
		return 0, false, 0, err
	}
	switch v {
	case zcrce, zcrcg, zcrcq, zcrcw:
		return 0, true, v, nil
	default:
		return v ^ 0x40, false, 0, nil
	}
}

// readN reads exactly n decoded bytes, erroring on a terminator (which a fixed-length
// read never expects) or a cancel.
func (z *zreader) readN(n int) ([]byte, error) {
	out := make([]byte, 0, n)
	for range n {
		b, isTerm, _, err := z.next()
		if err != nil {
			return nil, err
		}
		if isTerm {
			return nil, ErrProtocol
		}
		out = append(out, b)
	}
	return out, nil
}

// zwriter encodes the ZDLE layer. full escapes every control character (0x00-0x1F and
// 0x80-0x9F); otherwise only what the protocol always requires: ZDLE itself, XON/XOFF
// and DLE (which a modem or terminal could act on), and a CR that follows an '@' (which
// some transports turn into CR LF).
type zwriter struct {
	w    io.Writer
	full bool
	last byte
}

func newZWriter(w io.Writer, full bool) *zwriter {
	return &zwriter{w: w, full: full}
}

func (z *zwriter) raw(p []byte) error {
	_, err := z.w.Write(p)
	return err
}

func (z *zwriter) put(c byte) error {
	var out [2]byte
	n := 1
	switch {
	case c == zdle:
		out[0], out[1], n = zdle, zdlee, 2
	case (c == 0x0d || c == 0x8d) && (z.last == 0x40 || z.last == 0xc0):
		out[0], out[1], n = zdle, c^0x40, 2
	case c == 0x10 || c == 0x90 || c == 0x11 || c == 0x91 || c == 0x13 || c == 0x93:
		out[0], out[1], n = zdle, c^0x40, 2
	case z.full && c&0x60 == 0:
		out[0], out[1], n = zdle, c^0x40, 2
	default:
		out[0] = c
	}
	z.last = c
	return z.raw(out[:n])
}

func (z *zwriter) putAll(p []byte) error {
	for _, c := range p {
		if err := z.put(c); err != nil {
			return err
		}
	}
	return nil
}
