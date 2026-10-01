// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package transfer

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// send drives the sender side of a ZMODEM batch: wait for the far end's readiness, then
// offer each file in order, then finish the session.
func (s *session) send(paths []string) error {
	for {
		select {
		case <-s.ctx.Done():
			s.cancelPeer()
			return ErrCancelled
		default:
		}
		h, _, err := s.await(func() error { return writeHex(s.zw, header{typ: zrqinit}) }, maxRetries)
		if err != nil {
			return mapErr(err)
		}
		switch h.typ {
		case zsinit:
			if err := s.writeHeader(header{typ: zack}, false); err != nil {
				return err
			}
			continue
		case zcan:
			return ErrCancelled
		case zrinit:
		default:
			continue
		}
		break
	}

	for i, p := range paths {
		if err := s.sendFile(p, paths[i+1:]); err != nil {
			return err
		}
	}

	h, _, err := s.await(func() error { return writeHex(s.zw, header{typ: zfin}) }, maxRetries)
	if err != nil {
		return mapErr(err)
	}
	for h.typ != zfin {
		if h.typ == zcan {
			return ErrCancelled
		}
		h, _, err = s.awaitHeaderOnly(maxRetries)
		if err != nil {
			return mapErr(err)
		}
	}
	return s.zw.raw([]byte("OO"))
}

// sendFile offers one file: its info subpacket, then its data from wherever the far end
// asks (0, or its resume offset), retrying a request for an earlier offset until the far
// end accepts the end of the file.
func (s *session) sendFile(path string, rest []string) error {
	f, err := os.Open(path) //nolint:gosec // the caller names its own files to send
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() //nolint:errcheck // read-only; nothing left to flush on close
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	size := fi.Size()
	name := filepath.Base(path)

	var bytesLeft int64
	for _, p := range rest {
		if fi2, err := os.Stat(p); err == nil {
			bytesLeft += fi2.Size()
		}
	}
	info := encodeFileInfo(name, size, fi.ModTime(), len(rest), bytesLeft)

	// ZF0: binary, or ZCRESUM (3) to ask the far end to report the exact byte count it
	// already holds rather than rounding down to a block boundary out of caution.
	conversion := byte(1)
	if s.opt.Resume {
		conversion = 3
	}
	h, _, err := s.await(func() error {
		if err := s.writeHeader(header{typ: zfile, data: [4]byte{conversion, 0, 0, 0}}, false); err != nil {
			return err
		}
		return writeSubpacket(s.zw, info, zcrcw, s.useCRC32)
	}, maxRetries)
	if err != nil {
		return mapErr(err)
	}
	// Only a ZRPOS or ZSKIP actually answers the ZFILE. In between, a far end can emit
	// noise this exchange didn't ask for: a ZACK for the info subpacket's own zcrcw (a
	// separate frame from the answer), or a stale ZRINIT it was still retrying when our
	// ZFILE arrived. Skipping anything else keeps that noise from being mistaken for the
	// answer and left to surprise the data-streaming loop later as a bogus interrupt.
	for h.typ != zrpos && h.typ != zskip {
		if h.typ == zcan {
			return ErrCancelled
		}
		h, _, err = s.awaitHeaderOnly(maxRetries)
		if err != nil {
			return mapErr(err)
		}
	}

	var offset int64
	switch h.typ {
	case zrpos:
		if p := h.position(); p >= 0 && p <= size {
			offset = p
		}
	case zskip:
		return nil
	}
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return err
		}
	}

	for {
		if err := s.streamFrom(f, &offset, size, name); err != nil {
			return err
		}
		h, _, err := s.await(func() error { return s.writeHeader(posHeader(zeof, offset), false) }, maxRetries)
		if err != nil {
			return mapErr(err)
		}
		if h.typ == zrpos {
			if p := h.position(); p >= 0 && p <= size && p != offset {
				offset = p
				if _, err := f.Seek(offset, io.SeekStart); err != nil {
					return err
				}
				continue
			}
		}
		break
	}
	if s.opt.Progress != nil {
		s.opt.Progress(Progress{Name: name, Done: size, Total: size})
	}
	return nil
}

// streamFrom sends the file's data in one or more ZDATA frames starting at *offset,
// restarting a fresh frame whenever the far end interrupts with a ZRPOS (a corrupted
// subpacket on its end) asking for a different position.
func (s *session) streamFrom(f *os.File, offset *int64, size int64, name string) error {
	chunkSize := s.opt.SubpacketSize
	if chunkSize <= 0 {
		chunkSize = 1024
	}
	buf := make([]byte, chunkSize)
	for *offset < size {
		if err := s.writeHeader(posHeader(zdata, *offset), false); err != nil {
			return err
		}
		restart, err := s.streamOneFrame(f, offset, size, name, buf)
		if err != nil {
			return err
		}
		if !restart {
			break
		}
	}
	return nil
}

// frameResult is one header the background watcher picked up while the main loop was
// busy writing data, so a mid-stream ZRPOS (or cancel) is noticed without blocking sends.
type frameResult struct {
	h   header
	err error
}

func (s *session) watch(ctx context.Context, out chan<- frameResult) {
	for {
		h, _, ok, err := readFrame(ctx, s.src, s.timeout)
		if err != nil {
			switch {
			case errors.Is(err, ErrTimeout):
				if ctx.Err() != nil {
					return
				}
				continue
			case errors.Is(err, ErrCancelled):
				// readByte returns this only when ctx itself was cancelled: our own
				// teardown via stopWatch, or the caller's s.ctx, which streamOneFrame's
				// main loop already watches directly. Either way it is never something
				// the far end sent, so there is nothing to deliver.
				return
			default:
				deliver(ctx, out, frameResult{err: err})
				if errors.Is(err, errGotCancel) || errors.Is(err, io.EOF) {
					return
				}
				continue
			}
		}
		if !ok {
			continue
		}
		deliver(ctx, out, frameResult{h: h})
	}
}

// deliver sends fr to out, trying a non-blocking send first so an already-decoded frame
// is never lost to a simultaneous ctx cancellation: select picks uniformly among ready
// cases, so without this, a frame arriving the instant the main loop stops reading could
// be silently dropped half the time instead of landing in the channel's open buffer.
func deliver(ctx context.Context, out chan<- frameResult, fr frameResult) {
	select {
	case out <- fr:
		return
	default:
	}
	select {
	case out <- fr:
	case <-ctx.Done():
	}
}

func (s *session) streamOneFrame(f *os.File, offset *int64, size int64, name string, buf []byte) (restart bool, err error) {
	watchCtx, cancelWatch := context.WithCancel(s.ctx)
	done := make(chan struct{})
	frames := make(chan frameResult, 4)
	go func() {
		defer close(done)
		s.watch(watchCtx, frames)
	}()
	// The watcher and the rest of the session both read s.src; cancelling isn't enough
	// on its own; stopWatch must also wait for the goroutine to actually stop reading,
	// or it can still take the next byte the caller needs right after this returns.
	stopWatch := func() {
		cancelWatch()
		<-done
	}
	defer stopWatch()

	for *offset < size {
		select {
		case <-s.ctx.Done():
			s.cancelPeer()
			return false, ErrCancelled
		case fr := <-frames:
			if restart, ferr, handled := s.handleFrame(fr, f, offset, size); handled {
				return restart, ferr
			}
			continue
		default:
		}
		n, rerr := f.Read(buf)
		if n == 0 {
			if rerr != nil && !errors.Is(rerr, io.EOF) {
				return false, rerr
			}
			break
		}
		term := byte(zcrcg)
		if *offset+int64(n) >= size {
			term = zcrce
		}
		if werr := writeSubpacket(s.zw, buf[:n], term, s.useCRC32); werr != nil {
			return false, werr
		}
		*offset += int64(n)
		if s.opt.Progress != nil {
			s.opt.Progress(Progress{Name: name, Done: *offset, Total: size})
		}
	}

	// The far end's ZRPOS for this frame's last subpacket, if it found one corrupt, can
	// still be in flight the instant *offset reaches size; stop the watcher and drain
	// what it already decoded before declaring the frame finished, or that answer is
	// lost and the caller's ZEOF goes to a far end that is still expecting a resend.
	stopWatch()
	for {
		select {
		case fr := <-frames:
			if restart, ferr, handled := s.handleFrame(fr, f, offset, size); handled {
				return restart, ferr
			}
		default:
			return false, nil
		}
	}
}

// handleFrame applies one frame the watcher picked up: a cancel ends the transfer, a
// ZRPOS naming a different position means the far end found this frame corrupt and the
// stream must restart there; anything else is noise the caller ignores.
func (s *session) handleFrame(fr frameResult, f *os.File, offset *int64, size int64) (restart bool, err error, handled bool) {
	switch {
	case fr.err != nil && (errors.Is(fr.err, errGotCancel) || errors.Is(fr.err, ErrCancelled)):
		return false, ErrCancelled, true
	case fr.err == nil && fr.h.typ == zrpos:
		if p := fr.h.position(); p >= 0 && p <= size {
			*offset = p
			if _, err := f.Seek(*offset, io.SeekStart); err != nil {
				return false, err, true
			}
			return true, nil, true
		}
	}
	return false, nil, false
}
