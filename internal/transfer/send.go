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
	defer func() { _ = f.Close() }()
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

	h, _, err := s.await(func() error {
		if err := s.writeHeader(header{typ: zfile, data: [4]byte{1, 0, 0, 0}}, false); err != nil {
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
	if s.opt.Progress != nil {
		s.opt.Progress(Progress{Name: name, Done: offset, Total: size})
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
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			if errors.Is(err, ErrTimeout) {
				continue
			}
			select {
			case out <- frameResult{err: err}:
			case <-ctx.Done():
			}
			if errors.Is(err, errGotCancel) || errors.Is(err, io.EOF) {
				return
			}
			continue
		}
		if !ok {
			continue
		}
		select {
		case out <- frameResult{h: h}:
		case <-ctx.Done():
			return
		}
	}
}

func (s *session) streamOneFrame(f *os.File, offset *int64, size int64, name string, buf []byte) (restart bool, err error) {
	watchCtx, stopWatch := context.WithCancel(s.ctx)
	defer stopWatch()
	frames := make(chan frameResult, 4)
	go s.watch(watchCtx, frames)

	for *offset < size {
		select {
		case <-s.ctx.Done():
			s.cancelPeer()
			return false, ErrCancelled
		case fr := <-frames:
			switch {
			case fr.err != nil && (errors.Is(fr.err, errGotCancel) || errors.Is(fr.err, ErrCancelled)):
				return false, ErrCancelled
			case fr.err == nil && fr.h.typ == zrpos:
				if p := fr.h.position(); p >= 0 && p <= size {
					*offset = p
					if _, err := f.Seek(*offset, io.SeekStart); err != nil {
						return false, err
					}
					return true, nil
				}
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
	return false, nil
}
