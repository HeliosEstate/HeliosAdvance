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
func (conversation *session) send(paths []string) error {
	for {
		select {
		case <-conversation.ctx.Done():
			conversation.cancelPeer()
			return ErrCancelled
		default:
		}
		head, _, err := conversation.await(func() error { return writeHex(conversation.writer, header{typ: zrqinit}) }, maxRetries)
		if err != nil {
			return mapErr(err)
		}
		switch head.typ {
		case zsinit:
			if err := conversation.writeHeader(header{typ: zack}, false); err != nil {
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

	for i, path := range paths {
		if err := conversation.sendFile(path, paths[i+1:]); err != nil {
			return err
		}
	}

	head, _, err := conversation.await(func() error { return writeHex(conversation.writer, header{typ: zfin}) }, maxRetries)
	if err != nil {
		return mapErr(err)
	}
	for head.typ != zfin {
		if head.typ == zcan {
			return ErrCancelled
		}
		head, _, err = conversation.awaitHeaderOnly(maxRetries)
		if err != nil {
			return mapErr(err)
		}
	}
	return conversation.writer.raw([]byte("OO"))
}

// sendFile offers one file: its info subpacket, then its data from wherever the far end
// asks (0, or its resume offset), retrying a request for an earlier offset until the far
// end accepts the end of the file.
func (conversation *session) sendFile(path string, rest []string) error {
	file, err := os.Open(path) //nolint:gosec // the caller names its own files to send
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // read-only; nothing left to flush on close
	stat, err := file.Stat()
	if err != nil {
		return err
	}
	size := stat.Size()
	name := filepath.Base(path)

	var bytesLeft int64
	for _, pending := range rest {
		if fi2, err := os.Stat(pending); err == nil {
			bytesLeft += fi2.Size()
		}
	}
	info := encodeFileInfo(name, size, stat.ModTime(), len(rest), bytesLeft)

	// ZF0: binary, or ZCRESUM (3) to ask the far end to report the exact byte count it
	// already holds rather than rounding down to a block boundary out of caution.
	conversion := byte(1)
	if conversation.opt.Resume {
		conversion = 3
	}
	head, _, err := conversation.await(func() error {
		if err := conversation.writeHeader(header{typ: zfile, data: [4]byte{conversion, 0, 0, 0}}, false); err != nil {
			return err
		}
		return writeSubpacket(conversation.writer, info, zcrcw, conversation.useCRC32)
	}, maxRetries)
	if err != nil {
		return mapErr(err)
	}
	// Only a ZRPOS or ZSKIP actually answers the ZFILE. In between, a far end can emit
	// noise this exchange didn't ask for: a ZACK for the info subpacket's own zcrcw (a
	// separate frame from the answer), or a stale ZRINIT it was still retrying when our
	// ZFILE arrived. Skipping anything else keeps that noise from being mistaken for the
	// answer and left to surprise the data-streaming loop later as a bogus interrupt.
	for head.typ != zrpos && head.typ != zskip {
		if head.typ == zcan {
			return ErrCancelled
		}
		head, _, err = conversation.awaitHeaderOnly(maxRetries)
		if err != nil {
			return mapErr(err)
		}
	}

	var offset int64
	switch head.typ {
	case zrpos:
		if position := head.position(); position >= 0 && position <= size {
			offset = position
		}
	case zskip:
		return nil
	}
	if offset > 0 {
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			return err
		}
	}

	for {
		if err := conversation.streamFrom(file, &offset, size, name); err != nil {
			return err
		}
		head, _, err := conversation.await(func() error { return conversation.writeHeader(posHeader(zeof, offset), false) }, maxRetries)
		if err != nil {
			return mapErr(err)
		}
		if head.typ == zrpos {
			if position := head.position(); position >= 0 && position <= size && position != offset {
				offset = position
				if _, err := file.Seek(offset, io.SeekStart); err != nil {
					return err
				}
				continue
			}
		}
		break
	}
	if conversation.opt.Progress != nil {
		conversation.opt.Progress(Progress{Name: name, Done: size, Total: size})
	}
	return nil
}

// streamFrom sends the file's data in one or more ZDATA frames starting at *offset,
// restarting a fresh frame whenever the far end interrupts with a ZRPOS (a corrupted
// subpacket on its end) asking for a different position.
func (conversation *session) streamFrom(file *os.File, offset *int64, size int64, name string) error {
	chunkSize := conversation.opt.SubpacketSize
	if chunkSize <= 0 {
		chunkSize = 1024
	}
	buf := make([]byte, chunkSize)
	for *offset < size {
		if err := conversation.writeHeader(posHeader(zdata, *offset), false); err != nil {
			return err
		}
		restart, err := conversation.streamOneFrame(file, offset, size, name, buf)
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
	head header
	err  error
}

func (conversation *session) watch(ctx context.Context, out chan<- frameResult) {
	for {
		head, _, ok, err := readFrame(ctx, conversation.src, conversation.timeout)
		if err != nil {
			switch {
			case errors.Is(err, ErrTimeout):
				if ctx.Err() != nil {
					return
				}
				continue
			case errors.Is(err, ErrCancelled):
				// readByte returns this only when ctx itself was cancelled: our own
				// teardown via stopWatch, or the caller's conversation.ctx, which streamOneFrame's
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
		deliver(ctx, out, frameResult{head: head})
	}
}

// deliver sends result to out, trying a non-blocking send first so an already-decoded frame
// is never lost to a simultaneous ctx cancellation: select picks uniformly among ready
// cases, so without this, a frame arriving the instant the main loop stops reading could
// be silently dropped half the time instead of landing in the channel's open buffer.
func deliver(ctx context.Context, out chan<- frameResult, result frameResult) {
	select {
	case out <- result:
		return
	default:
	}
	select {
	case out <- result:
	case <-ctx.Done():
	}
}

func (conversation *session) streamOneFrame(file *os.File, offset *int64, size int64, name string, buf []byte) (restart bool, err error) {
	watchCtx, cancelWatch := context.WithCancel(conversation.ctx)
	done := make(chan struct{})
	frames := make(chan frameResult, 4)
	go func() {
		defer close(done)
		conversation.watch(watchCtx, frames)
	}()
	// The watcher and the rest of the session both read conversation.src; cancelling isn't enough
	// on its own; stopWatch must also wait for the goroutine to actually stop reading,
	// or it can still take the next byte the caller needs right after this returns.
	stopWatch := func() {
		cancelWatch()
		<-done
	}
	defer stopWatch()

	for *offset < size {
		select {
		case <-conversation.ctx.Done():
			conversation.cancelPeer()
			return false, ErrCancelled
		case result := <-frames:
			if restart, ferr, handled := conversation.handleFrame(result, file, offset, size); handled {
				return restart, ferr
			}
			continue
		default:
		}
		n, rerr := file.Read(buf)
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
		if werr := writeSubpacket(conversation.writer, buf[:n], term, conversation.useCRC32); werr != nil {
			return false, werr
		}
		*offset += int64(n)
		if conversation.opt.Progress != nil {
			conversation.opt.Progress(Progress{Name: name, Done: *offset, Total: size})
		}
	}

	// The far end's ZRPOS for this frame's last subpacket, if it found one corrupt, can
	// still be in flight the instant *offset reaches size; stop the watcher and drain
	// what it already decoded before declaring the frame finished, or that answer is
	// lost and the caller's ZEOF goes to a far end that is still expecting a resend.
	stopWatch()
	for {
		select {
		case result := <-frames:
			if restart, ferr, handled := conversation.handleFrame(result, file, offset, size); handled {
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
func (conversation *session) handleFrame(result frameResult, file *os.File, offset *int64, size int64) (restart bool, err error, handled bool) {
	switch {
	case result.err != nil && (errors.Is(result.err, errGotCancel) || errors.Is(result.err, ErrCancelled)):
		return false, ErrCancelled, true
	case result.err == nil && result.head.typ == zrpos:
		if position := result.head.position(); position >= 0 && position <= size {
			*offset = position
			if _, err := file.Seek(*offset, io.SeekStart); err != nil {
				return false, err, true
			}
			return true, nil, true
		}
	}
	return false, nil, false
}
