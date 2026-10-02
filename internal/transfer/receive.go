// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package transfer

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

// receive drives the receiver side of a ZMODEM batch: advertise readiness, accept each
// file the far end offers, and stop cleanly at ZFIN.
func (conversation *session) receive(dir string) ([]Received, error) {
	var out []Received
	flags := byte(canfdx | canovio | canfc32)
	if conversation.opt.Escape {
		flags |= escctl
	}
	for {
		head, crc32mode, err := conversation.await(func() error {
			return writeHex(conversation.writer, header{typ: zrinit, data: [4]byte{0, 0, 0, flags}})
		}, maxRetries)
		if err != nil {
			return out, mapErr(err)
		}
		switch head.typ {
		case zfile:
			rec, err := conversation.receiveFile(dir, crc32mode)
			if err != nil {
				return out, err
			}
			out = append(out, rec)
		case zcommand:
			//nolint:errcheck // refused regardless of the command text or whether it even arrives whole
			_, _, _, _ = readSubpacket(conversation.ctx, conversation.src, conversation.timeout, maxSubpacket, crc32mode)
			conversation.cancelPeer()
			return out, ErrRemoteCommand
		case zfin:
			//nolint:errcheck // the far end already declared the batch done; our reply is a courtesy
			_ = writeHex(conversation.writer, header{typ: zfin})
			return out, nil
		case zcan:
			return out, ErrCancelled
		default:
			continue
		}
	}
}

// receiveFile reads one file's info subpacket, tells the far end where to start (0, or
// the size already on disk when resuming), and writes the data it sends until ZEOF.
func (conversation *session) receiveFile(dir string, crc32mode bool) (Received, error) {
	info, _, ok, err := readSubpacket(conversation.ctx, conversation.src, conversation.timeout, maxSubpacket, crc32mode)
	if err != nil {
		return Received{}, mapErr(err)
	}
	if !ok {
		return Received{}, ErrProtocol
	}
	name, size, mtime := decodeFileInfo(info)
	base := filepath.Base(name)
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = unnamed
	}
	dest := filepath.Join(dir, base)

	var offset int64
	flags := os.O_CREATE | os.O_WRONLY
	if conversation.opt.Resume {
		if stat, err := os.Stat(dest); err == nil && stat.Size() <= size {
			offset = stat.Size()
		}
	}
	if offset == 0 {
		flags |= os.O_TRUNC
	}
	//nolint:gosec // G304: dest is dir joined with filepath.Base(name), so it cannot escape dir
	file, err := os.OpenFile(dest, flags, 0o600)
	if err != nil {
		return Received{}, err
	}
	//nolint:errcheck // best-effort on an error exit; the success path closes and checks explicitly
	defer func() { _ = file.Close() }()
	if offset > 0 {
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			return Received{}, err
		}
	}
	if conversation.opt.Progress != nil {
		conversation.opt.Progress(Progress{Name: base, Done: offset, Total: size})
	}

	sendRPos := func() error { return conversation.writeHeader(posHeader(zrpos, offset), false) }
	head, hcrc32, err := conversation.await(sendRPos, maxRetries)
	if err != nil {
		return Received{}, mapErr(err)
	}

	// A resync that lands at the same offset as the last one means a dead line, not a
	// transient error (the far end genuinely retried and we're still stuck); give up
	// after maxRetries of those in a row rather than retrying a corrupted frame forever.
	stuckAt := int64(-1)
	stuckCount := 0
	// Once a frame has come back corrupted, some senders (lrzsz's sz especially) switch
	// into a cautious windowed mode where a ZCRCW's ack is not reliably followed by a
	// fresh header on their own; from then on a ZCRCW gets an immediate ZRPOS nudge
	// rather than the one passive wait a clean transfer gets.
	recovering := false
	for {
		switch head.typ {
		case zeof:
			if head.position() != offset {
				head, hcrc32, err = conversation.await(sendRPos, maxRetries)
				if err != nil {
					return Received{}, mapErr(err)
				}
				continue
			}
			if err := file.Close(); err != nil {
				return Received{}, err
			}
			if err := os.Chtimes(dest, mtime, mtime); err != nil {
				return Received{}, err
			}
			return Received{Name: base, Path: dest, Size: offset, ModTime: mtime}, nil
		case zdata:
			// sz can retransmit a frame it already sent (its retry raced our ZRPOS);
			// skip back over whatever this frame repeats instead of rewriting it.
			skip := max(offset-head.position(), 0)
			before := offset
			var corrupted, resync bool
			corrupted, resync, err = conversation.consumeDataFrame(file, &offset, size, base, hcrc32, skip, recovering)
			if err != nil {
				return Received{}, err
			}
			if corrupted {
				recovering = true
				// A resync landing at the same offset as the last one means a dead line,
				// not a transient error (the far end genuinely retried and we're still
				// stuck): give up after maxRetries of those in a row rather than retrying
				// a corrupted frame forever. A clean ZCRCW resync (no corruption) never
				// counts here: the far end does not always follow it with a fresh header
				// on its own, so asking again at the same offset there is routine, not stuck.
				if offset == before && offset == stuckAt {
					stuckCount++
					if stuckCount >= maxRetries {
						return Received{}, ErrTimeout
					}
				} else {
					stuckAt, stuckCount = offset, 0
				}
			}
			switch {
			case resync:
				head, hcrc32, err = conversation.await(sendRPos, maxRetries)
			default:
				// A clean end normally gets a header on its own; try that passively once
				// before nudging with a ZRPOS, for senders that need the nudge instead.
				head, hcrc32, err = conversation.awaitHeaderOnly(1)
				if errors.Is(err, ErrTimeout) {
					head, hcrc32, err = conversation.await(sendRPos, maxRetries)
				}
			}
		default:
			head, hcrc32, err = conversation.await(sendRPos, maxRetries)
		}
		if err != nil {
			return Received{}, mapErr(err)
		}
	}
}

// consumeDataFrame reads subpackets from one ZDATA frame, writing each to f and
// reporting progress, until a terminator ends the frame or a bad CRC breaks it. corrupted
// reports a genuine CRC or protocol failure, needing a fresh offset to retry from; resync
// reports that the caller should proactively ask for the next position (ZRPOS) rather than
// passively wait for a header, which covers both corruption and a clean ZCRCW end (the far
// end, lrzsz's sz especially, does not reliably follow ZCRCW with a fresh header on its own).
func (conversation *session) consumeDataFrame(file *os.File, offset *int64, total int64, name string, crc32mode bool, skip int64, recovering bool) (corrupted, resync bool, err error) {
	for {
		select {
		case <-conversation.ctx.Done():
			conversation.cancelPeer()
			return false, false, ErrCancelled
		default:
		}
		data, term, ok, err := readSubpacket(conversation.ctx, conversation.src, conversation.timeout, maxSubpacket, crc32mode)
		if err != nil {
			switch {
			case errors.Is(err, errGotCancel), errors.Is(err, ErrCancelled):
				return false, false, ErrCancelled
			case errors.Is(err, ErrTimeout), errors.Is(err, ErrProtocol):
				// A corrupted ZDLE can eat the terminator and CRC bytes along with it,
				// so the far end's next write (often just silence, waiting for our ack)
				// looks like a stall rather than a bad CRC. Either way, resync.
				return true, true, nil
			default:
				return false, false, mapErr(err)
			}
		}
		if !ok {
			return true, true, nil
		}
		if skip > 0 {
			if skip >= int64(len(data)) {
				skip -= int64(len(data))
				data = nil
			} else {
				data = data[skip:]
				skip = 0
			}
		}
		if len(data) > 0 {
			if _, err := file.Write(data); err != nil {
				return false, false, err
			}
			*offset += int64(len(data))
			if conversation.opt.Progress != nil {
				conversation.opt.Progress(Progress{Name: name, Done: *offset, Total: total})
			}
		}
		switch term {
		case zcrcq:
			// Asks for an ack but keeps streaming more subpackets in the same frame with
			// no fresh header (sz windowing mid-file).
			if err := conversation.writeHeader(posHeader(zack, *offset), false); err != nil {
				return false, false, err
			}
		case zcrcw:
			// Ends the frame and asks for an ack; a header is supposed to follow. Once a
			// sender has needed a resync, it may not reliably send one on its own (lrzsz's
			// sz under heavy windowing): nudge it with a ZRPOS right away. Otherwise try
			// a passive wait first, like zcrce, since the sender usually sends one anyway.
			if err := conversation.writeHeader(posHeader(zack, *offset), false); err != nil {
				return false, false, err
			}
			return false, recovering, nil
		case zcrce:
			return false, false, nil
		}
	}
}
