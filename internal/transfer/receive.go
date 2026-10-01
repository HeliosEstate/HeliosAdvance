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
		base = "unnamed"
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
			var broken bool
			broken, err = conversation.consumeDataFrame(file, &offset, size, base, hcrc32, skip)
			if err != nil {
				return Received{}, err
			}
			if broken {
				if offset == before && offset == stuckAt {
					stuckCount++
					if stuckCount >= maxRetries {
						return Received{}, ErrTimeout
					}
				} else {
					stuckAt, stuckCount = offset, 0
				}
				head, hcrc32, err = conversation.await(sendRPos, maxRetries)
			} else {
				head, hcrc32, err = conversation.awaitHeaderOnly(maxRetries)
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
// reporting progress, until a terminator ends the frame or a bad CRC breaks it (the
// caller then re-requests from the last good offset).
func (conversation *session) consumeDataFrame(file *os.File, offset *int64, total int64, name string, crc32mode bool, skip int64) (broken bool, err error) {
	for {
		select {
		case <-conversation.ctx.Done():
			conversation.cancelPeer()
			return false, ErrCancelled
		default:
		}
		data, term, ok, err := readSubpacket(conversation.ctx, conversation.src, conversation.timeout, maxSubpacket, crc32mode)
		if err != nil {
			switch {
			case errors.Is(err, errGotCancel), errors.Is(err, ErrCancelled):
				return false, ErrCancelled
			case errors.Is(err, ErrTimeout), errors.Is(err, ErrProtocol):
				// A corrupted ZDLE can eat the terminator and CRC bytes along with it,
				// so the far end's next write (often just silence, waiting for our ack)
				// looks like a stall rather than a bad CRC. Either way, resync.
				return true, nil
			default:
				return false, mapErr(err)
			}
		}
		if !ok {
			return true, nil
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
				return false, err
			}
			*offset += int64(len(data))
			if conversation.opt.Progress != nil {
				conversation.opt.Progress(Progress{Name: name, Done: *offset, Total: total})
			}
		}
		switch term {
		case zcrcw, zcrcq:
			// Both ask for an ack; neither ends the frame (sz can keep streaming more
			// subpackets after a zcrcw ack without a fresh header, e.g. once it starts
			// windowing after noticing a lossy line). Only ZCRCE really ends it.
			if err := conversation.writeHeader(posHeader(zack, *offset), false); err != nil {
				return false, err
			}
		case zcrce:
			return false, nil
		}
	}
}
