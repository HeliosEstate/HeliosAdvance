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
func (s *session) receive(dir string) ([]Received, error) {
	var out []Received
	flags := byte(canfdx | canovio | canfc32)
	if s.opt.Escape {
		flags |= escctl
	}
	for {
		h, crc32mode, err := s.await(func() error {
			return writeHex(s.zw, header{typ: zrinit, data: [4]byte{0, 0, 0, flags}})
		}, maxRetries)
		if err != nil {
			return out, mapErr(err)
		}
		switch h.typ {
		case zfile:
			rec, err := s.receiveFile(dir, crc32mode)
			if err != nil {
				return out, err
			}
			out = append(out, rec)
		case zcommand:
			_, _, _, _ = readSubpacket(s.ctx, s.src, s.timeout, maxSubpacket, crc32mode)
			s.cancelPeer()
			return out, ErrRemoteCommand
		case zfin:
			_ = writeHex(s.zw, header{typ: zfin})
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
func (s *session) receiveFile(dir string, crc32mode bool) (Received, error) {
	info, _, ok, err := readSubpacket(s.ctx, s.src, s.timeout, maxSubpacket, crc32mode)
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
	if s.opt.Resume {
		if fi, err := os.Stat(dest); err == nil && fi.Size() <= size {
			offset = fi.Size()
		}
	}
	if offset == 0 {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(dest, flags, 0o600)
	if err != nil {
		return Received{}, err
	}
	defer func() { _ = f.Close() }()
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return Received{}, err
		}
	}
	if s.opt.Progress != nil {
		s.opt.Progress(Progress{Name: base, Done: offset, Total: size})
	}

	sendRPos := func() error { return s.writeHeader(posHeader(zrpos, offset), false) }
	h, hcrc32, err := s.await(sendRPos, maxRetries)
	if err != nil {
		return Received{}, mapErr(err)
	}

	for {
		switch h.typ {
		case zeof:
			if h.position() != offset {
				h, hcrc32, err = s.await(sendRPos, maxRetries)
				if err != nil {
					return Received{}, mapErr(err)
				}
				continue
			}
			_ = f.Close()
			_ = os.Chtimes(dest, mtime, mtime)
			return Received{Name: base, Path: dest, Size: offset, ModTime: mtime}, nil
		case zdata:
			broken, err := s.consumeDataFrame(f, &offset, size, base, hcrc32)
			if err != nil {
				return Received{}, err
			}
			if broken {
				h, hcrc32, err = s.await(sendRPos, maxRetries)
			} else {
				h, hcrc32, err = s.awaitHeaderOnly(maxRetries)
			}
		default:
			h, hcrc32, err = s.await(sendRPos, maxRetries)
		}
		if err != nil {
			return Received{}, mapErr(err)
		}
	}
}

// consumeDataFrame reads subpackets from one ZDATA frame, writing each to f and
// reporting progress, until a terminator ends the frame or a bad CRC breaks it (the
// caller then re-requests from the last good offset).
func (s *session) consumeDataFrame(f *os.File, offset *int64, total int64, name string, crc32mode bool) (broken bool, err error) {
	for {
		select {
		case <-s.ctx.Done():
			s.cancelPeer()
			return false, ErrCancelled
		default:
		}
		data, term, ok, err := readSubpacket(s.ctx, s.src, s.timeout, maxSubpacket, crc32mode)
		if err != nil {
			if errors.Is(err, errGotCancel) {
				return false, ErrCancelled
			}
			return false, mapErr(err)
		}
		if !ok {
			return true, nil
		}
		if _, err := f.Write(data); err != nil {
			return false, err
		}
		*offset += int64(len(data))
		if s.opt.Progress != nil {
			s.opt.Progress(Progress{Name: name, Done: *offset, Total: total})
		}
		switch term {
		case zcrcw, zcrcq:
			if err := s.writeHeader(posHeader(zack, *offset), false); err != nil {
				return false, err
			}
			if term == zcrcw {
				return false, nil
			}
		case zcrce:
			return false, nil
		}
	}
}
