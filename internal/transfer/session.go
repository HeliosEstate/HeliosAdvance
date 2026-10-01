// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package transfer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"time"
)

// maxRetries bounds how many times a session resends a frame while awaiting a reply
// before giving up. Each attempt waits up to the session's timeout, so a caller's
// Options.Timeout still bounds how long a hung exchange takes to fail.
const maxRetries = 3

// maxSubpacket is a safety bound on a decoded subpacket's size: larger than any
// SubpacketSize this package offers (1024 or 8192), so it never rejects a good packet.
const maxSubpacket = 8200

// session holds the state of one ZMODEM conversation: the stream, the escape and CRC
// choices for frames this side originates, and the options the caller asked for.
type session struct {
	ctx      context.Context
	src      *byteSource
	zw       *zwriter
	raw      io.Writer
	timeout  time.Duration
	useCRC32 bool
	opt      Options
}

func newSession(ctx context.Context, rw io.ReadWriter, opt Options) *session {
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &session{
		ctx:      ctx,
		src:      newByteSource(rw),
		zw:       newZWriter(rw, opt.Escape),
		raw:      rw,
		timeout:  timeout,
		useCRC32: !opt.CRC16,
		opt:      opt,
	}
}

func (s *session) writeHeader(h header, hex bool) error {
	if hex {
		return writeHex(s.zw, h)
	}
	return writeBinary(s.zw, h, s.useCRC32)
}

// cancelPeer sends the ZMODEM cancel sequence: enough raw CAN bytes that no escaped
// stream could produce them by accident.
func (s *session) cancelPeer() {
	_, _ = s.raw.Write(bytes.Repeat([]byte{zdle}, 8))
}

// awaitHeaderOnly waits for the next valid header, retrying a bad CRC immediately and a
// read timeout up to retries times.
func (s *session) awaitHeaderOnly(retries int) (header, bool, error) {
	for range retries {
		h, crc32mode, ok, err := readFrame(s.ctx, s.src, s.timeout)
		switch {
		case err != nil && (errors.Is(err, errGotCancel) || errors.Is(err, ErrCancelled)):
			return header{}, false, ErrCancelled
		case err != nil && errors.Is(err, ErrTimeout):
			continue
		case err != nil:
			return header{}, false, err
		case !ok:
			continue
		default:
			return h, crc32mode, nil
		}
	}
	return header{}, false, ErrTimeout
}

// await sends (or resends) via send, then waits for the next valid header, retrying the
// whole send-and-wait cycle up to retries times.
func (s *session) await(send func() error, retries int) (header, bool, error) {
	for range retries {
		if err := send(); err != nil {
			return header{}, false, err
		}
		h, crc32mode, err := s.awaitHeaderOnly(1)
		switch {
		case err == nil:
			return h, crc32mode, nil
		case errors.Is(err, ErrCancelled):
			return header{}, false, err
		case !errors.Is(err, ErrTimeout):
			return header{}, false, err
		}
	}
	return header{}, false, ErrTimeout
}

// mapErr turns the internal cancel sentinel and a closed stream into the errors the
// public API promises.
func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errGotCancel):
		return ErrCancelled
	case errors.Is(err, ErrCancelled), errors.Is(err, ErrTimeout), errors.Is(err, ErrProtocol), errors.Is(err, ErrRemoteCommand):
		return err
	case errors.Is(err, io.EOF):
		return ErrTimeout
	default:
		return err
	}
}
