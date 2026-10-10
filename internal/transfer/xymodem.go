// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package transfer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

// XMODEM and YMODEM protocol bytes. Names follow Chuck Forsberg's XMODEM/YMODEM protocol
// reference. Unlike ZMODEM these protocols move raw bytes with no escaping layer.
const (
	xsoh   = 0x01 // starts a 128-byte block
	xstx   = 0x02 // starts a 1024-byte block
	xeot   = 0x04 // no more blocks
	xack   = 0x06
	xnak   = 0x15
	xcan   = 0x18 // the same byte as ZMODEM's ZDLE; cancel-run detection applies only between blocks, never inside one — see xyreadBlock
	xcrc   = 'C'  // the receiver's opening byte, asking for 16-bit CRC
	xgmode = 'G'  // the receiver's opening byte, asking for streaming (YMODEM-G)
	xpad   = 0x1A // pads the last block to the block size
)

// xysession holds the state of one XMODEM or YMODEM conversation. Unlike ZMODEM's
// session there is no escaping layer, so it writes straight to the stream.
type xysession struct {
	ctx     context.Context
	src     *byteSource
	raw     io.Writer
	timeout time.Duration
	opt     Options
}

func newXYSession(ctx context.Context, rw io.ReadWriter, opt Options) *xysession {
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &xysession{ctx: ctx, src: newByteSource(rw), raw: rw, timeout: timeout, opt: opt}
}

func (conversation *xysession) putByte(value byte) error {
	_, err := conversation.raw.Write([]byte{value})
	return err
}

// cancelPeer sends enough raw CAN bytes that no block's data could produce them by
// accident, the same reasoning as ZMODEM's cancel sequence.
func (conversation *xysession) cancelPeer() {
	_, _ = conversation.raw.Write([]byte{xcan, xcan, xcan, xcan, xcan, xcan, xcan, xcan}) //nolint:errcheck // best-effort; we're already ending the session
}

// awaitByte calls send, then waits for one byte, resending and waiting again on a
// timeout up to retries times.
func (conversation *xysession) awaitByte(send func() error, retries int) (byte, error) {
	for range retries {
		if err := send(); err != nil {
			return 0, err
		}
		value, err := conversation.src.readByte(conversation.ctx, conversation.timeout)
		switch {
		case err == nil:
			return value, nil
		case errors.Is(err, errGotCancel):
			return 0, ErrCancelled
		case errors.Is(err, ErrTimeout):
			continue
		default:
			return 0, err
		}
	}
	return 0, ErrTimeout
}

// nextByte waits for one byte without sending anything first, for streaming mode, where
// nothing is acknowledged between blocks.
func (conversation *xysession) nextByte() (byte, error) {
	value, err := conversation.src.readByte(conversation.ctx, conversation.timeout)
	if err != nil {
		if errors.Is(err, errGotCancel) {
			return 0, ErrCancelled
		}
		return 0, err
	}
	return value, nil
}

// openByte is a sender's wait for the receiver's opening byte (NAK, C or G), which also
// says which checksum, if any, the receiver wants.
func (conversation *xysession) openByte() (byte, error) {
	for range xyRetries {
		value, err := conversation.src.readByte(conversation.ctx, conversation.timeout)
		switch {
		case err == nil:
			return value, nil
		case errors.Is(err, errGotCancel):
			return 0, ErrCancelled
		case errors.Is(err, ErrTimeout):
			continue
		default:
			return 0, err
		}
	}
	return 0, ErrTimeout
}

// xyreadBlock reads the rest of one block after its lead byte (xsoh or xstx) has already
// been read: the block number, its complement, 128 or 1024 bytes of data per the lead,
// and a trailing 1-byte checksum or 2-byte CRC per useCRC. ok reports whether the
// complement and trailer validate; it is false, not an error, for ordinary corruption.
// It reads with readRawByte, not readByte: block data is unescaped, so a run of 0x18
// inside it is ordinary content, not the far end's cancel sequence.
func xyreadBlock(ctx context.Context, src *byteSource, timeout time.Duration, lead byte, useCRC bool) (blk byte, data []byte, ok bool, err error) {
	size := 128
	if lead == xstx {
		size = 1024
	}
	trailer := 1
	if useCRC {
		trailer = 2
	}
	raw := make([]byte, 0, 2+size+trailer)
	for len(raw) < 2+size+trailer {
		value, rerr := src.readRawByte(ctx, timeout)
		if rerr != nil {
			return 0, nil, false, rerr
		}
		raw = append(raw, value)
	}
	blk = raw[0]
	data = raw[2 : 2+size]
	tail := raw[2+size:]
	ok = raw[1] == 0xff^blk
	if useCRC {
		want := uint16(tail[0])<<8 | uint16(tail[1])
		ok = ok && crc16(data) == want
	} else {
		var sum byte
		for _, value := range data {
			sum += value
		}
		ok = ok && sum == tail[0]
	}
	return blk, data, ok, nil
}

// xywriteBlock writes one block: SOH or STX per len(data) (128 or 1024), blk, its
// complement, data, and a trailing checksum or CRC per useCRC.
func xywriteBlock(dst io.Writer, blk byte, data []byte, useCRC bool) error {
	lead := byte(xsoh)
	if len(data) > 128 {
		lead = xstx
	}
	buf := make([]byte, 0, len(data)+5)
	buf = append(buf, lead, blk, 0xff^blk)
	buf = append(buf, data...)
	if useCRC {
		crc := crc16(data)
		buf = append(buf, byte(crc>>8), byte(crc)) //nolint:gosec // G115: serializing a 16-bit CRC byte by byte
	} else {
		var sum byte
		for _, value := range data {
			sum += value
		}
		buf = append(buf, sum)
	}
	_, err := dst.Write(buf)
	return err
}

func (conversation *xysession) send(paths []string) error {
	if conversation.opt.Protocol == XMODEM {
		return conversation.sendXMODEM(paths)
	}
	return conversation.sendYMODEM(paths)
}

func (conversation *xysession) receive(root *os.Root) ([]Received, error) {
	if conversation.opt.Protocol == XMODEM {
		return conversation.receiveXMODEM(root)
	}
	return conversation.receiveYMODEM(root)
}

// blocks drives the block phase shared by an XMODEM transfer and one file of a YMODEM
// batch: send open (xnak, xcrc or xgmode) until the far end starts sending blocks, call
// write for each block's data in order starting at 1, and stop at EOT. A bad block is
// NAKed and retransmitted, except in streaming (G) mode, where the first error cancels
// the transfer and reports ErrProtocol: G has no retransmission.
func (conversation *xysession) blocks(open byte, write func([]byte) error) error {
	useCRC := open != xnak
	streaming := open == xgmode
	expected := byte(1)
	control := open
	send := func() error { return conversation.putByte(control) }

	lead, err := conversation.awaitByte(send, xyRetries)
	if err != nil {
		return mapErr(err)
	}
	for {
		switch lead {
		case xeot:
			return conversation.putByte(xack)
		case xcan:
			return ErrCancelled
		case xsoh, xstx:
			blk, data, ok, rerr := xyreadBlock(conversation.ctx, conversation.src, conversation.timeout, lead, useCRC)
			if rerr != nil && errors.Is(rerr, errGotCancel) {
				return ErrCancelled
			}
			switch {
			case rerr == nil && ok && blk == expected:
				if werr := write(data); werr != nil {
					return werr
				}
				expected++
				if streaming {
					lead, err = conversation.nextByte()
				} else {
					control = xack
					lead, err = conversation.awaitByte(send, xyRetries)
				}
			case streaming:
				conversation.cancelPeer()
				return ErrProtocol
			default:
				// ponytail: a lost ACK looks identical to corruption here and is simply
				// retried as a bad block; the oracle never drops a byte, only flips one,
				// so this path only ever fires on genuine corruption in practice.
				control = xnak
				lead, err = conversation.awaitByte(send, xyRetries)
			}
		default:
			if streaming {
				conversation.cancelPeer()
				return ErrProtocol
			}
			control = xnak
			lead, err = conversation.awaitByte(send, xyRetries)
		}
		if err != nil {
			return mapErr(err)
		}
	}
}

// receiveXMODEM accepts one file from the far end into dir, under Options.Name: XMODEM
// carries no name. It keeps the last block's padding, since XMODEM carries no size
// either and there is nothing to trim to.
func (conversation *xysession) receiveXMODEM(root *os.Root) ([]Received, error) {
	base := filepath.Base(conversation.opt.Name)
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = unnamed
	}
	dest := filepath.Join(root.Name(), base)
	file, err := openReceived(root, base, os.O_CREATE|os.O_WRONLY|os.O_TRUNC)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // best-effort on an error exit; the success path closes and checks explicitly

	open := byte(xcrc)
	switch {
	case conversation.opt.Streaming:
		open = xgmode
	case conversation.opt.Checksum:
		open = xnak
	}
	werr := conversation.blocks(open, func(data []byte) error {
		_, ferr := file.Write(data)
		return ferr
	})
	if werr != nil {
		return nil, mapErr(werr)
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	stat, err := root.Stat(base)
	if err != nil {
		return nil, err
	}
	return []Received{{Name: base, Path: dest, Size: stat.Size(), ModTime: stat.ModTime()}}, nil
}

// sendXMODEM sends paths[0], the only file XMODEM carries, waiting for the receiver's
// opening byte to learn whether it wants CRC or checksum blocks.
func (conversation *xysession) sendXMODEM(paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	file, err := os.Open(paths[0])
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // read-only; nothing left to flush on close

	open, err := conversation.openByte()
	if err != nil {
		return mapErr(err)
	}
	if open == xcan {
		return ErrCancelled
	}
	return mapErr(conversation.sendBlocks(file, open == xcrc || open == xgmode, open == xgmode))
}

// sendBlocks sends file's remaining content as blocks of Options.SubpacketSize (128 or
// 1024, default 1024) starting at 1, padding the last block to the block size with
// 0x1A, then sends EOT and waits for the ACK. In streaming (G) mode each block is sent
// without waiting for its own ack, since the receiver opened with G precisely to skip that
// round trip; only EOT still waits, same as the receiver's own G handling in blocks().
func (conversation *xysession) sendBlocks(file *os.File, useCRC, streaming bool) error {
	blockSize := conversation.opt.SubpacketSize
	if blockSize != 128 {
		blockSize = 1024
	}
	buf := make([]byte, blockSize)
	blk := byte(1)
	for {
		n, rerr := io.ReadFull(file, buf)
		if n == 0 {
			break
		}
		if rerr != nil && !errors.Is(rerr, io.EOF) && !errors.Is(rerr, io.ErrUnexpectedEOF) {
			return rerr
		}
		data := buf[:n:n]
		if n < blockSize {
			data = append(data, bytes.Repeat([]byte{xpad}, blockSize-n)...)
		}
		if streaming {
			if err := xywriteBlock(conversation.raw, blk, data, useCRC); err != nil {
				return err
			}
		} else if err := conversation.sendOneBlock(blk, data, useCRC); err != nil {
			return err
		}
		blk++
	}
	return conversation.sendEOT()
}

func (conversation *xysession) sendOneBlock(blk byte, data []byte, useCRC bool) error {
	for range xyRetries {
		if err := xywriteBlock(conversation.raw, blk, data, useCRC); err != nil {
			return err
		}
		reply, err := conversation.src.readByte(conversation.ctx, conversation.timeout)
		switch {
		case err != nil && errors.Is(err, errGotCancel):
			return ErrCancelled
		case err != nil && errors.Is(err, ErrTimeout):
			continue
		case err != nil:
			return err
		case reply == xack:
			return nil
		case reply == xcan:
			return ErrCancelled
		default:
			continue // a NAK, or noise: resend the same block
		}
	}
	return ErrTimeout
}

func (conversation *xysession) sendEOT() error {
	for range xyRetries {
		if err := conversation.putByte(xeot); err != nil {
			return err
		}
		reply, err := conversation.src.readByte(conversation.ctx, conversation.timeout)
		switch {
		case err != nil && errors.Is(err, errGotCancel):
			return ErrCancelled
		case err != nil && errors.Is(err, ErrTimeout):
			continue
		case err != nil:
			return err
		case reply == xack:
			return nil
		default:
			continue // a NAK, or noise: resend EOT
		}
	}
	return ErrTimeout
}

// receiveYMODEM accepts a batch from the far end into dir: block 0 names each file in
// turn, then its data follows as XMODEM blocks under a fresh open, until a block 0 with
// an empty name ends the batch.
func (conversation *xysession) receiveYMODEM(root *os.Root) ([]Received, error) {
	open := byte(xcrc)
	switch {
	case conversation.opt.Streaming:
		open = xgmode
	case conversation.opt.Checksum:
		open = xnak
	}
	var out []Received
	for {
		header, err := conversation.receiveHeaderBlock(open)
		if err != nil {
			return out, mapErr(err)
		}
		if header == nil {
			return out, nil
		}
		rec, err := conversation.receiveOneYMODEMFile(root, open, header)
		if err != nil {
			return out, mapErr(err)
		}
		out = append(out, rec)
	}
}

// receiveHeaderBlock opens with open and waits for YMODEM's block 0, ACKing it like any
// other block. A block 0 whose name is empty ends the batch and is reported as nil, nil.
func (conversation *xysession) receiveHeaderBlock(open byte) ([]byte, error) {
	useCRC := open != xnak
	control := open
	send := func() error { return conversation.putByte(control) }
	lead, err := conversation.awaitByte(send, xyRetries)
	if err != nil {
		return nil, err
	}
	for {
		switch lead {
		case xeot:
			return nil, conversation.putByte(xack)
		case xcan:
			return nil, ErrCancelled
		case xsoh, xstx:
			_, data, ok, rerr := xyreadBlock(conversation.ctx, conversation.src, conversation.timeout, lead, useCRC)
			if rerr != nil && errors.Is(rerr, errGotCancel) {
				return nil, ErrCancelled
			}
			if rerr != nil || !ok {
				control = xnak
				lead, err = conversation.awaitByte(send, xyRetries)
				break
			}
			if ackErr := conversation.putByte(xack); ackErr != nil {
				return nil, ackErr
			}
			// lrzsz's sb writes the file's 128-byte block count into the header's last two
			// bytes on purpose, for the old IMP and KMD programs; its closing header
			// carries the previous file's count there instead of zeroing it. Only the
			// name field (NUL-terminated from byte 0) says whether this is a real file or
			// the batch's closing empty header.
			if name, _, _ := decodeFileInfo(data); name == "" {
				return nil, nil
			}
			return data, nil
		default:
			control = xnak
			lead, err = conversation.awaitByte(send, xyRetries)
		}
		if err != nil {
			return nil, err
		}
	}
}

// receiveOneYMODEMFile reads header's name, size and modification time, then the file's
// data as XMODEM blocks, and stores it trimmed to size: unlike XMODEM, YMODEM carries
// the size, so the last block's padding is not part of the stored file. A block 0 without
// a length leaves every byte that arrived.
func (conversation *xysession) receiveOneYMODEMFile(root *os.Root, open byte, header []byte) (Received, error) {
	name, size, mtime := decodeFileInfo(header)
	base := filepath.Base(name)
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = unnamed
	}
	dest := filepath.Join(root.Name(), base)
	file, err := openReceived(root, base, os.O_CREATE|os.O_WRONLY|os.O_TRUNC)
	if errors.Is(err, ErrNameRefused) {
		conversation.cancelPeer()
		return Received{}, err
	}
	if err != nil {
		return Received{}, err
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // best-effort on an error exit; the success path closes and checks explicitly

	var written int64
	werr := conversation.blocks(open, func(data []byte) error {
		n, ferr := file.Write(data)
		written += int64(n)
		return ferr
	})
	if werr != nil {
		return Received{}, werr
	}
	if hasFileLength(header) && size >= 0 && size < written {
		if err := file.Truncate(size); err != nil {
			return Received{}, err
		}
		written = size
	}
	if err := file.Close(); err != nil {
		return Received{}, err
	}
	if !mtime.IsZero() {
		if err := root.Chtimes(base, mtime, mtime); err != nil {
			return Received{}, err
		}
	}
	return Received{Name: base, Path: dest, Size: written, ModTime: mtime}, nil
}

// sendYMODEM sends each path as one YMODEM batch entry, then a null block 0 to end it.
func (conversation *xysession) sendYMODEM(paths []string) error {
	for _, path := range paths {
		if err := conversation.sendOneYMODEMFile(path); err != nil {
			return err
		}
	}
	open, err := conversation.openByte()
	if err != nil {
		return mapErr(err)
	}
	if open == xcan {
		return ErrCancelled
	}
	_, err = conversation.sendHeaderBlock(nil, open == xcrc || open == xgmode)
	if errors.Is(err, io.EOF) {
		// Every real file already got its ack; some receivers (sexyz's ry) exit the
		// moment they see the batch's closing null block instead of acking it too, which
		// is a clean end, not a cancel.
		return nil
	}
	return mapErr(err)
}

// sendOneYMODEMFile sends path's block 0 (name, size, modification time), waits for a
// fresh open to begin its data phase, same as a new XMODEM transfer, then its blocks.
func (conversation *xysession) sendOneYMODEMFile(path string) error {
	//nolint:gosec // the caller names its own files to send
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // read-only; nothing left to flush on close
	stat, err := file.Stat()
	if err != nil {
		return err
	}

	open, err := conversation.openByte()
	if err != nil {
		return mapErr(err)
	}
	if open == xcan {
		return ErrCancelled
	}
	info := encodeFileInfo(filepath.Base(path), stat.Size(), stat.ModTime(), 0, 0)
	reply, err := conversation.sendHeaderBlock(info, open == xcrc || open == xgmode)
	if err != nil {
		return mapErr(err)
	}
	// In streaming mode sexyz's ry/rg acks the header with a fresh 'G' directly, rather
	// than a plain ACK followed by its own separate open byte for the data phase; a plain
	// ACK still gets the usual fresh open byte before data starts.
	if reply != xgmode {
		reply, err = conversation.openByte()
		if err != nil {
			return mapErr(err)
		}
	}
	if reply == xcan {
		return ErrCancelled
	}
	return mapErr(conversation.sendBlocks(file, reply == xcrc || reply == xgmode, reply == xgmode))
}

// sendHeaderBlock sends YMODEM's block 0, info padded with NUL to the block size (or all
// NUL when info is nil, which ends the batch), and waits for the ack, reporting it back:
// a plain ACK, or sexyz's streaming receivers which fold the ack and their next open byte
// into a single 'G'.
func (conversation *xysession) sendHeaderBlock(info []byte, useCRC bool) (byte, error) {
	blockSize := conversation.opt.SubpacketSize
	if blockSize != 128 {
		blockSize = 1024
	}
	data := make([]byte, blockSize)
	copy(data, info)
	for range xyRetries {
		if err := xywriteBlock(conversation.raw, 0, data, useCRC); err != nil {
			return 0, err
		}
		reply, err := conversation.src.readByte(conversation.ctx, conversation.timeout)
		switch {
		case err != nil && errors.Is(err, errGotCancel):
			return 0, ErrCancelled
		case err != nil && errors.Is(err, ErrTimeout):
			continue
		case err != nil:
			return 0, err
		case reply == xack, reply == xgmode:
			return reply, nil
		case reply == xcan:
			return 0, ErrCancelled
		default:
			continue // a NAK, or noise: resend block 0
		}
	}
	return 0, ErrTimeout
}
