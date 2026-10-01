// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package transfer moves files over a byte stream with the classic BBS protocols. It
// speaks over an io.ReadWriter and knows nothing about sessions, terminals or transports:
// a telnet transport doubles IAC before the bytes get here, an SSH transport hands over
// the channel, the module sees a clean stream either way.
//
// The exported names in this file are the ones the approved tests call; a change to one
// is a change to a locked test.
package transfer

import (
	"context"
	"errors"
	"io"
	"time"
)

// Errors a transfer reports. A caller tests them with errors.Is.
var (
	ErrCancelled     = errors.New("transfer: cancelled")
	ErrTimeout       = errors.New("transfer: timeout")
	ErrRemoteCommand = errors.New("transfer: remote command refused")
	ErrProtocol      = errors.New("transfer: protocol error")
)

// Options shape one transfer. The zero value is ZMODEM with 1K subpackets, 32-bit CRC
// where the far end allows it, and no escaping beyond what the protocol requires.
type Options struct {
	// Escape asks the far end to escape all control characters when it sends to us, and
	// escapes them when we send to a far end that asks.
	Escape bool
	// CRC16 forces 16-bit CRC on send even where the far end could take 32-bit.
	CRC16 bool
	// SubpacketSize is the largest ZMODEM subpacket we offer when sending: 1024 or 8192.
	// Zero means 1024.
	SubpacketSize int
	// Resume continues a file the receiver already holds in part, from the bytes it has.
	Resume bool
	// Timeout is how long to wait for the far end before giving up with ErrTimeout. Zero
	// means ten seconds.
	Timeout time.Duration
	// Progress, if set, is called as bytes move: after each subpacket and at the end of
	// each file. Done reaches Total for every file that completes.
	Progress func(Progress)
}

// Progress is one report from a transfer in flight.
type Progress struct {
	Name  string
	Done  int64
	Total int64
}

// Received describes one file a Receive stored.
type Received struct {
	Name    string
	Path    string
	Size    int64
	ModTime time.Time
}

// Send offers the named files by ZMODEM to the far end on rw, in order, and ends the
// session cleanly after the last. It returns on the far end's cancel (ErrCancelled), on
// ctx being done (ErrCancelled, after sending the cancel sequence), on silence past the
// timeout (ErrTimeout), or on success.
func Send(ctx context.Context, rw io.ReadWriter, paths []string, opt Options) error {
	//nolint:contextcheck // ctx is the one stored on the session; streamOneFrame derives its watcher context from that same field
	return newSession(ctx, rw, opt).send(paths)
}

// Receive accepts a ZMODEM batch from the far end on rw into dir and returns what it
// stored, in the order received, each with the name, size and modification time from
// its header. A ZCOMMAND frame is refused with ErrRemoteCommand and nothing is run.
func Receive(ctx context.Context, rw io.ReadWriter, dir string, opt Options) ([]Received, error) {
	return newSession(ctx, rw, opt).receive(dir)
}
