// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The approved tests for issue #141, written by the QA session from the issue's lines: a
// name that would reach past the download folder is refused with ErrNameRefused, and the
// transfer is cancelled. No real sender names a file "..", so those rows use a sender
// written here from the standard library, never from the module's own frame code, which
// would hide a fault in the encoder behind the same fault in the decoder. The edges a real
// sender can send come from the lrzsz oracle. The symbolic link rows are in
// names_linux_test.go and the Windows device name rows in names_windows_test.go.
package transfer_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/transfer"
)

const (
	lineParentName = "When a sender names a file `..` or `a/..`, the receive cancels the transfer with `ErrNameRefused` and writes nothing outside the download folder."
	lineXMODEMName = "When an XMODEM receive is given an `Options.Name` of `..` or `a/..`, of a symbolic link in the download folder that points outside it, or on Windows of a reserved device name, the receive returns `ErrNameRefused` before it sends its opening byte and writes nothing outside the folder."
)

// The two names the parent line gives: the parent itself, and the parent reached through a
// folder.
const (
	parentName          = ".."
	parentThroughFolder = "a/.."
)

// nameRowDeadline bounds a row against today's code, which accepts some of these names
// and then waits for data the test's own sender never sends.
const nameRowDeadline = 30 * time.Second

// The ZMODEM spec aborts a session on five CAN bytes in a row; XMODEM and YMODEM on two.
// CAN is also ZMODEM's escape byte, so one alone starts every ZMODEM header.
const (
	zmodemCancelRun = 5
	ymodemCancelRun = 2
	cancelByte      = 0x18
)

// ymodemStartOfBlock leads a 128-byte XMODEM or YMODEM block.
const ymodemStartOfBlock = 0x01

// withinNameRow is the row's context, ending at nameRowDeadline.
func withinNameRow(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), nameRowDeadline)
	t.Cleanup(cancel)
	return ctx
}

// newDownloadFolder makes a parent folder with an empty download folder inside it, so a
// row can watch the parent for anything written outside the download folder.
func newDownloadFolder(t *testing.T) (parent, download string) {
	t.Helper()
	parent = t.TempDir()
	download = filepath.Join(parent, "download")
	if err := os.Mkdir(download, 0o700); err != nil {
		t.Fatal(err)
	}
	return parent, download
}

// folderState lists every entry under parent, the parent included, with its type, size,
// modification time and, for a regular file, its checksum. Two equal states mean nothing
// under parent was created, removed or written.
func folderState(t *testing.T, parent string) string {
	t.Helper()
	var state strings.Builder
	err := filepath.WalkDir(parent, func(path string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(parent, path)
		if err != nil {
			return err
		}
		fmt.Fprintf(&state, "%s %v %d %d", relative, info.Mode().Type(), info.Size(), info.ModTime().UnixNano())
		if info.Mode().IsRegular() {
			fmt.Fprintf(&state, " %s", mustSum(t, path))
		}
		state.WriteString("\n")
		return nil
	})
	if err != nil {
		t.Fatalf("listing %s: %v", parent, err)
	}
	return state.String()
}

// loopback returns the two ends of a real TCP connection on the loopback interface. The
// far end, theirs, stops at deadline, so a sender written here never outlives its row.
func loopback(t *testing.T, deadline time.Time) (ours, theirs *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, acceptErr := listener.AcceptTCP()
		if acceptErr != nil {
			accepted <- nil
			return
		}
		accepted <- conn
	}()
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("the listener's address %v is not TCP", listener.Addr())
	}
	ours, err = net.DialTCP("tcp", nil, address)
	if err != nil {
		t.Fatal(err)
	}
	theirs = <-accepted
	if theirs == nil {
		_ = ours.Close()
		t.Fatal("accepting the loopback connection failed")
	}
	t.Cleanup(func() { _ = ours.Close(); _ = theirs.Close() })
	if err := theirs.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	return ours, theirs
}

// crcXMODEM is the 16-bit CRC that ZMODEM headers and XMODEM and YMODEM blocks carry:
// polynomial 0x1021, starting from zero.
func crcXMODEM(data []byte) uint16 {
	var crc uint16
	for _, value := range data {
		crc ^= uint16(value) << 8
		for range 8 {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// appendZMODEMEscaped appends value as a ZMODEM sender must: the escape byte itself and
// the flow-control bytes go as the escape byte and the value with bit 6 flipped.
func appendZMODEMEscaped(out []byte, value byte) []byte {
	switch value {
	case cancelByte, 0x10, 0x90, 0x11, 0x91, 0x13, 0x93:
		return append(out, cancelByte, value^0x40)
	}
	return append(out, value)
}

// zmodemFileOffer is what a ZMODEM sender writes to offer one file: a binary ZFILE header
// with a 16-bit CRC, then the file information subpacket (the name, a NUL, the size and the
// octal modification time) ended by ZCRCW. A binary header has no trailer to skip.
func zmodemFileOffer(name string, size int64, modified time.Time) []byte {
	const frameFile, endWait = 4, 'k'
	header := []byte{frameFile, 0, 0, 0, 0}
	header = binary.BigEndian.AppendUint16(header, crcXMODEM(header))
	offer := []byte{'*', cancelByte, 'A'}
	for _, value := range header {
		offer = appendZMODEMEscaped(offer, value)
	}
	information := fmt.Appendf(nil, "%s\x00%d %o 0", name, size, modified.Unix())
	for _, value := range information {
		offer = appendZMODEMEscaped(offer, value)
	}
	offer = append(offer, cancelByte, endWait)
	checked := append(append([]byte{}, information...), endWait)
	for _, value := range binary.BigEndian.AppendUint16(nil, crcXMODEM(checked)) {
		offer = appendZMODEMEscaped(offer, value)
	}
	return offer
}

// ymodemBlock is one 128-byte YMODEM block with its number and 16-bit CRC.
func ymodemBlock(number byte, data []byte, fill byte) []byte {
	padded := bytes.Repeat([]byte{fill}, 128)
	copy(padded, data)
	block := []byte{ymodemStartOfBlock, number, ^number}
	block = append(block, padded...)
	return binary.BigEndian.AppendUint16(block, crcXMODEM(padded))
}

// ymodemHeaderBlock is block 0 naming one file: the name, a NUL, the size and the octal
// modification time, padded with NULs.
func ymodemHeaderBlock(name string, size int64, modified time.Time) []byte {
	return ymodemBlock(0, fmt.Appendf(nil, "%s\x00%d %o", name, size, modified.Unix()), 0)
}

// farReader reads what our receiver sends, byte by byte, and keeps the longest run of CAN
// bytes it has seen.
type farReader struct {
	reader  *bufio.Reader
	run     int
	longest int
}

func (far *farReader) next() (byte, error) {
	value, err := far.reader.ReadByte()
	if err != nil {
		return 0, err
	}
	if value == cancelByte {
		far.run++
		far.longest = max(far.longest, far.run)
	} else {
		far.run = 0
	}
	return value, nil
}

// awaitByte reads until want arrives.
func (far *farReader) awaitByte(want byte) error {
	for {
		value, err := far.next()
		if err != nil {
			return err
		}
		if value == want {
			return nil
		}
	}
}

// awaitText reads until want arrives as consecutive bytes.
func (far *farReader) awaitText(want string) error {
	var seen []byte
	for {
		value, err := far.next()
		if err != nil {
			return err
		}
		seen = append(seen, value)
		if bytes.HasSuffix(seen, []byte(want)) {
			return nil
		}
	}
}

// drain reads until the connection ends, so every byte our receiver sends is counted.
func (far *farReader) drain() {
	for {
		if _, err := far.next(); err != nil {
			return
		}
	}
}

// offerName plays a sender that offers one file under name and sends nothing more: for
// ZMODEM it waits for the receiver's ZRINIT (a hex header of type 01) and sends the file
// offer; for YMODEM it waits for the receiver's C and sends block 0. Then it reads until
// the connection ends, closes it, and returns the longest run of CAN bytes it read.
func offerName(conn *net.TCPConn, protocol transfer.Protocol, name string) int {
	defer func() { _ = conn.Close() }()
	far := &farReader{reader: bufio.NewReader(conn)}
	var offer []byte
	var err error
	if protocol == transfer.ZMODEM {
		err = far.awaitText("B01")
		offer = zmodemFileOffer(name, 100, mtime)
	} else {
		err = far.awaitByte('C')
		offer = ymodemHeaderBlock(name, 100, mtime)
	}
	if err != nil {
		return far.longest
	}
	if _, err := conn.Write(offer); err != nil {
		return far.longest
	}
	far.drain()
	return far.longest
}

// mustRefuseOffer offers name to a receive into download by the test's own sender for
// protocol, and holds the receive to the line: ErrNameRefused, the cancel read by the
// sender, and nothing under parent changed.
func mustRefuseOffer(t *testing.T, parent, download string, protocol transfer.Protocol, name string) {
	t.Helper()
	before := folderState(t, parent)
	ctx := withinNameRow(t)
	deadline, _ := ctx.Deadline()
	ours, theirs := loopback(t, deadline)
	cancelRun := make(chan int, 1)
	go func() { cancelRun <- offerName(theirs, protocol, name) }()
	got, err := transfer.Receive(ctx, ours, download, transfer.Options{Protocol: protocol})
	// Half-closing ends the sender's read without a reset, which could drop bytes it has
	// not read yet.
	_ = ours.CloseWrite()
	longest := <-cancelRun
	if !errors.Is(err, transfer.ErrNameRefused) {
		t.Errorf("Receive of %q returned %+v, %v; want ErrNameRefused", name, got, err)
	}
	want := zmodemCancelRun
	if protocol == transfer.YMODEM {
		want = ymodemCancelRun
	}
	if longest < want {
		t.Errorf("the sender read at most %d CAN bytes in a row; a cancel is %d", longest, want)
	}
	if after := folderState(t, parent); after != before {
		t.Errorf("the folder changed\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// mustRefuseXMODEMName runs an XMODEM receive into download under name, with a far end
// that sends nothing, and holds it to the line: ErrNameRefused, no byte sent to the far
// end, and nothing under parent changed. The far end hangs up on the first byte it reads,
// so today's code, which opens and then waits for blocks, ends at once.
func mustRefuseXMODEMName(t *testing.T, parent, download, name string) {
	t.Helper()
	before := folderState(t, parent)
	ctx := withinNameRow(t)
	deadline, _ := ctx.Deadline()
	ours, theirs := loopback(t, deadline)
	bytesRead := make(chan int, 1)
	go func() {
		defer func() { _ = theirs.Close() }()
		first := make([]byte, 1)
		if _, err := io.ReadFull(theirs, first); err != nil {
			bytesRead <- 0
			return
		}
		bytesRead <- 1
	}()
	got, err := transfer.Receive(ctx, ours, download, transfer.Options{Protocol: transfer.XMODEM, Name: name})
	_ = ours.CloseWrite()
	if !errors.Is(err, transfer.ErrNameRefused) {
		t.Errorf("Receive under %q returned %+v, %v; want ErrNameRefused", name, got, err)
	}
	if count := <-bytesRead; count != 0 {
		t.Error("the receive sent its opening byte before refusing the name")
	}
	if after := folderState(t, parent); after != before {
		t.Errorf("the folder changed\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// mustReceiveUnder asserts that a receive stored exactly one file, src's bytes, under name
// in download.
func mustReceiveUnder(t *testing.T, got []transfer.Received, download, name, src string) {
	t.Helper()
	if len(got) != 1 || got[0].Name != name || got[0].Path != filepath.Join(download, name) {
		t.Fatalf("got %+v, want one file %q in %s", got, name, download)
	}
	if mustSum(t, got[0].Path) != mustSum(t, src) {
		t.Fatal("received bytes differ from the sent file")
	}
}

func TestReceiveRefusesParentName(t *testing.T) {
	t.Parallel()
	t.Run(lineParentName, func(t *testing.T) {
		t.Parallel()
		rows := []struct {
			name     string
			protocol transfer.Protocol
			offered  string
		}{
			{"ZMODEM ..", transfer.ZMODEM, parentName},
			{"ZMODEM a/..", transfer.ZMODEM, parentThroughFolder},
			{"YMODEM ..", transfer.YMODEM, parentName},
			{"YMODEM a/..", transfer.YMODEM, parentThroughFolder},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				parent, download := newDownloadFolder(t)
				mustRefuseOffer(t, parent, download, row.protocol, row.offered)
			})
		}
		edges := []struct {
			name    string
			command string
			opt     transfer.Options
		}{
			{"edge: ZMODEM ..report is an ordinary name", "sz", transfer.Options{}},
			{"edge: YMODEM ..report is an ordinary name", "sb", transfer.Options{Protocol: transfer.YMODEM}},
		}
		for _, edge := range edges {
			t.Run(edge.name, func(t *testing.T) {
				t.Parallel()
				far := t.TempDir()
				_, download := newDownloadFolder(t)
				src := mustWriteRandom(t, far, "..report", 5000, mtime)
				sender, wait := oracle(t, far, edge.command, "-b", "-q", "..report")
				got, err := transfer.Receive(withinNameRow(t), sender, download, edge.opt)
				if err != nil {
					t.Fatalf("Receive: %v", err)
				}
				if stderr, err := wait(); err != nil {
					t.Fatalf("%s exited %v: %s", edge.command, err, stderr)
				}
				mustReceiveUnder(t, got, download, "..report", src)
			})
		}
	})
}

func TestXMODEMRefusesParentName(t *testing.T) {
	t.Parallel()
	t.Run(lineXMODEMName, func(t *testing.T) {
		t.Parallel()
		for _, name := range []string{parentName, parentThroughFolder} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				parent, download := newDownloadFolder(t)
				mustRefuseXMODEMName(t, parent, download, name)
			})
		}
		t.Run("edge: ..report is an ordinary name", func(t *testing.T) {
			t.Parallel()
			far := t.TempDir()
			_, download := newDownloadFolder(t)
			src := mustWriteRandom(t, far, "payload.bin", 1024, mtime)
			sender, wait := oracle(t, far, "sx", "-b", "-q", "payload.bin")
			got, err := transfer.Receive(withinNameRow(t), sender, download, transfer.Options{Protocol: transfer.XMODEM, SubpacketSize: 128, Name: "..report"})
			if err != nil {
				t.Fatalf("Receive: %v", err)
			}
			if stderr, err := wait(); err != nil {
				t.Fatalf("sx exited %v: %s", err, stderr)
			}
			mustReceiveUnder(t, got, download, "..report", src)
		})
	})
}
