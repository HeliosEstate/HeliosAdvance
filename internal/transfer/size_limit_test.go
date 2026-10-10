// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The approved tests for issue #156, written by the QA session from the issue's lines: a
// ZMODEM header carries a file's position in four bytes, so a ZMODEM file holds at most
// 4,294,967,295 bytes, while XMODEM and YMODEM, which carry no such field, keep no limit.
// Every big file is sparse, so no row moves 4 GiB: the rows at the limit resume a file one
// byte short of it. No real sender sends past the size it announced, so that row uses a
// sender written here from the standard library and the locked tests' own CRC and escape
// helpers, never the module's frame code, which would hide a fault in the encoder behind
// the same fault in the decoder. The offers and the rows at the limit use the lrzsz oracle
// (oracle/README.md); the rest need only a far end written here.
package transfer_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/transfer"
)

const (
	limitLineSender = "When a ZMODEM send names a file larger than 4,294,967,295 bytes, the sender refuses the whole send with `ErrTooLarge` before it sends any byte."
	limitLineOffer  = "When a ZMODEM receiver is offered a file whose announced size is larger than 4,294,967,295 bytes, it cancels the transfer with `ErrTooLarge` and creates no file for it. Files received earlier in the transfer stay."
	limitLineData   = "When a ZMODEM receiver gets more than 4,294,967,295 bytes of a file, it cancels the transfer with `ErrTooLarge` and deletes that file. Files received earlier in the transfer stay."
	limitLineWithin = "A ZMODEM file of 4,294,967,295 bytes or less is sent and received as before."
	limitLineOthers = "XMODEM and YMODEM have no limit."
)

// zmodemLargest is the largest file whose end a ZMODEM header's four-byte position can name;
// zmodemOver, one byte more, is the smallest file over the limit.
const (
	zmodemLargest = 4_294_967_295
	zmodemOver    = zmodemLargest + 1
)

// The files the rows send: one at or over the limit, and a small one that must arrive whole
// before it.
const (
	limitBigName   = "big.bin"
	limitSmallName = "small.bin"
	limitSmallSize = 10_000
)

// limitRowDeadline bounds a row against today's code, which takes what these rows offer and
// would otherwise wait out its own timeouts or stream gigabytes of zeros.
const limitRowDeadline = 30 * time.Second

// The ZMODEM reference aborts a session on five CAN bytes in a row, XMODEM and YMODEM on two.
// CAN is also ZMODEM's escape byte, so one alone starts every ZMODEM header.
const (
	limitCancelByte      = 0x18
	limitZMODEMCancelRun = 5
)

// The ZMODEM reference's frame types a sender writes here, and the hex headers our receiver
// writes back, read as text: the escape byte, B, then the type in two hex digits.
const (
	limitFrameFile       = 4
	limitFrameData       = 10
	limitFrameEnd        = 11
	limitReceiverReady   = "\x18B01"
	limitReceiverAck     = "\x18B03"
	limitReceiverRequest = "\x18B09"
)

// The XMODEM and YMODEM bytes a far end written here sends: the receiver's opening byte
// asking for 16-bit CRC, and the acknowledgement.
const (
	limitOpenCRC = 'C'
	limitAck     = 0x06
)

// withinLimitRow is the row's context, ending at limitRowDeadline.
func withinLimitRow(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), limitRowDeadline)
	t.Cleanup(cancel)
	return ctx
}

// mustSparse makes dir/name a sparse file of size bytes, all zeros, by marking it sparse and
// then setting its length alone, so it takes almost no disk, even after a byte is written
// near its end.
func mustSparse(t *testing.T, dir, name string, size int64) string {
	t.Helper()
	path := filepath.Join(dir, name)
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := markSparse(file); err != nil {
		_ = file.Close()
		t.Fatalf("marking %s sparse: %v", name, err)
	}
	if err := file.Truncate(size); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// mustRandom is size random bytes.
func mustRandom(t *testing.T, size int) []byte {
	t.Helper()
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

// mustBeAbsent fails the row if dir/name exists.
func mustBeAbsent(t *testing.T, dir, name, why string) {
	t.Helper()
	info, err := os.Stat(filepath.Join(dir, name))
	switch {
	case err == nil:
		t.Errorf("%s is there, %d bytes; %s", name, info.Size(), why)
	case !errors.Is(err, fs.ErrNotExist):
		t.Errorf("stat %s: %v", name, err)
	}
}

// mustHoldBytes fails the row unless dir/name holds exactly want.
func mustHoldBytes(t *testing.T, dir, name string, want []byte) {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Errorf("reading %s, which must stay: %v", name, err)
		return
	}
	if !bytes.Equal(content, want) {
		t.Errorf("%s holds %d bytes, not the %d sent", name, len(content), len(want))
	}
}

// mustHaveSize fails the row unless path is size bytes long.
func mustHaveSize(t *testing.T, path string, size int64) {
	t.Helper()
	if got := mustStat(t, path).Size(); got != size {
		t.Errorf("%s is %d bytes; want %d", filepath.Base(path), got, size)
	}
}

// limitLoopback returns the two ends of a real TCP connection on the loopback interface,
// both stopping at the row's deadline, so a far end written here never outlives its row.
func limitLoopback(t *testing.T) (ours, theirs *net.TCPConn) {
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
	deadline := time.Now().Add(limitRowDeadline)
	if err := ours.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := theirs.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	return ours, theirs
}

// limitHeader is a binary ZMODEM header with a 16-bit CRC: its type, four bytes holding a
// position low byte first, and the CRC high byte first, escaped as a sender must.
func limitHeader(frameType byte, position uint32) []byte {
	raw := binary.LittleEndian.AppendUint32([]byte{frameType}, position)
	raw = binary.BigEndian.AppendUint16(raw, dateCutCRC16(raw))
	return append([]byte{'*', limitCancelByte, 'A'}, dateCutEscape(raw)...)
}

// limitSubpacket is a ZMODEM data subpacket after a 16-bit header: the data escaped, the
// escape byte and end, then the CRC over the data and end, escaped.
func limitSubpacket(data []byte, end byte) []byte {
	out := append(dateCutEscape(data), limitCancelByte, end)
	return append(out, dateCutEscape(dateCutSubpacketCRC(data, end, 2))...)
}

// limitOffer is what a ZMODEM sender writes to offer one file: a ZFILE header, then the
// file information (the name, a NUL, the size and the octal modification time) in a
// subpacket that asks for an acknowledgement.
func limitOffer(name string, size int64) []byte {
	information := fmt.Appendf(nil, "%s\x00%d %o 0", name, size, mtime.Unix())
	return append(limitHeader(limitFrameFile, 0), limitSubpacket(information, 'k')...)
}

// limitBlock is one XMODEM or YMODEM block: its start, its number and that number's
// complement, data padded with NULs to size, and the 16-bit CRC high byte first.
func limitBlock(number byte, data []byte, size int) []byte {
	start := byte(blockStartShort)
	if size == 1024 {
		start = blockStartLong
	}
	padded := make([]byte, size)
	copy(padded, data)
	block := append([]byte{start, number, ^number}, padded...)
	return binary.BigEndian.AppendUint16(block, blockCRC(padded))
}

// limitFar reads what our end sends, byte by byte, keeping the longest run of CAN bytes and
// the last few bytes, so it can wait for a header read as text.
type limitFar struct {
	reader  *bufio.Reader
	run     int
	longest int
	recent  []byte
}

func newLimitFar(conn io.Reader) *limitFar {
	return &limitFar{reader: bufio.NewReader(conn)}
}

func (far *limitFar) next() (byte, error) {
	value, err := far.reader.ReadByte()
	if err != nil {
		return 0, err
	}
	if value == limitCancelByte {
		far.run++
		far.longest = max(far.longest, far.run)
	} else {
		far.run = 0
	}
	far.recent = append(far.recent, value)
	if len(far.recent) > 8 {
		far.recent = far.recent[1:]
	}
	return value, nil
}

// sawText reports whether the last bytes read are want.
func (far *limitFar) sawText(want string) bool {
	return bytes.HasSuffix(far.recent, []byte(want))
}

// awaitText reads until want arrives as consecutive bytes.
func (far *limitFar) awaitText(want string) error {
	for {
		if _, err := far.next(); err != nil {
			return err
		}
		if far.sawText(want) {
			return nil
		}
	}
}

// awaitByte reads until want arrives.
func (far *limitFar) awaitByte(want byte) error {
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

// awaitRequest reads until our receiver asks for data (a ZRPOS) and returns the position it
// asks for: four bytes in hex, low byte first.
func (far *limitFar) awaitRequest() (int64, error) {
	if err := far.awaitText(limitReceiverRequest); err != nil {
		return 0, err
	}
	digits := make([]byte, 8)
	for i := range digits {
		value, err := far.next()
		if err != nil {
			return 0, err
		}
		digits[i] = value
	}
	position, err := hex.DecodeString(string(digits))
	if err != nil {
		return 0, fmt.Errorf("the request's position %q: %w", digits, err)
	}
	return int64(binary.LittleEndian.Uint32(position)), nil
}

// pastLimit is what the test's own ZMODEM sender saw: the longest run of CAN bytes our
// receiver sent, and, if the receiver did anything but cancel, what it did.
type pastLimit struct {
	longest int
	note    string
}

// sendPastLimit plays a ZMODEM sender to a receive with Resume into a folder that already
// holds limitBigName at the limit. If small is not nil it first sends small whole as
// limitSmallName, which is limitSmallSize bytes. Then it offers limitBigName at the limit, expects to be asked for data from
// the limit on, and sends one byte there, which is one byte more than the limit allows. It
// reads until the connection ends, or hangs up at once if the receiver answers that byte
// with a header instead of cancelling.
func sendPastLimit(conn *net.TCPConn, small []byte) pastLimit {
	defer func() { _ = conn.Close() }()
	far := newLimitFar(conn)
	outcome := func(format string, args ...any) pastLimit {
		return pastLimit{longest: far.longest, note: fmt.Sprintf(format, args...)}
	}
	if small != nil {
		if err := far.awaitText(limitReceiverReady); err != nil {
			return outcome("no ZRINIT before the small file: %v", err)
		}
		if _, err := conn.Write(limitOffer(limitSmallName, int64(len(small)))); err != nil {
			return outcome("offering the small file: %v", err)
		}
		position, err := far.awaitRequest()
		if err != nil || position != 0 {
			return outcome("the small file was asked for from %d (%v); want 0", position, err)
		}
		whole := limitHeader(limitFrameData, 0)
		for start := 0; start < len(small); start += 1024 {
			// 1,024 bytes a subpacket, as a sender offers by default: the frame goes on
			// (ZCRCG) until the last, which ends it (ZCRCE).
			end, last := byte('i'), min(start+1024, len(small))
			if last == len(small) {
				end = 'h'
			}
			whole = append(whole, limitSubpacket(small[start:last], end)...)
		}
		whole = append(whole, limitHeader(limitFrameEnd, limitSmallSize)...)
		if _, err := conn.Write(whole); err != nil {
			return outcome("sending the small file: %v", err)
		}
	}
	if err := far.awaitText(limitReceiverReady); err != nil {
		return outcome("no ZRINIT before the big file: %v", err)
	}
	if _, err := conn.Write(limitOffer(limitBigName, zmodemLargest)); err != nil {
		return outcome("offering the big file: %v", err)
	}
	position, err := far.awaitRequest()
	if err != nil || position != zmodemLargest {
		return outcome("the big file was asked for from %d (%v); want %d, the resume point", position, err, zmodemLargest)
	}
	past := append(limitHeader(limitFrameData, zmodemLargest), limitSubpacket([]byte{'x'}, 'k')...)
	if _, err := conn.Write(past); err != nil {
		return outcome("sending the byte past the limit: %v", err)
	}
	for {
		if _, err := far.next(); err != nil {
			return pastLimit{longest: far.longest}
		}
		if far.sawText(limitReceiverAck) || far.sawText(limitReceiverRequest) {
			return outcome("the receiver took the byte past the limit and answered with a header")
		}
	}
}

// offerWatch is our receiver's side of the line to sz, read as it is written: the longest run
// of CAN bytes, and whether the receiver asked for data after it reported an offer over the
// limit. That request means the offer was taken, and the row then ends the receive rather
// than let sz stream 4 GiB; the CAN bytes the module sends for that ending are not counted.
type offerWatch struct {
	io.WriteCloser
	stop    context.CancelFunc
	mutex   sync.Mutex
	over    bool
	taken   bool
	run     int
	longest int
	recent  []byte
}

func (watch *offerWatch) Write(data []byte) (int, error) {
	watch.mutex.Lock()
	for _, value := range data {
		if watch.taken {
			break
		}
		if value == limitCancelByte {
			watch.run++
			watch.longest = max(watch.longest, watch.run)
		} else {
			watch.run = 0
		}
		watch.recent = append(watch.recent, value)
		if len(watch.recent) > len(limitReceiverRequest) {
			watch.recent = watch.recent[1:]
		}
		if watch.over && string(watch.recent) == limitReceiverRequest {
			watch.taken = true
			watch.stop()
		}
	}
	watch.mutex.Unlock()
	return watch.WriteCloser.Write(data)
}

// progress is the receive's Progress: a report whose total is over the limit is an offer
// over the limit that the receiver has read.
func (watch *offerWatch) progress(report transfer.Progress) {
	watch.mutex.Lock()
	defer watch.mutex.Unlock()
	if report.Total > zmodemLargest {
		watch.over = true
	}
}

// limitSendStart sends paths by ZMODEM to a far end that hangs up on the first byte it
// reads, and returns how many bytes it read (none, if the send wrote nothing before it
// returned) and the send's error.
func limitSendStart(t *testing.T, paths []string) (int, error) {
	t.Helper()
	ctx := withinLimitRow(t)
	ours, theirs := limitLoopback(t)
	arrived := make(chan int, 1)
	go func() {
		buffer := make([]byte, 4096)
		n, readErr := theirs.Read(buffer)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			n = 0
		}
		_ = theirs.Close()
		arrived <- n
	}()
	err := transfer.Send(ctx, ours, paths, transfer.Options{})
	_ = ours.Close()
	return <-arrived, err
}

func TestZMODEMSendTooLarge(t *testing.T) {
	t.Parallel()
	t.Run(limitLineSender, func(t *testing.T) {
		t.Parallel()
		rows := []struct {
			name  string
			small bool
		}{
			{"one file over the limit", false},
			{"a small file, then one over the limit", true},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				var paths []string
				if row.small {
					paths = append(paths, mustWriteRandom(t, dir, limitSmallName, limitSmallSize, mtime))
				}
				paths = append(paths, mustSparse(t, dir, limitBigName, zmodemOver))
				written, err := limitSendStart(t, paths)
				if !errors.Is(err, transfer.ErrTooLarge) {
					t.Errorf("Send: %v; want ErrTooLarge", err)
				}
				if written != 0 {
					t.Errorf("the sender wrote %d bytes; want none before it refuses", written)
				}
			})
		}
		t.Run("edge: one file at exactly the limit starts", func(t *testing.T) {
			t.Parallel()
			path := mustSparse(t, t.TempDir(), limitBigName, zmodemLargest)
			written, err := limitSendStart(t, []string{path})
			if errors.Is(err, transfer.ErrTooLarge) {
				t.Errorf("Send: %v; a file at the limit is within it", err)
			}
			if written == 0 {
				t.Errorf("the sender wrote nothing (%v); want the send started", err)
			}
		})
	})
}

func TestZMODEMOfferTooLarge(t *testing.T) {
	t.Parallel()
	t.Run(limitLineOffer, func(t *testing.T) {
		t.Parallel()
		rows := []struct {
			name  string
			small bool
		}{
			{"sz offers one file over the limit", false},
			{"sz sends a small file whole, then offers one over the limit", true},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				far, download := t.TempDir(), t.TempDir()
				args := []string{"sz", "-b", "-q"}
				var small string
				if row.small {
					small = mustWriteRandom(t, far, limitSmallName, limitSmallSize, mtime)
					args = append(args, limitSmallName)
				}
				mustSparse(t, far, limitBigName, zmodemOver)
				farEnd, _ := oracle(t, far, append(args, limitBigName)...)
				ctx, stop := context.WithTimeout(t.Context(), limitRowDeadline)
				defer stop()
				watch := &offerWatch{WriteCloser: farEnd.WriteCloser, stop: stop}
				_, err := transfer.Receive(ctx, &line{Reader: farEnd.Reader, WriteCloser: watch}, download, transfer.Options{Progress: watch.progress})
				watch.mutex.Lock()
				taken, longest := watch.taken, watch.longest
				watch.mutex.Unlock()
				if !errors.Is(err, transfer.ErrTooLarge) {
					t.Errorf("Receive: %v; want ErrTooLarge (the receiver asked sz for the big file's data: %v)", err, taken)
				}
				if longest < limitZMODEMCancelRun {
					t.Errorf("the longest run of CAN bytes to sz was %d; a cancel is %d", longest, limitZMODEMCancelRun)
				}
				mustBeAbsent(t, download, limitBigName, "an offer over the limit creates no file")
				if row.small {
					if mustSum(t, filepath.Join(download, limitSmallName)) != mustSum(t, small) {
						t.Errorf("%s differs from what sz sent", limitSmallName)
					}
				}
			})
		}
	})
}

func TestZMODEMDataTooLarge(t *testing.T) {
	t.Parallel()
	t.Run(limitLineData, func(t *testing.T) {
		t.Parallel()
		rows := []struct {
			name  string
			small bool
		}{
			{"one byte past the limit, by resume", false},
			{"a small file whole, then one byte past the limit", true},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				download := t.TempDir()
				mustSparse(t, download, limitBigName, zmodemLargest)
				var small []byte
				if row.small {
					small = mustRandom(t, limitSmallSize)
				}
				ctx := withinLimitRow(t)
				ours, theirs := limitLoopback(t)
				seen := make(chan pastLimit, 1)
				go func() { seen <- sendPastLimit(theirs, small) }()
				_, err := transfer.Receive(ctx, ours, download, transfer.Options{Resume: true})
				_ = ours.Close()
				sender := <-seen
				if !errors.Is(err, transfer.ErrTooLarge) {
					t.Errorf("Receive: %v; want ErrTooLarge (the test's sender: %s)", err, sender.note)
				}
				if sender.longest < limitZMODEMCancelRun {
					t.Errorf("the longest run of CAN bytes to the sender was %d; a cancel is %d", sender.longest, limitZMODEMCancelRun)
				}
				mustBeAbsent(t, download, limitBigName, "a file cut off at the limit is deleted")
				if row.small {
					mustHoldBytes(t, download, limitSmallName, small)
				}
			})
		}
	})
}

func TestZMODEMWithinLimit(t *testing.T) {
	t.Parallel()
	t.Run(limitLineWithin, func(t *testing.T) {
		t.Parallel()
		t.Run("sz -r resumes a file to us at exactly the limit", func(t *testing.T) {
			t.Parallel()
			far, download := t.TempDir(), t.TempDir()
			mustSparse(t, far, limitBigName, zmodemLargest)
			mustSparse(t, download, limitBigName, zmodemLargest-1)
			farEnd, wait := oracle(t, far, "sz", "-b", "-q", "-r", limitBigName)
			got, err := transfer.Receive(withinLimitRow(t), farEnd, download, transfer.Options{Resume: true})
			if err != nil {
				t.Fatalf("Receive: %v", err)
			}
			if stderr, err := wait(); err != nil {
				t.Errorf("sz: %v: %s", err, stderr)
			}
			if len(got) != 1 || got[0].Size != zmodemLargest {
				t.Errorf("Receive returned %+v; want one file of %d bytes", got, zmodemLargest)
			}
			mustHaveSize(t, filepath.Join(download, limitBigName), zmodemLargest)
		})
		t.Run("we resume a file to rz -r at exactly the limit", func(t *testing.T) {
			t.Parallel()
			ourFolder, far := t.TempDir(), t.TempDir()
			path := mustSparse(t, ourFolder, limitBigName, zmodemLargest)
			mustSparse(t, far, limitBigName, zmodemLargest-1)
			farEnd, wait := oracle(t, far, "rz", "-b", "-q", "-r")
			if err := transfer.Send(withinLimitRow(t), farEnd, []string{path}, transfer.Options{Resume: true}); err != nil {
				t.Fatalf("Send: %v", err)
			}
			if stderr, err := wait(); err != nil {
				t.Errorf("rz: %v: %s", err, stderr)
			}
			mustHaveSize(t, filepath.Join(far, limitBigName), zmodemLargest)
		})
	})
}

// firstBlocks plays an XMODEM or YMODEM receiver that takes the start of a send and then
// cancels: it opens asking for CRC, reads block 0 too if header is set (acknowledging it and
// opening again), reads block 1, sends two CAN bytes and hangs up. It returns the blocks it
// read, block 0 first, or why it stopped.
func firstBlocks(conn *net.TCPConn, header bool) ([][]byte, error) {
	defer func() { _ = conn.Close() }()
	readBlock := func() ([]byte, error) {
		block := make([]byte, 3+1024+2)
		_, err := io.ReadFull(conn, block)
		return block, err
	}
	var blocks [][]byte
	if _, err := conn.Write([]byte{limitOpenCRC}); err != nil {
		return blocks, err
	}
	if header {
		block, err := readBlock()
		if err != nil {
			return blocks, fmt.Errorf("reading block 0: %w", err)
		}
		blocks = append(blocks, block)
		if _, err := conn.Write([]byte{limitAck, limitOpenCRC}); err != nil {
			return blocks, err
		}
	}
	block, err := readBlock()
	if err != nil {
		return blocks, fmt.Errorf("reading block 1: %w", err)
	}
	blocks = append(blocks, block)
	_, err = conn.Write([]byte{limitCancelByte, limitCancelByte})
	return blocks, err
}

// mustBeFirstBlock fails the row unless block is block 1 of 1,024 bytes of zeros, the start
// of a sparse file.
func mustBeFirstBlock(t *testing.T, block []byte) {
	t.Helper()
	if block[0] != blockStartLong || block[1] != 1 || block[2] != 0xfe {
		t.Errorf("the first data block starts % x; want %02x 01 fe", block[:3], blockStartLong)
	}
	if !bytes.Equal(block[3:3+1024], make([]byte, 1024)) {
		t.Error("the first data block is not the file's first 1,024 bytes, all zeros")
	}
}

// sendYMODEMOver plays a YMODEM sender whose block 0 announces a file over the limit and
// then sends payload as one block and ends the file and the batch. It returns why it
// stopped, if it did not finish.
func sendYMODEMOver(conn *net.TCPConn, payload []byte) error {
	defer func() { _ = conn.Close() }()
	far := newLimitFar(conn)
	steps := []struct {
		await byte
		send  []byte
	}{
		{limitOpenCRC, limitBlock(0, fmt.Appendf(nil, "%s\x00%d %o", limitBigName, int64(zmodemOver), mtime.Unix()), 128)},
		{limitAck, nil},
		{limitOpenCRC, limitBlock(1, payload, 1024)},
		{limitAck, []byte{endOfTransfer}},
		{limitAck, nil},
		{limitOpenCRC, limitBlock(0, nil, 128)},
		{limitAck, nil},
	}
	for i, step := range steps {
		if err := far.awaitByte(step.await); err != nil {
			return fmt.Errorf("step %d, waiting for %#x: %w", i+1, step.await, err)
		}
		if step.send == nil {
			continue
		}
		if _, err := conn.Write(step.send); err != nil {
			return fmt.Errorf("step %d, sending: %w", i+1, err)
		}
	}
	return nil
}

func TestXMODEMAndYMODEMNoLimit(t *testing.T) {
	t.Parallel()
	t.Run(limitLineOthers, func(t *testing.T) {
		t.Parallel()
		t.Run("an XMODEM send of a file over the limit starts", func(t *testing.T) {
			t.Parallel()
			path := mustSparse(t, t.TempDir(), limitBigName, zmodemOver)
			ours, theirs := limitLoopback(t)
			type result struct {
				blocks [][]byte
				err    error
			}
			seen := make(chan result, 1)
			go func() {
				blocks, err := firstBlocks(theirs, false)
				seen <- result{blocks, err}
			}()
			err := transfer.Send(withinLimitRow(t), ours, []string{path}, transfer.Options{Protocol: transfer.XMODEM})
			_ = ours.Close()
			far := <-seen
			if errors.Is(err, transfer.ErrTooLarge) {
				t.Errorf("Send: %v; XMODEM has no limit", err)
			}
			if far.err != nil || len(far.blocks) != 1 {
				t.Fatalf("the far end read %d blocks: %v", len(far.blocks), far.err)
			}
			mustBeFirstBlock(t, far.blocks[0])
		})
		t.Run("a YMODEM send of a file over the limit starts", func(t *testing.T) {
			t.Parallel()
			path := mustSparse(t, t.TempDir(), limitBigName, zmodemOver)
			ours, theirs := limitLoopback(t)
			type result struct {
				blocks [][]byte
				err    error
			}
			seen := make(chan result, 1)
			go func() {
				blocks, err := firstBlocks(theirs, true)
				seen <- result{blocks, err}
			}()
			err := transfer.Send(withinLimitRow(t), ours, []string{path}, transfer.Options{Protocol: transfer.YMODEM})
			_ = ours.Close()
			far := <-seen
			if errors.Is(err, transfer.ErrTooLarge) {
				t.Errorf("Send: %v; YMODEM has no limit", err)
			}
			if far.err != nil || len(far.blocks) != 2 {
				t.Fatalf("the far end read %d blocks: %v", len(far.blocks), far.err)
			}
			name, information, _ := bytes.Cut(far.blocks[0][3:3+1024], []byte{0})
			fields := strings.Fields(string(bytes.TrimRight(information, "\x00")))
			if string(name) != limitBigName || len(fields) == 0 || fields[0] != fmt.Sprint(int64(zmodemOver)) {
				t.Errorf("block 0 names %q with %q; want %s with the size %d", name, fields, limitBigName, int64(zmodemOver))
			}
			mustBeFirstBlock(t, far.blocks[1])
		})
		t.Run("a YMODEM receive offered a file over the limit stores what arrives", func(t *testing.T) {
			t.Parallel()
			download := t.TempDir()
			payload := mustRandom(t, 1024)
			ours, theirs := limitLoopback(t)
			sent := make(chan error, 1)
			go func() { sent <- sendYMODEMOver(theirs, payload) }()
			got, err := transfer.Receive(withinLimitRow(t), ours, download, transfer.Options{Protocol: transfer.YMODEM})
			_ = ours.Close()
			if senderErr := <-sent; senderErr != nil {
				t.Errorf("the test's sender: %v", senderErr)
			}
			if err != nil {
				t.Fatalf("Receive: %v; YMODEM has no limit", err)
			}
			if len(got) != 1 || got[0].Size != int64(len(payload)) {
				t.Errorf("Receive returned %+v; want one file of %d bytes", got, len(payload))
			}
			mustHoldBytes(t, download, limitBigName, payload)
		})
	})
}
