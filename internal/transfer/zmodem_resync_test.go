// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The approved tests for issue #105, written by the QA session from the issue's two lines
// against the lrzsz oracle (oracle/README.md). One exchange is tapped and every row judges
// its trace: the headers and subpackets in the order they crossed the line, read with the
// framing in the ZMODEM reference document, never with the engine's own decoder.
//
// The module reads the far end's bytes ahead of the sender, so the tap sees when a header
// was read, not when the sender acted on it. Every row therefore judges our own frames, and
// checks a header of the far end's only as "it had arrived before we sent this", which holds
// whatever the read-ahead.
package transfer_test

import (
	"bytes"
	"encoding/hex"
	"io"
	"path/filepath"
	"sync"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/transfer"
)

// The ZMODEM reference's frame bytes the tap reads. A data byte never escapes to ZDLE
// followed by A, B, C or h to k, so those pairs mark headers and subpacket ends only.
const (
	tapZDLE      = 0x18
	headerZACK   = 3
	headerZRPOS  = 9
	headerZDATA  = 10
	endZCRCW     = 'k'
	hexHeaderLen = 10 // the type and four position bytes, as hex digits

	resyncFileSize = 200_000
	// rz fakes a CRC error every this many bytes. At 3,000 a ZRPOS also arrives while the
	// sender waits for its acknowledgement, dozens of times in every exchange, with no load;
	// at 7,000 it never did (probed 2026-10-06).
	resyncErrorInterval = "3000"
)

// tappedLine is the line to the far end, recording what crosses it in the order it does:
// our writes before they reach the far end, the far end's bytes as the module reads them.
type tappedLine struct {
	io.Reader
	io.WriteCloser
	mutex  sync.Mutex
	chunks []lineChunk
}

type lineChunk struct {
	fromUs bool
	data   []byte
}

func (tapped *tappedLine) Read(buffer []byte) (int, error) {
	n, err := tapped.Reader.Read(buffer)
	if n > 0 {
		tapped.record(false, buffer[:n])
	}
	return n, err
}

func (tapped *tappedLine) Write(buffer []byte) (int, error) {
	tapped.record(true, buffer)
	return tapped.WriteCloser.Write(buffer)
}

func (tapped *tappedLine) record(fromUs bool, data []byte) {
	tapped.mutex.Lock()
	defer tapped.mutex.Unlock()
	tapped.chunks = append(tapped.chunks, lineChunk{fromUs: fromUs, data: bytes.Clone(data)})
}

// lineEvent is one header, or the end of one data subpacket, seen on the line.
type lineEvent struct {
	fromUs   bool
	isHeader bool
	kind     byte   // the header's type, or the byte that ends the subpacket
	position uint32 // a header's position field
	length   uint32 // a subpacket's data bytes, unescaped
}

type placedEvent struct {
	event lineEvent
	last  int // the offset of its last byte in its direction's stream
}

// traceOf turns the recorded chunks into events, each placed at the chunk that carried its
// last byte, so a header of the far end's before one of ours had arrived before we sent it.
func traceOf(chunks []lineChunk) []lineEvent {
	var ourStream, theirStream []byte
	for _, chunk := range chunks {
		if chunk.fromUs {
			ourStream = append(ourStream, chunk.data...)
		} else {
			theirStream = append(theirStream, chunk.data...)
		}
	}
	ourEvents, theirEvents := framesIn(ourStream, true), framesIn(theirStream, false)
	var trace []lineEvent
	ourEnd, theirEnd := 0, 0
	for _, chunk := range chunks {
		if chunk.fromUs {
			ourEnd += len(chunk.data)
			for len(ourEvents) > 0 && ourEvents[0].last < ourEnd {
				trace = append(trace, ourEvents[0].event)
				ourEvents = ourEvents[1:]
			}
		} else {
			theirEnd += len(chunk.data)
			for len(theirEvents) > 0 && theirEvents[0].last < theirEnd {
				trace = append(trace, theirEvents[0].event)
				theirEvents = theirEvents[1:]
			}
		}
	}
	return trace
}

// framesIn finds every hex header, binary header and subpacket end in one direction's
// bytes, counting each subpacket's data bytes. A subpacket's CRC follows its end, two bytes
// or four as the last binary header said, and is skipped so it is never read as framing.
func framesIn(stream []byte, fromUs bool) []placedEvent {
	var events []placedEvent
	crcLength := 2
	var dataLength uint32
	for i := 0; i+1 < len(stream); i++ {
		if stream[i] != tapZDLE {
			dataLength++
			continue
		}
		next := stream[i+1]
		switch {
		case next == 'B':
			if i+2+hexHeaderLen > len(stream) {
				return events
			}
			raw, err := hex.DecodeString(string(stream[i+2 : i+2+hexHeaderLen]))
			if err != nil {
				i++
				continue
			}
			events = append(events, placedEvent{lineEvent{fromUs: fromUs, isHeader: true, kind: raw[0], position: littleEndian(raw[1:5])}, i + 1 + hexHeaderLen})
			i += 1 + hexHeaderLen
			dataLength = 0
		case next == 'A' || next == 'C':
			crcLength = 2
			if next == 'C' {
				crcLength = 4
			}
			decoded, after, ok := unescape(stream, i+2, 5+crcLength)
			if !ok {
				return events
			}
			events = append(events, placedEvent{lineEvent{fromUs: fromUs, isHeader: true, kind: decoded[0], position: littleEndian(decoded[1:5])}, after - 1})
			i = after - 1
			dataLength = 0
		case next >= 'h' && next <= 'k':
			_, after, ok := unescape(stream, i+2, crcLength)
			if !ok {
				return events
			}
			events = append(events, placedEvent{lineEvent{fromUs: fromUs, kind: next, length: dataLength}, after - 1})
			i = after - 1
			dataLength = 0
		default:
			dataLength++ // an escaped data byte
			i++
		}
	}
	return events
}

// unescape reads count bytes from start, undoing ZDLE escapes, and says where it stopped.
func unescape(stream []byte, start, count int) (decoded []byte, after int, ok bool) {
	i := start
	for len(decoded) < count {
		if i >= len(stream) {
			return nil, i, false
		}
		if stream[i] != tapZDLE {
			decoded = append(decoded, stream[i])
			i++
			continue
		}
		if i+1 >= len(stream) {
			return nil, i, false
		}
		switch escaped := stream[i+1]; escaped {
		case 'l':
			decoded = append(decoded, 0x7f)
		case 'm':
			decoded = append(decoded, 0xff)
		default:
			decoded = append(decoded, escaped^0x40)
		}
		i += 2
	}
	return decoded, i, true
}

func littleEndian(four []byte) uint32 {
	return uint32(four[0]) | uint32(four[1])<<8 | uint32(four[2])<<16 | uint32(four[3])<<24
}

// dataFrame is one ZDATA header of ours and the subpackets we sent under it.
type dataFrame struct {
	header     int // its index in the trace
	position   uint32
	subpackets []lineEvent
}

func (frame dataFrame) length() uint32 {
	var total uint32
	for _, subpacket := range frame.subpackets {
		total += subpacket.length
	}
	return total
}

// asksAcknowledgement is the step the lines name: one subpacket, ending with ZCRCW.
func (frame dataFrame) asksAcknowledgement() bool {
	return len(frame.subpackets) == 1 && frame.subpackets[0].kind == endZCRCW
}

func dataFrames(trace []lineEvent) []dataFrame {
	var frames []dataFrame
	open := false
	for i, event := range trace {
		switch {
		case !event.fromUs:
		case event.isHeader && event.kind == headerZDATA:
			frames = append(frames, dataFrame{header: i, position: event.position})
			open = true
		case event.isHeader:
			open = false
		case open:
			frames[len(frames)-1].subpackets = append(frames[len(frames)-1].subpackets, event)
		}
	}
	return frames
}

// streams says whether a frame streams: its first subpacket does not end with ZCRCW. A
// frame whose first does is a step, and the rows check it is the lines' step.
func (frame dataFrame) streams() bool {
	return len(frame.subpackets) > 0 && frame.subpackets[0].kind != endZCRCW
}

func (frame dataFrame) isStep() bool {
	return len(frame.subpackets) > 0 && frame.subpackets[0].kind == endZCRCW
}

// arrivedBefore says whether the far end's header of kind for position had arrived before
// the trace's index.
func arrivedBefore(trace []lineEvent, index int, kind byte, position uint32) bool {
	for _, event := range trace[:index] {
		if !event.fromUs && event.isHeader && event.kind == kind && event.position == position {
			return true
		}
	}
	return false
}

// checkStep fails unless frame is the lines' step: one subpacket ending with ZCRCW, from a
// position a ZRPOS that had arrived before it named.
func checkStep(t *testing.T, trace []lineEvent, frame dataFrame) {
	t.Helper()
	if !frame.asksAcknowledgement() {
		kinds := make([]byte, 0, len(frame.subpackets))
		for _, subpacket := range frame.subpackets {
			kinds = append(kinds, subpacket.kind)
		}
		t.Errorf("the ZDATA for %d answering a ZRPOS has subpackets ending %q, want one ending ZCRCW (%q)", frame.position, kinds, endZCRCW)
	}
	if !arrivedBefore(trace, frame.header, headerZRPOS, frame.position) {
		t.Errorf("the ZDATA for %d answers no ZRPOS for %d", frame.position, frame.position)
	}
}

func TestResyncAfterZRPOS(t *testing.T) {
	t.Parallel()
	ours, far := t.TempDir(), t.TempDir()
	src := mustWriteRandom(t, ours, "noisy.bin", resyncFileSize, mtime)
	farEnd, wait := oracle(t, far, "rz", "-b", "-q", "-y", "--errors", resyncErrorInterval)
	tapped := &tappedLine{Reader: farEnd, WriteCloser: farEnd}
	sendErr := transfer.Send(t.Context(), tapped, []string{src}, transfer.Options{})
	stderr, waitErr := wait()
	// The rows judge the trace; a failed exchange is logged, since its trace still shows
	// what we sent. That the file arrives whole is TestCorruption's row.
	t.Logf("Send: %v; rz: %v %s", sendErr, waitErr, stderr)
	if sendErr == nil && waitErr == nil && mustSum(t, filepath.Join(far, "noisy.bin")) != mustSum(t, src) {
		t.Log("the file differs")
	}
	tapped.mutex.Lock()
	trace := traceOf(tapped.chunks)
	tapped.mutex.Unlock()
	frames := dataFrames(trace)

	// Each row fails when it finds nothing to judge, so none passes vacuously.
	t.Run("When the far end asks with a ZRPOS to resume at a position, the ZMODEM sender shall send one data subpacket from that position that asks the far end to acknowledge it, and shall stream again only after that acknowledgement.", func(t *testing.T) {
		t.Parallel()
		t.Run("each ZDATA after the first that does not stream is one ZCRCW subpacket from a position a ZRPOS named", func(t *testing.T) {
			t.Parallel()
			steps := 0
			for k := 1; k < len(frames); k++ {
				if frames[k].isStep() {
					steps++
					checkStep(t, trace, frames[k])
				}
			}
			if steps == 0 {
				t.Fatal("no ZDATA after the first was a ZCRCW step, so there is nothing to judge")
			}
		})
		t.Run("each ZDATA that streams after the first starts where the step before it ended", func(t *testing.T) {
			t.Parallel()
			streams := 0
			for k := 1; k < len(frames); k++ {
				if !frames[k].streams() {
					continue
				}
				streams++
				previous := frames[k-1]
				if !previous.asksAcknowledgement() || frames[k].position != previous.position+previous.length() {
					t.Errorf("the ZDATA for %d streams without following a ZCRCW step that ended there", frames[k].position)
				}
			}
			if streams == 0 {
				t.Fatal("no ZDATA after the first streamed, so there is nothing to judge")
			}
		})
		t.Run("each ZDATA that streams after the first follows the far end's ZACK for its position", func(t *testing.T) {
			t.Parallel()
			streams := 0
			for k := 1; k < len(frames); k++ {
				if !frames[k].streams() {
					continue
				}
				streams++
				if !arrivedBefore(trace, frames[k].header, headerZACK, frames[k].position) {
					t.Errorf("the ZDATA for %d went before the far end's ZACK for %d had arrived", frames[k].position, frames[k].position)
				}
			}
			if streams == 0 {
				t.Fatal("no ZDATA after the first streamed, so there is nothing to judge")
			}
		})
	})

	t.Run("If another ZRPOS arrives while the sender waits for that acknowledgement, then the sender shall start that step again from the position the new ZRPOS names.", func(t *testing.T) {
		t.Parallel()
		t.Run("a ZDATA right after a ZCRCW step that does not stream is the step again, from a position a ZRPOS named", func(t *testing.T) {
			t.Parallel()
			again := 0
			for k := 1; k < len(frames); k++ {
				if frames[k-1].asksAcknowledgement() && frames[k].isStep() {
					again++
					checkStep(t, trace, frames[k])
				}
			}
			if again == 0 {
				t.Fatal("no ZCRCW step followed another, so there is nothing to judge")
			}
		})
	})
}
