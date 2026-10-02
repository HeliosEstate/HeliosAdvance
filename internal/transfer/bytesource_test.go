// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The approved tests for issue #51, inside the package because the byte source is not
// exported. No oracle and no sleeps: a reader hands over its last bytes and the end of its
// stream, the row waits until the byte source holds both, then reads. Go chooses at random
// between two ready channels, so each row repeats until a byte source that lets the end win
// would have been caught many times over.
package transfer

import (
	"context"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

const endRepeats = 64

// Line 1: every byte before the end, whether the bytes and the end come in one read or two,
// and through both readers: the one that watches for a cancel run and the raw one.
func TestByteSourceEnd(t *testing.T) {
	t.Parallel()
	rows := []struct {
		name   string
		reader func() io.Reader
		read   func(*byteSource) (byte, error)
	}{
		{"bytes and end in one read, raw", func() io.Reader { return iotest.DataErrReader(strings.NewReader("ZFIN")) }, rawRead},
		{"bytes and end in one read, cancel-aware", func() io.Reader { return iotest.DataErrReader(strings.NewReader("ZFIN")) }, cancelAwareRead},
		{"bytes then end in two reads, raw", func() io.Reader { return strings.NewReader("ZFIN") }, rawRead},
		{"bytes then end in two reads, cancel-aware", func() io.Reader { return strings.NewReader("ZFIN") }, cancelAwareRead},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			for attempt := range endRepeats {
				source := newByteSource(row.reader())
				for len(source.errc) == 0 {
					runtime.Gosched() // the reader goroutine queues every byte before it sends the end
				}
				var got []byte
				var err error
				for {
					var value byte
					value, err = row.read(source)
					if err != nil {
						break
					}
					got = append(got, value)
				}
				if string(got) != "ZFIN" || !errors.Is(err, io.EOF) {
					t.Fatalf("attempt %d: read %q then %v, want \"ZFIN\" then io.EOF", attempt, got, err)
				}
			}
		})
	}
}

func rawRead(source *byteSource) (byte, error) {
	return source.readRawByte(context.Background(), time.Second)
}

func cancelAwareRead(source *byteSource) (byte, error) {
	return source.readByte(context.Background(), time.Second)
}
