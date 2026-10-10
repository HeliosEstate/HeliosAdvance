// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// A download folder that cannot be opened cancels a ZMODEM or YMODEM sender at once, and
// leaves an XMODEM one, whose far end has not started, unanswered.
package transfer_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"path/filepath"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/transfer"
)

func TestReceiveMissingFolderCancelsFarEnd(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		protocol transfer.Protocol
		cancels  bool
	}{
		{"review round 2, item 1: ZMODEM is cancelled", transfer.ZMODEM, true},
		{"review round 2, item 1: YMODEM is cancelled", transfer.YMODEM, true},
		{"review round 2, item 1: XMODEM sends nothing", transfer.XMODEM, false},
	}
	for _, row := range cases {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			var listenConfig net.ListenConfig
			listener, err := listenConfig.Listen(context.Background(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			accepted := make(chan net.Conn, 1)
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					conn = nil
				}
				accepted <- conn
			}()
			var dialer net.Dialer
			far, err := dialer.DialContext(context.Background(), "tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = far.Close() }()
			near := <-accepted

			missing := filepath.Join(t.TempDir(), "absent")
			_, err = transfer.Receive(context.Background(), near, missing, transfer.Options{Protocol: row.protocol, Name: "x"})
			if err == nil {
				t.Fatal("Receive into a missing folder returned no error")
			}
			if err := near.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(far)
			if err != nil {
				t.Fatal(err)
			}
			if row.cancels != bytes.Contains(got, bytes.Repeat([]byte{0x18}, 5)) {
				t.Fatalf("far end read %q, cancels want %v", got, row.cancels)
			}
			if !row.cancels && len(got) != 0 {
				t.Fatalf("XMODEM sent %q", got)
			}
		})
	}
}
