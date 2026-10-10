// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The Windows device name rows of issue #141. They need no oracle, since the test's own
// sender names the file, so they run on CI's Windows runner, which runs every test whose
// name starts with TestWindows. On Windows 11, CON makes an ordinary file of that name and
// NUL opens the null device, where the data is lost.
package transfer_test

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/transfer"
)

const lineDeviceName = "On Windows, when a sender names a file `CON` or another reserved device name, the receive cancels the transfer with `ErrNameRefused` and creates no file."

// The two device names the rows name most: the console, which Windows 11 makes an ordinary
// file of, and the null device, which loses the data.
const (
	deviceConsole = "CON"
	deviceNull    = "NUL"
)

// A YMODEM sender's end of file, the receiver's acknowledgement, and the byte that pads a
// last block.
const (
	ymodemEndOfFile   = 0x04
	ymodemAcknowledge = 0x06
	ymodemPadding     = 0x1a
)

// sendWholeYMODEMFile plays a YMODEM sender that sends one whole file of fewer than 129
// bytes under name: block 0, the data as one block, the end of the file, then the batch's
// empty block 0. It returns the first error the line gave it.
func sendWholeYMODEMFile(conn *net.TCPConn, name string, data []byte) error {
	defer func() { _ = conn.Close() }()
	far := &farReader{reader: bufio.NewReader(conn)}
	steps := []struct {
		await byte
		send  []byte
	}{
		{'C', ymodemHeaderBlock(name, int64(len(data)), mtime)},
		{ymodemAcknowledge, nil},
		{'C', ymodemBlock(1, data, ymodemPadding)},
		{ymodemAcknowledge, []byte{ymodemEndOfFile}},
		{ymodemAcknowledge, nil},
		{'C', ymodemBlock(0, nil, 0)},
		{ymodemAcknowledge, nil},
	}
	for _, step := range steps {
		if err := far.awaitByte(step.await); err != nil {
			return fmt.Errorf("waiting for %#x: %w", step.await, err)
		}
		if step.send == nil {
			continue
		}
		if _, err := conn.Write(step.send); err != nil {
			return err
		}
	}
	return nil
}

func TestWindowsDeviceName(t *testing.T) {
	t.Parallel()
	t.Run(lineDeviceName, func(t *testing.T) {
		t.Parallel()
		rows := []struct {
			name     string
			protocol transfer.Protocol
			offered  string
		}{
			{"ZMODEM CON", transfer.ZMODEM, deviceConsole},
			{"ZMODEM NUL", transfer.ZMODEM, deviceNull},
			{"ZMODEM com1", transfer.ZMODEM, "com1"},
			{"YMODEM CON", transfer.YMODEM, deviceConsole},
			{"YMODEM NUL", transfer.YMODEM, deviceNull},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				parent, download := newDownloadFolder(t)
				mustRefuseOffer(t, parent, download, row.protocol, row.offered)
			})
		}
		t.Run("edge: YMODEM CON.txt is an ordinary name", func(t *testing.T) {
			t.Parallel()
			_, download := newDownloadFolder(t)
			data := []byte("an ordinary file whose name starts with a device name")
			src := filepath.Join(t.TempDir(), "CON.txt")
			if err := os.WriteFile(src, data, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx := withinNameRow(t)
			deadline, _ := ctx.Deadline()
			ours, theirs := loopback(t, deadline)
			sent := make(chan error, 1)
			go func() { sent <- sendWholeYMODEMFile(theirs, "CON.txt", data) }()
			got, err := transfer.Receive(ctx, ours, download, transfer.Options{Protocol: transfer.YMODEM})
			_ = ours.CloseWrite()
			if sendErr := <-sent; sendErr != nil {
				t.Fatalf("the sender: %v", sendErr)
			}
			if err != nil {
				t.Fatalf("Receive: %v", err)
			}
			mustReceiveUnder(t, got, download, "CON.txt", src)
		})
	})
	t.Run(lineXMODEMName, func(t *testing.T) {
		t.Parallel()
		for _, name := range []string{deviceConsole, deviceNull} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				parent, download := newDownloadFolder(t)
				mustRefuseXMODEMName(t, parent, download, name)
			})
		}
	})
}
