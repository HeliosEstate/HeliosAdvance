// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Command hadv-transfer sends or receives files over stdin and stdout with the options
// lrzsz takes, so it can stand in for sz or rz. QA stub for issue #13: the flags the
// approved tests pass; the build session fills in whatever the library needs.
package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/heliosestate/heliosadvance/internal/transfer"
)

// stdio is stdin and stdout as one stream, the way sz and rz see a line.
type stdio struct {
	io.Reader
	io.Writer
}

func main() {
	receive := flag.Bool("r", false, "receive into the current directory (rz)")
	escape := flag.Bool("e", false, "escape all control characters")
	crc16 := flag.Bool("o", false, "use 16-bit CRC")
	try8k := flag.Bool("8", false, "offer 8K subpackets")
	resume := flag.Bool("resume", false, "resume an interrupted transfer")
	timeout := flag.Duration("t", 10*time.Second, "give up after this long without the far end")
	flag.Bool("b", true, "binary (always)")
	flag.Bool("q", true, "quiet (always)")
	flag.Parse()

	opt := transfer.Options{Escape: *escape, CRC16: *crc16, Resume: *resume, Timeout: *timeout}
	if *try8k {
		opt.SubpacketSize = 8192
	}
	line := stdio{os.Stdin, os.Stdout}
	ctx := context.Background()
	var err error
	if *receive {
		_, err = transfer.Receive(ctx, line, ".", opt)
	} else {
		err = transfer.Send(ctx, line, flag.Args(), opt)
	}
	if err != nil {
		slog.Error("transfer failed", "error", err)
		os.Exit(1)
	}
}
