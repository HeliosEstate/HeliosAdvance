// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package transfer

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// encodeFileInfo builds a ZFILE data subpacket: the name, a NUL, then the size (decimal),
// modification time (octal seconds since the epoch), mode (unused, 0), a serial number
// (unused, 0), the count of files remaining in the batch and their total bytes.
func encodeFileInfo(name string, size int64, mtime time.Time, filesLeft int, bytesLeft int64) []byte {
	info := fmt.Sprintf("%d %o 0 0 %d %d", size, mtime.Unix(), filesLeft, bytesLeft)
	buf := append([]byte(name), 0)
	return append(buf, info...)
}

// decodeFileInfo reads back what encodeFileInfo wrote. A field lrzsz omits is zero.
func decodeFileInfo(b []byte) (name string, size int64, mtime time.Time) {
	nameB, infoB, found := bytes.Cut(b, []byte{0})
	if !found {
		return string(b), 0, time.Time{}
	}
	name = string(nameB)
	rest := strings.TrimRight(string(infoB), "\x00")
	fields := strings.Fields(rest)
	if len(fields) > 0 {
		if v, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
			size = v
		}
	}
	if len(fields) > 1 {
		if v, err := strconv.ParseInt(fields[1], 8, 64); err == nil {
			mtime = time.Unix(v, 0).UTC()
		}
	}
	return name, size, mtime
}
