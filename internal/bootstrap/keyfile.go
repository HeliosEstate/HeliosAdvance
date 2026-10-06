// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
)

const keyTextLength = 44

// readKeyFile reads a key file, or a Swarm secret, which holds the same form: 32 bytes as
// base64 in 44 characters, at most one trailing newline. Any other content is a *Refusal
// with KeyFileMalformed. It is the fuzz target for that reader.
func readKeyFile(source io.Reader) ([]byte, error) {
	var input [keyTextLength + 2]byte
	defer clear(input[:])
	n, err := io.ReadFull(source, input[:])
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	text := input[:n]
	if len(text) == keyTextLength+1 && text[keyTextLength] == '\n' {
		text = text[:keyTextLength]
	}
	if len(text) != keyTextLength {
		return nil, &Refusal{Cause: KeyFileMalformed}
	}
	key := make([]byte, 33)
	decoded, err := base64.StdEncoding.Decode(key, text)
	if err != nil || decoded != 32 {
		clear(key)
		return nil, &Refusal{Cause: KeyFileMalformed}
	}
	key = key[:decoded]
	var encoded [keyTextLength]byte
	defer clear(encoded[:])
	base64.StdEncoding.Encode(encoded[:], key)
	if !bytes.Equal(encoded[:], text) {
		clear(key)
		return nil, &Refusal{Cause: KeyFileMalformed}
	}
	return key, nil
}
