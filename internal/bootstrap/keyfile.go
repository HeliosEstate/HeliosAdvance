// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"bytes"
	"encoding/base64"
	"io"
)

const keyTextLength = 44

// readKeyFile reads a key file, or a Swarm secret, which holds the same form: 32 bytes as
// base64 in 44 characters, at most one trailing newline. Any other content is a *Refusal
// with KeyFileMalformed. It is the fuzz target for that reader; it refuses until it is built.
func readKeyFile(source io.Reader) ([]byte, error) {
	var input bytes.Buffer
	_, err := io.Copy(&input, io.LimitReader(source, keyTextLength+2))
	if err != nil {
		return nil, err
	}
	text := input.Bytes()
	if len(text) == keyTextLength+1 && text[keyTextLength] == '\n' {
		text = text[:keyTextLength]
	}
	if len(text) != keyTextLength {
		return nil, &Refusal{Cause: KeyFileMalformed}
	}
	key, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil || len(key) != 32 || !bytes.Equal([]byte(base64.StdEncoding.EncodeToString(key)), text) {
		return nil, &Refusal{Cause: KeyFileMalformed}
	}
	return key, nil
}
