// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"context"
	"errors"
	"io"
)

// The seam the approved tests call, declared by the QA session for issue #148, every body
// refusing until the build fills it. The locked tests pin these signatures and the record
// type's two fields; the bodies are the build's.

// errNotBuilt marks what the build has not filled yet.
var errNotBuilt = errors.New("bootstrap: not built")

// New returns the Bootstrap.
func New() Bootstrap { return unbuilt{} }

type unbuilt struct{}

func (unbuilt) Create(context.Context, string, KeyHolder, ServiceAccount, Fields, bool) (string, error) {
	return "", Error{Code: errNotBuilt}
}

func (unbuilt) Open(context.Context, string, ServiceAccount) (File, error) {
	return nil, Error{Code: errNotBuilt}
}

// readFile reads a whole bootstrap file from reader: at most MaxSize bytes, and ErrFormat for a
// larger one, having read no more than one byte past MaxSize.
func readFile(io.Reader) ([]byte, error) {
	return nil, Error{Code: errNotBuilt}
}

// readHeader is the header reader: it checks the header at the start of a whole bootstrap file
// against the format's table, and gives the key holder and the sealed key it names, or
// ErrFormat.
func readHeader([]byte) (KeyHolder, []byte, error) {
	return 0, nil, Error{Code: errNotBuilt}
}

// record is one record of the unsealed plaintext.
type record struct {
	name string
	data []byte
}

// readRecords is the record reader: it splits the unsealed plaintext into its records, in file
// order, or gives ErrInvalid.
func readRecords([]byte) ([]record, error) {
	return nil, Error{Code: errNotBuilt}
}

// readKey is the base64 key reader: the bootstrap key from what reader gives of the key file
// or the Swarm secret, or ErrKey.
func readKey(io.Reader) (Key256, error) {
	return Key256{}, Error{Code: errNotBuilt}
}
