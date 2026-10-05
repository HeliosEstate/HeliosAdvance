// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"errors"
	"io"
)

// The bootstrap file's reader and writer, as the approved tests call them. The QA session
// declared these signatures so the tests compile; every body refuses until it is built.

// record is one field record, as the file holds it.
type record struct {
	name string
	data []byte
}

// bootstrapFile is a bootstrap file's records, in the order the file holds them.
type bootstrapFile struct {
	records []record
}

// errNotBuilt is the reader and writer's answer until they are built.
var errNotBuilt = errors.New("bootstrap: not built")

// openFile reads a bootstrap file of size bytes from source under key and checks all of it.
func openFile(source io.Reader, size int64, key []byte) (*bootstrapFile, error) {
	return nil, notBuilt(source, size, key)
}

// readRecords splits the decrypted fields into records.
func readRecords(plaintext []byte) ([]record, error) {
	return nil, notBuilt(plaintext)
}

// fields is the known fields.
func (file *bootstrapFile) fields() Fields {
	return Fields{}
}

// setFields replaces the known fields; every other record keeps its place.
func (file *bootstrapFile) setFields(fields Fields) {
	_ = fields
}

// writeTo seals the records under key with a new nonce.
func (file *bootstrapFile) writeTo(destination io.Writer, key []byte) error {
	return notBuilt(file.records, destination, key)
}

// Error makes a *Refusal an error, as the contract's errors.As needs.
func (refusal *Refusal) Error() string {
	return errNotBuilt.Error()
}

// notBuilt takes the parameters so the unused-parameter rule passes while the names stay.
// A method with no error to return uses its parameter in a blank assignment instead.
func notBuilt(...any) error { return errNotBuilt }
