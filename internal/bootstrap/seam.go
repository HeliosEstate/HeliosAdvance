// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"regexp"
	"unicode/utf8"
)

// The seam the approved tests call: New, the size-limited reader and the three readers. The
// locked tests pin these signatures and the record type's two fields.

// errNotBuilt marks what is not built yet: create and save, and the key holders other than 4 and
// 5.
var errNotBuilt = errors.New("bootstrap: not built")

// New returns the Bootstrap.
func New() Bootstrap { return entry{} }

type entry struct{}

func (entry) Create(context.Context, string, KeyHolder, ServiceAccount, Fields, bool) (string, error) {
	return "", Error{Code: errNotBuilt}
}

// readFile reads a whole bootstrap file from reader: at most MaxSize bytes, and ErrFormat for a
// larger one, having read no more than one byte past MaxSize.
func readFile(reader io.Reader) ([]byte, error) {
	buffer := make([]byte, MaxSize+1)
	count, err := io.ReadFull(reader, buffer)
	switch {
	case err == nil:
		return nil, Error{Code: ErrFormat}
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return buffer[:count], nil
	default:
		return nil, Error{Code: ErrUnreadable, Place: PlaceFile, Err: err}
	}
}

// sealedKeyName is the first 37 bytes of key holder 1's sealed key.
var sealedKeyName = regexp.MustCompile(`^hadv-[0-9a-f]{32}$`)

// readHeader is the header reader: it checks the header at the start of a whole bootstrap file
// against the format's table, and gives the key holder and the sealed key it names, or
// ErrFormat.
func readHeader(file []byte) (KeyHolder, []byte, error) {
	failure := Error{Code: ErrFormat}
	// Each check comes before the first index that depends on it.
	if len(file) < HeaderStartSize || string(file[:len(Magic)]) != Magic ||
		binary.BigEndian.Uint16(file[8:10]) != FormatVersion {
		return 0, nil, failure
	}
	keyHolder := KeyHolder(file[10])
	length := int(binary.BigEndian.Uint16(file[11:13]))
	switch keyHolder {
	case WindowsKeyStore:
		if length != WindowsKeyNameSize+WindowsWrapSize {
			return 0, nil, failure
		}
	case SystemdByService, SystemdAtStart:
		if length < 1 || length > SystemdCredentialMax {
			return 0, nil, failure
		}
	case KeyFile, SwarmSecret:
		if length != 0 {
			return 0, nil, failure
		}
	default:
		return 0, nil, failure
	}
	if len(file) < HeaderStartSize+length+NonceSize+TagSize {
		return 0, nil, failure
	}
	sealedKey := file[HeaderStartSize : HeaderStartSize+length]
	if keyHolder == WindowsKeyStore && !sealedKeyName.Match(sealedKey[:WindowsKeyNameSize]) {
		return 0, nil, failure
	}
	return keyHolder, sealedKey, nil
}

// record is one record of the unsealed plaintext.
type record struct {
	name string
	data []byte
}

// readRecords is the record reader: it splits the unsealed plaintext into its records, in file
// order, or gives ErrInvalid.
func readRecords(plaintext []byte) ([]record, error) {
	failure := Error{Code: ErrInvalid}
	var records []record
	seen := map[string]bool{}
	for len(plaintext) > 0 {
		if len(plaintext) < 2 {
			return nil, failure
		}
		nameLength := int(binary.BigEndian.Uint16(plaintext))
		plaintext = plaintext[2:]
		if nameLength == 0 || nameLength > 255 || nameLength > len(plaintext) ||
			!utf8.Valid(plaintext[:nameLength]) {
			return nil, failure
		}
		name := string(plaintext[:nameLength])
		plaintext = plaintext[nameLength:]
		if seen[name] || len(plaintext) < 4 {
			return nil, failure
		}
		seen[name] = true
		dataLength := int64(binary.BigEndian.Uint32(plaintext))
		plaintext = plaintext[4:]
		if dataLength > int64(len(plaintext)) {
			return nil, failure
		}
		// The data is a slice of the plaintext, so clearing the plaintext clears every record.
		records = append(records, record{name: name, data: plaintext[:dataLength]})
		plaintext = plaintext[dataLength:]
	}
	return records, nil
}

// readKey is the base64 key reader: the bootstrap key from what reader gives of the key file
// or the Swarm secret, or ErrKey.
func readKey(reader io.Reader) (Key256, error) {
	// 44 characters and a newline are the most a key can be; a full buffer proves it is longer.
	var text [46]byte
	var decoded [33]byte
	defer clear(text[:])
	defer clear(decoded[:])
	count, err := io.ReadFull(reader, text[:])
	switch {
	case err == nil:
		return Key256{}, Error{Code: ErrKey}
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
	default:
		return Key256{}, Error{Code: ErrKey, Err: err}
	}
	trimmed := bytes.TrimSuffix(text[:count], []byte("\n"))
	// StdEncoding skips "\r" and "\n" inside the text even when strict, so these two length checks
	// refuse a newline inside the key, not the decoder.
	if len(trimmed) != 44 {
		return Key256{}, Error{Code: ErrKey}
	}
	decodedCount, err := base64.StdEncoding.Strict().Decode(decoded[:], trimmed)
	if err != nil || decodedCount != KeySize {
		return Key256{}, Error{Code: ErrKey}
	}
	return Key256(decoded[:KeySize]), nil
}
