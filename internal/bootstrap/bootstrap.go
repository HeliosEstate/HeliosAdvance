// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

const (
	// keyTextBytes is the key file's line without its line ending: 43 alphabet characters and the
	// padding.
	keyTextBytes = 44
	alphabet     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

// refusals are the errors a file's reading gives: the file is not there, will not open or read, or
// is longer than its bound.
type refusals struct{ missing, unreadable, tooLarge error }

var (
	fileRefusals    = refusals{ErrFileMissing, ErrFileUnreadable, ErrFileTooLarge}
	keyFileRefusals = refusals{ErrKeyFileMissing, ErrKeyFileUnreadable, ErrKeyFileForm}
)

func open(folder string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Clean(folder))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrFolderMissing
	}
	if err != nil {
		return nil, ErrFolderUnreadable
	}
	contents, err := unseal(root)
	if closeErr := root.Close(); err == nil && closeErr != nil {
		clear(contents)
		return nil, ErrFolderUnreadable
	}
	return contents, err
}

func unseal(root *os.Root) ([]byte, error) {
	sealed, err := readFrom(root, FileName, FileMostBytes, fileRefusals, nil)
	if err != nil {
		return nil, err
	}
	defer clear(sealed)
	if !headerIsOurs(sealed) {
		return nil, ErrHeader
	}
	keyText, err := readFrom(root, KeyFileName, KeyFileMostBytes, keyFileRefusals, checkKeyFile)
	if err != nil {
		return nil, err
	}
	defer clear(keyText)
	// One byte more than the key, so that a text decoding to more shows as a full buffer.
	decoded := make([]byte, KeyBytes+1)
	defer clear(decoded)
	key, ok := decodeKey(keyText, decoded)
	if !ok {
		return nil, ErrKeyFileForm
	}
	return unsealWith(key, sealed)
}

// headerIsOurs is true when the file is long enough for its header, nonce and tag and its header
// is format version 1's for the key file.
func headerIsOurs(sealed []byte) bool {
	if len(sealed) < HeaderBytes+NonceBytes+TagBytes {
		return false
	}
	return string(sealed[:len(Magic)]) == Magic &&
		binary.BigEndian.Uint16(sealed[8:10]) == FormatVersion &&
		sealed[10] == KeyHolderKeyFile &&
		binary.BigEndian.Uint16(sealed[11:13]) == 0
}

// readFrom reads a file of the folder into a buffer one byte longer than the most allowed, so a
// longer file is told from one of exactly the most. The file is opened non-blocking so that a
// named pipe opens at once on Linux, and every check after the open is on the opened file. The
// caller clears what it gets.
func readFrom(root *os.Root, name string, most int, refuse refusals,
	check func(*os.File, fs.FileInfo) error,
) ([]byte, error) {
	opened, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, refuse.missing
	}
	if err != nil {
		return nil, refuse.unreadable
	}
	contents, err := readOpened(opened, most, refuse, check)
	if closeErr := opened.Close(); err == nil && closeErr != nil {
		clear(contents)
		return nil, refuse.unreadable
	}
	return contents, err
}

func readOpened(opened *os.File, most int, refuse refusals, check func(*os.File, fs.FileInfo) error,
) ([]byte, error) {
	info, err := opened.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, refuse.unreadable
	}
	if check != nil {
		if err := check(opened, info); err != nil {
			return nil, err
		}
	}
	contents := make([]byte, most+1)
	count, err := io.ReadFull(opened, contents)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		clear(contents)
		return nil, refuse.unreadable
	}
	if count == len(contents) {
		clear(contents)
		return nil, refuse.tooLarge
	}
	return contents[:count], nil
}

// decodeKey checks the key file's form before it decodes, because Go's decoder skips carriage
// returns and line feeds anywhere in its input. The key is a slice of decoded, which the caller
// clears.
func decodeKey(text, decoded []byte) ([]byte, bool) {
	if len(text) < keyTextBytes || !bytes.HasSuffix(text[:keyTextBytes], []byte("=")) {
		return nil, false
	}
	switch string(text[keyTextBytes:]) {
	case "", "\n", "\r\n":
	default:
		return nil, false
	}
	for _, character := range text[:keyTextBytes-1] {
		if bytes.IndexByte([]byte(alphabet), character) < 0 {
			return nil, false
		}
	}
	count, err := base64.StdEncoding.Strict().Decode(decoded, text[:keyTextBytes])
	if err != nil || count != KeyBytes || bytes.Equal(decoded[:count], make([]byte, KeyBytes)) {
		return nil, false
	}
	return decoded[:count], true
}

// unsealWith opens the sealed JSON under the key. The authenticated data is every byte before it,
// the header and the nonce; the JSON is a new slice, sharing no memory with the file's buffer.
func unsealWith(key, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrUnseal
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrUnseal
	}
	start := HeaderBytes + NonceBytes
	plaintext, err := gcm.Open(nil, sealed[HeaderBytes:start], sealed[start:], sealed[:start])
	if err != nil {
		return nil, ErrUnseal
	}
	return plaintext, nil
}
