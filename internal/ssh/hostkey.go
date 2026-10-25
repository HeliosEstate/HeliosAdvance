// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package ssh

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	cryptossh "golang.org/x/crypto/ssh"
)

const (
	hostKeyPEMType = "OPENSSH PRIVATE KEY"
	// othersReadBits are the group and other read bits of a file's mode.
	othersReadBits = 0o044
	pemWhiteSpace  = " \t\r\n"
)

// readHostKey returns only the package's sentinels, never the os or library error, since the
// library's text can quote the file.
func readHostKey(path string) (*HostKey, error) {
	cleaned := filepath.Clean(path)
	info, err := os.Stat(cleaned)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrHostKeyMissing
		}
		return nil, ErrHostKeyUnreadable
	}
	if runtime.GOOS == "linux" && info.Mode().Perm()&othersReadBits != 0 {
		return nil, ErrHostKeyReadableByOthers
	}
	file, err := os.Open(cleaned)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrHostKeyMissing
		}
		return nil, ErrHostKeyUnreadable
	}
	// One byte more than the most, so that a longer file shows as a full array.
	var contents [HostKeyMostBytes + 1]byte
	defer clear(contents[:])
	count, readErr := io.ReadFull(file, contents[:])
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.ErrUnexpectedEOF) && !errors.Is(readErr, io.EOF) {
		return nil, ErrHostKeyUnreadable
	}
	if closeErr != nil {
		return nil, ErrHostKeyUnreadable
	}
	if count == len(contents) {
		return nil, ErrHostKeyNotOpenSSH
	}
	return parseHostKey(contents[:count])
}

func parseHostKey(contents []byte) (*HostKey, error) {
	if !bytes.HasPrefix(bytes.TrimLeft(contents, pemWhiteSpace), []byte("-----BEGIN ")) {
		return nil, ErrHostKeyNotOpenSSH
	}
	block, rest := pem.Decode(contents)
	if block == nil {
		return nil, ErrHostKeyNotOpenSSH
	}
	defer clear(block.Bytes)
	if block.Type != hostKeyPEMType || len(bytes.Trim(rest, pemWhiteSpace)) != 0 {
		return nil, ErrHostKeyNotOpenSSH
	}
	parsed, err := cryptossh.ParseRawPrivateKey(contents)
	if err != nil {
		var missing *cryptossh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, ErrHostKeyPassphrase
		}
		return nil, ErrHostKeyNotOpenSSH
	}
	var key ed25519.PrivateKey
	switch typed := parsed.(type) {
	case *ed25519.PrivateKey:
		key = *typed
	case ed25519.PrivateKey:
		key = typed
	default:
		return nil, ErrHostKeyNotEd25519
	}
	defer clear(key)
	signer, err := cryptossh.NewSignerFromKey(key)
	if err != nil {
		return nil, ErrHostKeyNotOpenSSH
	}
	return &HostKey{state: hostKeyState{signer: signer}}, nil
}
