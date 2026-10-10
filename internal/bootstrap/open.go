// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io/fs"
	"math"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/heliosestate/heliosadvance/internal/board"
)

// handle keeps no root and no open file because the contract opens the folder for each
// operation; a root held here would leave the folder open between them.
type handle struct {
	fields    Fields
	keyHolder KeyHolder
	sealedKey []byte
}

func (opened *handle) Fields() Fields {
	return Fields{
		Server:          opened.fields.Server,
		Connection:      opened.fields.Connection,
		AccountName:     opened.fields.AccountName,
		AccountPassword: bytes.Clone(opened.fields.AccountPassword),
		VaultKeys:       slices.Clone(opened.fields.VaultKeys),
		ReceivingKey:    bytes.Clone(opened.fields.ReceivingKey),
		SigningKey:      bytes.Clone(opened.fields.SigningKey),
	}
}

func (opened *handle) KeyHolder() KeyHolder { return opened.keyHolder }

func (opened *handle) SealedKey() []byte { return bytes.Clone(opened.sealedKey) }

func (*handle) Save(Fields) error { return Error{Code: errNotBuilt} }

func (opened *handle) Release() { opened.fields.Zero() }

// openFailure is the error for a folder or a file that will not open: not there, or there and
// refusing.
func openFailure(err error, place Place) Error {
	code := ErrUnreadable
	if errors.Is(err, fs.ErrNotExist) {
		code = ErrNotFound
	}
	return Error{Code: code, Place: place, Err: err}
}

func (entry) Open(ctx context.Context, folder string, account ServiceAccount) (File, error) {
	root, err := os.OpenRoot(folder)
	if err != nil {
		return nil, openFailure(err, PlaceFolder)
	}
	defer root.Close() //nolint:errcheck // a folder opened read-only; nothing to flush

	file, err := root.Open(FileName)
	if err != nil {
		return nil, openFailure(err, PlaceFile)
	}
	content, readErr := readFile(file)
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, Error{Code: ErrUnreadable, Place: PlaceFile, Err: closeErr}
	}

	keyHolder, sealedKey, err := readHeader(content)
	if err != nil {
		return nil, err
	}
	keyHolding, err := holderFor(keyHolder)
	if err != nil {
		return nil, err
	}
	key, err := keyHolding.key(ctx, root, sealedKey, account)
	if err != nil {
		return nil, err
	}
	defer clear(key[:])

	plaintext, err := unseal(&key, content, HeaderStartSize+len(sealedKey))
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)

	records, err := readRecords(plaintext)
	if err != nil {
		return nil, err
	}
	fields, err := fieldsFrom(records)
	if err != nil {
		return nil, err
	}
	return &handle{fields: fields, keyHolder: keyHolder, sealedKey: bytes.Clone(sealedKey)}, nil
}

// unseal takes the key by pointer so it makes no copy of its own; Open owns the key and clears it,
// and Save will need it after unsealing. The header and the nonce, headerSize plus NonceSize
// bytes, are the authenticated data.
func unseal(key *Key256, content []byte, headerSize int) ([]byte, error) {
	failure := Error{Code: ErrDecrypt}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, failure
	}
	sealer, err := cipher.NewGCM(block)
	if err != nil {
		return nil, failure
	}
	nonceEnd := headerSize + NonceSize
	plaintext, err := sealer.Open(nil, content[headerSize:nonceEnd], content[nonceEnd:], content[:nonceEnd])
	if err != nil {
		return nil, failure
	}
	return plaintext, nil
}

// holderFor is the key holder the platform has for a number in a header. A holder the platform
// has but is not built yet is errNotBuilt; any other number, and every number on a platform that
// is neither Windows nor Linux, is ErrKey.
func holderFor(number KeyHolder) (holder, error) {
	onLinux := runtime.GOOS == "linux"
	switch {
	case runtime.GOOS == "windows" && number == WindowsKeyStore,
		onLinux && (number == SystemdByService || number == SystemdAtStart):
		return nil, Error{Code: errNotBuilt}
	case onLinux && number == KeyFile:
		return fileKeyHolder{openFile: openKeyFile}, nil
	case onLinux && number == SwarmSecret:
		return fileKeyHolder{openFile: openSwarmSecret}, nil
	default:
		return nil, Error{Code: ErrKey}
	}
}

// fieldsFrom copies the known records into fields, with the record rules; the field rules are
// not checked here. The data is copied because the plaintext it slices is cleared.
func fieldsFrom(records []record) (Fields, error) {
	var fields Fields
	vaultKeyCount := 0
	for _, item := range records {
		if strings.HasPrefix(item.name, FieldVaultKeyPrefix) {
			vaultKeyCount++
		}
	}
	// Sized up front so append never moves the keys to a new array and leaves the old one
	// holding them uncleared.
	fields.VaultKeys = slices.Grow(fields.VaultKeys, vaultKeyCount)
	for _, item := range records {
		switch {
		case item.name == FieldServer:
			if len(item.data) != 4 {
				fields.Zero()
				return Fields{}, Error{Code: ErrInvalid}
			}
			fields.Server = board.ServerID(binary.BigEndian.Uint32(item.data))
		case item.name == FieldConnection:
			fields.Connection = string(item.data)
		case item.name == FieldAccountName:
			fields.AccountName = string(item.data)
		case item.name == FieldAccountPassword:
			fields.AccountPassword = bytes.Clone(item.data)
		case item.name == FieldReceivingKey:
			fields.ReceivingKey = bytes.Clone(item.data)
		case item.name == FieldSigningKey:
			fields.SigningKey = bytes.Clone(item.data)
		case strings.HasPrefix(item.name, FieldVaultKeyPrefix):
			vaultKey, err := vaultKeyFrom(item)
			if err != nil {
				fields.Zero()
				return Fields{}, err
			}
			fields.VaultKeys = append(fields.VaultKeys, vaultKey)
		}
	}
	return fields, nil
}

// vaultKeyFrom reads a vault.key.<version> record: a version in decimal from 1 to 4,294,967,295
// with no leading zero, and 32 bytes.
func vaultKeyFrom(item record) (VaultKey, error) {
	digits := strings.TrimPrefix(item.name, FieldVaultKeyPrefix)
	if digits == "" || digits[0] == '0' {
		return VaultKey{}, Error{Code: ErrInvalid}
	}
	version, err := strconv.ParseUint(digits, 10, 32)
	if err != nil || version > math.MaxUint32 || len(item.data) != KeySize {
		return VaultKey{}, Error{Code: ErrInvalid}
	}
	return VaultKey{Version: uint32(version), Key: Key256(item.data)}, nil
}
