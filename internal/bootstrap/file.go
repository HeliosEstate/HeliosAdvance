// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/heliosestate/heliosadvance/internal/board"
)

// The envelope's sizes, as the package comment gives the layout.
const (
	magicSize  = len(Magic)
	nonceSize  = 12
	headerSize = magicSize + 2 + nonceSize // the additional authenticated data
	maxName    = 255
	vaultKey   = 32 // bytes
)

// record is one field record, as the file holds it.
type record struct {
	name string
	data []byte
}

// bootstrapFile is a bootstrap file's records, in the order the file holds them.
type bootstrapFile struct {
	records []record
}

// openFile reads a bootstrap file of size bytes from source under key and checks all of it.
func openFile(source io.Reader, size int64, key []byte) (*bootstrapFile, error) {
	if size > MaxSize || size < int64(headerSize+TagSize) {
		return nil, &Refusal{Cause: FileNotUnsealed}
	}
	whole := make([]byte, size)
	if _, err := io.ReadFull(source, whole); err != nil {
		return nil, &Refusal{Cause: FileNotUnsealed}
	}
	// Only the magic and the version are acted on until the tag verifies.
	if string(whole[:magicSize]) != Magic {
		return nil, &Refusal{Cause: FileNotUnsealed}
	}
	version := binary.BigEndian.Uint16(whole[magicSize:])
	if version == 0 {
		return nil, &Refusal{Cause: FileNotUnsealed}
	}
	if version > FormatVersion {
		return nil, &Refusal{Cause: NewerFormat, FileVersion: version, OwnVersion: FormatVersion}
	}
	aead, err := newSealer(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, whole[magicSize+2:headerSize], whole[headerSize:], whole[:headerSize])
	if err != nil {
		return nil, &Refusal{Cause: FileNotUnsealed}
	}
	defer clear(plaintext) // the records are copies; the plaintext holds every secret in the file
	records, err := readRecords(plaintext)
	if err != nil {
		return nil, err
	}
	if err := checkFields(records); err != nil {
		return nil, err
	}
	return &bootstrapFile{records: records}, nil
}

func newSealer(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, &Refusal{Cause: KeyNotUnsealed}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, &Refusal{Cause: KeyNotUnsealed}
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &Refusal{Cause: KeyNotUnsealed}
	}
	return aead, nil
}

// readRecords splits the decrypted fields into records.
func readRecords(plaintext []byte) ([]record, error) {
	var records []record
	seen := map[string]bool{}
	for len(plaintext) > 0 {
		if len(plaintext) < 2 {
			return nil, &Refusal{Cause: FileNotUnsealed}
		}
		nameLength := int(binary.BigEndian.Uint16(plaintext))
		plaintext = plaintext[2:]
		if nameLength == 0 || nameLength > maxName || len(plaintext) < nameLength+4 {
			return nil, &Refusal{Cause: FileNotUnsealed}
		}
		name := string(plaintext[:nameLength])
		dataLength := binary.BigEndian.Uint32(plaintext[nameLength:])
		plaintext = plaintext[nameLength+4:]
		if !utf8.ValidString(name) || seen[name] || uint64(dataLength) > uint64(len(plaintext)) {
			return nil, &Refusal{Cause: FileNotUnsealed}
		}
		seen[name] = true
		records = append(records, record{name: name, data: slices.Clone(plaintext[:dataLength])})
		plaintext = plaintext[dataLength:]
	}
	return records, nil
}

// checkFields holds the known records to their form and to the rules in the table on Fields.
func checkFields(records []record) error {
	found := map[string][]byte{}
	vaultKeys := 0
	for _, rec := range records {
		if rest, isVault := strings.CutPrefix(rec.name, FieldVaultKeyPrefix); isVault {
			if !vaultVersion(rest) || len(rec.data) != vaultKey {
				return &Refusal{Cause: FileNotUnsealed}
			}
			vaultKeys++
		}
		found[rec.name] = rec.data
	}
	server, hasServer := found[FieldServer]
	_, hasPassword := found[FieldAccountPassword]
	ok := hasServer && len(server) == 4 && binary.BigEndian.Uint32(server) != 0 && hasPassword &&
		vaultKeys >= 1 && vaultKeys <= 2
	for _, name := range []string{FieldConnection, FieldAccountName} {
		ok = ok && len(found[name]) > 0 && utf8.Valid(found[name])
	}
	for _, name := range []string{FieldReceivingKey, FieldSigningKey} {
		ok = ok && len(found[name]) > 0
	}
	if !ok {
		return &Refusal{Cause: FileNotUnsealed}
	}
	return nil
}

// vaultVersion is a decimal from 1 to 4,294,967,295 with no leading zero; ParseUint alone
// would take a leading zero.
func vaultVersion(text string) bool {
	if text == "" || text[0] == '0' {
		return false
	}
	_, err := strconv.ParseUint(text, 10, 32)
	return err == nil
}

// fields is the known fields, in memory of their own.
func (file *bootstrapFile) fields() Fields {
	var fields Fields
	for _, rec := range file.records {
		switch rec.name {
		case FieldServer:
			if len(rec.data) == 4 {
				fields.Server = board.ServerID(binary.BigEndian.Uint32(rec.data))
			}
		case FieldConnection:
			fields.Connection = string(rec.data)
		case FieldAccountName:
			fields.AccountName = string(rec.data)
		case FieldAccountPassword:
			fields.AccountPassword = slices.Clone(rec.data)
		case FieldReceivingKey:
			fields.ReceivingKey = slices.Clone(rec.data)
		case FieldSigningKey:
			fields.SigningKey = slices.Clone(rec.data)
		default:
			if rest, isVault := strings.CutPrefix(rec.name, FieldVaultKeyPrefix); isVault {
				version, err := strconv.ParseUint(rest, 10, 32)
				if err != nil {
					continue // a name checked on open
				}
				fields.VaultKeys = append(fields.VaultKeys, VaultKey{Version: uint32(version), Key: slices.Clone(rec.data)})
			}
		}
	}
	return fields
}

// setFields replaces the known fields; every other record keeps its place.
func (file *bootstrapFile) setFields(fields Fields) {
	server := binary.BigEndian.AppendUint32(nil, uint32(fields.Server))
	known := []record{
		{FieldServer, server},
		{FieldConnection, []byte(fields.Connection)},
		{FieldAccountName, []byte(fields.AccountName)},
		{FieldAccountPassword, fields.AccountPassword},
	}
	for _, key := range fields.VaultKeys {
		known = append(known, record{FieldVaultKeyPrefix + strconv.FormatUint(uint64(key.Version), 10), key.Key})
	}
	known = append(known, record{FieldReceivingKey, fields.ReceivingKey}, record{FieldSigningKey, fields.SigningKey})

	var records []record
	placed := map[string]bool{}
	for _, rec := range file.records {
		if !isKnown(rec.name) {
			records = append(records, rec)
			continue
		}
		// A known record keeps its place if it is still wanted; a removed vault key goes.
		if index := slices.IndexFunc(known, func(want record) bool { return want.name == rec.name }); index >= 0 {
			records = append(records, record{known[index].name, slices.Clone(known[index].data)})
			placed[rec.name] = true
		}
	}
	for _, want := range known {
		if !placed[want.name] {
			records = append(records, record{want.name, slices.Clone(want.data)})
		}
	}
	file.records = records
}

func isKnown(name string) bool {
	switch name {
	case FieldServer, FieldConnection, FieldAccountName, FieldAccountPassword, FieldReceivingKey, FieldSigningKey:
		return true
	}
	return strings.HasPrefix(name, FieldVaultKeyPrefix)
}

// writeTo seals the records under key with a new nonce.
func (file *bootstrapFile) writeTo(destination io.Writer, key []byte) error {
	aead, err := newSealer(key)
	if err != nil {
		return err
	}
	size := 0
	for _, rec := range file.records {
		size += 2 + len(rec.name) + 4 + len(rec.data)
	}
	if size > MaxSize {
		return &Refusal{Cause: RewriteFailed}
	}
	plaintext := make([]byte, 0, size) // sized first so append never reallocates and leaves partly filled copies
	defer clear(plaintext[:size])
	for _, rec := range file.records {
		plaintext = binary.BigEndian.AppendUint16(plaintext, uint16(len(rec.name))) //nolint:gosec // a name read or set here is at most 255 bytes
		plaintext = append(plaintext, rec.name...)
		plaintext = binary.BigEndian.AppendUint32(plaintext, uint32(len(rec.data))) //nolint:gosec // bounded by MaxSize above
		plaintext = append(plaintext, rec.data...)
	}
	header := make([]byte, headerSize)
	copy(header, Magic)
	binary.BigEndian.PutUint16(header[magicSize:], FormatVersion)
	if _, err := rand.Read(header[magicSize+2:]); err != nil {
		return fmt.Errorf("bootstrap: reading random bytes for the nonce: %w", err)
	}
	sealed := aead.Seal(header, header[magicSize+2:headerSize], plaintext, header)
	if len(sealed) > MaxSize {
		return &Refusal{Cause: RewriteFailed}
	}
	_, err = destination.Write(sealed)
	return err
}

// Error makes a *Refusal an error, as the contract's errors.As needs. It names the cause and
// the two versions of a NewerFormat, and no key and no field's data.
func (refusal *Refusal) Error() string {
	if refusal.Cause == NewerFormat {
		return fmt.Sprintf("bootstrap: refused, cause %d: file format version %d, this build reads %d", refusal.Cause, refusal.FileVersion, refusal.OwnVersion)
	}
	return fmt.Sprintf("bootstrap: refused, cause %d", refusal.Cause)
}
