// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package database

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// The field names are compared exactly: "Host" and "host " are fields the format does not name,
// not spellings of one it does.
const (
	fieldServerID    = "server_id"
	fieldHost        = "host"
	fieldPort        = "port"
	fieldDatabase    = "database"
	fieldLogin       = "login"
	fieldPassword    = "password"
	fieldCertificate = "ca_certificate"
)

var fileFields = []string{fieldServerID, fieldHost, fieldPort, fieldDatabase, fieldLogin, fieldPassword,
	fieldCertificate}

// groupOrOthersRead is any of the bits that let someone but the owner read a file that holds a
// password.
const groupOrOthersRead = 0o044

func readConnectionFile(path string) (ConnectionFile, error) {
	cleaned := filepath.Clean(path)
	info, err := os.Stat(cleaned)
	if errors.Is(err, os.ErrNotExist) {
		return ConnectionFile{}, ErrFileMissing
	}
	if err != nil {
		return ConnectionFile{}, ErrFileUnreadable
	}
	// The mode is checked before the file is opened: a file others can read is refused unread.
	if runtime.GOOS == "linux" && info.Mode().Perm()&groupOrOthersRead != 0 {
		return ConnectionFile{}, ErrFileReadableByOthers
	}
	contents, err := readLimited(cleaned)
	if err != nil {
		return ConnectionFile{}, err
	}
	defer clear(contents)
	values, err := splitObject(contents)
	if err != nil {
		return ConnectionFile{}, err
	}
	return parseValues(values)
}

// readLimited reads the file into a buffer one byte longer than the most allowed, so a longer file
// is told from one of exactly the most.
func readLimited(path string) ([]byte, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, ErrFileUnreadable
	}
	contents := make([]byte, ConnectionFileMostBytes+1)
	count, readErr := io.ReadFull(file, contents)
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.ErrUnexpectedEOF) && !errors.Is(readErr, io.EOF) {
		clear(contents)
		return nil, ErrFileUnreadable
	}
	if closeErr != nil {
		clear(contents)
		return nil, ErrFileUnreadable
	}
	if count == len(contents) {
		clear(contents)
		return nil, ErrFileTooLarge
	}
	return contents[:count], nil
}

// splitObject reads the one JSON object and returns each field's raw value by name. The names are
// checked here in the order the lines give: a name twice, then one that is not named, then one
// that is missing.
func splitObject(contents []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if first, err := decoder.Token(); err != nil || first != json.Delim('{') {
		return nil, ErrFileFormat
	}
	values := map[string]json.RawMessage{}
	duplicate := false
	for decoder.More() {
		name, err := decoder.Token()
		nameText, isText := name.(string)
		if err != nil || !isText {
			return nil, ErrFileFormat
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, ErrFileFormat
		}
		if _, seen := values[nameText]; seen {
			duplicate = true
		}
		values[nameText] = raw
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return nil, ErrFileFormat
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrFileFormat
	}
	if duplicate {
		return nil, ErrFileFormat
	}
	named := 0
	for _, name := range fileFields {
		if _, present := values[name]; present {
			named++
		}
	}
	if named != len(values) {
		return nil, ErrFileFieldUnknown
	}
	if named != len(fileFields) {
		return nil, ErrFileFieldMissing
	}
	return values, nil
}

func parseValues(values map[string]json.RawMessage) (ConnectionFile, error) {
	var file ConnectionFile
	serverID, err := strconv.ParseInt(string(values[fieldServerID]), 10, 64)
	if err != nil {
		return ConnectionFile{}, ErrFileFormat
	}
	port, err := strconv.ParseUint(string(values[fieldPort]), 10, 16)
	if err != nil || port == 0 {
		return ConnectionFile{}, ErrFileFormat
	}
	file.ServerID, file.Port = serverID, uint16(port)
	for name, target := range map[string]*string{fieldHost: &file.Host, fieldDatabase: &file.Database,
		fieldLogin: &file.Login, fieldPassword: &file.Password, fieldCertificate: &file.CACertificate} {
		if err := json.Unmarshal(values[name], target); err != nil || *target == "" {
			return ConnectionFile{}, ErrFileFormat
		}
	}
	if !onlyCertificates([]byte(file.CACertificate)) {
		return ConnectionFile{}, ErrFileFormat
	}
	return file, nil
}

// onlyCertificates is true when the text is one or more CERTIFICATE blocks, each an X.509
// certificate, with nothing but white space around them: pem.Decode alone skips text before a
// block.
func onlyCertificates(text []byte) bool {
	blocks := 0
	for {
		text = bytes.TrimSpace(text)
		if len(text) == 0 {
			return blocks > 0
		}
		if !bytes.HasPrefix(text, []byte("-----BEGIN ")) {
			return false
		}
		var block *pem.Block
		block, text = pem.Decode(text)
		if block == nil || block.Type != "CERTIFICATE" {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		blocks++
	}
}
