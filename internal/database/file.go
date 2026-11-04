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

var connectionFields = []string{fieldServerID, fieldHost, fieldPort, fieldDatabase, fieldLogin, fieldPassword,
	fieldCertificate}

func parseConnection(contents []byte) (Connection, error) {
	values, err := splitObject(contents)
	if err != nil {
		return Connection{}, err
	}
	return parseValues(values)
}

// splitObject reads the one JSON object and returns each field's raw value by name. The names are
// checked here in the order the lines give: a name twice, then one that is not named, then one
// that is missing.
func splitObject(contents []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if first, err := decoder.Token(); err != nil || first != json.Delim('{') {
		return nil, ErrFormat
	}
	values := map[string]json.RawMessage{}
	duplicate := false
	for decoder.More() {
		name, err := decoder.Token()
		nameText, isText := name.(string)
		if err != nil || !isText {
			return nil, ErrFormat
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, ErrFormat
		}
		if _, seen := values[nameText]; seen {
			duplicate = true
		}
		values[nameText] = raw
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return nil, ErrFormat
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrFormat
	}
	if duplicate {
		return nil, ErrFormat
	}
	named := 0
	for _, name := range connectionFields {
		if _, present := values[name]; present {
			named++
		}
	}
	if named != len(values) {
		return nil, ErrFieldUnknown
	}
	if named != len(connectionFields) {
		return nil, ErrFieldMissing
	}
	return values, nil
}

func parseValues(values map[string]json.RawMessage) (Connection, error) {
	var connection Connection
	serverID, err := strconv.ParseInt(string(values[fieldServerID]), 10, 64)
	if err != nil {
		return Connection{}, ErrFormat
	}
	port, err := strconv.ParseUint(string(values[fieldPort]), 10, 16)
	if err != nil || port == 0 {
		return Connection{}, ErrFormat
	}
	connection.ServerID, connection.Port = serverID, uint16(port)
	for name, target := range map[string]*string{fieldHost: &connection.Host, fieldDatabase: &connection.Database,
		fieldLogin: &connection.Login, fieldPassword: &connection.Password,
		fieldCertificate: &connection.CACertificate} {
		if err := json.Unmarshal(values[name], target); err != nil || *target == "" {
			return Connection{}, ErrFormat
		}
	}
	if !onlyCertificates([]byte(connection.CACertificate)) {
		return Connection{}, ErrFormat
	}
	return connection, nil
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
