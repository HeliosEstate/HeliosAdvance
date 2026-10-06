// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The approved fuzz target for issue #87: the reader of a key file or Swarm secret, an
// untrusted input. Its oracle is the form the package comment gives a key: RFC 4648's
// standard base64 alphabet with its padding, one spelling for each key, in 44 characters
// with at most one trailing newline.
package bootstrap

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// keyFileLength is a key's 32 bytes as base64: 44 characters, padding included.
const keyFileLength = 44

// FuzzKeyFile reads anything as a key file: it never panics, accepts exactly the one
// spelling of 32 bytes with or without one trailing newline and returns those bytes, and
// refuses everything else with KeyFileMalformed.
func FuzzKeyFile(fuzz *testing.F) {
	seed, err := os.ReadFile(filepath.Join(samples, "test.key"))
	if err != nil {
		fuzz.Fatal(err)
	}
	fuzz.Add(seed)
	fuzz.Add(bytes.TrimSuffix(seed, []byte("\n")))
	fuzz.Add(append(bytes.Clone(seed), '\n'))
	fuzz.Fuzz(func(t *testing.T, data []byte) {
		key, err := readKeyFile(bytes.NewReader(data))
		want, canonical := canonicalKey(data)
		if canonical {
			if err != nil {
				t.Fatalf("refused %q: %v", data, err)
			}
			if !bytes.Equal(key, want) {
				t.Fatalf("read %q as %x, want %x", data, key, want)
			}
			return
		}
		if refusal := refusalOf(err); refusal == nil || refusal.Cause != KeyFileMalformed {
			t.Fatalf("read %q: got %v, want a KeyFileMalformed refusal", data, err)
		}
	})
}

// canonicalKey is the oracle: the key data spells, when it is the one spelling of 32 bytes,
// with or without one trailing newline. Go's decoder skips newlines inside its input, so the
// spelling is proved by encoding the bytes again, not by decoding alone.
func canonicalKey(data []byte) ([]byte, bool) {
	text := bytes.TrimSuffix(data, []byte("\n"))
	if len(text) != keyFileLength {
		return nil, false
	}
	key, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil || len(key) != 32 {
		return nil, false
	}
	return key, base64.StdEncoding.EncodeToString(key) == string(text)
}
