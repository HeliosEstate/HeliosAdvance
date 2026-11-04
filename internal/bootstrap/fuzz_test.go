// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The contract's two fuzz targets, the header reader and the key file's reader, both reached
// only through Open: any bytes as the bootstrap file beside a good key file, and any bytes as
// the key file beside a good bootstrap file. Open returns the sealed JSON or one of its own
// refusals, never panics and never waits.
package bootstrap_test

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzHeader(fuzzing *testing.F) {
	key, keyText, err := randomKey()
	if err != nil {
		fuzzing.Fatalf("making a key: %v", err)
	}
	plaintext := paddedPlaintext(64)
	for _, edits := range append([]string{""}, editsOf(headerEdits)...) {
		sealed, err := sealIn(fuzzing.TempDir(), keyText, plaintext, edits)
		if err != nil {
			fuzzing.Fatalf("%v", err)
		}
		fuzzing.Add(sealed)
	}
	fuzzing.Add([]byte{})
	fuzzing.Add([]byte("HADVBOOT"))
	fuzzing.Fuzz(func(t *testing.T, file []byte) {
		made := fuzzFolder(t, key, keyText, plaintext, file, keyText)
		contents, err := open(t, made.folder)
		expectOneOutcome(t, made, contents, err)
	})
}

func FuzzKeyFile(fuzzing *testing.F) {
	key, keyText, err := randomKey()
	if err != nil {
		fuzzing.Fatalf("making a key: %v", err)
	}
	plaintext := paddedPlaintext(64)
	sealed, err := sealIn(fuzzing.TempDir(), keyText, plaintext, "")
	if err != nil {
		fuzzing.Fatalf("%v", err)
	}
	for _, text := range []string{keyText, keyText[:44], keyText[:44] + "\r\n", keyText[:43], "", "\n"} {
		fuzzing.Add([]byte(text))
	}
	for _, build := range malformedKeys {
		fuzzing.Add([]byte(build(keyText[:44])))
	}
	fuzzing.Fuzz(func(t *testing.T, text []byte) {
		made := fuzzFolder(t, key, keyText, plaintext, sealed, string(text))
		contents, err := open(t, made.folder)
		expectOneOutcome(t, made, contents, err)
	})
}

// editsOf lists the edits of a map of named edits.
func editsOf(named map[string]string) []string {
	edits := make([]string, 0, len(named))
	for _, each := range named {
		edits = append(edits, each)
	}
	return edits
}

// fuzzFolder makes a bootstrap folder holding file as the bootstrap file and keyFileText as the
// key file, given a good key file's permissions.
func fuzzFolder(t *testing.T, key []byte, keyText string, plaintext, file []byte, keyFileText string) *layout {
	t.Helper()
	folder := filepath.Join(t.TempDir(), "bootstrap")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatalf("making the bootstrap folder: %v", err)
	}
	made := &layout{folder: folder, file: filepath.Join(folder, fileName), keyFile: filepath.Join(folder, keyFileName),
		key: key, keyText: keyText, plaintext: plaintext}
	made.writeFile(t, file)
	made.writeKey(t, keyFileText)
	return made
}

// expectOneOutcome fails the input unless Open returned bytes and no error, or no bytes and
// exactly one of its refusals, with nothing secret in the error's text.
func expectOneOutcome(t *testing.T, made *layout, contents []byte, err error) {
	t.Helper()
	if err == nil {
		return
	}
	index := errorIndex(err)
	if index < 0 {
		t.Fatalf("Open returned %v, none of its refusals", err)
	}
	expectError(t, contents, err, openErrors[index])
	made.expectNothingSecret(t, err)
}
