// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The bootstrap folder every run of the program is given: the bootstrap file sealed by the
// bootstrap file oracle, built once for the run from oracle/bootstrap-file with Free Pascal and
// self-tested, and the key file written by the test's own encoder, its permissions set from
// outside with the system's own tools.
package main_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// The bootstrap folder's two names, and what a good bootstrap file adds to its plaintext: the
// 13 bytes of the header, the 12 of the nonce and the 16 of the tag. The test's own copy, as the
// page states them.
const (
	bootstrapFileName = "bootstrap.hadv"
	keyFileName       = "bootstrap.key"
	sealedOverhead    = 41
	bootstrapMost     = 65536
)

// windowsOS is Windows as runtime.GOOS names it.
const windowsOS = "windows"

// bootstrapOraclePath is the built oracle, and bootstrapOracleFailure why it could not be built
// or failed its self-test: a missing oracle fails every row that starts the program.
var (
	bootstrapOraclePath    string
	bootstrapOracleFailure error
)

// bootstrapFolder is one bootstrap folder a row made: its path, its two files, the key and its
// key file's text, and the plaintext the bootstrap file seals.
type bootstrapFolder struct {
	path      string
	file      string
	keyFile   string
	key       []byte
	keyText   string
	plaintext []byte
}

// newBootstrapKey makes a random key, never 32 zero bytes, and its key file's text with one line
// feed: RFC 4648's standard alphabet with padding.
func newBootstrapKey(t *testing.T) ([]byte, string) {
	t.Helper()
	key := make([]byte, 32)
	for bytes.Equal(key, make([]byte, 32)) {
		if _, err := rand.Read(key); err != nil {
			t.Fatalf("making a key: %v", err)
		}
	}
	return key, base64.StdEncoding.EncodeToString(key) + "\n"
}

// sealBootstrap has the oracle write a bootstrap file sealing plaintext under the key in keyText,
// broken as edits says (empty for a good file), and returns its bytes.
func sealBootstrap(t *testing.T, keyText string, plaintext []byte, edits string) []byte {
	t.Helper()
	if bootstrapOracleFailure != nil {
		t.Fatalf("the bootstrap file oracle could not be built: %v", bootstrapOracleFailure)
	}
	folder := t.TempDir()
	keyPath := filepath.Join(folder, "oracle.key")
	plainPath := filepath.Join(folder, "plain")
	outPath := filepath.Join(folder, "sealed")
	for path, text := range map[string][]byte{keyPath: []byte(keyText), plainPath: plaintext} {
		if err := os.WriteFile(path, text, 0o600); err != nil {
			t.Fatalf("writing the oracle's input: %v", err)
		}
	}
	arguments := []string{"write", keyPath, plainPath, outPath}
	if edits != "" {
		editsPath := filepath.Join(folder, "edits")
		if err := os.WriteFile(editsPath, []byte(edits), 0o600); err != nil {
			t.Fatalf("writing the oracle's edits: %v", err)
		}
		arguments = append(arguments, editsPath)
	}
	ctx, cancel := context.WithTimeout(context.Background(), testrun.Patient(testrun.HangBound))
	defer cancel()
	if output, err := exec.CommandContext(ctx, bootstrapOraclePath, arguments...).CombinedOutput(); err != nil {
		t.Fatalf("the oracle's write: %v: %s", err, strings.TrimSpace(string(output)))
	}
	sealed, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading the oracle's file: %v", err)
	}
	return sealed
}

// makeBootstrapFolder makes a bootstrap folder whose bootstrap file seals plaintext, broken as
// edits says, beside a fresh key in a key file only the engine's account may reach.
func makeBootstrapFolder(t *testing.T, plaintext []byte, edits string) *bootstrapFolder {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bootstrap")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("making the bootstrap folder: %v", err)
	}
	key, keyText := newBootstrapKey(t)
	made := &bootstrapFolder{path: path, file: filepath.Join(path, bootstrapFileName), keyFile: filepath.Join(path, keyFileName),
		key: key, keyText: keyText, plaintext: plaintext}
	made.writeFile(t, sealBootstrap(t, keyText, plaintext, edits))
	made.writeKey(t, keyText)
	return made
}

// writeFile writes the bootstrap file's bytes.
func (made *bootstrapFolder) writeFile(t *testing.T, contents []byte) {
	t.Helper()
	if err := os.WriteFile(made.file, contents, 0o600); err != nil {
		t.Fatalf("writing the bootstrap file: %v", err)
	}
}

// writeKey writes the key file's text and gives it a good key file's permissions.
func (made *bootstrapFolder) writeKey(t *testing.T, text string) {
	t.Helper()
	if err := os.WriteFile(made.keyFile, []byte(text), 0o600); err != nil {
		t.Fatalf("writing the key file: %v", err)
	}
	protectKeyFile(t, made.keyFile)
}

// writeBootstrapFolder makes a good bootstrap folder sealing text, and returns its path.
func writeBootstrapFolder(t *testing.T, text string) string {
	t.Helper()
	return makeBootstrapFolder(t, []byte(text), "").path
}

// expectKeyNotIn fails the row when the log holds the folder's key in any form: its key file's
// text, its bytes in hex, or the bytes themselves.
func (made *bootstrapFolder) expectKeyNotIn(t *testing.T, log string) {
	t.Helper()
	for name, secret := range map[string]string{
		"the key file's text": strings.TrimRight(made.keyText, "\r\n"),
		"the key in hex":      hex.EncodeToString(made.key),
		"the key's bytes":     string(made.key),
	} {
		if strings.Contains(log, secret) {
			t.Fatalf("the local log holds %s:\n%s", name, log)
		}
	}
}

// runSystemTool runs a system tool and fails the row when it fails or is not there.
func runSystemTool(t *testing.T, name string, arguments ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testrun.Patient(testrun.HangBound))
	defer cancel()
	if output, err := exec.CommandContext(ctx, name, arguments...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
}
