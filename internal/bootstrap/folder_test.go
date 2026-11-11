// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/bootstrap"
	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// The test's own copy of the folder's names and bounds, as the page and the contract's package
// comment state them, never the package's constants, so a fault there cannot hide here too.
const (
	fileName         = "bootstrap.hadv"
	keyFileName      = "bootstrap.key"
	fileMostBytes    = 65536
	keyFileMostBytes = 46
	// sealedOverhead is what a good file adds to its plaintext: the 13 bytes of the header, the
	// 12 of the nonce and the 16 of the tag.
	sealedOverhead = 41
)

// canary is planted in every plaintext, so an error's text that carries any of the sealed JSON
// is found by it.
const canary = "canary-7f3a9c-bootstrap"

// openErrors is every refusal Open may return; a row's exact error is one of them and none other.
var openErrors = []error{
	bootstrap.ErrFolderMissing, bootstrap.ErrFolderUnreadable, bootstrap.ErrFileMissing,
	bootstrap.ErrFileUnreadable, bootstrap.ErrFileTooLarge, bootstrap.ErrHeader,
	bootstrap.ErrKeyFileMissing, bootstrap.ErrKeyFileUnreadable, bootstrap.ErrKeyFilePermissions,
	bootstrap.ErrKeyFileReachable, bootstrap.ErrKeyFileForm, bootstrap.ErrKeyStore,
	bootstrap.ErrKeyStorePermissions, bootstrap.ErrKeyStoreReachable, bootstrap.ErrUnwrap,
	bootstrap.ErrUnseal,
}

// layout is one bootstrap folder a row made: the folder, its two files' paths, the key and its
// key file's text, and the plaintext the bootstrap file seals. Under key holder 2 or 3 it also
// holds the key store key's name and the wrapped bytes the sealed key carries, and what the key
// store unwraps from them when that is not the key, each a secret no error may hold.
type layout struct {
	folder    string
	file      string
	keyFile   string
	key       []byte
	keyText   string
	plaintext []byte
	sealed    []byte
	keyName   string
	wrapped   []byte
	unwrapped []byte
	// turn, when set, is held while Open runs: the TPM serves one command at a time, so a row's
	// Open would otherwise wait on every other row's, and on the oracle's keys, which take seconds
	// each; taken in turn, the hang bound measures this Open alone.
	turn *sync.Mutex
}

// open calls Open on the folder, in its turn when it has one.
func (made *layout) open(t *testing.T) ([]byte, error) {
	t.Helper()
	if made.turn != nil {
		made.turn.Lock()
		defer made.turn.Unlock()
	}
	return open(t, made.folder)
}

// newKey makes a random key, never 32 zero bytes, and its key file's text with one line feed,
// written by the test's own encoder: RFC 4648's standard alphabet with padding.
func newKey(t *testing.T) ([]byte, string) {
	t.Helper()
	key, text, err := randomKey()
	if err != nil {
		t.Fatalf("making a key: %v", err)
	}
	return key, text
}

// randomKey is newKey for a caller with no row of its own, a fuzz target's seeds.
func randomKey() ([]byte, string, error) {
	key := make([]byte, 32)
	for bytes.Equal(key, make([]byte, 32)) {
		if _, err := rand.Read(key); err != nil {
			return nil, "", err
		}
	}
	return key, base64.StdEncoding.EncodeToString(key) + "\n", nil
}

// plaintextOf is a plaintext of exactly size bytes, the canary at its start and spaces after,
// as a JSON object padded with spaces would be; at least the canary's object.
func plaintextOf(_ *testing.T, size int) []byte {
	return paddedPlaintext(size)
}

// paddedPlaintext is plaintextOf for a caller with no row of its own.
func paddedPlaintext(size int) []byte {
	text := []byte(`{"note":"` + canary + `"}`)
	return append(text, bytes.Repeat([]byte(" "), max(0, size-len(text)))...)
}

// seal has the oracle write a bootstrap file sealing plaintext under the key in keyText, broken
// as edits says (empty for a good file), and returns its bytes. The oracle judges no key, so a
// key of 32 zero bytes is sealed under like any other.
func seal(t *testing.T, keyText string, plaintext []byte, edits string) []byte {
	t.Helper()
	sealed, err := sealIn(t.TempDir(), keyText, plaintext, edits)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return sealed
}

// sealIn is seal for a caller with no row of its own, working in folder.
func sealIn(folder, keyText string, plaintext []byte, edits string) ([]byte, error) {
	if oracleFailure != nil {
		return nil, fmt.Errorf("the bootstrap file oracle could not be built: %w", oracleFailure)
	}
	keyPath := filepath.Join(folder, "oracle.key")
	plainPath := filepath.Join(folder, "plain")
	outPath := filepath.Join(folder, "sealed")
	for path, text := range map[string][]byte{keyPath: []byte(keyText), plainPath: plaintext} {
		if err := os.WriteFile(path, text, 0o600); err != nil {
			return nil, fmt.Errorf("writing the oracle's input: %w", err)
		}
	}
	arguments := []string{"write", keyPath, plainPath, outPath}
	if edits != "" {
		editsPath := filepath.Join(folder, "edits")
		if err := os.WriteFile(editsPath, []byte(edits), 0o600); err != nil {
			return nil, fmt.Errorf("writing the oracle's edits: %w", err)
		}
		arguments = append(arguments, editsPath)
	}
	ctx, cancel := context.WithTimeout(context.Background(), testrun.Patient(testrun.HangBound))
	defer cancel()
	if output, err := exec.CommandContext(ctx, oraclePath, arguments...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("the oracle's write: %w: %s", err, strings.TrimSpace(string(output)))
	}
	sealed, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("reading the oracle's file: %w", err)
	}
	return sealed, nil
}

// makeFolder makes a good bootstrap folder: a fresh key in a key file only the engine's account
// may reach, and a bootstrap file the oracle sealed under it, its plaintext 64 bytes with the
// canary.
func makeFolder(t *testing.T) *layout {
	t.Helper()
	return makeFolderWith(t, plaintextOf(t, 64), "")
}

// makeFolderWith makes a bootstrap folder whose bootstrap file seals plaintext, broken as edits
// says.
func makeFolderWith(t *testing.T, plaintext []byte, edits string) *layout {
	t.Helper()
	folder := filepath.Join(t.TempDir(), "bootstrap")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatalf("making the bootstrap folder: %v", err)
	}
	key, keyText := newKey(t)
	made := &layout{folder: folder, file: filepath.Join(folder, fileName), keyFile: filepath.Join(folder, keyFileName),
		key: key, keyText: keyText, plaintext: plaintext}
	made.writeFile(t, seal(t, keyText, plaintext, edits))
	made.writeKey(t, keyText)
	return made
}

// writeFile writes the bootstrap file's bytes.
func (made *layout) writeFile(t *testing.T, contents []byte) {
	t.Helper()
	made.sealed = contents
	if err := os.WriteFile(made.file, contents, 0o600); err != nil {
		t.Fatalf("writing the bootstrap file: %v", err)
	}
}

// writeKey writes the key file's text and gives it the permissions of a good key file: only the
// engine's account may reach it.
func (made *layout) writeKey(t *testing.T, text string) {
	t.Helper()
	if err := os.WriteFile(made.keyFile, []byte(text), 0o600); err != nil {
		t.Fatalf("writing the key file: %v", err)
	}
	protectKeyFile(t, made.keyFile)
}

// remove deletes one of the folder's files.
func remove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("removing %s: %v", path, err)
	}
}

// openResult is what one Open returned.
type openResult struct {
	contents []byte
	err      error
}

// open calls Open on the folder, bounded by the hang bound: an Open that waits fails its row by
// name instead of running the package into Go's timeout.
func open(t *testing.T, folder string) ([]byte, error) {
	t.Helper()
	results := make(chan openResult, 1)
	go func() {
		contents, err := bootstrap.Open(folder)
		results <- openResult{contents: contents, err: err}
	}()
	select {
	case result := <-results:
		return result.contents, result.err
	case <-time.After(testrun.Patient(testrun.HangBound)):
		t.Fatalf("Open did not return within %v: it waited", testrun.Patient(testrun.HangBound))
		return nil, nil
	}
}

// expectRefused opens the folder and fails the row unless Open returned exactly want, no other
// refusal, no bytes, and an error whose text holds none of the key, the key file's text or the
// bootstrap file's contents.
func (made *layout) expectRefused(t *testing.T, want error) {
	t.Helper()
	contents, err := made.open(t)
	expectError(t, contents, err, want)
	made.expectNothingSecret(t, err)
}

// expectError fails the row unless err is want and no other of Open's refusals, and no bytes
// came back.
func expectError(t *testing.T, contents []byte, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("Open returned %v, want %v", err, want)
	}
	for _, other := range openErrors {
		if !errors.Is(other, want) && errors.Is(err, other) {
			t.Fatalf("Open's error %v is also %v", err, other)
		}
	}
	if len(contents) != 0 {
		t.Fatalf("Open refused with %v but returned %d bytes", err, len(contents))
	}
}

// expectNothingSecret fails the row when the error's text holds the key in any of its forms, the
// key file's text, the canary in the plaintext, or the bootstrap file's bytes after its magic;
// under key holder 2 or 3 also the key store key's name or its 32 hex digits, the wrapped bytes
// raw or in hex, and what the key store unwrapped in its forms. The refusal's own fixed words are
// set aside first: they carry nothing of the files, and a fuzzed file's few bytes after its magic
// can be found in them by chance, such as "e".
func (made *layout) expectNothingSecret(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	text := err.Error()
	if index := errorIndex(err); index >= 0 {
		text = strings.Replace(text, openErrors[index].Error(), "", 1)
	}
	secrets := map[string]string{
		"the canary in the plaintext": canary,
		"the key's bytes":             string(made.key),
		"the key in hex":              hex.EncodeToString(made.key),
		"the key in base64":           strings.TrimSpace(base64.StdEncoding.EncodeToString(made.key)),
		"the key file's text":         strings.TrimRight(made.keyText, "\r\n"),
		"the plaintext":               string(bytes.TrimRight(made.plaintext, " ")),
	}
	if len(made.sealed) > 8 {
		secrets["the bootstrap file's bytes after its magic"] = string(made.sealed[8:])
	}
	if made.keyName != "" {
		secrets["the key store key's name"] = made.keyName
		secrets["the key store key's hex digits"] = made.keyName[min(len("hadv-"), len(made.keyName)):]
	}
	if len(made.wrapped) > 0 {
		secrets["the wrapped bytes"] = string(made.wrapped)
		secrets["the wrapped bytes in hex"] = hex.EncodeToString(made.wrapped)
	}
	if len(made.unwrapped) > 0 {
		secrets["what the key store unwrapped"] = string(made.unwrapped)
		secrets["what the key store unwrapped, in hex"] = hex.EncodeToString(made.unwrapped)
		secrets["what the key store unwrapped, in base64"] = base64.StdEncoding.EncodeToString(made.unwrapped)
		// A part of it as well: its first 32 bytes, which an engine that took a longer result
		// would hold as the key, and its first and last 16.
		for name, part := range map[string][]byte{"its first 32 bytes": made.unwrapped[:min(32, len(made.unwrapped))],
			"its first 16 bytes": made.unwrapped[:min(16, len(made.unwrapped))],
			"its last 16 bytes":  made.unwrapped[max(0, len(made.unwrapped)-16):]} {
			secrets["what the key store unwrapped, "+name] = string(part)
			secrets["what the key store unwrapped, "+name+", in hex"] = hex.EncodeToString(part)
		}
		secrets["what the key store unwrapped, its first 30 bytes in base64"] = base64.StdEncoding.EncodeToString(made.unwrapped[:min(30, len(made.unwrapped))])
	}
	for name, secret := range secrets {
		if secret != "" && strings.Contains(text, secret) {
			t.Fatalf("Open's error holds %s: %q", name, err.Error())
		}
	}
}

// outcome is one way Open can end: the folder that leads there, and the refusal it gives, nil
// for opened.
type outcome struct {
	make func(t *testing.T) *layout
	want error
}

// reach makes the outcome's folder and opens it, failing the row unless Open ended as the
// outcome says, so a row about what Open leaves behind is red until Open is built.
func (way outcome) reach(t *testing.T) *layout {
	t.Helper()
	made := way.make(t)
	if way.want == nil {
		made.expectOpened(t)
	} else {
		made.expectRefused(t, way.want)
	}
	return made
}

// closingOutcomes is each way Open can end that a row can reach without holding a file open
// itself: opened, and each refusal from the bootstrap file's to the unseal's.
func closingOutcomes() map[string]outcome {
	ways := closingFolders()
	wants := map[string]error{
		"opened": nil, "ErrFileMissing": bootstrap.ErrFileMissing,
		"ErrFileUnreadable, a folder as the bootstrap file": bootstrap.ErrFileUnreadable,
		"ErrFileTooLarge": bootstrap.ErrFileTooLarge, "ErrHeader": bootstrap.ErrHeader,
		"ErrKeyFileMissing": bootstrap.ErrKeyFileMissing,
		"ErrKeyFileUnreadable, a folder as the key file": bootstrap.ErrKeyFileUnreadable,
		"ErrKeyFileReachable":                            bootstrap.ErrKeyFileReachable,
		"ErrKeyFileForm":                                 bootstrap.ErrKeyFileForm, "ErrUnseal": bootstrap.ErrUnseal,
	}
	outcomes := map[string]outcome{}
	for name, made := range ways {
		outcomes[name] = outcome{make: made, want: wants[name]}
	}
	return outcomes
}

// closingFolders makes each closing outcome's folder.
func closingFolders() map[string]func(t *testing.T) *layout {
	return map[string]func(t *testing.T) *layout{
		"opened": makeFolder,
		"ErrFileMissing": func(t *testing.T) *layout {
			t.Helper()
			made := makeFolder(t)
			remove(t, made.file)
			return made
		},
		"ErrFileUnreadable, a folder as the bootstrap file": func(t *testing.T) *layout {
			t.Helper()
			made := makeFolder(t)
			remove(t, made.file)
			if err := os.Mkdir(made.file, 0o700); err != nil {
				t.Fatalf("making the folder: %v", err)
			}
			return made
		},
		"ErrFileTooLarge": func(t *testing.T) *layout {
			t.Helper()
			return makeFolderWith(t, plaintextOf(t, fileMostBytes+1-sealedOverhead), "")
		},
		"ErrHeader": func(t *testing.T) *layout {
			t.Helper()
			return makeFolderWith(t, plaintextOf(t, 64), `magic "HADVBOOX"`)
		},
		"ErrKeyFileMissing": func(t *testing.T) *layout {
			t.Helper()
			made := makeFolder(t)
			remove(t, made.keyFile)
			return made
		},
		"ErrKeyFileUnreadable, a folder as the key file": func(t *testing.T) *layout {
			t.Helper()
			made := makeFolder(t)
			remove(t, made.keyFile)
			if err := os.Mkdir(made.keyFile, 0o700); err != nil {
				t.Fatalf("making the folder: %v", err)
			}
			return made
		},
		"ErrKeyFileReachable": func(t *testing.T) *layout {
			t.Helper()
			made := makeFolder(t)
			openToOthers(t, made.keyFile)
			return made
		},
		"ErrKeyFileForm": func(t *testing.T) *layout {
			t.Helper()
			made := makeFolder(t)
			made.writeKey(t, strings.TrimRight(made.keyText, "\r\n")[:43])
			return made
		},
		"ErrUnseal": func(t *testing.T) *layout {
			t.Helper()
			return makeFolderWith(t, plaintextOf(t, 64), "flip 60")
		},
	}
}

// expectOpened opens the folder and fails the row unless Open returned no error and exactly the
// plaintext the oracle sealed.
func (made *layout) expectOpened(t *testing.T) {
	t.Helper()
	contents, err := made.open(t)
	if err != nil {
		t.Fatalf("Open refused a good folder: %v", err)
	}
	if !bytes.Equal(contents, made.plaintext) {
		t.Fatalf("Open returned %d bytes, not the %d the oracle sealed", len(contents), len(made.plaintext))
	}
}
