// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The program and its bootstrap folder, driven from outside: the folder, the bootstrap file and
// its key file missing, unreadable or linked out; the bootstrap file's size, header and seal; the
// key file's form. Every bootstrap file is the oracle's, sealing a row of its own on the shared
// board; every key file is written by the test's own encoder. Each refusal is one start_failed
// line and a non-zero exit, its reason not the reason another check gives, since each start_failed
// line names which check failed; neither the key nor a password is in the log. The lines that
// differ by system are in the files named for each.
package main_test

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The oracle's broken headers the page's header line needs, each of which the engine refuses
// before it reads the key file: the README's list, status 3.
var headerEdits = map[string]string{
	"a wrong magic":                      `magic "HADVBOOX"`,
	"format version 0":                   "version 0",
	"format version 2":                   "version 2",
	"key holder 0":                       "holder 0",
	"key holder 2":                       "holder 2",
	"a sealed-key length of 1 that lies": "sealed-length 1",
	"40 bytes, too short for its header": "truncate 40",
}

// malformedKeys are key files not in the key file's form, each built from a good key's 44
// characters.
var malformedKeys = map[string]func(base string) string{
	"43 characters":                      func(base string) string { return base[:42] + "=" },
	"45 characters":                      func(base string) string { return base[:43] + "A=" },
	"no padding":                         func(base string) string { return base[:43] },
	"two padding characters":             func(base string) string { return base[:42] + "==" },
	"a - from the URL-safe alphabet":     func(base string) string { return "-" + base[1:] },
	"a leading space":                    func(base string) string { return " " + base },
	"a bit set after the last byte":      withTrailingBit,
	"two line feeds":                     func(base string) string { return base + "\n\n" },
	"a bare carriage return":             func(base string) string { return base + "\r" },
	"47 bytes, a CR LF then a line feed": func(base string) string { return base + "\r\n\n" },
}

// withTrailingBit sets the lowest of the bits after the key's last byte: the 43rd character
// carries 4 bits of the last byte and 2 that must be zero.
func withTrailingBit(base string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	index := strings.IndexByte(alphabet, base[42])
	return base[:42] + string(alphabet[index|1]) + "="
}

// goodFolder makes a good bootstrap folder for a row of its own on the shared board.
func goodFolder(t *testing.T) *bootstrapFolder {
	t.Helper()
	return brokenFolder(t, "")
}

// brokenFolder makes a bootstrap folder for a row of its own on the shared board, its bootstrap
// file broken as the oracle's edits say.
func brokenFolder(t *testing.T, edits string) *bootstrapFolder {
	t.Helper()
	return makeBootstrapFolder(t, []byte(sharedRowSettings(t).text(t)), edits)
}

// keyBase is a good key file's 44 characters, without its line ending.
func (made *bootstrapFolder) keyBase() string {
	return strings.TrimRight(made.keyText, "\r\n")
}

// refused starts the program with the folder, checks it refuses with one start_failed line and
// a non-zero exit, and neither a password nor the key in its log, and returns the reason.
func (made *bootstrapFolder) refused(t *testing.T) string {
	t.Helper()
	program, release := made.start(t)
	reason := program.expectRefusal(t)
	release()
	expectNoPassword(t, program)
	made.expectKeyNotIn(t, program.text())
	return reason
}

// starts starts the program with the folder and checks it starts and listens, with neither a
// password nor the key in its log.
func (made *bootstrapFolder) starts(t *testing.T) {
	t.Helper()
	program, release := made.start(t)
	program.listening(t)
	release()
	expectNoPassword(t, program)
	made.expectKeyNotIn(t, program.text())
}

// start starts the program with the folder, in the folder's turn when it has one, and returns
// what gives the turn back once the program has started or refused; a row that fails first
// gives it back when it ends.
func (made *bootstrapFolder) start(t *testing.T) (*run, func()) {
	t.Helper()
	release := func() {}
	if made.turn != nil {
		made.turn.Lock()
		var once sync.Once
		release = func() { once.Do(made.turn.Unlock) }
		t.Cleanup(release)
	}
	return startWithFile(t, made.path, nil, portOption, "0"), release
}

// keyMissingReason is the reason for another check than most rows': a good bootstrap file whose
// key file is missing.
func keyMissingReason(t *testing.T) string {
	t.Helper()
	made := goodFolder(t)
	removeFile(t, made.keyFile)
	return made.refused(t)
}

// fileMissingReason is the reason for another check than the key file's rows: a good key file
// whose bootstrap file is missing.
func fileMissingReason(t *testing.T) string {
	t.Helper()
	made := goodFolder(t)
	removeFile(t, made.file)
	return made.refused(t)
}

// expectOwnReason fails the row when its reason is the one another check gives: the line says
// which, and each start_failed line names the check that failed.
func expectOwnReason(t *testing.T, reason, other, otherName string) {
	t.Helper()
	if reason == other {
		t.Fatalf("the reason %q is the same as for %s, where it must say which check failed", reason, otherName)
	}
}

// removeFile deletes one of the folder's files.
func removeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("removing %s: %v", path, err)
	}
}

// makeFolderAt puts a folder where a file was.
func makeFolderAt(t *testing.T, path string) {
	t.Helper()
	removeFile(t, path)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("making a folder at %s: %v", path, err)
	}
}

// folderCases are the folder line's cases, each a folder made broken; the six kinds the line
// names (the folder missing or unreadable, each file missing or unreadable) come first in each
// name, for the row that compares their reasons.
func folderCases() map[string]func(t *testing.T) *bootstrapFolder {
	return map[string]func(t *testing.T) *bootstrapFolder{
		"the folder missing": func(t *testing.T) *bootstrapFolder {
			t.Helper()
			made := goodFolder(t)
			made.path += "-missing"
			return made
		},
		"the folder unreadable, no one may open it": func(t *testing.T) *bootstrapFolder {
			t.Helper()
			made := goodFolder(t)
			makeUnopenable(t, made.path)
			return made
		},
		"the folder unreadable, a regular file in its place": func(t *testing.T) *bootstrapFolder {
			t.Helper()
			made := goodFolder(t)
			path := made.path + "-file"
			if err := os.WriteFile(path, []byte("not a folder"), 0o600); err != nil {
				t.Fatalf("writing the file: %v", err)
			}
			made.path = path
			return made
		},
		"the bootstrap file missing": func(t *testing.T) *bootstrapFolder {
			t.Helper()
			made := goodFolder(t)
			removeFile(t, made.file)
			return made
		},
		"the bootstrap file unreadable, no one may open it": func(t *testing.T) *bootstrapFolder {
			t.Helper()
			made := goodFolder(t)
			makeUnopenable(t, made.file)
			return made
		},
		"the bootstrap file unreadable, a folder in its place": func(t *testing.T) *bootstrapFolder {
			t.Helper()
			made := goodFolder(t)
			makeFolderAt(t, made.file)
			return made
		},
		"the bootstrap file unreadable, " + linkKinds + " to a good one outside": func(t *testing.T) *bootstrapFolder {
			t.Helper()
			made := goodFolder(t)
			sealed, err := os.ReadFile(made.file)
			if err != nil {
				t.Fatalf("reading the bootstrap file: %v", err)
			}
			removeFile(t, made.file)
			linkOutside(t, made.file, sealed)
			return made
		},
		"the key file missing": func(t *testing.T) *bootstrapFolder {
			t.Helper()
			made := goodFolder(t)
			removeFile(t, made.keyFile)
			return made
		},
		"the key file unreadable, no one may open it": func(t *testing.T) *bootstrapFolder {
			t.Helper()
			made := goodFolder(t)
			makeUnopenable(t, made.keyFile)
			return made
		},
		"the key file unreadable, a folder in its place": func(t *testing.T) *bootstrapFolder {
			t.Helper()
			made := goodFolder(t)
			makeFolderAt(t, made.keyFile)
			return made
		},
		"the key file unreadable, " + linkKinds + " to a good one outside": func(t *testing.T) *bootstrapFolder {
			t.Helper()
			made := goodFolder(t)
			removeFile(t, made.keyFile)
			linkOutside(t, made.keyFile, []byte(made.keyText))
			return made
		},
	}
}

func TestBootstrapProgram(t *testing.T) {
	t.Parallel()

	t.Run("If the bootstrap folder is missing or unreadable, the bootstrap file in it is missing, unreadable or a link leading out of the bootstrap folder, or, when the bootstrap file's key holder is the key file, the key file is, then the engine shall write one `start_failed` line saying which, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		for name, build := range folderCases() {
			t.Run(name+": one start_failed line, and a non-zero exit", func(t *testing.T) {
				t.Parallel()
				reason := build(t).refused(t)
				if strings.HasPrefix(name, "the key file") {
					expectOwnReason(t, reason, fileMissingReason(t), "a missing bootstrap file")
				} else {
					expectOwnReason(t, reason, keyMissingReason(t), "a missing key file")
				}
			})
		}
		t.Run("the folder missing, the folder unreadable, each file missing, each file unreadable: six reasons, each its own and none the reason for no folder named", func(t *testing.T) {
			t.Parallel()
			cases := folderCases()
			reasons := map[string]string{noFileKey: noFileReason(t)}
			for _, name := range []string{"the folder missing", "the folder unreadable, no one may open it",
				"the bootstrap file missing", "the bootstrap file unreadable, no one may open it",
				"the key file missing", "the key file unreadable, no one may open it"} {
				reasons[name] = cases[name](t).refused(t)
			}
			expectDifferent(t, reasons)
		})
	})

	t.Run("If the bootstrap file is over 64 KiB, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("65,537 bytes, a good file one byte over: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			made := paddedFolder(t, bootstrapMost+1)
			expectOwnReason(t, made.refused(t), keyMissingReason(t), "a missing key file")
		})
		t.Run("exactly 65,536 bytes, its settings padded with spaces: it starts", func(t *testing.T) {
			t.Parallel()
			paddedFolder(t, bootstrapMost).starts(t)
		})
	})

	t.Run("If the bootstrap file's key holder is the key file and the key file is not in the key file's form, or holds a key of 32 zero bytes, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		for name, build := range malformedKeys {
			t.Run(name+": one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) {
				t.Parallel()
				made := goodFolder(t)
				made.writeKey(t, build(made.keyBase()))
				expectOwnReason(t, made.refused(t), keyMissingReason(t), "a missing key file")
			})
		}
		t.Run("the key of 32 zero bytes, the bootstrap file sealed under it by the oracle: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			zero := base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
			made := goodFolder(t)
			made.key, made.keyText = make([]byte, 32), zero
			made.writeFile(t, sealBootstrap(t, zero, made.plaintext, ""))
			made.writeKey(t, zero)
			expectOwnReason(t, made.refused(t), keyMissingReason(t), "a missing key file")
		})
		for name, ending := range map[string]string{"no line ending": "", "a line feed": "\n", "a carriage return and line feed": "\r\n"} {
			t.Run("the key with "+name+": it starts", func(t *testing.T) {
				t.Parallel()
				made := goodFolder(t)
				made.writeKey(t, made.keyBase()+ending)
				made.starts(t)
			})
		}
	})

	t.Run("If the bootstrap file's header is not format version 1's for the key file or, on Windows, for the TPM or the software key store, or the bootstrap file is too short for its header, nonce and tag, then the engine shall write one `start_failed` line saying so, without reading the key file or asking a key store, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		for name, edits := range headerEdits {
			t.Run(name+", alone, with the key file missing, unreadable and open to others: the same reason each time, not a missing key file's", func(t *testing.T) {
				t.Parallel()
				reason := brokenFolder(t, edits).refused(t)
				expectOwnReason(t, reason, keyMissingReason(t), "a missing key file")
				for kind, spoil := range map[string]func(t *testing.T, path string){
					"missing":        removeFile,
					"unreadable":     makeUnopenable,
					"open to others": openToOthers,
				} {
					made := brokenFolder(t, edits)
					spoil(t, made.keyFile)
					if got := made.refused(t); got != reason {
						t.Fatalf("with the key file %s the reason was %q, not the header's %q: the key file was read", kind, got, reason)
					}
				}
			})
		}
		t.Run("41 bytes, a header, nonce and tag with nothing sealed: past the header, refused as a file that does not unseal", func(t *testing.T) {
			t.Parallel()
			reason := brokenFolder(t, "truncate 41").refused(t)
			wrongKey := goodFolder(t)
			_, other := newBootstrapKey(t)
			wrongKey.writeFile(t, sealBootstrap(t, other, wrongKey.plaintext, ""))
			if unseal := wrongKey.refused(t); reason != unseal {
				t.Fatalf("41 bytes gave %q, not the reason for a file that does not unseal, %q", reason, unseal)
			}
			expectOwnReason(t, reason, brokenFolder(t, headerEdits["a wrong magic"]).refused(t), "a wrong magic")
		})
	})

	t.Run("If the bootstrap file does not unseal under the key its key holder gives, then the engine shall write one `start_failed` line saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("a good file under another key: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			made := goodFolder(t)
			_, other := newBootstrapKey(t)
			made.writeFile(t, sealBootstrap(t, other, made.plaintext, ""))
			expectOwnReason(t, made.refused(t), keyMissingReason(t), "a missing key file")
		})
		for name, edits := range map[string]string{
			"a byte of the nonce changed": "flip 14",
			"a sealed byte changed":       "flip 60",
			"a byte added after the tag":  "append hex:00",
		} {
			t.Run(name+": one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) {
				t.Parallel()
				expectOwnReason(t, brokenFolder(t, edits).refused(t), keyMissingReason(t), "a missing key file")
			})
		}
		t.Run("the tag's last byte changed: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			made := goodFolder(t)
			sealed, err := os.ReadFile(made.file)
			if err != nil {
				t.Fatalf("reading the bootstrap file: %v", err)
			}
			sealed[len(sealed)-1] ^= 1
			made.writeFile(t, sealed)
			expectOwnReason(t, made.refused(t), keyMissingReason(t), "a missing key file")
		})
	})

	t.Run("If a command-line option is malformed, or the engine fails to listen at both addresses for Telnet or, when SSH or Telnet over TLS is on, for that kind, then the engine shall write one `start_failed` line to the local log saying why, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("the old -database and a connection file, beside a good bootstrap folder: one start_failed line, a reason of its own, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			settings := sharedRowSettings(t)
			old := filepath.Join(t.TempDir(), "connection.json")
			if err := os.WriteFile(old, []byte(settings.text(t)), 0o600); err != nil {
				t.Fatalf("writing the old connection file: %v", err)
			}
			program := startWithFile(t, settings.write(t), nil, portOption, "0", "-database", old)
			reason := program.expectRefusal(t)
			expectNoPassword(t, program)
			expectOwnReason(t, reason, keyMissingReason(t), "a missing key file")
		})
	})
}

// paddedFolder makes a good bootstrap folder for a row of its own on the shared board, its
// settings padded with spaces so the bootstrap file is exactly size bytes.
func paddedFolder(t *testing.T, size int) *bootstrapFolder {
	t.Helper()
	text := sharedRowSettings(t).text(t)
	plain := size - sealedOverhead
	if len(text) > plain {
		t.Fatalf("the settings are %d bytes, more than %d: a fault in the test", len(text), plain)
	}
	made := makeBootstrapFolder(t, []byte(text[:len(text)-1]+strings.Repeat(" ", plain-len(text))+"}"), "")
	if info, err := os.Stat(made.file); err != nil || info.Size() != int64(size) {
		t.Fatalf("the oracle's file is not %d bytes: a fault in the test (%v)", size, err)
	}
	return made
}
