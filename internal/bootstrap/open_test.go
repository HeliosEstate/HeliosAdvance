// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Open's lines that hold on every system: the folder, the bootstrap file, its size and header,
// the key file's presence and form, the unseal, the order of the checks, and what an error may
// hold. Every bootstrap file is the oracle's; every key file is written by the test's own encoder.
// The lines that differ by system are in the files named for each.
package bootstrap_test

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/bootstrap"
)

// headerEdits are the oracle's broken headers, each one Open refuses with ErrHeader: the README's
// list of the files the page's lines need, status 3.
var headerEdits = map[string]string{
	"a wrong magic":                                `magic "HADVBOOX"`,
	"format version 0":                             "version 0",
	"format version 2":                             "version 2",
	"key holder 0":                                 "holder 0",
	"key holder 2":                                 "holder 2",
	"key holder 2 with a sealed key":               "holder 2\nsealed random:100",
	"a sealed key under the key file":              "sealed hex:00",
	"a sealed-key length of 1 that lies":           "sealed-length 1",
	"10 bytes, shorter than the header's start":    "truncate 10",
	"40 bytes, one short of header, nonce and tag": "truncate 40",
}

// keyText is a key file's text built from base, the 44 characters of a good one.
type keyText func(base string) string

// malformedKeys are key files not in the key file's form, each built from a good key's 44
// characters.
var malformedKeys = map[string]keyText{
	"43 characters, the last before the padding dropped": func(base string) string { return base[:42] + "=" },
	"45 characters, an A added before the padding":       func(base string) string { return base[:43] + "A=" },
	"no padding, the 43 characters alone":                func(base string) string { return base[:43] },
	"two padding characters, decoding to 31 bytes":       func(base string) string { return base[:42] + "==" },
	"a - from the URL-safe alphabet as its first character": func(base string) string {
		return "-" + base[1:]
	},
	"a leading space":                           func(base string) string { return " " + base },
	"a bit set after the last byte":             withTrailingBit,
	"two line feeds":                            func(base string) string { return base + "\n\n" },
	"a bare carriage return":                    func(base string) string { return base + "\r" },
	"47 bytes, a CR LF then a line feed":        func(base string) string { return base + "\r\n\n" },
	"a 1 MiB key file, the key then line feeds": func(base string) string { return base + strings.Repeat("\n", 1<<20) },
}

// withTrailingBit sets the lowest of the bits after the key's last byte: the 43rd character
// carries 4 bits of the last byte and 2 that must be zero.
func withTrailingBit(base string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	index := strings.IndexByte(alphabet, base[42])
	return base[:42] + string(alphabet[index|1]) + "="
}

// baseOf is a good key file's 44 characters, without its line ending.
func baseOf(made *layout) string {
	return strings.TrimRight(made.keyText, "\r\n")
}

func TestOpen(t *testing.T) {
	t.Parallel()

	t.Run("If the bootstrap folder does not exist, then Open shall return ErrFolderMissing.", func(t *testing.T) {
		t.Parallel()
		t.Run("a folder that is not there: ErrFolderMissing", func(t *testing.T) {
			t.Parallel()
			contents, err := open(t, filepath.Join(t.TempDir(), "bootstrap"))
			expectError(t, contents, err, bootstrap.ErrFolderMissing)
		})
		t.Run("a folder whose parent is not there either: ErrFolderMissing", func(t *testing.T) {
			t.Parallel()
			contents, err := open(t, filepath.Join(t.TempDir(), "gone", "bootstrap"))
			expectError(t, contents, err, bootstrap.ErrFolderMissing)
		})
	})

	t.Run("If the bootstrap folder exists but will not open, then Open shall return ErrFolderUnreadable.", func(t *testing.T) {
		t.Parallel()
		t.Run("a good folder no one may open: ErrFolderUnreadable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			makeUnopenable(t, made.folder)
			made.expectRefused(t, bootstrap.ErrFolderUnreadable)
		})
		t.Run("a regular file where the folder should be: ErrFolderUnreadable", func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "bootstrap")
			if err := os.WriteFile(path, []byte("not a folder"), 0o600); err != nil {
				t.Fatalf("writing the file: %v", err)
			}
			contents, err := open(t, path)
			expectError(t, contents, err, bootstrap.ErrFolderUnreadable)
		})
	})

	t.Run("If the bootstrap folder holds no bootstrap file, then Open shall return ErrFileMissing.", func(t *testing.T) {
		t.Parallel()
		t.Run("a good key file alone: ErrFileMissing", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			remove(t, made.file)
			made.expectRefused(t, bootstrap.ErrFileMissing)
		})
	})

	t.Run("If the bootstrap file will not open or read, is not a regular file, or is a link leading out of the bootstrap folder, then Open shall return ErrFileUnreadable.", func(t *testing.T) {
		t.Parallel()
		t.Run("a good bootstrap file no one may open: ErrFileUnreadable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			makeUnopenable(t, made.file)
			made.expectRefused(t, bootstrap.ErrFileUnreadable)
		})
		t.Run("a folder where the bootstrap file should be: ErrFileUnreadable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			remove(t, made.file)
			if err := os.Mkdir(made.file, 0o700); err != nil {
				t.Fatalf("making the folder: %v", err)
			}
			made.expectRefused(t, bootstrap.ErrFileUnreadable)
		})
		t.Run(linkKinds+" to a good bootstrap file outside the folder: ErrFileUnreadable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			sealed := made.sealed
			remove(t, made.file)
			linkOutside(t, made.file, sealed)
			made.expectRefused(t, bootstrap.ErrFileUnreadable)
		})
	})

	t.Run("If the bootstrap file is longer than FileMostBytes, then Open shall return ErrFileTooLarge, having read at most FileMostBytes and one byte more of it.", func(t *testing.T) {
		t.Parallel()
		t.Run("65,537 bytes, a good file one byte over: ErrFileTooLarge", func(t *testing.T) {
			t.Parallel()
			made := makeFolderWith(t, plaintextOf(t, fileMostBytes+1-sealedOverhead), "")
			expectSize(t, made, fileMostBytes+1)
			made.expectRefused(t, bootstrap.ErrFileTooLarge)
		})
		t.Run("1 MiB, a good file with zeros after it: ErrFileTooLarge", func(t *testing.T) {
			t.Parallel()
			// The oracle's zeros stop at 262,144 bytes, so the test adds them.
			made := makeFolder(t)
			made.writeFile(t, append(made.sealed, make([]byte, 1<<20-len(made.sealed))...))
			expectSize(t, made, 1<<20)
			made.expectRefused(t, bootstrap.ErrFileTooLarge)
		})
		t.Run("exactly 65,536 bytes, its plaintext padded with spaces: opens, the plaintext exact", func(t *testing.T) {
			t.Parallel()
			made := makeFolderWith(t, plaintextOf(t, fileMostBytes-sealedOverhead), "")
			expectSize(t, made, fileMostBytes)
			made.expectOpened(t)
		})
	})

	t.Run("If the bootstrap file is shorter than HeaderBytes, NonceBytes and TagBytes together, or its first HeaderBytes are not Magic, FormatVersion, KeyHolderKeyFile and a sealed-key length of 0, then Open shall return ErrHeader before it opens the key file.", func(t *testing.T) {
		t.Parallel()
		for name, edits := range headerEdits {
			t.Run(name+": ErrHeader", func(t *testing.T) {
				t.Parallel()
				made := makeFolderWith(t, plaintextOf(t, 64), edits)
				made.expectRefused(t, bootstrap.ErrHeader)
			})
			t.Run(name+", the key file missing: ErrHeader", func(t *testing.T) {
				t.Parallel()
				made := makeFolderWith(t, plaintextOf(t, 64), edits)
				remove(t, made.keyFile)
				made.expectRefused(t, bootstrap.ErrHeader)
			})
			t.Run(name+", the key file no one may open: ErrHeader", func(t *testing.T) {
				t.Parallel()
				made := makeFolderWith(t, plaintextOf(t, 64), edits)
				makeUnopenable(t, made.keyFile)
				made.expectRefused(t, bootstrap.ErrHeader)
			})
			t.Run(name+", the key file open to others: ErrHeader", func(t *testing.T) {
				t.Parallel()
				made := makeFolderWith(t, plaintextOf(t, 64), edits)
				openToOthers(t, made.keyFile)
				made.expectRefused(t, bootstrap.ErrHeader)
			})
		}
		t.Run("41 bytes, a header, nonce and tag with nothing sealed: past the header, ErrUnseal", func(t *testing.T) {
			t.Parallel()
			made := makeFolderWith(t, plaintextOf(t, 64), "truncate 41")
			expectSize(t, made, sealedOverhead)
			made.expectRefused(t, bootstrap.ErrUnseal)
		})
	})

	t.Run("If the bootstrap folder holds no key file, then Open shall return ErrKeyFileMissing.", func(t *testing.T) {
		t.Parallel()
		t.Run("a good bootstrap file alone: ErrKeyFileMissing", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			remove(t, made.keyFile)
			made.expectRefused(t, bootstrap.ErrKeyFileMissing)
		})
	})

	t.Run("If the key file will not open, is not a regular file, or is a link leading out of the bootstrap folder, then Open shall return ErrKeyFileUnreadable.", func(t *testing.T) {
		t.Parallel()
		t.Run("a good key file no one may open: ErrKeyFileUnreadable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			makeUnopenable(t, made.keyFile)
			made.expectRefused(t, bootstrap.ErrKeyFileUnreadable)
		})
		t.Run("a folder where the key file should be: ErrKeyFileUnreadable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			remove(t, made.keyFile)
			if err := os.Mkdir(made.keyFile, 0o700); err != nil {
				t.Fatalf("making the folder: %v", err)
			}
			made.expectRefused(t, bootstrap.ErrKeyFileUnreadable)
		})
		t.Run(linkKinds+" to a good key file outside the folder: ErrKeyFileUnreadable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			remove(t, made.keyFile)
			linkOutside(t, made.keyFile, []byte(made.keyText))
			made.expectRefused(t, bootstrap.ErrKeyFileUnreadable)
		})
	})

	t.Run("If the key file is longer than KeyFileMostBytes, is not in the form the package comment gives, or holds a key of 32 zero bytes, then Open shall return ErrKeyFileForm, having read at most KeyFileMostBytes and one byte more of it.", func(t *testing.T) {
		t.Parallel()
		for name, build := range malformedKeys {
			t.Run(name+": ErrKeyFileForm", func(t *testing.T) {
				t.Parallel()
				made := makeFolder(t)
				made.writeKey(t, build(baseOf(made)))
				made.expectRefused(t, bootstrap.ErrKeyFileForm)
			})
		}
		t.Run("the key of 32 zero bytes, the bootstrap file sealed under it by the oracle: ErrKeyFileForm", func(t *testing.T) {
			t.Parallel()
			zero := base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
			made := makeFolder(t)
			made.key, made.keyText = make([]byte, 32), zero
			made.writeFile(t, seal(t, zero, made.plaintext, ""))
			made.writeKey(t, zero)
			made.expectRefused(t, bootstrap.ErrKeyFileForm)
		})
		for name, ending := range map[string]string{"no line ending": "", "a line feed": "\n", "a carriage return and line feed": "\r\n"} {
			t.Run("the key with "+name+": opens, the plaintext exact", func(t *testing.T) {
				t.Parallel()
				made := makeFolder(t)
				made.writeKey(t, baseOf(made)+ending)
				made.expectOpened(t)
			})
		}
		t.Run("a key written from RFC 4648's vectors, Zm9vYmFy five times and Zm8=: opens, the plaintext exact", func(t *testing.T) {
			t.Parallel()
			text := strings.Repeat("Zm9vYmFy", 5) + "Zm8=\n"
			made := makeFolder(t)
			made.key, made.keyText = []byte(strings.Repeat("foobar", 5)+"fo"), text
			made.writeFile(t, seal(t, text, made.plaintext, ""))
			made.writeKey(t, text)
			made.expectOpened(t)
		})
	})

	t.Run("If the bootstrap file's tag does not verify under the key, then Open shall return ErrUnseal and no bytes.", func(t *testing.T) {
		t.Parallel()
		t.Run("a good file under another key: ErrUnseal, no bytes", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			_, other := newKey(t)
			made.writeFile(t, seal(t, other, made.plaintext, ""))
			made.expectRefused(t, bootstrap.ErrUnseal)
		})
		for name, edits := range map[string]string{
			"a byte of the nonce changed": "flip 14",
			"a sealed byte changed":       "flip 60",
			"the tag's last byte changed": "flip " + strconv.Itoa(64+sealedOverhead-1),
			"a byte added after the tag":  "append hex:00",
		} {
			t.Run(name+": ErrUnseal, no bytes", func(t *testing.T) {
				t.Parallel()
				made := makeFolderWith(t, plaintextOf(t, 64), edits)
				made.expectRefused(t, bootstrap.ErrUnseal)
			})
		}
	})

	t.Run("Open shall check in the order of these lines and return the first refusal that applies.", func(t *testing.T) {
		t.Parallel()
		t.Run("nothing to refuse: the sealed plaintext, exact", func(t *testing.T) {
			t.Parallel()
			makeFolder(t).expectOpened(t)
		})
		t.Run("the bootstrap file and the key file both missing: ErrFileMissing", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			remove(t, made.file)
			remove(t, made.keyFile)
			made.expectRefused(t, bootstrap.ErrFileMissing)
		})
		t.Run("the bootstrap file no one may open and the key file missing: ErrFileUnreadable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			remove(t, made.keyFile)
			makeUnopenable(t, made.file)
			made.expectRefused(t, bootstrap.ErrFileUnreadable)
		})
		t.Run("65,537 bytes with a wrong magic: ErrFileTooLarge", func(t *testing.T) {
			t.Parallel()
			made := makeFolderWith(t, plaintextOf(t, fileMostBytes+1-sealedOverhead), `magic "HADVBOOX"`)
			made.expectRefused(t, bootstrap.ErrFileTooLarge)
		})
		t.Run("the key file missing and a tag that does not verify: ErrKeyFileMissing", func(t *testing.T) {
			t.Parallel()
			made := makeFolderWith(t, plaintextOf(t, 64), "flip 60")
			remove(t, made.keyFile)
			made.expectRefused(t, bootstrap.ErrKeyFileMissing)
		})
		t.Run("the key file no one may open and out of form: ErrKeyFileUnreadable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			made.writeKey(t, baseOf(made)[:43])
			makeUnopenable(t, made.keyFile)
			made.expectRefused(t, bootstrap.ErrKeyFileUnreadable)
		})
		t.Run("the key file open to others and out of form: ErrKeyFileReachable", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			made.writeKey(t, baseOf(made)[:43])
			openToOthers(t, made.keyFile)
			made.expectRefused(t, bootstrap.ErrKeyFileReachable)
		})
		t.Run("the key file out of form and a tag that does not verify: ErrKeyFileForm", func(t *testing.T) {
			t.Parallel()
			made := makeFolderWith(t, plaintextOf(t, 64), "flip 60")
			made.writeKey(t, baseOf(made)[:43])
			made.expectRefused(t, bootstrap.ErrKeyFileForm)
		})
	})

	t.Run("No error the bootstrap package returns shall hold, in its text, the key or any part of either file's contents.", func(t *testing.T) {
		t.Parallel()
		// Every refusal row above checks its error's text the same way; these rows put the
		// secrets where a careless error would quote them.
		t.Run("a key file out of form by one character: ErrKeyFileForm, the key's text not in the error", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			made.writeKey(t, "!"+baseOf(made)[1:])
			made.expectRefused(t, bootstrap.ErrKeyFileForm)
		})
		t.Run("a wrong magic before the canary: ErrHeader, no byte after the magic in the error", func(t *testing.T) {
			t.Parallel()
			made := makeFolderWith(t, plaintextOf(t, 64), `magic "HADVBOOX"`)
			made.expectRefused(t, bootstrap.ErrHeader)
		})
		t.Run("the canary under another key: ErrUnseal, neither key nor canary in the error", func(t *testing.T) {
			t.Parallel()
			made := makeFolder(t)
			_, other := newKey(t)
			made.writeFile(t, seal(t, other, made.plaintext, ""))
			made.expectRefused(t, bootstrap.ErrUnseal)
		})
	})
}

// expectSize fails the row when the oracle's file is not the size the row is about.
func expectSize(t *testing.T, made *layout, size int) {
	t.Helper()
	if len(made.sealed) != size {
		t.Fatalf("the oracle's file is %d bytes, not %d: a fault in the test", len(made.sealed), size)
	}
}
