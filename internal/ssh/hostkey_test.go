// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Reading the host key file: each refusal on a file made for it, by ssh-keygen where it can make
// one and by the test in the openssh-key-v1 format where a size must be exact, and that
// no refusal's text holds any part of the file.
package ssh_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/ssh"
)

// hostKeyMostBytes is the contract's bound on the file, as its line states it.
const hostKeyMostBytes = 16384

// canary marks text a refusal must never repeat.
const canary = "helios-canary-7319"

// writeFile writes contents to a new file in a folder of the row's own, mode 0600.
func writeFile(t *testing.T, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "host_key")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return contents
}

// openSSHKey builds an unencrypted Ed25519 key in the openssh-key-v1 format (the magic, the
// cipher and KDF none, one public key, and the private section padded 1, 2, 3 … to a multiple
// of 8), with the comment given, as PEM wrapped at width characters a line.
func openSSHKey(comment string, width int) []byte {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	publicBlob := (&wire{}).text("ssh-ed25519").bytesValue(public).data
	section := (&wire{}).uint32Value(0x01020304).uint32Value(0x01020304).
		text("ssh-ed25519").bytesValue(public).bytesValue(private).text(comment).data
	for pad := byte(1); len(section)%8 != 0; pad++ {
		section = append(section, pad)
	}
	blob := append([]byte("openssh-key-v1\x00"), (&wire{}).text("none").text("none").text("").
		uint32Value(1).bytesValue(publicBlob).bytesValue(section).data...)
	encoded := base64.StdEncoding.EncodeToString(blob)
	var out bytes.Buffer
	out.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n")
	for len(encoded) > width {
		out.WriteString(encoded[:width] + "\n")
		encoded = encoded[width:]
	}
	out.WriteString(encoded + "\n")
	out.WriteString("-----END OPENSSH PRIVATE KEY-----\n")
	return out.Bytes()
}

// sizedKey finds a comment length and a line width that make the key file exactly size bytes.
// The size depends only on the lengths, so each trial key's size is the real one's.
func sizedKey(t *testing.T, size int) []byte {
	t.Helper()
	// The comment is about three quarters of the file once base64 has grown it by a third.
	for commentLength := size*3/4 - 600; commentLength < size; commentLength++ {
		smallest := size + 1
		for width := 60; width <= 76; width++ {
			contents := openSSHKey(strings.Repeat("c", commentLength), width)
			if len(contents) == size {
				return contents
			}
			smallest = min(smallest, len(contents))
		}
		if smallest > size {
			break
		}
	}
	t.Fatalf("no comment length and line width give a key file of %d bytes", size)
	return nil
}

// pemBody is the base64 text between a PEM file's armour lines, joined.
func pemBody(contents []byte) string {
	var body strings.Builder
	for _, line := range strings.Split(string(contents), "\n") {
		if !strings.HasPrefix(line, "-----") {
			body.WriteString(strings.TrimSpace(line))
		}
	}
	return body.String()
}

// holdsPartOf is whether text holds any 8 characters in a row of part.
func holdsPartOf(text, part string) bool {
	for start := 0; start+8 <= len(part); start++ {
		if strings.Contains(text, part[start:start+8]) {
			return true
		}
	}
	return false
}

func expectRefusal(t *testing.T, path string, want error) error {
	t.Helper()
	key, err := ssh.ReadHostKey(path)
	if !errors.Is(err, want) || key != nil {
		t.Fatalf("ReadHostKey gave %v and %v, want %v and no key", key, err, want)
	}
	return err
}

func TestReadHostKey(t *testing.T) {
	t.Parallel()

	t.Run("ReadHostKey shall check the file in the order of these lines and return the first refusal that applies.", func(t *testing.T) {
		t.Parallel()
		t.Run("an RSA key in OpenSSH's format, protected by a passphrase: the passphrase, before the key's type", func(t *testing.T) {
			t.Parallel()
			_ = expectRefusal(t, makeKey(t, "rsa", "secret", "-b", "2048"), ssh.ErrHostKeyPassphrase)
		})
		t.Run("an ECDSA key protected by a passphrase: the passphrase, before the key's type", func(t *testing.T) {
			t.Parallel()
			_ = expectRefusal(t, makeKey(t, "ecdsa", "secret"), ssh.ErrHostKeyPassphrase)
		})
		t.Run("an RSA key in the RSA PRIVATE KEY format: not OpenSSH's, before the key's type", func(t *testing.T) {
			t.Parallel()
			_ = expectRefusal(t, makeKey(t, "rsa", "", "-b", "2048", "-m", "PEM"), ssh.ErrHostKeyNotOpenSSH)
		})
		t.Run("an RSA key of 16385 bytes in OpenSSH's format: too long, before the key's type", func(t *testing.T) {
			t.Parallel()
			contents := readFile(t, makeKey(t, "rsa", "", "-b", "2048"))
			padded := append(bytes.Clone(contents), bytes.Repeat([]byte("\n"), hostKeyMostBytes+1-len(contents))...)
			_ = expectRefusal(t, writeFile(t, padded), ssh.ErrHostKeyNotOpenSSH)
		})
	})

	t.Run("If no file is at path, then ReadHostKey shall return ErrHostKeyMissing.", func(t *testing.T) {
		t.Parallel()
		t.Run("a path in an empty folder", func(t *testing.T) {
			t.Parallel()
			_ = expectRefusal(t, filepath.Join(t.TempDir(), "host_key"), ssh.ErrHostKeyMissing)
		})
		t.Run("a path whose folder does not exist", func(t *testing.T) {
			t.Parallel()
			_ = expectRefusal(t, filepath.Join(t.TempDir(), "absent", "host_key"), ssh.ErrHostKeyMissing)
		})
	})

	t.Run("If the file cannot be read, then ReadHostKey shall return ErrHostKeyUnreadable.", func(t *testing.T) {
		t.Parallel()
		t.Run("a key file the engine cannot read", func(t *testing.T) {
			t.Parallel()
			path := makeKey(t, "ed25519", "")
			keepFromReading(t, path)
			_ = expectRefusal(t, path, ssh.ErrHostKeyUnreadable)
		})
	})

	t.Run("If the file is longer than HostKeyMostBytes, or is not one PEM block of type \"OPENSSH PRIVATE KEY\", then ReadHostKey shall return ErrHostKeyNotOpenSSH.", func(t *testing.T) {
		t.Parallel()
		pkcs8 := func(t *testing.T) []byte {
			t.Helper()
			_, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			der, err := x509.MarshalPKCS8PrivateKey(private)
			if err != nil {
				t.Fatal(err)
			}
			return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		}
		rows := []struct {
			name     string
			contents func(t *testing.T) []byte
		}{
			{"an empty file", func(*testing.T) []byte { return nil }},
			{"a line of text", func(*testing.T) []byte { return []byte(canary + " is not a key\n") }},
			{"the public key file ssh-keygen wrote beside the key", func(t *testing.T) []byte {
				t.Helper()
				return readFile(t, makeKey(t, "ed25519", "")+".pub")
			}},
			{"an Ed25519 key as PKCS#8, PRIVATE KEY", pkcs8},
			{"two OPENSSH PRIVATE KEY blocks", func(t *testing.T) []byte {
				t.Helper()
				return append(readFile(t, makeKey(t, "ed25519", "")), readFile(t, makeKey(t, "ed25519", ""))...)
			}},
			{"an Ed25519 key followed by a line of text", func(t *testing.T) []byte {
				t.Helper()
				return append(readFile(t, makeKey(t, "ed25519", "")), []byte(canary+"\n")...)
			}},
			{"an Ed25519 key of 16385 bytes", func(t *testing.T) []byte {
				t.Helper()
				return sizedKey(t, hostKeyMostBytes+1)
			}},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				_ = expectRefusal(t, writeFile(t, row.contents(t)), ssh.ErrHostKeyNotOpenSSH)
			})
		}
		t.Run("the edge just inside: an Ed25519 key of exactly 16384 bytes is read", func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, sizedKey(t, hostKeyMostBytes))
			if key, err := ssh.ReadHostKey(path); err != nil || key == nil {
				t.Fatalf("ReadHostKey gave %v and %v, want a key", key, err)
			}
		})
	})

	t.Run("If the key is protected by a passphrase, then ReadHostKey shall return ErrHostKeyPassphrase.", func(t *testing.T) {
		t.Parallel()
		t.Run("an Ed25519 key ssh-keygen protected with a passphrase", func(t *testing.T) {
			t.Parallel()
			_ = expectRefusal(t, makeKey(t, "ed25519", "secret"), ssh.ErrHostKeyPassphrase)
		})
	})

	t.Run("If the key is not an Ed25519 key, then ReadHostKey shall return ErrHostKeyNotEd25519.", func(t *testing.T) {
		t.Parallel()
		for _, row := range []struct{ name, keyType string }{
			{"an ECDSA key in OpenSSH's format", "ecdsa"},
			{"an RSA key in OpenSSH's format", "rsa"},
		} {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				_ = expectRefusal(t, makeKey(t, row.keyType, ""), ssh.ErrHostKeyNotEd25519)
			})
		}
		t.Run("the edge: an Ed25519 key ssh-keygen made is read", func(t *testing.T) {
			t.Parallel()
			if key, err := ssh.ReadHostKey(makeKey(t, "ed25519", "")); err != nil || key == nil {
				t.Fatalf("ReadHostKey gave %v and %v, want a key", key, err)
			}
		})
	})

	t.Run("ReadHostKey shall return an error whose text holds no part of the file's contents.", func(t *testing.T) {
		t.Parallel()
		rows := []struct {
			name string
			path func(t *testing.T) string
			want error
			// part is what the error must not repeat: the key's base64 body, or the canary.
			part func(contents []byte) string
		}{
			{"a line of text holding the canary", func(t *testing.T) string {
				t.Helper()

				return writeFile(t, []byte(canary+" "+canary+"\n"))
			}, ssh.ErrHostKeyNotOpenSSH, func([]byte) string { return canary }},
			{"an RSA PRIVATE KEY", func(t *testing.T) string {
				t.Helper()

				return makeKey(t, "rsa", "", "-b", "2048", "-m", "PEM")
			}, ssh.ErrHostKeyNotOpenSSH, func(contents []byte) string { return pemBody(contents) }},
			{"an Ed25519 key followed by the canary", func(t *testing.T) string {
				t.Helper()

				return writeFile(t, append(readFile(t, makeKey(t, "ed25519", "")), []byte(canary+"\n")...))
			}, ssh.ErrHostKeyNotOpenSSH, func(contents []byte) string { return pemBody(contents) }},
			{"a passphrase-protected key", func(t *testing.T) string {
				t.Helper()

				return makeKey(t, "ed25519", "secret")
			}, ssh.ErrHostKeyPassphrase, func(contents []byte) string { return pemBody(contents) }},
			{"an ECDSA key whose comment is the canary", func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "host_key")
				makeKeyAt(t, path, "ecdsa", "", "-C", canary)
				return path
			}, ssh.ErrHostKeyNotEd25519, func(contents []byte) string { return pemBody(contents) + canary }},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				path := row.path(t)
				err := expectRefusal(t, path, row.want)
				if part := row.part(readFile(t, path)); holdsPartOf(err.Error(), part) {
					t.Fatalf("the error %q holds part of the file", err)
				}
			})
		}
	})
}

// withMode is an Ed25519 key ssh-keygen made, or another type, set to mode.
func withMode(t *testing.T, keyType string, mode os.FileMode) string {
	t.Helper()
	path := makeKey(t, keyType, "")
	setMode(t, path, mode)
	return path
}

// setMode gives a file the mode its row is about, one its group or others may read among them.
func setMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("setting %s to %#o: %v", path, mode, err)
	}
}

// TestLinuxReadHostKey is Linux's alone because the mode check is: the page cut it to Linux.
func TestLinuxReadHostKey(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Fatalf("these rows need an ordinary user: root reads a file of any mode")
	}

	t.Run("If, on Linux, the file's mode lets its group or others read it, then ReadHostKey shall return ErrHostKeyReadableByOthers without reading the file.", func(t *testing.T) {
		t.Parallel()
		for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o444, 0o660, 0o606} {
			t.Run(fmtMode("an Ed25519 key of mode", mode, "is refused"), func(t *testing.T) {
				t.Parallel()
				_ = expectRefusal(t, withMode(t, "ed25519", mode), ssh.ErrHostKeyReadableByOthers)
			})
		}
		for _, mode := range []os.FileMode{0o600, 0o400, 0o620, 0o602, 0o700} {
			t.Run(fmtMode("the edge: an Ed25519 key of mode", mode, "is read"), func(t *testing.T) {
				t.Parallel()
				if key, err := ssh.ReadHostKey(withMode(t, "ed25519", mode)); err != nil || key == nil {
					t.Fatalf("ReadHostKey gave %v and %v, want a key", key, err)
				}
			})
		}
		t.Run("mode 0004, which others may read and its owner may not: refused for its mode, without reading it", func(t *testing.T) {
			t.Parallel()
			_ = expectRefusal(t, withMode(t, "ed25519", 0o004), ssh.ErrHostKeyReadableByOthers)
		})
	})

	t.Run("ReadHostKey shall check the file in the order of these lines and return the first refusal that applies.", func(t *testing.T) {
		t.Parallel()
		t.Run("an RSA key of mode 0644: its mode, before the key's type", func(t *testing.T) {
			t.Parallel()
			_ = expectRefusal(t, withMode(t, "rsa", 0o644), ssh.ErrHostKeyReadableByOthers)
		})
		t.Run("a passphrase-protected key of mode 0640: its mode, before the passphrase", func(t *testing.T) {
			t.Parallel()
			path := makeKey(t, "ed25519", "secret")
			setMode(t, path, 0o640)
			_ = expectRefusal(t, path, ssh.ErrHostKeyReadableByOthers)
		})
		t.Run("a line of text of mode 0644: its mode, before its format", func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, []byte(canary+"\n"))
			setMode(t, path, 0o644)
			_ = expectRefusal(t, path, ssh.ErrHostKeyReadableByOthers)
		})
		t.Run("mode 0200, which nobody but root may read: unreadable, before its format", func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, []byte(canary+"\n"))
			keepFromReading(t, path)
			_ = expectRefusal(t, path, ssh.ErrHostKeyUnreadable)
		})
	})
}

func fmtMode(before string, mode os.FileMode, after string) string {
	return fmt.Sprintf("%s %04o %s", before, mode, after)
}
