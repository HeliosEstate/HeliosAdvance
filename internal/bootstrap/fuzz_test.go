// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The fuzz targets the contract names for issue #148: the header reader, the record reader and
// the base64 key reader, each seeded from the kept samples. Plain go test runs the seeds alone;
// random inputs run only under go test -fuzz. Each reader refuses only with its own code and
// never panics, and what it accepts it gives back whole.
package bootstrap

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// keptSamples is every kept sample, by name, without its extension.
var keptSamples = []string{"keyholder-1", "keyholder-2", "keyholder-3", sampleKeyFile, sampleSwarmSecret, sampleTwoVaultKeys, sampleUnknown}

// windowsKeyName is a Windows key's name as the header carries it.
var windowsKeyName = regexp.MustCompile(`^hadv-[0-9a-f]{32}$`)

func FuzzReadHeader(fuzz *testing.F) {
	for _, sample := range keptSamples {
		file, err := os.ReadFile(filepath.Join(samples, sample+".hadv"))
		if err != nil {
			fuzz.Fatal(err)
		}
		fuzz.Add(file)
	}
	fuzz.Fuzz(func(t *testing.T, file []byte) {
		holder, sealedKey, err := readHeader(file)
		if err != nil {
			if !errors.Is(err, ErrFormat) {
				t.Fatalf("got %v, want ErrFormat or a header", err)
			}
			return
		}
		// What the reader accepted holds to the table: the magic, format version 1, a key
		// holder from 1 to 5 as the header names it, the sealed key it carries at its length,
		// that length right for the key holder, and room for the nonce and the tag after it.
		if len(file) < HeaderStartSize {
			t.Fatalf("accepted a file of %d bytes, shorter than the header's start", len(file))
		}
		if string(file[:8]) != Magic || binary.BigEndian.Uint16(file[8:10]) != FormatVersion {
			t.Fatalf("accepted a magic %q and format version %d", file[:8], binary.BigEndian.Uint16(file[8:10]))
		}
		if holder != KeyHolder(file[10]) || holder < WindowsKeyStore || holder > SwarmSecret {
			t.Fatalf("got key holder %d from a header naming %d", holder, file[10])
		}
		length := int(binary.BigEndian.Uint16(file[11:HeaderStartSize]))
		if len(file) < HeaderStartSize+length+NonceSize+TagSize {
			t.Fatalf("accepted a file of %d bytes with a sealed key of %d", len(file), length)
		}
		if !bytes.Equal(sealedKey, file[HeaderStartSize:HeaderStartSize+length]) {
			t.Fatal("the sealed key given is not the one the header carries")
		}
		switch holder {
		case WindowsKeyStore:
			if length != WindowsKeyNameSize+WindowsWrapSize || !windowsKeyName.Match(sealedKey[:WindowsKeyNameSize]) {
				t.Fatalf("accepted a Windows sealed key of %d bytes named %q", length, sealedKey[:min(length, WindowsKeyNameSize)])
			}
		case SystemdByService, SystemdAtStart:
			if length < 1 || length > SystemdCredentialMax {
				t.Fatalf("accepted a systemd sealed key of %d bytes", length)
			}
		default:
			if length != 0 {
				t.Fatalf("accepted a sealed key of %d bytes for key holder %d", length, holder)
			}
		}
	})
}

func FuzzReadRecords(fuzz *testing.F) {
	for _, sample := range keptSamples {
		text, err := os.ReadFile(filepath.Join(samples, sample+".records"))
		if err != nil {
			fuzz.Fatal(err)
		}
		records, err := listOf(string(text)).records()
		if err != nil {
			fuzz.Fatal(err)
		}
		plaintext, err := plaintextOf(records)
		if err != nil {
			fuzz.Fatal(err)
		}
		fuzz.Add(plaintext)
	}
	fuzz.Fuzz(func(t *testing.T, plaintext []byte) {
		records, err := readRecords(plaintext)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid or the records", err)
			}
			return
		}
		again, err := plaintextOf(records)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, plaintext) {
			t.Fatalf("the records accepted do not frame back to the plaintext they came from:\n got % x\nwant % x", again, plaintext)
		}
	})
}

func FuzzReadKey(fuzz *testing.F) {
	text, err := os.ReadFile(filepath.Join(samples, "test.key"))
	if err != nil {
		fuzz.Fatal(err)
	}
	fuzz.Add(text)
	fuzz.Add(bytes.TrimSuffix(text, []byte("\n")))
	fuzz.Fuzz(func(t *testing.T, text []byte) {
		key, err := readKey(bytes.NewReader(text))
		// A key's one spelling: 44 characters of the standard alphabet with its padding, the
		// bits after its last byte zero, one trailing newline allowed. Strict decoding refuses
		// any other spelling of the same bytes.
		spelling := strings.TrimSuffix(string(text), "\n")
		decoded, decodeErr := base64.StdEncoding.Strict().DecodeString(spelling)
		isKey := decodeErr == nil && len(spelling) == 44 && len(decoded) == KeySize
		if err != nil {
			if !errors.Is(err, ErrKey) {
				t.Fatalf("got %v, want ErrKey or a key", err)
			}
			if isKey {
				t.Fatalf("refused a key in its one spelling: %q", text)
			}
			return
		}
		if !isKey || base64.StdEncoding.EncodeToString(key[:]) != spelling {
			t.Fatalf("accepted %q, which is not a key's one spelling, as % x", text, key)
		}
	})
}
