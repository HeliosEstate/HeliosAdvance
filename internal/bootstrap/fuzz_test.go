// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The fuzz targets for issue #85: the header reader, through openFile, and the field-record
// reader, each seeded by the kept samples. Neither may panic, and each refuses only with a
// Refusal; what the record reader accepts holds every byte it was given.
package bootstrap

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

var fuzzSamples = []string{sampleOneKey, sampleTwoKeys, sampleUnknown, sampleLargest}

func FuzzOpenFile(fuzz *testing.F) {
	key, err := loadTestKey()
	if err != nil {
		fuzz.Fatal(err)
	}
	for _, sample := range fuzzSamples {
		data, err := os.ReadFile(filepath.Join(samples, sample+".hadv"))
		if err != nil {
			fuzz.Fatal(err)
		}
		fuzz.Add(data)
	}
	fuzz.Fuzz(func(t *testing.T, data []byte) {
		_, err := openSealed(data, key)
		if err == nil {
			return
		}
		if refusal := refusalOf(err); refusal == nil || (refusal.Cause != FileNotUnsealed && refusal.Cause != NewerFormat) {
			t.Fatalf("got %v, want a refusal with FileNotUnsealed or NewerFormat", err)
		}
	})
}

func FuzzReadRecords(fuzz *testing.F) {
	for _, sample := range fuzzSamples {
		list, err := os.ReadFile(filepath.Join(samples, sample+".records"))
		if err != nil {
			fuzz.Fatal(err)
		}
		records, err := parseRecordList(string(list))
		if err != nil {
			fuzz.Fatal(err)
		}
		fuzz.Add(plaintextOf(records))
	}
	fuzz.Fuzz(func(t *testing.T, plaintext []byte) {
		records, err := readRecords(plaintext)
		if err != nil {
			if refusal := refusalOf(err); refusal == nil || refusal.Cause != FileNotUnsealed {
				t.Fatalf("got %v, want a refusal with FileNotUnsealed", err)
			}
			return
		}
		if again := plaintextOf(records); !bytes.Equal(again, plaintext) {
			t.Fatalf("the records accepted do not hold the plaintext they came from:\n got % x\nwant % x", again, plaintext)
		}
	})
}

// plaintextOf frames records as the format gives them.
func plaintextOf(records []record) []byte {
	var plaintext []byte
	for _, rec := range records {
		plaintext = binary.BigEndian.AppendUint16(plaintext, uint16(len(rec.name))) //nolint:gosec // a name read from a record list is far below 65,535 bytes
		plaintext = append(plaintext, rec.name...)
		plaintext = binary.BigEndian.AppendUint32(plaintext, uint32(len(rec.data))) //nolint:gosec // a plaintext is far below 4 GiB
		plaintext = append(plaintext, rec.data...)
	}
	return plaintext
}
