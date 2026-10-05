// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The approved tests for issue #85, written by the QA session from the issue's behavior
// lines against the bootstrap file oracle (oracle/bootstrap-file). Each group of rows quotes,
// word for word, the line its rows prove. Every wrong file is built by the oracle's write
// from a record list, at test time. The oracle is required, not optional: a missing docker
// is a failure, never a skip, because a skipped oracle is a vacuous pass.
package bootstrap

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/board"
)

const (
	oracleImage = "heliosestate/bootstrap-file-oracle:0.1"
	samples     = "testdata/format-1"
)

// The kept samples.
const (
	sampleOneKey  = "one-vault-key"
	sampleTwoKeys = "two-vault-keys"
	sampleUnknown = "unknown-records"
	sampleLargest = "largest"
)

// The lines, word for word.
const (
	lineLayout       = "The bootstrap package shall write the bootstrap file only in the layout this package comment gives for format version 1."
	lineNonce        = "The bootstrap package shall write a new random nonce each time it writes the bootstrap file."
	lineVaultRecords = "The bootstrap package shall write each vault key as a record of its own, named vault.key. followed by its version in decimal."
	lineLarger       = "If the bootstrap file is larger than 65,536 bytes, then the bootstrap package shall refuse it with FileNotUnsealed without reading its contents."
	lineShorter      = "If the bootstrap file is shorter than its 22-byte header and 16-byte tag, then the bootstrap package shall refuse it with FileNotUnsealed."
	lineMagic        = "If the bootstrap file does not begin with the magic HADVBOOT, then the bootstrap package shall refuse it with FileNotUnsealed."
	lineVersionZero  = "If the bootstrap file's format version is 0, then the bootstrap package shall refuse it with FileNotUnsealed."
	lineNewer        = "If the bootstrap file's format version is newer than 1, then the bootstrap package shall refuse it with NewerFormat, naming both versions."
	lineTag          = "If the GCM tag does not verify, then the bootstrap package shall refuse the bootstrap file with FileNotUnsealed."
	linePastEnd      = "If a record's name or data runs past the end of the plaintext, then the bootstrap package shall refuse the bootstrap file with FileNotUnsealed."
	lineName         = "If a record's name is empty, longer than 255 bytes, or not UTF-8, then the bootstrap package shall refuse the bootstrap file with FileNotUnsealed."
	lineShared       = "If two records share a name, then the bootstrap package shall refuse the bootstrap file with FileNotUnsealed."
	lineKnownField   = "If a known field is absent, its data breaks the form the format gives it, or it breaks a rule in the table on Fields, then the bootstrap package shall refuse the bootstrap file with FileNotUnsealed."
	lineVaultCount   = "If the bootstrap file holds no vault key or more than two, then the bootstrap package shall refuse it with FileNotUnsealed."
	lineVaultName    = "If a record's name begins with vault.key. and the rest is not a version in decimal from 1 to 4,294,967,295 with no leading zero, then the bootstrap package shall refuse the bootstrap file with FileNotUnsealed."
	lineUnknownKept  = "When the bootstrap package rewrites the bootstrap file, it shall keep every record of an unknown name byte for byte, in the order it was read."
)

// TestWrite proves the three lines on writing: the oracle reads what the package writes.
func TestWrite(t *testing.T) {
	t.Parallel()
	key := testKey(t)
	written := map[string][]byte{}
	wants := map[string][]record{}
	for _, sample := range []string{sampleOneKey, sampleTwoKeys} {
		want := parseRecords(t, sampleList(t, sample))
		file := &bootstrapFile{}
		file.setFields(fieldsOf(t, want))
		written[sample] = writeFile(t, file, key)
		wants[sample] = want
	}
	versions := fieldsOf(t, wants[sampleOneKey])
	versions.VaultKeys = []VaultKey{{Version: 1, Key: bytes.Repeat([]byte{1}, 32)}, {Version: 4294967295, Key: bytes.Repeat([]byte{2}, 32)}}
	file := &bootstrapFile{}
	file.setFields(versions)
	written["versions"] = writeFile(t, file, key)
	verdicts := oracleRead(t, written)

	t.Run(lineLayout, func(t *testing.T) {
		t.Parallel()
		for _, sample := range []string{sampleOneKey, sampleTwoKeys} {
			out := written[sample]
			if len(out) < 22 || string(out[:8]) != Magic || binary.BigEndian.Uint16(out[8:10]) != FormatVersion {
				t.Errorf("%s: the header is not HADVBOOT and format version 1: % x", sample, out[:min(len(out), 10)])
			}
			verdict := verdicts[sample]
			if verdict.status != 0 {
				t.Errorf("%s: the oracle refused what the package wrote, status %d: %s", sample, verdict.status, verdict.stderr)
				continue
			}
			sameRecordsAnyOrder(t, sample, parseRecords(t, verdict.records), wants[sample])
		}
	})
	t.Run(lineVaultRecords, func(t *testing.T) {
		t.Parallel()
		verdict := verdicts["versions"]
		if verdict.status != 0 {
			t.Fatalf("the oracle refused what the package wrote, status %d: %s", verdict.status, verdict.stderr)
		}
		var vault []record
		for _, rec := range parseRecords(t, verdict.records) {
			if strings.HasPrefix(rec.name, FieldVaultKeyPrefix) {
				vault = append(vault, rec)
			}
		}
		sameRecordsAnyOrder(t, "vault keys", vault, []record{
			{name: "vault.key.1", data: bytes.Repeat([]byte{1}, 32)},
			{name: "vault.key.4294967295", data: bytes.Repeat([]byte{2}, 32)},
		})
	})
	t.Run(lineNonce, func(t *testing.T) {
		t.Parallel()
		fields := fieldsOf(t, wants[sampleOneKey])
		file := &bootstrapFile{}
		file.setFields(fields)
		first, second := writeFile(t, file, key), writeFile(t, file, key)
		if bytes.Equal(nonceOf(t, first), nonceOf(t, second)) {
			t.Errorf("two writes of one file share the nonce % x", nonceOf(t, first))
		}
		sample := readSample(t, sampleOneKey+".hadv")
		opened, err := openSealed(sample, key)
		if err != nil {
			t.Fatalf("the sample did not open: %v", err)
		}
		if bytes.Equal(nonceOf(t, writeFile(t, opened, key)), nonceOf(t, sample)) {
			t.Error("a rewrite of an opened file kept its old nonce")
		}
	})
}

// TestOpenSamples opens the kept samples and reads each one's fields as its record list
// gives them. The largest sample is the size limit's edge.
func TestOpenSamples(t *testing.T) {
	t.Parallel()
	key := testKey(t)
	for _, sample := range []string{sampleOneKey, sampleTwoKeys, sampleUnknown, sampleLargest} {
		line := lineLayout
		if sample == sampleLargest {
			line = lineLarger
		}
		t.Run(sample+": "+line, func(t *testing.T) {
			t.Parallel()
			file, err := openSealed(readSample(t, sample+".hadv"), key)
			if err != nil {
				t.Fatalf("the sample did not open: %v", err)
			}
			sameFields(t, file.fields(), fieldsOf(t, parseRecords(t, sampleList(t, sample))))
		})
	}
}

// TestOpenLargerReadsNothing proves that a file past the limit is refused before a byte is
// read.
func TestOpenLargerReadsNothing(t *testing.T) {
	t.Parallel()
	t.Run(lineLarger, func(t *testing.T) {
		t.Parallel()
		_, err := openFile(unreadable{t}, MaxSize+1, testKey(t))
		wantRefusal(t, err, FileNotUnsealed)
	})
}

// unreadable is a file the test must not read.
type unreadable struct{ t *testing.T }

func (source unreadable) Read([]byte) (int, error) {
	source.t.Error("the file was read, though its size is past the limit")
	return 0, io.EOF
}

// A wrong file: a record list for the oracle's write, an edit to its bytes, and the key it
// is opened under.
type wrongFile struct {
	name string
	list string
	edit func([]byte) []byte
	key  []byte
}

// TestOpenRefuses builds every wrong file the lines name and opens it.
func TestOpenRefuses(t *testing.T) {
	t.Parallel()
	base := baseList(t)
	otherKey := bytes.Repeat([]byte{0x11}, 32)
	flip := func(at func(int) int) func([]byte) []byte {
		return func(file []byte) []byte {
			file = slices.Clone(file)
			file[at(len(file))] ^= 1
			return file
		}
	}
	groups := []struct {
		line  string
		cause Cause
		files []wrongFile
	}{
		{lineShorter, FileNotUnsealed, []wrongFile{
			{name: "empty", list: base.with("truncate 0")},
			{name: "37 bytes", list: base.with("truncate 37")},
		}},
		{lineMagic, FileNotUnsealed, []wrongFile{
			{name: "HADVBOOX", list: base.with(`magic "HADVBOOX"`)},
			{name: "lower case", list: base.with(`magic "hadvboot"`)},
		}},
		{lineVersionZero, FileNotUnsealed, []wrongFile{
			{name: "version 0", list: base.with("version 0")},
		}},
		{lineTag, FileNotUnsealed, []wrongFile{
			{name: "a bit of the ciphertext", list: base.list(), edit: flip(func(int) int { return 22 })},
			{name: "a bit of the tag", list: base.list(), edit: flip(func(size int) int { return size - 1 })},
			{name: "a bit of the nonce", list: base.list(), edit: flip(func(int) int { return 10 })},
			{name: "another key", list: base.list(), key: otherKey},
		}},
		{linePastEnd, FileNotUnsealed, []wrongFile{
			{name: "data past the end", list: base.with(`record "x.a" "abc" data-length=100`)},
			{name: "name past the end", list: base.with(`record "x.a" "abc" name-length=500`)},
			{name: "cut inside a name length", list: base.with("raw hex:00")},
			{name: "cut inside a name", list: base.with("raw hex:000561")},
			{name: "cut inside a data length", list: base.with("raw hex:000161000000")},
		}},
		{lineName, FileNotUnsealed, []wrongFile{
			{name: "empty", list: base.with(`record "" "x"`)},
			{name: "not UTF-8", list: base.with(`record hex:ff "x"`)},
			{name: "an overlong UTF-8 form", list: base.with(`record hex:c0af "x"`)},
			{name: "256 bytes", list: base.with(`record "` + strings.Repeat("n", 256) + `" "x"`)},
		}},
		{lineShared, FileNotUnsealed, []wrongFile{
			{name: "two unknown records", list: base.with(`record "x.a" "1"`, `record "x.a" "2"`)},
			{name: "two server records", list: base.with(`record "server" hex:0000002b`)},
		}},
		{lineKnownField, FileNotUnsealed, []wrongFile{
			{name: "server absent", list: base.without("server")},
			{name: "connection absent", list: base.without("database.connection")},
			{name: "account name absent", list: base.without("database.account.name")},
			{name: "account password absent", list: base.without("database.account.password")},
			{name: "receiving key absent", list: base.without("receiving.key")},
			{name: "signing key absent", list: base.without("signing.key")},
			{name: "server of 3 bytes", list: base.replacing("server", "hex:000001")},
			{name: "server of 5 bytes", list: base.replacing("server", "hex:000000002a")},
			{name: "server 0", list: base.replacing("server", "hex:00000000")},
			{name: "connection not UTF-8", list: base.replacing("database.connection", "hex:ff")},
			{name: "connection empty", list: base.replacing("database.connection", `""`)},
			{name: "account name not UTF-8", list: base.replacing("database.account.name", "hex:ff")},
			{name: "account name empty", list: base.replacing("database.account.name", `""`)},
			{name: "receiving key empty", list: base.replacing("receiving.key", `""`)},
			{name: "signing key empty", list: base.replacing("signing.key", `""`)},
			{name: "vault key of 31 bytes", list: base.replacing("vault.key.1", "zeros:31")},
			{name: "vault key of 33 bytes", list: base.replacing("vault.key.1", "zeros:33")},
		}},
		{lineVaultCount, FileNotUnsealed, []wrongFile{
			{name: "none", list: base.without("vault.key.1")},
			{name: "three", list: base.with(`record "vault.key.2" zeros:32`, `record "vault.key.3" zeros:32`)},
		}},
		{lineVaultName, FileNotUnsealed, []wrongFile{
			{name: "a leading zero", list: base.with(`record "vault.key.01" zeros:32`)},
			{name: "version 0", list: base.with(`record "vault.key.0" zeros:32`)},
			{name: "past 4,294,967,295", list: base.with(`record "vault.key.4294967296" zeros:32`)},
			{name: "not a number", list: base.with(`record "vault.key.x" zeros:32`)},
			{name: "nothing after the prefix", list: base.with(`record "vault.key." zeros:32`)},
			{name: "a plus sign", list: base.with(`record "vault.key.+1" zeros:32`)},
			{name: "a space", list: base.with(`record "vault.key. 1" zeros:32`)},
		}},
	}
	lists := map[string]string{}
	for g, group := range groups {
		for f, file := range group.files {
			lists[fmt.Sprintf("%02d-%02d", g, f)] = file.list
		}
	}
	sealed := oracleWrite(t, lists)
	key := testKey(t)
	for g, group := range groups {
		t.Run(group.line, func(t *testing.T) {
			t.Parallel()
			for f, file := range group.files {
				data := sealed[fmt.Sprintf("%02d-%02d", g, f)]
				if file.edit != nil {
					data = file.edit(data)
				}
				openKey := key
				if file.key != nil {
					openKey = file.key
				}
				_, err := openSealed(data, openKey)
				if refusal := refusalOf(err); refusal == nil || refusal.Cause != group.cause {
					t.Errorf("%s: got %v, want a refusal with cause %d", file.name, err, group.cause)
				}
			}
		})
	}
	t.Run(lineNewer, func(t *testing.T) {
		t.Parallel()
		newer := oracleWrite(t, map[string]string{"2": base.with("version 2"), "65535": base.with("version 65535")})
		for name, version := range map[string]uint16{"2": 2, "65535": 65535} {
			_, err := openSealed(newer[name], key)
			wantRefusal(t, err, NewerFormat)
			refusal := refusalOf(err)
			if refusal != nil && (refusal.FileVersion != version || refusal.OwnVersion != FormatVersion) {
				t.Errorf("version %s: the refusal names %d and %d, want %d and %d", name, refusal.FileVersion, refusal.OwnVersion, version, FormatVersion)
			}
		}
	})
}

// TestOpenAccepts opens the files at the edge of a refusal line, which the line lets
// through.
func TestOpenAccepts(t *testing.T) {
	t.Parallel()
	base := baseList(t)
	rows := []struct {
		line, name, list string
	}{
		{lineName, "a 255-byte name", base.with(`record "` + strings.Repeat("n", 255) + `" "x"`)},
		{lineKnownField, "an empty password, which the table gives no rule", base.replacing("database.account.password", `""`)},
		{lineVaultName, "version 4,294,967,295", base.with(`record "vault.key.4294967295" zeros:32`)},
	}
	lists := map[string]string{}
	for _, row := range rows {
		lists[row.name] = row.list
	}
	sealed := oracleWrite(t, lists)
	key := testKey(t)
	for _, row := range rows {
		t.Run(row.name+": "+row.line, func(t *testing.T) {
			t.Parallel()
			if _, err := openSealed(sealed[row.name], key); err != nil {
				t.Errorf("refused: %v", err)
			}
		})
	}
}

// TestRewriteKeepsUnknown opens the sample with unknown records, writes it back with and
// without a change, and has the oracle read what was written.
func TestRewriteKeepsUnknown(t *testing.T) {
	t.Parallel()
	key := testKey(t)
	unknownOf := func(records []record) []record {
		return slices.DeleteFunc(slices.Clone(records), func(rec record) bool {
			return isKnownName(rec.name)
		})
	}
	want := unknownOf(parseRecords(t, sampleList(t, sampleUnknown)))
	written := map[string][]byte{}
	for _, change := range []string{"no change", "a vault key added"} {
		file, err := openSealed(readSample(t, sampleUnknown+".hadv"), key)
		if err != nil {
			t.Fatalf("the sample did not open: %v", err)
		}
		if change == "a vault key added" {
			fields := file.fields()
			fields.VaultKeys = append(fields.VaultKeys, VaultKey{Version: 4, Key: bytes.Repeat([]byte{4}, 32)})
			file.setFields(fields)
		}
		written[change] = writeFile(t, file, key)
	}
	verdicts := oracleRead(t, written)
	for change := range written {
		t.Run(change+": "+lineUnknownKept, func(t *testing.T) {
			t.Parallel()
			verdict := verdicts[change]
			if verdict.status != 0 {
				t.Fatalf("the oracle refused the rewrite, status %d: %s", verdict.status, verdict.stderr)
			}
			got := unknownOf(parseRecords(t, verdict.records))
			if !slices.EqualFunc(got, want, sameRecord) {
				t.Errorf("unknown records\n got %s\nwant %s", recordNames(got), recordNames(want))
			}
		})
	}
}

// ---- helpers ----

// openSealed opens a whole file held in memory.
func openSealed(data, key []byte) (*bootstrapFile, error) {
	return openFile(bytes.NewReader(data), int64(len(data)), key)
}

func writeFile(t *testing.T, file *bootstrapFile, key []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := file.writeTo(&out, key); err != nil {
		t.Fatalf("writing: %v", err)
	}
	return out.Bytes()
}

func nonceOf(t *testing.T, file []byte) []byte {
	t.Helper()
	if len(file) < 22 {
		t.Fatalf("a file of %d bytes has no nonce", len(file))
	}
	return file[10:22]
}

func refusalOf(err error) *Refusal {
	var refusal *Refusal
	if errors.As(err, &refusal) {
		return refusal
	}
	return nil
}

func wantRefusal(t *testing.T, err error, cause Cause) {
	t.Helper()
	refusal := refusalOf(err)
	if refusal == nil || refusal.Cause != cause {
		t.Errorf("got %v, want a refusal with cause %d", err, cause)
	}
}

func testKey(tb testing.TB) []byte {
	tb.Helper()
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(readSample(tb, "test.key"))))
	if err != nil || len(key) != 32 {
		tb.Fatalf("test.key is not 32 bytes as base64: %v", err)
	}
	return key
}

func readSample(tb testing.TB, name string) []byte {
	tb.Helper()
	data, err := os.ReadFile(filepath.Join(samples, name))
	if err != nil {
		tb.Fatal(err)
	}
	return data
}

// sampleList is a sample's record list.
func sampleList(tb testing.TB, sample string) string {
	tb.Helper()
	return string(readSample(tb, sample+".records"))
}

func isKnownName(name string) bool {
	switch name {
	case FieldServer, FieldConnection, FieldAccountName, FieldAccountPassword, FieldReceivingKey, FieldSigningKey:
		return true
	}
	return strings.HasPrefix(name, FieldVaultKeyPrefix)
}

// fieldsOf is the known fields a record list holds, as the format gives them.
func fieldsOf(tb testing.TB, records []record) Fields {
	tb.Helper()
	var fields Fields
	for _, rec := range records {
		switch {
		case rec.name == FieldServer:
			fields.Server = board.ServerID(binary.BigEndian.Uint32(rec.data))
		case rec.name == FieldConnection:
			fields.Connection = string(rec.data)
		case rec.name == FieldAccountName:
			fields.AccountName = string(rec.data)
		case rec.name == FieldAccountPassword:
			fields.AccountPassword = rec.data
		case rec.name == FieldReceivingKey:
			fields.ReceivingKey = rec.data
		case rec.name == FieldSigningKey:
			fields.SigningKey = rec.data
		case strings.HasPrefix(rec.name, FieldVaultKeyPrefix):
			version, err := strconv.ParseUint(strings.TrimPrefix(rec.name, FieldVaultKeyPrefix), 10, 32)
			if err != nil {
				tb.Fatalf("%s: %v", rec.name, err)
			}
			fields.VaultKeys = append(fields.VaultKeys, VaultKey{Version: uint32(version), Key: rec.data})
		}
	}
	return fields
}

func sameFields(t *testing.T, got, want Fields) {
	t.Helper()
	if got.Server != want.Server || got.Connection != want.Connection || got.AccountName != want.AccountName {
		t.Errorf("got server %d, connection %q, account %q; want %d, %q, %q", got.Server, got.Connection, got.AccountName, want.Server, want.Connection, want.AccountName)
	}
	for _, pair := range []struct {
		name      string
		got, want []byte
	}{
		{FieldAccountPassword, got.AccountPassword, want.AccountPassword},
		{FieldReceivingKey, got.ReceivingKey, want.ReceivingKey},
		{FieldSigningKey, got.SigningKey, want.SigningKey},
	} {
		if !bytes.Equal(pair.got, pair.want) {
			t.Errorf("%s: got % x, want % x", pair.name, pair.got, pair.want)
		}
	}
	byVersion := func(a, b VaultKey) int { return int(a.Version) - int(b.Version) }
	gotKeys, wantKeys := slices.Clone(got.VaultKeys), slices.Clone(want.VaultKeys)
	slices.SortFunc(gotKeys, byVersion)
	slices.SortFunc(wantKeys, byVersion)
	if !slices.EqualFunc(gotKeys, wantKeys, func(a, b VaultKey) bool { return a.Version == b.Version && bytes.Equal(a.Key, b.Key) }) {
		t.Errorf("vault keys: got %v, want %v", gotKeys, wantKeys)
	}
}

func sameRecord(a, b record) bool { return a.name == b.name && bytes.Equal(a.data, b.data) }

func sameRecordsAnyOrder(t *testing.T, what string, got, want []record) {
	t.Helper()
	byName := func(a, b record) int { return strings.Compare(a.name, b.name) }
	got, want = slices.Clone(got), slices.Clone(want)
	slices.SortFunc(got, byName)
	slices.SortFunc(want, byName)
	if !slices.EqualFunc(got, want, sameRecord) {
		t.Errorf("%s: records\n got %s\nwant %s", what, recordNames(got), recordNames(want))
	}
}

func recordNames(records []record) string {
	names := make([]string, len(records))
	for i, rec := range records {
		names[i] = fmt.Sprintf("%q(%d)", rec.name, len(rec.data))
	}
	return strings.Join(names, " ")
}

// ---- record lists ----

// recordList is a record list's lines without its header directives, so that a row can
// give its own.
type recordList []string

// baseList is every known field and one vault key: the one-vault-key sample without its
// header.
func baseList(tb testing.TB) recordList {
	tb.Helper()
	var list recordList
	for line := range strings.SplitSeq(sampleList(tb, sampleOneKey), "\n") {
		if strings.HasPrefix(line, "record ") {
			list = append(list, line)
		}
	}
	return list
}

func (list recordList) list() string { return strings.Join(list, "\n") + "\n" }

func (list recordList) with(lines ...string) string {
	return recordList(append(slices.Clone(list), lines...)).list()
}

func (list recordList) without(name string) string {
	prefix := fmt.Sprintf("record %q ", name)
	return recordList(slices.DeleteFunc(slices.Clone(list), func(line string) bool {
		return strings.HasPrefix(line, prefix)
	})).list()
}

func (list recordList) replacing(name, value string) string {
	prefix := fmt.Sprintf("record %q ", name)
	replaced := slices.Clone(list)
	for i, line := range replaced {
		if strings.HasPrefix(line, prefix) {
			replaced[i] = prefix + value
		}
	}
	return replaced.list()
}

// parseRecords reads the record lines of a record list in the oracle's form.
func parseRecords(tb testing.TB, list string) []record {
	tb.Helper()
	var records []record
	for line := range strings.SplitSeq(list, "\n") {
		rest, found := strings.CutPrefix(strings.TrimRight(line, "\r"), "record ")
		if !found {
			continue
		}
		name, rest := parseValue(tb, rest)
		data, rest := parseValue(tb, strings.TrimPrefix(rest, " "))
		if rest != "" {
			tb.Fatalf("a record line with more than a name and data: %q", line)
		}
		records = append(records, record{name: string(name), data: data})
	}
	return records
}

// parseValue reads one quoted or hex: value and returns what follows it.
func parseValue(tb testing.TB, text string) ([]byte, string) {
	tb.Helper()
	if hexDigits, found := strings.CutPrefix(text, "hex:"); found {
		end := strings.IndexByte(hexDigits, ' ')
		if end < 0 {
			end = len(hexDigits)
		}
		value, err := hex.DecodeString(hexDigits[:end])
		if err != nil {
			tb.Fatalf("%q: %v", text, err)
		}
		return value, hexDigits[end:]
	}
	if !strings.HasPrefix(text, `"`) {
		tb.Fatalf("not a value: %q", text)
	}
	value := []byte{}
	for i := 1; i < len(text); i++ {
		switch text[i] {
		case '"':
			return value, text[i+1:]
		case '\\':
			if i+1 >= len(text) {
				tb.Fatalf("an escape at the end: %q", text)
			}
			i++
			switch text[i] {
			case 'n':
				value = append(value, '\n')
			case 'r':
				value = append(value, '\r')
			case 't':
				value = append(value, '\t')
			case 'x':
				if i+2 >= len(text) {
					tb.Fatalf("a short \\x escape: %q", text)
				}
				b, err := hex.DecodeString(text[i+1 : i+3])
				if err != nil {
					tb.Fatalf("%q: %v", text, err)
				}
				value = append(value, b...)
				i += 2
			default:
				value = append(value, text[i])
			}
		default:
			value = append(value, text[i])
		}
	}
	tb.Fatalf("an unclosed quote: %q", text)
	return nil, ""
}

// ---- the oracle ----

// oracle runs one shell script in the oracle's image, with dir as /data.
func oracle(tb testing.TB, dir, script string) {
	tb.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		tb.Fatal("docker is required: the oracle is in a container, and a skipped oracle is a vacuous pass")
	}
	args := []string{"run", "--rm", "-v", dir + ":/data"}
	if uid := os.Getuid(); uid >= 0 {
		// On Unix the container would otherwise write as root into the temp dir.
		args = append(args, "--user", fmt.Sprintf("%d:%d", uid, os.Getgid()))
	}
	args = append(args, oracleImage, "sh", "-c", script)
	out, err := exec.CommandContext(tb.Context(), "docker", args...).CombinedOutput()
	if err != nil {
		tb.Fatalf("the oracle: %v\n%s", err, out)
	}
}

// oracleDir is a temporary folder holding the test key.
func oracleDir(tb testing.TB) string {
	tb.Helper()
	dir := tb.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "test.key"), readSample(tb, "test.key"), 0o600); err != nil {
		tb.Fatal(err)
	}
	return dir
}

// oracleWrite seals each record list with the oracle's write under the test key, in one run.
func oracleWrite(tb testing.TB, lists map[string]string) map[string][]byte {
	tb.Helper()
	dir := oracleDir(tb)
	for name, list := range lists {
		if err := os.WriteFile(filepath.Join(dir, name+".records"), []byte(list), 0o600); err != nil {
			tb.Fatal(err)
		}
	}
	oracle(tb, dir, `for f in /data/*.records; do bootstrap-file write /data/test.key "$f" "${f%.records}.hadv" || exit 1; done`)
	sealed := map[string][]byte{}
	for name := range lists {
		sealed[name] = readFileIn(tb, dir, name+".hadv")
	}
	return sealed
}

// verdict is the oracle's read of one file.
type verdict struct {
	status  int
	records string
	stderr  string
}

// oracleRead has the oracle read each file under the test key, in one run.
func oracleRead(tb testing.TB, files map[string][]byte) map[string]verdict {
	tb.Helper()
	dir := oracleDir(tb)
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name+".hadv"), data, 0o600); err != nil {
			tb.Fatal(err)
		}
	}
	oracle(tb, dir, `for f in /data/*.hadv; do b="${f%.hadv}"; bootstrap-file read /data/test.key "$f" >"$b.out" 2>"$b.err"; echo $? >"$b.status"; done`)
	verdicts := map[string]verdict{}
	for name := range files {
		status, err := strconv.Atoi(strings.TrimSpace(string(readFileIn(tb, dir, name+".status"))))
		if err != nil {
			tb.Fatal(err)
		}
		verdicts[name] = verdict{
			status:  status,
			records: string(readFileIn(tb, dir, name+".out")),
			stderr:  string(readFileIn(tb, dir, name+".err")),
		}
	}
	return verdicts
}

func readFileIn(tb testing.TB, dir, name string) []byte {
	tb.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		tb.Fatal(err)
	}
	return data
}
