// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Reading the connection file: each refusal, the order they are made in, the edges a valid file
// may reach, and that no refusal's text holds what the file held. Every file is a real file in
// a temporary folder.
package database_test

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/database"
)

// canary marks the file's strings, so an error's text can be searched for them.
const canary = "helios-canary-7340"

// The file's limit as the line states it, written here so a changed constant in the package
// cannot move a test with it.
const fileMostBytes = 65536

// The seven fields the format names, a field it does not, and JSON's null.
const (
	fieldServerID    = "server_id"
	fieldHost        = "host"
	fieldPort        = "port"
	fieldDatabase    = "database"
	fieldLogin       = "login"
	fieldPassword    = "password"
	fieldCertificate = "ca_certificate"
	unknownField     = "sslmode"
	jsonNull         = "null"
)

// fileErrors are every refusal ReadConnectionFile may return.
var fileErrors = []error{database.ErrFileMissing, database.ErrFileReadableByOthers, database.ErrFileUnreadable,
	database.ErrFileTooLarge, database.ErrFileFormat, database.ErrFileFieldUnknown, database.ErrFileFieldMissing}

// field is one name and its raw JSON value, in the order a file gives them.
type field struct {
	name  string
	value string
}

// validFields are a valid file's seven fields, each string holding the canary.
func validFields(t *testing.T) []field {
	t.Helper()
	return []field{
		{fieldServerID, "42"},
		{fieldHost, strconv.Quote("db-" + canary + ".invalid")},
		{fieldPort, "5432"},
		{fieldDatabase, strconv.Quote("board-" + canary)},
		{fieldLogin, strconv.Quote("login-" + canary)},
		{fieldPassword, strconv.Quote("password-" + canary)},
		{fieldCertificate, strconv.Quote(newAuthority(t).pemText)},
	}
}

// objectText writes the fields as one JSON object.
func objectText(fields []field) string {
	parts := make([]string, 0, len(fields))
	for _, entry := range fields {
		parts = append(parts, strconv.Quote(entry.name)+": "+entry.value)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// with returns the fields with one replaced, or added when it is not there.
func with(fields []field, name, value string) []field {
	changed := append([]field{}, fields...)
	for index := range changed {
		if changed[index].name == name {
			changed[index].value = value
			return changed
		}
	}
	return append(changed, field{name, value})
}

// without returns the fields with one left out.
func without(fields []field, name string) []field {
	var kept []field
	for _, entry := range fields {
		if entry.name != name {
			kept = append(kept, entry)
		}
	}
	return kept
}

// expectFileError reads the file at path and checks the refusal is want and no other, and that
// its text holds no part of the file.
func expectFileError(t *testing.T, path string, want error) {
	t.Helper()
	_, err := database.ReadConnectionFile(path)
	expectOnly(t, err, want, fileErrors)
	expectNoContents(t, err)
}

// expectOnly checks err matches want and none of the others.
func expectOnly(t *testing.T, err, want error, all []error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("the error was %v, want %v", err, want)
	}
	for _, other := range all {
		if !errors.Is(other, want) && errors.Is(err, other) {
			t.Fatalf("the error %v matches %v as well as %v", err, other, want)
		}
	}
}

// expectNoContents checks an error's text holds none of what the tests write in a file.
func expectNoContents(t *testing.T, err error) {
	t.Helper()
	if err != nil && (strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), "BEGIN CERTIFICATE")) {
		t.Fatalf("the error's text holds part of the file: %q", err.Error())
	}
}

// expectRead reads the file at path and checks it is read as the fields give.
func expectRead(t *testing.T, path string, want database.ConnectionFile) {
	t.Helper()
	got, err := database.ReadConnectionFile(path)
	if err != nil {
		t.Fatalf("a valid file was refused: %v", err)
	}
	if got != want {
		t.Fatalf("the file was read as %+v, want %+v", got, want)
	}
}

// readAs is what the valid fields read as, with the server ID, port and certificate given.
func readAs(fields []field, serverID int64, port uint16) database.ConnectionFile {
	text := map[string]string{}
	for _, entry := range fields {
		value, err := strconv.Unquote(entry.value)
		if err == nil {
			text[entry.name] = value
		}
	}
	return database.ConnectionFile{ServerID: serverID, Host: text[fieldHost], Port: port, Database: text[fieldDatabase],
		Login: text[fieldLogin], Password: text[fieldPassword], CACertificate: text[fieldCertificate]}
}

// padTo pads a JSON object with spaces before its closing brace to exactly size bytes.
func padTo(t *testing.T, object string, size int) string {
	t.Helper()
	if len(object) > size {
		t.Fatalf("the object is %d bytes, more than %d", len(object), size)
	}
	return object[:len(object)-1] + strings.Repeat(" ", size-len(object)) + "}"
}

func TestConnectionFile(t *testing.T) {
	t.Parallel()

	t.Run("If no file is at path, then ReadConnectionFile shall return ErrFileMissing.", func(t *testing.T) {
		t.Parallel()
		t.Run("a path in an empty folder: ErrFileMissing", func(t *testing.T) {
			t.Parallel()
			expectFileError(t, filepath.Join(t.TempDir(), "connection.json"), database.ErrFileMissing)
		})
	})

	t.Run("If the file cannot be read, then ReadConnectionFile shall return ErrFileUnreadable.", func(t *testing.T) {
		t.Parallel()
		t.Run("a valid file the user may not read: ErrFileUnreadable", func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, objectText(validFields(t)))
			keepFromReading(t, path)
			expectFileError(t, path, database.ErrFileUnreadable)
		})
	})

	t.Run("If the file is longer than ConnectionFileMostBytes, then ReadConnectionFile shall return ErrFileTooLarge.", func(t *testing.T) {
		t.Parallel()
		t.Run("a valid object padded to 65,537 bytes: ErrFileTooLarge", func(t *testing.T) {
			t.Parallel()
			expectFileError(t, writeFile(t, padTo(t, objectText(validFields(t)), fileMostBytes+1)), database.ErrFileTooLarge)
		})
		t.Run("10 MiB: ErrFileTooLarge", func(t *testing.T) {
			t.Parallel()
			expectFileError(t, writeFile(t, padTo(t, objectText(validFields(t)), 10<<20)), database.ErrFileTooLarge)
		})
		t.Run("a valid object padded to exactly 65,536 bytes is read, every field exact", func(t *testing.T) {
			t.Parallel()
			fields := validFields(t)
			expectRead(t, writeFile(t, padTo(t, objectText(fields), fileMostBytes)), readAs(fields, 42, 5432))
		})
	})

	t.Run("If the file is not one JSON object, or gives a field twice, then ReadConnectionFile shall return ErrFileFormat.", func(t *testing.T) {
		t.Parallel()
		cases := map[string]func([]field) string{
			"not JSON":               func([]field) string { return "server_id=42 host=" + canary },
			"an empty file":          func([]field) string { return "" },
			jsonNull:                 func([]field) string { return jsonNull },
			"an array of the object": func(fields []field) string { return "[" + objectText(fields) + "]" },
			"two objects":            func(fields []field) string { return objectText(fields) + objectText(fields) },
			"the object, then text":  func(fields []field) string { return objectText(fields) + " " + canary },
			"the object cut short":   func(fields []field) string { text := objectText(fields); return text[:len(text)-1] },
			"host given twice": func(fields []field) string {
				return objectText(append(fields, field{fieldHost, strconv.Quote(canary)}))
			},
			"server_id given twice, the same value": func(fields []field) string {
				return objectText(append(fields, field{fieldServerID, "42"}))
			},
		}
		for name, text := range cases {
			t.Run(name+": ErrFileFormat", func(t *testing.T) {
				t.Parallel()
				expectFileError(t, writeFile(t, text(validFields(t))), database.ErrFileFormat)
			})
		}
	})

	t.Run("If the object holds a field whose name is not exactly one of server_id, host, port, database, login, password and ca_certificate, then ReadConnectionFile shall return ErrFileFieldUnknown.", func(t *testing.T) {
		t.Parallel()
		for _, name := range []string{unknownField, "Host", "PORT", "password "} {
			t.Run(strconv.Quote(name)+" beside the seven: ErrFileFieldUnknown", func(t *testing.T) {
				t.Parallel()
				expectFileError(t, writeFile(t, objectText(append(validFields(t), field{name, strconv.Quote(canary)}))), database.ErrFileFieldUnknown)
			})
		}
	})

	t.Run("If the object lacks one of those seven fields, then ReadConnectionFile shall return ErrFileFieldMissing.", func(t *testing.T) {
		t.Parallel()
		for _, name := range []string{fieldServerID, fieldHost, fieldPort, fieldDatabase, fieldLogin, fieldPassword, fieldCertificate} {
			t.Run(name+" left out: ErrFileFieldMissing", func(t *testing.T) {
				t.Parallel()
				expectFileError(t, writeFile(t, objectText(without(validFields(t), name))), database.ErrFileFieldMissing)
			})
		}
		t.Run("an empty object: ErrFileFieldMissing", func(t *testing.T) {
			t.Parallel()
			expectFileError(t, writeFile(t, "{}"), database.ErrFileFieldMissing)
		})
	})

	t.Run("If server_id is not an integer, port is not an integer from 1 to 65535, another field is not a non-empty string, or ca_certificate is not one or more PEM blocks of type CERTIFICATE, each an X.509 certificate, and nothing else, then ReadConnectionFile shall return ErrFileFormat.", func(t *testing.T) {
		t.Parallel()
		authorityPEM := func(t *testing.T) string {
			t.Helper()
			return newAuthority(t).pemText
		}
		cases := []struct {
			name  string
			field string
			value func(t *testing.T) string
		}{
			{"server_id a string", fieldServerID, func(*testing.T) string { return `"42"` }},
			{"server_id 1.5", fieldServerID, func(*testing.T) string { return "1.5" }},
			{"server_id null", fieldServerID, func(*testing.T) string { return jsonNull }},
			{"server_id true", fieldServerID, func(*testing.T) string { return "true" }},
			{"port 0", fieldPort, func(*testing.T) string { return "0" }},
			{"port 65536", fieldPort, func(*testing.T) string { return "65536" }},
			{"port -1", fieldPort, func(*testing.T) string { return "-1" }},
			{"port a string", fieldPort, func(*testing.T) string { return `"5432"` }},
			{"port 5432.5", fieldPort, func(*testing.T) string { return "5432.5" }},
			{"ca_certificate not PEM", fieldCertificate, func(*testing.T) string { return strconv.Quote(canary) }},
			{"ca_certificate white space alone, no block", fieldCertificate, func(*testing.T) string { return strconv.Quote(" \n\t\n") }},
			{"ca_certificate a PRIVATE KEY block", fieldCertificate, func(*testing.T) string {
				return strconv.Quote("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
			}},
			{"ca_certificate a CERTIFICATE block that is not a certificate", fieldCertificate, func(*testing.T) string {
				return strconv.Quote("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
			}},
			{"ca_certificate a certificate, then text", fieldCertificate, func(t *testing.T) string {
				t.Helper()
				return strconv.Quote(authorityPEM(t) + canary + "\n")
			}},
			{"ca_certificate text, then a certificate", fieldCertificate, func(t *testing.T) string {
				t.Helper()
				return strconv.Quote(canary + "\n" + authorityPEM(t))
			}},
			{"ca_certificate a certificate, then a PRIVATE KEY block", fieldCertificate, func(t *testing.T) string {
				t.Helper()
				return strconv.Quote(authorityPEM(t) + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
			}},
		}
		for _, name := range []string{fieldHost, fieldDatabase, fieldLogin, fieldPassword, fieldCertificate} {
			cases = append(cases,
				struct {
					name  string
					field string
					value func(t *testing.T) string
				}{name + " empty", name, func(*testing.T) string { return `""` }},
				struct {
					name  string
					field string
					value func(t *testing.T) string
				}{name + " a number", name, func(*testing.T) string { return "5" }})
		}
		for _, entry := range cases {
			t.Run(entry.name+": ErrFileFormat", func(t *testing.T) {
				t.Parallel()
				expectFileError(t, writeFile(t, objectText(with(validFields(t), entry.field, entry.value(t)))), database.ErrFileFormat)
			})
		}
		t.Run("port 1, the lowest, is read", func(t *testing.T) {
			t.Parallel()
			fields := with(validFields(t), fieldPort, "1")
			expectRead(t, writeFile(t, objectText(fields)), readAs(fields, 42, 1))
		})
		t.Run("port 65535, the highest, is read", func(t *testing.T) {
			t.Parallel()
			fields := with(validFields(t), fieldPort, "65535")
			expectRead(t, writeFile(t, objectText(fields)), readAs(fields, 42, 65535))
		})
		t.Run("server_id 0 is read", func(t *testing.T) {
			t.Parallel()
			fields := with(validFields(t), fieldServerID, "0")
			expectRead(t, writeFile(t, objectText(fields)), readAs(fields, 0, 5432))
		})
		t.Run("ca_certificate two certificates is read", func(t *testing.T) {
			t.Parallel()
			fields := with(validFields(t), fieldCertificate, strconv.Quote(authorityPEM(t)+authorityPEM(t)))
			expectRead(t, writeFile(t, objectText(fields)), readAs(fields, 42, 5432))
		})
	})

	t.Run("ReadConnectionFile shall check the file in the order of these lines and return the first refusal that applies.", func(t *testing.T) {
		t.Parallel()
		t.Run("a 70 KiB file the user may not read: ErrFileUnreadable, not ErrFileTooLarge", func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, padTo(t, objectText(validFields(t)), 70<<10))
			keepFromReading(t, path)
			expectFileError(t, path, database.ErrFileUnreadable)
		})
		t.Run("70 KiB that is not JSON: ErrFileTooLarge, not ErrFileFormat", func(t *testing.T) {
			t.Parallel()
			expectFileError(t, writeFile(t, strings.Repeat(canary, (70<<10)/len(canary))), database.ErrFileTooLarge)
		})
		t.Run("a field twice and an unknown field: ErrFileFormat, not ErrFileFieldUnknown", func(t *testing.T) {
			t.Parallel()
			fields := append(validFields(t), field{fieldHost, strconv.Quote(canary)}, field{unknownField, `"disable"`})
			expectFileError(t, writeFile(t, objectText(fields)), database.ErrFileFormat)
		})
		t.Run("an unknown field and a missing one: ErrFileFieldUnknown, not ErrFileFieldMissing", func(t *testing.T) {
			t.Parallel()
			fields := append(without(validFields(t), fieldPort), field{unknownField, `"disable"`})
			expectFileError(t, writeFile(t, objectText(fields)), database.ErrFileFieldUnknown)
		})
		t.Run("a missing field and a port of 0: ErrFileFieldMissing, not ErrFileFormat", func(t *testing.T) {
			t.Parallel()
			fields := with(without(validFields(t), fieldLogin), fieldPort, "0")
			expectFileError(t, writeFile(t, objectText(fields)), database.ErrFileFieldMissing)
		})
	})

	t.Run("ReadConnectionFile shall return an error whose text holds no part of the file's contents.", func(t *testing.T) {
		t.Parallel()
		t.Run("each refusal above is checked for the canary and the certificate's text; a host given twice holding only the canary: ErrFileFormat, its text without the canary", func(t *testing.T) {
			t.Parallel()
			fields := append(validFields(t), field{fieldHost, strconv.Quote(canary + canary)})
			expectFileError(t, writeFile(t, objectText(fields)), database.ErrFileFormat)
		})
	})
}

// TestLinuxConnectionFileMode is Linux's alone: the line checks the file's mode on Linux only.
func TestLinuxConnectionFileMode(t *testing.T) {
	t.Parallel()
	t.Run("If, on Linux, the file's mode lets its group or others read it, then ReadConnectionFile shall return ErrFileReadableByOthers without reading the file.", func(t *testing.T) {
		t.Parallel()
		for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o606, 0o040, 0o004} {
			t.Run("mode "+strconv.FormatUint(uint64(mode), 8)+": ErrFileReadableByOthers", func(t *testing.T) {
				t.Parallel()
				path := writeFile(t, objectText(validFields(t)))
				setFileMode(t, path, mode)
				expectFileError(t, path, database.ErrFileReadableByOthers)
			})
		}
		for _, mode := range []os.FileMode{0o600, 0o620, 0o602, 0o400} {
			t.Run("mode "+strconv.FormatUint(uint64(mode), 8)+", which lets neither read it, is read", func(t *testing.T) {
				t.Parallel()
				fields := validFields(t)
				path := writeFile(t, objectText(fields))
				setFileMode(t, path, mode)
				expectRead(t, path, readAs(fields, 42, 5432))
			})
		}
	})
	t.Run("ReadConnectionFile shall check the file in the order of these lines and return the first refusal that applies.", func(t *testing.T) {
		t.Parallel()
		t.Run("mode 0644 and not JSON: ErrFileReadableByOthers, not ErrFileFormat", func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, canary)
			setFileMode(t, path, 0o644)
			expectFileError(t, path, database.ErrFileReadableByOthers)
		})
		t.Run("mode 0044, which its owner may not read: ErrFileReadableByOthers, not ErrFileUnreadable", func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, objectText(validFields(t)))
			setFileMode(t, path, 0o044)
			expectFileError(t, path, database.ErrFileReadableByOthers)
		})
		t.Run("mode 0644 and 70 KiB: ErrFileReadableByOthers, not ErrFileTooLarge", func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, padTo(t, objectText(validFields(t)), 70<<10))
			setFileMode(t, path, 0o644)
			expectFileError(t, path, database.ErrFileReadableByOthers)
		})
	})
}

// setFileMode sets the file's mode, as a row's case needs it.
func setFileMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("setting %s to %#o: %v", path, mode, err)
	}
}
