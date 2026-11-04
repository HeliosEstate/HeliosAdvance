// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Parsing the connection settings, the JSON the bootstrap unit unseals: each refusal, the order
// they are made in, the edges valid settings may reach, and that no refusal's text holds any
// part of the settings. Every input is bytes written by the test.
package database_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/database"
)

// canary marks the settings' strings, so an error's text can be searched for them.
const canary = "helios-canary-7340"

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

// The valid settings' numbers, chosen so their text is found in an error's text if an error
// quotes them.
const (
	validServerID = 4271
	validPort     = 5487
)

// parseErrors are every refusal ParseConnection may return.
var parseErrors = []error{database.ErrFormat, database.ErrFieldUnknown, database.ErrFieldMissing}

// field is one name and its raw JSON value, in the order the settings give them.
type field struct {
	name  string
	value string
}

// validFields are valid settings' seven fields, each string holding the canary.
func validFields(t *testing.T) []field {
	t.Helper()
	return []field{
		{fieldServerID, strconv.Itoa(validServerID)},
		{fieldHost, strconv.Quote("db-" + canary + ".invalid")},
		{fieldPort, strconv.Itoa(validPort)},
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

// expectParseError parses the text and checks the refusal is want and no other, and that its
// text holds no part of the settings.
func expectParseError(t *testing.T, text string, want error) {
	t.Helper()
	_, err := database.ParseConnection([]byte(text))
	expectOnly(t, err, want, parseErrors)
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

// expectNoContents checks an error's text holds none of what the tests put in the settings: the
// canary in every string, the certificate's text, and the server ID's and port's numbers.
func expectNoContents(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, part := range []string{canary, "BEGIN CERTIFICATE", strconv.Itoa(validServerID), strconv.Itoa(validPort)} {
		if strings.Contains(err.Error(), part) {
			t.Fatalf("the error's text holds part of the settings, %q: %q", part, err.Error())
		}
	}
}

// expectParsed parses the text and checks it is read as the fields give.
func expectParsed(t *testing.T, text string, want database.Connection) {
	t.Helper()
	got, err := database.ParseConnection([]byte(text))
	if err != nil {
		t.Fatalf("valid settings were refused: %v", err)
	}
	if got != want {
		t.Fatalf("the settings were read as %+v, want %+v", got, want)
	}
}

// readAs is what the valid fields read as, with the server ID and port given.
func readAs(fields []field, serverID int64, port uint16) database.Connection {
	text := map[string]string{}
	for _, entry := range fields {
		value, err := strconv.Unquote(entry.value)
		if err == nil {
			text[entry.name] = value
		}
	}
	return database.Connection{ServerID: serverID, Host: text[fieldHost], Port: port, Database: text[fieldDatabase],
		Login: text[fieldLogin], Password: text[fieldPassword], CACertificate: text[fieldCertificate]}
}

func TestParseConnection(t *testing.T) {
	t.Parallel()

	t.Run("If the connection settings are not one JSON object, or give a field twice, then ParseConnection shall return ErrFormat.", func(t *testing.T) {
		t.Parallel()
		cases := map[string]func([]field) string{
			"not JSON":               func([]field) string { return "server_id=42 host=" + canary },
			"no bytes":               func([]field) string { return "" },
			jsonNull:                 func([]field) string { return jsonNull },
			"an array of the object": func(fields []field) string { return "[" + objectText(fields) + "]" },
			"two objects":            func(fields []field) string { return objectText(fields) + objectText(fields) },
			"the object, then text":  func(fields []field) string { return objectText(fields) + " " + canary },
			"the object cut short":   func(fields []field) string { text := objectText(fields); return text[:len(text)-1] },
			"host given twice": func(fields []field) string {
				return objectText(append(fields, field{fieldHost, strconv.Quote(canary)}))
			},
			"server_id given twice, the same value": func(fields []field) string {
				return objectText(append(fields, field{fieldServerID, strconv.Itoa(validServerID)}))
			},
		}
		for name, text := range cases {
			t.Run(name+": ErrFormat", func(t *testing.T) {
				t.Parallel()
				expectParseError(t, text(validFields(t)), database.ErrFormat)
			})
		}
	})

	t.Run("If the object holds a field whose name is not exactly one of server_id, host, port, database, login, password and ca_certificate, then ParseConnection shall return ErrFieldUnknown.", func(t *testing.T) {
		t.Parallel()
		for _, name := range []string{unknownField, "Host", "PORT", "password "} {
			t.Run(strconv.Quote(name)+" beside the seven: ErrFieldUnknown", func(t *testing.T) {
				t.Parallel()
				expectParseError(t, objectText(append(validFields(t), field{name, strconv.Quote(canary)})), database.ErrFieldUnknown)
			})
		}
	})

	t.Run("If the object lacks one of those seven fields, then ParseConnection shall return ErrFieldMissing.", func(t *testing.T) {
		t.Parallel()
		for _, name := range []string{fieldServerID, fieldHost, fieldPort, fieldDatabase, fieldLogin, fieldPassword, fieldCertificate} {
			t.Run(name+" left out: ErrFieldMissing", func(t *testing.T) {
				t.Parallel()
				expectParseError(t, objectText(without(validFields(t), name)), database.ErrFieldMissing)
			})
		}
		t.Run("an empty object: ErrFieldMissing", func(t *testing.T) {
			t.Parallel()
			expectParseError(t, "{}", database.ErrFieldMissing)
		})
	})

	t.Run("If server_id is not an integer, port is not an integer from 1 to 65535, another field is not a non-empty string, or ca_certificate is not one or more PEM blocks of type CERTIFICATE, each an X.509 certificate, and nothing else, then ParseConnection shall return ErrFormat.", func(t *testing.T) {
		t.Parallel()
		authorityPEM := func(t *testing.T) string {
			t.Helper()
			return newAuthority(t).pemText
		}
		type kindCase struct {
			name  string
			field string
			value func(t *testing.T) string
		}
		cases := []kindCase{
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
				kindCase{name + " empty", name, func(*testing.T) string { return `""` }},
				kindCase{name + " a number", name, func(*testing.T) string { return "5" }})
		}
		for _, entry := range cases {
			t.Run(entry.name+": ErrFormat", func(t *testing.T) {
				t.Parallel()
				expectParseError(t, objectText(with(validFields(t), entry.field, entry.value(t))), database.ErrFormat)
			})
		}
		t.Run("port 1, the lowest, is read", func(t *testing.T) {
			t.Parallel()
			fields := with(validFields(t), fieldPort, "1")
			expectParsed(t, objectText(fields), readAs(fields, validServerID, 1))
		})
		t.Run("port 65535, the highest, is read", func(t *testing.T) {
			t.Parallel()
			fields := with(validFields(t), fieldPort, "65535")
			expectParsed(t, objectText(fields), readAs(fields, validServerID, 65535))
		})
		t.Run("server_id 0 is read", func(t *testing.T) {
			t.Parallel()
			fields := with(validFields(t), fieldServerID, "0")
			expectParsed(t, objectText(fields), readAs(fields, 0, validPort))
		})
		t.Run("ca_certificate two certificates is read", func(t *testing.T) {
			t.Parallel()
			fields := with(validFields(t), fieldCertificate, strconv.Quote(authorityPEM(t)+authorityPEM(t)))
			expectParsed(t, objectText(fields), readAs(fields, validServerID, validPort))
		})
	})

	t.Run("ParseConnection shall check the connection settings in the order of these lines and return the first refusal that applies.", func(t *testing.T) {
		t.Parallel()
		t.Run("not JSON, with an unknown field's name in it: ErrFormat, not ErrFieldUnknown", func(t *testing.T) {
			t.Parallel()
			expectParseError(t, `{"`+unknownField+`": "disable", `+canary, database.ErrFormat)
		})
		t.Run("a field twice and an unknown field: ErrFormat, not ErrFieldUnknown", func(t *testing.T) {
			t.Parallel()
			fields := append(validFields(t), field{fieldHost, strconv.Quote(canary)}, field{unknownField, `"disable"`})
			expectParseError(t, objectText(fields), database.ErrFormat)
		})
		t.Run("an unknown field and a missing one: ErrFieldUnknown, not ErrFieldMissing", func(t *testing.T) {
			t.Parallel()
			fields := append(without(validFields(t), fieldPort), field{unknownField, `"disable"`})
			expectParseError(t, objectText(fields), database.ErrFieldUnknown)
		})
		t.Run("a missing field and a port of 0: ErrFieldMissing, not ErrFormat", func(t *testing.T) {
			t.Parallel()
			fields := with(without(validFields(t), fieldLogin), fieldPort, "0")
			expectParseError(t, objectText(fields), database.ErrFieldMissing)
		})
	})

	t.Run("ParseConnection shall return an error whose text holds no part of the connection settings.", func(t *testing.T) {
		t.Parallel()
		t.Run("each refusal above is checked for every field's value; a host given twice holding only the canary: ErrFormat, its text without the canary", func(t *testing.T) {
			t.Parallel()
			fields := append(validFields(t), field{fieldHost, strconv.Quote(canary + canary)})
			expectParseError(t, objectText(fields), database.ErrFormat)
		})
		t.Run("a port of 70000, out of range: ErrFormat, its text without 70000", func(t *testing.T) {
			t.Parallel()
			_, err := database.ParseConnection([]byte(objectText(with(validFields(t), fieldPort, "70000"))))
			expectOnly(t, err, database.ErrFormat, parseErrors)
			if err != nil && strings.Contains(err.Error(), "70000") {
				t.Fatalf("the error's text holds the port: %q", err.Error())
			}
		})
	})
}
