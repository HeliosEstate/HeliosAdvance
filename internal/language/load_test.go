// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Load's lines on every system: each refusal with the case just inside it, what it reads once,
// the chain a missing text follows and the keys it ignores. Each refusal row carries exactly one
// fault, so the order Load checks in never decides what the row sees.
package language_test

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/heliosestate/heliosadvance/internal/language"
)

// esFile is a Spanish language file named code, with the parent given unless it is "", holding
// the texts given by short key, each written as given.
func esFile(code, parentCode string, texts map[string]string) string {
	top := []string{entry("name", "Español ("+code+")")}
	if parentCode != "" {
		top = append(top, entry("parent", parentCode))
	}
	var session []string
	for _, key := range []string{shortGreeting, shortNamePrompt, shortNameReply} {
		if text, held := texts[key]; held {
			session = append(session, entry(key, text))
		}
	}
	return fileOf(top, session)
}

// esShown is what each Spanish language's full set of texts shows.
func esShown(code string) shown {
	return shown{"Hola (" + code + ")", "¿Su nombre? (" + code + ") ", "Hola " + callerName + " (" + code + ")", nil}
}

// esTexts is the full set of texts esShown shows for code, leaving out the short keys given.
func esTexts(code string, without ...string) map[string]string {
	texts := map[string]string{
		shortGreeting:   "Hola (" + code + ")",
		shortNamePrompt: "¿Su nombre? (" + code + ") ",
		shortNameReply:  "Hola {$NAME} (" + code + ")",
	}
	for _, key := range without {
		delete(texts, key)
	}
	return texts
}

func TestLoad(t *testing.T) {
	t.Parallel()

	t.Run("If folder cannot be read, then Load shall return ErrFileRefused naming it.", func(t *testing.T) {
		t.Parallel()
		t.Run("no such folder: ErrFileRefused naming it", func(t *testing.T) {
			t.Parallel()
			folder := filepath.Join(t.TempDir(), langFolder)
			expectRefused(t, folder, fallbackCode, folder)
		})
		t.Run("a file in the folder's place: ErrFileRefused naming it", func(t *testing.T) {
			t.Parallel()
			folder := filepath.Join(t.TempDir(), langFolder)
			if err := os.WriteFile(folder, []byte(enUSFile()), 0o600); err != nil {
				t.Fatalf("writing a file where the folder goes: %v", err)
			}
			expectRefused(t, folder, fallbackCode, folder)
		})
		t.Run("a folder that will not open: ErrFileRefused naming it", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			makeUnopenable(t, folder)
			expectRefused(t, folder, fallbackCode, folder)
		})
	})

	t.Run("If a language's folder name is not a well-formed language tag in lower case, then Load shall return ErrFileRefused naming its file.", func(t *testing.T) {
		t.Parallel()
		for name, code := range map[string]string{
			"fr-FR, a region in upper case":    "fr-FR",
			"Fr, a language in upper case":     "Fr",
			"fr_fr, an underscore":             "fr_fr",
			"e, a language of one letter":      "e",
			"fr--fr, an empty subtag":          "fr--fr",
			"abcdefghi, a language of nine":    "abcdefghi",
			"fr-, a hyphen at the end":         "fr-",
			"fr-abcdefghi, a subtag of nine":   "fr-abcdefghi",
			"fr fr, a space":                   "fr fr",
			"fr-ç, a letter outside ASCII":     "fr-ç",
			"fr-fr-, a hyphen after a region":  "fr-fr-",
			"12, a language of digits":         "12",
			"fr-fr.x, a full stop in its name": "fr-fr.x",
		} {
			t.Run(name+": ErrFileRefused naming its file", func(t *testing.T) {
				t.Parallel()
				folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), code: frFile(nil)})
				expectRefused(t, folder, fallbackCode, fileName(code))
			})
		}
		for _, code := range []string{"zh-hant-tw", "de-ch-1996", "sr-latn-rs", "es-419", "fr"} {
			t.Run(code+", well-formed in lower case, the edge inside: loads, and shows its texts as the board's", func(t *testing.T) {
				t.Parallel()
				folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), code: frFile(nil)})
				expectShown(t, expectLoaded(t, folder, code), frShown)
			})
		}
		t.Run("notes/ holding no notes.toml, Bad_Name/ holding no Bad_Name.toml and a file readme.txt: not languages, left alone, loads", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			for _, made := range []string{"notes", "Bad_Name"} {
				if err := os.Mkdir(filepath.Join(folder, made), 0o700); err != nil {
					t.Fatalf("making %s: %v", made, err)
				}
				if err := os.WriteFile(filepath.Join(folder, made, "other.toml"), []byte("not = = toml"), 0o600); err != nil {
					t.Fatalf("writing in %s: %v", made, err)
				}
			}
			if err := os.WriteFile(filepath.Join(folder, "readme.txt"), []byte("not = = toml"), 0o600); err != nil {
				t.Fatalf("writing readme.txt: %v", err)
			}
			expectShown(t, expectLoaded(t, folder, fallbackCode), enUSShown)
		})
	})

	t.Run("If a language's folder or file is a link leading out of folder, or its file cannot be read, then Load shall return ErrFileRefused naming the file.", func(t *testing.T) {
		t.Parallel()
		t.Run("fr-fr's file will not open, the board en-us: ErrFileRefused naming it", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: frFile(nil)})
			makeUnopenable(t, filepath.Join(folder, frFR, fileName(frFR)))
			expectRefused(t, folder, fallbackCode, fileName(frFR))
		})
		t.Run("en-us's file will not open: ErrFileRefused naming it", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			makeUnopenable(t, filepath.Join(folder, fallbackCode, fileName(fallbackCode)))
			expectRefused(t, folder, fallbackCode, fileName(fallbackCode))
		})
	})

	t.Run("If a language's file is over MostFileBytes, then Load shall return ErrFileRefused naming it, having read no more than MostFileBytes and one byte of it.", func(t *testing.T) {
		t.Parallel()
		t.Run("1 MiB and one byte, a valid file padded by a comment: ErrFileRefused naming it", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: padded(t, frFile(nil), mostFileBytes+1)})
			expectRefused(t, folder, frFR, fileName(frFR))
		})
		t.Run("exactly 1 MiB, a valid file padded by a comment, the edge inside: loads, its texts shown", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: padded(t, frFile(nil), mostFileBytes)})
			expectShown(t, expectLoaded(t, folder, frFR), frShown)
		})
		t.Run("en-us itself 1 MiB and one byte: ErrFileRefused naming it", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: padded(t, enUSFile(), mostFileBytes+1)})
			expectRefused(t, folder, fallbackCode, fileName(fallbackCode))
		})
	})

	t.Run("If a language's file is not UTF-8 and TOML 1.1, then Load shall return ErrFileRefused naming it.", func(t *testing.T) {
		t.Parallel()
		for name, contents := range map[string][]byte{
			"a byte 0xFF in a comment":                    []byte(frFile(nil) + "# " + marker + " \xff\n"),
			"a byte 0xFF in the greeting":                 []byte(strings.Replace(frFile(nil), "Bonjour,", "Bonjour\xff,", 1)),
			"the file in UTF-16 with its byte-order mark": utf16File(frFile(nil)),
			"an unclosed string":                          []byte(frFile(map[string]string{shortGreeting: `greeting = "Bonjour ` + marker})),
			"the greeting given twice":                    []byte(frFile(map[string]string{shortGreeting: entry(shortGreeting, frGreeting) + "\n" + entry(shortGreeting, frGreeting)})),
			`a text written "a \{ b", no TOML escape`:     []byte(frFile(map[string]string{shortGreeting: `greeting = "a \{ b ` + marker + `"`})),
			"a key with no value":                         []byte(frFile(map[string]string{shortGreeting: "greeting = "})),
			"a table header never closed":                 []byte(frFile(nil) + "[menu\n"),
		} {
			t.Run(name+": ErrFileRefused naming it", func(t *testing.T) {
				t.Parallel()
				folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
				writeLanguage(t, folder, frFR, contents)
				expectRefused(t, folder, frFR, fileName(frFR))
			})
		}
		t.Run(`TOML 1.1, the edge inside: its name written with \xE7 and a multi-line inline table holding an unknown key, loads, its texts as written`, func(t *testing.T) {
			t.Parallel()
			file := fileOf([]string{`name = "Fran\xE7ais"`, "extra = {", `  unknown = "x",`, `  more = "y",`, "}"}, frSession(nil))
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: file})
			expectShown(t, expectLoaded(t, folder, frFR), frShown)
		})
		t.Run("literal and multi-line strings, the edge inside: loads, its texts as written", func(t *testing.T) {
			t.Parallel()
			file := fileOf([]string{`name = 'Français'`}, []string{
				`greeting = 'Bonjour, BBS Helios Advance !'`,
				"name_prompt = \"\"\"\\\n    Quel est votre nom ? \"\"\"",
				`name_reply = '''Bonjour {$NAME}'''`,
			})
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: file})
			expectShown(t, expectLoaded(t, folder, frFR), frShown)
		})
	})

	t.Run("If a language's file has no name, or a name that is not a string, is empty or holds a control character or a bidi control, as a text may not, then Load shall return ErrFileRefused naming it.", func(t *testing.T) {
		t.Parallel()
		for name, top := range map[string][]string{
			"no name":                 nil,
			"name = 5":                {"name = 5"},
			`name = ["Français"]`:     {`name = ["Français"]`},
			`name = ""`:               {`name = ""`},
			"a name holding U+0007":   {entry("name", "Fran\u0007çais")},
			"a name holding a tab":    {entry("name", "Fran\tçais")},
			"a name holding U+0085":   {entry("name", "Fran\u0085çais")},
			"a name holding U+202E":   {entry("name", "Fran\u202Eçais")},
			"a name holding U+061C":   {entry("name", "Fran\u061Cçais")},
			"a name holding a CR LF":  {entry("name", "Français\r\n")},
			"name given in [session]": nil,
		} {
			t.Run(name+": ErrFileRefused naming it", func(t *testing.T) {
				t.Parallel()
				session := frSession(nil)
				if name == "name given in [session]" {
					session = append(session, entry("name", frName))
				}
				folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: fileOf(top, session)})
				expectRefused(t, folder, frFR, fileName(frFR))
			})
		}
		for name, given := range map[string]string{
			"Français":                                "Français",
			"a name with spaces":                      "Français de France",
			"a name holding U+00A0":                   "Français\u00A0de France",
			"a name of one character":                 "F",
			"a name holding MessageFormat 2's syntax": "Français {$NAME} \\{",
		} {
			t.Run(name+", the edge inside: loads, its texts shown", func(t *testing.T) {
				t.Parallel()
				folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: fileOf([]string{entry("name", given)}, frSession(nil))})
				expectShown(t, expectLoaded(t, folder, frFR), frShown)
			})
		}
	})

	t.Run("If Fallback is not a language in folder, then Load shall return ErrFileRefused naming its file.", func(t *testing.T) {
		t.Parallel()
		t.Run("no en-us folder: ErrFileRefused naming en-us.toml", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{frFR: frFile(nil)})
			expectRefused(t, folder, frFR, fileName(fallbackCode))
		})
		t.Run("en-us/ holding no en-us.toml: ErrFileRefused naming en-us.toml", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{frFR: frFile(nil)})
			if err := os.Mkdir(filepath.Join(folder, fallbackCode), 0o700); err != nil {
				t.Fatalf("making en-us/: %v", err)
			}
			if err := os.WriteFile(filepath.Join(folder, fallbackCode, "fr-fr.toml"), []byte(enUSFile()), 0o600); err != nil {
				t.Fatalf("writing in en-us/: %v", err)
			}
			expectRefused(t, folder, frFR, fileName(fallbackCode))
		})
		t.Run("en-us's file as en-us/EN-US.toml, not its folder's own name: ErrFileRefused naming en-us.toml", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{frFR: frFile(nil)})
			if err := os.Mkdir(filepath.Join(folder, fallbackCode), 0o700); err != nil {
				t.Fatalf("making en-us/: %v", err)
			}
			path := filepath.Join(folder, fallbackCode, "EN-US.toml")
			if err := os.WriteFile(path, []byte(enUSFile()), 0o600); err != nil {
				t.Fatalf("writing en-us/EN-US.toml: %v", err)
			}
			if names := folderNames(t, filepath.Join(folder, fallbackCode)); len(names) != 1 || names[0] != "EN-US.toml" {
				t.Fatalf("en-us/ lists %q, not EN-US.toml alone: a fault in the test", names)
			}
			expectRefused(t, folder, frFR, fileName(fallbackCode))
		})
	})

	t.Run("If code is not a language in folder, then Load shall return ErrNotInstalled.", func(t *testing.T) {
		t.Parallel()
		for name, code := range map[string]string{
			"de-de, absent":                          deDE,
			"../x, a folder beside lang":             "../x",
			"en-us/../fr-fr, a path to fr-fr":        "en-us/../fr-fr",
			"the empty code":                         "",
			"fr-fr/fr-fr.toml, fr-fr's file by path": "fr-fr/fr-fr.toml",
			".., lang's own parent":                  "..",
			"., lang itself":                         ".",
			"fr, a part of fr-fr":                    "fr",
			"fr-fr with a space after":               "fr-fr ",
		} {
			t.Run(name+": ErrNotInstalled", func(t *testing.T) {
				t.Parallel()
				folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: frFile(nil)})
				writeLanguage(t, filepath.Dir(folder), "x", []byte(frFile(nil)))
				expectNotInstalled(t, folder, code)
			})
		}
		t.Run("fr-fr a folder holding no file of its own name: ErrNotInstalled", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			if err := os.Mkdir(filepath.Join(folder, frFR), 0o700); err != nil {
				t.Fatalf("making fr-fr/: %v", err)
			}
			if err := os.WriteFile(filepath.Join(folder, frFR, "other.toml"), []byte(frFile(nil)), 0o600); err != nil {
				t.Fatalf("writing in fr-fr/: %v", err)
			}
			expectNotInstalled(t, folder, frFR)
		})
		for code, want := range map[string]shown{"FR-FR": frShown, "Fr-fR": frShown, "En-Us": enUSShown, "EN-US": enUSShown} {
			t.Run(code+", a code in another case, the edge inside: names the language whatever its case, loads", func(t *testing.T) {
				t.Parallel()
				folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: frFile(nil)})
				expectShown(t, expectLoaded(t, folder, code), want)
			})
		}
		t.Run("AZ-ZA, a code holding the first and the last capital letter, the edge inside: names az-za, loads", func(t *testing.T) {
			t.Parallel()
			const azZA = "az-za"
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), azZA: esFile(azZA, "", esTexts(azZA))})
			expectShown(t, expectLoaded(t, folder, "AZ-ZA"), esShown(azZA))
		})
	})

	t.Run("If a language's file other than Fallback's has a parent that is not a string or names no language in folder, or whose chain of parents leads back to that language, then Load shall return ErrFileRefused naming it.", func(t *testing.T) {
		t.Parallel()
		for name, parentLine := range map[string]string{
			"parent = 1":                          "parent = 1",
			`parent = ["en-us"]`:                  `parent = ["en-us"]`,
			`parent = deDE, absent`:               entry("parent", deDE),
			`parent = frFR, its own`:              entry("parent", frFR),
			`parent = "", the empty code`:         entry("parent", ""),
			`parent = "../x", a folder beside`:    entry("parent", "../x"),
			`parent = "fr-fr/..", a path to lang`: entry("parent", "fr-fr/.."),
		} {
			t.Run(name+": ErrFileRefused naming it", func(t *testing.T) {
				t.Parallel()
				folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: fileOf([]string{entry("name", frName), parentLine}, frSession(nil))})
				writeLanguage(t, filepath.Dir(folder), "x", []byte(frFile(nil)))
				expectRefused(t, folder, frFR, fileName(frFR))
			})
		}
		t.Run("fr-fr and fr-ca each the other's parent: ErrFileRefused naming one of them", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{
				fallbackCode: enUSFile(),
				frFR:         fileOf([]string{entry("name", frName), entry("parent", frCA)}, frSession(nil)),
				frCA:         fileOf([]string{entry("name", "Français (Canada)"), entry("parent", frFR)}, frSession(nil)),
			})
			expectRefusedNaming(t, folder, frFR, fileName(frFR), fileName(frCA))
		})
		t.Run("a loop of three, fr-fr to fr-ca to fr-be and back: ErrFileRefused naming one of them", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{
				fallbackCode: enUSFile(),
				frFR:         fileOf([]string{entry("name", frName), entry("parent", frCA)}, frSession(nil)),
				frCA:         fileOf([]string{entry("name", "Français (Canada)"), entry("parent", "fr-be")}, frSession(nil)),
				"fr-be":      fileOf([]string{entry("name", "Français (Belgique)"), entry("parent", frFR)}, frSession(nil)),
			})
			expectRefusedNaming(t, folder, frFR, fileName(frFR), fileName(frCA), fileName("fr-be"))
		})
		t.Run("a loop the board's chain only reaches, fr-fr to fr-ca and fr-ca to fr-be and back: ErrFileRefused naming one of the loop", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{
				fallbackCode: enUSFile(),
				frFR:         fileOf([]string{entry("name", frName), entry("parent", frCA)}, frSession(nil)),
				frCA:         fileOf([]string{entry("name", "Français (Canada)"), entry("parent", "fr-be")}, frSession(nil)),
				"fr-be":      fileOf([]string{entry("name", "Français (Belgique)"), entry("parent", frCA)}, frSession(nil)),
			})
			expectRefusedNaming(t, folder, frFR, fileName(frCA), fileName("fr-be"), fileName(frFR))
		})
		t.Run("the bad file a language not in the board's chain, de-de's parent absent, the board en-us: ErrFileRefused naming it", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{
				fallbackCode: enUSFile(),
				deDE:         fileOf([]string{entry("name", "Deutsch"), entry("parent", "de-at")}, frSession(nil)),
			})
			expectRefused(t, folder, fallbackCode, fileName(deDE))
		})
		t.Run(`fr-ca's parent = "FR-FR", a code in upper case, the edge inside: loads, fr-ca's missing texts from fr-fr`, func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{
				fallbackCode: enUSFile(),
				frFR:         frFile(nil),
				frCA:         fileOf([]string{entry("name", "Français (Canada)"), entry("parent", "FR-FR")}, nil),
			})
			expectShown(t, expectLoaded(t, folder, frCA), frShown.missingFrom(keyGreeting, keyNamePrompt, keyNameReply))
		})
		for name, parentLine := range map[string]string{
			"naming a language absent":            entry("parent", "xx-yy"),
			"not a string":                        "parent = 5",
			"naming fr-fr, whose parent is en-us": entry("parent", frFR),
			"naming itself":                       entry("parent", fallbackCode),
		} {
			t.Run("en-us's own parent "+name+", ignored, the edge inside: loads", func(t *testing.T) {
				t.Parallel()
				folder := makeLang(t, map[string]string{
					fallbackCode: fileOf([]string{entry("name", enUSName), parentLine}, []string{
						entry(shortGreeting, enUSGreeting), entry(shortNamePrompt, enUSNamePrompt), entry(shortNameReply, enUSNameReply),
					}),
					frFR: fileOf([]string{entry("name", frName), entry("parent", fallbackCode)}, frSession(map[string]string{shortGreeting: ""})),
				})
				expectShown(t, expectLoaded(t, folder, frFR), frShown.from(keyGreeting, enUSShown).missingFrom(keyGreeting))
			})
		}
	})

	t.Run("If Fallback's file does not hold one of the keys above as a text that does not count as missing, then Load shall return ErrFileRefused naming Fallback's file.", func(t *testing.T) {
		t.Parallel()
		enUSWith := func(key, line string) string {
			lines := map[string]string{
				shortGreeting: entry(shortGreeting, enUSGreeting), shortNamePrompt: entry(shortNamePrompt, enUSNamePrompt), shortNameReply: entry(shortNameReply, enUSNameReply),
			}
			lines[key] = line
			var session []string
			for _, each := range []string{shortGreeting, shortNamePrompt, shortNameReply} {
				if lines[each] != "" {
					session = append(session, lines[each])
				}
			}
			return fileOf([]string{entry("name", enUSName)}, session)
		}
		for name, file := range map[string]string{
			"no greeting":                       enUSWith(shortGreeting, ""),
			"no name prompt":                    enUSWith(shortNamePrompt, ""),
			"no name reply":                     enUSWith(shortNameReply, ""),
			"the greeting broken, {":            enUSWith(shortGreeting, entry(shortGreeting, "Hello {")),
			"the greeting holding {$NAME}":      enUSWith(shortGreeting, entry(shortGreeting, "Hello {$NAME}")),
			"the name prompt holding a bell":    enUSWith(shortNamePrompt, entry(shortNamePrompt, "What is your name?\u0007 ")),
			"the name reply holding {$USER}":    enUSWith(shortNameReply, entry(shortNameReply, "Hello {$USER}")),
			"the name reply a number":           enUSWith(shortNameReply, "name_reply = 5"),
			"the name reply a function":         enUSWith(shortNameReply, entry(shortNameReply, "Hello {$NAME :string}")),
			"the greeting a complex message":    enUSWith(shortGreeting, entry(shortGreeting, "{{Hello Helios Advance BBS!}}")),
			"the three texts outside [session]": fileOf([]string{entry("name", enUSName), entry(shortGreeting, enUSGreeting), entry(shortNamePrompt, enUSNamePrompt), entry(shortNameReply, enUSNameReply)}, nil),
		} {
			t.Run(name+": ErrFileRefused naming en-us.toml", func(t *testing.T) {
				t.Parallel()
				folder := makeLang(t, map[string]string{fallbackCode: file, frFR: frFile(nil)})
				expectRefused(t, folder, frFR, fileName(fallbackCode))
			})
		}
		t.Run("the page's en-us file, the edge inside: loads, its texts shown", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile()})
			expectShown(t, expectLoaded(t, folder, fallbackCode), enUSShown)
		})
	})

	t.Run("Load shall read each language's file once, and every language's, not only those in the chain.", func(t *testing.T) {
		t.Parallel()
		t.Run("de-de, outside the board's chain, holding an unclosed string: ErrFileRefused naming de-de.toml", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{
				fallbackCode: enUSFile(),
				frFR:         frFile(nil),
				deDE:         fileOf([]string{entry("name", "Deutsch")}, []string{`greeting = "Hallo ` + marker}),
			})
			expectRefused(t, folder, frFR, fileName(deDE))
		})
		t.Run("the whole lang folder deleted after Load: every Text and Missing unchanged", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{
				fallbackCode: enUSFile(),
				esES:         esFile(esES, "", esTexts(esES)),
				esMX:         esFile(esMX, esES, esTexts(esMX, shortNamePrompt, shortNameReply)),
			})
			texts := expectLoaded(t, folder, esMX)
			want := esShown(esMX).from(keyNamePrompt, esShown(esES)).from(keyNameReply, esShown(esES)).missingFrom(keyNamePrompt, keyNameReply)
			expectShown(t, texts, want)
			if err := os.RemoveAll(folder); err != nil {
				t.Fatalf("deleting the lang folder: %v", err)
			}
			if _, err := os.Stat(folder); !os.IsNotExist(err) {
				t.Fatalf("the lang folder is still there: %v", err)
			}
			expectShown(t, texts, want)
		})
	})

	t.Run("For each key above, Load shall take the text from the first language in the chain for code whose file holds that key as a text that does not count as missing.", func(t *testing.T) {
		t.Parallel()
		// The chain for es-mexico: es-mexico, its parent es-419, es-419's parent es-es, then en-us.
		chain := func(t *testing.T, mexico, latin, spain map[string]string) *language.Texts {
			t.Helper()
			folder := makeLang(t, map[string]string{
				fallbackCode: enUSFile(),
				esMX:         esFile(esMX, "es-419", mexico),
				"es-419":     esFile("es-419", esES, latin),
				esES:         esFile(esES, "", spain),
			})
			return expectLoaded(t, folder, esMX)
		}
		t.Run("every text in the board's own: all from es-mexico, Missing none", func(t *testing.T) {
			t.Parallel()
			got := chain(t, esTexts(esMX), esTexts("es-419"), esTexts(esES))
			expectShown(t, got, esShown(esMX))
		})
		t.Run("the greeting absent from es-mexico, held by es-419 and es-es both: the parent's, es-419's, before the grandparent's, Missing the greeting", func(t *testing.T) {
			t.Parallel()
			got := chain(t, esTexts(esMX, shortGreeting), esTexts("es-419"), esTexts(esES))
			expectShown(t, got, esShown(esMX).from(keyGreeting, esShown("es-419")).missingFrom(keyGreeting))
		})
		t.Run("the name prompt absent from es-mexico and es-419: the parent's parent es-es's, Missing the name prompt", func(t *testing.T) {
			t.Parallel()
			got := chain(t, esTexts(esMX, shortNamePrompt), esTexts("es-419", shortNamePrompt), esTexts(esES))
			expectShown(t, got, esShown(esMX).from(keyNamePrompt, esShown(esES)).missingFrom(keyNamePrompt))
		})
		t.Run("the name reply absent from the whole chain: en-us's, Missing the name reply", func(t *testing.T) {
			t.Parallel()
			got := chain(t, esTexts(esMX, shortNameReply), esTexts("es-419", shortNameReply), esTexts(esES, shortNameReply))
			expectShown(t, got, esShown(esMX).from(keyNameReply, enUSShown).missingFrom(keyNameReply))
		})
		t.Run("es-mexico's greeting broken, {: skipped for es-419's, Missing the greeting", func(t *testing.T) {
			t.Parallel()
			mexico := esTexts(esMX)
			mexico[shortGreeting] = "Hola {"
			got := chain(t, mexico, esTexts("es-419"), esTexts(esES))
			expectShown(t, got, esShown(esMX).from(keyGreeting, esShown("es-419")).missingFrom(keyGreeting))
		})
		t.Run("es-mexico's and es-419's name prompt each counting as missing, a bell and {$NAME}: es-es's", func(t *testing.T) {
			t.Parallel()
			mexico := esTexts(esMX)
			mexico[shortNamePrompt] = "¿Su nombre?\u0007 "
			latin := esTexts("es-419")
			latin[shortNamePrompt] = "¿{$NAME}? "
			got := chain(t, mexico, latin, esTexts(esES))
			expectShown(t, got, esShown(esMX).from(keyNamePrompt, esShown(esES)).missingFrom(keyNamePrompt))
		})
		t.Run("es-mexico holding no text: each from along the chain, Missing all three in the order of the keys", func(t *testing.T) {
			t.Parallel()
			got := chain(t, map[string]string{}, esTexts("es-419", shortNameReply, shortGreeting), esTexts(esES, shortNameReply))
			want := shown{esShown(esES).greeting, esShown("es-419").namePrompt, enUSShown.nameReply, nil}.missingFrom(keyGreeting, keyNamePrompt, keyNameReply)
			expectShown(t, got, want)
		})
		t.Run("the board en-us, other languages lacking texts: en-us's, Missing none", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{
				fallbackCode: enUSFile(),
				esMX:         esFile(esMX, "", map[string]string{}),
			})
			expectShown(t, expectLoaded(t, folder, fallbackCode), enUSShown)
		})
		t.Run("es-mx a sibling of es-es, not its child: es-es's texts never taken, en-us's", func(t *testing.T) {
			t.Parallel()
			folder := makeLang(t, map[string]string{
				fallbackCode: enUSFile(),
				esMX:         esFile(esMX, "", esTexts(esMX, shortGreeting)),
				esES:         esFile(esES, "", esTexts(esES)),
			})
			expectShown(t, expectLoaded(t, folder, esMX), esShown(esMX).from(keyGreeting, enUSShown).missingFrom(keyGreeting))
		})
	})

	t.Run("Load shall ignore a key in a language's file that is not name, parent or one of the keys above.", func(t *testing.T) {
		t.Parallel()
		for name, file := range map[string]string{
			"a top-level version = 3":                 fileOf([]string{entry("name", frName), "version = 3"}, frSession(nil)),
			"a table [menu] holding a text":           fileOf([]string{entry("name", frName)}, frSession(nil), "", "[menu]", entry(shortGreeting, "Menu")),
			"farewell inside [session]":               fileOf([]string{entry("name", frName)}, append(frSession(nil), entry("farewell", "Au revoir"))),
			"farewell holding broken syntax, {":       fileOf([]string{entry("name", frName)}, append(frSession(nil), entry("farewell", "Au revoir {"))),
			"farewell holding a bell":                 fileOf([]string{entry("name", frName)}, append(frSession(nil), entry("farewell", "Au revoir\u0007"))),
			"farewell a number":                       fileOf([]string{entry("name", frName)}, append(frSession(nil), "farewell = 5")),
			"a table inside session, [session.extra]": fileOf([]string{entry("name", frName)}, frSession(nil), "", "[session.extra]", entry("text", "x {")),
			"a key holding the text of a known key":   fileOf([]string{entry("name", frName), entry(shortGreeting, "{$USER}")}, frSession(nil)),
			"session.greeting as a quoted dotted key": fileOf([]string{entry("name", frName), entry(`"session.greeting"`, "Autre")}, frSession(nil)),
		} {
			t.Run(name+": loads, the texts as written", func(t *testing.T) {
				t.Parallel()
				folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: file})
				expectShown(t, expectLoaded(t, folder, frFR), frShown)
			})
		}
	})
}

// padded is file with a comment of spaces added so it is exactly size bytes.
func padded(t *testing.T, file string, size int) string {
	t.Helper()
	room := size - len(file) - len("#\n")
	if room < 0 {
		t.Fatalf("the file is already %d bytes, over %d: a fault in the test", len(file), size)
	}
	made := file + "#" + strings.Repeat(" ", room) + "\n"
	if len(made) != size {
		t.Fatalf("the padded file is %d bytes, not %d: a fault in the test", len(made), size)
	}
	return made
}

// utf16File is text in UTF-16, little-endian, with its byte-order mark.
func utf16File(text string) []byte {
	contents := []byte{0xFF, 0xFE}
	for _, unit := range utf16.Encode([]rune(text)) {
		contents = binary.LittleEndian.AppendUint16(contents, unit)
	}
	return contents
}

// folderNames lists the names in folder as the system gives them.
func folderNames(t *testing.T, folder string) []string {
	t.Helper()
	entries, err := os.ReadDir(folder)
	if err != nil {
		t.Fatalf("listing %s: %v", folder, err)
	}
	var names []string
	for _, each := range entries {
		names = append(names, each.Name())
	}
	return names
}
