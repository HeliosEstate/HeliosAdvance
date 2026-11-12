// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The language files' lines, driven from outside: each row links the built program into a folder
// of its own, writes a lang folder beside it with the test's own TOML writer, starts it on a row of
// the shared board, and reads what a scripted caller is shown and what the local log holds.
package main_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// The page's option, keys and limit, written here so a changed constant in the engine cannot move
// a test with it.
const (
	langOption        = "-lang"
	fallbackCode      = "en-us"
	keyGreeting       = "session.greeting"
	keyNamePrompt     = "session.name_prompt"
	keyNameReply      = "session.name_reply"
	shortGreeting     = "greeting"
	shortNamePrompt   = "name_prompt"
	shortNameReply    = "name_reply"
	mostLanguageBytes = 1 << 20
)

// The page's en-us file's texts, word for word.
const (
	enUSName       = "English (United States)"
	enUSGreeting   = "Hello Helios Advance BBS!"
	enUSNamePrompt = "What is your name? "
	enUSNameReply  = "Hello {$NAME}"
)

// A full French translation, each text distinct from en-us's, and the codes the rows write.
const (
	frName       = "Français"
	frGreeting   = "Bonjour, BBS Helios Advance !"
	frNamePrompt = "Quel est votre nom ? "
	frNameReply  = "Bonjour {$NAME} !"
	frFR         = "fr-fr"
	frCA         = "fr-ca"
	frBare       = "fr"
	deDE         = "de-de"
)

// startedKey is the local log's key for the started line.
const startedKey = "started"

// The greetings fr-fr and fr give where the chain of parents is the row's case.
const (
	fromFrFR = "Allo de fr-fr"
	fromFr   = "Allo de fr"
)

// languageCaller is the name the rows' callers type.
const languageCaller = "ann"

// tomlString writes text as a TOML basic string: the quotation mark, the backslash and every
// control character escaped as TOML 1.0 and 1.1 both read them, so the file holds exactly the
// characters text names.
func tomlString(text string) string {
	var written strings.Builder
	written.WriteByte('"')
	for _, character := range text {
		switch {
		case character == '"':
			written.WriteString(`\"`)
		case character == '\\':
			written.WriteString(`\\`)
		case character < 0x20 || (character >= 0x7F && character <= 0x9F):
			fmt.Fprintf(&written, `\u%04X`, character)
		default:
			written.WriteRune(character)
		}
	}
	written.WriteByte('"')
	return written.String()
}

// entry is one TOML key and its string value.
func entry(key, text string) string {
	return key + " = " + tomlString(text)
}

// languageFile is a language file's text: the lines given for its top, then the table session
// holding the lines given for it, then the lines given after it.
func languageFile(top, session []string, after ...string) string {
	lines := append(slices.Clone(top), "", "[session]")
	lines = append(lines, session...)
	lines = append(lines, after...)
	return strings.Join(lines, "\n") + "\n"
}

// texts is a language's three texts by their names inside the table session; a text left
// empty is left out of the file.
type texts struct{ greeting, namePrompt, nameReply string }

var (
	enUSTexts = texts{enUSGreeting, enUSNamePrompt, enUSNameReply}
	frTexts   = texts{frGreeting, frNamePrompt, frNameReply}
)

// lines is the table session's lines for the texts.
func (each texts) lines() []string {
	var lines []string
	for _, text := range []struct{ key, text string }{
		{shortGreeting, each.greeting}, {shortNamePrompt, each.namePrompt}, {shortNameReply, each.nameReply},
	} {
		if text.text != "" {
			lines = append(lines, entry(text.key, text.text))
		}
	}
	return lines
}

// fileWith is a language file named name, with parent when it is not empty, holding the texts.
func fileWith(name, parent string, each texts) string {
	top := []string{entry("name", name)}
	if parent != "" {
		top = append(top, entry("parent", parent))
	}
	return languageFile(top, each.lines())
}

// enUSFile is the page's en-us file, and frFile the full French one with no parent.
func enUSFile() string { return fileWith(enUSName, "", enUSTexts) }
func frFile() string   { return fileWith(frName, "", frTexts) }

// placeProgram links the built program into a folder of the row's own, where a row writes the
// lang folder the program is to read beside it, and returns the folder and the program's path.
// A link is the program itself under a second name, in that folder.
func placeProgram(t *testing.T) (folder, program string) {
	t.Helper()
	if buildFailure != nil {
		t.Fatalf("the program did not build: %v", buildFailure)
	}
	folder = t.TempDir()
	program = filepath.Join(folder, filepath.Base(programPath))
	if err := os.Link(programPath, program); err != nil {
		t.Fatalf("linking the program into the row's folder: %v", err)
	}
	return folder, program
}

// writeLangFile writes contents at the path given inside folder's lang folder, written with
// slashes, making the folders on the way.
func writeLangFile(t *testing.T, folder, inside string, contents []byte) {
	t.Helper()
	path := filepath.Join(folder, langFolder, filepath.FromSlash(inside))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("making the folder for %s: %v", inside, err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("writing %s: %v", inside, err)
	}
}

// languagePath is where a language's file sits inside the lang folder, written with slashes.
func languagePath(code string) string {
	return code + "/" + code + ".toml"
}

// writeLanguages writes each language given as its code and its file's text.
func writeLanguages(t *testing.T, folder string, languages map[string]string) {
	t.Helper()
	for code, text := range languages {
		writeLangFile(t, folder, languagePath(code), []byte(text))
	}
}

// boardWith places the program beside a lang folder holding the languages given, and returns
// the program's path.
func boardWith(t *testing.T, languages map[string]string) string {
	t.Helper()
	folder, program := placeProgram(t)
	writeLanguages(t, folder, languages)
	return program
}

// startPlaced starts the program at the path given, on a row of the shared board at ports the
// system picks, with the options given after.
func startPlaced(t *testing.T, program string, options ...string) *run {
	t.Helper()
	arguments := append([]string{databaseOption, sharedRowFile(t), portOption, "0"}, options...)
	return startCommand(t, exec.CommandContext(t.Context(), program, arguments...))
}

// telnetAmidMissing waits for the started line among the program's opening lines and returns its
// Telnet addresses. The page does not say whether a text_missing line comes before the started
// line or after it, so one before it is passed over; anything else first fails the row.
func (program *run) telnetAmidMissing(t *testing.T) []string {
	t.Helper()
	deadline := time.Now().Add(startLimit)
	for index := 0; ; index++ {
		key, value, _ := program.waitForLine(t, index, deadline)
		switch key {
		case textMissingKey:
			continue
		case startedKey:
			return telnetAlone(t, strings.Split(value, ","))
		}
		t.Fatalf("the program's log's line %d is %s=%s, want a started line; its log:\n%s", index+1, key, value, program.text())
	}
}

// shownTo is what a caller who agreed to ECHO is shown through a whole call, after the opening:
// the greeting and CR LF, the name prompt, the name as typed echoed with CR LF, and the name
// reply with the name in it and CR LF.
func shownTo(name, greeting, namePrompt, nameReply string) string {
	return greeting + "\r\n" + namePrompt + name + "\r\n" + nameReply + "\r\n"
}

// tryCall makes one whole call at the address without failing the row, so a goroutine may make
// it: the opening read, the eight requests answered, the name typed with CR, and everything
// after the opening read to the end of the stream, which must come within the hang bound.
func tryCall(address, name string) (string, error) {
	bound := testrun.Patient(testrun.HangBound)
	opened, err := (&net.Dialer{Timeout: bound}).Dial("tcp", address)
	if err != nil {
		return "", err
	}
	defer func() { _ = opened.Close() }()
	_ = opened.SetDeadline(time.Now().Add(bound))
	received := make([]byte, len(opening))
	if _, err := io.ReadFull(opened, received); err != nil || !slices.Equal(received, opening) {
		return "", fmt.Errorf("the opening was % x, want % x: %w", received, opening, err)
	}
	if _, err := opened.Write(append(slices.Clone(answers), name+"\r"...)); err != nil {
		return "", err
	}
	rest, err := io.ReadAll(opened)
	if err != nil {
		return string(rest), fmt.Errorf("the call did not end within %v: %w", bound, err)
	}
	return string(rest), nil
}

// expectShown makes one whole call at the address and fails the row unless the caller is shown
// exactly want after the opening, then the end of the stream.
func expectShown(t *testing.T, address, name, want string) {
	t.Helper()
	got, err := tryCall(address, name)
	if err != nil || got != want {
		t.Fatalf("the caller was shown %q and %v, want %q and the end", got, err, want)
	}
}

// stoppedLog stops the program with the stop signal prepared before it started, then checks its
// whole local log as expectLog does but in any order, and returns its lines as key and value.
func stoppedLog(t *testing.T, program *run, send func(*testing.T, *run) (time.Time, time.Time)) [][2]string {
	t.Helper()
	stopProgram(t, program, send)
	text := program.text()
	var keys []string
	var lines [][2]string
	for line := range strings.SplitSeq(strings.TrimSuffix(text, "\n"), "\n") {
		if line == "" {
			continue
		}
		key, value, _ := strings.Cut(line, "=")
		keys = append(keys, key)
		lines = append(lines, [2]string{key, value})
	}
	expectLogText(t, text, keys...)
	return lines
}

// expectMissingLog stops the program and checks its log holds one started line and, for each key
// given, one text_missing line naming code and that key and no other key, and nothing else, in
// any order.
func expectMissingLog(t *testing.T, program *run, send func(*testing.T, *run) (time.Time, time.Time), code string, keys ...string) {
	t.Helper()
	lines := stoppedLog(t, program, send)
	started := 0
	named := map[string]int{}
	allKeys := []string{keyGreeting, keyNamePrompt, keyNameReply}
	for _, line := range lines {
		switch line[0] {
		case startedKey:
			started++
			continue
		case textMissingKey:
		default:
			t.Fatalf("the log holds a %s line, want started and text_missing alone: %v", line[0], lines)
		}
		value := unquoted(line[1])
		if !strings.Contains(value, code) {
			t.Fatalf("the text_missing line %q does not name the board's language %s", value, code)
		}
		count := 0
		for _, key := range allKeys {
			if strings.Contains(value, key) {
				named[key]++
				count++
			}
		}
		if count != 1 {
			t.Fatalf("the text_missing line %q names %d of the texts, want one", value, count)
		}
	}
	if started != 1 {
		t.Fatalf("the log holds %d started lines, want one: %v", started, lines)
	}
	want := map[string]int{}
	for _, key := range keys {
		want[key] = 1
	}
	if len(named) != len(want) {
		t.Fatalf("the text_missing lines name %v, want one line each for %q", named, keys)
	}
	for key, count := range named {
		if want[key] != count {
			t.Fatalf("the text_missing lines name %v, want one line each for %q", named, keys)
		}
	}
}

// unquoted is a log value as the sysop reads it: a quoted value with its quoting undone.
func unquoted(value string) string {
	if text, err := strconv.Unquote(value); err == nil {
		return text
	}
	return value
}

// expectRefusalNaming waits for a program that must refuse to start and checks its one
// start_failed line names what is given, such as a file's name or a code.
func expectRefusalNaming(t *testing.T, program *run, named string) {
	t.Helper()
	reason := unquoted(program.expectRefusal(t))
	if !strings.Contains(reason, named) {
		t.Fatalf("the start_failed line %q does not name %q", reason, named)
	}
}

// folderWord matches the folder called name, named as a word of its own, by itself or at the end of
// a path: not followed by a path separator, as a path to something inside it is, nor by .toml, as
// a language's own file is. A word joined to others by an underscore or a hyphen does not count:
// the row's own temporary folder is named after the row, and holds such words.
func folderWord(name string) *regexp.Regexp {
	return regexp.MustCompile(`(^|[^A-Za-z0-9_-])` + regexp.QuoteMeta(name) + `($|[^A-Za-z0-9_./\\-]|\.$|\.[^A-Za-z0-9])`)
}

// langWord is the lang folder named as a word of its own, so that a word such as "language",
// which a refusal may hold whatever it names, or a path to the folder the program sits in, does
// not count.
var langWord = folderWord(langFolder)

// expectRefusalNamingLang waits for a program that must refuse to start and checks its one
// start_failed line names the lang folder.
func expectRefusalNamingLang(t *testing.T, program *run) {
	t.Helper()
	reason := unquoted(program.expectRefusal(t))
	if !langWord.MatchString(reason) {
		t.Fatalf("the start_failed line %q does not name the lang folder", reason)
	}
}

// startAt starts the program from a board folder holding the languages given, with the stop
// signal prepared first, and returns it, its stop and its first Telnet address.
func startAt(t *testing.T, languages map[string]string, options ...string) (*run, func(*testing.T, *run) (time.Time, time.Time), string) {
	t.Helper()
	send := stopSignals()[0].prepare(t)
	program := startPlaced(t, boardWith(t, languages), options...)
	return program, send, program.telnetAmidMissing(t)[0]
}

// missingFrom is the French file with the text under key short replaced by text, or left out when
// text is empty.
func missingFrom(short, text string) string {
	each := frTexts
	switch short {
	case shortGreeting:
		each.greeting = text
	case shortNamePrompt:
		each.namePrompt = text
	case shortNameReply:
		each.nameReply = text
	}
	return fileWith(frName, "", each)
}

// withName is a name reply as shown, the name put in place of {$NAME}.
func withName(nameReply, name string) string {
	return strings.ReplaceAll(nameReply, "{$NAME}", name)
}

// enUSShown and frShown are a whole call as en-us's and fr-fr's texts show it to name.
func enUSShown(name string) string {
	return shownTo(name, enUSGreeting, enUSNamePrompt, withName(enUSNameReply, name))
}

func frShown(name string) string {
	return shownTo(name, frGreeting, frNamePrompt, withName(frNameReply, name))
}

// shownWithEnUS is a call fr-fr's texts show, with the text under short taken from en-us.
func shownWithEnUS(short, name string) string {
	greeting, namePrompt, nameReply := frGreeting, frNamePrompt, withName(frNameReply, name)
	switch short {
	case shortGreeting:
		greeting = enUSGreeting
	case shortNamePrompt:
		namePrompt = enUSNamePrompt
	case shortNameReply:
		nameReply = withName(enUSNameReply, name)
	}
	return shownTo(name, greeting, namePrompt, nameReply)
}

// keyOf is a text's key as the page names it, from its name inside the table session.
func keyOf(short string) string {
	return "session." + short
}

// expectCountedMissing is the row for a French text under short that counts as missing: the
// caller is shown en-us's text in its place, and the log holds one text_missing line for it.
func expectCountedMissing(t *testing.T, short, text string) {
	t.Helper()
	program, send, address := startAt(t, map[string]string{fallbackCode: enUSFile(), frFR: missingFrom(short, text)}, langOption, frFR)
	expectShown(t, address, languageCaller, shownWithEnUS(short, languageCaller))
	expectMissingLog(t, program, send, frFR, keyOf(short))
}

// nestedBrackets is the file around makes of a text of opening brackets, sized so the file is
// exactly 1 MiB, the most the size line lets through, so a refusal is for the brackets alone. The
// frame is measured around one bracket, since around leaves an empty text's line out.
func nestedBrackets(t *testing.T, around func(text string) string) string {
	t.Helper()
	file := around(strings.Repeat("{", mostLanguageBytes-len(around("{"))+1))
	if len(file) != mostLanguageBytes {
		t.Fatalf("the nested-brackets file is %d bytes, want exactly %d", len(file), mostLanguageBytes)
	}
	return file
}

func TestLanguageLines(t *testing.T) {
	t.Parallel()

	t.Run("The engine shall read each language from `lang/<code>/<code>.toml` in the folder holding its executable, `<code>` being the language's tag in lower case, once, when it starts.", func(t *testing.T) {
		t.Parallel()
		t.Run("run from a working folder holding another lang: the texts of the lang beside the executable", func(t *testing.T) {
			t.Parallel()
			elsewhere := t.TempDir()
			writeLanguages(t, elsewhere, map[string]string{fallbackCode: fileWith(enUSName, "", texts{"Elsewhere", "Where? ", "Hi {$NAME}"})})
			command := exec.CommandContext(t.Context(), boardWith(t, map[string]string{fallbackCode: enUSFile()}), databaseOption, sharedRowFile(t), portOption, "0")
			command.Dir = elsewhere
			program := startCommand(t, command)
			expectShown(t, program.telnetAmidMissing(t)[0], languageCaller, enUSShown(languageCaller))
		})
		t.Run("after the start, fr-fr's file rewritten and en-us's removed: a caller is shown the texts as they were at the start", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			// fr-fr lacks the prompt, so the call needs en-us's file as it was at the start too.
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile(), frFR: missingFrom(shortNamePrompt, "")})
			program := startPlaced(t, programFile, langOption, frFR)
			address := program.telnetAmidMissing(t)[0]
			writeLangFile(t, folder, languagePath(frFR), []byte(fileWith(frName, "", texts{"Changed", "Changed? ", "Changed {$NAME}"})))
			if err := os.Remove(filepath.Join(folder, langFolder, filepath.FromSlash(languagePath(fallbackCode)))); err != nil {
				t.Fatalf("removing en-us's file after the start: %v", err)
			}
			expectShown(t, address, languageCaller, shownWithEnUS(shortNamePrompt, languageCaller))
		})
		t.Run("-lang FR-FR names the folder fr-fr: fr-fr's texts", func(t *testing.T) {
			t.Parallel()
			_, _, address := startAt(t, map[string]string{fallbackCode: enUSFile(), frFR: frFile()}, langOption, "FR-FR")
			expectShown(t, address, languageCaller, frShown(languageCaller))
		})
	})

	t.Run("The engine shall take a language file's `name` as the language's name, and its `parent`, when present, as the code of the language that fills in its missing texts.", func(t *testing.T) {
		t.Parallel()
		t.Run("a name of characters beyond ASCII, Français: it starts and shows fr-fr's texts", func(t *testing.T) {
			t.Parallel()
			_, _, address := startAt(t, map[string]string{fallbackCode: enUSFile(), frFR: frFile()}, langOption, frFR)
			expectShown(t, address, languageCaller, frShown(languageCaller))
		})
		t.Run("name = 5, not a string: start_failed naming fr-fr.toml", func(t *testing.T) {
			t.Parallel()
			program := startPlaced(t, boardWith(t, map[string]string{
				fallbackCode: enUSFile(), frFR: languageFile([]string{"name = 5"}, frTexts.lines()),
			}), langOption, frFR)
			expectRefusalNaming(t, program, frFR+".toml")
		})
		t.Run("fr-ca with parent fr-fr and no greeting: fr-fr's greeting", func(t *testing.T) {
			t.Parallel()
			_, _, address := startAt(t, map[string]string{
				fallbackCode: enUSFile(), frFR: frFile(),
				frCA: fileWith("Français (Canada)", frFR, texts{"", "Votre nom ? ", "Salut {$NAME}"}),
			}, langOption, frCA)
			expectShown(t, address, languageCaller, shownTo(languageCaller, frGreeting, "Votre nom ? ", withName("Salut {$NAME}", languageCaller)))
		})
	})

	t.Run("The engine shall be released with `lang/en-us/en-us.toml` holding every text it shows, in English (United States).", func(t *testing.T) {
		t.Parallel()
		t.Run("the shipped lang folder and no -lang: the page's en-us texts byte for byte, and no text_missing line", func(t *testing.T) {
			t.Parallel()
			send := stopSignals()[0].prepare(t)
			program := startProgram(t, portOption, "0")
			expectShown(t, program.telnetAmidMissing(t)[0], languageCaller, enUSShown(languageCaller))
			expectMissingLog(t, program, send, fallbackCode)
		})
	})

	t.Run("The engine shall ignore a key in a language file that names no text it shows.", func(t *testing.T) {
		t.Parallel()
		t.Run("fr-fr with a top-level version, a table menu and session.farewell: it starts, shows fr-fr's texts, and logs no text_missing", func(t *testing.T) {
			t.Parallel()
			file := languageFile([]string{entry("name", frName), entry("version", "2")},
				append(frTexts.lines(), entry("farewell", "Au revoir")), "", "[menu]", entry("title", "Menu"))
			program, send, address := startAt(t, map[string]string{fallbackCode: enUSFile(), frFR: file}, langOption, frFR)
			expectShown(t, address, languageCaller, frShown(languageCaller))
			expectMissingLog(t, program, send, frFR)
		})
	})

	t.Run("When started with `-lang` and a code, the engine shall show its texts in that language, and without it, in en-us.", func(t *testing.T) {
		t.Parallel()
		t.Run("-lang fr-fr over Telnet: fr-fr's greeting, prompt and reply, byte for byte", func(t *testing.T) {
			t.Parallel()
			_, _, address := startAt(t, map[string]string{fallbackCode: enUSFile(), frFR: frFile()}, langOption, frFR)
			expectShown(t, address, languageCaller, frShown(languageCaller))
		})
		t.Run("no -lang, with fr-fr present: en-us's texts, byte for byte", func(t *testing.T) {
			t.Parallel()
			_, _, address := startAt(t, map[string]string{fallbackCode: enUSFile(), frFR: frFile()})
			expectShown(t, address, languageCaller, enUSShown(languageCaller))
		})
		t.Run("-lang fr-fr over Telnet over TLS: fr-fr's greeting, prompt and reply, byte for byte", func(t *testing.T) {
			t.Parallel()
			files := goodTLSFiles(t, tlsP256)
			program := startPlaced(t, boardWith(t, map[string]string{fallbackCode: enUSFile(), frFR: frFile()}),
				tlsCertificateOption, files.certificate, tlsKeyOption, files.key, tlsPortOption, "0", langOption, frFR)
			_, _, telnets := threeKinds(t, program.listeners(t))
			call := dialTLS(t, telnets[0], tlsConfig(tls.VersionTLS13))
			call.readExactly(t, opening, time.Now().Add(testrun.Patient(testrun.HangBound)))
			call.send(t, append(slices.Clone(answers), languageCaller+"\r"...))
			call.readExactly(t, []byte(frShown(languageCaller)), time.Now().Add(testrun.Patient(testrun.HangBound)))
			call.expectClosedInChannel(t, time.Now().Add(testrun.Patient(testrun.HangBound)))
		})
	})

	t.Run("If `-lang` names no language the `lang` folder holds, then the engine shall write one `start_failed` line to the local log saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		// x/x.toml beside lang is where a code made into a path would land, and fr-fr where
		// en-us/../fr-fr cleaned as a path would: a program that does either starts, and fails.
		for _, each := range []struct{ name, code string }{
			{"de-de, which lang does not hold", deDE},
			{"../x, with a valid x/x.toml beside lang", "../x"},
			{"en-us/../fr-fr, with fr-fr in lang", "en-us/../fr-fr"},
			{"fr-be, a folder in lang holding no file", "fr-be"},
		} {
			t.Run(each.name+": one start_failed line naming the code as given, and a non-zero exit", func(t *testing.T) {
				t.Parallel()
				folder, programFile := placeProgram(t)
				writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile(), frFR: frFile()})
				beside := filepath.Join(folder, "x")
				if err := os.Mkdir(beside, 0o700); err != nil {
					t.Fatalf("making x beside lang: %v", err)
				}
				if err := os.WriteFile(filepath.Join(beside, "x.toml"), []byte(frFile()), 0o600); err != nil {
					t.Fatalf("writing x/x.toml beside lang: %v", err)
				}
				if err := os.Mkdir(filepath.Join(folder, langFolder, "fr-be"), 0o700); err != nil {
					t.Fatalf("making an empty folder in lang: %v", err)
				}
				expectRefusalNaming(t, startPlaced(t, programFile, langOption, each.code), each.code)
			})
		}
		t.Run("the empty code: one start_failed line saying so as for de-de, which lang does not hold, and a non-zero exit", func(t *testing.T) {
			t.Parallel()
			// Load counts the empty code as one that names no language, as it does de-de, and
			// the rows above prove the program's line for such a code says so by naming it. No
			// check of the words alone tells that from another refusal naming lang or the option,
			// so the empty code's line must be de-de's from the same folder, de-de taken out.
			programFile := boardWith(t, map[string]string{fallbackCode: enUSFile()})
			unknown := unquoted(startPlaced(t, programFile, langOption, deDE).expectRefusal(t))
			if !strings.Contains(unknown, deDE) {
				t.Fatalf("the start_failed line for -lang %s, %q, does not name it", deDE, unknown)
			}
			empty := unquoted(startPlaced(t, programFile, langOption, "").expectRefusal(t))
			if want := strings.ReplaceAll(unknown, deDE, ""); empty != want {
				t.Fatalf("the start_failed line for the empty code is %q, not de-de's with de-de taken out, %q", empty, want)
			}
		})
	})

	t.Run("The engine shall take the greeting from the text `session.greeting`, the name prompt from `session.name_prompt` and the name reply from `session.name_reply`, with `{$NAME}` the name.", func(t *testing.T) {
		t.Parallel()
		t.Run("a distinct text under each key: each where its key puts it, and Bonjour {$NAME} ! gives Bonjour ann !", func(t *testing.T) {
			t.Parallel()
			_, _, address := startAt(t, map[string]string{
				fallbackCode: enUSFile(), frFR: fileWith(frName, "", texts{"G-text", "P-text ", "Bonjour {$NAME} !"}),
			}, langOption, frFR)
			expectShown(t, address, languageCaller, shownTo(languageCaller, "G-text", "P-text ", "Bonjour ann !"))
		})
	})

	t.Run("When a text is missing from the board's language, the engine shall take it from each parent in turn, starting with that language's own, and then from en-us.", func(t *testing.T) {
		t.Parallel()
		// fr-ca's parent is fr-fr, whose parent is fr; fr-ca holds every text but the greeting.
		caFile := fileWith("Français (Canada)", frFR, texts{"", frNamePrompt, frNameReply})
		for _, each := range []struct {
			name             string
			frFRText, frText string
			want             string
		}{
			{"the greeting from the parent, fr-fr", fromFrFR, "", fromFrFR},
			{"the greeting from the parent's parent, fr", "", fromFr, fromFr},
			{"the greeting from en-us, held by none of the chain", "", "", enUSGreeting},
			{"the parent's greeting before the parent's parent's", fromFrFR, fromFr, fromFrFR},
		} {
			t.Run(each.name+", and one text_missing line naming fr-ca and session.greeting", func(t *testing.T) {
				t.Parallel()
				program, send, address := startAt(t, map[string]string{
					fallbackCode: enUSFile(), frCA: caFile,
					frFR:   fileWith(frName, frBare, texts{each.frFRText, frNamePrompt, frNameReply}),
					frBare: fileWith("Français", "", texts{each.frText, frNamePrompt, frNameReply}),
				}, langOption, frCA)
				expectShown(t, address, languageCaller, shownTo(languageCaller, each.want, frNamePrompt, withName(frNameReply, languageCaller)))
				expectMissingLog(t, program, send, frCA, keyGreeting)
			})
		}
	})

	t.Run("The engine shall send every text to the caller as UTF-8.", func(t *testing.T) {
		t.Parallel()
		t.Run("a greeting holding Grüß and a prompt ending in U+FF1F: their UTF-8 bytes on the wire", func(t *testing.T) {
			t.Parallel()
			const greeting, namePrompt = "Grüß Gott", "Ihr Name\uff1f "
			_, _, address := startAt(t, map[string]string{
				fallbackCode: enUSFile(), deDE: fileWith("Deutsch", "", texts{greeting, namePrompt, "Hallo {$NAME}"}),
			}, langOption, deDE)
			want := []byte("Gr\xc3\xbc\xc3\x9f Gott\r\nIhr Name\xef\xbc\x9f " + languageCaller + "\r\nHallo " + languageCaller + "\r\n")
			expectShown(t, address, languageCaller, string(want))
		})
	})

	t.Run("When a text is first missing from the board's language in a run, the engine shall write one `text_missing` line to the local log naming the board's language and the text.", func(t *testing.T) {
		t.Parallel()
		t.Run("fr-fr lacking the prompt, three callers one after another and two at once: one line, naming fr-fr and session.name_prompt", func(t *testing.T) {
			t.Parallel()
			program, send, address := startAt(t, map[string]string{fallbackCode: enUSFile(), frFR: missingFrom(shortNamePrompt, "")}, langOption, frFR)
			want := shownWithEnUS(shortNamePrompt, languageCaller)
			for range 3 {
				expectShown(t, address, languageCaller, want)
			}
			type result struct {
				shown string
				err   error
			}
			results := make(chan result, 2)
			for range 2 {
				go func() {
					shown, err := tryCall(address, languageCaller)
					results <- result{shown, err}
				}()
			}
			for range 2 {
				if got := <-results; got.err != nil || got.shown != want {
					t.Fatalf("a caller at once was shown %q and %v, want %q and the end", got.shown, got.err, want)
				}
			}
			expectMissingLog(t, program, send, frFR, keyNamePrompt)
		})
		t.Run("fr-fr lacking the greeting and the reply: two lines, one naming each", func(t *testing.T) {
			t.Parallel()
			program, send, address := startAt(t, map[string]string{
				fallbackCode: enUSFile(), frFR: fileWith(frName, "", texts{"", frNamePrompt, ""}),
			}, langOption, frFR)
			expectShown(t, address, languageCaller, shownTo(languageCaller, enUSGreeting, frNamePrompt, withName(enUSNameReply, languageCaller)))
			expectMissingLog(t, program, send, frFR, keyGreeting, keyNameReply)
		})
		t.Run("board en-us: no line", func(t *testing.T) {
			t.Parallel()
			program, send, address := startAt(t, map[string]string{fallbackCode: enUSFile(), frFR: missingFrom(shortNamePrompt, "")})
			expectShown(t, address, languageCaller, enUSShown(languageCaller))
			expectMissingLog(t, program, send, fallbackCode)
		})
		t.Run("fr-fr holding every text: no line", func(t *testing.T) {
			t.Parallel()
			program, send, address := startAt(t, map[string]string{fallbackCode: enUSFile(), frFR: frFile()}, langOption, frFR)
			expectShown(t, address, languageCaller, frShown(languageCaller))
			expectMissingLog(t, program, send, frFR)
		})
	})

	t.Run("The engine shall put the caller's name into a text as the characters it holds, never read as a text's syntax.", func(t *testing.T) {
		t.Parallel()
		for _, name := range []string{"{$NAME}", "{#x}", `\{`, `\|`} {
			for _, board := range []string{fallbackCode, frFR} {
				t.Run("the name "+name+" under "+board+": the reply holds it as typed", func(t *testing.T) {
					t.Parallel()
					options := []string{langOption, board}
					want := frShown(name)
					if board == fallbackCode {
						want = enUSShown(name)
					}
					_, _, address := startAt(t, map[string]string{fallbackCode: enUSFile(), frFR: frFile()}, options...)
					expectShown(t, address, name, want)
				})
			}
		}
	})

	t.Run("The engine shall treat a text as missing from a language when it is not valid MessageFormat 2, or holds anything but characters, the standard's escapes and variable placeholders, `{$name}`.", func(t *testing.T) {
		t.Parallel()
		for _, each := range []struct{ name, text string }{
			{"a greeting with an unclosed placeholder, Bonjour {", "Bonjour {"},
			{"a greeting that is a complex message, {{Bonjour}}", "{{Bonjour}}"},
			{"a greeting with a literal placeholder, {BBSNAME}", "{BBSNAME}"},
		} {
			t.Run(each.name+": en-us's greeting, and one text_missing line", func(t *testing.T) {
				t.Parallel()
				expectCountedMissing(t, shortGreeting, each.text)
			})
		}
		t.Run("a greeting of nested brackets making fr-fr a file of 1 MiB: it starts, shows en-us's greeting, and logs one text_missing line", func(t *testing.T) {
			t.Parallel()
			around := func(text string) string { return missingFrom(shortGreeting, text) }
			program, send, address := startAt(t, map[string]string{fallbackCode: enUSFile(), frFR: nestedBrackets(t, around)}, langOption, frFR)
			expectShown(t, address, languageCaller, shownWithEnUS(shortGreeting, languageCaller))
			expectMissingLog(t, program, send, frFR, keyGreeting)
		})
	})

	t.Run("The engine shall treat a text as missing from a language when it holds a placeholder the engine does not give that text.", func(t *testing.T) {
		t.Parallel()
		t.Run("{$NAME} in the greeting, which is given no name: en-us's greeting, and one text_missing line", func(t *testing.T) {
			t.Parallel()
			expectCountedMissing(t, shortGreeting, "Bonjour {$NAME}")
		})
	})

	t.Run("The engine shall treat a text as missing from a language when it holds a control character, U+0000 to U+001F or U+007F to U+009F, or a bidi control: U+061C, U+200E, U+200F, U+202A to U+202E or U+2066 to U+2069.", func(t *testing.T) {
		t.Parallel()
		t.Run("U+202E in the reply: en-us's reply, and one text_missing line", func(t *testing.T) {
			t.Parallel()
			expectCountedMissing(t, shortNameReply, "Bonjour \u202e{$NAME}")
		})
		t.Run("U+0007 in the prompt: en-us's prompt, and one text_missing line", func(t *testing.T) {
			t.Parallel()
			expectCountedMissing(t, shortNamePrompt, "Votre nom \u0007? ")
		})
	})

	t.Run("If the engine fails to read the `lang` folder or its en-us file, or en-us lacks a text the engine shows or holds one that counts as missing, then the engine shall write one `start_failed` line naming the file and why, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("no lang folder beside the executable: start_failed naming lang", func(t *testing.T) {
			t.Parallel()
			_, programFile := placeProgram(t)
			expectRefusalNamingLang(t, startPlaced(t, programFile))
		})
		t.Run("en-us a folder holding no file: start_failed naming en-us.toml", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			if err := os.MkdirAll(filepath.Join(folder, langFolder, fallbackCode), 0o700); err != nil {
				t.Fatalf("making lang/en-us: %v", err)
			}
			expectRefusalNaming(t, startPlaced(t, programFile), fallbackCode+".toml")
		})
		for _, short := range []string{shortGreeting, shortNamePrompt, shortNameReply} {
			t.Run("en-us lacking "+keyOf(short)+": start_failed naming en-us.toml", func(t *testing.T) {
				t.Parallel()
				each := enUSTexts
				switch short {
				case shortGreeting:
					each.greeting = ""
				case shortNamePrompt:
					each.namePrompt = ""
				case shortNameReply:
					each.nameReply = ""
				}
				program := startPlaced(t, boardWith(t, map[string]string{fallbackCode: fileWith(enUSName, "", each)}))
				expectRefusalNaming(t, program, fallbackCode+".toml")
			})
		}
		t.Run("en-us's greeting holding {$NAME}, which counts as missing: start_failed naming en-us.toml", func(t *testing.T) {
			t.Parallel()
			program := startPlaced(t, boardWith(t, map[string]string{
				fallbackCode: fileWith(enUSName, "", texts{"Hello {$NAME}", enUSNamePrompt, enUSNameReply}),
			}))
			expectRefusalNaming(t, program, fallbackCode+".toml")
		})
		t.Run("a greeting of nested brackets making en-us a file of 1 MiB: start_failed naming en-us.toml", func(t *testing.T) {
			t.Parallel()
			around := func(text string) string {
				return fileWith(enUSName, "", texts{text, enUSNamePrompt, enUSNameReply})
			}
			program := startPlaced(t, boardWith(t, map[string]string{fallbackCode: nestedBrackets(t, around)}))
			expectRefusalNaming(t, program, fallbackCode+".toml")
		})
	})

	t.Run("If a language file is over 1 MiB, is not UTF-8 and TOML 1.1, or has no `name` of characters with no control character, then the engine shall write one `start_failed` line naming the file and why, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		padded := func(size int) []byte {
			file := frFile()
			return []byte(file + "#" + strings.Repeat("x", size-len(file)-2) + "\n")
		}
		t.Run("fr-fr of 1 MiB and one byte: start_failed naming fr-fr.toml", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			writeLangFile(t, folder, languagePath(frFR), padded(mostLanguageBytes+1))
			expectRefusalNaming(t, startPlaced(t, programFile, langOption, frFR), frFR+".toml")
		})
		t.Run("fr-fr of exactly 1 MiB: it starts and shows fr-fr's texts", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			writeLangFile(t, folder, languagePath(frFR), padded(mostLanguageBytes))
			expectShown(t, startPlaced(t, programFile, langOption, frFR).telnetAmidMissing(t)[0], languageCaller, frShown(languageCaller))
		})
		for _, each := range []struct{ name, file string }{
			{"a 0xFF byte in a comment, not UTF-8", frFile() + "# \xff\n"},
			{"an unclosed string, not TOML", frFile() + "broken = \"open\n"},
			{"no name", languageFile(nil, frTexts.lines())},
			{"a name holding U+0007", fileWith("Fran\u0007çais", "", frTexts)},
		} {
			t.Run(each.name+": start_failed naming fr-fr.toml", func(t *testing.T) {
				t.Parallel()
				program := startPlaced(t, boardWith(t, map[string]string{fallbackCode: enUSFile(), frFR: each.file}), langOption, frFR)
				expectRefusalNaming(t, program, frFR+".toml")
			})
		}
		t.Run("de-de, outside the board's chain, not TOML, board en-us and no -lang: start_failed naming de-de.toml", func(t *testing.T) {
			t.Parallel()
			program := startPlaced(t, boardWith(t, map[string]string{fallbackCode: enUSFile(), deDE: "name = \n"}))
			expectRefusalNaming(t, program, deDE+".toml")
		})
	})

	t.Run("If a folder in `lang` holding a file of its own name is not a well-formed language tag in lower case, or a `parent` names no language the folder holds or leads back to itself, then the engine shall write one `start_failed` line naming the file and why, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		t.Run("fr-FR/fr-FR.toml, not in lower case: start_failed naming fr-FR.toml", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			writeLangFile(t, folder, "fr-FR/fr-FR.toml", []byte(frFile()))
			expectRefusalNaming(t, startPlaced(t, programFile), "fr-FR.toml")
		})
		t.Run("fr-fr's parent de-de, which lang does not hold: start_failed naming fr-fr.toml", func(t *testing.T) {
			t.Parallel()
			program := startPlaced(t, boardWith(t, map[string]string{fallbackCode: enUSFile(), frFR: fileWith(frName, deDE, frTexts)}))
			expectRefusalNaming(t, program, frFR+".toml")
		})
		t.Run("fr-ca and fr-fr each the other's parent: start_failed naming one of their files", func(t *testing.T) {
			t.Parallel()
			program := startPlaced(t, boardWith(t, map[string]string{
				fallbackCode: enUSFile(), frFR: fileWith(frName, frCA, frTexts), frCA: fileWith("Français (Canada)", frFR, frTexts),
			}))
			reason := unquoted(program.expectRefusal(t))
			if !strings.Contains(reason, frFR+".toml") && !strings.Contains(reason, frCA+".toml") {
				t.Fatalf("the start_failed line %q names neither fr-fr.toml nor fr-ca.toml", reason)
			}
		})
		t.Run("the edge inside: notes holding no notes.toml, and readme.txt in lang: it starts", func(t *testing.T) {
			t.Parallel()
			folder, programFile := placeProgram(t)
			writeLanguages(t, folder, map[string]string{fallbackCode: enUSFile()})
			writeLangFile(t, folder, "notes/todo.txt", []byte("not a language\n"))
			writeLangFile(t, folder, "readme.txt", []byte("not a language\n"))
			expectShown(t, startPlaced(t, programFile).telnetAmidMissing(t)[0], languageCaller, enUSShown(languageCaller))
		})
	})

	t.Run("The engine shall write no line to the local log other than `started`, `start_failed`, `waiting`, `lease_lost` and `text_missing`.", func(t *testing.T) {
		t.Parallel()
		t.Run("a run with a text missing and a whole call: started and text_missing lines alone", func(t *testing.T) {
			t.Parallel()
			program, send, address := startAt(t, map[string]string{fallbackCode: enUSFile(), frFR: missingFrom(shortGreeting, "")}, langOption, frFR)
			expectShown(t, address, languageCaller, shownWithEnUS(shortGreeting, languageCaller))
			expectMissingLog(t, program, send, frFR, keyGreeting)
		})
	})
}
