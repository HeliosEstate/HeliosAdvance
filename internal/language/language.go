// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package language

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/pelletier/go-toml/v2"
)

// keySpec pairs a text's key with its placeholders, so that Load, Text and Missing cannot
// disagree on either.
type keySpec struct {
	key   string
	given []string
}

var keySpecs = []keySpec{
	{KeyGreeting, nil},
	{KeyNamePrompt, nil},
	{KeyNameReply, []string{PlaceholderName}},
}

// part is kept apart from the others so that a value put in a placeholder's place is never
// parsed as a text.
type part struct {
	text        string
	placeholder bool
}

// textsState holds each key's text already read, so Text never reads a file's syntax again.
type textsState struct {
	parts   map[string][]part
	missing []string
}

// tagPattern is RFC 5646's grammar in lower case: a language tag, private use alone, or one of the
// irregular grandfathered tags; the regular grandfathered ones already match a language tag.
var tagPattern = regexp.MustCompile(`^(?:(?:[a-z]{2,3}(?:-[a-z]{3}){0,3}|[a-z]{4,8})` +
	`(?:-[a-z]{4})?(?:-(?:[a-z]{2}|[0-9]{3}))?(?:-(?:[a-z0-9]{5,8}|[0-9][a-z0-9]{3}))*` +
	`(?:-[0-9a-wyz](?:-[a-z0-9]{2,8})+)*(?:-x(?:-[a-z0-9]{1,8})+)?` +
	`|x(?:-[a-z0-9]{1,8})+|en-gb-oed` +
	`|i-(?:ami|bnn|default|enochian|hak|klingon|lux|mingo|navajo|pwn|tao|tay|tsu)` +
	`|sgn-(?:be-fr|be-nl|ch-de))$`)

// language keeps of each file only what Load still needs once the bytes are dropped.
type language struct {
	code string
	path string
	// fault is why the folder or its file cannot be read, found while listing.
	fault string
	// contents is the file's bytes, held only until every file has been read and sized.
	contents string
	tooLarge bool
	name     any
	parent   any
	session  map[string]any
	// parentOf is the language parent names, once resolved.
	parentOf *language
}

// refusal makes every refusal: the file's path and why, and a system error after it, which names a
// path and a cause and never the file's bytes. Only ErrFileRefused matches it.
func refusal(path, why string, cause error) error {
	if cause != nil {
		why += ": " + cause.Error()
	}
	return fmt.Errorf("%w: %s: %s", ErrFileRefused, path, why)
}

func load(folder, code string) (*Texts, error) {
	root, err := os.OpenRoot(filepath.Clean(folder))
	if err != nil {
		return nil, refusal(folder, "the language folder cannot be opened", err)
	}
	texts, err := loadFrom(root, folder, code)
	if closeErr := root.Close(); err == nil && closeErr != nil {
		return nil, refusal(folder, "the language folder cannot be closed", closeErr)
	}
	return texts, err
}

func loadFrom(root *os.Root, folder, code string) (*Texts, error) {
	languages, err := find(root, folder)
	if err != nil {
		return nil, err
	}
	byCode := make(map[string]*language, len(languages))
	for _, each := range languages {
		byCode[each.code] = each
	}
	if err := checkNames(languages); err != nil {
		return nil, err
	}
	if err := readFiles(root, languages); err != nil {
		return nil, err
	}
	if err := decodeFiles(languages); err != nil {
		return nil, err
	}
	fallback := byCode[Fallback]
	if fallback == nil {
		return nil, refusal(filepath.Join(folder, Fallback, Fallback+".toml"), "there is no such language", nil)
	}
	board := byCode[asciiLower(code)]
	if board == nil {
		return nil, ErrNotInstalled
	}
	if err := checkParents(languages, byCode, fallback); err != nil {
		return nil, err
	}
	return findTexts(board, fallback, len(languages))
}

// find lists the languages from the listing alone, never from an open that succeeds, since
// Windows' file names ignore case. A regular file is left alone; any other entry is opened inside
// the root, non-blocking so a named pipe never holds Load, and judged on the opened handle.
func find(root *os.Root, folder string) ([]*language, error) {
	listed, err := root.Open(".")
	if err != nil {
		return nil, refusal(folder, "the language folder cannot be listed", err)
	}
	entries, err := listed.ReadDir(MostEntries + 1)
	if closeErr := listed.Close(); err == nil || errors.Is(err, io.EOF) {
		err = closeErr
	}
	if err != nil {
		return nil, refusal(folder, "the language folder cannot be listed", err)
	}
	if len(entries) > MostEntries {
		return nil, tooManyEntries(folder)
	}
	slices.SortFunc(entries, func(first, second fs.DirEntry) int { return strings.Compare(first.Name(), second.Name()) })
	var languages []*language
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			continue
		}
		name := entry.Name()
		found := &language{code: name, path: filepath.Join(folder, name, name+".toml")}
		isLanguage, err := hasOwnFile(root, name)
		if errors.Is(err, errTooManyEntries) {
			return nil, tooManyEntries(filepath.Join(folder, name))
		}
		if err != nil {
			found.fault = "cannot be read: " + err.Error()
		} else if !isLanguage {
			continue
		}
		languages = append(languages, found)
	}
	return languages, nil
}

// tooManyEntries refuses a folder holding more than MostEntries entries. Load lists one more than
// that and no further, so a folder of any size costs the same.
func tooManyEntries(folder string) error {
	return refusal(folder, fmt.Sprintf("it holds more than %d entries", MostEntries), nil)
}

// errTooManyEntries tells a folder holding too many entries from one that cannot be read, which
// is the language's own fault, refused in its turn.
var errTooManyEntries = errors.New("too many entries")

// hasOwnFile judges the entry on its opened handle, so a link cannot change what was judged
// between the check and the use.
func hasOwnFile(root *os.Root, name string) (bool, error) {
	opened, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false, err
	}
	isFolder, names, err := listOpened(opened)
	if closeErr := opened.Close(); err == nil {
		err = closeErr
	}
	if len(names) > MostEntries {
		return false, errTooManyEntries
	}
	if err != nil {
		return false, err
	}
	return isFolder && slices.Contains(names, name+".toml"), nil
}

// listOpened lists one more than MostEntries names at most, enough to know a folder holds too many.
func listOpened(opened *os.File) (bool, []string, error) {
	info, err := opened.Stat()
	if err != nil || !info.IsDir() {
		return false, nil, err
	}
	names, err := opened.Readdirnames(MostEntries + 1)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return true, names, err
}

func checkNames(languages []*language) error {
	for _, each := range languages {
		if !tagPattern.MatchString(each.code) {
			return refusal(each.path, "its folder's name is not a language tag in lower case", nil)
		}
	}
	return nil
}

// readFiles reads every file into one buffer of the most and one byte, used again for each, so a
// larger file is told from one of exactly the most and no more than that is read.
func readFiles(root *os.Root, languages []*language) error {
	buffer := make([]byte, MostFileBytes+1)
	for _, each := range languages {
		if each.fault != "" {
			return refusal(each.path, each.fault, nil)
		}
		count, err := readFile(root, filepath.Join(each.code, each.code+".toml"), buffer)
		if err != nil {
			return refusal(each.path, "cannot be read", err)
		}
		if count == len(buffer) {
			each.tooLarge = true
			continue
		}
		each.contents = string(buffer[:count])
	}
	return nil
}

func readFile(root *os.Root, name string, buffer []byte) (int, error) {
	opened, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0, err
	}
	count, err := readOpened(opened, buffer)
	if closeErr := opened.Close(); err == nil {
		err = closeErr
	}
	return count, err
}

func readOpened(opened *os.File, buffer []byte) (int, error) {
	info, err := opened.Stat()
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, errors.New("not a regular file")
	}
	count, err := io.ReadFull(opened, buffer)
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		err = nil
	}
	return count, err
}

// decodeFiles checks the size of every file, then decodes each and drops its bytes, keeping only
// the name, the parent and the session table. UTF-8 is checked here and not by the library, which
// skips a UTF-16 byte-order mark and reads on, and the bound is the engine's own read.
func decodeFiles(languages []*language) error {
	for _, each := range languages {
		if each.tooLarge {
			return refusal(each.path, fmt.Sprintf("over %d bytes", MostFileBytes), nil)
		}
	}
	for _, each := range languages {
		var decoded map[string]any
		var err error
		if !utf8.ValidString(each.contents) {
			err = errors.New("not UTF-8")
		} else {
			err = toml.Unmarshal([]byte(each.contents), &decoded)
		}
		each.contents = ""
		if err != nil {
			why := "not UTF-8 and TOML 1.1"
			var decodeError *toml.DecodeError
			if errors.As(err, &decodeError) {
				line, _ := decodeError.Position()
				why += fmt.Sprintf(", at line %d", line)
			}
			return refusal(each.path, why, nil)
		}
		each.name = decoded["name"]
		each.parent = decoded["parent"]
		if session, isTable := decoded["session"].(map[string]any); isTable {
			each.session = session
		}
	}
	for _, each := range languages {
		name, isString := each.name.(string)
		if !isString || name == "" || strings.ContainsFunc(name, isControlOrBidi) {
			return refusal(each.path, "its name is not a string of characters", nil)
		}
	}
	return nil
}

// checkParents resolves every parent first, so a walk meets only resolved ones, then judges each
// language by folder name against the whole parent check and returns the first that fails. A walk
// is at most as many steps as there are languages.
func checkParents(languages []*language, byCode map[string]*language, fallback *language) error {
	for _, each := range languages {
		if parent, isString := each.parent.(string); isString {
			each.parentOf = byCode[asciiLower(parent)]
		}
	}
	for _, each := range languages {
		if each == fallback {
			continue
		}
		if _, isString := each.parent.(string); each.parent != nil && !isString {
			return refusal(each.path, "its parent is not a string", nil)
		}
		if each.parent != nil && each.parentOf == nil {
			return refusal(each.path, "its parent names no language", nil)
		}
		next := each.parentOf
		for range languages {
			if next == nil || next == fallback {
				break
			}
			if next == each {
				return refusal(each.path, "its chain of parents leads back to it", nil)
			}
			next = next.parentOf
		}
	}
	return nil
}

// findTexts takes each key from the first language of the board's chain that holds it as a text
// that counts, the chain being the board's language, its parents and then fallback, whose own
// parent is never followed. The walk takes at most most steps, the number of languages, so a loop
// that the parent check let through ends the walk instead of growing the chain without end. A key
// not taken from the board's language is missing.
func findTexts(board, fallback *language, most int) (*Texts, error) {
	chain := []*language{board}
	last := board
	for range most {
		if last == fallback || last.parentOf == nil {
			break
		}
		last = last.parentOf
		chain = append(chain, last)
	}
	if chain[len(chain)-1] != fallback {
		chain = append(chain, fallback)
	}
	state := textsState{parts: make(map[string][]part, len(keySpecs))}
	for _, spec := range keySpecs {
		if _, ok := fallback.textFor(spec); !ok {
			return nil, refusal(fallback.path, "it holds no usable text "+spec.key, nil)
		}
		for index, each := range chain {
			if parts, ok := each.textFor(spec); ok {
				state.parts[spec.key] = parts
				if index > 0 {
					state.missing = append(state.missing, spec.key)
				}
				break
			}
		}
	}
	return &Texts{state: state}, nil
}

func (each *language) textFor(spec keySpec) ([]part, bool) {
	_, name, _ := strings.Cut(spec.key, ".")
	text, isString := each.session[name].(string)
	if !isString {
		return nil, false
	}
	return readText(text, spec.given)
}

func asciiLower(code string) string {
	return strings.Map(func(character rune) rune {
		if character >= 'A' && character <= 'Z' {
			return character + 'a' - 'A'
		}
		return character
	}, code)
}

func isControlOrBidi(character rune) bool {
	return character <= 0x1F || (character >= 0x7F && character <= 0x9F) || character == 0x061C ||
		character == 0x200E || character == 0x200F || (character >= 0x202A && character <= 0x202E) ||
		(character >= 0x2066 && character <= 0x2069)
}

func (t *Texts) text(key string, values []Value) string {
	if t == nil {
		return ""
	}
	var text strings.Builder
	for _, each := range t.state.parts[key] {
		if !each.placeholder {
			text.WriteString(each.text)
			continue
		}
		if index := slices.IndexFunc(values, func(value Value) bool { return value.Name == each.text }); index >= 0 {
			text.WriteString(values[index].Text)
		}
	}
	return text.String()
}

func (t *Texts) missing() []string {
	if t == nil {
		return nil
	}
	return slices.Clone(t.state.missing)
}
