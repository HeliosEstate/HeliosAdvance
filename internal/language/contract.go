// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package language reads the board's language files once, when the engine starts, and gives every
// text the engine shows in the board's language.
//
// It owns the language files: their format, the checks each file and each text meets, the chain a
// text missing from the board's language follows, and the key of every text the engine shows,
// with the placeholders each is given. It does not own which language is the board's, which the
// program takes from its command line, nor where the folder is, which the program finds beside its
// executable; nor writing to a caller, which is the session's; nor the local log: Load hands back
// which texts were missing, and the program writes the lines.
//
// What the engine does as a whole, this package included, is in docs/behavior.md.
//
// # The file's format
//
// A language is the file <code>/<code>.toml in the folder Load is given, <code> its language tag
// (RFC 5646) in lower case, such as en-us. The file is UTF-8 TOML 1.1, at most MostFileBytes. At
// its top, name, a string, the language's own name, and parent, a string and optional, the code of
// the language that fills in its missing texts. Each text is a string in a table named for the
// part of the engine that shows it; its key is the table's name, a dot and the text's own name.
// A text is written in Unicode's MessageFormat 2 (LDML part 9, its MessageFormat part). This
// package reads its characters, its escapes, \{, \}, \| and \\, and its variable placeholders,
// {$NAME}, with no function, option or attribute, and spaces allowed inside the braces.
//
// # Untrusted input
//
// The language files come from outside the engine: translators, language packs and the sysop. A
// text reaches every caller, so a text that could reach a terminal reading UTF-8 as anything but
// its characters counts as missing: one holding a control character or a bidi control, broken
// syntax, more of the standard than this package reads, or a placeholder the engine does not give
// it. A terminal on a legacy code page reads a text's UTF-8 bytes as that page's characters, and
// one that reads 8-bit controls may read a byte of 0x80 to 0x9F as one; converting a text for such
// a terminal is Terminal negotiation's, not this package's. A code,
// whether the board's language, a folder's name or a parent, is matched against the languages the
// folder holds and never made into a path. A placeholder's value, the caller's name among them,
// is put in as its characters and never read as a text's syntax. The parser of a text is the fuzz
// target.
//
// # What it needs from its callers
//
// One Load per engine, at start, before any caller is served; the Texts it returns is handed to
// every Listener. Text given one of the keys below, with the values that key's text is given.
//
// # Lines for the package
//
//   - The language package shall read files only inside the folder Load is given, following no
//     link out of it. [read]
//   - The language package shall write nothing to a file, standard output, standard error or any
//     log. [read]
//   - The language package shall import nothing outside the Go standard library and
//     github.com/pelletier/go-toml/v2. [read]
package language

import "errors"

const (
	// Folder is the language folder's name, beside the engine's executable.
	Folder = "lang"
	// Fallback is the language every chain ends at, released holding every text the engine shows.
	Fallback = "en-us"
	// MostFileBytes bounds a language file; a larger one is refused, no more than this and one
	// byte of it read.
	MostFileBytes = 1 << 20
	// MostEntries bounds how many entries the language folder, or a folder in it, may hold; one
	// holding more is refused, no more than this and one of its entries listed. With it, the
	// language files held at once while Load checks them come to at most this many times
	// MostFileBytes.
	MostEntries = 256
	// KeyGreeting is the greeting, written first; it is given no placeholder.
	KeyGreeting = "session.greeting"
	// KeyNamePrompt is the name prompt, written after the greeting; it is given no placeholder.
	KeyNamePrompt = "session.name_prompt"
	// KeyNameReply is the name reply, written once the caller ends the name; it is given one
	// placeholder, PlaceholderName.
	KeyNameReply = "session.name_reply"
	// PlaceholderName is the caller's name, as the line editor returned it.
	PlaceholderName = "NAME"
)

var (
	// ErrNotInstalled means the board's language is no folder in the language folder holding a
	// file of its own name.
	ErrNotInstalled = errors.New("language: the board's language is not installed")
	// ErrFileRefused means a language file, or the folder, was refused; it is returned wrapped,
	// its message naming the file and why, never a text the file holds.
	ErrFileRefused = errors.New("language: a language file was refused")
)

// Value is a placeholder's name and the characters put in its place.
type Value struct {
	// Name is the placeholder's name, without its $, such as PlaceholderName.
	Name string
	// Text is put in the placeholder's place as its characters.
	Text string
}

// Texts is every text the engine shows, in the board's language, each found along its chain and
// checked by Load. It does not change once Load returns it, and is safe for use from many
// goroutines at once.
type Texts struct {
	state textsState
}

// Load reads every language in folder once, checks each file, and finds every text the engine
// shows for code, the board's language. With an error it returns no Texts. Results:
// ErrNotInstalled, ErrFileRefused.
//
// A language is a folder in folder holding a file named exactly the folder's own name and .toml,
// as folder lists it. An entry other than a regular file that cannot be opened to tell whether it
// is a language, such as a link to nothing, a link leading out of folder, a folder that cannot be
// read or a socket, counts as a language whose file cannot be read. Anything else in folder is not
// a language and is left alone, but for the limit on how many entries a folder in it holds. A code,
// given as code or as a parent, names the language whose folder's name it matches without regard
// to case (RFC 5646). The chain for code is code, then its parent, then that language's parent
// and so on, then Fallback; Fallback's own parent, if it has one, is ignored, so every chain ends
// there.
//
// Load makes the checks below in the order listed, the languages taken in the order of their
// folders' names, and returns the first that fails.
//
//   - If folder cannot be read, then Load shall return ErrFileRefused naming it.
//   - If folder, or a folder in it, holds more than MostEntries entries, then Load shall return
//     ErrFileRefused naming that folder, having listed no more than MostEntries and one of its
//     entries.
//   - If a language's folder name is not a well-formed language tag in lower case, then Load shall
//     return ErrFileRefused naming its file.
//   - If a language's folder or file is a link leading out of folder, or its file cannot be read,
//     then Load shall return ErrFileRefused naming the file.
//   - If a language's file is over MostFileBytes, then Load shall return ErrFileRefused naming it,
//     having read no more than MostFileBytes and one byte of it.
//   - If a language's file is not UTF-8 and TOML 1.1, then Load shall return ErrFileRefused naming
//     it.
//   - If a language's file has no name, or a name that is not a string, is empty or holds a
//     control character or a bidi control, as a text may not, then Load shall return
//     ErrFileRefused naming it.
//   - If Fallback is not a language in folder, then Load shall return ErrFileRefused naming its
//     file.
//   - If code is not a language in folder, then Load shall return ErrNotInstalled.
//   - If a language's file other than Fallback's has a parent that is not a string or names no
//     language in folder, or whose chain of parents leads back to that language, then Load shall
//     return ErrFileRefused naming it.
//   - If Fallback's file does not hold one of the keys above as a text that does not count as
//     missing, then Load shall return ErrFileRefused naming Fallback's file.
//
// Its other lines:
//
//   - Load shall read each language's file once, and every language's, not only those in the
//     chain.
//   - For each key above, Load shall take the text from the first language in the chain for code
//     whose file holds that key as a text that does not count as missing.
//   - Load shall ignore a key in a language's file that is not name, parent or one of the keys
//     above.
//
// A text counts as missing from a language when its key is not in the file, or when it:
//
//   - is not a string, or is not valid MessageFormat 2;
//   - is a complex message, one that begins with a declaration or is a quoted pattern, {{…}};
//   - holds anything but characters, the escapes and variable placeholders with no function,
//     option or attribute, a literal placeholder such as {BBSNAME} included;
//   - holds a placeholder its key is not given;
//   - holds a control character, U+0000 to U+001F or U+007F to U+009F, or a bidi control, U+061C,
//     U+200E, U+200F, U+202A to U+202E or U+2066 to U+2069.
func Load(folder, code string) (*Texts, error) {
	return load(folder, code)
}

// Text returns the text for key in the board's language, each escape the character it escapes and
// each placeholder replaced by the Text of the Value of its Name. A Texts not made by Load, or
// nil, gives the empty string for every key.
//
//   - Text shall give each escape, \{, \}, \| or \\, as the one character it escapes.
//   - Text shall put each Value's Text in its placeholder's place as its characters, never read as
//     a text's syntax.
//   - Text shall replace a placeholder given no Value with nothing, and ignore a Value whose Name
//     the text does not hold.
//   - If key is not one of the keys above, then Text shall return the empty string.
func (t *Texts) Text(key string, values ...Value) string {
	return t.text(key, values)
}

// Missing returns, in the order of the keys above, the keys that were missing from the board's
// language, each found further along its chain; for each, the program writes one text_missing
// line. With the board's language Fallback, there are none; a Texts not made by Load, or nil,
// gives none.
func (t *Texts) Missing() []string {
	return t.missing()
}
