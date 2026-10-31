// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package bootstrap is the engine's bootstrap folder: the bootstrap file, sealed, and the key file
// that holds its key.
//
// It owns reading both files through the folder; the bootstrap file's layout, format version 1;
// checking the key file's owner and permissions; the key file's form; and unsealing the bootstrap
// file with AES-256-GCM. It hands back the sealed JSON as bytes and knows nothing of what it
// means: the connection settings are the database unit's. It does not own the command line, which
// names the folder, or the local log, which are the program's; making the folder, its permissions,
// the key and both files, which are hadv-setup's; writing the bootstrap file, which is the vault's;
// or any way of holding the key but the key file, which later parts add.
//
// What the engine does as a whole, this package included, is in docs/behavior.md.
//
// # The bootstrap file, format version 1
//
// Every number is big-endian.
//
//	offset 0     8 bytes   HADVBOOT
//	offset 8     2 bytes   format version: 1
//	offset 10    1 byte    key holder: 1, the key file
//	offset 11    2 bytes   sealed-key length: 0 for the key file
//	offset 13    n bytes   sealed key: none for the key file
//	then        12 bytes   nonce
//	then         m bytes   the JSON, AES-256-GCM under the key
//	then        16 bytes   the GCM tag
//
// Every byte before the JSON is the authenticated data. The whole file is at most FileMostBytes.
//
// # The key file
//
// One line: 44 characters of RFC 4648's standard base64 alphabet with its padding, decoding to
// the 32-byte key with the bits after its last byte zero, then nothing, one line feed, or one
// carriage return and line feed.
//
// # Untrusted input
//
// The bootstrap file is untrusted until its tag verifies: its first HeaderBytes are read and
// checked before anything else, and nothing after them is used before the tag verifies. The key
// file is untrusted until its form is checked. Both come from the bootstrap folder, which only
// hadv-setup and administrators should write; the key file's owner and permissions are checked
// because a key file someone else can write or replace could point the engine at a database of
// their choosing. No caller's byte reaches this package. Fuzz targets: the header reader and the
// key file's reader.
//
// # Oracles
//
// The bootstrap file reference, oracle/bootstrap-file (Free Pascal, with its own AES and GCM, its
// self-test running the published vectors; HeliosDesign #284), which the tests make every
// bootstrap file with, good and broken; RFC 4648's test vectors for the key file's reader; and the
// real file systems, whose owners, modes and access lists the tests set from outside on Linux
// x86-64, Linux ARM64 and Windows x86-64.
//
// # What it needs from its callers
//
// One Open per start of the engine, given the folder the command line names, never empty. The
// caller wipes the bytes Open returns once it has read them.
//
// # Lines for the package
//
//   - The bootstrap package shall write nothing to the local log, standard output or standard
//     error. [read]
//   - No error the bootstrap package returns shall hold, in its text, the key or any part of
//     either file's contents.
//   - The bootstrap package shall import nothing outside the Go standard library and
//     golang.org/x/sys/windows. [read]
package bootstrap

import "errors"

// The layout's constants and the bounds on what is read.
const (
	// FileName is the bootstrap file's name in the bootstrap folder.
	FileName = "bootstrap.hadv"
	// KeyFileName is the key file's name, beside it.
	KeyFileName = "bootstrap.key"
	// Magic is the bootstrap file's first 8 bytes, saying what it is.
	Magic = "HADVBOOT"
	// FormatVersion is the only layout this engine reads.
	FormatVersion = 1
	// KeyHolderKeyFile is the header's number for a key kept in the key file.
	KeyHolderKeyFile = 1
	// HeaderBytes is the header's fixed start: the magic, the version, the key holder and the
	// sealed-key length.
	HeaderBytes = 13
	// NonceBytes is the nonce after the header.
	NonceBytes = 12
	// TagBytes is the integrity tag at the end.
	TagBytes = 16
	// KeyBytes is the key: 256 bits.
	KeyBytes = 32
	// FileMostBytes bounds the bootstrap file: a larger one is refused, so what is read has a bound.
	FileMostBytes = 65536
	// KeyFileMostBytes bounds the key file: 44 characters and a line ending of two; a longer one is
	// refused.
	KeyFileMostBytes = 46
)

// Why Open refused, one error for each check, in the order the checks run. None holds the key or
// any part of either file's contents, so the program can write it to the local log as it is.
var (
	// ErrFolderMissing means the bootstrap folder is not there.
	ErrFolderMissing = errors.New("bootstrap: the bootstrap folder does not exist")
	// ErrFolderUnreadable means the bootstrap folder is there but will not open.
	ErrFolderUnreadable = errors.New("bootstrap: the bootstrap folder cannot be opened")
	// ErrFileMissing means the bootstrap folder holds no bootstrap file.
	ErrFileMissing = errors.New("bootstrap: the bootstrap file does not exist")
	// ErrFileUnreadable means the bootstrap file is there but will not open or read, or is a link
	// leading out of the bootstrap folder.
	ErrFileUnreadable = errors.New("bootstrap: the bootstrap file cannot be read")
	// ErrFileTooLarge means the bootstrap file is longer than FileMostBytes.
	ErrFileTooLarge = errors.New("bootstrap: the bootstrap file is too large")
	// ErrHeader means the bootstrap file's header is not format version 1's for the key file, or
	// the file is too short for its header, nonce and tag.
	ErrHeader = errors.New("bootstrap: the bootstrap file's header is not one this engine reads")
	// ErrKeyFileMissing means the bootstrap folder holds no key file.
	ErrKeyFileMissing = errors.New("bootstrap: the key file does not exist")
	// ErrKeyFileUnreadable means the key file is there but will not open or read, or is a link
	// leading out of the bootstrap folder.
	ErrKeyFileUnreadable = errors.New("bootstrap: the key file cannot be read")
	// ErrKeyFilePermissions means the key file's owner or permissions could not be read.
	ErrKeyFilePermissions = errors.New("bootstrap: the key file's owner or permissions cannot be read")
	// ErrKeyFileReachable means someone but the engine's own account, SYSTEM or Administrators
	// owns the key file or may reach it.
	ErrKeyFileReachable = errors.New("bootstrap: someone but the engine's account, SYSTEM or Administrators can reach the key file")
	// ErrKeyFileForm means the key file is not in its form, or holds a key of 32 zero bytes.
	ErrKeyFileForm = errors.New("bootstrap: the key file is not in its form")
	// ErrUnseal means the bootstrap file does not unseal under the key: a wrong key or a changed
	// file, which cannot be told apart.
	ErrUnseal = errors.New("bootstrap: the bootstrap file does not unseal under the key in the key file")
)

// Open opens the bootstrap folder, checks the bootstrap file and its header, then the key file,
// and unseals the bootstrap file. It returns the sealed JSON, which the caller wipes once read.
// The checks run in the order of the lines below, and the first that applies is the result.
//
//   - Open shall check in the order of these lines and return the first refusal that applies.
//   - If the bootstrap folder does not exist, then Open shall return ErrFolderMissing.
//   - If the bootstrap folder exists but will not open, then Open shall return
//     ErrFolderUnreadable.
//   - If the bootstrap folder holds no bootstrap file, then Open shall return ErrFileMissing.
//   - If the bootstrap file will not open or read, or is a link leading out of the bootstrap
//     folder, then Open shall return ErrFileUnreadable.
//   - If the bootstrap file is longer than FileMostBytes, then Open shall return ErrFileTooLarge,
//     having read at most FileMostBytes and one byte more of it.
//   - If the bootstrap file is shorter than HeaderBytes, NonceBytes and TagBytes together, or its
//     first HeaderBytes are not Magic, FormatVersion, KeyHolderKeyFile and a sealed-key length of
//     0, then Open shall return ErrHeader before it opens the key file.
//   - If the bootstrap folder holds no key file, then Open shall return ErrKeyFileMissing.
//   - If the key file will not open, or is a link leading out of the bootstrap folder, then Open
//     shall return ErrKeyFileUnreadable.
//   - If reading the key file's owner or permissions fails, or the engine runs on a system other
//     than Linux or Windows, then Open shall return ErrKeyFilePermissions.
//   - If, on Linux, the key file's owner is not the user the engine runs as, or its mode gives
//     its group or others any access, then Open shall return ErrKeyFileReachable.
//   - If, on Windows, the key file's owner, or any entry of its access list that allows access,
//     whether the file's own or inherited, names anyone but SYSTEM (S-1-5-18), Administrators
//     (S-1-5-32-544) or the user of the engine's own token, or the key file has no access list,
//     then Open shall return ErrKeyFileReachable. An entry that denies access is not counted.
//   - Open shall read the key file's owner and permissions from the key file it opened, never by
//     its name again. [read]
//   - If reading the key file fails, then Open shall return ErrKeyFileUnreadable.
//   - If the key file is longer than KeyFileMostBytes, is not in the form the package comment
//     gives, or holds a key of 32 zero bytes, then Open shall return ErrKeyFileForm, having read
//     at most KeyFileMostBytes and one byte more of it.
//   - If the bootstrap file's tag does not verify under the key, then Open shall return ErrUnseal
//     and no bytes.
//   - When it returns, Open shall have closed the bootstrap folder and both files.
//   - Open shall wipe the key, the key file's text and the bootstrap file's bytes before it
//     returns, keeping only the JSON it returns. [read]
func Open(folder string) ([]byte, error) {
	return open(folder)
}
