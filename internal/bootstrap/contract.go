// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package bootstrap is the bootstrap package: the only code that reads or writes one server's
// bootstrap file, or the bootstrap key it is sealed under. It owns the file and its format from
// the header to the fields, what a valid file holds, create, open and save of the whole file, and
// the five key holders behind one small interface, each of which makes, gets and deletes its own
// key. hadv-setup and hadv-service use the same operations and the same handle.
//
// It does not own the bootstrap folder, its access list, the service account or the service
// registration, the sealed key written into it included: those are hadv-setup's. Adding and
// removing a vault key, and what the vault keys mean, are the shared secrets unit's. The words of
// a refusal and every log line are the callers'. It does not defend the file from the service
// account or from administrators: the folder's access list and the key holder keep other local
// accounts out. It holds no lock and checks no links. It never reaches the database.
//
// What the package must do as the board sees it is in docs/behavior.md, under "Bootstrap
// package"; the lines here say how, at the package's edge.
//
// # Where things are
//
// In the bootstrap folder, whose path the caller passes, opened with os.OpenRoot for each
// operation and never kept open between:
//
//	bootstrap.hadv        the bootstrap file
//	bootstrap.hadv.new    the temp file of a create or save; a leftover one is overwritten
//	bootstrap.key         the key file, made by the sysop
//
// A Swarm secret is /run/secrets/hadv-bootstrap-key. A systemd credential is named
// hadv-bootstrap-key, embedded when it is encrypted and checked when it is decrypted; when systemd
// decrypts it at service start, it is that file in the credential folder. A Windows key is a
// machine key named hadv- plus 32 lowercase hex digits (16 random bytes), in Microsoft's TPM
// provider where the machine has a TPM, in the software key store provider where it does not.
//
//   - If the bootstrap folder is there and opening it fails, then the bootstrap package shall
//     return ErrUnreadable with the OS's cause beneath it.
//   - When the bootstrap package returns ErrNotFound or ErrUnreadable, the error shall name
//     whether the bootstrap folder or bootstrap.hadv is the cause.
//
// # The key holders
//
// By the number the header carries:
//
//	1  Windows key store. Create makes a 2048-bit RSA key, sets its access list to the service
//	   account, SYSTEM and Administrators, and wraps the bootstrap key with RSA-OAEP (SHA-256,
//	   MGF1 with SHA-256, no label). Open looks for the key by its name in the TPM provider,
//	   then in software.
//	2  systemd, decrypted by the service. Create runs systemd-creds encrypt with --uid= the
//	   service account, --with-key=auto and --tpm2-pcrs= with no PCR, so a firmware or Secure
//	   Boot change never locks the server out. Open runs systemd-creds decrypt with --uid= the
//	   service account it is given: root must name the account, and the account may name
//	   itself.
//	3  systemd, decrypted by systemd at service start. Create encrypts as for 2, with no --uid.
//	   Open reads the credential folder when systemd set CREDENTIALS_DIRECTORY (the service);
//	   otherwise it decrypts the header's sealed key with systemd-creds decrypt, which needs
//	   root (hadv-setup).
//	4  key file.
//	5  Swarm secret.
//
// The key file and the Swarm secret each hold exactly 44 characters of RFC 4648's standard base64
// alphabet with its padding, with one trailing newline allowed, and each key has one spelling:
// the bits after its last byte are zero. Neither makes nor deletes a key: create seals under the
// key they hold. Windows has key holder 1; Linux has 2 to 5. A systemd too old for a key holder
// fails at systemd-creds and gets ErrKey.
//
//   - When create makes a Windows key, create shall make a 2048-bit RSA machine key named hadv-
//     followed by 32 lowercase hex digits from 16 random bytes.
//   - Where the server has a TPM, create shall make the Windows key in Microsoft's TPM provider,
//     and in the software key store provider where it has none. [run]
//   - When create makes a Windows key, create shall set the key's access list to the service
//     account, SYSTEM and Administrators. [run]
//   - When create makes a Windows key, create shall wrap the bootstrap key under it with
//     RSA-OAEP, SHA-256 and MGF1 with SHA-256, and no label.
//   - When open gets the bootstrap key from a Windows key, open shall look for the key by its
//     name in the TPM provider, then in the software key store provider. [run]
//   - When create seals under systemd credentials decrypted by the service, create shall run
//     systemd-creds encrypt with --uid= the service account, --with-key=auto, --tpm2-pcrs= with
//     no PCR, and --name=hadv-bootstrap-key.
//   - When create seals under systemd credentials decrypted at service start, create shall run
//     systemd-creds encrypt with --with-key=auto, --tpm2-pcrs= with no PCR, and
//     --name=hadv-bootstrap-key.
//   - When open gets the bootstrap key from systemd credentials decrypted by the service, open
//     shall run systemd-creds decrypt with --uid= the service account it is given and
//     --name=hadv-bootstrap-key.
//   - When open gets the bootstrap key from systemd credentials decrypted at service start and
//     CREDENTIALS_DIRECTORY is set, open shall read hadv-bootstrap-key from that folder.
//   - When open gets the bootstrap key from systemd credentials decrypted at service start and
//     CREDENTIALS_DIRECTORY is not set, open shall run systemd-creds decrypt on the header's
//     sealed key with --name=hadv-bootstrap-key.
//   - If the key file or the Swarm secret breaks the form the package comment gives, then the
//     bootstrap package shall return ErrKey.
//   - If the caller or the header names a key holder the platform does not have, then the
//     bootstrap package shall return ErrKey.
//   - If the Windows key the sealed key names is in neither provider, or unwrapping the
//     bootstrap key under it fails, then open shall return ErrKey.
//   - If systemd-creds decrypt fails, or CREDENTIALS_DIRECTORY is set and reading
//     hadv-bootstrap-key from it fails, then open shall return ErrKey.
//   - If the key file or the Swarm secret is not there, or reading it fails, then the bootstrap
//     package shall return ErrKey.
//   - If making the Windows key, setting its access list, wrapping the bootstrap key under it or
//     running systemd-creds encrypt fails, then create shall return ErrKey.
//   - If a key holder gives a bootstrap key that is not 32 bytes, then the bootstrap package
//     shall return ErrKey.
//   - The bootstrap package shall read at most 46 bytes from the key file or the Swarm secret,
//     and at most 33 bytes from the credential folder's hadv-bootstrap-key or from the output of
//     systemd-creds decrypt.
//   - If systemd-creds encrypt gives more than 4,096 bytes, then create shall return ErrKey,
//     having read at most 4,097 bytes of it.
//   - When create seals under systemd credentials, create shall give systemd-creds encrypt the
//     bootstrap key's 32 raw bytes on standard input.
//
// # The bootstrap file, format version 1
//
// Every number is unsigned and big-endian.
//
//	offset 0     8 bytes   magic: the ASCII characters HADVBOOT
//	offset 8     2 bytes   format version: 1
//	offset 10    1 byte    key holder: 1 to 5
//	offset 11    2 bytes   sealed-key length, n: exactly 293 for key holder 1, 1 to 4,096 for
//	                       2 and 3, 0 for 4 and 5
//	offset 13    n bytes   sealed key: for 1, the key name (37 ASCII bytes, hadv- and 32
//	                       lowercase hex digits, never used as a path) then the 256-byte
//	                       RSA-OAEP wrap; for 2 and 3, systemd's encrypted credential; for 4
//	                       and 5, nothing
//	then        12 bytes   nonce: random, new on every write
//	then         m bytes   the records, AES-256-GCM under the bootstrap key, with every byte
//	                       before them (the header and the nonce) as the authenticated data
//	then        16 bytes   the GCM tag
//
// The header is the first 13 + n bytes. Each part of it is checked against this table before it
// is used; anything else gets ErrFormat, a format version above 1 included, as does a file too
// short for its header, nonce and tag. The whole file is at most 65,536 bytes; a larger one gets
// ErrFormat unread. Nothing after the header is trusted until the tag verifies.
//
// Once unsealed, the records follow one another to the end of the plaintext:
//
//	2 bytes    name length, 1 to 255
//	n bytes    name, UTF-8, unique in the file
//	4 bytes    data length
//	n bytes    data
//
// A record running past the end, an empty, over-long or non-UTF-8 name, or two records of one name
// gets ErrInvalid. The known names and their data:
//
//	server                       4 bytes: the server's ID
//	database.connection          UTF-8: the database connection, with no account in it
//	database.account.name        UTF-8: the server's database account
//	database.account.password    bytes
//	vault.key.<version>          32 bytes, one record per vault key
//	receiving.key                bytes: the receiving key pair's private half
//	signing.key                  bytes: the signing key pair's private half
//
// A vault key's version is written in decimal with no leading zero, from 1 to 4,294,967,295, so
// each version has one name; any other name under vault.key. gets ErrInvalid and is never an
// unknown record. A record of any other name is kept unchanged, in its place, on save.
//
//   - The bootstrap package shall write the bootstrap file only in the layout the package
//     comment gives for format version 1.
//   - The bootstrap package shall write a new random nonce each time it writes a bootstrap file.
//   - The bootstrap package shall seal the records with AES-256-GCM under the bootstrap key, with
//     the header and the nonce as the authenticated data.
//   - If a record breaks the record layout the package comment gives, then the bootstrap package
//     shall return ErrInvalid.
//   - If a record's name begins with vault.key. and the rest is not a version in decimal from 1
//     to 4,294,967,295 with no leading zero, then the bootstrap package shall return ErrInvalid.
//   - When the bootstrap package writes a bootstrap file, it shall keep each record of an unknown
//     name byte for byte, in the order it was read.
//
// # The write path
//
// One for create and save, through the folder's os.Root: write the temp file, truncating a
// leftover; flush it; open it under the bootstrap key in hand, by the same reading open uses;
// rename it over bootstrap.hadv; on Linux, flush the folder. If any step fails, the temp file is
// deleted and the old file stands.
//
//   - When create or save writes a bootstrap file, the bootstrap package shall write it as
//     bootstrap.hadv.new and rename it over bootstrap.hadv through the folder's os.Root.
//   - The bootstrap package shall flush bootstrap.hadv.new before it renames it. [read]
//   - The bootstrap package shall open bootstrap.hadv.new under the bootstrap key before it
//     renames it.
//   - Where the server runs Linux, the bootstrap package shall flush the bootstrap folder after
//     the rename. [read]
//   - If writing, flushing, opening or renaming bootstrap.hadv.new fails, then the bootstrap
//     package shall delete bootstrap.hadv.new and return ErrWrite.
//
// # Untrusted input and oracles
//
// Untrusted inputs: the bootstrap file (the header before anything is verified, the records after
// it unseals); the key file; the Swarm secret; the credential folder's file; what systemd-creds
// decrypt and the Windows key store return. Each parser among them is a fuzz target: the header
// reader, the record reader and the base64 key reader, seeded from the kept samples. The fields a
// caller passes are checked (ErrInvalid), not parsed.
//
// What proves each part:
//
//	the file format and AES-256-GCM   oracle/bootstrap-file, given the new header, and the
//	                                  samples it makes in testdata/format-1/; its self-test runs
//	                                  the published AES and GCM test vectors
//	key holder 1                      the real key store, with and without a TPM; RSA-OAEP
//	                                  against crypto/rsa on the exported public key; a key's
//	                                  presence and deletion by certutil -csp; the access list by
//	                                  a run as another account, refused
//	key holders 2 and 3               systemd-creds run as a separate command in the
//	                                  oracle/systemd-252 (key holder 3) and systemd-257 (key
//	                                  holder 2) containers, systemd-249 below both: a file create
//	                                  made opens with a key the command decrypts, and a
//	                                  credential the command made opens here
//	the base64 key reader             RFC 4648's test vectors and plain tests
//	the write path                    plain tests, and a save killed partway that leaves the
//	                                  old file whole
//
// # What it needs from its callers
//
//	hadv-setup      makes the bootstrap folder and sets its access list before create
//	hadv-setup      runs as administrator or root
//	hadv-setup      creates and saves only once the OS service manager says the service is
//	                stopped
//	hadv-setup      for key holder 3, writes the header's sealed key into the service
//	                registration as hadv-bootstrap-key
//	hadv-setup      tells the sysop of any key create could not delete
//	hadv-service    opens at start, takes what it needs and releases the handle; on a failure,
//	                writes the code to its local log and stops
//	shared secrets  the only saver in the service, one save at a time
//	every caller    passes the service account to create and open
//	every caller    releases every handle it opens, uses none after its release, and never logs
//	                a field
//	every caller    zeroes, with Zero, every Fields it takes from a handle, and any secret it
//	                copies out of one
//	backup utility  leaves out bootstrap.hadv, bootstrap.hadv.new and bootstrap.key
//
// This file is the developer's contract (HeliosDesign records/skeleton/Bootstrap.pas) and is
// locked: a loop session does not edit it.
package bootstrap

import (
	"context"
	"errors"
	"os"

	"github.com/heliosestate/heliosadvance/internal/board"
)

// The format's constants, as the package comment states them.
const (
	Magic                = "HADVBOOT"
	FormatVersion        = 1
	MaxSize              = 65536 // bytes; a larger file gets ErrFormat, unread
	HeaderStartSize      = 13    // magic, format version, key holder, sealed-key length
	NonceSize            = 12
	TagSize              = 16
	KeySize              = 32   // the bootstrap key: 256 random bits
	WindowsKeyNameSize   = 37   // "hadv-" + 32 lowercase hex digits
	WindowsWrapSize      = 256  // RSA-2048 OAEP
	SystemdCredentialMax = 4096 // bytes of systemd's encrypted credential
	SystemdKeyName       = "hadv-bootstrap-key"
)

// The names in the bootstrap folder, and the Swarm secret's path.
const (
	FileName        = "bootstrap.hadv"
	TempFileName    = "bootstrap.hadv.new"
	KeyFileName     = "bootstrap.key"
	SwarmSecretPath = "/run/secrets/hadv-bootstrap-key"
)

// The known field names.
const (
	FieldServer          = "server"
	FieldConnection      = "database.connection"
	FieldAccountName     = "database.account.name"
	FieldAccountPassword = "database.account.password"
	FieldVaultKeyPrefix  = "vault.key." // followed by the version in decimal
	FieldReceivingKey    = "receiving.key"
	FieldSigningKey      = "signing.key"
)

// KeyHolder is one of the five key holders, numbered as the header carries it.
type KeyHolder uint8

// The five key holders.
const (
	WindowsKeyStore  KeyHolder = 1
	SystemdByService KeyHolder = 2
	SystemdAtStart   KeyHolder = 3
	KeyFile          KeyHolder = 4
	SwarmSecret      KeyHolder = 5
)

// ServiceAccount is the account hadv-service runs under, by name: NT SERVICE\... on Windows, a
// system user on Linux. hadv-setup owns it; this package grants it the key and names it to
// systemd.
type ServiceAccount string

// The codes, one per cause of failure, never prose. The returned error is an Error, holding the
// code and, where there is one, the OS's own error beneath it.
var (
	// ErrNotFound: the bootstrap folder or the bootstrap file is not there.
	ErrNotFound = errors.New("bootstrap: not found")
	// ErrUnreadable: the bootstrap folder or the bootstrap file is there and opening or reading
	// it fails.
	ErrUnreadable = errors.New("bootstrap: unreadable")
	// ErrFormat: the header does not match format version 1's layout, the format version is
	// newer, or the file is over 64 KiB.
	ErrFormat = errors.New("bootstrap: format")
	// ErrKey: the key holder gives no bootstrap key, or gives one that is not a 256-bit key; or
	// the platform does not have the key holder.
	ErrKey = errors.New("bootstrap: key")
	// ErrDecrypt: the bootstrap file does not unseal under the bootstrap key.
	ErrDecrypt = errors.New("bootstrap: decrypt")
	// ErrInvalid: the fields or the records break the rules of a valid bootstrap file, as read or
	// as the caller would save them.
	ErrInvalid = errors.New("bootstrap: invalid")
	// ErrExists: create is called with overwrite false and a bootstrap file is present.
	ErrExists = errors.New("bootstrap: exists")
	// ErrWrite: writing the new file, opening it, or putting it in place of the old one fails.
	ErrWrite = errors.New("bootstrap: write")
)

// Place is which one a code is about, for ErrNotFound and ErrUnreadable: the bootstrap folder
// or bootstrap.hadv. hadv-setup makes a missing folder again, but offers create or restore for a
// missing file.
type Place uint8

// The places. PlaceNone goes with every other code.
const (
	PlaceNone Place = iota
	PlaceFolder
	PlaceFile
)

// Error is the error every operation returns when it fails. errors.Is finds its code;
// errors.As finds the Error, with its place, and the OS's own error beneath it. None of them
// carries a secret.
type Error struct {
	Code  error // one of the codes above
	Place Place // PlaceNone unless Code is ErrNotFound or ErrUnreadable
	Err   error // the OS's own error, or nil
}

// Error gives the code, the place and the OS's error as text, for a log. Declared here so that
// errors.As has one type to find.
func (e *Error) Error() string {
	s := e.Code.Error()
	switch e.Place {
	case PlaceFolder:
		s += ": folder"
	case PlaceFile:
		s += ": " + FileName
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

// Unwrap gives the code and the OS's error, so errors.Is and errors.As reach both.
func (e *Error) Unwrap() []error {
	if e.Err == nil {
		return []error{e.Code}
	}
	return []error{e.Code, e.Err}
}

// Key256 is a 256-bit key held as a value: assigning or returning it copies the 32 bytes, so no
// two holders share them. The bootstrap key and each vault key are one.
type Key256 [32]byte

// VaultKey is one vault key, numbered as the shared secrets unit numbers it.
type VaultKey struct {
	Version uint32
	Key     Key256
}

// Fields is the known fields, what crosses the edge. Secrets are bytes, never strings, so they
// can be zeroed. Every Fields the handle gives out is a fresh copy of every secret, never the
// handle's own memory; whoever holds a copy is responsible for zeroing it with Zero (the
// developer: "Everything that touches something security sensitive has to be responsible for its
// own stuff"). Go's garbage collector may leave the bytes elsewhere in memory, so zeroing is best
// effort (runtime/secret to be revisited once it is stable). Unknown records never cross: the
// handle keeps them and writes them back.
//
//   - If the fields create or save is passed, or the fields open reads from a file, break a rule
//     the Fields type gives, then the bootstrap package shall return ErrInvalid.
//   - The bootstrap package shall zero every buffer it fills with the bootstrap key or the
//     unsealed records before create, open or save returns, except the handle's own. [read]
//
// A file read or fields saved get ErrInvalid when:
//
//	any known field             its record is missing from the file
//	Server                      it is 0
//	Connection, AccountName     it is empty or not UTF-8
//	AccountPassword             it is empty
//	VaultKeys                   it holds none, more than two, two of one version, or a key of
//	                            version 0
//	ReceivingKey, SigningKey    it is empty
type Fields struct {
	Server          board.ServerID
	Connection      string // the database connection, with no account in it
	AccountName     string // the server's database account
	AccountPassword []byte
	VaultKeys       []VaultKey // one; two during a vault-key change, old and new
	ReceivingKey    []byte     // the private half; opaque here
	SigningKey      []byte     // the private half; opaque here
}

// Zero zeroes every secret in this copy of the fields. With Error's two methods, the only bodies
// in this contract: small, and the same for every holder.
func (fields *Fields) Zero() {
	clear(fields.AccountPassword)
	for i := range fields.VaultKeys {
		clear(fields.VaultKeys[i].Key[:])
	}
	clear(fields.ReceivingKey)
	clear(fields.SigningKey)
}

// File is an opened bootstrap file. The file itself is closed; the handle holds its fields, its
// header, its unknown records, the bootstrap key and the folder's path, so it saves only back to
// the file it came from.
type File interface {
	// Fields is a fresh copy of the fields as opened or last saved. The caller changes its copy,
	// passes it to Save, and zeroes it with Zero when done.
	Fields() Fields

	// KeyHolder and SealedKey are for hadv-setup's repair step, which rewrites the service
	// registration from them. SealedKey is a fresh copy; it is no secret.
	KeyHolder() KeyHolder
	SealedKey() []byte

	// Save seals the fields under the handle's bootstrap key, with the same header and a new
	// nonce, unknown records in their places, through the write path. The key holder is not
	// asked again. The handle keeps its own copy of what it saved; the caller's stays the
	// caller's to zero. Results: ErrNotFound, ErrUnreadable, ErrInvalid, ErrWrite.
	//
	//   - If the bootstrap folder or bootstrap.hadv is not there, then save shall return
	//     ErrNotFound before it writes bootstrap.hadv.new.
	//   - When save is called, save shall write the header the file was opened with and seal
	//     under the handle's bootstrap key, without asking the key holder.
	//   - If save fails, then the handle shall keep the fields it held before the save.
	//   - When save succeeds, the handle shall hold the fields it saved.
	Save(fields Fields) error

	// Release zeroes every secret the handle holds, its own copies and the bootstrap key, best
	// effort, as on Fields. The handle is not used after.
	//
	//   - When release is called, release shall zero every secret the handle holds, the
	//     bootstrap key included.
	Release()
}

// Bootstrap is the entry. Both programs call Open; only hadv-setup calls Create. Each takes a
// context with a deadline, for the calls out to a key holder.
type Bootstrap interface {
	// Create makes a new bootstrap file in folder, sealed under holder: with a new bootstrap key
	// for key holders 1 to 3, granted to account where the key holder needs it; under the key
	// the key file or Swarm secret holds for 4 and 5. With overwrite false and a file present, it
	// refuses before it makes anything. With overwrite true, it never reads the old file: the new
	// file goes in place only after it opens. So a file copied from another system, whose header
	// names a key holder this platform lacks, is still replaced. The old file's Windows key, if it
	// had one, is left: named hadv-, it opens nothing and blocks nothing, and hadv-setup may list
	// it for the sysop. A failure leaves the folder and the key holder as they were, deleting any
	// key it made.
	//
	// After a failure it returns the name of the Windows key it made and could not delete, beside
	// the code, or "" for none. Results: ErrNotFound, ErrUnreadable, ErrExists, ErrInvalid,
	// ErrKey, ErrWrite.
	//
	//   - If the bootstrap folder is not there, then create shall return ErrNotFound.
	//   - If create is called with overwrite false and bootstrap.hadv is present, then create
	//     shall return ErrExists before it makes a bootstrap key or writes a file.
	//   - If create returns ErrNotFound or ErrInvalid, then create shall return it before it makes
	//     a bootstrap key or writes a file.
	//   - If create fails after it makes a Windows key, then create shall delete that key.
	//   - If create fails and deleting the Windows key it made fails, then create shall return
	//     that key's name with the failure's code.
	Create(ctx context.Context, folder string, holder KeyHolder, account ServiceAccount,
		fields Fields, overwrite bool) (undeleted string, err error)

	// Open reads bootstrap.hadv in folder, gets the bootstrap key from the key holder its header
	// names, unseals it and closes it before returning. account is used only by key holder 2.
	// Results: ErrNotFound, ErrUnreadable, ErrFormat, ErrKey, ErrDecrypt, ErrInvalid.
	//
	//   - If the bootstrap folder or bootstrap.hadv is not there, then open shall return
	//     ErrNotFound.
	//   - If bootstrap.hadv is there and opening or reading it fails, then open shall return
	//     ErrUnreadable with the OS's cause beneath it.
	//   - If bootstrap.hadv holds more than 65,536 bytes, then open shall return ErrFormat, having
	//     read at most 65,537 bytes of it.
	//   - If a part of the header does not match the table the package comment gives for format
	//     version 1, or the file is too short for its header, nonce and tag, then open shall
	//     return ErrFormat before it asks the key holder.
	//   - If the GCM tag does not verify under the bootstrap key, then open shall return
	//     ErrDecrypt and no handle.
	//   - When open returns a handle, the handle shall give the file's fields, its key holder and
	//     its sealed key.
	Open(ctx context.Context, folder string, account ServiceAccount) (File, error)
}

// holder is the five key holders behind one interface, inside the package and not offered to
// callers, so platform differences live in them and not in Create, Open or Save.
type holder interface {
	// newKey makes a new bootstrap key and its sealed form for the header, granted to account
	// where the key holder needs it. Key holders 4 and 5 make nothing: the key they hold, and
	// no sealed key. folder is the bootstrap folder's root, open for the call that holds it;
	// the key file holder reads bootstrap.key through it, and the others ignore it.
	newKey(ctx context.Context, folder *os.Root, account ServiceAccount) (
		key Key256, sealedKey []byte, err error)

	// key is the bootstrap key, from the sealed key the header carries (key holders 1 to 3) or
	// the key file or Swarm secret (4 and 5): exactly 32 bytes, or ErrKey. folder as on newKey.
	key(ctx context.Context, folder *os.Root, sealedKey []byte, account ServiceAccount) (
		Key256, error)

	// deleteKey deletes the Windows key the sealed key names, for key holder 1; the others do
	// nothing, since a systemd credential lives only in the header and the sysop's keys are the
	// sysop's.
	deleteKey(ctx context.Context, sealedKey []byte) error
}

// The key-holder interface is declared here for the build to implement; this keeps it in use
// until it does.
var _ holder = nil
