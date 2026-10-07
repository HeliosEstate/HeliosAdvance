// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package bootstrap is the bootstrap key subsystem: one server's bootstrap file, sealed with
// AES-256-GCM under the bootstrap key, and that key held by the OS credential store. It owns
// the file: its envelope and named fields (fields it does not know are kept unchanged),
// building it, unlocking it, rewriting it beside the old one and swapping it in one step,
// and deleting a half-made one. It also owns the bootstrap key, made from 256 random bits
// and sealed and unsealed by the OS credential store (the CNG machine key pair on Windows,
// systemd credentials on Linux), or read from a Swarm secret or a key file the sysop made;
// the checks on what it opens, each made on the open handle and never by name; the rules
// those checks use; and setting one item to its rule when hadv-setup asks. For the detailed
// health report, it reports how the bootstrap key is held and a rewrite that failed.
//
// It does not own creating the service account, the bootstrap folder or the service
// registration, or offering a permission fix and asking the sysop: those are hadv-setup's.
// What the vault keys and private keys mean is the shared secrets subsystem's; using the
// database connection is the database-access unit's. The retry timer, the words of a
// refusal and every log line belong to hadv-service and hadv-setup, built from what this
// package returns. The health report is the Admin API's.
//
// Two programs link this package and it cannot ask which one is calling, so each gets its
// own handle. hadv-setup's operations are refused unless the process is elevated or root.
// hadv-service's handle changes the vault-key fields and nothing else, and is refused when
// elevated or root, since hadv-service runs only as the account that owns the bootstrap
// folder. hadv-service therefore has no way to ask for a change to any other field.
//
// # Where things are
//
// Every file sits in the bootstrap folder, which is opened once and used through its
// handle:
//
//	bootstrap.hadv         the bootstrap file
//	bootstrap.hadv.new     a rewrite in progress; found at start, a half-made file
//	bootstrap.lock         locked exclusively while any handle is open
//	bootstrap-key.sealed   Windows: the bootstrap key under the machine key pair
//	bootstrap-key.cred     Linux: the bootstrap key as a systemd credential
//	bootstrap.key          the key file, made by the sysop
//
// A Swarm secret is /run/secrets/heliosadvance-bootstrap-key, and on Windows the machine key
// pair is named heliosadvance-bootstrap-key in the CNG key store. The bootstrap folder
// defaults to %ProgramData%\HeliosAdvance on Windows and /var/lib/heliosadvance on Linux; in a
// container it is always /var/lib/heliosadvance, a volume. The service account is the
// virtual account NT SERVICE\HeliosAdvance on Windows and the system user heliosadvance on
// Linux. Every file in the bootstrap folder other than the key file takes the bootstrap
// file's permission rule. A key file or Swarm secret is RFC 4648's standard base64 alphabet
// with its padding, and each key has one spelling: the bits after its last byte are zero.
//
// The folder rules. The bootstrap folder is refused when:
//
//	NotAbsolute    its path is not absolute
//	NetworkShare   it is on a network share
//	Removable      the OS reports it on a removable drive
//	FolderLink     it is a symbolic link or, on Windows, a junction
//	FileSystem     its file system is not NTFS or ReFS on Windows, or ext2, ext3, ext4,
//	               XFS, Btrfs or ZFS on Linux
//
// The permission table, each item's rule for the service account:
//
//	Item                Linux and a container           Windows
//	ItemFolder          owned by it, mode 0700          it, SYSTEM and Administrators only,
//	                                                    with no inherited access
//	ItemFile            owned by it, mode 0600          the same as ItemFolder
//	ItemOtherFile       ItemFile's rule                 ItemFile's rule
//	ItemKeyFile         owned by it, mode 0400          none: no key file on Windows
//	ItemSwarmSecret     owned by it, mode 0400          none
//	ItemMachineKeyPair  none                            usable only by it, SYSTEM and
//	                                                    Administrators
//
// On Windows the owner of every item is the service account, SYSTEM or Administrators, since
// an owner can rewrite the access list whatever it says; an item set to its rule is owned by
// Administrators.
//
// On Linux the bootstrap key is unsealed one of two ways, chosen by hadv-setup at build and
// recorded in the service registration. On systemd 256 and later the credential is
// user-scoped and this package decrypts it at each use. Below 256, systemd decrypts it when
// the service starts, into the service's credential folder in memory that is never swapped,
// and this package reads it from there at each use. A server has systemd when systemd is its
// running service manager, as systemd's own test for that reports, and its version is the
// running manager's, not the installed program's.
//
// # The bootstrap file, format version 1
//
// Every number is unsigned and big-endian.
//
//	offset 0     8 bytes   magic: the ASCII characters HADVBOOT
//	offset 8     2 bytes   format version: 1
//	offset 10   12 bytes   nonce: random, new on every write
//	offset 22    n bytes   the AES-256-GCM ciphertext of the fields, under the bootstrap key,
//	                       with the 22 bytes before it as the additional authenticated data
//	then        16 bytes   the GCM tag
//
// The whole file is at most 65,536 bytes. Only the magic and the format version are read
// before the integrity check. The fields, once decrypted, are records one after another to
// the end of the plaintext:
//
//	2 bytes    name length, 1 to 255
//	n bytes    name, UTF-8, unique in the file
//	4 bytes    data length
//	n bytes    data
//
// The known names and their data:
//
//	server                       4 bytes: the server's ID
//	database.connection          UTF-8: the database connection, with no account in it
//	database.account.name        UTF-8: the server's database account
//	database.account.password    bytes
//	vault.key.<version>          32 bytes, one record per vault key; the version in decimal
//	receiving.key                bytes: the receiving key pair's private half
//	signing.key                  bytes: the signing key pair's private half
//
// A vault key's version is written in decimal with no leading zero, from 1 to 4,294,967,295,
// so each version has one name; a name that begins with vault.key. and is spelled any other
// way is a malformed field, never an unknown record. A record with any other name is kept
// unchanged, in its place, when the file is rewritten.
//
// On Windows, bootstrap-key.sealed is the bootstrap key encrypted with RSA-OAEP under the
// machine key pair (RSA 2048, SHA-256 with MGF1 SHA-256, no label): 256 bytes, nothing
// around them. On Linux, bootstrap-key.cred is systemd's own credential format, named for
// its purpose and bound to no TPM PCR.
//
// The lines for the file:
//
//   - The bootstrap package shall write the bootstrap file only in the layout this package
//     comment gives for format version 1.
//   - The bootstrap package shall write a new random nonce each time it writes the bootstrap
//     file.
//   - The bootstrap package shall write each vault key as a record of its own, named vault.key.
//     followed by its version in decimal.
//   - If the bootstrap file is larger than 65,536 bytes, then the bootstrap package shall
//     refuse it with FileNotUnsealed without reading its contents.
//   - If the bootstrap file is shorter than its 22-byte header and 16-byte tag, then the
//     bootstrap package shall refuse it with FileNotUnsealed.
//   - If the bootstrap file does not begin with the magic HADVBOOT, then the bootstrap package
//     shall refuse it with FileNotUnsealed.
//   - If the bootstrap file's format version is 0, then the bootstrap package shall refuse it
//     with FileNotUnsealed.
//   - If the bootstrap file's format version is newer than 1, then the bootstrap package shall
//     refuse it with NewerFormat, naming both versions.
//   - If the GCM tag does not verify, then the bootstrap package shall refuse the bootstrap
//     file with FileNotUnsealed.
//   - The bootstrap package shall act on no part of the bootstrap file but its size, its magic
//     and its format version before the GCM tag verifies. [read]
//   - If a record's name or data runs past the end of the plaintext, then the bootstrap package
//     shall refuse the bootstrap file with FileNotUnsealed.
//   - If a record's name is empty, longer than 255 bytes, or not UTF-8, then the bootstrap
//     package shall refuse the bootstrap file with FileNotUnsealed.
//   - If two records share a name, then the bootstrap package shall refuse the bootstrap file
//     with FileNotUnsealed.
//   - If a known field is absent, its data breaks the form the format gives it, or it breaks a
//     rule in the table on Fields, then the bootstrap package shall refuse the bootstrap file
//     with FileNotUnsealed.
//   - If the bootstrap file holds no vault key or more than two, then the bootstrap package
//     shall refuse it with FileNotUnsealed.
//   - If a record's name begins with vault.key. and the rest is not a version in decimal from 1
//     to 4,294,967,295 with no leading zero, then the bootstrap package shall refuse the
//     bootstrap file with FileNotUnsealed.
//   - When the bootstrap package rewrites the bootstrap file, it shall keep every record of an
//     unknown name byte for byte, in the order it was read.
//   - The bootstrap package shall put no key, no field's data and no field's length in a
//     Refusal. [read]
//
// # A rewrite
//
// A rewrite is any of SetupHandle.Rewrite, ServiceHandle.AddVaultKey and
// ServiceHandle.RemoveVaultKey. The lines for every rewrite:
//
//   - Rewrite shall read the bootstrap key again for each rewrite from where its mode holds it:
//     unsealed by the OS credential store, or read from the key file or the Swarm secret.
//   - Where the mode is not ModeSystemdAtStart, AddVaultKey and RemoveVaultKey shall read the
//     bootstrap key again for each rewrite from where its mode holds it: unsealed by the OS
//     credential store, or read from the key file or the Swarm secret.
//   - Where the mode is ModeSystemdAtStart, AddVaultKey and RemoveVaultKey shall read the
//     bootstrap key again from the credential folder systemd gives the service for each
//     rewrite. [run]
//   - If the bootstrap key is absent at a rewrite, then the rewrite shall refuse with
//     KeyNotFound.
//   - If the OS credential store does not unseal the bootstrap key at a rewrite, then the
//     rewrite shall refuse with KeyNotUnsealed.
//   - A rewrite shall create bootstrap.hadv.new exclusively, already set to its rule. [read]
//   - A rewrite shall write bootstrap.hadv.new, flush it, check that it reads back, and then
//     rename it over bootstrap.hadv through the folder's handle. [read]
//   - Where the server runs Linux, a rewrite shall flush the folder after the rename. [read]
//   - If bootstrap.hadv.new does not read back, then the rewrite shall delete it, keep the old
//     bootstrap file, and refuse with RewriteFailed. [read]
//   - If writing bootstrap.hadv.new fails, then the rewrite shall delete what it wrote, keep
//     the old bootstrap file, and refuse with RewriteFailed.
//   - If a rewrite fails, then the handle shall keep the fields it held before the rewrite.
//   - If a rewrite fails, then the handle shall record the failure for RewriteFailure.
//   - A rewrite shall overwrite the bootstrap key in its memory before it returns. [read]
//
// # Untrusted input and oracles
//
// Each parser of untrusted input is a fuzz target: the header reader and the field-record
// reader, seeded by the format's sample files, and the reader of a key file or Swarm
// secret. The files and folder as found, the sealed-key file and the fields a caller
// passes in are checked but not parsed. The service registration is trusted: only root or
// administrators change it. The oracles are the CNG key store driven through PowerShell,
// systemd-creds, AES-256-GCM's published test vectors and OpenSSL, and, for the file
// format, the developer's own oracle in oracle/bootstrap-file, whose sample files for each
// format version are kept for good in testdata.
//
// This file is the developer's contract (HeliosDesign records/skeleton/Bootstrap.pas) and is
// locked: a loop session does not edit it.
package bootstrap

import (
	"context"
	"io/fs"
	"time"

	"github.com/heliosestate/heliosadvance/internal/board"
)

// The file's constants, as the format above states them.
const (
	Magic         = "HADVBOOT"
	FormatVersion = 1
	MaxSize       = 65536 // bytes; a larger file is refused as corrupt, unread
	TagSize       = 16    // the AES-256-GCM tag, after the ciphertext
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

// VaultKey is one vault key, numbered as the shared secrets subsystem numbers it.
type VaultKey struct {
	Version uint32
	Key     []byte // 32 bytes
}

// Fields is the known fields. Secrets are byte slices, never strings, so Close can overwrite
// them; the garbage collector may leave the bytes elsewhere in memory, so the overwrite
// narrows the exposure and does not end it. Unknown fields never cross this edge: the handle
// keeps them and writes them back unchanged.
//
// A field breaks its rule when:
//
//	Server                      it is 0
//	Connection, AccountName     it is empty
//	VaultKeys                   it holds none, more than two, two of one version, a key of
//	                            version 0, or a key that is not 32 bytes
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

// KeySource is where hadv-setup asks Build to take the bootstrap key from.
type KeySource uint8

// Key sources. FromOSStore makes a new key in the platform's OS credential store. FromKeyFile
// is the sysop's explicit choice, accepted only on Linux without systemd 250 or later.
// FromContainer is passed by the shipped image: the Swarm secret or the key file, whichever
// is present.
const (
	FromOSStore KeySource = iota + 1
	FromKeyFile
	FromContainer
)

// KeyMode is which way the bootstrap key is held. Build returns it, hadv-setup writes it into
// the service registration, and hadv-service passes it back to UnlockForService.
type KeyMode uint8

// Key modes. In a container the shipped image's command line passes ModeContainer, decided at
// each unlock by which of the Swarm secret and the key file is present.
//
// A platform's modes, the ones an unlock accepts on it:
//
//	Windows                        ModeMachineKeyPair
//	Linux without systemd          ModeKeyFile, ModeContainer
//	Linux, systemd below 250       ModeKeyFile
//	Linux, systemd 250 to 255      ModeSystemdAtStart, ModeKeyFile
//	Linux, systemd 256 or later    ModeSystemdPerUse, ModeSystemdAtStart, ModeKeyFile
//
// A server whose systemd was upgraded after Build keeps the mode Build gave it.
const (
	ModeMachineKeyPair KeyMode = iota + 1
	ModeSystemdPerUse
	ModeSystemdAtStart
	ModeKeyFile
	ModeContainer
)

// Holding is how the bootstrap key is held, for the detailed health report. No warning goes
// with HeldInSoftwareKeyStore or HeldUnderHostKey: a TPM is never required.
type Holding uint8

// Holdings.
const (
	HeldInTPM Holding = iota + 1
	HeldInSoftwareKeyStore
	HeldUnderHostKey
	HeldAsSwarmSecret
	HeldInKeyFile
)

// BuildPath is which of hadv-setup's paths is building.
type BuildPath uint8

// Build paths. At first setup and joining, an existing machine key pair of this package's
// name is refused; at joining again and restore it is deleted and a new one made.
const (
	FirstSetup BuildPath = iota + 1
	Joining
	JoiningAgain
	Restore
)

// Item is what a permission rule covers.
type Item uint8

// Items. OtherFile is any other file in the bootstrap folder (the sealed-key file, the lock,
// a half-made file), under the bootstrap file's rule.
const (
	ItemFolder Item = iota + 1
	ItemFile
	ItemOtherFile
	ItemKeyFile
	ItemSwarmSecret
	ItemMachineKeyPair
)

// FolderRule is which folder rule was broken.
type FolderRule uint8

// Folder rules. Removable is what the OS reports, so a USB hard disk the OS calls fixed
// passes.
const (
	NotAbsolute FolderRule = iota + 1
	NetworkShare
	Removable
	FolderLink
	FileSystem
)

// Cause is why an operation was refused. The first five are where an unlock fails;
// hadv-service turns each into the path, the cause in plain words and what the sysop does
// next.
type Cause uint8

// Causes.
const (
	KeyNotFound          Cause = iota + 1 // no sealed-key file, Swarm secret or key file
	KeyNotUnsealed                        // the store refused: another machine, or corrupt
	FileNotFound                          // no bootstrap file
	FileNotUnsealed                       // corrupt or altered; or, under a Swarm secret or key file, not this file's key
	NewerFormat                           // FileVersion and OwnVersion name both
	FolderRefused                         // Rule names which
	LooserThanRule                        // Item names what
	NotWritable                           // the bootstrap file, for the service account
	Link                                  // an item is a symbolic link, a junction, or a file with more than one name
	WrongAccount                          // not the account that owns the bootstrap folder
	NotElevated                           // a hadv-setup operation without administrator or root rights
	KeyFileMalformed                      // not 32 bytes as base64 in 44 characters, at most one trailing newline
	NoCredentialStore                     // Linux without systemd 250 or later, and no key file chosen
	NoKeySource                           // a container with neither a Swarm secret nor a key file
	BothKeySources                        // a container with both
	MachineKeyPairExists                  // at first setup or joining
	InUse                                 // another handle holds the lock: the service is running
	FieldMalformed                        // Field names which, never its data
	VaultKeyConflict                      // AddVaultKey: that version held with other bytes, or two held
	RewriteFailed                         // the new file was not written or did not read back; the old one is kept
	SourceRefused                         // a key source or mode this platform does not allow
	FileExists                            // a bootstrap file is already there at first setup or joining
	TPMLibrariesMissing                   // Linux: a TPM, but not the libraries systemd needs to use it (tpm2-tss)
)

// Refusal is the one refusal every operation returns, tested with errors.As. It carries no
// key and no field's data, so it belongs in any log or message as it is.
type Refusal struct {
	Cause       Cause
	Path        string
	Item        Item       // LooserThanRule; Link from Check
	Rule        FolderRule // FolderRefused
	Field       string     // FieldMalformed: the field's name as the bootstrap file names it; vault.key. alone when the count of vault keys is wrong
	FileVersion uint16     // NewerFormat
	OwnVersion  uint16     // NewerFormat
}

// Permissions is who owns an item and who can reach it, as data: hadv-setup writes the words.
// An account is named as the OS resolves it: DOMAIN\name on Windows (NT AUTHORITY\SYSTEM,
// BUILTIN\Administrators), the user name on Linux.
type Permissions struct {
	Owner     string      // the account that owns it
	Mode      fs.FileMode // Linux and a container: its permission bits
	Accounts  []string    // Windows: every account its access list grants anything
	Inherited bool        // Windows: its access list inherits from the folder above
}

// Finding is one item set looser than its rule: what hadv-setup shows before it asks.
type Finding struct {
	Item  Item
	Path  string      // for ItemMachineKeyPair, the key pair's name
	Found Permissions // as found
	Rule  Permissions // what SetToRule sets
}

// RewriteFailure is the last rewrite that failed, for the detailed health report. Failed is
// false once a rewrite succeeds.
type RewriteFailure struct {
	Failed bool
	Path   string
	When   time.Time // UTC
}

// Handle is what both handles share. If Rewrite, AddVaultKey or RemoveVaultKey is called
// after Close:
//
//   - If Rewrite, AddVaultKey or RemoveVaultKey is called after Close, then it shall refuse
//     with RewriteFailed.
type Handle interface {
	// Fields is the known fields, in memory of their own. Unknown fields stay inside the
	// handle.
	//
	//   - Fields shall return the known fields in memory of their own, so that a change to what it
	//     returns changes nothing in the handle.
	Fields() Fields

	// Holding is how the bootstrap key is held. hadv-service logs a warning at every start
	// when it is HeldInKeyFile.
	//
	//   - Holding shall return how the bootstrap key was held when the handle was unlocked.
	Holding() Holding

	// RewriteFailure is the last rewrite that failed. On a failure the handle's fields are
	// unchanged; the caller keeps what it meant to write and retries: hadv-service on its
	// timer and at every start, hadv-setup by telling the sysop.
	//
	//   - RewriteFailure shall return the path and the UTC time of the last rewrite that failed,
	//     with Failed set.
	//   - When a rewrite succeeds, the handle shall clear Failed in what RewriteFailure returns.
	RewriteFailure() RewriteFailure

	// Close overwrites every secret the handle holds and releases the lock.
	//
	//   - Close shall overwrite with zeros every secret the handle holds and every unknown record
	//     it keeps. [read]
	//   - Close shall release the lock.
	//   - If Close is called a second time, then Close shall do nothing.
	Close()
}

// SetupHandle is hadv-setup's handle: any field.
type SetupHandle interface {
	Handle

	// Rewrite unseals the bootstrap key again, writes the new file beside the old with every
	// unknown field unchanged, and swaps it in. hadv-setup calls it only with the service
	// stopped, which the lock enforces. It follows the lines for every rewrite in the package
	// comment, and:
	//
	//   - If a field breaks a rule in the table on Fields, then Rewrite shall refuse with
	//     FieldMalformed, naming the field.
	Rewrite(ctx context.Context, fields Fields) error
}

// ServiceHandle is hadv-service's handle: the vault-key fields and nothing else. Its two
// writes follow the lines for every rewrite in the package comment.
//
//   - The ServiceHandle shall offer no operation that changes any field other than the
//     vault-key fields. [read]
type ServiceHandle interface {
	Handle

	// AddVaultKey is called during a vault-key change.
	//
	//   - If the key's version is held with the same bytes, then AddVaultKey shall write nothing
	//     and succeed.
	//   - If the key's version is held with other bytes, then AddVaultKey shall refuse with
	//     VaultKeyConflict.
	//   - If two vault keys are held and the key's version is neither of them, then AddVaultKey
	//     shall refuse with VaultKeyConflict.
	//   - If the key is not 32 bytes, then AddVaultKey shall refuse with FieldMalformed, naming
	//     its field.
	//   - When one vault key is held and the key's version is new, AddVaultKey shall rewrite the
	//     bootstrap file with the key added.
	AddVaultKey(ctx context.Context, key VaultKey) error

	// RemoveVaultKey is called when a vault-key change finishes.
	//
	//   - If the version is not held, then RemoveVaultKey shall write nothing and succeed.
	//   - If the version is the only vault key held, then RemoveVaultKey shall refuse with
	//     FieldMalformed, naming its field.
	//   - When two vault keys are held and the version is one of them, RemoveVaultKey shall
	//     rewrite the bootstrap file without it.
	RemoveVaultKey(ctx context.Context, version uint32) error
}

// Bootstrap is the contract, and New returns it. The folder is the bootstrap folder from the
// service registration: empty means the platform's default, and in a container it is ignored
// for the fixed path. The account is the service account. Every operation that reaches the OS
// credential store carries a context with a deadline. Every refusal is a *Refusal, never a
// default.
type Bootstrap interface {
	// Build is called by hadv-setup, elevated, in a folder hadv-setup has made, after it has
	// registered the service so that the account exists. It returns the mode to record in
	// the service registration.
	//
	//   - If the process is neither elevated nor root, then Build shall refuse with NotElevated.
	//   - If another handle holds the lock, then Build shall refuse with InUse.
	//   - If the folder breaks a folder rule, then Build shall refuse with FolderRefused, naming
	//     the rule.
	//   - If a field breaks a rule in the table on Fields, then Build shall refuse with
	//     FieldMalformed, naming the field.
	//   - If a bootstrap file is in the folder and the path is FirstSetup or Joining, then Build
	//     shall refuse with FileExists.
	//   - If the source is FromKeyFile where the server runs Windows or has systemd 250 or later,
	//     then Build shall refuse with SourceRefused.
	//   - If the source is FromContainer where the server runs Windows or Linux with systemd, then
	//     Build shall refuse with SourceRefused.
	//   - If the source is FromOSStore where the server runs Linux without systemd 250 or later,
	//     then Build shall refuse with NoCredentialStore.
	//   - When the source is FromOSStore, Build shall make the bootstrap key from 256 bits read
	//     from the operating system's random source. [read]
	//   - Where the server runs Windows, when the source is FromOSStore, Build shall make a
	//     2048-bit RSA machine key pair that is not exportable.
	//   - Where the server runs Windows and has a TPM, Build shall make the machine key pair in
	//     the Microsoft Platform Crypto Provider. [run]
	//   - Where the server runs Windows without a TPM, Build shall make the machine key pair in
	//     the Microsoft Software Key Storage Provider.
	//   - Where the server runs Windows, Build shall give the machine key pair an access list
	//     naming only the account, SYSTEM and Administrators.
	//   - If a machine key pair of this package's name exists and the path is FirstSetup or
	//     Joining, then Build shall refuse with MachineKeyPairExists.
	//   - When the path is JoiningAgain or Restore, Build shall delete any machine key pair of
	//     this package's name before it makes the new one.
	//   - Where the server runs Windows, Build shall write bootstrap-key.sealed as the bootstrap
	//     key encrypted with RSA-OAEP under the machine key pair, as this package comment gives
	//     it.
	//   - Where the server runs Windows, when the source is FromOSStore, Build shall return
	//     ModeMachineKeyPair.
	//   - Where the server runs Linux with systemd 256 or later, when the source is FromOSStore,
	//     Build shall seal the bootstrap key as a credential scoped to the account and return
	//     ModeSystemdPerUse.
	//   - Where the server runs Linux with systemd 250 to 255, when the source is FromOSStore,
	//     Build shall seal the bootstrap key as a system credential and return ModeSystemdAtStart.
	//   - Where the server runs Linux and has a TPM, Build shall have systemd seal the bootstrap
	//     key under both the TPM and the host key. [run]
	//   - Where the server runs Linux and has a TPM, Build shall ask systemd for the TPM and the
	//     host key by name, never for systemd's default choice. [read]
	//   - If the server runs Linux and has a TPM without the libraries systemd needs to use it,
	//     then Build shall refuse with TPMLibrariesMissing. [run]
	//   - Where the server runs Linux without a TPM, Build shall have systemd seal the bootstrap
	//     key under the host key.
	//   - Where the server runs Linux, Build shall name the credential heliosadvance-bootstrap-key.
	//   - Where the server runs Linux and has a TPM, Build shall bind the credential to no PCR.
	//     [run]
	//   - When the source is FromKeyFile, Build shall read the bootstrap key from bootstrap.key in
	//     the folder and return ModeKeyFile.
	//   - When the source is FromContainer, Build shall read the bootstrap key from the Swarm
	//     secret or the key file and return ModeContainer.
	//   - If the source is FromContainer and neither a Swarm secret nor a key file is present,
	//     then Build shall refuse with NoKeySource.
	//   - If the source is FromContainer and both a Swarm secret and a key file are present, then
	//     Build shall refuse with BothKeySources.
	//   - If the source is FromKeyFile and the key file is absent, then Build shall refuse with
	//     KeyNotFound.
	//   - If the key file is a symbolic link or a file with more than one name, then Build shall
	//     refuse with Link.
	//   - If a key file or Swarm secret holds anything other than 32 bytes as base64 in 44
	//     characters with at most one trailing newline, then Build shall refuse with
	//     KeyFileMalformed.
	//   - When the source is FromKeyFile or FromContainer, Build shall make no bootstrap key and
	//     no machine key pair.
	//   - Build shall set the folder to its rule before it writes any file in it. [read]
	//   - Build shall create every file it writes already set to its rule, owned by or listed for
	//     the account. [read]
	//   - Build shall write the bootstrap file beside any old one, flush it, check that it reads
	//     back, and then swap it in. [read]
	//   - If the new bootstrap file does not read back, then Build shall refuse with RewriteFailed
	//     and delete it. [read]
	//   - If Build fails after it makes a machine key pair or a credential, then Build shall
	//     delete that machine key pair or credential. [read]
	//   - Build shall overwrite the bootstrap key in its memory before it returns. [read]
	Build(ctx context.Context, folder string, fields Fields, path BuildPath, account string, source KeySource) (KeyMode, error)

	// UnlockForSetup is called by hadv-setup, elevated. It unlocks and takes the lock.
	//
	//   - If the process is neither elevated nor root, then UnlockForSetup shall refuse with
	//     NotElevated.
	//   - If another handle holds the lock, then UnlockForSetup shall refuse with InUse.
	//   - If the folder breaks a folder rule, then UnlockForSetup shall refuse with FolderRefused,
	//     naming the rule.
	//   - If the bootstrap file or the key file is a symbolic link, a junction, or a file with
	//     more than one name, then UnlockForSetup shall refuse with Link.
	//   - UnlockForSetup shall not refuse an item set looser than its rule.
	//   - If bootstrap.hadv.new is in the folder, then UnlockForSetup shall delete it.
	//   - If the mode is not one of this platform's, then UnlockForSetup shall refuse with
	//     SourceRefused.
	//   - If the mode is ModeContainer and neither a Swarm secret nor a key file is present, then
	//     UnlockForSetup shall refuse with NoKeySource.
	//   - If the mode is ModeContainer and both a Swarm secret and a key file are present, then
	//     UnlockForSetup shall refuse with BothKeySources.
	//   - If the mode is not ModeContainer and the sealed-key file, the credential or the key file
	//     is absent, then UnlockForSetup shall refuse with KeyNotFound.
	//   - If a key file or Swarm secret holds anything other than 32 bytes as base64 in 44
	//     characters with at most one trailing newline, then UnlockForSetup shall refuse with
	//     KeyFileMalformed.
	//   - If the OS credential store does not unseal the bootstrap key, then UnlockForSetup shall
	//     refuse with KeyNotUnsealed.
	//   - If the credential is sealed under the TPM and the libraries systemd needs to use it are
	//     absent, then UnlockForSetup shall refuse with TPMLibrariesMissing. [run]
	//   - If the bootstrap file is absent, then UnlockForSetup shall refuse with FileNotFound.
	//   - Where the server runs Linux with systemd, UnlockForSetup shall have systemd decrypt the
	//     credential itself, in either mode.
	//   - UnlockForSetup shall overwrite the bootstrap key in its memory before it returns.
	//     [read]
	//   - When UnlockForSetup unlocks the bootstrap file, it shall return a handle that holds the
	//     lock until Close.
	UnlockForSetup(ctx context.Context, folder string, mode KeyMode) (SetupHandle, error)

	// Check is called by hadv-setup, elevated: every item set looser than its rule, empty
	// when all hold.
	//
	//   - If the process is neither elevated nor root, then Check shall refuse with NotElevated.
	//   - If the folder breaks a folder rule, then Check shall refuse with FolderRefused, naming
	//     the rule.
	//   - If an item in the folder is a file with more than one name, then Check shall refuse with
	//     Link, naming the item.
	//   - Check shall return one finding for each item set looser than its rule, with its path,
	//     what it found and its rule.
	//   - If every item holds to its rule, then Check shall return no finding.
	//   - Check shall judge which account owns each item, and each access list, against the
	//     account it is given.
	//   - Check shall change nothing. [read]
	//   - Check shall run without the lock.
	Check(folder string, mode KeyMode, account string) ([]Finding, error)

	// SetToRule is called by hadv-setup, elevated, after the sysop's yes. A Swarm secret's
	// file is mounted read-only: for it hadv-setup names the stack file's account and mode
	// settings instead of calling this.
	//
	//   - If the process is neither elevated nor root, then SetToRule shall refuse with
	//     NotElevated.
	//   - SetToRule shall set the finding's item to its rule for the account it is given, and
	//     change nothing else.
	//   - SetToRule shall set the item through the handle it opened, never by name alone.
	//     [read]
	//   - If the finding's item is a symbolic link, a junction, or a file with more than one name,
	//     then SetToRule shall refuse with Link.
	//   - If the finding's item is ItemSwarmSecret, then SetToRule shall refuse with
	//     LooserThanRule and change nothing.
	SetToRule(finding Finding, account string) error

	// UnlockForService is called by hadv-service, as the account that owns the bootstrap
	// folder. It runs every start check, takes the lock, deletes a half-made file and
	// unlocks.
	//
	//   - UnlockForService shall check the account first, then take the lock, then check the
	//     folder, the links and the permissions, then delete a half-made file, and only then
	//     unlock.
	//   - If the process runs elevated or as root, then UnlockForService shall refuse with
	//     WrongAccount.
	//   - If the process runs under any account other than the one that owns the bootstrap folder,
	//     then UnlockForService shall refuse with WrongAccount.
	//   - If another handle holds the lock, then UnlockForService shall refuse with InUse.
	//   - If the folder breaks a folder rule, then UnlockForService shall refuse with
	//     FolderRefused, naming the rule.
	//   - If the bootstrap file or the key file is a symbolic link, a junction, or a file with
	//     more than one name, then UnlockForService shall refuse with Link.
	//   - If an item in the permission table is set looser than its rule, then UnlockForService
	//     shall refuse with LooserThanRule, naming the item and its path.
	//   - If the bootstrap file is not writable by the service account, then UnlockForService
	//     shall refuse with NotWritable.
	//   - UnlockForService shall make every check on the handle it opened, never on a name alone.
	//     [read]
	//   - UnlockForService shall change no permission. [read]
	//   - If bootstrap.hadv.new is in the folder, then UnlockForService shall delete it.
	//   - If the mode is not one of this platform's, then UnlockForService shall refuse with
	//     SourceRefused.
	//   - If the mode is ModeContainer and neither a Swarm secret nor a key file is present, then
	//     UnlockForService shall refuse with NoKeySource.
	//   - If the mode is ModeContainer and both a Swarm secret and a key file are present, then
	//     UnlockForService shall refuse with BothKeySources.
	//   - If the mode is not ModeContainer and the sealed-key file, the credential or the key file
	//     is absent, then UnlockForService shall refuse with KeyNotFound.
	//   - If a key file or Swarm secret holds anything other than 32 bytes as base64 in 44
	//     characters with at most one trailing newline, then UnlockForService shall refuse with
	//     KeyFileMalformed.
	//   - If the OS credential store does not unseal the bootstrap key, then UnlockForService
	//     shall refuse with KeyNotUnsealed.
	//   - If the credential is sealed under the TPM and the libraries systemd needs to use it are
	//     absent, then UnlockForService shall refuse with TPMLibrariesMissing. [run]
	//   - If the bootstrap file is absent, then UnlockForService shall refuse with FileNotFound.
	//   - Where the mode is ModeSystemdPerUse, UnlockForService shall have systemd decrypt the
	//     credential for this unlock. [run]
	//   - Where the mode is ModeSystemdAtStart, UnlockForService shall read the bootstrap key from
	//     the credential folder systemd gives the service. [run]
	//   - Where the server runs Windows, UnlockForService shall report HeldInTPM when the machine
	//     key pair is in the Microsoft Platform Crypto Provider, and HeldInSoftwareKeyStore
	//     otherwise.
	//   - Where the server runs Linux with systemd, UnlockForService shall report HeldInTPM when
	//     the credential is sealed under the TPM, and HeldUnderHostKey otherwise.
	//   - UnlockForService shall report HeldAsSwarmSecret for a Swarm secret and HeldInKeyFile for
	//     a key file.
	//   - UnlockForService shall overwrite the bootstrap key in its memory before it returns.
	//     [read]
	//   - When UnlockForService unlocks the bootstrap file, it shall return a handle that holds
	//     the lock until Close.
	UnlockForService(ctx context.Context, folder string, mode KeyMode) (ServiceHandle, error)
}
