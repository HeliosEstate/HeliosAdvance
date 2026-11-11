// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package bootstrap is the engine's bootstrap folder: the bootstrap file, sealed, and where its key
// is held: the key file; on Windows a machine key in Microsoft's TPM or software key store; on
// Linux a credential systemd hands the service at start, or a Swarm secret.
//
// It owns reading both files through the folder; the bootstrap file's layout, format version 1;
// checking the key file's owner and permissions and its form; on Windows, finding the key store's
// key, checking who has access to it and unwrapping the bootstrap file's key under it; on Linux,
// reading systemd's credential and checking its form, and reading the Swarm secret and checking
// its owner, mode and form; and unsealing the bootstrap file with AES-256-GCM. It hands back the
// sealed JSON as bytes and knows nothing of what it means: the connection settings are the
// database unit's. It does not own the command line, which names the folder, or the local log,
// which are the program's; making the folder, its permissions, the key file, the key store's key
// and its access list, systemd's credential and the service setting that loads it, the Swarm
// secret and the stack file that grants it, and both files, which are hadv-setup's and the
// installs'; or writing the bootstrap file, which is the vault's.
//
// What the engine does as a whole, this package included, is in docs/behavior.md.
//
// # The bootstrap file, format version 1
//
// Every number is big-endian.
//
//	offset 0     8 bytes   HADVBOOT
//	offset 8     2 bytes   format version: 1
//	offset 10    1 byte    key holder: 1, the key file; 2, the TPM key store; 3, the software
//	                       key store; 4, systemd's credential; 5, the Swarm secret
//	offset 11    2 bytes   sealed-key length: 0 for 1, 4 and 5, SealedKeyBytes for 2 and 3
//	offset 13    n bytes   sealed key: none for 1, 4 and 5; for 2 and 3, the key store key's
//	                       name (KeyNameBytes: KeyNamePrefix and 32 lower-case hex digits), then
//	                       the bootstrap file's key wrapped under it (WrappedKeyBytes)
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
// # The key store's key
//
// Under key holder 2, a machine key in Microsoft Platform Crypto Provider, the TPM's key store;
// under 3, one in Microsoft Software Key Storage Provider. An RSA-2048 key whose name is the sealed
// key's first KeyNameBytes; the rest of the sealed key is the bootstrap file's 32-byte key wrapped
// under it by RSA-OAEP with SHA-256. Its owner and access list are judged as the key file's are
// on Windows. The key store is loaded from System32 alone, and a call into it is not cut short:
// Windows offers no way to.
//
// # systemd's credential
//
// Under key holder 4, on Linux, the file CredentialName in the folder systemd names in the
// environment variable CredentialsVariable when it starts the service: the raw 32-byte key, which
// systemd unsealed from the credential the service's setting loads. Who may read the folder is
// systemd's to decide, so Open checks no owner or permissions there. When systemd cannot unseal
// the credential it does not start the service, and Open is never reached.
//
// # The Swarm secret
//
// Under key holder 5, on Linux, the file SecretName in SecretFolder, where Swarm puts a service's
// secrets: in the key file's form, owned by the engine's own account with no access for its group
// or others, as the key file is on Linux.
//
// # Untrusted input
//
// The bootstrap file is untrusted until its tag verifies: its size is bounded, its first
// HeaderBytes are checked before anything after them is used, and nothing after them but the
// sealed key is used before the tag verifies. The sealed key, under key holder 2 or 3, is used
// before: its name is checked against its form before the key store is asked for it, and is
// never a path; its wrapped bytes go only to the key store's own RSA-OAEP decryption, whose result
// is bounded and checked. The key file, systemd's credential and the Swarm secret are untrusted
// until their form is checked, and each is read with a bound. The folder named in
// CredentialsVariable is taken as given: a folder named by anyone but systemd gives a key that
// does not unseal the bootstrap file, unless it holds the real key. Both files come
// from the bootstrap folder, which only hadv-setup and administrators should write; the key
// file's owner and permissions are checked because a key file someone else can write or replace
// could point the engine at a database of their choosing, and the key store's key is checked
// because anyone with access to it can unwrap the bootstrap file's key. No caller's byte reaches
// this package. Fuzz targets: the header reader and the key file's reader.
//
// The package builds for Linux and Windows only, the two systems whose key file checks it holds,
// so the engine is never built where it would start with the key file unchecked.
//
// # Oracles
//
// The bootstrap file reference, oracle/bootstrap-file (Free Pascal, with its own AES and GCM, its
// self-test running the published vectors), which the tests make every
// bootstrap file with, good and broken; RFC 4648's test vectors for the key file's reader; and the
// real file systems on Linux x86-64, Linux ARM64 and Windows x86-64, whose modes and access lists,
// and on Windows owners, the tests set from outside, and on Linux the system's own answer to
// whether the account `nobody` may read or write the key file; and on Windows, the real key
// stores, driven from outside through PowerShell and .NET's CngKey and RSACng, which make each
// key store key with its access list, wrap the bootstrap file's key and delete the key: the TPM's
// where there is one and the process is elevated, the software key store's on CI; and on Linux,
// systemd itself, sealing a credential and starting a real unit that loads it, and Docker Swarm
// itself, granting a service the secret with its owner and mode.
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
	// KeyHolderTPM is the header's number for a key wrapped by a machine key in Microsoft's TPM
	// key store.
	KeyHolderTPM = 2
	// KeyHolderSoftwareKeyStore is the header's number for a key wrapped by a machine key in
	// Microsoft's software key store.
	KeyHolderSoftwareKeyStore = 3
	// KeyHolderSystemd is the header's number, on Linux, for a key systemd unseals and hands the
	// service at start.
	KeyHolderSystemd = 4
	// KeyHolderSwarm is the header's number, on Linux, for a key held as a Swarm secret.
	KeyHolderSwarm = 5
	// CredentialsVariable is the environment variable in which systemd names the service's
	// credential folder.
	CredentialsVariable = "CREDENTIALS_DIRECTORY"
	// CredentialName is systemd's credential in that folder: the raw 32-byte key.
	CredentialName = "hadv-bootstrap-key"
	// SecretFolder is where Swarm puts a service's secrets.
	SecretFolder = "/run/secrets"
	// SecretName is the Swarm secret in SecretFolder, in the key file's form.
	SecretName = "hadv-bootstrap-key"
	// SealedKeyBytes is the sealed key's length under key holders 2 and 3: the key store key's
	// name, then the wrapped key.
	SealedKeyBytes = KeyNameBytes + WrappedKeyBytes
	// KeyNameBytes is the key store key's name: KeyNamePrefix and 32 lower-case hex digits.
	KeyNameBytes = len(KeyNamePrefix) + 32
	// KeyNamePrefix is how every key store key's name starts.
	KeyNamePrefix = "hadv-"
	// WrappedKeyBytes is the bootstrap file's key wrapped by the RSA-2048 key store key, OAEP with
	// SHA-256.
	WrappedKeyBytes = 256
	// HeaderBytes is the header's fixed start: the magic, the version, the key holder and the
	// sealed-key length.
	HeaderBytes = 13
	// NonceBytes is the nonce after the header.
	NonceBytes = 12
	// TagBytes is the integrity tag at the end.
	TagBytes = 16
	// KeyBytes is the key: 256 bits.
	KeyBytes = 32
	// FileMostBytes bounds the bootstrap file: a larger one is refused, so what is read has a
	// bound.
	FileMostBytes = 65536
	// KeyFileMostBytes bounds the key file and the Swarm secret: 44 characters and a line ending of
	// two; a longer one is refused.
	KeyFileMostBytes = 46
)

// Why Open refused, one error for each kind of refusal; the order of the checks is Open's. None
// holds the key or any part of either file's contents, so the program can write it to the local
// log as it is.
var (
	// ErrFolderMissing means the bootstrap folder is not there.
	ErrFolderMissing = errors.New("bootstrap: the bootstrap folder does not exist")
	// ErrFolderUnreadable means the bootstrap folder is there but will not open.
	ErrFolderUnreadable = errors.New("bootstrap: the bootstrap folder cannot be opened")
	// ErrFileMissing means the bootstrap folder holds no bootstrap file.
	ErrFileMissing = errors.New("bootstrap: the bootstrap file does not exist")
	// ErrFileUnreadable means the bootstrap file is there but will not open or read, is not a
	// regular file, or is a link leading out of the bootstrap folder.
	ErrFileUnreadable = errors.New("bootstrap: the bootstrap file cannot be read")
	// ErrFileTooLarge means the bootstrap file is longer than FileMostBytes.
	ErrFileTooLarge = errors.New("bootstrap: the bootstrap file is too large")
	// ErrHeader means the bootstrap file's header is not format version 1's for a key holder this
	// system has (the key file; on Windows also the TPM and the software key store; on Linux also
	// systemd's credential and the Swarm secret), the file is
	// too short for its header, sealed key, nonce and tag, or the sealed key's name is not in its
	// form.
	ErrHeader = errors.New("bootstrap: the bootstrap file's header is not one this engine reads")
	// ErrKeyFileMissing means the bootstrap folder holds no key file.
	ErrKeyFileMissing = errors.New("bootstrap: the key file does not exist")
	// ErrKeyFileUnreadable means the key file is there but will not open or read, is not a regular
	// file, or is a link leading out of the bootstrap folder.
	ErrKeyFileUnreadable = errors.New("bootstrap: the key file cannot be read")
	// ErrKeyFilePermissions means Open is unable to confirm who has access to the key file: its
	// owner or permissions could not be read, or its access list holds an entry of a kind Open does
	// not judge.
	ErrKeyFilePermissions = errors.New("bootstrap: who has access to the key file cannot be confirmed")
	// ErrKeyFileReachable means someone but the engine's own account, SYSTEM or Administrators
	// owns the key file or may reach it.
	ErrKeyFileReachable = errors.New("bootstrap: someone but the engine's account, SYSTEM or Administrators can reach the key file")
	// ErrKeyFileForm means the key file is not in its form, or holds a key of 32 zero bytes.
	ErrKeyFileForm = errors.New("bootstrap: the key file is not in its form")
	// ErrKeyStore means, under key holder 2 or 3, that the key store the header names will not
	// load or open, the key store key is not in it, or the key store refuses to open the key or to
	// unwrap with it for any reason but a result longer than the buffer. Windows' answer is wrapped
	// beneath it.
	ErrKeyStore = errors.New("bootstrap: the key store key cannot be used")
	// ErrKeyStorePermissions means Open is unable to confirm who has access to the key store key:
	// its owner or access list could not be read, or its access list holds an entry of a kind Open
	// does not judge.
	ErrKeyStorePermissions = errors.New("bootstrap: who has access to the key store key cannot be confirmed")
	// ErrKeyStoreReachable means someone but the engine's own account, SYSTEM or Administrators
	// owns the key store key or has access to it, or it has no access list.
	ErrKeyStoreReachable = errors.New("bootstrap: someone but the engine's account, SYSTEM or Administrators can use the key store key")
	// ErrUnwrap means the unwrap under the key store key gave other than KeyBytes bytes, a result
	// longer than the buffer included, or KeyBytes zero bytes.
	ErrUnwrap = errors.New("bootstrap: the key store key does not unwrap a 32-byte key")
	// ErrCredentialUnset means, under key holder 4, that CredentialsVariable names no folder: the
	// engine was not started by systemd with the credential.
	ErrCredentialUnset = errors.New("bootstrap: systemd named no credential folder")
	// ErrCredentialMissing means, under key holder 4, that the folder CredentialsVariable names, or
	// CredentialName in it, does not exist.
	ErrCredentialMissing = errors.New("bootstrap: systemd's credential does not exist")
	// ErrCredentialUnreadable means, under key holder 4, that the folder or the credential is there
	// but will not open or read, or the credential is not a regular file.
	ErrCredentialUnreadable = errors.New("bootstrap: systemd's credential cannot be read")
	// ErrCredentialForm means, under key holder 4, that the credential is not exactly KeyBytes
	// bytes, or is KeyBytes zero bytes.
	ErrCredentialForm = errors.New("bootstrap: systemd's credential is not a 32-byte key")
	// ErrSecretMissing means, under key holder 5, that SecretFolder holds no SecretName.
	ErrSecretMissing = errors.New("bootstrap: the Swarm secret does not exist")
	// ErrSecretUnreadable means, under key holder 5, that the secret is there but will not open or
	// read, its owner or mode cannot be read, it is not a regular file, or it is a link leading out
	// of SecretFolder.
	ErrSecretUnreadable = errors.New("bootstrap: the Swarm secret cannot be read")
	// ErrSecretReachable means, under key holder 5, that the secret's mode gives its group or
	// others any access, or its owner is not the engine's account.
	ErrSecretReachable = errors.New("bootstrap: someone but the engine's account can reach the Swarm secret")
	// ErrSecretForm means, under key holder 5, that the secret is not in the key file's form, or
	// holds a key of 32 zero bytes.
	ErrSecretForm = errors.New("bootstrap: the Swarm secret is not in the key file's form")
	// ErrUnseal means the bootstrap file does not unseal under the key its key holder gives: a
	// wrong key or a changed file, which cannot be told apart.
	ErrUnseal = errors.New("bootstrap: the bootstrap file does not unseal under its key")
)

// Open opens the bootstrap folder, checks the bootstrap file and its header, then, by the key
// holder the header names, the key file, the key store key, systemd's credential or the Swarm
// secret, takes the key, and unseals the bootstrap file. It returns the sealed JSON, which the
// caller wipes once read.
// The checks run in the order of the lines below, and the first that applies is the result.
//
//   - Open shall check in the order of these lines and return the first refusal that applies.
//   - If the bootstrap folder does not exist, then Open shall return ErrFolderMissing.
//   - If the bootstrap folder exists but will not open, then Open shall return
//     ErrFolderUnreadable.
//   - If the bootstrap folder holds no bootstrap file, then Open shall return ErrFileMissing.
//   - If the bootstrap file will not open or read, is not a regular file, or is a link leading out
//     of the bootstrap folder, then Open shall return ErrFileUnreadable.
//   - Open shall open each file without waiting on it, so a file that is not a regular file, such
//     as a named pipe, is refused and never waited on.
//   - If the bootstrap file is longer than FileMostBytes, then Open shall return ErrFileTooLarge,
//     having read at most FileMostBytes and one byte more of it.
//   - If the bootstrap file is shorter than HeaderBytes, NonceBytes and TagBytes together, or its
//     first HeaderBytes are not Magic, FormatVersion, then KeyHolderKeyFile with a sealed-key
//     length of 0, on Windows KeyHolderTPM or KeyHolderSoftwareKeyStore with a sealed-key length
//     of SealedKeyBytes, or on Linux KeyHolderSystemd or KeyHolderSwarm with a sealed-key length
//     of 0, or, under key holder 2 or 3, the file is too short for the sealed key, nonce and tag,
//     or the sealed key's first KeyNameBytes are not KeyNamePrefix and 32 lower-case hex digits,
//     then Open shall return ErrHeader before it opens the key file, asks a key store, or reads a
//     credential or secret.
//   - Open shall take the key under KeyHolderKeyFile by the lines on the key file, under
//     KeyHolderTPM or KeyHolderSoftwareKeyStore by the lines on the key store key, under
//     KeyHolderSystemd by the lines on systemd's credential, and under KeyHolderSwarm by the lines
//     on the Swarm secret, never by another holder's; it shall open the key file only under key
//     holder 1.
//   - If the bootstrap folder holds no key file, then Open shall return ErrKeyFileMissing.
//   - If the key file will not open, is not a regular file, or is a link leading out of the
//     bootstrap folder, then Open shall return ErrKeyFileUnreadable.
//   - If reading the key file's owner or permissions fails, or, on Windows, an entry of its access
//     list that allows access is of a kind other than a plain allow entry, such as a conditional
//     entry, then Open shall return ErrKeyFilePermissions.
//   - If, on Linux, the key file's mode gives its group or others any access, then Open shall
//     return ErrKeyFileReachable.
//   - If, on Linux, the key file's owner is not the engine's effective user ID, then Open shall
//     return ErrKeyFileReachable. [read]
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
//   - Under KeyHolderTPM, Open shall look for the key store key the sealed key names only among
//     the machine keys of Microsoft Platform Crypto Provider, and under KeyHolderSoftwareKeyStore
//     only among those of Microsoft Software Key Storage Provider.
//   - Open shall load the key store from the System32 folder alone. [read]
//   - Open shall make every key store call silent, so a key that would ask for a prompt is refused
//     at once rather than waited on. [read]
//   - If the key store will not load or open, the key store key is not there, or the key store
//     refuses to open it, then Open shall return ErrKeyStore, with the key store's answer beneath
//     it.
//   - If reading the key store key's owner or access list fails, or an entry of its access list
//     that allows access is of a kind other than a plain allow entry, such as a conditional entry,
//     then Open shall return ErrKeyStorePermissions.
//   - If the key store key's owner, or any entry of its access list that allows access, whether
//     the key's own or inherited, names anyone but SYSTEM (S-1-5-18), Administrators
//     (S-1-5-32-544) or the user of the engine's own token, or the key has no access list, then
//     Open shall return ErrKeyStoreReachable. An entry that denies access is not counted.
//   - Open shall read the key store key's owner and access list from the key it opened, never by
//     its name again. [read]
//   - Open shall take the bootstrap file's key by unwrapping the sealed key's last WrappedKeyBytes
//     under the key store key by RSA-OAEP with SHA-256, reading at most KeyBytes and one byte more.
//   - If the unwrap gives other than KeyBytes bytes, a result longer than KeyBytes and one byte
//     included, or KeyBytes zero bytes, then Open shall return ErrUnwrap.
//   - If the key store refuses the unwrap for any other reason, then Open shall return ErrKeyStore,
//     with the key store's answer beneath it.
//   - Under KeyHolderSystemd, Open shall take the key only from CredentialName in the folder named
//     in CredentialsVariable.
//   - If CredentialsVariable is unset or empty, then Open shall return ErrCredentialUnset.
//   - If the folder CredentialsVariable names, or CredentialName in it, does not exist, then Open
//     shall return ErrCredentialMissing.
//   - If the folder or the credential will not open or read, or the credential is not a regular
//     file, then Open shall return ErrCredentialUnreadable.
//   - If the credential is not exactly KeyBytes bytes, or is KeyBytes zero bytes, then Open shall
//     return ErrCredentialForm, having read at most KeyBytes and one byte more of it.
//   - Open shall judge no owner or permissions of the credential or its folder.
//   - Under KeyHolderSwarm, Open shall take the key only from SecretName in SecretFolder.
//   - If SecretFolder, or SecretName in it, does not exist, then Open shall return
//     ErrSecretMissing.
//   - If the secret will not open, is not a regular file, or is a link leading out of
//     SecretFolder, or reading its owner or mode fails, then Open shall return
//     ErrSecretUnreadable.
//   - If the secret's mode gives its group or others any access, then Open shall return
//     ErrSecretReachable.
//   - If the secret's owner is not the engine's effective user ID, then Open shall return
//     ErrSecretReachable. [read]
//   - Open shall read the secret's owner and mode from the secret it opened, never by its name
//     again. [read]
//   - If reading the secret fails, then Open shall return ErrSecretUnreadable.
//   - If the secret is longer than KeyFileMostBytes, is not in the key file's form, or holds a key
//     of 32 zero bytes, then Open shall return ErrSecretForm, having read at most KeyFileMostBytes
//     and one byte more of it.
//   - If the bootstrap file's tag does not verify under the key, then Open shall return ErrUnseal
//     and no bytes.
//   - When it returns, Open shall have closed the bootstrap folder and the files it opened, and
//     freed every key store handle it opened.
//   - Open shall wipe each buffer it allocates for the key, the key file's text, the unwrapped key,
//     the credential, the secret's text and the bootstrap file's bytes before it returns, keeping
//     only the JSON it returns; the copies Go's AES and GCM keep inside the cipher, and the key
//     store's own, are out of its reach. [read]
func Open(folder string) ([]byte, error) {
	return open(folder)
}
