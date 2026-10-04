# Behavior

This page lists what each outcome of the board must do, one section per outcome, in lines that a
test or a run on the real system can check. The lines use the EARS form and only "shall" and
"shall not". The developer approves every line, and the lines are locked like the contracts: a
change goes back through design before it reaches this page.

Every term in these lines has the one meaning the estate's
[glossary](https://github.com/HeliosEstate/.github/blob/main/GLOSSARY.md) gives it.

## Storage

Storage is where the board's files live and how its servers reach them: folders on a server's
disk, SMB shares, S3 buckets, ISO images and optical drives. The database is not storage. A board
is one server or several, in any mix of supported operating systems, and the lines assume nothing
about where the servers sit or the network between them. A sysop runs the board, not a systems
administrator, so every default starts at the secure end and loosening one is the sysop's choice.

### The registry and its storages

- The storage subsystem shall support five kinds of registry entry: local, SMB, S3, ISO and optical.
- The storage subsystem shall allow one server to own more than one local registry entry.
- If a registry entry other than an optical registry entry has a root path, then the storage
  subsystem shall refuse the registry entry.
- If a registry entry's path, after links are resolved, lies inside a location on the
  refused-locations list, then the storage subsystem shall refuse the registry entry.
- If an SMB registry entry's UNC path names a drive-letter administrative share or `ADMIN$`, then the
  storage subsystem shall refuse the registry entry.
- The storage subsystem shall accept an SMB share whose name ends in `$` and is neither a drive-letter
  administrative share nor `ADMIN$`.
- If a registry entry's path lies inside another registry entry's path, or contains it, then the
  storage subsystem shall refuse the registry entry.
- When the storage subsystem uses an optical registry entry, the storage subsystem shall confirm with
  the operating system that the path is an optical drive, and that the disc's volume label and serial
  match the registry entry.
- When the storage subsystem uses an ISO registry entry, the storage subsystem shall confirm that the
  image's size and the volume label inside it match the registry entry.
- If either confirmation above fails, then the storage subsystem shall report the registry entry as
  unavailable to every caller that uses it.
- If an ISO image is malformed or states a size above the storage subsystem's limits, then the
  storage subsystem shall report the ISO registry entry as unavailable, and continue serving every
  other registry entry.
- The storage subsystem shall use one set of credentials per SMB or S3 registry entry, the same on
  every server.
- The storage subsystem shall obtain an SMB or S3 registry entry's credentials from the shared vault
  when it connects, and shall not write them anywhere else.
- When a sysop changes an SMB or S3 registry entry's credentials, every server shall use the new
  credentials from its next connection to that storage.
- When the storage subsystem creates a local, SMB or S3 registry entry, the storage subsystem shall
  write a marker file holding the registry entry's identity at the registry entry's path.
- If a sysop changes a local, SMB or S3 registry entry's path and the marker file at the new path is
  missing or holds a different identity, then the storage subsystem shall refuse the change.
- If a sysop removes a registry entry that an area uses, then the storage subsystem shall refuse the
  removal.
- The storage subsystem shall reach an SMB registry entry through its own SMB client by UNC path, and
  shall not use a mapped drive or an operating-system mount.
- The storage subsystem shall keep, for each SMB registry entry, a signing setting and an encryption
  setting, each set to Required, Negotiated or No.
- When a sysop creates an SMB registry entry, the storage subsystem shall set its signing setting and
  its encryption setting to Required.
- While an SMB registry entry's signing setting is Required, if the SMB server does not sign the
  session, then the storage subsystem shall refuse the connection.
- While an SMB registry entry's encryption setting is Required, if the SMB server does not encrypt the
  session, then the storage subsystem shall refuse the connection.
- While a setting is Negotiated, the storage subsystem shall use signing or encryption when the SMB
  server supports it, and shall connect without it when the server does not.
- While a setting is No, the storage subsystem shall not request signing or encryption, and shall use
  it when the SMB server requires it.
- When a sysop sets a signing or encryption setting to Negotiated or No, the configuration utilities
  shall warn the sysop what the setting gives up before saving it.
- If an SMB server offers only a guest or anonymous login, then the storage subsystem shall refuse the
  connection.
- If an SMB server sends a reply that is malformed or states a size above the storage subsystem's
  limits, then the storage subsystem shall close the connection, report the registry entry as
  unreachable, and continue serving every other registry entry.
- The storage subsystem shall not support NFS.
- When first setup completes, `hadv-setup` shall have created a local registry entry at
  `C:\HADV\DOWNLOADS` on Windows or `/var/lib/hadv/downloads` on Linux.

### Kinds, areas, names, writes, uploads, imports

- The storage subsystem shall accept kind registrations only from the engine's own subsystems, and
  shall offer custom scripts no way to register a kind.
- If a subsystem removes a kind while files of that kind exist on any registry entry, then the
  storage subsystem shall refuse the removal.
- The storage subsystem shall store an area's files on a local, SMB or S3 registry entry under
  `<registry entry path>/<KIND>/<NAME>`.
- If an area's Name contains a space or a character on the refused-characters list, then the storage
  subsystem shall refuse the Name.
- If a file name to be written contains a path separator, a `..` component, or a character on the
  refused-characters list, then the storage subsystem shall refuse the write.
- The storage subsystem shall store every Name in uppercase.
- If a Name is already used by another area of the same kind, then the storage subsystem shall refuse
  the Name.
- When an area uses an optical or ISO registry entry, the storage subsystem shall serve the area's
  files from the path on the disc the sysop chose, and shall not create a folder for the area.
- The storage subsystem shall treat two file names in one area that differ only in letter case as the
  same file, on every kind of registry entry.
- The storage subsystem shall not make a file visible until the file is completely written.
- If two writes of the same file name in one area overlap, then the storage subsystem shall keep one
  complete file and shall not mix their contents.
- The storage subsystem shall not write, move or delete any file on an optical or ISO registry entry.
- When a file on an optical or ISO registry entry is imported, the storage subsystem shall record the
  file where it sits and shall not copy it.
- The storage subsystem shall keep a file being received in the receiving server's work folder until
  the owning subsystem releases it.
- When the owning subsystem releases a file, the storage subsystem shall write it to its area's
  registry entry, hidden.
- When the owning subsystem approves a hidden file, the storage subsystem shall make it visible
  without copying it again.
- When the owning subsystem rejects a hidden file, the storage subsystem shall delete it.
- The storage subsystem shall not decide whether a user is allowed to read or write a file.
- The import utility shall send files through the Admin API, and the receiving server shall write them
  through the storage subsystem.
- The storage subsystem shall not add to its records a file placed on a storage by anything other
  than the storage subsystem.

### Missing files, moves, hashes, space

- If a file in the storage subsystem's records is missing from its storage when opened, then the
  storage subsystem shall report the file as missing to the owning subsystem.
- When the storage subsystem opens a file it reported missing and the file is present again, the
  storage subsystem shall report the file as available.
- When a sysop assigns an area to a different registry entry, the storage subsystem shall move each of
  the area's files by copying it, confirming the copy's hash, switching the file's record to the new
  location, and then deleting the old copy.
- While an area's files are moving, the storage subsystem shall serve each file from its old location
  until the file's record is switched.
- If a move is interrupted, then the storage subsystem shall resume it without losing or duplicating a
  file.
- When a sysop changes the Name of an area on a local, SMB or S3 registry entry, the storage subsystem
  shall move the area's files to the new Name's folder in the same way.
- When the storage subsystem writes a file, the storage subsystem shall record the file's SHA-256
  hash.
- When the storage subsystem moves a file, or serves a file from its first byte to its last, the
  storage subsystem shall compare the file's hash with the recorded hash.
- If the hashes differ, then the storage subsystem shall mark the file damaged, report it as damaged to
  the owning subsystem, and raise an event for the sysop.
- Where a sysop has scheduled a scrub job for a registry entry, the storage subsystem shall compare the
  hash of every file on that registry entry at the scheduled time.
- When a sysop creates an S3 registry entry, the storage subsystem shall leave its scrub job off.
- The storage subsystem shall keep, for each registry entry, an optional limit and an optional
  low-space warning level, both set by the sysop.
- The storage subsystem shall count a registry entry's space used from the sizes of the files in its
  records.
- When asked to write a file of known size, the storage subsystem shall confirm the registry entry has
  room before writing any of it. Room is the limit minus the space used, and on local and SMB registry
  entries no more than the storage's free space.
- If a registry entry lacks room for a file of known size, then the storage subsystem shall refuse the
  write before writing any of it.
- When a registry entry's room falls below its low-space warning level, the storage subsystem shall
  raise one event for the sysop, and no further event until its room has risen above that level again.
- If a storage refuses a write because a quota is reached, then the storage subsystem shall report the
  registry entry as full.

### Unreachable entries, downloads, transfers, work folder

- If a registry entry is unreachable, then the storage subsystem shall report it as unreachable to
  every caller that uses it.
- When a registry entry becomes unreachable, the storage subsystem shall raise one event for the
  sysop, and no further event for that registry entry until it has been reachable again.
- When an unreachable registry entry becomes reachable, the storage subsystem shall resume serving its
  files without any action by the sysop.
- The storage subsystem shall let a reader read a file from any position, on every kind of registry
  entry.
- The storage subsystem shall stream a file to its reader without first copying it, except from an
  optical registry entry.
- When a file on an optical registry entry is opened, the storage subsystem shall copy it to the
  server's work folder, compare its hash, and serve it from the copy.
- The storage subsystem shall read from each optical drive one file at a time.
- The storage subsystem shall keep copies from optical registry entries for the time, and within the
  space, that the sysop sets.
- When a reader on one server opens a file on another server's local registry entry, the storage
  subsystem shall fetch it from that server over the ClusterAPI.
- The web server, X/Y/Zmodem and the FTP server shall not open files through the storage subsystem,
  and shall receive opened files only from the owning subsystem.
- When first setup completes, `hadv-setup` shall have set the server's work folder to
  `C:\HADV\WORK` on Windows or `/var/lib/hadv/work` on Linux.
- The configuration utilities shall let the sysop change each server's work folder.
- If a work folder lies inside a registry entry's path, or a registry entry's path lies inside a work
  folder, then the storage subsystem shall refuse it.
- When a server starts, the storage subsystem shall delete everything left in that server's work
  folder.

### Boundaries

- Each server shall serve the ClusterAPI on its own port, 8443 by default, and the Admin API on its
  own port, 9443 by default.
- The configuration utilities shall let the sysop change both ports.
- If a caller to the ClusterAPI port presents no paired server's certificate, then the server shall
  refuse the connection during the TLS handshake.
- If a caller to the Admin API presents anything other than an admin sign-in, a paired server's
  certificate included, then the Admin API shall refuse the request.
- The storage subsystem shall offer other servers, over the ClusterAPI, four operations on its local
  registry entries: read a range of a file, write a file, list a folder, and read a file's recorded
  hash.
- The storage subsystem shall offer, through the Admin API and only to a sysop, the creation, change
  and removal of registry entries.
- The storage subsystem shall offer, through the Admin API and only to a sysop, a listing of the
  folders on a registry entry.
- The storage subsystem shall offer, through the Admin API and only to a sysop, a listing of a
  server's drives and folders that leaves out every location the path rules refuse.
- The storage subsystem shall raise its events for the sysop through the event subsystem.
- When a message is deleted, the message system shall have the storage subsystem delete that message's
  attachments.
- The network-mail subsystem shall place files arriving by network mail, TIC files and file
  attachments, into a file area through the storage subsystem in the same way as an import.

## Shared secrets

Shared secrets are the passwords, keys and other secret values the board presents to other
systems, along with those a protocol needs in plain form to check: SMB and S3 credentials, network
node passwords, mail account passwords and a DKIM private key, among others. Every server needs
them. The shared secrets subsystem keeps them encrypted in the database, where every server can
reach them, and hands each one only to the part of the board that owns it. Passwords that others
use to sign in to the board are not kept here; the board keeps only one-way hashes of those.

A board comes back up on its own after a reboot, so no passphrase guards the key that opens the
secrets. Each server keeps that key in its own bootstrap file, sealed under a bootstrap key that the
operating system's credential store holds, and never in the database. If no server holds the key any more, the only way back
is the 24-word recovery code the sysop wrote down by hand at first setup. Without it, every secret
has to be entered again. A sysop runs the board, not a systems administrator, so every default
starts at the secure end and loosening one is the sysop's choice.

### Names, the vault key and values

- When a value is stored from any server, the shared secrets subsystem shall return it to its owner
  on every server.
- The shared secrets subsystem shall return a value to its owner byte for byte as it was stored.
- The shared secrets subsystem shall keep the vault key in each server's bootstrap file, sealed by the
  bootstrap key subsystem.
- The shared secrets subsystem shall not write the vault key to the database.
- The shared secrets subsystem shall not give the vault key to any program other than `hadv-service`.
- When a server starts, the shared secrets subsystem shall open the vault key from the bootstrap file
  without asking for a passphrase.
- The shared secrets subsystem shall encrypt and decrypt every value inside `hadv-service`.
- The shared secrets subsystem shall not send the vault key, a working key or a decrypted value to the
  database.
- The shared secrets subsystem shall encrypt each value with AES-256-GCM under its own working key.
- The shared secrets subsystem shall derive each write's working key with HKDF-SHA256 from the vault
  key, the owner, the identity and a new random salt.
- The shared secrets subsystem shall store each value's salt beside the value.
- The shared secrets subsystem shall seal each value to its owner and identity as authenticated data.
- If a value is moved in the database to another secret, then the shared secrets subsystem shall
  treat it as a value that fails to decrypt.
- The shared secrets subsystem shall record on each value the vault-key version that encrypted it.
- The shared secrets subsystem shall record on each value its format version.
- The shared secrets subsystem shall not write a format version that the previous engine release
  does not read.
- If a value records a format version this engine release does not read, then the shared secrets
  subsystem shall treat it as a value that fails to decrypt.
- If a store carries a value larger than 64 KiB, then the shared secrets subsystem shall refuse the
  store.
- If a store carries a value larger than 64 KiB, then the shared secrets subsystem shall log the
  refusal.

### Changing the vault key

- The shared secrets subsystem shall start a vault-key change only when the event subsystem tells it
  to, on the server the event subsystem names.
- When a sysop asks for a vault-key change through the Admin API, the shared secrets subsystem shall
  ask the event subsystem to start one.
- The shared secrets subsystem shall schedule a vault-key change once a year by default.
- If a sysop sets the vault-key schedule shorter than 45 days, then the shared secrets subsystem shall
  refuse the setting.
- If a sysop sets the vault-key schedule longer than two years, then the shared secrets subsystem
  shall refuse the setting.
- While the vault-key schedule is switched off, the shared secrets subsystem shall not schedule a
  vault-key change.
- When a vault-key change finishes, the shared secrets subsystem shall restart the schedule's clock.
- If a vault-key change is asked for while another is unfinished, then the shared secrets subsystem
  shall refuse the second change.
- If a vault-key change is asked for while another is unfinished, then the shared secrets subsystem
  shall resume the unfinished change.
- When a vault-key change starts, the shared secrets subsystem shall write a copy of the new vault key
  for every registered server and for the recovery key before it re-encrypts any value.
- When every copy of a new vault key is written, the shared secrets subsystem shall send a NOTIFY that
  a new vault key is ready.
- When the NOTIFY for a new vault key is sent, the shared secrets subsystem shall re-encrypt every
  value under the new vault key.
- While a vault-key change is unfinished, the shared secrets subsystem shall decrypt each value under
  either the old or the new vault key, as the value records.
- If a vault-key change stops before it finishes, then the shared secrets subsystem shall resume it
  from the values still under the old vault-key version.
- When no value records the old vault-key version, the shared secrets subsystem shall delete every
  copy of the old vault key from the database.
- When a vault-key change has finished, the shared secrets subsystem on each server shall delete the
  old vault key from that server's bootstrap file.
- The shared secrets subsystem shall encrypt every store under the newest vault key.
- If a value records a vault-key version newer than the server holds, then the shared secrets
  subsystem shall collect that version's copy before it decrypts the value.

### Delivering a new vault key

- The shared secrets subsystem shall keep each server's two private keys only in that server's
  bootstrap file.
- The shared secrets subsystem shall use a server's receiving key pair only to open copies of the
  vault key.
- The shared secrets subsystem shall use a server's signing key pair only to sign copies of the vault
  key.
- The shared secrets subsystem shall encrypt each copy to the receiving server's public key with HPKE
  (RFC 9180) in base mode, using `MLKEM768-X25519`.
- The shared secrets subsystem shall sign each copy with Ed25519 over the copy, the server it is for
  and its vault-key version.
- If a copy's signer is not a registered server, then the shared secrets subsystem shall refuse the
  copy.
- If a copy's signature does not verify for this server and the copy's vault-key version, then the
  shared secrets subsystem shall refuse the copy.
- If a copy's vault-key version is not newer than the vault key the server holds, then the shared
  secrets subsystem shall refuse the copy.
- If a copy fails to decrypt, then the shared secrets subsystem shall refuse the copy.
- If a copy records a format version this engine release does not read, then the shared secrets
  subsystem shall refuse the copy.
- When the shared secrets subsystem refuses a copy, it shall keep its current vault key.
- When the shared secrets subsystem refuses a copy, it shall alert every sysop.
- The shared secrets subsystem shall send no key and no part of a copy in a NOTIFY.
- When a server receives a NOTIFY that a new vault key is ready, the shared secrets subsystem shall
  collect that server's copy.
- If a NOTIFY arrives and no newer copy exists for the server, then the shared secrets subsystem shall
  keep its current vault key.
- When a server starts, the shared secrets subsystem shall collect any newer copy of the vault key for
  that server before the engine serves anything.
- If a newer vault-key version exists and no copy of it is there for the server, then the shared
  secrets subsystem shall treat it as a refused copy.
- If a server starts without the newest vault key, then the shared secrets subsystem shall stop the
  engine from starting.
- The shared secrets subsystem shall use only Go's standard library for its cryptography.

### The recovery code

- `hadv-setup` shall derive the recovery key pair from the 256-bit seed that the recovery code
  encodes.
- `hadv-setup` shall encode the recovery code as 24 words with the published BIP-39 English word list
  and checksum, unchanged.
- `hadv-setup` shall not use BIP-39's seed process to derive the recovery key pair.
- `hadv-setup` shall show the recovery code as 24 numbered words in six rows of four.
- `hadv-setup` shall show the recovery code in English words whatever the interface's language.
- `hadv-setup` shall show the recovery code only when it is made, at first setup or on a replacement.
- `hadv-setup` shall offer no clipboard, save or print option for the recovery code.
- `hadv-setup` shall show with the recovery code that it is to be written by hand, kept where no one
  else finds it, and never typed into anything else.
- `hadv-setup` shall show with the recovery code that without it there is no recovery and every
  secret is entered again.
- `hadv-setup` shall not store, log or send the recovery code.
- `hadv-setup` shall keep nothing of the recovery key pair but its public half, registered in the
  database.
- When the recovery code is shown, `hadv-setup` shall require it typed back before it continues.
- `hadv-setup` shall offer no way to skip or postpone typing the recovery code back.
- `hadv-setup` shall complete a typed word once its first four letters are entered.
- `hadv-setup` shall accept a typed recovery code in Latin letters whatever the interface's script.
- If a typed word is not on the word list, then `hadv-setup` shall refuse the code.
- If a typed recovery code fails its checksum, then `hadv-setup` shall refuse the code.
- If a typed-back recovery code does not match the code shown, then `hadv-setup` shall not continue.

### `hadv-setup` and first setup

- `hadv-setup` shall offer no way to be run from another machine.
- If `hadv-setup` runs without the OS rights that open the bootstrap file, then `hadv-setup` shall
  refuse to run.
- `hadv-setup` shall hold the vault key only until it is sealed into the bootstrap file, before the
  engine starts.
- When first setup runs, `hadv-setup` shall make the vault key and the server's two key pairs.
- When first setup runs, `hadv-setup` shall seal the vault key and the server's two private keys in
  the bootstrap file.
- When first setup runs, `hadv-setup` shall register the server's two public keys in the database.
- When first setup runs, `hadv-setup` shall make the recovery key pair and register its public half.
- When first setup runs, `hadv-setup` shall write a signed copy of the vault key for the recovery key.
- While first setup is unfinished, the shared secrets subsystem shall refuse every store.

### Restore and replacing the recovery code

- When restore is chosen, `hadv-setup` shall ask for the recovery code.
- `hadv-setup` shall not ask for a sign-in to restore.
- When a recovery code is typed for a restore, `hadv-setup` shall rebuild the recovery key pair from
  it.
- When the recovery key pair is rebuilt, `hadv-setup` shall open the recovery copy of the newest vault
  key.
- If the recovery copy does not open with the rebuilt key pair, then `hadv-setup` shall refuse the
  restore.
- If the recovery copy's signer is not a registered server, then `hadv-setup` shall refuse the
  restore.
- If the recovery copy's signature does not verify for the recovery key and its vault-key version,
  then `hadv-setup` shall refuse the restore.
- `hadv-setup` shall show each registered server's health status on the restore screen.
- When the sysop picks the server a restore replaces, `hadv-setup` shall show a warning and require
  confirmation before it continues.
- If any registered server shows as healthy, then `hadv-setup` shall warn that the replacement server
  joins through a healthy server, with no restore.
- When a restore opens the vault key, `hadv-setup` shall make the server's two key pairs.
- When a restore opens the vault key, `hadv-setup` shall seal the vault key and the server's two
  private keys in a new bootstrap file.
- When a restore opens the vault key, `hadv-setup` shall register the server's two public keys in the
  database.
- When a restore registers the new server, `hadv-setup` shall remove the registration of the server
  the sysop picks as the one it replaces.
- When a restore finishes, `hadv-setup` shall ask the event subsystem to start a vault-key change.
- When a restore finishes, `hadv-setup` shall alert every sysop.
- If a replacement of the recovery code is asked for without the #1 Sysop's sign-in with a second
  factor, then `hadv-setup` shall refuse the replacement.
- `hadv-setup` shall not ask for the old recovery code to replace it.
- When the #1 Sysop's sign-in is accepted for a replacement, `hadv-setup` shall make a new recovery key
  pair.
- When the new recovery code is typed back correctly, `hadv-setup` shall register its public half in
  place of the old one.
- When the new public half is registered, `hadv-setup` shall ask the event subsystem to start a
  vault-key change.
- `hadv-setup` shall not open the vault key for a replacement.
- When a replacement finishes, `hadv-setup` shall alert every sysop.

### Access and failures

- The shared secrets subsystem shall offer only five operations on secrets: store, read, delete,
  status and deliver.
- The shared secrets subsystem shall accept a store only through the Admin API.
- When a store arrives, the shared secrets subsystem shall write the value under the owner and
  identity the store names, replacing any value already there.
- The shared secrets subsystem shall not return a value through the Admin API.
- When the owner reads a secret, the shared secrets subsystem shall return its value.
- If no value is stored for a secret its owner reads, then the shared secrets subsystem shall answer
  "not set".
- If a reader is not the secret's owner, then the shared secrets subsystem shall answer "refused",
  whether or not a value is stored.
- The shared secrets subsystem shall decrypt each value only with the vault key of the version the
  value records.
- If a value fails to decrypt, then the shared secrets subsystem shall answer "unavailable" to its
  owner.
- If a value fails to decrypt, then the shared secrets subsystem shall log it as possible tampering,
  with the secret's owner and identity.
- If a value fails to decrypt, then the shared secrets subsystem shall alert every sysop.
- When a sysop deletes a secret through the Admin API, the shared secrets subsystem shall remove its
  value.
- When an owner deletes one of its own secrets, the shared secrets subsystem shall remove its value.
- When asked for a secret's status, the shared secrets subsystem shall answer only whether a value is
  set and when it last changed.
- When an authenticated helper program asks for its secrets, the shared secrets subsystem shall
  deliver only the secrets that helper program owns.
- If a program that is not an authenticated helper program asks for secrets, then the shared secrets
  subsystem shall deliver nothing.
- The shared secrets subsystem shall not pass a secret to a helper program on a command line or in an
  environment variable.

### Logs and memory

- When a secret is stored or replaced, the shared secrets subsystem shall log its owner and identity,
  who did it, from which server and when.
- When a secret is deleted, the shared secrets subsystem shall log its owner and identity, who did it,
  from which server and when.
- The shared secrets subsystem shall log the start and the finish of every vault-key change.
- When the shared secrets subsystem answers "refused", it shall log the reader and the secret's owner
  and identity.
- When the shared secrets subsystem delivers nothing to a program that is not an authenticated helper
  program, it shall log the attempt.
- When the shared secrets subsystem refuses a copy, it shall log the refusal.
- When the vault-key schedule is switched off, the shared secrets subsystem shall log who did it and
  when.
- `hadv-setup` shall log every restore, whether it finishes or is refused.
- `hadv-setup` shall log every replacement of the recovery code.
- The shared secrets subsystem shall not log a value, any part of a value, or its length.
- The shared secrets subsystem shall not log the vault key, a working key or a server's private key.
- The shared secrets subsystem shall hold decrypted values and keys as byte slices, never as strings.
- The shared secrets subsystem shall overwrite a decrypted value's bytes as soon as its use ends.
- `hadv-service` shall not write a crash dump of its own.


## Bootstrap key

Each server keeps a file of its own, the bootstrap file, with what it needs before it can reach the
database: its ID, the database connection, the server's database account, the vault key and the
server's two private keys. The bootstrap key subsystem seals that file under a random key, the bootstrap key,
and the operating system's credential store holds that key. So the file opens only where its key is
held, and only for `hadv-setup` and `hadv-service`. No other program of the board reads it. Where no
credential store fits, the sysop can choose a key file instead, and the board warns about that
choice at every start. A sysop runs the board, not a systems administrator, so every default starts
at the secure end and loosening one is the sysop's choice.


### Who unlocks and writes

- The bootstrap key subsystem shall unlock the bootstrap file for no program other than `hadv-setup`
  and `hadv-service`.
- The bootstrap key subsystem shall keep in the bootstrap file the server's ID, the database
  connection, the server's database account, the vault key and the server's two private keys, and
  no other setting.
- While the OS credential store holds the bootstrap key on Windows or on Linux on a bare OS, when
  `hadv-setup` builds a bootstrap file, the bootstrap key subsystem shall seal it under a new
  bootstrap key.
- The bootstrap key subsystem shall let `hadv-service` change only the vault-key fields of the
  bootstrap file.
- If `hadv-service` asks to change any other field of the bootstrap file, then the bootstrap key
  subsystem shall refuse the change.
- If `hadv-service` asks to change any other field of the bootstrap file, then the bootstrap key
  subsystem shall log the attempt, naming the field.

### The OS credential store by platform

- Where the server runs Windows, the bootstrap key subsystem shall have the OS credential store seal
  the bootstrap key under a machine key pair made for that server.
- Where the server runs Windows, the bootstrap key subsystem shall make the machine key pair
  non-exportable.
- Where the server runs Windows, the bootstrap key subsystem shall make the machine key pair usable
  only by the service account, SYSTEM and Administrators.
- Where the server runs Windows and has a TPM, the bootstrap key subsystem shall keep the machine key
  pair in the TPM.
- Where the server runs Windows without a TPM, the bootstrap key subsystem shall keep the machine key
  pair in the OS software key store.
- Where the server runs Linux on a bare OS, the bootstrap key subsystem shall have systemd credentials
  seal the bootstrap key.
- Where the server runs Linux on a bare OS and has a TPM, the bootstrap key subsystem shall have the
  bootstrap key sealed under both the TPM and the host key.
- Where the server runs Linux on a bare OS without a TPM, the bootstrap key subsystem shall have the
  bootstrap key sealed under the host key.
- Where the server runs in a container, the bootstrap key subsystem shall read the bootstrap key from
  a Swarm secret.
- While the OS credential store holds the bootstrap key on Windows or on Linux on a bare OS, the
  bootstrap key subsystem shall refuse to unlock a bootstrap file opened on another machine.
- While a Swarm secret holds the bootstrap key, the bootstrap key subsystem shall refuse to unlock a
  bootstrap file opened outside that Swarm.

### The key file, containers, TPM, never replaced

- If the server runs Linux on a bare OS without systemd 250 or later, then `hadv-setup` shall refuse
  to build a bootstrap file until the sysop explicitly chooses a key file.
- When the sysop chooses a key file, `hadv-setup` shall show that the bootstrap key sits unsealed on
  the same disk as the bootstrap file.
- While a key file holds the bootstrap key, `hadv-service` shall log a warning at every start that
  the bootstrap key is not sealed.
- Where the server runs in a container, `hadv-setup` shall use the bootstrap key it finds in a Swarm
  secret or a key file.
- Where the server runs in a container, `hadv-setup` shall create neither the bootstrap key nor the
  service account.
- If the server runs in a container with neither a Swarm secret nor a key file, then `hadv-setup`
  shall refuse to build a bootstrap file, naming both.
- Where the server runs in a container, if the file holding the bootstrap key is open to any account
  other than the service account, then `hadv-service` shall name a Swarm secret and a volume-mounted
  key file in its refusal.
- The shipped Dockerfile shall create the service account with a fixed uid.
- The shipped stack file shall make the service account own the Swarm secret, with mode `0400`.
- If a key file or a Swarm secret holds anything other than 32 bytes as base64 in 44 characters, with
  at most one trailing newline, then `hadv-service` shall refuse to start.
- If a key file or a Swarm secret holds anything other than 32 bytes as base64 in 44 characters, with
  at most one trailing newline, then `hadv-service` shall name the command that makes one,
  `openssl rand -base64 32`.
- The bootstrap key subsystem shall not require a TPM.
- If the server has no TPM, then the bootstrap key subsystem shall not fall back to a key file.
- The bootstrap key subsystem shall report how the bootstrap key is held, for the detailed health
  report: in a TPM, in the OS software key store, under the host key, as a Swarm secret or in a key
  file.
- The bootstrap key subsystem shall not warn that the server has no TPM.
- The bootstrap key subsystem shall offer no way to replace the bootstrap key on its own, by schedule
  or by command.
- While a Swarm secret or a key file holds the bootstrap key, when `hadv-setup` builds a bootstrap
  file, the bootstrap key subsystem shall seal it under the bootstrap key the sysop made.

### The account and the folder

- Where the server runs Windows or Linux on a bare OS, `hadv-setup` shall create the service account.
- `hadv-setup` shall give the service account no administrator or root rights.
- If `hadv-service` runs under any account other than the account that owns the bootstrap folder,
  then `hadv-service` shall refuse to start.
- Where the server runs Windows or Linux on a bare OS, `hadv-setup` shall create the bootstrap
  folder, owned by the service account.
- The bootstrap key subsystem shall keep the bootstrap file in the bootstrap folder, outside the
  program folder.
- Where the sysop picks no other folder, `hadv-setup` shall put the bootstrap folder in the
  platform's place for a service's machine-wide data: under `%ProgramData%` on Windows, under
  `/var/lib` on Linux.
- Where the server runs in a container, the bootstrap key subsystem shall keep the bootstrap folder at
  one fixed path inside the container.
- Where the sysop picks another bootstrap folder, `hadv-setup` shall record its location in the
  service registration.
- Where the service registration names no bootstrap folder, the bootstrap key subsystem shall use the
  platform's default bootstrap folder.
- If the bootstrap folder the sysop picks breaks a rule in the table below, then `hadv-setup` shall
  refuse it.
- If the bootstrap folder breaks a rule in the table below, then `hadv-service` shall refuse to
  start.
- If the bootstrap file or the key file is a symbolic link or, on Windows, a junction, then
  `hadv-service` shall refuse to start.
- The bootstrap key subsystem shall check each file and folder as it opened it, never by its name
  alone.

| The bootstrap folder is refused when |
|---|
| its path is not absolute |
| it is on a network share |
| it is on a removable drive |
| it is a symbolic link or, on Windows, a junction |
| its file system is not NTFS or ReFS on Windows, or ext2, ext3, ext4, XFS, Btrfs or ZFS on Linux |

### Permissions and refusals

- When `hadv-setup` builds a bootstrap file, `hadv-setup` shall set the bootstrap file and the
  bootstrap folder to their rules in the table below.
- If anything in the table below is set looser than its rule, then `hadv-service` shall refuse to
  start, naming it.
- If the bootstrap file is not writable by the service account, then `hadv-service` shall refuse to
  start, naming its path.
- `hadv-service` shall not change the permissions of anything in the table below.
- When `hadv-setup` finds anything in the table below set looser than its rule, `hadv-setup` shall
  offer to set it right.
- When `hadv-setup` offers to set a permission right, `hadv-setup` shall show what it found and what
  it sets.
- `hadv-setup` shall change no permission without the sysop's yes.
- Where the server runs in a container, if the Swarm secret's file is set looser than its rule, then
  `hadv-setup` shall name the stack file's account and mode settings instead of offering to change
  it.
- Where the server runs Windows, if a machine key pair of the bootstrap key subsystem's name already
  exists at first setup or joining, then `hadv-setup` shall refuse to create one.
- When joining again or a restore runs on Windows, `hadv-setup` shall delete the server's existing
  machine key pair and make a new one.

| What | Rule on Linux and in a container | Rule on Windows |
|---|---|---|
| the bootstrap folder | owned by the service account, mode `0700` | the service account, SYSTEM and Administrators only, with no inherited access |
| the bootstrap file | owned by the service account, mode `0600` | the service account, SYSTEM and Administrators only, with no inherited access |
| every other file in the bootstrap folder but the key file | the bootstrap file's rule | the bootstrap file's rule |
| the key file, or the Swarm secret's file | owned by the service account, mode `0400` | none (no key file on Windows) |
| the machine key pair | none | usable only by the service account, SYSTEM and Administrators |

### The file

- The bootstrap key subsystem shall seal the bootstrap file with AES-256-GCM under the bootstrap key.
- When the bootstrap key subsystem makes a bootstrap key, the bootstrap key subsystem shall make it
  from 256 random bits.
- The bootstrap key subsystem shall write the format version at the head of the bootstrap file,
  unencrypted.
- If any byte of the bootstrap file is changed, its format version included, then the bootstrap key
  subsystem shall refuse to unlock it.
- The bootstrap key subsystem shall act on nothing in the bootstrap file's header before the file's
  integrity check passes, beyond what the check needs.
- The bootstrap key subsystem shall raise the format version only when the bootstrap file's envelope
  or the meaning of a field changes.
- The bootstrap key subsystem shall keep the bootstrap file's contents as named fields.
- When the bootstrap key subsystem rewrites the bootstrap file, the bootstrap key subsystem shall keep
  every field it does not know, unchanged.
- The bootstrap key subsystem shall read a bootstrap file of its own format version or any older one.
- The bootstrap key subsystem shall write a bootstrap file only in its own format version.
- If a bootstrap file's format version is newer than its own, then the bootstrap key subsystem shall
  refuse to unlock it, naming both versions.
- When the bootstrap key subsystem rewrites the bootstrap file, the bootstrap key subsystem shall
  write the new file beside the old one.
- When the bootstrap key subsystem has written a new bootstrap file, the bootstrap key subsystem shall
  check that it reads back before replacing the old one.
- When a new bootstrap file reads back, the bootstrap key subsystem shall replace the old one with it
  in one step.
- If a new bootstrap file does not read back, then the bootstrap key subsystem shall delete it and
  keep the old one.
- If a rewrite stops before it finishes, then the bootstrap key subsystem shall leave the old
  bootstrap file whole.
- If a half-made new bootstrap file is found at start, then the bootstrap key subsystem shall delete
  it.
- If a half-made new bootstrap file is found at start, then the bootstrap key subsystem shall unlock
  the existing bootstrap file.

### Startup, failure and recovery

- If the bootstrap key subsystem refuses to unlock the bootstrap file, then `hadv-service` shall
  refuse to start.
- When the bootstrap key subsystem refuses to unlock the bootstrap file, the bootstrap key subsystem
  shall name the cause the table below gives for where the unlock failed.
- When `hadv-service` refuses to start, `hadv-service` shall name the path, the cause in plain words
  and what the sysop does next.
- When `hadv-service` refuses to start, `hadv-service` shall write the refusal to the server's local
  log only.
- If the bootstrap file does not unlock for any cause but a newer format version, then `hadv-service`
  shall name `hadv-setup` as the way back: joining again on a board with other servers, restore on a
  one-server board.
- If a rewrite of the bootstrap file fails, then `hadv-service` shall keep running on the vault keys
  it holds in memory.
- If a rewrite of the bootstrap file fails, then `hadv-service` shall log the failure as an error,
  naming the path.
- If a rewrite of the bootstrap file fails, then the bootstrap key subsystem shall report the failure
  for the detailed health report.
- If a rewrite of the bootstrap file fails, then `hadv-service` shall retry it on a timer and at every
  start until it succeeds.
- The bootstrap key subsystem shall hold the bootstrap key in its own memory only while it unlocks or
  rewrites the bootstrap file.
- When the bootstrap key subsystem rewrites the bootstrap file, the bootstrap key subsystem shall
  unseal the bootstrap key again, or on Linux with systemd older than 256 read it again from
  systemd, for that rewrite.
- The bootstrap key subsystem shall not show the bootstrap key or the bootstrap file's contents in a
  log, an error message, an audit entry, the detailed health report or a screen.

| Where the unlock fails | The cause it names |
|---|---|
| no bootstrap key in the OS credential store, the Swarm secret or the key file | the bootstrap key is not found |
| the OS credential store does not unseal the bootstrap key | sealed on another machine, or corrupt; both where the store does not tell them apart |
| no bootstrap file in the bootstrap folder | the bootstrap file is not found |
| the bootstrap file does not unseal under the bootstrap key | the bootstrap file is corrupt or altered; under a Swarm secret or a key file, also that the key is not this file's |
| the format version is newer than the program's | a newer format version, naming both |
