# Behavior

This page lists what each outcome of the board must do, one section per outcome, in lines that a
test or a run on the real system can check. The lines use the EARS form and only "shall" and
"shall not". The developer approves every line, and the lines are locked like the contracts: a
change goes back through design before it reaches this page.

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
- When first-time setup completes, the installer shall have created a local registry entry at
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

- If a registry entry cannot be reached, then the storage subsystem shall report it as unreachable to
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
- When first-time setup completes, the installer shall have set the server's work folder to
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
- If a caller to the Admin API presents anything other than a sysop login, a paired server's
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
- The storage subsystem shall raise its events for the sysop through the event system.
- When a message is deleted, the message system shall have the storage subsystem delete that message's
  attachments.
- The network-mail subsystem shall place files arriving by network mail, TIC files and file
  attachments, into a file area through the storage subsystem in the same way as an import.

### Terms

Each term below has one meaning in these lines.

- **storage**: a physical place where the board's files live: a folder on a server's disk, an SMB
  share, an S3 bucket, an ISO or an optical drive.
- **registry entry**: the record describing one storage (its kind, path, owner, credentials).
- **the registry**: the list of all registry entries.
- **storage subsystem**: the part of the engine that reaches storages and does the broad checks.
- **server**: one computer, physical or virtual, running the board.
- **local vault**: one per server; it only unlocks that server's bootstrap file at startup (the
  bootstrap holds the database connection details and settings such as pool size).
- **shared vault**: in the database; it holds every credential the servers share (network node
  credentials, registry entries' credentials). The storage subsystem uses only the shared vault.

- **sysop**: the person who runs the board and holds a sysop login.
- **user**: a person who uses the board without a sysop login.
- **configuration utilities**: `hadv-config` and `hadv-config-gui`.
- **import utility**: the CLI/TUI tool that brings files into an area through the Admin API.
- **installer**: `hadv-setup`; **first-time setup** is its path that seeds the first server.
- **engine**: the board's server program; its own subsystems are the ones compiled into it, not
  custom scripts.
- **custom script**: a Lua script a sysop adds; not part of the engine.
- **owning subsystem**: the engine subsystem that asked the storage subsystem to keep a file, and
  decides who may use it.
- **message system**: the engine subsystem for message areas and mail.
- **network-mail subsystem**: the engine subsystem that exchanges mail with other systems (FidoNet,
  QWK and the like).
- **event system**: database tables with NOTIFY/LISTEN, carrying events between subsystems.
- **Admin API**: the sysops' endpoint on each server, on its own port.
- **ClusterAPI**: the servers' endpoint on each server, on its own port, open only to paired servers.
- **paired server**: a server that has joined the board and holds the certificate joining gave it.
- **area**: a file area or a message area, as storage sees it: the files of one kind kept under one
  folder, or one disc path, on one registry entry. Not to be confused with a registry entry.
- **file area**: an area of files offered for download.
- **Name**: an area's short identifier: no spaces, stored uppercase, unique within its kind; on a
  writable registry entry, the area's folder name. Not to be confused with the descriptions users see.
- **kind**: a category of files registered by an engine subsystem (file areas, message attachments),
  with its own folder on each writable registry entry.
- **visible**: appears in listings and can be opened. **hidden**: on a storage, seen only by the
  owning subsystem.
- **work folder**: a server's own local folder for files in progress and optical copies, outside the
  registry.
- **root path**: the top of a drive or file system (`C:\`, `/`).
- **drive-letter administrative share**: a share named by one letter followed by `$` (`C$`).
- **refused-locations list**: the system folders per OS, the board's program folders and the
  database's data folder; the system folders are not settled yet.
- **refused-characters list**: the characters and names unsafe on any supported OS; not settled yet.
- **marker file**: a small file at a writable registry entry's path holding that entry's identity.
- **path rules**: the root, refused-location, admin-share and nesting rules in the first section of
  lines.
- **volume label and serial**: the name and number recorded on a disc or image when it was made.
- **missing**: in the records, but not on its storage.
- **damaged**: its hash differs from the recorded hash.
- **unreachable**: the storage cannot be contacted.
- **unavailable**: the storage was contacted but is not the one its registry entry describes (wrong
  disc, not an optical drive, an image that does not match).
- **full**: too little room for the write.
- **available**: none of the above.
- **limit**: the most space the board may use on a registry entry; optional, set by the sysop.
- **room**: the limit minus the space used, and on local and SMB registry entries no more than the
  storage's free space.
- **low-space warning level**: the room below which the sysop is warned.
- **scrub job**: a job that reads every file on a registry entry and compares its hash.
- **door**: a door game, an external program the board runs for a caller; used in no other sense.
- **size limits**: the bounds the storage subsystem sets on every size an SMB server or an
  ISO image states; not settled yet.

## Shared secrets

Shared secrets are the passwords, keys and other secret values the board presents to other
systems, along with those a protocol needs in plain form to check: SMB and S3 credentials, network
node passwords, mail account passwords and a DKIM private key, among others. Every server needs
them. The shared secrets subsystem keeps them encrypted in the database, where every server can
reach them, and hands each one only to the part of the board that owns it. Passwords that others
use to sign in to the board are not kept here; the board keeps only one-way hashes of those.

A board comes back up on its own after a reboot, so no passphrase guards the key that opens the
secrets. Each server keeps that key in its own bootstrap file, sealed with the operating system's
credential store, and never in the database. If no server holds the key any more, the only way back
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

### Terms

Each term below has one meaning in these lines.

- **shared secrets subsystem**: the part of `hadv-service` that keeps the secrets every server needs,
  encrypted in the shared vault, and hands each only to its owner.
- **shared vault**: the shared secrets subsystem's store, in the database.
- **bootstrap key subsystem**: the per-server subsystem that seals the bootstrap file with the
  operating system's own secret store. A separate subsystem from the shared secrets subsystem.
- **bootstrap file**: the per-server file holding the database connection, settings such as pool
  size, the vault key and the server's private keys.
- **vault key**: the one key every server keeps in its bootstrap file; each value's working key is
  derived from it; never stored in the database.
- **working key**: the key that encrypts one write of one value, derived from the vault key, owner,
  identity and salt.
- **vault-key change**: replacing the vault key and re-encrypting every value under the new one.
- **vault-key schedule**: the yearly vault-key change, on by default, settable from 45 days to two
  years, switched off only by the #1 Sysop. Not the event subsystem's schedule as a whole.
- **copy** (of the vault key): the vault key encrypted to one server's or the recovery key's public
  key, and signed. Used in no other sense: never a clipboard copy.
- **recovery copy**: the copy of the vault key made for the recovery key. Not a backup.
- **vault-key version**, **format version**: recorded on every value; which vault key encrypted it,
  and which cipher and derivation. Not the engine release.
- **engine release**: one released version of `hadv-service`; servers run at most one release apart.
- **receiving key pair**, **signing key pair**: a server's two single-purpose key pairs; one opens
  the copies sent to it, the other signs the copies it makes. Neither is the server's TLS certificate.
- **registered server**: a server whose two public keys are registered in the database and which has
  not been deleted. Not a server that is running; that is its health status.
- **health status**: what a registered server's public, basic health check answers: whether it is
  running and reachable, as the restore screen shows it. Not the Admin API's detailed health report,
  which needs a sign-in.
- **recovery key pair**: the key pair whose private half the recovery code rebuilds.
- **recovery code**: the 24 numbered words that rebuild the recovery key pair.
- **secret**: one owner's named entry in the shared vault: its owner, identity and value. Not a
  "shared secret" in the protocol sense; that is a session password.
- **value**: the opaque bytes a secret holds, which the vault never interprets. Not a setting's
  value in the configuration.
- **owner**: the engine subsystem or helper program a secret belongs to, named when it is stored; the
  only one that reads it, or, for a helper program, the only one it is delivered to.
- **identity**: the name an owner gives a secret, unique for that owner.
- **store**, **read**, **delete**, **status**, **deliver**: the five operations on secrets. "Store" is
  never the operating system's credential store; "deliver" is only ever to a helper program.
- **not set**, **unavailable**, **refused**: the read results other than a value: no value stored; a
  value that failed to decrypt; a reader that is not the owner.
- **helper program**: one of the board's own programs running beside `hadv-service` on the same
  server and doing part of the board's ongoing work (the mail processors, `hadv-xyz`, `hadv-doors`);
  it receives only the secrets it owns, if any. `hadv-setup` and the configuration utilities are not
  helper programs.
- **authenticated helper program**: a helper program that has proven which helper it is on the
  channel that delivers its secrets.
- **engine**: `hadv-service`.
- **`hadv-setup`**: the setup wizard; it runs only on the server itself. **First setup** seeds the
  first server; **restore** rebuilds a server from a backup and the recovery code.
- **Admin API**: the sysops' endpoint on each server, on its own port.
- **Sysop role**: the default role that runs the board. **#1 Sysop**: the main Sysop, the #1 account,
  who owns the board. **sysop**, lower case: anyone holding the Sysop role.
- **alert every sysop**: a message that reaches every sysop directly. Not a log entry.
- **log**: an entry in both the server's local log and the central audit system, unless a line
  names one.
- **NOTIFY**: PostgreSQL's NOTIFY, a nudge that carries no key. Not an alert.
- **session password**: the password two FidoNet-technology nodes share for a link.
