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
