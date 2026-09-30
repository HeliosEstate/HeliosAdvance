// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package board holds the identifiers every unit shares and nothing else, so that no
// unit has to import another for a type alone. The registry allocates a ServerID; the
// audit, lease, node and settings units name servers by it; none of them may import the
// registry for it, because the registry imports audit and a cycle would follow.
//
// This file is the developer's contract (HeliosDesign records/skeleton/Board.pas) and is
// locked: a loop session does not edit it.
package board

// ServerID is allocated by the database at join, never reused, and held in the bootstrap
// record. It carries no authority: the server's database login does. Small so it reads in
// a log line.
type ServerID uint32
