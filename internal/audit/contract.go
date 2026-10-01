// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Package audit is the record of operator actions: who did what to which server or
// setting, with the values before and after, on the database's UTC clock. An entry is
// written inside the transaction of the change it records, so there is never a change
// without its entry or an entry without its change. Nothing in the engine updates,
// deletes or reads entries; the sysop's tools read them in pages. Retention is a later
// feature's question. Every operation may return database.ErrUnavailable.
//
// This file is the developer's contract (HeliosDesign records/skeleton/Audit.pas) and is
// locked: a loop session does not edit it.
package audit

import (
	"context"
	"time"

	"github.com/heliosestate/heliosadvance/internal/board"
	"github.com/heliosestate/heliosadvance/internal/database"
)

// ActorKind is what kind of thing did it. The list grows as features arrive; adding a
// kind reopens nothing.
type ActorKind uint8

// Actor kinds.
const (
	Sysop ActorKind = iota + 1
	Engine
	SetupTool
)

// Actor is who did it: a kind and that kind's identifier. One field per kind, so a sysop
// account and a server ID never share a column and the tools can join each to its table.
type Actor struct {
	Kind   ActorKind
	Sysop  string         // Sysop: the account
	Server board.ServerID // Engine: the server the engine runs on
	Host   string         // SetupTool: the host it ran on
}

// Entry is one audit entry.
type Entry struct {
	Recorded time.Time // UTC, filled by the database; ignored on Write
	Actor    Actor
	Server   board.ServerID // the server the action concerns; 0 if none
	Action   string         // dotted, chosen by the writing unit: registry.remove
	Target   string         // a server ID, a setting name; as text
	Before   string         // as text; empty where there was none
	After    string
}

// Filter selects entries. Any field left empty or zero matches everything.
type Filter struct {
	FromUTC, ToUTC time.Time
	Server         board.ServerID
	ActorKind      ActorKind
	HasActorKind   bool
	ActionPrefix   string
	Target         string
}

// Audit is the contract.
type Audit interface {
	// Write is called inside the caller's transaction, which carries the deadline of the
	// change. Recorded is filled by the database.
	Write(transaction database.Transaction, entry Entry) error

	// Read is newest first. Page is 1 upward; pageSize is bounded by the implementation.
	Read(ctx context.Context, filter Filter, page, pageSize uint32) ([]Entry, error)
}
