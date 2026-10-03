# Architecture

The one page a session reads before it reads a contract. Each unit below is a Go package
under `internal/` whose `contract.go` is the developer's, locked, and transliterated from
the Pascal unit of the same name in HeliosDesign `records/skeleton/`. The brief behind the
cluster units is `features/ADV-001` in HeliosDesign, as amended 2026-09-30. Where this page
and a contract disagree, the contract is right and this page is fixed.

## Units and what each owns

| Unit | Owns | Uses |
|---|---|---|
| `board` | The identifiers every unit shares: `ServerID`, `AccountID`, `RoleID`. Nothing else, so no unit imports another for a type. | nothing |
| `database` | The board's one PostgreSQL database as every unit reaches it: the connection (TLS, chain and host name verified), `Transact` (SERIALIZABLE, retried on a collision), one-statement reads, `ErrUnavailable` and what counts as it, the one sequence of additive migrations only `hadv-setup` applies, and the harness that gives every test its own database. The only importer of the driver. | `board` |
| `audit` | The record of operator actions: who, what, to which server or setting, before and after, on the database's UTC clock. Written inside the change's transaction. Read by tools only. | `board`, `database` |
| `registry` | The servers of one board: ID, display name, version, admitted or removed. Admission at start with the one-minor version check; removal as a mark; the board's minimum version. | `audit`, `board` |
| `lease` | Liveness: one row per server on the database's clock, a generation per acquisition, expiry computed by readers. The refusal protocol the engine follows is on `RenewalResult`. | `board` |
| `nodes` | One board-wide pool of node numbers. Acquire is one statement: lowest free, lease live, under the server's limit. A node on a dead lease is free. | `board` |
| `settings` | Every sysop setting, board, server or role scoped, declared in code by its feature, read on use with no cache, Set and audit in one transaction. | `audit`, `board` |
| `session` | One caller on one server from arrival to disconnect, transport-agnostic: identity, lifecycle, account, node, the row who's-online is built from, and the view a script is handed. | `audit`, `board`, `nodes` |
| `rbac` | Roles, permissions, holders, and the one check every gate asks. Five seeded roles by fixed ID, none deletable; account #1 is Sysop always. | `audit`, `board` |

`cmd/hadv-service` is the composition root and may import anything. The `Uses` column is
enforced by `depguard` in `.golangci.yml`; a new arrow is a change to that file in the same
PR, with its reason.

## The arrows, in words

- Everything above `board` and `database` goes to the database and returns
  `database.ErrUnavailable` rather than a default. There is no degraded mode.
- Only `database` reaches PostgreSQL. Every write runs in `Transact`; a unit's SQL is its
  own, against its own tables; a migration is written in the QA session, never in a build.
- The registry never reads the lease. A removed server finds out at its next renewal.
- The lease never calls anyone. Expiry is a fact readers compute; the allocator's
  occupancy rule, who's-online's filter and health's one line all read `Live`.
- The allocator knows servers, not sessions. The session row records the node.
- Settings notifies nobody. A change is seen on the next read, on every server.
- Audit is written only inside another unit's transaction. Nothing in the engine reads it.
- RBAC is asked; it never asks. Nothing imports `session`, `rbac` or `registry` for a type:
  `board` has the types.

## Two rules no contract can state alone

1. **A gate asks two units.** Whether a caller may do a thing is RBAC's answer AND the
   requirements unit's answer (age, ratio, time of day; not yet designed). Neither unit
   evaluates the other's question, and a gate proceeds only on two yeses.
2. **Role settings are read for the primary role only.** A role-scoped setting may be set
   on any role, grant roles included, and is inert until that role is someone's primary.

## The engine's loop, as the contracts imply it

Start: read the bootstrap record; `database.Verify`; `registry.Approve`; `lease.Acquire`; `session.Repair`;
declare settings and register permissions; open listeners. Then renew at the interval.
On `Expired`: `session.DisconnectAll`, refuse new callers, `Approve` and `Acquire` again on
your own. On `Superseded` or `NotAdmitted`: `DisconnectAll` and stay down. On
`database.ErrUnavailable` at renewal: count a miss and try again. On a clean stop:
`DisconnectAll`, then `lease.Release`, then `database.Close`.
