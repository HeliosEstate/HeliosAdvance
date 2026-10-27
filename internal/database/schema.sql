-- SPDX-FileCopyrightText: 2026 Pascal Fairchild
-- SPDX-License-Identifier: AGPL-3.0-only

-- The board's schema, version 1, and what a server's login may do with it: database Part 1's
-- records and grants as the developer approved them. It runs once, under the owner login that only
-- hadv-setup uses, which then owns the schema and every table in it. The role hadv_server must
-- exist first, with no login: each server's own login is a member of it and is granted nothing
-- else. A change here is a new schema version, additive only, by the developer's pull request.

CREATE SCHEMA hadv;

-- One row: the version of the shape the records below have.
CREATE TABLE hadv.schema_version (
    version integer NOT NULL
);
CREATE UNIQUE INDEX schema_version_one_row ON hadv.schema_version ((true));
INSERT INTO hadv.schema_version (version) VALUES (1);

-- One row per server. The ID is never reused. The lease is the server's claim to be alive until
-- lease_until, by the database's clock; lease_holder is the random number the run holding it
-- wrote, empty before any run has taken it.
CREATE TABLE hadv.servers (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    lease_holder uuid,
    lease_until timestamptz NOT NULL
);

-- A server's login reads the two tables and changes only the lease. It inserts, deletes, creates,
-- alters and drops nothing.
GRANT USAGE ON SCHEMA hadv TO hadv_server;
GRANT SELECT ON hadv.schema_version TO hadv_server;
GRANT SELECT ON hadv.servers TO hadv_server;
GRANT UPDATE (lease_holder, lease_until) ON hadv.servers TO hadv_server;
