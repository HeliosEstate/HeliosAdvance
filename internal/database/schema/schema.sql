-- SPDX-FileCopyrightText: 2026 Pascal Fairchild
-- SPDX-License-Identifier: AGPL-3.0-only

-- The board's schema, version 2, and what a server's login may do with it: database Parts 1 and
-- 2's records and grants as the developer approved them. It is the whole schema of its version,
-- run once on a new database, under the owner login that only hadv-setup uses, which then owns the
-- schema and every table in it; upgrading a database of an older version is hadv-setup's. The
-- role hadv_server must exist first, with no login: each server's own login is a member of it and
-- is granted nothing else. A change here is a new schema version, additive only against the
-- version before it, by the developer's pull request.

CREATE SCHEMA hadv;

-- One row: the version of the shape the records below have.
CREATE TABLE hadv.schema_version (
    version integer NOT NULL
);
CREATE UNIQUE INDEX schema_version_one_row ON hadv.schema_version ((true));
INSERT INTO hadv.schema_version (version) VALUES (2);

-- One row per server. The ID is never reused. The lease is the server's claim to be alive until
-- lease_until, by the database's clock; lease_holder is the random number the run holding it
-- wrote, empty before any run has taken it. The server's settings follow: which of Telnet, SSH
-- and Telnet over TLS (telnets) it runs, and their ports. Each is required, and a new row takes
-- the default here: every service off, on its usual port. A port of 0 lets the operating system
-- pick one.
CREATE TABLE hadv.servers (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    lease_holder uuid,
    lease_until timestamptz NOT NULL,
    telnet_on boolean NOT NULL DEFAULT false,
    telnet_port integer NOT NULL DEFAULT 23
        CONSTRAINT telnet_port_range CHECK (telnet_port BETWEEN 0 AND 65535),
    ssh_on boolean NOT NULL DEFAULT false,
    ssh_port integer NOT NULL DEFAULT 22
        CONSTRAINT ssh_port_range CHECK (ssh_port BETWEEN 0 AND 65535),
    telnets_on boolean NOT NULL DEFAULT false,
    telnets_port integer NOT NULL DEFAULT 992
        CONSTRAINT telnets_port_range CHECK (telnets_port BETWEEN 0 AND 65535)
);

-- A server's login reads the two tables, its settings among them, and changes only the lease. It
-- inserts, deletes, creates, alters and drops nothing: PostgreSQL's default right for everyone to
-- make temporary tables and functions in this database is taken away first. The owner login owns
-- this database, so it may take it away.
DO $$
BEGIN
    EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
END
$$;
GRANT USAGE ON SCHEMA hadv TO hadv_server;
GRANT SELECT ON hadv.schema_version TO hadv_server;
GRANT SELECT ON hadv.servers TO hadv_server;
GRANT UPDATE (lease_holder, lease_until) ON hadv.servers TO hadv_server;
