// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package database

// tooPowerfulQuery is true when the login itself (session_user: a default role it signs in under
// must not hide its own rights) holds more than a server's login is
// granted, or when hadv_server, whose powers every login shares, holds an attribute but INHERIT.
//
// Each source below is an ACL in the database, read with aclexplode; a NULL ACL is read as
// PostgreSQL's default for the object's owner. A source gives its kind's catalog, the object, its
// schema, its name, a column's name, the ACL, and the ACL the object started with.
//
// Schemas, relations and functions are named, not cast with regclass, so a missing hadv table
// cannot fail this query before the schema version is read.
const tooPowerfulQuery = `
WITH me AS (SELECT oid FROM pg_roles WHERE rolname = session_user),
server AS (SELECT oid FROM pg_roles WHERE rolname = 'hadv_server'),
grantees AS (SELECT oid FROM me UNION SELECT oid FROM server UNION SELECT 0::oid),
sources AS (
    SELECT 'pg_database'::regclass::oid AS kind, oid AS object, NULL::text AS schema_name, datname AS object_name,
        NULL::text AS column_name, coalesce(datacl, acldefault('d', datdba)) AS acl, NULL::aclitem[] AS initial
    FROM pg_database WHERE datname = current_database()
  UNION ALL
    SELECT 'pg_namespace'::regclass::oid, n.oid, n.nspname, n.nspname, NULL,
        coalesce(n.nspacl, acldefault('n', n.nspowner)),
        coalesce((SELECT initprivs FROM pg_init_privs i WHERE i.objoid = n.oid AND i.classoid = 'pg_namespace'::regclass AND i.objsubid = 0),
            acldefault('n', n.nspowner))
    FROM pg_namespace n
  UNION ALL
    SELECT 'pg_class'::regclass::oid, c.oid, n.nspname, c.relname, NULL,
        coalesce(c.relacl, acldefault((CASE WHEN c.relkind = 'S' THEN 's' ELSE 'r' END)::"char", c.relowner)),
        coalesce((SELECT initprivs FROM pg_init_privs i WHERE i.objoid = c.oid AND i.classoid = 'pg_class'::regclass AND i.objsubid = 0),
            acldefault((CASE WHEN c.relkind = 'S' THEN 's' ELSE 'r' END)::"char", c.relowner))
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  UNION ALL
    SELECT 'pg_class'::regclass::oid, a.attrelid, n.nspname, c.relname, a.attname, a.attacl,
        (SELECT initprivs FROM pg_init_privs i WHERE i.objoid = a.attrelid AND i.classoid = 'pg_class'::regclass AND i.objsubid = a.attnum)
    FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE a.attacl IS NOT NULL AND NOT a.attisdropped
  UNION ALL
    SELECT 'pg_proc'::regclass::oid, p.oid, n.nspname, p.proname, NULL,
        coalesce(p.proacl, acldefault('f', p.proowner)),
        coalesce((SELECT initprivs FROM pg_init_privs i WHERE i.objoid = p.oid AND i.classoid = 'pg_proc'::regclass AND i.objsubid = 0),
            acldefault('f', p.proowner))
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  UNION ALL
    SELECT 'pg_largeobject_metadata'::regclass::oid, oid, NULL, NULL, NULL, coalesce(lomacl, acldefault('L', lomowner)), NULL
    FROM pg_largeobject_metadata
  UNION ALL
    SELECT 'pg_foreign_data_wrapper'::regclass::oid, oid, NULL, NULL, NULL, coalesce(fdwacl, acldefault('F', fdwowner)), NULL
    FROM pg_foreign_data_wrapper
  UNION ALL
    SELECT 'pg_foreign_server'::regclass::oid, oid, NULL, NULL, NULL, coalesce(srvacl, acldefault('S', srvowner)), NULL
    FROM pg_foreign_server
  UNION ALL
    SELECT 'pg_default_acl'::regclass::oid, oid, NULL, NULL, NULL, defaclacl, NULL FROM pg_default_acl
  UNION ALL
    SELECT 'pg_parameter_acl'::regclass::oid, oid, NULL, NULL, NULL, paracl, NULL FROM pg_parameter_acl
),
held AS (
    SELECT s.*, a.grantee, a.privilege_type, a.is_grantable
    FROM sources s, aclexplode(s.acl) a
    WHERE a.grantee IN (SELECT oid FROM grantees)
)
SELECT
    EXISTS (SELECT 1 FROM pg_roles WHERE rolname = session_user
        AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls))
    OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hadv_server'
        AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolcanlogin OR rolreplication OR rolbypassrls))
    OR EXISTS (SELECT 1 FROM pg_auth_members m
        WHERE m.roleid = (SELECT oid FROM server) AND m.member = (SELECT oid FROM me) AND m.admin_option)
    OR EXISTS (SELECT 1 FROM pg_roles r
        WHERE r.rolname NOT IN (session_user, 'hadv_server') AND pg_has_role(session_user, r.oid, 'MEMBER'))
    OR EXISTS (SELECT 1 FROM pg_database d WHERE d.datname = current_database()
        AND d.datdba IN (SELECT oid FROM me UNION SELECT oid FROM server))
    OR EXISTS (SELECT 1 FROM pg_shdepend d
        WHERE d.deptype = 'o' AND d.refclassid = 'pg_authid'::regclass
          AND d.refobjid IN (SELECT oid FROM me UNION SELECT oid FROM server)
          AND d.dbid = (SELECT oid FROM pg_database WHERE datname = current_database()))
    OR EXISTS (SELECT 1 FROM held h WHERE (
        -- schema.sql's four grants to hadv_server.
        (h.grantee = (SELECT oid FROM server) AND NOT h.is_grantable AND (
            (h.kind = 'pg_namespace'::regclass AND h.schema_name = 'hadv' AND h.privilege_type = 'USAGE')
            OR (h.kind = 'pg_class'::regclass AND h.schema_name = 'hadv' AND h.column_name IS NULL
                AND h.object_name IN ('schema_version', 'servers') AND h.privilege_type = 'SELECT')
            OR (h.kind = 'pg_class'::regclass AND h.schema_name = 'hadv' AND h.object_name = 'servers'
                AND h.column_name IN ('lease_holder', 'lease_until') AND h.privilege_type = 'UPDATE')))
        -- PostgreSQL's default right for every login to connect, and to use the schema public.
        OR (NOT h.is_grantable AND h.kind = 'pg_database'::regclass AND h.privilege_type = 'CONNECT')
        OR (h.grantee = 0 AND NOT h.is_grantable AND h.kind = 'pg_namespace'::regclass
            AND h.schema_name = 'public' AND h.privilege_type = 'USAGE')
        -- What PUBLIC held on pg_catalog when the cluster was made. Its record, pg_init_privs, has
        -- no row for information_schema, whose own SQL grants PUBLIC USAGE on the schema and SELECT
        -- on each of its relations and EXECUTE on each of its functions, so those three are named.
        OR (h.grantee = 0 AND NOT h.is_grantable AND h.schema_name = 'information_schema'
            AND ((h.kind = 'pg_namespace'::regclass AND h.privilege_type = 'USAGE')
                OR (h.kind = 'pg_class'::regclass AND h.column_name IS NULL AND h.privilege_type = 'SELECT')
                OR (h.kind = 'pg_proc'::regclass AND h.privilege_type = 'EXECUTE')))
        OR (h.grantee = 0 AND NOT h.is_grantable AND h.schema_name = 'pg_catalog'
            AND EXISTS (SELECT 1 FROM aclexplode(h.initial) i
                WHERE i.grantee = 0 AND NOT i.is_grantable AND i.privilege_type = h.privilege_type))
    ) IS NOT TRUE)`
