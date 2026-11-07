-- haltlab fixture: composite
-- Composite tenant key: (org_id, workspace_id) (PLAN.md §8.2, row 2).
--
-- workspace_id values repeat across orgs ('eng', 'ops', ...), so a query that
-- filters on only one of the two key columns leaks rows from another tenant.
-- billing_accounts is scoped by org_id only (org-level data); api_keys is not
-- in the policy at all (table denied); ws.tags is global.
--
-- Policy: lab/policies/composite.yaml. RLS keys: app.org_id, app.workspace_id.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'haltlab_owner') THEN
    CREATE ROLE haltlab_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'haltlab_rls') THEN
    CREATE ROLE haltlab_rls NOLOGIN NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'haltlab_cols') THEN
    CREATE ROLE haltlab_cols NOLOGIN NOBYPASSRLS;
  END IF;
  EXECUTE format('GRANT haltlab_owner, haltlab_rls, haltlab_cols TO %I', current_user);
END $$;

CREATE SCHEMA IF NOT EXISTS ws AUTHORIZATION haltlab_owner;
SET search_path = ws;

CREATE TABLE ws.tags (                     -- global
  id    serial PRIMARY KEY,
  name  text NOT NULL
);

CREATE TABLE ws.workspaces (
  id            bigserial PRIMARY KEY,
  org_id        text NOT NULL,
  workspace_id  text NOT NULL,
  name          text NOT NULL,
  created_at    timestamptz NOT NULL,
  UNIQUE (org_id, workspace_id)
);

CREATE TABLE ws.members (
  id            bigserial PRIMARY KEY,
  org_id        text NOT NULL,
  workspace_id  text NOT NULL,
  display_name  text NOT NULL,
  email         text NOT NULL,             -- PII (denied)
  role          text NOT NULL,
  created_at    timestamptz NOT NULL
);

CREATE TABLE ws.projects (
  id            bigserial PRIMARY KEY,
  org_id        text NOT NULL,
  workspace_id  text NOT NULL,
  name          text NOT NULL,
  status        text NOT NULL,
  budget_cents  bigint NOT NULL,
  created_at    timestamptz NOT NULL
);

CREATE TABLE ws.tasks (
  id              bigserial PRIMARY KEY,
  org_id          text NOT NULL,
  workspace_id    text NOT NULL,
  project_id      bigint REFERENCES ws.projects (id),
  assignee_id     bigint REFERENCES ws.members (id),
  title           text NOT NULL,
  status          text NOT NULL,
  priority        text NOT NULL,
  estimate_hours  numeric(6, 1) NOT NULL,
  created_at      timestamptz NOT NULL
);

CREATE TABLE ws.documents (
  id              bigserial PRIMARY KEY,
  org_id          text NOT NULL,
  workspace_id    text NOT NULL,
  project_id      bigint REFERENCES ws.projects (id),
  title           text NOT NULL,
  body            text NOT NULL,           -- denied (free text, may hold secrets)
  classification  text NOT NULL,
  created_at      timestamptz NOT NULL
);

CREATE TABLE ws.billing_accounts (         -- org-scoped only
  id          bigserial PRIMARY KEY,
  org_id      text NOT NULL,
  plan        text NOT NULL,
  seats       integer NOT NULL,
  card_token  text NOT NULL,               -- secret (denied)
  created_at  timestamptz NOT NULL
);

CREATE TABLE ws.api_keys (                 -- not in the policy at all
  id            bigserial PRIMARY KEY,
  org_id        text NOT NULL,
  workspace_id  text NOT NULL,
  label         text NOT NULL,
  secret        text NOT NULL,
  created_at    timestamptz NOT NULL
);

CREATE INDEX ON ws.projects (org_id, workspace_id);
CREATE INDEX ON ws.tasks (org_id, workspace_id, project_id);
CREATE INDEX ON ws.documents (org_id, workspace_id);

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'ws' AND c.relkind IN ('r', 'p', 'v', 'm')
  LOOP
    EXECUTE format('ALTER TABLE ws.%I OWNER TO haltlab_owner', r.relname);
  END LOOP;
END $$;

-- RLS: both key columns for workspace data, org_id only for org data.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['workspaces', 'members', 'projects', 'tasks', 'documents', 'api_keys']
  LOOP
    EXECUTE format('ALTER TABLE ws.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS haltlab_tenant ON ws.%I', t);
    EXECUTE format($p$CREATE POLICY haltlab_tenant ON ws.%I FOR SELECT
                      TO haltlab_rls, haltlab_cols
                      USING (org_id = current_setting('app.org_id', true)
                             AND workspace_id = current_setting('app.workspace_id', true))$p$, t);
  END LOOP;
END $$;
ALTER TABLE ws.billing_accounts ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS haltlab_tenant ON ws.billing_accounts;
CREATE POLICY haltlab_tenant ON ws.billing_accounts FOR SELECT TO haltlab_rls, haltlab_cols
  USING (org_id = current_setting('app.org_id', true));

GRANT USAGE ON SCHEMA ws TO haltlab_rls, haltlab_cols;
GRANT SELECT ON ALL TABLES IN SCHEMA ws TO haltlab_rls;

REVOKE ALL ON ALL TABLES IN SCHEMA ws FROM haltlab_cols;
GRANT SELECT ON ws.tags TO haltlab_cols;
GRANT SELECT (id, org_id, workspace_id, name, created_at) ON ws.workspaces TO haltlab_cols;
GRANT SELECT (id, org_id, workspace_id, display_name, role, created_at) ON ws.members TO haltlab_cols;
GRANT SELECT (id, org_id, workspace_id, name, status, budget_cents, created_at) ON ws.projects TO haltlab_cols;
GRANT SELECT (id, org_id, workspace_id, project_id, assignee_id, title, status, priority, estimate_hours, created_at) ON ws.tasks TO haltlab_cols;
GRANT SELECT (id, org_id, workspace_id, project_id, title, classification, created_at) ON ws.documents TO haltlab_cols;
GRANT SELECT (id, org_id, plan, seats, created_at) ON ws.billing_accounts TO haltlab_cols;
