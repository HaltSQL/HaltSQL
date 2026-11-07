-- haltlab fixture: hierarchical
-- Hierarchical tenants: a parent org may read its own rows and its child
-- orgs' rows (PLAN.md §8.2, row 3). The caller's context carries the full set
-- of visible tenants as a list (tenant_ids), and queries compare with
-- `tenant_id = ANY($1)` in bound mode.
--
-- Stresses: set-valued tenant context, sibling leakage, over-broad matches
-- (prefix LIKE, parent_tenant_id joins).
--
-- Policy: lab/policies/hierarchical.json (JSON on purpose, to exercise the
-- second policy format). RLS key: app.tenant_ids (comma-separated list).

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

CREATE SCHEMA IF NOT EXISTS crm AUTHORIZATION haltlab_owner;
SET search_path = crm;

CREATE TABLE crm.regions (                 -- global
  code  text PRIMARY KEY,
  name  text NOT NULL
);

CREATE TABLE crm.tenants (
  id                bigserial PRIMARY KEY,
  tenant_id         text NOT NULL UNIQUE,
  parent_tenant_id  text,                  -- NULL for roots
  name              text NOT NULL,
  region            text REFERENCES crm.regions (code),
  created_at        timestamptz NOT NULL
);

CREATE TABLE crm.accounts (
  id          bigserial PRIMARY KEY,
  tenant_id   text NOT NULL,
  name        text NOT NULL,
  tier        text NOT NULL,
  created_at  timestamptz NOT NULL
);

CREATE TABLE crm.contacts (
  id          bigserial PRIMARY KEY,
  tenant_id   text NOT NULL,
  account_id  bigint REFERENCES crm.accounts (id),
  full_name   text NOT NULL,
  email       text,                        -- PII (denied)
  phone       text,                        -- PII (denied)
  created_at  timestamptz NOT NULL
);

CREATE TABLE crm.opportunities (
  id            bigserial PRIMARY KEY,
  tenant_id     text NOT NULL,
  account_id    bigint REFERENCES crm.accounts (id),
  stage         text NOT NULL,
  amount_cents  bigint NOT NULL,
  close_date    date NOT NULL,
  title         text NOT NULL
);

CREATE TABLE crm.activities (
  id              bigserial PRIMARY KEY,
  tenant_id       text NOT NULL,
  opportunity_id  bigint REFERENCES crm.opportunities (id),
  kind            text NOT NULL,
  note            text NOT NULL,
  created_at      timestamptz NOT NULL
);

CREATE INDEX ON crm.accounts (tenant_id);
CREATE INDEX ON crm.contacts (tenant_id);
CREATE INDEX ON crm.opportunities (tenant_id, stage);
CREATE INDEX ON crm.activities (tenant_id);

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'crm' AND c.relkind IN ('r', 'p', 'v', 'm')
  LOOP
    EXECUTE format('ALTER TABLE crm.%I OWNER TO haltlab_owner', r.relname);
  END LOOP;
END $$;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['tenants', 'accounts', 'contacts', 'opportunities', 'activities']
  LOOP
    EXECUTE format('ALTER TABLE crm.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS haltlab_tenant ON crm.%I', t);
    EXECUTE format($p$CREATE POLICY haltlab_tenant ON crm.%I FOR SELECT
                      TO haltlab_rls, haltlab_cols
                      USING (tenant_id = ANY (string_to_array(current_setting('app.tenant_ids', true), ',')))$p$, t);
  END LOOP;
END $$;

GRANT USAGE ON SCHEMA crm TO haltlab_rls, haltlab_cols;
GRANT SELECT ON ALL TABLES IN SCHEMA crm TO haltlab_rls;

REVOKE ALL ON ALL TABLES IN SCHEMA crm FROM haltlab_cols;
GRANT SELECT ON crm.regions TO haltlab_cols;
GRANT SELECT (id, tenant_id, parent_tenant_id, name, region, created_at) ON crm.tenants TO haltlab_cols;
GRANT SELECT (id, tenant_id, name, tier, created_at) ON crm.accounts TO haltlab_cols;
GRANT SELECT (id, tenant_id, account_id, full_name, created_at) ON crm.contacts TO haltlab_cols;
GRANT SELECT (id, tenant_id, account_id, stage, amount_cents, close_date, title) ON crm.opportunities TO haltlab_cols;
GRANT SELECT (id, tenant_id, opportunity_id, kind, note, created_at) ON crm.activities TO haltlab_cols;
