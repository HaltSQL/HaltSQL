-- haltlab fixture: saas_shared
-- Multi-tenant SaaS, shared tables keyed by tenant_id (PLAN.md §8.2, row 1).
--
-- Stresses: the core per-relation tenant proof, PII column denial (email,
-- phone, ssn, password_hash, card_token), a global reference table, legacy
-- data quality (nullable tenant_id, single-column FKs that do not pin the
-- tenant, so cross-tenant references exist in the data).
--
-- Policy: lab/policies/saas_shared.yaml. Roles and RLS are installed at the
-- end of this file; the harness re-applies haltlab_cols grants from the policy.
-- Loaded into a fresh database by the harness (idempotent where practical).

-- ---------------------------------------------------------------- roles ----
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

CREATE SCHEMA IF NOT EXISTS app AUTHORIZATION haltlab_owner;
SET search_path = app;

-- --------------------------------------------------------------- tables ----
CREATE TABLE app.currencies (            -- global: no tenant column
  code      char(3) PRIMARY KEY,
  name      text NOT NULL,
  symbol    text NOT NULL,
  decimals  smallint NOT NULL DEFAULT 2
);

CREATE TABLE app.orgs (
  id          bigserial PRIMARY KEY,
  tenant_id   text,                       -- nullable on purpose (legacy rows)
  name        text NOT NULL,
  plan        text NOT NULL,
  created_at  timestamptz NOT NULL
);

CREATE TABLE app.users (
  id             bigserial PRIMARY KEY,
  tenant_id      text,
  email          text NOT NULL,           -- PII (denied)
  full_name      text NOT NULL,
  role           text NOT NULL,
  password_hash  text NOT NULL,           -- secret (denied)
  created_at     timestamptz NOT NULL,
  last_login_at  timestamptz
);

CREATE TABLE app.customers (
  id          bigserial PRIMARY KEY,
  tenant_id   text,
  name        text NOT NULL,
  email       text,                       -- PII (denied)
  phone       text,                       -- PII (denied)
  ssn         text,                       -- PII (denied)
  country     char(2) NOT NULL,
  created_at  timestamptz NOT NULL
);

CREATE TABLE app.orders (
  id           bigserial PRIMARY KEY,
  tenant_id    text,
  customer_id  bigint REFERENCES app.customers (id),   -- does not pin tenant
  status       text NOT NULL,
  total_cents  bigint NOT NULL,
  currency     char(3) NOT NULL REFERENCES app.currencies (code),
  note         text,
  created_at   timestamptz NOT NULL
);

CREATE TABLE app.order_items (
  id                bigserial PRIMARY KEY,
  tenant_id         text,
  order_id          bigint REFERENCES app.orders (id),
  sku               text NOT NULL,
  description       text NOT NULL,
  quantity          integer NOT NULL,
  unit_price_cents  bigint NOT NULL
);

CREATE TABLE app.invoices (
  id            bigserial PRIMARY KEY,
  tenant_id     text,
  order_id      bigint REFERENCES app.orders (id),
  number        text NOT NULL,
  status        text NOT NULL,
  amount_cents  bigint NOT NULL,
  due_date      date NOT NULL,
  issued_at     timestamptz NOT NULL
);

CREATE TABLE app.payments (
  id            bigserial PRIMARY KEY,
  tenant_id     text,
  invoice_id    bigint REFERENCES app.invoices (id),
  method        text NOT NULL,
  amount_cents  bigint NOT NULL,
  card_last4    text,
  card_token    text,                     -- secret (denied)
  paid_at       timestamptz NOT NULL
);

CREATE TABLE app.audit_events (
  id             bigserial PRIMARY KEY,
  tenant_id      text,
  actor_user_id  bigint REFERENCES app.users (id),
  action         text NOT NULL,
  detail         jsonb NOT NULL,
  ip             inet,                    -- denied
  created_at     timestamptz NOT NULL
);

CREATE INDEX ON app.orders (tenant_id, created_at);
CREATE INDEX ON app.customers (tenant_id);
CREATE INDEX ON app.order_items (tenant_id, order_id);
CREATE INDEX ON app.invoices (tenant_id, status);
CREATE INDEX ON app.payments (tenant_id);
CREATE INDEX ON app.audit_events (tenant_id, created_at);

-- --------------------------------------------------------- ownership -------
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'app' AND c.relkind IN ('r', 'p', 'v', 'm')
  LOOP
    EXECUTE format('ALTER TABLE app.%I OWNER TO haltlab_owner', r.relname);
  END LOOP;
END $$;

-- ------------------------------------------------------------------ RLS ----
-- Oracle role haltlab_rls sees only rows of current_setting('app.tenant_id').
-- haltlab_cols gets the same row policy (it exists to test column grants).
-- The owner is not subject to RLS (no FORCE), which is what the "owner" run uses.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['orgs', 'users', 'customers', 'orders', 'order_items',
                           'invoices', 'payments', 'audit_events']
  LOOP
    EXECUTE format('ALTER TABLE app.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS haltlab_tenant ON app.%I', t);
    EXECUTE format($p$CREATE POLICY haltlab_tenant ON app.%I FOR SELECT
                      TO haltlab_rls, haltlab_cols
                      USING (tenant_id = current_setting('app.tenant_id', true))$p$, t);
  END LOOP;
END $$;

-- --------------------------------------------------------------- grants ----
GRANT USAGE ON SCHEMA app TO haltlab_rls, haltlab_cols;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO haltlab_rls;

-- haltlab_cols: exactly the policy's allowed columns (lab/policies/saas_shared.yaml).
-- tests/test_fixtures.py checks these lines against the policy.
REVOKE ALL ON ALL TABLES IN SCHEMA app FROM haltlab_cols;
GRANT SELECT ON app.currencies TO haltlab_cols;
GRANT SELECT (id, tenant_id, name, plan, created_at) ON app.orgs TO haltlab_cols;
GRANT SELECT (id, tenant_id, full_name, role, created_at, last_login_at) ON app.users TO haltlab_cols;
GRANT SELECT (id, tenant_id, name, country, created_at) ON app.customers TO haltlab_cols;
GRANT SELECT (id, tenant_id, customer_id, status, total_cents, currency, note, created_at) ON app.orders TO haltlab_cols;
GRANT SELECT (id, tenant_id, order_id, sku, description, quantity, unit_price_cents) ON app.order_items TO haltlab_cols;
GRANT SELECT (id, tenant_id, order_id, number, status, amount_cents, due_date, issued_at) ON app.invoices TO haltlab_cols;
GRANT SELECT (id, tenant_id, invoice_id, method, amount_cents, card_last4, paid_at) ON app.payments TO haltlab_cols;
GRANT SELECT (id, tenant_id, actor_user_id, action, detail, created_at) ON app.audit_events TO haltlab_cols;
