-- Schema and a little data for the local console stack. demo-traffic.sh runs
-- the queries haltsql-server allows against this database (verify, then execute),
-- which is how an agent uses HaltSQL. haltsql-server itself never connects here.
CREATE SCHEMA app;

CREATE TABLE app.currencies (code char(3) PRIMARY KEY, name text NOT NULL);
CREATE TABLE app.customers (
  id bigserial PRIMARY KEY, tenant_id text NOT NULL, name text NOT NULL,
  email text, phone text, country char(2), created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE app.orders (
  id bigserial PRIMARY KEY, tenant_id text NOT NULL, customer_id bigint REFERENCES app.customers,
  status text NOT NULL, total_cents bigint NOT NULL, currency char(3) REFERENCES app.currencies,
  created_at timestamptz NOT NULL DEFAULT now(), internal_notes text);
CREATE TABLE app.invoices (
  id bigserial PRIMARY KEY, tenant_id text NOT NULL, order_id bigint REFERENCES app.orders,
  amount_cents bigint NOT NULL, currency char(3) REFERENCES app.currencies,
  issued_at timestamptz NOT NULL DEFAULT now(), paid_at timestamptz);

INSERT INTO app.currencies VALUES ('USD', 'US dollar'), ('EUR', 'Euro');
INSERT INTO app.customers (tenant_id, name, email, phone, country) VALUES
  ('acme', 'Ada Lovelace', 'ada@acme.example', '+1-555-0100', 'US'),
  ('acme', 'Grace Hopper', 'grace@acme.example', '+1-555-0101', 'US'),
  ('globex', 'Hank Scorpio', 'hank@globex.example', '+1-555-0199', 'US');
INSERT INTO app.orders (tenant_id, customer_id, status, total_cents, currency) VALUES
  ('acme', 1, 'paid', 12500, 'USD'), ('acme', 2, 'open', 4200, 'USD'),
  ('globex', 3, 'paid', 990000, 'USD');
INSERT INTO app.invoices (tenant_id, order_id, amount_cents, currency, paid_at) VALUES
  ('acme', 1, 12500, 'USD', now()), ('globex', 3, 990000, 'USD', now());

-- The role an agent would use: read-only.
CREATE ROLE agent_ro NOLOGIN;
GRANT USAGE ON SCHEMA app TO agent_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO agent_ro;
