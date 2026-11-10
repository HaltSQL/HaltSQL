-- The saas schema of the console e2e scratch database: the same app.orders table and
-- rows the integration packages' test fixtures create (their conftest SETUP).
CREATE SCHEMA app;
CREATE TABLE app.orders (id int8 PRIMARY KEY, tenant_id text NOT NULL, customer_id int8,
  status text, total_cents int8, currency text, created_at timestamptz DEFAULT now(),
  updated_at timestamptz);
INSERT INTO app.orders (id, tenant_id, customer_id, status, total_cents, currency) VALUES
  (1, 'acme', 10, 'open', 1250, 'USD'), (2, 'globex', 11, 'open', 990, 'EUR'),
  (3, 'acme', 12, 'paid', 4200, 'USD'), (4, 'globex', 13, 'paid', 100, 'EUR');
