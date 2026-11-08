"""(Re)create the dbt validation database from lab/schemas/saas_shared.sql.

Usage: python setup_db.py SCHEMA_SQL
Connection from DBT_PG_HOST/PORT/USER/PASSWORD; database DBT_PG_DBNAME
(default haltsql_dbt_lab). Uses psycopg2, which dbt-postgres installs.
Only the named database is dropped and recreated; nothing else is touched.
"""

import os
import re
import sys

import psycopg2

host = os.environ.get("DBT_PG_HOST", "127.0.0.1")
port = int(os.environ.get("DBT_PG_PORT", "5417"))
user = os.environ.get("DBT_PG_USER", "postgres")
password = os.environ.get("DBT_PG_PASSWORD", "haltlab")
dbname = os.environ.get("DBT_PG_DBNAME", "haltsql_dbt_lab")

if not re.fullmatch(r"[a-z_][a-z0-9_]*", dbname):
    sys.exit(f"refusing unsafe database name {dbname!r}")
if dbname in ("postgres", "template0", "template1"):
    sys.exit(f"refusing to recreate {dbname!r}")

admin = psycopg2.connect(host=host, port=port, user=user, password=password, dbname="postgres")
admin.autocommit = True
with admin.cursor() as cur:
    cur.execute(f"DROP DATABASE IF EXISTS {dbname} WITH (FORCE)")
    cur.execute(f"CREATE DATABASE {dbname}")
admin.close()

sql = open(sys.argv[1], encoding="utf-8").read()
conn = psycopg2.connect(host=host, port=port, user=user, password=password, dbname=dbname)
conn.autocommit = True
with conn.cursor() as cur:
    cur.execute(sql)
conn.close()
print(f"created database {dbname} from {os.path.basename(sys.argv[1])}")
