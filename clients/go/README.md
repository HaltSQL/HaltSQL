# HaltSQL Go SDK

- [`haltsql/`](haltsql): the SDK, module `github.com/HaltSQL/HaltSQL/clients/go/haltsql`
  (standard library only).
- [`pgxtest/`](pgxtest): integration tests with `github.com/jackc/pgx/v5/stdlib` against
  Postgres, in a separate module so the SDK has no dependencies.

Guide: [docs/sdk-go.md](../../docs/sdk-go.md).

```sh
(cd haltsql && go vet ./... && go test -race ./...)
(cd pgxtest && go test ./...)   # skips without Postgres (make -C lab up)
```
