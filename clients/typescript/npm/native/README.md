# @haltsql/native-{{platform}}

Prebuilt [HaltSQL](https://github.com/HaltSQL/HaltSQL) engine for `{{platform}}`
({{libc_note}}). You do not install this package yourself: it is an optional
dependency of [`@haltsql/client`](https://www.npmjs.com/package/@haltsql/client),
and npm installs the one that matches your platform.

`LocalVerifier` from `@haltsql/client` finds it automatically and runs
`bin/haltsql` as one long-lived child process, so SQL is verified locally with
no sidecar:

```ts
import { LocalVerifier } from "@haltsql/client";
const haltsql = await LocalVerifier.create({ policyFile: "policy.yaml" });
const verdict = await haltsql.verify(sql, { tenant_id: session.tenantId });
```

Contents:

| Path | What |
|---|---|
| `bin/haltsql` | The `haltsql` CLI (`haltsql verify --policy FILE --batch` is what the client drives). |
| `lib/{{lib}}` | `libhaltsql`, the same engine as a C shared library (reserved for future in-process use). |
| `include/haltsql.h` | The C ABI of `libhaltsql`. |

Licensed under the MIT License (`LICENSE`, `NOTICE`); the bundled PostgreSQL
parser (libpg_query) is under its own license (`LICENSE.libpg_query`).
