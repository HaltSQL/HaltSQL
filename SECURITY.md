# Security Policy

HaltSQL is a security control. A bug that lets a query through that the policy
should have denied is a vulnerability, and we treat it as one.

## Reporting a vulnerability

**Do not open a public issue, discussion, or pull request for a vulnerability
or a policy bypass.**

Report it privately through GitHub Security Advisories:

1. Go to <https://github.com/ardada2468/HaltSQL/security/advisories/new>.
2. Describe the problem. For a bypass, include:
   - the policy (minimized if possible),
   - the context JSON,
   - the exact SQL string,
   - the verdict HaltSQL returned and the verdict you expected,
   - the HaltSQL version (`haltsql version`) and how you ran it (library, CLI,
     or sidecar).
3. Submit. Only the maintainers can see the report.

If you cannot use GitHub Security Advisories, open a public issue that says only
"please contact me about a security issue" with no details, and a maintainer
will reach out.

## What to expect

| Step | Target |
|---|---|
| Acknowledge the report | within 3 business days |
| Initial assessment (confirmed, needs info, or not a vulnerability) | within 10 business days |
| Fix released for confirmed high or critical issues | as fast as practical, normally within 30 days |
| Public disclosure | when a fix is released, or 90 days after the report, whichever comes first |

We follow a **90-day coordinated disclosure policy**. We may agree with you on
a shorter or longer window if there is a good reason (for example, active
exploitation, or a fix that needs changes in libpg_query). We will credit you in
the advisory and the changelog unless you ask us not to.

Confirmed vulnerabilities get a GitHub Security Advisory and, where
appropriate, a CVE issued through GitHub. Every fixed bypass also gets a
regression case in the attack corpus (`test/corpus/`) so it cannot come back.

## Supported versions

HaltSQL is pre-1.0. Only the latest release receives security fixes.

| Version | Supported |
|---|---|
| 0.1.x (latest) | Yes |
| anything older | No |

After 1.0, the latest minor release and the current LTS line (if any) will be
supported.

## Scope

In scope:

- **Policy bypasses:** any SQL string that HaltSQL allows although the policy
  should deny it. Examples: reading a table, column, or function not in the
  policy; a tenant-scoped relation without a valid tenant predicate in its
  scope; a statement kind that is not allowed; a second statement; a
  data-modifying construct inside an allowed statement; a limit that is not
  enforced.
- **Fail-open behavior:** any input (SQL, policy, config, HTTP request) that
  causes HaltSQL to allow a query because of a crash, timeout, exception, or
  resource exhaustion, instead of denying it.
- **Policy and config loading:** a document that loads with a looser meaning
  than written (for example, an unknown key that is silently ignored, or a YAML
  value that changes type).
- **Sidecar:** authentication bypass, a token used with a policy it is not
  pinned to, secret leakage in logs, metrics, `config show`, or error messages,
  and denial of service from small requests.
- **Release integrity:** problems with published binaries, images, signatures,
  or SBOMs.

Out of scope:

- Attacks that require control of the context (tenant ID, user ID). The context
  must come from the host application's authenticated session; see
  [docs/threat-model.md](docs/threat-model.md).
- A policy that allows something dangerous because it was written to allow it
  (for example, allowing `pg_read_file` or `columns: "*"` on a sensitive
  table). Reports that point out confusing policy semantics are still welcome
  as normal issues.
- Prompt injection itself. HaltSQL judges the SQL, not the prompt.
- Data returned by an allowed query that is permitted by the policy.
- Vulnerabilities in PostgreSQL or libpg_query that do not affect HaltSQL's
  verdicts. Please report those upstream.
- Findings from automated scanners without a demonstrated impact.

## Safe harbor

We will not pursue legal action against anyone who reports in good faith,
follows this policy, avoids harm to other people's data and systems, and gives
us reasonable time to fix the issue before disclosure. Test against your own
deployments and data only.
