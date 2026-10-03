# moat-audit

Append-only local audit log for kernel decisions.

One SQLite database in WAL mode with a busy timeout, safe for several concurrent
`moat guard` processes. Every stored command and reason passes `redact()` first,
which removes bearer/basic credentials, `key=value` secrets, well-known token
shapes (GitHub, OpenAI, AWS, Slack, Google, npm, GitLab, JWT) and URL passwords.
Event ids are shown as hex (`moat show 1f`).

Schema changes bump `SCHEMA_VERSION` and ship a migration; a newer database than
the binary understands is refused rather than mis-read.
