# AGENTS.md

Guidance for coding agents running or changing this repo. Read README.md first.

## What running this touches

- `repro/run.sh claims` makes one sign-in request (ROPC) to the Entra token endpoint for a lab user and decodes the access token locally. It creates and changes nothing in the tenant.
- It writes `repro/results/<date>-claims/` (gitignored): `run.log`, `summary.txt` and `claims.json`, which holds only `aud`, `scp`, `roles`, `groups` and `_claim_names`. The token itself is never saved.
- The user's password is read from the file named in `repro/env` (`TEST_USER_PASSWORD_FILE`) and sent on stdin, never as an argument. Sign-ins show up in the tenant's sign-in logs and can count toward lockout, so don't loop.
- Changing `groupMembershipClaims` or app role assignments, which this repo only describes, is a tenant change. Do it only when the operator asks, and say what you changed.

## Rules

- **Secrets.** Never print, log or commit tokens, client secrets, passwords or JWTs. When inspecting JSON from a CLI or API that may carry secrets, select known-safe fields (`jq '{id, name}'`, or `jq 'keys'` first); don't rely on deleting the field names you expect.
- **Tenant data stays out of git.** Keep deployment facts in gitignored files. Don't add tenant, app, user or group IDs, domains or customer names to tracked files; use placeholders (`<tenant id>`, `<api app id>`).
- **Only touch what you created.** Never delete or edit objects you didn't create; others may share the tenant.
- **Report what you observe.** A result counts only if a log or response shows it. If a claim comes from docs rather than a run (for example the 200-group overage limit), say so.
- **Token source.** Say which token you decoded (access or ID) and which app registration issued it. The two have different claims.

## Cleanup (always finish with this)

1. Delete `repro/results/` if it holds output you don't need.
2. Delete `repro/env` and any password file you created for the run.

## Changing the code

- Bash, `curl`, `jq` and `python3` only; no other dependencies.
- Keep the framework and dispatch sections of `repro/run.sh` as they are; change only the article-specific part. `bash -n repro/run.sh` must pass.
- If you change what the scenario expects, update the Findings in README.md with the new date and add a dated folder under the private evidence tree. Don't edit an old one.
- Run `kb lint .` before committing.
