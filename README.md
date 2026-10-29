# aigw-entra-groups-claim-vs-roles

An Entra access token has no `groups` claim unless the API app registration enables it with `groupMembershipClaims`. Until then, a group assigned to an app role shows up only as that role in `roles`. With the claim enabled, a user in two groups gets both group IDs in the token. For gateway workspace mapping, use app roles and one distinct group per workspace.

> **Disclaimer:** Personal test notes. Not an official Microsoft or Palo Alto Networks statement, and no support. Behavior may change in later releases.

## How to recognize it

Decode the access token payload and check `roles`, `groups` and `_claim_names`.

| You see | Cause |
|---|---|
| `roles` is set, no `groups`, no `_claim_names` | The groups claim isn't enabled on the API app registration. |
| No `groups`, but `_claim_names.groups` is set | Group overage. The user is in more than 200 groups, so Entra drops the claim and expects a Microsoft Graph lookup. |
| `groups` lists fewer groups than the user is in | The claim is restricted. `ApplicationGroup` emits only groups assigned to the app, and `SecurityGroup` omits Microsoft 365 groups (use `All`). |

The access token's claims come from the API (resource) app named in `aud`, not the client app. The ID token is issued for the client app and has its own setting. It has no `roles` unless that app defines them.

## Workaround

Nothing to fix; this is configuration. Recommended design for workspace mapping:

1. **Use app roles, not groups.** Assign each group to an app role on the API's enterprise application and read `roles`. The claim holds only assigned roles, so it stays small and never overages. Microsoft recommends this for users in many groups (from its docs; not tested here).
2. **One distinct group per workspace.** A user should be in exactly one group that defines workspace membership. Don't make one user a member of two.
3. **If you read `groups`,** set `groupMembershipClaims` to `ApplicationGroup`. Emitting every security group bloats the token and risks overage.

## Re-run

Read-only. About 1 minute.

1. Prerequisites: `curl`, `jq`, `python3`. A lab tenant with an API app registration that exposes a scope, a public client app with "Allow public client flows" on, and a test user in the groups under test with no MFA or Conditional Access.
2. `cp repro/env.example repro/env` and fill it in, including the expected group and role counts. Put the password in a file and point to it.
3. `repro/run.sh check`
4. `repro/run.sh claims`
5. Read `repro/results/<date>-claims/summary.txt`. `PASS`: counts match. `CHANGED`: the token differs from what you expected; compare `claims.json` with `groupMembershipClaims` and the role assignments first. `ERROR`: sign-in failed; fix the environment, not the script.

For the baseline, run it against an API app with `groupMembershipClaims` unset and `EXPECT_GROUP_COUNT=0`.

## Mint a token by hand

To look at the claims yourself, this signs in a lab user with ROPC and prints the claims that matter. It saves no token. The user needs no MFA or Conditional Access, and the client app needs "Allow public client flows" on.

```bash
export TENANT_ID=<tenant id or verified domain>
export CLIENT_ID=<public client app id>
export API_APP_ID_URI=api://<api app id>
export USERNAME=<test user upn>
export PASSWORD_FILE=<path to a file holding only the password>

resp=$(tr -d '\r\n' < "$PASSWORD_FILE" | curl -s -X POST \
  "https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token" \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "username=${USERNAME}" \
  --data-urlencode "password@/dev/stdin" \
  --data-urlencode "scope=openid profile email ${API_APP_ID_URI}/.default")

echo "$resp" | jq -e '.error' >/dev/null && { echo "$resp" | jq -r '.error_description'; exit 1; }

echo "$resp" | jq -r '.access_token' | cut -d. -f2 | python3 -c '
import sys, base64, json
raw = sys.stdin.read().strip()
c = json.loads(base64.urlsafe_b64decode(raw + "=" * ((4 - len(raw) % 4) % 4)))
print(json.dumps({k: c.get(k) for k in ("aud", "azp", "scp", "roles", "groups", "_claim_names")}, indent=2))'
```

A key that isn't in the token prints as `null`. For the ID token, use `.id_token` instead of `.access_token`.

## Findings

Tested 2026-10-29 against the Entra v2.0 token endpoint (access tokens with `ver` 2.0), signing in a lab user with ROPC.

- **Groups claim not enabled:** a user in one group, assigned to a workspace app role, got `roles` with that role, no `groups` key and no `_claim_names`.
- **Groups claim enabled, one group:** `groups` held that group's ID and `roles` still held the role.
- **Second group added, with its own app role:** `groups` held both IDs and `roles` held both roles. The token did not stop at the first group.
- **Not reproduced:** a report that only the first of two groups appeared. The cause is unknown. Possible causes, none tested: the claim was restricted to assigned groups and only one was assigned; the user was in only one of the groups; the decoded token was the ID token or came from a different app registration.
- **Not tested:** gateway behavior for a user in two workspace groups, Mode A or B, overage, and the exact `groupMembershipClaims` value used.

Access token claims for the same user, IDs masked (`aud` is the API app, `azp` the public client, `scp` is `access_as_user` in all three):

Groups claim not enabled. Membership shows only as the role:

```json
{
  "aud": "<api app id>",
  "azp": "<client app id>",
  "preferred_username": "<user>@<lab domain>",
  "oid": "<user object id>",
  "roles": ["Portkey.Workspace.Finance"],
  "groups": null,
  "_claim_names": null
}
```

Groups claim enabled, user in one group:

```json
{
  "roles": ["Portkey.Workspace.Finance"],
  "groups": ["<finance group id>"],
  "_claim_names": null
}
```

Same user added to a second group that is assigned a second role:

```json
{
  "roles": ["Portkey.Workspace.Finance", "Portkey.Workspace.HR"],
  "groups": ["<finance group id>", "<hr group id>"],
  "_claim_names": null
}
```

(`null` here means the key was absent from the token; the `jq` summary prints a missing key as `null`.)

## License

MIT; see [LICENSE](LICENSE).
