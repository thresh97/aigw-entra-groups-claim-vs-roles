# aigw-entra-groups-claim-vs-roles

An Entra access token has no `groups` claim unless the API app registration enables it with `groupMembershipClaims`. Until then, a group assigned to an app role shows up only as that role in `roles`. With the claim enabled, a user in two groups gets both group IDs in the token. For gateway workspace mapping, use one app role per workspace and keep the groups that map to different workspaces from sharing members.

> **Disclaimer:** Personal test notes. Not an official Microsoft or Palo Alto Networks statement, and no support. Behavior may change in later releases.

## How user groups, app groups and roles relate

Three separate things decide what lands in the token:

| | Lives on | Changed by |
|---|---|---|
| **User's groups**: every group the user is in | the user, in the directory | group membership |
| **App's groups**: groups assigned to the API | the API's **enterprise application** | an app role assignment (a role, or default access) |
| **Roles and the claim setting** | the API's **app registration** | `appRoles`, `groupMembershipClaims` |

In the access token, which is issued for the API named in `aud`:

- **`roles`** holds the API's roles that the user holds, directly or through an app group. Only assigned roles appear, so it stays small however many groups the user is in.
- **`groups`** with `ApplicationGroup` holds the user's groups that are also app groups, and only where the user is a direct member ([docs](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles)). A group the app wasn't given never appears. With `SecurityGroup` or `All` it holds all of the user's groups, and can overage.

`roles` carries a name you chose; `groups` carries directory group IDs. Orgs that don't want the gateway to see directory group IDs use roles.

Example, observed in the lab on 2026-10-29: a user in `finance`, `hr` and `it`, where only `finance` (role `Portkey.Workspace.Finance`) and `hr` (role `Portkey.Workspace.HR`) are assigned to the API, with `ApplicationGroup`. The token's `roles` held both roles and `groups` held the finance and hr group IDs. The `it` group was absent.

### Get and set

```bash
API_APP_ID=<api app (client) id>      # the "aud" of the access token
API_SP_ID=$(az ad sp list --filter "appId eq '$API_APP_ID'" --query "[0].id" -o tsv)   # the enterprise application's object id
GRAPH=https://graph.microsoft.com/v1.0
USER_UPN=<user upn>

# App client ids and Application ID URI, by name (the client app's id is the token request's client_id and the token's azp)
az ad app list --display-name "<app name>" --query "[].{name:displayName, appId:appId, uri:identifierUris[0]}" -o table

# User's groups (includes nested)
az ad user get-member-groups --id "$USER_UPN" --query "[].{name:displayName, groupId:id}" -o table
USER_OID=$(az ad user show --id "$USER_UPN" --query id -o tsv)
az ad group member add    --group "<group name or id>" --member-id "$USER_OID"
az ad group member remove --group "<group name or id>" --member-id "$USER_OID"

# App's groups: get, assign to a role, remove (all-zero role id 00000000-0000-0000-0000-000000000000 = default access, no role in the token)
az rest --method GET --url "$GRAPH/servicePrincipals/$API_SP_ID/appRoleAssignedTo" \
  --query "value[].{principal:principalDisplayName, type:principalType, roleId:appRoleId, assignmentId:id}" -o table
GROUP_ID=$(az ad group show --group "<group name>" --query id -o tsv)
ROLE_ID=$(az ad app show --id "$API_APP_ID" --query "appRoles[?value=='<role value>'].id | [0]" -o tsv)
az rest --method POST --url "$GRAPH/servicePrincipals/$API_SP_ID/appRoleAssignedTo" \
  --body "{\"principalId\":\"$GROUP_ID\",\"resourceId\":\"$API_SP_ID\",\"appRoleId\":\"$ROLE_ID\"}"
az rest --method DELETE --url "$GRAPH/servicePrincipals/$API_SP_ID/appRoleAssignedTo/<assignmentId>"

# Claim setting: get, set (None | SecurityGroup | ApplicationGroup | DirectoryRole | All)
az ad app show --id "$API_APP_ID" --query groupMembershipClaims -o tsv
az ad app update --id "$API_APP_ID" --set groupMembershipClaims=ApplicationGroup
```

Then sign in again and decode the token with [Mint a token by hand](#mint-a-token-by-hand). A token already issued keeps its old claims until it expires. The role's `allowedMemberTypes` must include `User` for a group to hold it, and assigning a group needs Entra ID P1 or higher. Graph: [create](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-post-approleassignedto), [list](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignedto) and [delete](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-delete-approleassignedto) appRoleAssignedTo.

## How to recognize it

Decode the access token payload and check `roles`, `groups` and `_claim_names`.

| You see | Cause |
|---|---|
| `roles` is set, no `groups`, no `_claim_names` | The groups claim isn't enabled on the API app registration. |
| No `groups`, but `_claim_names.groups` is set | [Group overage](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles). The user is in more than 200 groups, so Entra drops the claim and expects a Microsoft Graph lookup. |
| `groups` lists fewer groups than the user is in | The claim is restricted. `ApplicationGroup` emits only groups assigned to the app, and `SecurityGroup` omits Microsoft 365 groups (use `All`). |

The access token's claims ([reference](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference)) come from the API (resource) app named in `aud`, not the client app. The ID token is issued for the client app and has its own setting. It has no `roles` unless that app defines them.

## Workaround

Nothing to fix; this is configuration. Recommended design for workspace mapping:

1. **Use app roles, not groups.** Assign each group to an app role on the API's enterprise application and read `roles`. The claim holds only assigned roles, so it stays small and never overages. Microsoft offers this as the way around group overage ([docs](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles)); the overage case itself was not tested here.
2. **Distinct members per workspace.** Several groups can map to one workspace (`groupa1` and `groupa2` to workspace A, `groupb1` and `groupb2` to workspace B), by assigning them all to that workspace's role. No user should be in groups that map to different workspaces. Entra doesn't enforce this, and a user who breaks it gets both workspaces' roles in `roles`.
3. **If you read `groups`,** set [`groupMembershipClaims`](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims) to `ApplicationGroup`. Emitting every security group bloats the token and risks overage.

## Limit which roles are in the token

The `roles` claim lists the app roles of the API in `aud` that the user holds, directly or through a group assigned to the role. Roles of other apps never appear, and there is no per-request filter. So you limit the roles by controlling what the API's registration defines and what is assigned on its enterprise application. This section is from Microsoft's documentation ([app roles and the `roles` claim](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps), [group claims vs app roles](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles)) and the `az` help; the commands below are not run against a tenant here (see Findings). The variables are set under [Get and set](#get-and-set).

**1. See which roles the API defines.**

```bash
az ad app show --id "$API_APP_ID" \
  --query "appRoles[].{id:id, value:value, enabled:isEnabled, types:allowedMemberTypes}" -o table
```

**2. Define only the roles the gateway needs.** [`az ad app update --app-roles`](https://learn.microsoft.com/en-us/cli/azure/ad/app#az-ad-app-update) replaces the whole list, so edit the current one. Disable a role first, then remove it in a second update (the docs say to apply the disable before deleting). Disabling alone does not stop the role being issued: per the [docs](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps), a disabled role can't be assigned any more, but existing assignments remain and the role keeps appearing in tokens until those assignments are removed. Remove the assignments (step 4) to take it out of tokens.

```bash
az ad app show --id "$API_APP_ID" --query appRoles -o json \
  | jq 'map(if .value == "Portkey.Workspace.HR" then .isEnabled = false else . end)' > roles.json
az ad app update --id "$API_APP_ID" --app-roles @roles.json

jq 'map(select(.value != "Portkey.Workspace.HR"))' roles.json > roles-trimmed.json
az ad app update --id "$API_APP_ID" --app-roles @roles-trimmed.json
```

**3. [Require assignment](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal)**, so a user or group with no assignment can't get a token for the API at all.

```bash
az rest --method PATCH --url "$GRAPH/servicePrincipals/$API_SP_ID" \
  --body '{"appRoleAssignmentRequired": true}'
```

**4. Assign each group to exactly one role, and review or remove assignments.** The commands are under [Get and set](#get-and-set), "App's groups".

**5. Check the token** with [Mint a token by hand](#mint-a-token-by-hand).

Things that surprise people:

- A group assigned to a role gives the role only to its direct members. Members of nested groups don't get it. The [docs](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal) say "The assignment doesn't cascade to nested groups" and "Nested group memberships aren't currently supported", and the `ApplicationGroup` option doesn't support indirect membership either. Tested 2026-10-29 with assignment required: a user who was only a nested member was refused at sign-in (see Findings).
- A role that is defined but assigned to none of the user's groups isn't in the token, so extra defined roles are harmless to a given user. Extra assignments are what widen the token.
- For client-credentials tokens (no user), `roles` comes from the client's own assignments on the API's enterprise application, not from groups.

## Re-run

Read-only. About 1 minute.

1. Prerequisites: `curl`, `jq`, `python3`, and for the `membership` scenario `az` logged in to the same tenant. A lab tenant with an API app registration that exposes a scope, a public client app with "Allow public client flows" on, and a test user in the groups under test with no MFA or Conditional Access.
2. `cp repro/env.example repro/env` and fill it in, including the expected group and role counts. Put the password in a file and point to it.
3. `repro/run.sh check`
4. `repro/run.sh claims` checks the token against the expected counts. `repro/run.sh membership` also reads the user's memberships with `az` (read-only) and checks that the user is in more groups than the token carries, and that every `groups` entry is a real membership. For it, put the user in a group that is not assigned to the API app, set `EXPECT_MEMBER_GROUP_COUNT`, and set `groupMembershipClaims` to `ApplicationGroup`. The count includes nested groups.
5. Read `repro/results/<date>-<scenario>/summary.txt`. `PASS`: counts match. `CHANGED`: the token differs from what you expected; compare `claims.json` with `groupMembershipClaims` and the role assignments first. `ERROR`: sign-in failed; fix the environment, not the script.

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
- **Not tested:** gateway behavior for a user in two workspace groups, Mode A or B, and the exact `groupMembershipClaims` value used when the peer saw one group.

Tested 2026-10-29 with `groupMembershipClaims` set to `ApplicationGroup` and assignment required (`repro/run.sh membership`):

- **User in three groups, two assigned to the API:** `groups` held the two assigned group IDs, `roles` held both roles, the third group was absent, no overage marker. Every `groups` entry was a real membership of the user.
- **Two groups assigned to the same role, plus a third unassigned group:** `groups` held the two assigned groups, `roles` held that role once, not twice.
- **Nested group:** a user whose only link to an assigned group was through a child group could not sign in. The token endpoint refused with `AADSTS50105`: the user "is blocked because they are not a direct member of a group with access, nor had access directly assigned". With assignment required, the refusal came before any claims were issued, so what a token would have held was not observed. The assignment docs say nested membership isn't supported (see "Things that surprise people").
- **Docs checked 2026-10-29** (Microsoft Learn), read but not tested here:
  - Nested groups aren't supported for assignment, group-based assignment needs Entra ID P1 or higher, and the default app role ID is the all-zero GUID: [Manage users and groups assignment to an application](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal).
  - `ApplicationGroup` includes a group only when it is assigned to the enterprise app and the user is a direct member; above 200 groups the `groups` claim is replaced by an overage marker; app roles avoid overage: [Configure group claims and app roles in tokens](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles).
  - `ApplicationGroup` is a valid `groupMembershipClaims` value and includes only groups assigned to the application: [Configure optional claims](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims).
  - In v2.0 tokens `aud` is the API's client ID, and for user tokens `roles` holds the user's assigned roles on the target app: [Access token claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference).
  - A disabled app role keeps appearing in tokens while assignments to it remain, and a role must be disabled before it is deleted: [Add app roles and get them from a token](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps).
  - The Graph calls under "Get and set": [grant](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-post-approleassignedto), [list](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignedto) and [delete](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-delete-approleassignedto) appRoleAssignedTo. The list page warns of replication delays for recently granted or removed assignments.
- **Not tested:** the overage case (more than 200 groups), default access (all-zero role ID) giving no role in the token, a disabled role, client-credentials `roles`, and the commands in "Limit which roles are in the token" (only the `az ad app update --app-roles` flag was checked against `az` 2.91 help).

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

## Example: a token with app roles and app groups

One user, three groups, an API with two workspace roles, `groupMembershipClaims` set to `ApplicationGroup`. Observed in the lab on 2026-10-29 (IDs masked). Background: [app roles and the `roles` claim](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps), [groups assigned to the application](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles), [access token claims](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference).

| Step | State |
|---|---|
| User's groups | `finance`, `hr`, `it` |
| API app registration | roles `Portkey.Workspace.Finance` and `Portkey.Workspace.HR`; `groupMembershipClaims` = `ApplicationGroup` |
| API enterprise application, assignments | `finance` to `Portkey.Workspace.Finance`, `hr` to `Portkey.Workspace.HR`. `it` is not assigned. Assignment is required. |

The access token for the API (`aud`), after the user signs in again:

```json
{
  "aud": "<api app id>",
  "scp": "access_as_user",
  "roles": ["Portkey.Workspace.Finance", "Portkey.Workspace.HR"],
  "groups": ["<finance group id>", "<hr group id>"]
}
```

How each claim got there:

- `roles` has both roles because the user is a direct member of two groups that each hold one. `it` holds none, so it adds nothing.
- `groups` has the finance and hr IDs because those two groups are assigned to the API. `it` is a real membership but is not assigned, so it is left out.
- There is no `_claim_names`, because the token carries two groups, far below the 200-group overage limit.

A gateway that maps `roles` to workspaces sees `Finance` and `HR` here. If the two roles belong to different workspaces, this user is in both workspaces' groups, which the [Workaround](#workaround) says to avoid. To keep the user in one workspace, remove them from one of the two groups and sign in again for a new token. The removal case was not run here; only adding a group was.

## License

MIT; see [LICENSE](LICENSE).
