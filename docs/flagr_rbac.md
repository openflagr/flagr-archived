# RBAC
For an overview of how Casbin works, as well as terminology used on this page, see the [Casbin docs](https://casbin.org/docs/en/how-it-works).

Enable Casbin enforcement with the `FLAGR_CASBIN_ENFORCEMENT_ENABLED` flag.  As this flag only controls enforcement, RBAC policies can still be modified via the policy and group APIs when it is disabled.

**Note:** A valid Casbin model file must be available to Flagr on the configured path to use enforcement or modify policies via the API.

To use Casbin, Flagr must be given a model file by setting `FLAGR_CASBIN_MODEL_PATH` with the location of the model file. Policies are created via [the Auth APIs](https://openflagr.github.io/flagr/api_docs/#tag/auth) and enforced on all requests that are not whitelisted. By default, *user info (subject), the URL (object), and the HTTP action (action)* will be passed in.

You can optionally configure Flagr to pass in a JWT claim as a fourth request field to Casbin.  To utilize this, set `FLAGR_CASBIN_PASS_JWT_CLAIMS_FIELD` to the name of the JWT claim.  For an example of using the `roles` claim in a model, see [the example below](#Read/Write/Admin-with-JWT-Roles).

## Recommended Model Examples
The following are example Models/Policies that Flagr users can base their rules on.

**Note:** The policies below are shown in CSV format.

### Read/Write
The first example supports Read/Write access. It simply filters based on the HTTP Method (ex. GET, PUT, POST, etc.), allowing everyone access to GET transactions and specified users access to other transactions.

In this case, we are not specifying any groups/roles, but adding policies for specific users (WriteUser1 and WriteUser2) to perform write actions.

**Model**
```
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (r.sub == p.sub || p.sub == "*") && keyMatch(r.obj, p.obj) && (r.act == p.act || p.act == "*")
```

**Policy**
```
p, *, *, GET
p, WriteUser1, *, *
p, WriteUser2, *, *
```

### Read/Write/Admin without JWT Roles
This example shows three groups/roles with Read/Write/Admin access. The roles are defined through Grouping Policies as:
* **ReadRole** - can perform any GET actions, except for the [Export APIs](https://openflagr.github.io/flagr/api_docs/#tag/export)
* **WriteRole** - can perform any actions except for
  * [Create Flag](https://openflagr.github.io/flagr/api_docs/#operation/createFlag)
  * [Delete Flag](https://openflagr.github.io/flagr/api_docs/#operation/deleteFlag)
  * [Restore Flag](https://openflagr.github.io/flagr/api_docs/#operation/restoreFlag)
  * [Export APIs](https://openflagr.github.io/flagr/api_docs/#tag/export)
  * The new Casbin Policy Management APIs listed above
* **AdminRole** - can perform any actions

There are no restrictions on which Flags users can update.

**Model**
```
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (g(r.sub, p.sub) && regexMatch(r.obj, p.obj) && regexMatch(r.act, p.act)) || g(r.sub, "AdminRole")
```

**Policy**
```
p, ReadRole, /(flags|tags|auth), GET

p, WriteRole, /(flags|tags|auth), GET
p, WriteRole, /flags/([0-9]+/*)$, PUT
p, WriteRole, /flags/[0-9]+/(variants|segments)/([0-9]+/*)$, PUT
p, WriteRole, /flags/[0-9]+/., POST|DELETE

g, User1, ReadRole
g, User2, WriteRole
g, User3, AdminRole
```

### Read/Write/Admin with JWT Roles
This example will provide the same access as the previous example but will use the `role` claim defined in the JWT rather than defining them through policies. To pass in the `role` JWT claim for Casbin to use, set `FLAGR_CASBIN_PASS_JWT_CLAIMS_FIELD` to `role`.

**Model**
```
[request_definition]
r = sub, obj, act, roles

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (p.sub in r.roles && regexMatch(r.obj, p.obj) && regexMatch(r.act, p.act)) || "AdminRole" in r.roles
```

**Policy**
```
p, ReadRole, /(flags|tags|auth), GET

p, WriteRole, /(flags|tags|auth), GET
p, WriteRole, /flags/([0-9]+/*)$, PUT
p, WriteRole, /flags/[0-9]+/(variants|segments)/([0-9]+/*)$, PUT
p, WriteRole, /flags/[0-9]+/., POST|DELETE
```