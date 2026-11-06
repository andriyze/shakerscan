# Saved logins in a Hunt (sign in by reference)

**Status:** implemented in 2.12 (`api/hunt/saved_logins.py`).

A Hunt driven by a model holds no credential, and a login is a state-changing request a person
must allow. A *saved login* lets the model sign in without ever seeing the credential: a person
attaches an existing form or JSON login profile of the target to the Hunt, and the model sends
the login by reference.

## What counts as a saved login

An active `form_login` or `json_login` credential profile attached to the Hunt's target (its own
profile, or one shared to it with a credential grant) whose binding allows `http.request`. Its
login URL is the profile's endpoint (scheme, host, port and path).

## Attaching one

- **At start:** `saved_logins: [{"profile_id": "<id>", "max_logins": 3}]` on `POST /hunts`
  (`shakerscan hunt start --saved-login <id>[=<logins>]`). It needs `policy.active_testing`. The
  start is refused, before the Hunt exists, when a profile is not a saved login of the target or
  its login URL cannot be read under the Hunt's authorization. The MCP start tool drops the field:
  an agent never attaches a login itself.
- **Later:** the model binds an available saved login; the first call raises a `login.use`
  permission request (`shakerscan approve <id>`).
- **By a launch bound:** `login.use:<profile-id>` in the person's start bounds
  (`shakerscan agent --allow login.use:<id>`) attaches that saved login when each Hunt starts, with
  the default login count, and grants the first request of a Hunt that asks for it later. When every allowed login was used, the next one is a new request that only a person
  decides; no bound covers it.
- **Revoking** a `login.use` grant stops the next login at admission and in the worker; the start
  bound no longer answers for it.

## What the model sees

The Hunt read (`GET /hunts/{id}`), its briefing and `GET /hunts/{id}/permission-requests` carry
`saved_logins`: for each attached login its reference (`saved_login`, the profile id), version,
principal label, kind, login URL and logins left; for the target's other saved logins the
reference, label and kind only. Never a username or secret value.

## The login request

```json
{"method": "POST", "path": "/hub/login", "form_body": {"username": "", "password": ""},
 "request_bindings": [
   {"saved_login": "<id>", "credential_field": "username", "body_pointer": "/username"},
   {"saved_login": "<id>", "credential_field": "secret", "body_pointer": "/password"}],
 "capture": [{"name": "session", "header": "Set-Cookie"}]}
```

- POST to the login URL exactly (origin and path; the query may differ), with one saved login's
  username and secret bound into the body. It may also bind values this Hunt captured (a CSRF
  token); never another credential, a withheld value, a discovered secret, `as_principal` or
  `session_ref`.
- It needs the Hunt's active testing, not its state-changing permission, and is charged as an
  active HTTP action, not a state-changing request. Each admitted login is recorded in
  `hunt_credential_uses` (slot `login`) and counted against the attachment.
- The worker re-reads the live grant, the profile's current version and its login URL after
  decryption, and sends the values only there.

## What comes back, and where the secret never goes

- The login's answer is reduced to its status and cookie names (the request binds a credential).
  The session cookie it set is a capture reference, sent back only to the origin that set it.
- The secret is sealed with the action's encrypted private result as an *unreferenced* known
  value: in every later `http.request`, `artifact.inspect` and `javascript.analyze` output of the
  Hunt, and in every scanner action's observations (the public secrecy boundary), an echo of it in
  any case or HTML, JSON, URL or base64 encoding is masked, and it is never given a
  `withheld://` reference, so it cannot be sent anywhere else.
- Receipts, the Hunt record, permission requests and events hold ids and labels only. The raw
  login body exists only in the explicitly sensitive archive, marked private.

## Known limits

- A secret shorter than six characters is not masked in later pages (it would match ordinary
  text); the login's own answer is still reduced to its status.
- A form whose page and POST target differ (page `/login`, action `/session`) cannot be used as a
  saved login: the POST must go to the profile's endpoint path.
- The Enterprise gateway must pass `saved_logins` and the `login.use` bound through unchanged.
