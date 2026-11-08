# Session capabilities (`session-capabilities/v1`)

The web UI asks once per page load what the person using it may do, and hides the controls and
links that would only end in a refusal. The open-source engine answers that everything is
allowed. A gateway in front of the engine (for example an authenticating deployment with roles)
answers the same request itself, for the signed-in person.

This is a presentation hint, never an authorization decision: the server that executes a request
still decides it, and a request the hint allowed can still be refused.

## Request

```
GET /session/capabilities
Accept: application/json
```

The UI sends it to its API origin with the same credentials as every other API request
(`credentials: 'include'` behind a same-origin gateway). It sends no body and no query.

## Response

`200 OK`, `Cache-Control: no-store`:

```json
{
  "schema_version": "session-capabilities/v1",
  "source": "engine",
  "role": null,
  "default": "allow",
  "actions": {
    "targets.add": true,
    "targets.edit": true,
    "targets.check": true,
    "scans.start": true,
    "findings.retest": true,
    "findings.verify": true,
    "findings.triage": true,
    "findings.accept_risk": true,
    "hunts.manage": true,
    "secrets.read": true,
    "secrets.manage": true,
    "secrets.decide": true
  },
  "pages": {},
  "reasons": {}
}
```

| Field | Meaning |
|---|---|
| `schema_version` | Always `session-capabilities/v1` for this contract. The UI ignores an answer with another value (and treats every control as allowed). |
| `source` | `engine` when the engine answered, `gateway` when a gateway did. Informational. |
| `role` | The person's role name when the answering side has roles (`viewer`, `operator`, `admin`), else `null`. Informational: the UI decides from `actions` and `pages`, never from the role name. |
| `default` | `allow` or `deny`: what an action or page that is not listed means. The engine answers `allow`. |
| `actions` | Action name → `true` (offer the control) or `false` (hide it). |
| `pages` | UI path prefix → `true` or `false`. A link whose path starts with a `false` prefix is shown as plain text, not a link; the longest matching prefix wins. |
| `reasons` | Optional. Action name or page prefix → one sentence a person can read (for example `this action needs the operator role`). The UI may show it where a hidden control would have been. |

### Actions

| Action | UI controls |
|---|---|
| `targets.add` | Targets: "Add targets"; Dashboard: "Add a target" |
| `targets.edit` | Targets list: "Restore", the target's instructions, "Authorize testing…" / "Revoke authorization", "Archive or delete…", the bulk "Authorize"; target page: "Rename", "Edit details", "Authorize asset", the target's instructions ("Create instructions"), "Edit learned knowledge", "Edit Hunt permissions", "Add action" and its edit/delete |
| `targets.check` | Target page: "Check now" (liveness) |
| `scans.start` | Targets list: "Scan" / "Discover", "Quick scan", "Customize Scan…", "Network scan", domain discovery, "Schedule scans", the bulk "Scan"; target page: "Configure web scan", "Network Hunt" and "Start network scan" (these two also need the `/devices` page); sidebar: "New Scan"; New Scan page: "Run Scan"; Dashboard: "Start a scan" |
| `findings.retest` | Finding page: "Retest" and its mode |
| `findings.verify` | Finding page: "Verify finding" |
| `findings.triage` | Finding page: the status select and the analyst verdict (shown read-only when `false`); Findings list: the selection dock's status actions |
| `findings.accept_risk` | Finding page: "Accept risk" |
| `hunts.manage` | Hunt page: "Stop" and "Delete" |
| `secrets.read` | Target page: the "Discovered secrets" cards (their list requests are not sent when `false`) |
| `secrets.manage` | Discovered secrets: "Revoke" / "Reactivate" and "Expiry" |
| `secrets.decide` | Discovered secrets: "Reveal", "Grant", "Ungrant" and "Promote" (the gateway may still ask for a step-up) |

A new UI control that changes state names one of these actions, or a new one added to this table.
An action the answer does not list follows `default`.

### Pages

Prefixes are UI paths, for example `/devices`, `/credentials`, `/scan/new`, `/schedules`. Only
links are affected: navigating to a denied page by address still shows whatever the answering
side serves there.

## Failure and absence

If the request fails, times out, answers anything but `200` with this `schema_version`, or the
deployment predates the endpoint, the UI treats every action and page as allowed, which is how it
behaved before this contract. A gateway that does not implement the endpoint may pass it through
to the engine, which answers "everything allowed".

## Example: a gateway answer for a viewer

```json
{
  "schema_version": "session-capabilities/v1",
  "source": "gateway",
  "role": "viewer",
  "default": "deny",
  "actions": {"secrets.read": false},
  "pages": {"/devices": false, "/credentials": false, "/scan/new": false, "/schedules": false},
  "reasons": {"targets.add": "this action needs the operator role"}
}
```
