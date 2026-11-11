# UI extensions for a managed deployment

**Status:** maintained contract reference for `shakerscan.ui-extensions/v1`.

A managed deployment is a ShakerScan UI served behind a gateway that publishes a workspace policy
with the page (`window.__SHAKERSCAN_CAPABILITIES__`, schema
`shakerscan.workspace-capabilities/v1`, `mode: "managed"`). Such a deployment often has pages of
its own next to the UI: an account page, an administration page, a list the gateway keeps. This
contract lets it place those pages inside the UI instead of beside it:

- entries in the sidebar,
- pages of the deployment shown inside the UI's shell at `/ext/<id>`,
- panels in named places of the UI's own pages (today: the finding page),
- an account block at the foot of the sidebar (who is signed in, account links, sign out).

The UI does not know what any entry means. It draws what is declared, on its own origin only.

A standalone UI has no policy and therefore no extensions: nothing in this document changes it.
A managed policy without an `extensions` member is the UI exactly as it was.

## Finding out whether a UI reads the contract

`GET /api/build-identity` on the UI lists the optional contracts the build reads:

```json
{ "ui_version": "…", "source_revision": "…", "ui_contracts": ["shakerscan.ui-extensions/v1"] }
```

A build without `ui_contracts`, or without this name in it, ignores the block. Declaring it to
such a build is harmless; a deployment that keeps a fallback (for example its own floating menu)
uses this answer to decide which one to show.

## The block

The block is the `extensions` member of the managed workspace policy.

```json
{
  "schema": "shakerscan.ui-extensions/v1",
  "sections": [
    { "id": "follow-up", "label": "Follow-up", "after": "Review" }
  ],
  "pages": [
    { "id": "reports", "title": "Reports", "src": "/deployment/embed/reports" }
  ],
  "nav": [
    { "label": "Reports", "icon": "file-text", "page": "reports", "section": "follow-up" },
    { "label": "Calendar", "icon": "calendar", "href": "/deployment/calendar", "section": "Testing", "after": "/scans" }
  ],
  "slots": {
    "finding.detail": [
      { "id": "follow-up", "title": "Follow-up", "src": "/deployment/embed/finding/{finding_id}" }
    ]
  },
  "account": {
    "name": "Dana Example",
    "detail": "Operator",
    "links": [{ "label": "My account", "href": "/deployment/account" }],
    "sign_out": "/deployment/sign-out"
  }
}
```

Every member is optional. Unknown members are ignored. An entry that fails a check is dropped and
the rest of the block is still used. A block with another `schema` value is ignored whole.

### `sections`

New headings in the sidebar. `id` (`[a-z0-9-]`, 1 to 32 characters) is what `nav` entries name;
`label` is the heading shown; `after` is the existing heading the section follows (for example
`"Review"`). Without `after`, or when no heading has that name, the section goes last. A section
with no entries is not drawn. At most 4.

### `pages`

Pages of the deployment that the UI shows inside its own shell. Each has an `id`, a `title` and a
`src`, the same-origin path of the deployment page. The UI serves the page at `/ext/<id>` with its
sidebar, its page heading (`title`) and the tab title `<title> · ShakerScan`, and loads `src` in a
frame under the heading. At most 12.

`/ext/<id>` is a route of the UI like any other, so the workspace policy must allow it: a prefix
for `/ext` in `navigation`, mapped to an enabled feature, and the route in `ui_routes`. A route
the policy does not list is refused like any other route outside the workspace.

The query string of `/ext/<id>` is passed on to `src`, so a link can open the framed page at one
item: `/ext/reports?report=42` loads `/deployment/embed/reports?report=42`. A query longer than
2,048 characters is not passed.

### `nav`

Sidebar entries. Each has a `label`, an `icon` and exactly one destination:

- `page`: the `id` of a declared page. The entry links to `/ext/<id>`.
- `href`: a same-origin path of the deployment. The entry is a plain link that leaves the UI's
  shell (a full page load).

`section` is the heading the entry goes under: a declared section's `id`, or the name of one of
the UI's own headings. An entry whose section does not exist goes under a heading named "More".
`after` is the path of the UI's own entry it follows in that section (for example `"/scans"`);
without it the entry goes last. At most 12.

`icon` is one of: `bell`, `bug`, `calendar`, `calendar-clock`, `chart`, `clipboard-check`,
`clock`, `file-text`, `flag`, `gauge`, `globe`, `inbox`, `key`, `layers`, `link`, `list-checks`,
`puzzle`, `refresh`, `shield-check`, `tag`, `ticket`, `users`, `wrench`. Any other value, or
none, draws `puzzle`. Icons are chosen by name; a declaration cannot supply an image or markup.

### `slots`

Panels in named places of the UI's own pages. Each panel has an `id`, a `title` and a `src`; the
UI draws a card with the title, like the page's own cards, and loads `src` in a frame inside it.
At most 2 panels per slot.

| Slot | Where | Placeholders in `src` |
| --- | --- | --- |
| `finding.detail` | Finding page, top of the right-hand column | `{finding_id}` |

A placeholder is filled with an identifier the UI already holds, and only when that value is a
UUID. A `src` with any other `{name}` is dropped.

### `account`

Who is signed in. `name` is required; `detail` is one more line (a role, for example); `links`
are same-origin paths of the deployment (at most 6); `sign_out` is the same-origin path of the
deployment's sign-out page. The block is one row at the foot of the sidebar, and of the navigation
drawer on a narrow screen: the person's initial, the name and the detail (a detail that only
repeats the name is not printed). Pressing the row opens a panel above it with the links, Sign out
and the running version; Escape or a press elsewhere closes it. All of its links are plain links:
they leave the UI's shell. With nothing to open, the row is plain text.

A managed sidebar shows no link to another site: the website and source-code links of a standalone
install are not drawn.

The policy script that carries an account block is specific to one signed-in person. A deployment
that declares one serves the policy per session and with `Cache-Control: no-store`.

## What is checked

- **Text** (`label`, `title`, `name`, `detail`): a string of 1 to 60 characters after trimming,
  without control or direction-override characters. It is always rendered as text.
- **Paths** (`src`, `href`, `sign_out`, a link's `href`): at most 256 characters; starts with one
  `/`; only unreserved URL characters, the path and query delimiters and percent-encoding; no
  `//`, no `..` segment, and no encoded dot, slash or backslash in the path. Right before a path
  is used it is resolved against the page's own origin, and it is not used if it resolves
  anywhere else. A full URL, a protocol-relative URL, `javascript:` and `data:` are all refused.
- **Counts**: lists are cut at the limits above.
- **Ids**: `[a-z0-9-]`, 1 to 32 characters; a repeated id keeps the first entry.

These checks contain mistakes and keep the UI on its own origin. They are not a boundary against
the deployment: the gateway that serves the policy also serves the UI.

## What a framed page must do

A hosted page or a panel is an ordinary page of the deployment, loaded in a same-origin frame.

- **Allow the frame.** The page must be frameable by its own origin
  (`Content-Security-Policy: frame-ancestors 'self'`, and no `X-Frame-Options: DENY`). The UI's
  own pages keep `frame-ancestors 'none'`: nothing frames the UI.
- **No page title of its own.** The UI draws the heading (a hosted page) or the card title (a
  panel). The framed page starts with its content.
- **Share the UI's look.** The UI is dark only. The framed page declares `color-scheme: dark`,
  sets no background on its root (the frame is transparent, so the UI's surface shows through)
  and uses the UI's font and spacing.
- **Let its height follow its content.** The UI makes the frame as tall as the framed document
  and keeps the only scrollbar. The page must not size its root to the viewport (`100vh`,
  `height: 100%` on `html`), and should place dialogs in the document flow or scroll them into
  view rather than centring them on the viewport.
- **Mark links to the UI with `target="_top"`.** A `target="_top"` link to a route of the UI is
  opened by the UI without a reload. Any other link behaves as written: without a target it
  navigates inside the frame.
- **Handle a lost session.** When the session ends, the framed page shows its own sign-in notice
  or sends the top window to the sign-in page. The UI cannot tell an expired session from any
  other page.

The deployment's access rules are unchanged: the framed page is requested by the browser with the
person's own session, and the deployment decides what it shows. Declaring an entry grants nothing.
Declare only what the signed-in person can open.

## When a framed page cannot be shown

A frame that does not load within 20 seconds, is refused as a frame, or leaves the origin is
closed.

- A hosted page shows "*title* could not be shown." with a "Try again" button.
- A panel closes to one quiet line ("*title* is not available right now.") so the page's own
  cards keep their place.
- `/ext/<id>` for an id the block does not declare shows "This page is not part of this
  workspace." with a link back to the dashboard.

## Compatibility

The contract is additive within `v1`: new optional members, slots and icon names may be added,
and a UI ignores the ones it does not know. A change that an older UI could not safely ignore
gets a new schema name.
