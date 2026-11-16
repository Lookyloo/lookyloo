# Panels of the Capture menu

The entries of the **Capture** menu of the capture page open panels in the side
panel ([side-panel.md](side-panel.md)). They share one look: the pivot cards of
the site ([pivot-pages.md](pivot-pages.md)) in a compact version, and
[vitrine](vitrine.md) components for the data.

Files: `templates/macros/panel.html` (macros), `static/css/components/capture-panels.css`,
`static/js/capture_panels.js` (vitrine, set-up of the panels),
`templates/partials/capture_panels_assets.html` (CSS and script for the
standalone pages).

## Building blocks (`macros/panel.html`)

- `panel_header(kind, title, description, icon_name, share_url, from_popup, capture_url)`:
  header card (icon, kind, title, one sentence, actions passed with `{% call %}`).
  In the side panel it has **Open as a page** (`share_url`: the panel alone, in
  a new tab, a link to share); in that standalone page it has **Open the
  capture** instead.
- `panel_section(title, icon_name, count)`: a card with a title and a count.
- `panel_empty(title, text, icon_name)`: nothing to show.
- `.lk-panel-facts`: key / value grid. When the panel is narrow (container
  query, 640 px), the actions of the header go under its text.

## The panels

| Entry | Template | What it shows | Kept features |
|-------|----------|---------------|---------------|
| Details & statistics | `tree/tree.html` `#detailsModal` | Page (URL with copy, title, time, referer, seed expiry), **In numbers** (the statistics: `tree/modals/statistics.html?embedded=1`, loaded the first time the panel is shown, `data-lk-remote-part` / `setupRemoteParts()`; the tiles without the frame of `<vt-stats>`, `::part(container)`), Browser (user agent, meta, proxy), Categories as tags | `#start_time`, `#seed_expire_at` filled by the page script; a category links to the captures in it |
| (Statistics) | `tree/modals/statistics.html` | No menu entry any more: a section of Details & statistics. The panel itself still exists (`#statsModal`, tabs kept in a URL). |
| | | `<vt-stats>` tiles: hostnames, URLs, nodes, depth, cookies received / sent, sum of load times (duration, the raw value under it), total size (bytes) | the same 8 figures; a `<noscript>` list. `stats()` converts the load time to seconds |
| Storage state | `tree/modals/storage.html` | Tabs Cookies / Storage / WebAuthn credentials with counts. Cookies, local storage, OPFS and credentials in `<vt-table>`: every value in full (`wrap`: long text goes to the next line, never cut; `layout="table"`: no cards in a narrow panel), sort, search, filter row shown at first (`filters`), column chooser; no copy / download / fullscreen buttons in their header. A value that is JSON (object or array) is shown pretty-printed in a small `<vt-json>` (`jsonOrText` in `js/capture_panels.js`); one foldable card per origin; IndexedDB stores in `<vt-json>` | download of the full storage state; a cookie name opens the other captures with that name (`#cookieNameModal`, was missing on the page); number of captures per cookie; CHIPS partition key and its details; expiry as a date (Session when none); OPFS files downloaded as `<capture uuid>_<name>` |
| Console messages | `tree/modals/console_messages.html` | `<vt-log>`: one entry per message, the level from the console type, URL / line / column / type as fields, buttons per level with counts, search, copy, download; no fullscreen | time of each message; nothing lost from the former table |
| Downloads | `tree/modals/downloads.html` | One card per file: index, name, Download, Submit to Pandora | `downloadsTable` id kept on the list |
| Video | `tree/modals/video.html` | One card per video: name, Download, player | |
| Page screenshot | `tree/tree.html` `#screenshotModal` | Header with Unblur / Download, the image in a frame | blurred at first (`#blurScreenshot`, `#screenshot`, doc/ui/screenshot-blur.md); warning and cropped image when it is over 10 MB |
| MISP export | `tree/tree.html` `#mispExportModal` (new) | The eyes of the logo (`macros/loader.html`) while the export is generated, then the export in `<vt-json>` (tree / raw, search; no path bar), its size; Copy, Download, Export again | was a raw JSON link; loaded the first time the panel is shown, not with the page. Over 50 MiB: download only |

Rows of the tables and lines of the log are prepared by the views
(`storage_state()`: `cookie_rows`; `console_messages()`: `log_lines`) and put in
a `<script type="application/json">` right after the component;
`setupCapturePanels(root)` (`js/capture_panels.js`) gives them to the component
with the column definitions (`TABLES`). It runs on the page, and on each panel
loaded in the side panel (`setupContent()` in `js/side_panel.js`).

Links drawn inside a component (cookie names) carry `data-bs-toggle="modal"`:
`js/side_panel.js` finds them through `event.composedPath()` (the click target
seen from the page is the component itself).

## Standalone pages

`?from_popup=True` on the storage state, console messages, downloads and video
URLs renders the panel as a page of the site (`layouts/page.html`), with the
panel CSS and the vitrine module (`partials/capture_panels_assets.html`).

## Fixed on the way

- `#cookieNameModal` did not exist on the capture page: the cookie names of the
  storage state did nothing.
- The WebAuthn credentials table was never set up (`render_tables.js` set up the
  cookies table twice). The DataTables of these panels are gone.
- With no download / no video, the views passed `uuid=` instead of `tree_uuid=`.
- Duplicate `#statsModal` in `tree/tree.html`; `| safe` removed with the old
  storage template.

## Loading

While a panel is fetched, the side panel shows the eyes of the logo
(`macros/loader.html`, a `<template>` in `tree/side_panel.html` cloned by
`loading()` in `js/side_panel.js`); `css/components/loader.css` is loaded by the
capture page. Like everywhere on the site, the eyes appear after a short delay,
so a fast panel does not flicker.

## Double-click to copy

In every panel of the side panel (and in a detached window, and the "Open as a
page" versions), **a double-click on a value copies it**; a green "Copied"
bubble shows next to the mouse ("Copy failed" in red). `copyOnDoubleClick()` in
`js/capture_panels.js` finds the value from the innermost element clicked
(`event.composedPath()`, so inside the vitrine components too):

- a cell of a table: the whole cell; a JSON value in it: the whole JSON;
- console log: the time, one field value, or the message without its fields;
- a line of a JSON viewer (MISP export, IndexedDB): that line;
- our markup: a fact (`dd`), a file name, an origin, a title, a paragraph…

The whole value is copied, not the word the browser selected (the selection is
cleared). Links, buttons, tabs and form fields keep their own double-click.
The values that can be copied show the **copy cursor** (`css/components/capture-panels.css`):
our markup (facts, file names, origins, paragraphs, cells), and inside the
vitrine components through their CSS parts (`vt-table::part(cell)`,
`vt-log::part(time | message | field)`, `vt-json::part(body)`; a JSON shown in
a cell inherits it). Links, buttons, tabs, filter fields keep their own cursor.
