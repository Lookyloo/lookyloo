# Monitoring page (admin)

`/admin/monitoring` (`admin_monitoring` in `website/web/__init__.py`,
template `admin/monitoring.html`, CSS `css/monitoring.css`),
logged-in users only, in the user menu: "Monitoring (ongoing captures)".

The web version of `tools/monitoring.py`. **Read only**: it only reads Redis keys
the backend already writes, never writes, cleans up or creates a key, and every
list is capped (200 captures, top 1000 entries of the day), so it is safe on an
instance with millions of captures. Reload the page to refresh.

## Ongoing captures, checked every 10 s

Rendered with the page, then `static/js/monitoring.js` requests
`GET /admin/monitoring/captures` every 10 s (countdown under the list, paused
while the tab is hidden, checked at once when it is shown again) and replaces
the list. The fragment carries the totals (`.lk-mon-totals` data-*) that
update the counter of the panel, its sub-title and the "Being captured" /
"Waiting" figures.

A capture in progress shows the eyes of the Lookyloo logo (`loader()` of
`macros/loader.html`, no 400 ms delay since it is redrawn every 10 s) and the
blue "Capturing" pill, first in the list; a waiting one an hourglass and the
amber "Queued" pill. While the browser works, a capture stays in `to_capture`:
only Lacus knows it is running, so the state comes from
`Lookyloo.get_capture_status()` (the same read as the waiting page of a capture),
for the first 50 waiting captures. No capture: the empty state, without eyes.

## Folded sections, loaded when opened

The status banner, the key figures and **Ongoing captures** are rendered with
the page. The other sections (Recent submissions, Services, Web requests today,
Tree cache and Lacus) are folded `<details>` (`folded()` in
`macros/monitoring.html`): nothing is read for them until they are opened.
Each time one is opened, `static/js/monitoring.js` requests
`GET /admin/monitoring/<section>` (`admin_monitoring_section`, login required,
`section` = `submissions` | `services` | `requests` | `cache`, anything else is a
404) and inserts the HTML fragment `admin/monitoring_section.html` (rendered and
escaped by Flask). The eyes loader shows while it loads; closing the section
aborts the request; an error is shown with `textContent`. Close and open again
to refresh a section.

| Section | Redis key (cache db) | Written by |
|---|---|---|
| Ongoing captures (being captured / waiting, priority, submitter) | `ongoing` (set), `to_capture` (zset), `<uuid>` hash (`url`, `document_name`), `<uuid>_mgmt`, status in Lacus (`get_capture_status`) | `async_capture`, `Lookyloo.enqueue_capture`, Lacus |
| Recent submissions per submitter | `queues` (zset `source\|authenticated\|user`: +1 when submitted, -1 when captured, expires 10 min after the last capture) | `enqueue_capture`, `async_capture` |
| Services | `running` + `service\|<name>` (db 1); dead PIDs are shown, not removed | `AbstractManager` |
| Web requests today per IP | `user_agents\|<today>` (one entry per IP + user agent, deleted daily) | `after_request` of the website, `background_processing` |
| Tree cache | `tree_cache` hash | each process |
| Lacus | `PyLacus.status()` / `is_busy()` (remote lacus only) | — |

Note: there is no per-IP *submission* counter in the backend; the per-IP table
counts web requests (all pages), the per-submitter table counts captures.

## Look

`css/monitoring.css`, only `--lk-*` tokens (light + dark), same building blocks
as the pivot pages and the tags:

- status banner: green when every service has a live process, amber when a
  service is down, none is registered, or a Lacus is busy;
- key figures: cards with a coloured top line and icon chip, tinted with the
  `--lk-tag-*` tokens (`.lk-mon-kpi.is-blue|amber|slate|violet|green|red`);
- panels: surface card, header with icon chip + title + counter pill;
- captures: state pill (`Capturing` pulses, off with `prefers-reduced-motion`,
  `Queued` amber), URL and UUID in mono, "Open" to the capture page;
- folded sections: the header is the `<summary>`, chevron turned when open,
  "Loaded at" line under the body;
- submissions: one `<meter>` bar per submitter (submitters at 0 are hidden);
- services: green / red dot, PIDs as mono chips, stale PIDs struck through;
- empty states like `.lk-pivot-empty`; stacked layout under 576 px.
