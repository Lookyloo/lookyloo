# Monitoring page (admin)

`/admin/monitoring` (`admin_monitoring` in `website/web/__init__.py`,
template `admin/monitoring.html`, CSS `css/monitoring.css` + `css/stats.css`),
logged-in users only, in the user menu: "Monitoring (ongoing captures)".

The web version of `tools/monitoring.py`. **Read only**: it only reads Redis keys
the backend already writes, never writes, cleans up or creates a key, and every
list is capped (200 captures, top 1000 entries of the day), so it is safe on an
instance with millions of captures. Reload the page to refresh.

| Section | Redis key (cache db) | Written by |
|---|---|---|
| Ongoing captures (being captured / waiting, priority, submitter) | `ongoing` (set), `to_capture` (zset), `<uuid>` hash (`url`, `document_name`), `<uuid>_mgmt` | `async_capture`, `Lookyloo.enqueue_capture` |
| Recent submissions per submitter | `queues` (zset `source\|authenticated\|user`: +1 when submitted, -1 when captured, expires 10 min after the last capture) | `enqueue_capture`, `async_capture` |
| Services | `running` + `service\|<name>` (db 1); dead PIDs are shown, not removed | `AbstractManager` |
| Web requests today per IP | `user_agents\|<today>` (one entry per IP + user agent, deleted daily) | `after_request` of the website, `background_processing` |
| Tree cache | `tree_cache` hash | each process |
| Lacus | `PyLacus.status()` / `is_busy()` (remote lacus only) | — |

Note: there is no per-IP *submission* counter in the backend; the per-IP table
counts web requests (all pages), the per-submitter table counts captures.
