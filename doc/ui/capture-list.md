# Capture list

The recent captures tables (`#IndexTable`): home page (`home/home.html`) and
recent / hidden / per category captures (`home/index.html`).

One row per capture: preview, title (link to the capture), initial URL with a
copy button, then either "No redirect" or the hostname trail
(`google.be › www.google.be › www.google.com`, an "Unencrypted hop" warning if
one URL is `http://`), and a folded redirect chain with a copy button per step
and the link to download the redirects. The time column shows "2 hours ago"
over the date and time, in the browser time zone.

## Front-end only

The rows are built in the browser, from the JSON returned by
`POST /tables/indexTable/` (`post_table()` in `website/web/__init__.py`), which
is not changed. Its `page.display` and `redirects.display` fields are HTML
rendered and escaped by Flask: `js/components/capture_list.js` parses them with
`DOMParser` (inert) to read the title, the URLs, the capture link and the
download link, then builds the row with DOM APIs (`textContent`, attributes).
Nothing else is shown: no category, no error flag, no screenshot, as the JSON
does not have them.

Search and paging stay server-side; the render function gives DataTables the
`filter` value of the JSON for the search.

## Files

| File | Role |
|------|------|
| `static/js/components/capture_list.js` | `lkIndexColumns(table)`: the DataTables columns of `#IndexTable`, row and time cells |
| `static/css/components/capture-list.css` | Table and row look |
| `static/js/components/capture_preview.js` | `lkCapturePreview(capture)`: the square at the left of a row |
| `static/css/components/capture-preview.css` | Its look |

The table needs `class="table lk-capture-table"` and
`data-lk-icons="{{ url_for('bootstrap.static', filename='icons/bootstrap-icons.svg') }}"`
(Bootstrap Icons sprite used by the row icons). `js/render_tables.js` uses
`lkIndexColumns()` when it is loaded (pages extending `layouts/page.html`),
the previous three columns otherwise.

## Preview: temporary identicon

Until the screenshots are shown (blurred, click to reveal), the preview is an
identicon like the GitHub avatars: a 5×5 symmetric pattern and a hue computed
from the hostname of the final page. Same site, same icon. The tones of the
hue are set in the CSS, for the light and the dark theme.

To show the screenshots instead, replace `lkCapturePreview()` and
`capture-preview.css`: the function gets `{url, finalUrl}` today, add the
capture UUID there when the thumbnail URL is needed. Nothing else changes.

## Home page: compact list

On the home page the same table has `data-lk-compact`: `js/render_tables.js`
removes every DataTables control (`layout` with all positions set to `null`):
the 10 latest captures, no paging, no "per page", no search. A "See all
captures" button under the list (and the link next to the title) opens the
full list (route `index`).
