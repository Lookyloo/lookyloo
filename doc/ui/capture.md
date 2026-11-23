# Capture form

Route `capture_web` (`/capture`), template `capture/capture.html`, styles
`static/css/capture.css`, script `static/js/capture.js`.

**Only the look changes**: every field keeps its `name`, its `id` and its
behaviour (tabs URL / document, multiple captures, operating system → browser →
user agent lists, devices, Lacus selection, monitoring, auto-report). The
backend (`capture_web()`) is not changed. When editing this page, check that the
submitted form is the same as before (same field names and values).

Layout: numbered sections (`<details class="lk-form-section">`: what to capture,
privacy, browser, advanced settings, capture engine, monitoring, auto-report)
and a sticky panel on the right with the list of the sections and the submit
button (sticky at the bottom of the screen on phones).

- `capture.js`: a link of the panel opens its section; a required field left
  empty in a closed section opens that section.
- The submit button shows the eyes loader while the form is sent
  (`data-lk-loading` on the form, `js/components/loader.js`).
- Callouts (logged-in user, warnings): `static/css/components/callout.css`
  (`lk-callout`, `lk-callout-info|warning|danger`).
