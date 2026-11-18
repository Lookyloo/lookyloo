# Vitrine web components

[Vitrine](https://github.com/ecrou-exact/vitrine) is a library of web
components (JSON viewer, tables, stats, logs…). The website uses it in the
panels of the capture page (see [capture-panels.md](capture-panels.md)).

## Installation

Like every third-party file, it is **not in the repository**: `tools/3rdparty.py`
downloads the source of a pinned commit (`VITRINE_COMMIT`), checks its SHA-256
(`VITRINE_SHA256`) and builds it with Node >= 20 (`npm ci --ignore-scripts`,
`node scripts/build.js`). Only what the website needs is kept in
`static/vendor/vitrine/` (`esm/`, `languages/`, `syntax-themes/`, `vendor/`,
`vitrine.css`), with a `COMMIT` file. To update: change both constants, run the
script, regenerate the SRI hashes (`tools/generate_sri.py`).

## Loading

`static/js/capture_panels.js` is a module (SRI on the `<script type="module">`
tag; the chunks it imports come from the same origin, allowed by the CSP with
`strict-dynamic`). It imports `api.js` and the components it uses
(`vt-json`, `vt-table`, `vt-stats`, `vt-log`), tells vitrine where its files are
and follows the theme of the site: `theme` is set from `data-bs-theme` on
`<html>` and updated when it changes (`js/theme_toggle.js`).

## Theme

Add the class `lk-vitrine` to a `<vt-*>` element (`css/components/vitrine.css`):
its `--vt-*` design tokens are mapped to the `--lk-*` tokens of the site (they
cross the shadow DOM), so the components follow light and dark mode.

## Security

Vitrine inserts every value as text (never HTML). Data is given to the
components as JSON: in the element (`<vt-json>…</vt-json>`, `<vt-stats>`) or
in a `<script type="application/json">` next to it (`<vt-table>`, `<vt-log>`),
always through Jinja's `tojson`, which escapes `<`, `>` and `&`.
