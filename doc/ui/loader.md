# Loader

Loading indicator drawn like the eyes of the Lookyloo logo: broken rings that
turn, pupils that look around, a blink. It only appears after 400 ms, so fast
loads never flash it, and it stops moving with `prefers-reduced-motion`.

- Jinja: `{% from 'macros/loader.html' import loader %}` then
  `{{ loader('Loading the captures') }}`, sizes `sm`, `md`, `lg`, `xl`,
  `show_label=True` to show the text under the eyes.
- JavaScript: `lkLoader(label, size, showLabel)` in
  `static/js/components/loader.js` returns the same markup (label escaped).
- CSS: `static/css/components/loader.css`.

Both the macro and the CSS / JS are loaded by `layouts/page.html`. Used today
as the DataTables processing indicator (see [tables.md](tables.md)).
