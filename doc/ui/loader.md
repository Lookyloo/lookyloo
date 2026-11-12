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

## Waiting page of a capture

`tree/tree_wait.html` is shown by `/tree/<uuid>` while the capture is queued,
running or being processed (the `message` says which). It shows the eyes, the
current step, the link to the interactive session when there is one, and a
**Check now** button.

`static/js/tree_wait.js` reloads `/tree/<uuid>` after 10 seconds, counting the
seconds left inside the button (`[data-lk-countdown]`). While the tour is open
(`body.lk-tour-running`) it waits, and goes on once the tour is closed. Without
JavaScript, a `<noscript>` meta refresh does the same reload. Styles: `.lk-wait*`
in `static/css/components/loader.css`.
