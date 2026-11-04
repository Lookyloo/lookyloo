# Tables (DataTables)

On the pages extending `layouts/page.html`, every DataTable gets the same
controls, the capture tree keeps the default DataTables look.

- `static/js/components/datatables.js`: `DataTable.defaults.language`, loaded
  after the library and before the tables are created (`renderTables()` in
  `js/generic.js`, on `DOMContentLoaded`). The eyes loader as the processing
  indicator, "Filter" field without label, "10 per page", "1–10 of 45", arrows
  for the pagination. A table can still set its own texts in
  `js/render_tables.js` (`#IndexTable`: "Filter by title or URL").
- `static/css/components/datatables.css`: rows per page and filter field as
  pills, pagination buttons (current page in the accent colour, first / last
  hidden on phones), info text, ordering arrows.

Only the look changes: `paging`, `ordering` and `searching` stay as set per
table in `js/render_tables.js`. The ordering arrows are only shown on the
columns that could already be ordered.

The eyes loader itself: [loader.md](loader.md).
