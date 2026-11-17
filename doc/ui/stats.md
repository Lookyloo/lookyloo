# Statistics

Route `statsfull` (`/stats`, logged-in users), template `admin/stats.html`,
styles `static/css/stats.css`, chart `static/js/stats_graph.js` (D3). The data
is the one of `Lookyloo.get_stats()`, unchanged.

- **This week**: one card per metric (captures, redirects, unique URLs, unique
  domains), with the difference with last week.
- **Per year**: a chart of the captures per month (bars or curve, the choice is
  kept in the browser) and a table per month with a total.

The tables only hold aggregates (one row per month), so they stay small however
many captures the instance has: they are plain HTML tables, no DataTables. On
phones they scroll sideways inside their card.

**Disabled**: the page is switched off for now (`/stats` answers 404 and the
Statistics entry is hidden), it takes too long on a large instance. See
[disabled_pages.md](disabled_pages.md).
