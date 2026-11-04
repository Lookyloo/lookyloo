# Category tags

A category is shown as a coloured pill with an icon:
`content-classification:cybercrime="phishing"` → [bug] cybercrime · phishing.
Used today on the categories page (`explore/categories.html`, `#categoriesTable`):
tag (link to the captures of the category), machine tag, number of captures.

- `static/js/components/category_tag.js`: `lkCategoryTag(sprite, category, href)`
  and `lkCategoriesColumns(table)`, the DataTables columns of `#categoriesTable`.
- `static/css/components/tag.css`: the pill and the categories table.
- Tints: `--lk-tag-<tint>` / `--lk-tag-<tint>-bg` tokens in
  `static/css/components/site.css`, light and dark.

The family of the MISP taxonomy gives the tint and the icon
(`LK_CATEGORY_FAMILIES`): general (blue), technology and technical services
(teal), cybersecurity (green), cybercrime and illegal markets (red), markets and
finance (amber), communities (pink), digital content and geopolitics (violet).
Anything else is slate with a tag icon.

Front-end only: built from the JSON of `POST /tables/categoriesTable/`, not
changed. `category.display` (a link rendered and escaped by Flask) is parsed with
`DOMParser`, the values are written back with `textContent`. Ordering is kept on
the columns that had it (category, captures); the machine tag column is not
orderable.

## Category filter of the captures list

`/index?category=…` (`home/index.html`): the active category is shown with the
same tag, plus a cross that removes the filter, on the row of the table
controls (next to "per page", before the search field). The page renders a
plain chip (`#lk-index-filters`, `data-category`); `lkIndexFilter()` turns it
into the tag and `js/render_tables.js` places it with the DataTables `layout`
option (`topStart`).

On phones the categories table hides the machine tag column and the family of
the tags (kept in the tooltip).
