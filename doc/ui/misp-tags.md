# MISP tags

Tags are drawn the way the events index of MISP 3 draws them, wherever Lookyloo
shows MISP tags or machinetags (MISP hits, Push to MISP, the categories of a
capture), with their MISP colours.

- **Split** (server side, `misp_tag_view(name, colour)` / `_misp_tag()` in
  `website/web/__init__.py`, also a Jinja global): `{name, namespace, value, lane,
  colour, clear}`. Lanes: `markings` (tlp:*, pap:*: "tlp amber", `amber+strict`
  as `amber*`), `attribution` (galaxy clusters of actors, malware, tools),
  `behaviour` (ATT&CK techniques as their ID) and `classification` (the other
  tags: `circl:incident-classification="phishing"` gives the namespace
  `incident-classification` and the value `phishing`). The colour is kept only
  when it is a hex colour (it goes in a style attribute).
- **Jinja**: `macros/misp.html`, `misp_tag(tag)` and `misp_lane(tags, shown)`
  ("+N" shows the others).
- **JS**: `static/js/components/misp_tag.js`, loaded on every page by
  `layouts/main.html`: `lkMispTag(tag)` (the same look with inline styles on the
  `--lk-*` tokens, so it is right inside the vitrine tables too),
  `lkMispTagView(name, colour)` (the split in the browser) and
  `lkCategoryColour(name)` (the colours of the categories, given by main.html in
  `#lk-category-colours`). `js/capture_panels.js` uses it for its tables.
- **Where**: MISP hits, Push to MISP (default tags; the favourite tags in
  `<vt-tags>`, chosen tags through its parts, the options of its list and browse
  panel through a stylesheet in its shadow DOM; an observer rebuilds each label as
  MISP shows it, namespace small and grey, TLP / PAP as markings, with the full
  tag name as title; 4 tags per line at most in the browse panel), and every category: the capture
  bar of the tree (`tree/capture_bar.html`) and Capture > Details (links to the captures of the
  category), Actions > Manage categories, the categories page and the category
  filter of the list of the captures (`lkCategoryTag()` in
  `js/components/category_tag.js`, which replaces the former coloured pills).
- **CSS**: `.lk-misp-mk` (markings: colour as border and tint), `.lk-misp-chip`
  (`.is-tag`: the colour on the left; `.is-gx`: galaxy, violet; `.is-tid`:
  technique ID) in `css/components/capture-panels.css`; the galaxy colours are
  tokens of `css/components/site.css` (`--lk-misp-gx*`).

## Colours of the categories of Lookyloo

The taxonomy of the categories (`content-classification`) has no colours: they
are written in `website/web/category_colours.json`, one per type (`predicates`,
like the MISP taxonomies) and, for a few categories, their own (`entries`, by
machinetag). `category_colour(machinetag, predicate)` in `website/web/__init__.py`
reads them (cached); used by Actions > Manage categories (the table and the
attached categories).

Every tag has its full name as title (`lkMispTag`, `misp_tag`, the labels of
`<vt-tags>`), so a tag cut by the width of its column can still be read.
