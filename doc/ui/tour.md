# Tutorial

A guided tour of the page, for beginners: the explained element is highlighted
(a hole in a dark veil) and a card explains it, with Previous / Next / Stop.
Every page extending `layouts/page.html` can have one. **The capture tree has
none** (it does not use `layouts/page.html`).

The "Tutorial" button of the site header (`#lk-tour-menu-btn`) offers:

- **Start the tour of this page** (disabled when the page has no tour);
- **Full tour of Lookyloo**: the pages of `#lk-tour-full-pages`, one after the
  other. That list is a hidden `<nav>` of links built with `url_for` in
  `partials/header.html`: the script clicks the next link, it never reads a URL
  from the page. Leaving the full tour for another page stops it.
  The list follows the rules of the menu: the Explore pages are only in it for
  logged-in users, and a disabled page (`page_enabled()`,
  [disabled_pages.md](disabled_pages.md)) never is, so the tour never goes to
  a page the visitor cannot see.

## Adding a tour to a page

```jinja
{% from 'macros/tour.html' import tour %}
{% block tour %}{{ tour([
  (None, "Title", "A step without element: a centred card."),
  ("#some-element", "Title", "Explains this element."),
  ("#menu-entry", "Title", "An entry of a menu, shown open.", "#menu-toggle"),
]) }}{% endblock %}
```

Steps whose element is missing or hidden are skipped (optional features,
logged-in only parts). The steps are a JSON data block, never executed.

Files: `static/js/components/tour.js`, `static/css/components/tour.css`,
`templates/macros/tour.html`.
