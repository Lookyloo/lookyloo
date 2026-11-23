# Disabled pages

Some pages are switched off on every instance, for everyone (logged-in admins
included). The code and the templates stay in the repository: only the access
is closed.

Set `DISABLED_PAGES` in `website/web/__init__.py` (Flask endpoint names):

| Endpoint | URL | Page |
|----------|-----|------|
| `ressources` | `/ressources` | Explore > Resources |
| `cookies_lookup` | `/cookies` | Explore > Cookies |
| `favicons_lookup` | `/favicons` | Explore > Favicons |
| `hhhashes_lookup` | `/hhhashes` | Explore > HTTP headers hashes |
| `statsfull` | `/stats` | Admin > Statistics |

Why: these pages compute over every indexed capture on each load; on a large
instance they take far too long.

How it works:

- A `before_request` hook (`disabled_pages()`) answers **404** for these
  endpoints, with the usual "Page not found" page (JSON for API clients).
- The `page_enabled(endpoint)` Jinja global (also a Jinja test) hides the links:
  the Explore menu (gone when all its entries are off), the Statistics entry of
  the user menu, the pages of the full tour, and the "or from Explore > …" hints
  of the search page.
- The detail pages reached from a capture (`/cookies/<name>`, `/hhhdetails/…`,
  `/favicon_details/…`, …) are not affected.

To bring a page back, remove its endpoint from `DISABLED_PAGES`.
