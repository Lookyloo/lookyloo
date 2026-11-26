# Actions panels (capture page)

The panels of the **Actions** menu of the capture page, opened in the side panel
([side-panel.md](side-panel.md)), styled like the Capture and Analysis ones
([capture-panels.md](capture-panels.md), [analysis-panels.md](analysis-panels.md)):
`panel_header()` ("Actions", title, description), sections, a submit bar at the
bottom (`.lk-panel-submit`, sticky). The cards of a panel, and of a form in it, are
spaced the same (`--lk-space-4`). The names of the form fields are the ones the
routes read: nothing changes on the server side.

| Panel | Template | What it is |
|---|---|---|
| Subsequent captures | `tree/modals/urls_rendered.html` | URLs to capture in the context of this capture (`bulk_captures`): typed URLs, and the URLs guessed during the redirects / found in the rendered page in a vitrine `<vt-table>` (search, sort, selection, copy buttons; `TABLES.subsequent`). The selected rows are sent as `guessed_url` / `url` (their index, built by `urls_rendered_page()`); the button is off until a URL is chosen. The errors are said in the panel instead of flashed. |
| Monitor capture | `tree/tree.html` `#monitoringModal` | The monitoring form (`monitoring_form()`), its submit at the bottom. The `<form>` is now **inside** the body: it was around the whole modal, and the side panel only takes the body, so nothing was sent. Same fix for `#emailModal` (Notify by email). |
| Manage categories | `tree/modals/categories_view.html` | The attached categories as MISP tags (links to the captures of the category), then every category of the taxonomy in a vitrine `<vt-table>` grouped by type: the category drawn as a MISP tag ([misp-tags.md](misp-tags.md)), its meaning; the attached ones selected at first. A capture can have several categories (the
backend keeps a set, the taxonomy is not exclusive), chosen one by one: no "select
all" (`data-lk-no-select-all`: the boxes of the header and the groups and the
selection menu are hidden, Ctrl/⌘+A is stopped). The selected rows are sent as `categories`. Admins replace the categories (unselect to remove), the other users only add. Replaces the DataTable whose script built the form with `innerHTML` (the risky sink listed in AGENTS.md). |
| Visibility and sharing | `tree/tree.html` `#visibilityModal` | The current visibility as a badge, the three choices (Public, Unlisted, Private) as cards with what they mean, the expiry of the seed (dimmed unless Private is chosen), the note about the administrators. |
| Push to MISP | `tree/modals/misp_push_view.html` | MISP 3 logo at the top left, the title of the event, the default tags of the instance (MISP tags, [misp-tags.md](misp-tags.md)), the favourite tags of the MISP user in a vitrine `<vt-tags>` (edit mode: type to search, pick, remove; the "Browse all tags" panel open at first, `data-lk-browse-open`; grouped by lane; the chosen tags drawn like MISP 3 tags through `::part(tag)` / `::part(tag-kind-<lane>)` with their MISP colours; `misp_tag_option` filter). The tags chosen are sent as one `tags` field each (`data-lk-tags-field`: vt-tags submits one JSON value, the route reads a list). Publish, also the parents. When the capture is already on the MISP: a warning with the link, and \"Push it anyway\" enables the button (`data-lk-force-push`; the inline `onchange` was blocked by the CSP). The reasons it cannot push are said in the panel. |
| Push to another Lookyloo | `tree/tree.html` `#lookylooPushModal` | The URL of the other instance and the Push button on one line, the eyes of the logo while it is sent. `web_lookyloo_push_view()` checks the address first and says what is wrong instead of the raw PyLookyloo error ("Expecting value..."): nothing answers there, or it is not the home page of a Lookyloo (a page of it, another tool). |

## Selection of a vitrine table sent with a form

`setupSelectForms()` in `js/capture_panels.js`: a `<vt-table data-lk-form-select="<field>" row-key="...">`
inside a form; the rows with `"selected": true` are selected at first; on submit,
each selected row adds a hidden field (`row.field` or the attribute value, with
`row.value`, or the key of the row, `row-key`, when it has no `value`); the tables
show 100 rows per page; `[data-lk-select-count]` says how many are chosen
(`data-lk-select-noun`), `[data-lk-select-chips]` shows the chosen rows above the table (as MISP tags when
the row has a `chip`), each with a × to unselect it (Manage categories);
`data-lk-select-required` keeps the button off until
something is chosen (rows or typed URLs).

## Forms being sent

`data-lk-busy="<text>"` on a form (pushes to Lookyloo and MISP, subsequent
captures, monitoring): on submit, the button is disabled and the eyes of the logo
(the loader template of the side panel) with the text are shown in its submit bar,
until the page answers (`js/capture_panels.js`).
