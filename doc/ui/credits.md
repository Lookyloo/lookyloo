# Credits & licenses page

Route `credits` (`/credits`), template `about/credits.html` (styles
`static/css/credits.css`), linked from the footer ("Credits & licenses"). It
lists the open source projects the interface ships or relies on, with their
licenses: Lookyloo itself (Lookyloo, Lacus, har2tree), the front-end libraries
(Bootstrap, Bootstrap Icons, Bootstrap-Flask, jQuery, DataTables, D3,
jquery.json-viewer) and the main server components.

The page is meant to grow with the interface: **when adding a library, a font
or an icon set (`tools/3rdparty.py`), add it here** with the macro
`credit(name, role, license, url, license_url)` of the template, in the right
section, or a new `<section class="lk-card lk-credits-section">`. Check the
license against the package metadata, the npm registry or the license file.
