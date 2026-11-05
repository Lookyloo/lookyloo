"use strict";
// DataTables defaults for the pages extending layouts/page.html (loaded there,
// after the DataTables library, before the tables are created in js/generic.js).
// Only the look changes: paging, ordering and searching stay as set per table in
// js/render_tables.js. Styles: css/components/datatables.css.
// Doc: doc/ui/tables.md

Object.assign(DataTable.defaults.language, {
    // The eyes instead of the default animated dots (js/components/loader.js)
    processing: lkLoader('Loading', 'md', true),
    search: '',
    searchPlaceholder: 'Filter',
    lengthMenu: '_MENU_ per page',
    info: '_START_–_END_ of _TOTAL_',
    infoEmpty: 'Nothing to show',
    infoFiltered: '(filtered from _MAX_)',
    emptyTable: 'Nothing to show yet',
    zeroRecords: 'No match',
    paginate: {first: '«', previous: '‹', next: '›', last: '»'},
});
