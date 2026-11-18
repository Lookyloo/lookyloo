"use strict";

// Pivot tables (investigate/*): rows like the list of the captures when
// js/components/capture_list.js is loaded, the plain columns otherwise.
function lkPivotColumnsOr(table, fallback) {
  return typeof lkPivotColumns === 'function' ? lkPivotColumns(table) : fallback;
}

function renderTables() {
  if (document.getElementById('IndexTable')) {
    let indexType = document.getElementById('IndexTable').dataset.indextype;
    new DataTable('#IndexTable', {
      processing: true,
      serverSide: true,
      retrieve: true,
      ordering: false,
      searching: true,
      drawCallback: function (settings) { newTabClickListener(); add_event_js_copy(); },
      order: [[ 1, "desc" ]],
      ajax: {
        url: `/tables/indexTable/${indexType}${window.location.search}`,
        type: 'POST',
      },
      // Capture list rows (js/components/capture_list.js) on the redesigned pages
      ...(typeof lkIndexColumns === 'function' ? {
        columns: lkIndexColumns(document.getElementById('IndexTable')),
        language: { searchPlaceholder: 'Filter by title or URL' },
        // Active category filter on the same row as "per page" and the search field
        layout: 'lkCompact' in document.getElementById('IndexTable').dataset
          // Home page: the 10 latest captures only, the full list is on the index page
          ? { topStart: null, topEnd: null, bottomStart: null, bottomEnd: null }
          : { topStart: ['pageLength', lkIndexFilter(document.getElementById('IndexTable').dataset.lkIcons)].filter(Boolean) },
      } : {
        columns : [
            { data: {_: 'page.display', filter: 'page.filter'}, width: '40%' },
            { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
            { data: {_: 'redirects.display', filter: 'redirects.filter'}, width: '40%' }
        ],
      }),
    })
  }
  if (document.getElementById('categoriesTable')) {
      new DataTable('#categoriesTable', {
        processing: true,
        retrieve: true,
        searching: true,
        drawCallback: function (settings) { newTabClickListener(); add_event_js_copy(); },
        pageLength: 25,
        ajax: {
            url: `/tables/categoriesTable/${window.location.search}`,
            type: 'POST',
            dataSrc:""
        },
        // Category tags (js/components/category_tag.js) on the redesigned pages
        ...(typeof lkCategoriesColumns === 'function' ? {
          order: [[ 2, "desc" ]],
          columns: lkCategoriesColumns(document.getElementById('categoriesTable')),
          language: { searchPlaceholder: 'Filter categories' },
        } : {
          order: [[ 1, "desc" ]],
          columns: [{ data: {_: 'category.display', filter: 'category.filter'}, width: '90%' },
                    { data: 'total_captures', width: '10%', orderable: true }],
        }),
      })
  }
  if (document.getElementById('HHHDetailsTable')) {
    let hhh = document.getElementById('HHHDetailsTable').dataset.hhh;
    new DataTable('#HHHDetailsTable', {
      processing: true,
      serverSide: true,
      retrieve: true,
      ordering: false,
      searching: true,
      drawCallback: function (settings) { newTabClickListener(); add_event_js_copy(); },
      ajax: {
          url: `/tables/HHHDetailsTable/${hhh}${window.location.search}`,
          type: 'POST'
      },
      columns: lkPivotColumnsOr(document.getElementById('HHHDetailsTable'), [
          { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
          { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
          { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
      ]),
    })
  }
  if (document.getElementById('bodyHashDetailsTable')) {
    let bodyhash = document.getElementById('bodyHashDetailsTable').dataset.bodyhash;
    new DataTable('#bodyHashDetailsTable', {
      processing: true,
      serverSide: true,
      retrieve: true,
      ordering: false,
      searching: true,
      drawCallback: function (settings) { newTabClickListener(); add_event_js_copy(); },
      ajax: {
          url: `/tables/bodyHashDetailsTable/${bodyhash}${window.location.search}`,
          type: 'POST'
      },
      columns: lkPivotColumnsOr(document.getElementById('bodyHashDetailsTable'), [
          { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
          { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
          { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
      ]),
    })
  }
  if (document.getElementById('hashTypeDetailsTable')) {
      let hash_value = document.getElementById('hashTypeDetailsTable').dataset.hashvalue;
      new DataTable('#hashTypeDetailsTable', {
        processing: true,
        serverSide: true,
        retrieve: true,
        ordering: false,
        searching: true,
        drawCallback: function (settings) { newTabClickListener(); add_event_js_copy(); },
        ajax: {
            url: `/tables/hashTypeDetailsTable/${hash_value}${window.location.search}`,
            type: 'POST'
        },
        columns: lkPivotColumnsOr(document.getElementById('hashTypeDetailsTable'), [
            { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
            { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
            { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
        ]),
      });
  }

  if (document.getElementById('identifierDetailsTable')) {
      let identifier_value = encodeURIComponent(document.getElementById('identifierDetailsTable').dataset.identifier);
      new DataTable('#identifierDetailsTable', {
        processing: true,
        serverSide: true,
        retrieve: true,
        ordering: false,
        searching: true,
        drawCallback: function (settings) { newTabClickListener(); add_event_js_copy(); },
        ajax: {
            url: `/tables/identifierDetailsTable/${identifier_value}${window.location.search}`,
            type: 'POST'
        },
        columns: lkPivotColumnsOr(document.getElementById('identifierDetailsTable'), [
            { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
            { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
            { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
        ]),
      });
  }
  if (document.getElementById('bodyHashesTable')) {
      let treeUUID = document.getElementById('bodyHashesTable').dataset.treeuuid;
      new DataTable('#bodyHashesTable', {
        processing: true,
        retrieve: true,
        searching: true,
        drawCallback: function (settings) {
            newTabClickListener(); add_event_js_copy();;
        },
        order: [[ 0, "desc" ]],
        ajax: {
            url: `/tables/bodyHashesTable/${treeUUID}${window.location.search}`,
            type: 'POST',
            dataSrc: ""
        },
        columns: [{ data: 'total_captures', width: '10%', orderable: false},
                  { data: {_: 'file_type.display', filter: 'file_type.filter'}, width: '10%' },
                  { data: {_: 'urls.display', filter: 'urls.filter'}, width: '60%', orderable: false },
                  { data: {_: 'sha512.display', filter: 'sha512.filter'}, width: '20%', orderable: false }],
      });
  }
  if (document.getElementById('faviconsTable')) {
      let treeUUID = document.getElementById('faviconsTable').dataset.treeuuid;
      new DataTable('#faviconsTable', {
        processing: true,
        retrieve: true,
        searching: true,
        drawCallback: function (settings) {
            newTabClickListener(); add_event_js_copy();;
            downloadFaviconListener();
        },
        order: [[ 0, "desc" ]],
        ajax: {
            url: `/tables/faviconsTable/${treeUUID}${window.location.search}`,
            type: 'POST',
            dataSrc: ""
        },
        columns: [{ data: 'total_captures', width: '10%' },
                  { data: {_: 'favicon.display', filter: 'favicon.filter'}, width: '40%', orderable: false },
                  { data: 'shodan_mmh3', width: '40%', orderable: false },
                  { data:  'download', width: '10%', orderable: false }],
      });
  }
  if (document.getElementById('cloudflareNSTable')) {
      let treeUUID = document.getElementById('cloudflareNSTable').dataset.treeuuid;
      new DataTable('#cloudflareNSTable', {
        processing: true,
        retrieve: true,
        searching: true,
        drawCallback: function (settings) {
            newTabClickListener(); add_event_js_copy();;
        },
        order: [[ 0, "desc" ]],
        ajax: {
            url: `/tables/cloudflareNSTable/${treeUUID}${window.location.search}`,
            type: 'POST',
            dataSrc: ""
        },
        columns: [{ data: 'total_captures', width: '10%' },
                  { data: {_: 'cloudflare_ns.display', filter: 'cloudflare_ns.filter'}, width: '40%' },
                  { data: {_: 'hostnames.display', filter: 'hostnames.filter'}, width: '50%', orderable: false }],
      });
  }
  if (document.getElementById('treeHashesTable')) {
      let treeUUID = document.getElementById('treeHashesTable').dataset.treeuuid;
      new DataTable('#treeHashesTable', {
        processing: true,
        retrieve: true,
        searching: true,
        drawCallback: function (settings) { newTabClickListener(); add_event_js_copy(); },
        order: [[ 0, "desc" ]],
        ajax: {
            url: `/tables/treeHashesTable/${treeUUID}${window.location.search}`,
            type: 'POST',
            dataSrc: ""
        },
        columns: [{ data: 'total_captures', width: '20%' },
                 { data: {_: 'capture_hash.display', 'filter': 'capture_hash.filter'}, width: '40%', orderable: false },
                 { data: 'hash_type', width: '40%', orderable: false }],
      });
  }
  if (document.getElementById('hostnamesTable')) {
      let treeUUID = document.getElementById('hostnamesTable').dataset.treeuuid;
      let hostname_table = new DataTable('#hostnamesTable', {
        processing: true,
        retrieve: true,
        searching: true,
        drawCallback: function (settings) {
            newTabClickListener(); add_event_js_copy();;
        },
        order: [[ 0, "desc" ]],
        ajax: {
            url: `/tables/hostnamesTable/${treeUUID}${window.location.search}`,
            type: 'POST',
            dataSrc: ""
        },
        columns: [{ data: 'total_captures', width: '10%' },
                  { data: {_: 'hostname.display', filter: 'hostname.filter'}, width: '30%', orderable: false },
                  { data: {_: 'ip.display', filter: 'ip.filter'}, width: '25%', orderable: false },
                  { data: {_: 'urls.display', filter: 'urls.filter'}, width: '35%', orderable: false }],
      });
  }
  if (document.getElementById('ipsTable')) {
      let treeUUID = document.getElementById('ipsTable').dataset.treeuuid;
      new DataTable('#ipsTable', {
        processing: true,
        retrieve: true,
        searching: true,
        drawCallback: function (settings) {
            newTabClickListener(); add_event_js_copy();;
        },
        order: [[ 0, "desc" ]],
        ajax: {
            url: `/tables/ipsTable/${treeUUID}${window.location.search}`,
            type: 'POST',
            dataSrc: ""
        },
        columns: [{ data: 'total_captures', width: '10%' },
                  { data: {_: 'ip.display', filter: 'ip.filter'}, width: '25%', orderable: false },
                  { data: {_: 'hostname.display', filter: 'hostname.filter'}, width: '30%', orderable: false },
                  { data: {_: 'urls.display', filter: 'urls.filter'}, width: '35%', orderable: false }],
      });
  }
  if (document.getElementById('identifiersTable')) {
      let treeUUID = document.getElementById('identifiersTable').dataset.treeuuid;
      new DataTable('#identifiersTable', {
        processing: true,
        retrieve: true,
        searching: true,
        drawCallback: function (settings) { newTabClickListener(); add_event_js_copy(); },
        order: [[ 0, "desc" ]],
        ajax: {
            url: `/tables/identifiersTable/${treeUUID}${window.location.search}`,
            type: 'POST',
            dataSrc: ""
        },
        columns: [{ data: 'total_captures', width: '20%', orderable: false },
                  { data: {_: 'identifier.display', filter: 'identifier.filter'}, width: '40%', orderable: false },
                  { data: 'identifier_type', width: '40%', orderable: false }],
      });
  }
  if (document.getElementById('urlsTable')) {
      let treeUUID = document.getElementById('urlsTable').dataset.treeuuid;
      new DataTable('#urlsTable', {
        processing: true,
        retrieve: true,
        searching: true,
        drawCallback: function (settings) { newTabClickListener(); add_event_js_copy(); },
        order: [[ 0, "desc" ]],
        ajax: {
            url: `/tables/urlsTable/${treeUUID}${window.location.search}`,
            type: 'POST',
            dataSrc:""
        },
        columns: [{ data: 'total_captures', width: '10%', orderable: false },
                  { data: {_: 'url.display', filter: 'url.filter'}, width: '90%', orderable: false }]
      })
  }
  if (document.getElementById('cookieNameTable')) {
      let cookieName = encodeURIComponent(document.getElementById('cookieNameTable').dataset.cookiename)
      new DataTable('#cookieNameTable', {
        processing: true,
        serverSide: true,
        retrieve: true,
        ordering: false,
        searching: true,
        drawCallback: function (settings) { newTabClickListener(); add_event_js_copy(); },
        ajax: {
            url: `/tables/cookieNameTable/${cookieName}${window.location.search}`,
            type: 'POST'
        },
        columns: lkPivotColumnsOr(document.getElementById('cookieNameTable'), [
            { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
            { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
            { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
        ]),
      });
  }

  if (document.getElementById('ipTable')) {
      let hostname = document.getElementById('ipTable').dataset.ip;
      new DataTable('#ipTable', {
        processing: true,
        serverSide: true,
        retrieve: true,
        ordering: false,
        searching: true,
        drawCallback: function (settings) { newTabClickListener(); add_event_js_copy(); },
        ajax: {
           url: `/tables/ipTable/${hostname}${window.location.search}`,
           type: 'POST'
        },
        columns: lkPivotColumnsOr(document.getElementById('ipTable'), [
           { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
           { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
           { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
        ]),
    });
  }

  if (document.getElementById('hostnameTable')) {
      let hostname = document.getElementById('hostnameTable').dataset.hostname;
      new DataTable('#hostnameTable', {
        processing: true,
        serverSide: true,
        retrieve: true,
        ordering: false,
        searching: true,
        drawCallback: function (settings) { newTabClickListener(); add_event_js_copy(); },
        ajax: {
           url: `/tables/hostnameTable/${hostname}${window.location.search}`,
           type: 'POST'
        },
        columns: lkPivotColumnsOr(document.getElementById('hostnameTable'), [
           { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
           { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
           { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
        ]),
    });
  }

  if (document.getElementById('domainTable')) {
      let domain = document.getElementById('domainTable').dataset.domain;
      new DataTable('#domainTable', {
        processing: true,
        serverSide: true,
        retrieve: true,
        ordering: false,
        searching: true,
        drawCallback: function (settings) { newTabClickListener(); add_event_js_copy(); },
        ajax: {
           url: `/tables/domainTable/${domain}${window.location.search}`,
           type: 'POST'
        },
        columns: lkPivotColumnsOr(document.getElementById('domainTable'), [
           { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
           { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
           { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
        ]),
    });
  }


  if (document.getElementById('tldTable')) {
      let tld = document.getElementById('tldTable').dataset.tld;
      new DataTable('#tldTable', {
        processing: true,
        serverSide: true,
        retrieve: true,
        ordering: false,
        searching: true,
        drawCallback: function (settings) { newTabClickListener(); add_event_js_copy(); },
        ajax: {
           url: `/tables/tldTable/${tld}${window.location.search}`,
           type: 'POST'
        },
        columns: lkPivotColumnsOr(document.getElementById('tldTable'), [
           { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
           { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
           { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
        ]),
    });
  }


  if (document.getElementById('urlTable')) {
      let url = document.getElementById('urlTable').dataset.url;
      new DataTable('#urlTable', {
        processing: true,
        serverSide: true,
        retrieve: true,
        ordering: false,
        searching: true,
        drawCallback: function (settings) { newTabClickListener(); add_event_js_copy(); },
        ajax: {
            url: `/tables/urlTable/${url}${window.location.search}`,
            type: 'POST'
        },
        columns: lkPivotColumnsOr(document.getElementById('urlTable'), [
            { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
            { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
            { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
        ]),
      });
  }

  if (document.getElementById('faviconDetailsTable')) {
      let favicon = document.getElementById('faviconDetailsTable').dataset.favicon;
      new DataTable('#faviconDetailsTable', {
        processing: true,
        serverSide: true,
        retrieve: true,
        ordering: false,
        searching: true,
        drawCallback: function (settings) { newTabClickListener(); add_event_js_copy(); },
        ajax: {
           url: `/tables/faviconDetailsTable/${favicon}${window.location.search}`,
           type: 'POST'
        },
        columns: lkPivotColumnsOr(document.getElementById('faviconDetailsTable'), [
           { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
           { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
           { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
        ]),
      });
  }
  if (document.getElementById('cloudflareNSDetailsTable')) {
      let cloudflarens = document.getElementById('cloudflareNSDetailsTable').dataset.cloudflarens;
      new DataTable('#cloudflareNSDetailsTable', {
        processing: true,
        serverSide: true,
        retrieve: true,
        ordering: false,
        searching: true,
        drawCallback: function (settings) { newTabClickListener(); add_event_js_copy(); },
        ajax: {
           url: `/tables/cloudflareNSDetailsTable/${cloudflarens}${window.location.search}`,
           type: 'POST'
        },
        columns: lkPivotColumnsOr(document.getElementById('cloudflareNSDetailsTable'), [
           { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
           { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '20%' },
           { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '30%' },
           { data: {_: 'hostnames.display', filter: 'hostnames.filter'}, width: '30%' }
        ]),
      });
  }
 //It is allowed to have more than one table on the same page
  if (document.getElementsByName('CIRCL_pdns_table')) {
      document.getElementsByName('CIRCL_pdns_table').forEach(function(table) {
        let query = table.dataset.query;
        new DataTable(`#${table.id}`, {
          processing: true,
          retrieve: true,
          ordering: true,
          searching: true,
          drawCallback: function (settings) { newTabClickListener(); add_event_js_copy(); },
          order: [[ 1, "desc" ]],
          language: { emptyTable: 'CIRCL Passive DNS has no record for this hostname.' },
          ajax: {
             url: `/tables/CIRCL_pdns_table/${query}${window.location.search}`,
             type: 'POST',
             dataSrc: "",
             data: {live: 'live' in table.dataset}
          },
          columns : [
             { data: 'time_first', width: '15%', render: DataTable.render.datetime_with_tz() },
             { data: 'time_last', width: '15%', render: DataTable.render.datetime_with_tz() },
             { data: 'rrtype', width: '10%' },
             { data: 'rdata', width: '20%' },
             { data: 'rrname', width: '40%' }
          ],
        });
      })
  }
  // Storage state and console messages (tree/modals/storage.html, console_messages.html):
  // vitrine <vt-table> / <vt-log>, set up by js/capture_panels.js
  // Categories of a capture (tree/modals/categories_view.html): plain checkboxes now,
  // set up by js/capture_panels.js (data-lk-categories)
};
