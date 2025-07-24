"use strict";

function renderTables() {
  if (document.getElementById('IndexTable')) {
    let indexType = document.getElementById('IndexTable').dataset.indextype;
    new DataTable('#IndexTable', {
      processing: true,
      retrieve: true,
      ordering: false,
      searching: true,
      pageLength: 50,
      order: [[ 1, "desc" ]],
      ajax: {
        url: `/tables/indexTable/${indexType}${window.location.search}`,
        type: 'POST',
        dataSrc:""
      },
      columns : [
          { data: {_: 'page.display', filter: 'page.filter'}, width: '40%' },
          { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
          { data: {_: 'redirects.display', filter: 'redirects.filter'}, width: '40%' }
      ],
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
      drawCallback: function (settings) { newTabClickListener() },
      ajax: {
          url: `/tables/HHHDetailsTable/${hhh}${window.location.search}`,
          type: 'POST'
      },
      columns : [
          { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
          { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
          { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
      ],
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
      drawCallback: function (settings) { newTabClickListener() },
      ajax: {
          url: `/tables/bodyHashDetailsTable/${bodyhash}${window.location.search}`,
          type: 'POST'
      },
      columns : [
          { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
          { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
          { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
      ],
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
        drawCallback: function (settings) { newTabClickListener() },
        ajax: {
            url: `/tables/hashTypeDetailsTable/${hash_value}${window.location.search}`,
            type: 'POST'
        },
        columns : [
            { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
            { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
            { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
        ],
      });
  }

  if (document.getElementById('identifierDetailsTable')) {
      let identifier_value = document.getElementById('identifierDetailsTable').dataset.identifier;
      new DataTable('#identifierDetailsTable', {
        processing: true,
        serverSide: true,
        retrieve: true,
        ordering: false,
        searching: true,
        drawCallback: function (settings) { newTabClickListener() },
        ajax: {
            url: `/tables/identifierDetailsTable/${identifier_value}${window.location.search}`,
            type: 'POST'
        },
        columns : [
            { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
            { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
            { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
        ],
      });
  }
  if (document.getElementById('bodyHashesTable')) {
      let treeUUID = document.getElementById('bodyHashesTable').dataset.treeuuid;
      new DataTable('#bodyHashesTable', {
        processing: true,
        retrieve: true,
        searching: true,
        drawCallback: function (settings) {
            newTabClickListener();
            $('[data-bs-toggle="tooltip"]').tooltip({html: true});
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
            newTabClickListener();
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
  if (document.getElementById('treeHashesTable')) {
      let treeUUID = document.getElementById('treeHashesTable').dataset.treeuuid;
      new DataTable('#treeHashesTable', {
        processing: true,
        retrieve: true,
        searching: true,
        drawCallback: function (settings) { newTabClickListener() },
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
      new DataTable('#hostnamesTable', {
        processing: true,
        retrieve: true,
        searching: true,
        drawCallback: function (settings) {
            newTabClickListener();
            $('[data-bs-toggle="tooltip"]').tooltip({html: true});
        },
        order: [[ 0, "desc" ]],
        ajax: {
            url: `/tables/hostnamesTable/${treeUUID}${window.location.search}`,
            type: 'POST',
            dataSrc: ""
        },
        columns: [{ data: 'total_captures', width: '10%' },
                  { data: {_: 'hostname.display', filter: 'hostname.filter'}, width: '30%', orderable: false },
                  { data: {_: 'ip.display', filter: 'ip.filter'}, width: '20%', orderable: false },
                  { data: {_: 'urls.display', filter: 'urls.filter'}, width: '40%', orderable: false }],
      });
  }
  if (document.getElementById('ipsTable')) {
      let treeUUID = document.getElementById('ipsTable').dataset.treeuuid;
      new DataTable('#ipsTable', {
        processing: true,
        retrieve: true,
        searching: true,
        drawCallback: function (settings) {
            newTabClickListener();
            $('[data-bs-toggle="tooltip"]').tooltip({html: true});
        },
        order: [[ 0, "desc" ]],
        ajax: {
            url: `/tables/ipsTable/${treeUUID}${window.location.search}`,
            type: 'POST',
            dataSrc: ""
        },
        columns: [{ data: 'total_captures', width: '10%' },
                  { data: {_: 'ip.display', filter: 'ip.filter'}, width: '20%', orderable: false },
                  { data: {_: 'hostname.display', filter: 'hostname.filter'}, width: '30%', orderable: false },
                  { data: {_: 'urls.display', filter: 'urls.filter'}, width: '40%', orderable: false }],
      });
  }
  if (document.getElementById('identifiersTable')) {
      let treeUUID = document.getElementById('identifiersTable').dataset.treeuuid;
      new DataTable('#identifiersTable', {
        processing: true,
        retrieve: true,
        searching: true,
        drawCallback: function (settings) { newTabClickListener() },
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
        drawCallback: function (settings) { newTabClickListener() },
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
      let cookieName = document.getElementById('cookieNameTable').dataset.cookiename;
      new DataTable('#cookieNameTable', {
        processing: true,
        serverSide: true,
        retrieve: true,
        ordering: false,
        searching: true,
        drawCallback: function (settings) { newTabClickListener() },
        ajax: {
            url: `/tables/cookieNameTable/${cookieName}${window.location.search}`,
            type: 'POST'
        },
        columns : [
            { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
            { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
            { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
        ],
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
        drawCallback: function (settings) { newTabClickListener() },
        ajax: {
           url: `/tables/ipTable/${hostname}${window.location.search}`,
           type: 'POST'
        },
        columns : [
           { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
           { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
           { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
        ],
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
        drawCallback: function (settings) { newTabClickListener() },
        ajax: {
           url: `/tables/hostnameTable/${hostname}${window.location.search}`,
           type: 'POST'
        },
        columns : [
           { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
           { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
           { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
        ],
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
        drawCallback: function (settings) { newTabClickListener() },
        ajax: {
           url: `/tables/tldTable/${tld}${window.location.search}`,
           type: 'POST'
        },
        columns : [
           { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
           { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
           { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
        ],
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
        drawCallback: function (settings) { newTabClickListener() },
        ajax: {
            url: `/tables/urlTable/${url}${window.location.search}`,
            type: 'POST'
        },
        columns : [
            { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
            { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
            { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
        ],
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
        drawCallback: function (settings) { newTabClickListener() },
        ajax: {
           url: `/tables/faviconDetailsTable/${favicon}${window.location.search}`,
           type: 'POST'
        },
        columns : [
           { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
           { data: {_: 'capture_title.display', filter: 'capture_title.filter'}, width: '40%' },
           { data: {_: 'landing_page.display', filter: 'landing_page.filter'}, width: '40%' }
        ],
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
          drawCallback: function (settings) { newTabClickListener() },
          order: [[ 1, "desc" ]],
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
  if (document.getElementById('storageStateCookiesTable')) {
      let cat_table = new DataTable('#storageStateCookiesTable', {
        retrieve: true,
        order: [[ 0, "desc" ]],
        pageLength: 25,
        columns: [
            {width: '7%'},
            {width: '15%'},
            {width: '20%'},
            {width: '12%'},
            {width: '13%'},
            {width: '10%', render: DataTable.render.datetime_with_tz()},
            {width: '5%'},
            {width: '5%'},
            {width: '6%'},
            {width: '5%'}
        ]
      });
  }
  if (document.getElementsByName('localStorageTable').length > 0) {
    let localStorageTables = document.getElementsByName("localStorageTable");
    Array.from(localStorageTables).forEach(function (localStorageTable) {
      let cat_table = new DataTable(`#${localStorageTable.id}`, {
        retrieve: true,
        order: [[ 0, "desc" ]],
        pageLength: 25,
        columns: [
            {width: '20%'},
            {width: '80%'}
        ]
      });
    });
  }
  if (document.getElementById('category_table')) {
      let cat_table = new DataTable('#category_table', {
        retrieve: true,
        drawCallback: function (settings) { newTabClickListener() },
        order: [[ 0, "desc" ]],
        pageLength: 25,
        lengthMenu: [25, 50, {label: 'All', value:-1} ],

        rowGroup: {
            dataSrc: [0],
        },
        columns: [{visible: false },
                  { width: '60%', orderable: false },
                  { width: '35%', orderable: false },
                  { width: '5%', orderable: false, render: DataTable.render.select()}],
        select: {
          style: 'multi',
          headerCheckbox: false,
        },
        layout: {
            topStart: {
                buttons: [
                  {
                    extend: 'selected',
                    text: 'Review categories',
                    action: function (e, dt, button, config) {
                        let counter = dt.rows( { selected: true } ).count()
                        let tags = dt.cells( dt.rows( { selected: true } ).nodes(), 2).data().toArray();
                        document.getElementById('categories_counter').innerText = counter;
                        let list = document.getElementById("categories_selected");
                        list.innerHTML = '';
                        tags.forEach((item) => {
                            let elt = document.createElement("div");
                            elt.className = "form-check";
                            elt.innerHTML = `<input class="form-check-input" type="checkbox" name="categories" value='${item}' checked hidden> <label class="form-check-label">${item}</label>`;
                            list.appendChild(elt);
                        });
                        document.getElementById('new_categories').style.display = 'block';
                    }
                  }
                ],
            }
        }
      });

      cat_table.rows('.selected').select();
      cat_table.on('user-select', function (e, dt, type, cell, originalEvent) {
          if (originalEvent.target.parentNode.classList.contains("unselectable") ||
              originalEvent.target.parentNode.parentNode.classList.contains("unselectable")) {
              e.preventDefault();
          }
      });
  }
};
