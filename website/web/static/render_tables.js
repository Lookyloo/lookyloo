["DOMContentLoaded", "shown.bs.modal"].forEach(e => window.addEventListener(e, function() {
  if (document.getElementById('IndexTable')) {
    indexType = document.getElementById('IndexTable').dataset.indextype;
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
          { data: 'page', width: '40%' },
          { data: 'capture_time', width: '20%', render: DataTable.render.datetime_with_tz() },
          { data: 'redirects', width: '40%' }
      ],
    })
  }
  if (document.getElementById('HHHDetailsTable')) {
    hhh = document.getElementById('HHHDetailsTable').dataset.hhh;
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
          { data: 'capture_title', width: '40%' },
          { data: 'landing_page', width: '40%' }
      ],
    })
  }
  if (document.getElementById('bodyHashDetailsTable')) {
    bodyhash = document.getElementById('bodyHashDetailsTable').dataset.bodyhash;
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
          { data: 'capture_title', width: '40%' },
          { data: 'landing_page', width: '40%' }
      ],
    })
  }
  if (document.getElementById('hashTypeDetailsTable')) {
      hash_value = document.getElementById('hashTypeDetailsTable').dataset.hashvalue;
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
            { data: 'capture_title', width: '40%' },
            { data: 'landing_page', width: '40%' }
        ],
      });
  }

  if (document.getElementById('identifierDetailsTable')) {
      identifier_value = document.getElementById('identifierDetailsTable').dataset.identifier;
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
            { data: 'capture_title', width: '40%' },
            { data: 'landing_page', width: '40%' }
        ],
      });
  }
  if (document.getElementById('bodyHashesTable')) {
      treeUUID = document.getElementById('bodyHashesTable').dataset.treeuuid;
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
                  { data: 'file_type', width: '10%' },
                  { data: 'urls', width: '60%', orderable: false },
                  { data: 'sha512', width: '20%', orderable: false }],
      });
  }
  if (document.getElementById('faviconsTable')) {
      treeUUID = document.getElementById('faviconsTable').dataset.treeuuid;
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
                  { data: 'favicon', width: '40%', orderable: false },
                  { data: 'shodan_mmh3', width: '40%', orderable: false },
                  { data:  'download', width: '10%', orderable: false }],
      });
  }
  if (document.getElementById('treeHashesTable')) {
      treeUUID = document.getElementById('treeHashesTable').dataset.treeuuid;
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
                 { data: 'capture_hash', width: '40%', orderable: false },
                 { data: 'hash_type', width: '40%', orderable: false }],
      });
  }
  if (document.getElementById('hostnamesTable')) {
      treeUUID = document.getElementById('hostnamesTable').dataset.treeuuid;
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
                  { data: 'hostname', width: '40%', orderable: false },
                  { data: 'urls', width: '50%', orderable: false }],
      });
  }
  if (document.getElementById('ipsTable')) {
      treeUUID = document.getElementById('ipsTable').dataset.treeuuid;
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
                  { data: 'ip', width: '40%', orderable: false },
                  { data: 'urls', width: '50%', orderable: false }],
      });
  }
  if (document.getElementById('identifiersTable')) {
      treeUUID = document.getElementById('identifiersTable').dataset.treeuuid;
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
                  { data: 'identifier', width: '40%', orderable: false },
                  { data: 'identifier_type', width: '40%', orderable: false }],
      });
  }
  if (document.getElementById('urlsTable')) {
      treeUUID = document.getElementById('urlsTable').dataset.treeuuid;
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
                  { data: 'url', width: '90%', orderable: false }]
      })
  }
  if (document.getElementById('cookieNameTable')) {
      cookieName = document.getElementById('cookieNameTable').dataset.cookiename;
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
            { data: 'capture_title', width: '40%' },
            { data: 'landing_page', width: '40%' }
        ],
      });
  }

  if (document.getElementById('ipTable')) {
      hostname = document.getElementById('ipTable').dataset.ip;
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
           { data: 'capture_title', width: '40%' },
           { data: 'landing_page', width: '40%' }
        ],
    });
  }

  if (document.getElementById('hostnameTable')) {
      hostname = document.getElementById('hostnameTable').dataset.hostname;
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
           { data: 'capture_title', width: '40%' },
           { data: 'landing_page', width: '40%' }
        ],
    });
  }

  if (document.getElementById('urlTable')) {
      url = document.getElementById('urlTable').dataset.url;
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
            { data: 'capture_title', width: '40%' },
            { data: 'landing_page', width: '40%' }
        ],
      });
  }

  if (document.getElementById('faviconDetailsTable')) {
      favicon = document.getElementById('faviconDetailsTable').dataset.favicon;
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
           { data: 'capture_title', width: '40%' },
           { data: 'landing_page', width: '40%' }
        ],
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
}));
