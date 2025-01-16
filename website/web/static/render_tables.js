["DOMContentLoaded", "shown.bs.modal", "jquery.modal.rendered"].forEach(e => window.addEventListener(e, function() {
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
        searching: false,  // Needs to implement that serverside
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
        searching: false,  // Needs to implement that serverside
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
      new DataTable('#bodyHashesTable', {
        retrieve: true,
        drawCallback: function (settings) {
            newTabClickListener();
            $('[data-bs-toggle="tooltip"]').tooltip({html: true});
        },
        order: [[ 0, "desc" ]],
        columns: [{ width: '10%' },
                  { width: '10%' },
                  { width: '60%', orderable: false },
                  { width: '20%', orderable: false }],
      });
  }
  if (document.getElementById('faviconsTable')) {
      new DataTable('#faviconsTable', {
        retrieve: true,
        drawCallback: function (settings) {
            newTabClickListener();
            downloadFaviconListener();
        },
        order: [[ 0, "desc" ]],
        columns: [{ width: '10%' },
                  { width: '40%', orderable: false },
                  { width: '40%', orderable: false },
                  { width: '10%', orderable: false }],
      });
  }
  if (document.getElementById('treeHashesTable')) {
      new DataTable('#treeHashesTable', {
        retrieve: true,
        order: [[ 0, "desc" ]],
        drawCallback: function (settings) { newTabClickListener() },
        column: [{ width: '20%' },
                 { width: '40%', orderable: false},
                 { width: '40%' }],
      });
  }
  if (document.getElementById('hostnamesTable')) {
      new DataTable('#hostnamesTable', {
        retrieve: true,
        drawCallback: function (settings) {
            newTabClickListener();
            $('[data-bs-toggle="tooltip"]').tooltip({html: true});
        },
        order: [[ 0, "desc" ]],
        columns: [{ width: '10%' },
                  { width: '40%', orderable: false },
                  { width: '50%', orderable: false }],
      });
  }
  if (document.getElementById('identifiersTable')) {
      new DataTable('#identifiersTable', {
        retrieve: true,
        drawCallback: function (settings) { newTabClickListener() },
        order: [[ 0, "desc" ]],
        columns: [{ width: '20%' },
                  { width: '40%' },
                  { width: '40%' }],
      });
  }
  if (document.getElementById('urlsTable')) {
      new DataTable('#urlsTable', {
        retrieve: true,
        drawCallback: function (settings) { newTabClickListener() },
        order: [[ 0, "desc" ]],
        columns: [{ width: '10%' },
                  { width: '90%', orderable: false }],
        initComplete: function (settings, json) {
          $('[data-bs-toggle="tooltip"]').tooltip({html: true});
        }
      }).on('draw', function() {
        $('[data-bs-toggle="tooltip"]').tooltip({html: true});
      });
  }
  if (document.getElementById('cookieNameTable')) {
      cookieName = document.getElementById('cookieNameTable').dataset.cookiename;
      new DataTable('#cookieNameTable', {
        processing: true,
        serverSide: true,
        retrieve: true,
        ordering: false,
        searching: false,  // Needs to implement that serverside
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

  if (document.getElementById('hostnameTable')) {
      hostname = document.getElementById('hostnameTable').dataset.hostname;
      new DataTable('#hostnameTable', {
        processing: true,
        serverSide: true,
        retrieve: true,
        ordering: false,
        searching: false,  // Needs to implement that serverside
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
        searching: false,  // Needs to implement that serverside
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
        searching: false,  // Needs to implement that serverside
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
