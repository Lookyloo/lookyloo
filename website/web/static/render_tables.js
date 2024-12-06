["DOMContentLoaded", "shown.bs.modal", "jquery.modal.rendered"].forEach(e => window.addEventListener(e, function() {
  if (document.getElementById('HHHDetailsTable')) {
    hhh = document.getElementById('HHHDetailsTable').dataset.hhh;
    new DataTable('#HHHDetailsTable', {
      processing: true,
      serverSide: true,
      retrieve: true,
      ordering: false,
      searching: false,  // Needs to implement that serverside
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
      searching: false,  // Needs to implement that serverside
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
        ordering: false,
        drawCallback: function (settings) {
            newTabClickListener();
            $('[data-bs-toggle="tooltip"]').tooltip({html: true});
        },
        order: [[ 0, "desc" ]],
        columns: [{ width: '10%' },
                  { width: '10%' }, // Would make sense to order on the file type
                  { width: '60%' },
                  { width: '20%' }],
      });
  }
  if (document.getElementById('faviconsTable')) {
      new DataTable('#faviconsTable', {
        retrieve: true,
        ordering: false,
        drawCallback: function (settings) {
            newTabClickListener();
            downloadFaviconListener();
        },
        columns: [{ width: '10%' },
                  { width: '40%' },
                  { width: '40%' },
                  { width: '10%' }],
      });
  }
  if (document.getElementById('treeHashesTable')) {
      new DataTable('#treeHashesTable', {
        retrieve: true,
        ordering: false,
        drawCallback: function (settings) { newTabClickListener() },
        column: [{ width: '20%' },
                 { width: '40%' },
                 { width: '40%' }],
      });
  }
  if (document.getElementById('hostnamesTable')) {
      new DataTable('#hostnamesTable', {
        retrieve: true,
        ordering: false,
        drawCallback: function (settings) {
            newTabClickListener();
            $('[data-bs-toggle="tooltip"]').tooltip({html: true});
        },
        order: [[ 0, "desc" ]],
        columns: [{ width: '10%' },
                  { width: '40%' },
                  { width: '50%' }],
      });
  }
  if (document.getElementById('identifiersTable')) {
      new DataTable('#identifiersTable', {
        retrieve: true,
        ordering: false,
        drawCallback: function (settings) { newTabClickListener() },
        columns: [{ width: '20%' },
                  { width: '40%' },
                  { width: '40%' }],
      });
  }
  if (document.getElementById('urlsTable')) {
      new DataTable('#urlsTable', {
        retrieve: true,
        ordering: false,
        drawCallback: function (settings) { newTabClickListener() },
        order: [[ 0, "desc" ]],
        columns: [{ width: '10%' },
                  { width: '90%' }],
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
}));
