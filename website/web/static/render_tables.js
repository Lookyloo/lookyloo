["DOMContentLoaded", "shown.bs.modal", "jquery.modal.rendered"].forEach(e => window.addEventListener(e, function() {
  if (document.getElementById('HHHDetailsTable')) {
    hhh = document.getElementById('HHHDetailsTable').dataset.hhh;
    new DataTable('#HHHDetailsTable', {
      processing: true,
      serverSide: true,
      retrieve: true,
      drawCallback: function (settings) { newTabClickListener() },
      ajax: {
          url: `/tables/HHHDetailsTable/${hhh}${window.location.search}`,
          type: 'POST'
      },
      columns : [
          { data: 'capture_time' },
          { data: 'capture_title' },
          { data: 'url' }
      ],
      order: [[ 0, "desc" ]],
      columnDefs: [{ width: '20%', targets: 0,
        render: (data) => {
           const date = new Date(data);
           return date.getFullYear() + '-' + (date.getMonth() + 1).toString().padStart(2, "0") + '-' + date.getDate().toString().padStart(2, "0") + ' ' + date.toTimeString();
        }
      },
      { width: '40%', targets: 1 },
      { width: '40%', targets: 2 }],
    })
  }
  if (document.getElementById('bodyHashDetailsTable')) {
    bodyhash = document.getElementById('bodyHashDetailsTable').dataset.bodyhash;
    new DataTable('#bodyHashDetailsTable', {
      processing: true,
      serverSide: true,
      retrieve: true,
	  drawCallback: function (settings) { newTabClickListener() },
      ajax: {
          url: `/tables/bodyHashDetailsTable/${bodyhash}${window.location.search}`,
          type: 'POST'
      },
      columns : [
          { data: 'capture_time' },
          { data: 'capture_title' },
          { data: 'url' }
      ],
      order: [[ 0, "desc" ]],
      columnDefs: [{ width: '20%', targets: 0,
        render: (data) => {
           const date = new Date(data);
           return date.getFullYear() + '-' + (date.getMonth() + 1).toString().padStart(2, "0") + '-' + date.getDate().toString().padStart(2, "0") + ' ' + date.toTimeString();
        }
      },
      { width: '40%', targets: 1 },
      { width: '40%', targets: 2 }],
    })
  }
  if (document.getElementById('hashTypeDetailsTable')) {
      hash_value = document.getElementById('hashTypeDetailsTable').dataset.hashvalue;
      new DataTable('#hashTypeDetailsTable', {
        processing: true,
        serverSide: true,
        retrieve: true,
		drawCallback: function (settings) { newTabClickListener() },
        ajax: {
            url: `/tables/hashTypeDetailsTable/${hash_value}`,
            type: 'POST'
        },
        columns : [
            { data: 'capture_time' },
            { data: 'capture_title' },
            { data: 'landing_page' }
        ],
        order: [[ 0, "desc" ]],
        columnDefs: [{ width: '30%',
                       targets: 0,
                       render: (data) => {
                        const date = new Date(data);
                        return date.getFullYear() + '-' + (date.getMonth() + 1).toString().padStart(2, "0") + '-' + date.getDate().toString().padStart(2, "0") + ' ' + date.toTimeString();
                       }
                     },
                     { width: '30%', targets: 1 },
                     { width: '50%', targets: 2 }],

      });
  }

  if (document.getElementById('identifierDetailsTable')) {
      identifier_value = document.getElementById('identifierDetailsTable').dataset.identifier;
      new DataTable('#identifierDetailsTable', {
        processing: true,
        serverSide: true,
        retrieve: true,
		drawCallback: function (settings) { newTabClickListener() },
        ajax: {
            url: `/tables/identifierDetailsTable/${identifier_value}`,
            type: 'POST'
        },
        columns : [
            { data: 'capture_time' },
            { data: 'capture_title' },
            { data: 'landing_page' }
        ],
        retrieve: true,
        order: [[ 0, "desc" ]],
        columnDefs: [{ width: '30%',
                       targets: 0,
                       render: (data) => {
                        const date = new Date(data);
                        return date.getFullYear() + '-' + (date.getMonth() + 1).toString().padStart(2, "0") + '-' + date.getDate().toString().padStart(2, "0") + ' ' + date.toTimeString();
                       }
                     },
                     { width: '30%', targets: 1 },
                     { width: '50%', targets: 2 }],

      });
  }
  if (document.getElementById('bodyHashesTable')) {
      new DataTable('#bodyHashesTable', {
        retrieve: true,
		drawCallback: function (settings) { newTabClickListener() },
        order: [[ 0, "desc" ]],
        columnDefs: [{ width: '10%', targets: 0 },
                     { width: '10%', targets: 1 },
                     { width: '60%', targets: 2 },
                     { width: '20%', targets: 3 }],
        initComplete: function (settings, json) {
          $('[data-bs-toggle="tooltip"]').tooltip({html: true});
        }
      }).on('draw', function() {
        $('[data-bs-toggle="tooltip"]').tooltip({html: true});
      });
  }
  if (document.getElementById('faviconsTable')) {
      new DataTable('#faviconsTable', {
        retrieve: true,
		drawCallback: function (settings) { newTabClickListener() },
        columnDefs: [{ width: '10%', targets: 0 },
                     { width: '40%', targets: 1 },
                     { width: '40%', targets: 2 },
                     { width: '10%', targets: 3 }],
      });
  }
  if (document.getElementById('treeHashesTable')) {
    new DataTable('#treeHashesTable', {
    retrieve: true,
	drawCallback: function (settings) { newTabClickListener() },
    columnDefs: [{ width: '20%', targets: 0 },
                 { width: '40%', targets: 1 },
                 { width: '40%', targets: 2 }],
    });
  }
  if (document.getElementById('hostnamesTable')) {
      new DataTable('#hostnamesTable', {
      retrieve: true,
	  drawCallback: function (settings) { newTabClickListener() },
      order: [[ 0, "desc" ]],
      columnDefs: [{ width: '10%', targets: 0 },
                   { width: '40%', targets: 1 },
                   { width: '50%', targets: 2 }],
      initComplete: function (settings, json) {
        $('[data-bs-toggle="tooltip"]').tooltip({html: true});
      }
    }).on('draw', function() {
      $('[data-bs-toggle="tooltip"]').tooltip({html: true});
    });
  }
  if (document.getElementById('identifiersTable')) {
      new DataTable('#identifiersTable', {
        retrieve: true,
		drawCallback: function (settings) { newTabClickListener() },
        columnDefs: [{ width: '20%', targets: 0 },
                     { width: '40%', targets: 1 },
                     { width: '40%', targets: 2 }],
      });
  }
  if (document.getElementById('urlsTable')) {
      new DataTable('#urlsTable', {
        retrieve: true,
		drawCallback: function (settings) { newTabClickListener() },
        order: [[ 0, "desc" ]],
        columnDefs: [{ width: '10%', targets: 0 },
                     { width: '90%', targets: 1 }],
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
		drawCallback: function (settings) { newTabClickListener() },
        ajax: {
            url: `/tables/cookieNameTable/${cookieName}${window.location.search}`,
            type: 'POST'
        },
        columns : [
            { data: 'capture_time' },
            { data: 'capture_title' },
            { data: 'landing_page' }
        ],
        order: [[ 0, "desc" ]],
        columnDefs: [{ width: '20%', targets: 0,
                       render: (data) => {
                        const date = new Date(data);
                        return date.getFullYear() + '-' + (date.getMonth() + 1).toString().padStart(2, "0") + '-' + date.getDate().toString().padStart(2, "0") + ' ' + date.toTimeString();
                       }
                     },
                     { width: '40%', targets: 1 },
                     { width: '40%', targets: 2 }]
      });
  }

  if (document.getElementById('hostnameTable')) {
    hostname = document.getElementById('hostnameTable').dataset.hostname;
    new DataTable('#hostnameTable', {
    processing: true,
    serverSide: true,
    retrieve: true,
	drawCallback: function (settings) { newTabClickListener() },
    ajax: {
        url: `/tables/hostnameTable/${hostname}`,
        type: 'POST'
    },
    columns : [
        { data: 'capture_time' },
        { data: 'capture_title' },
        { data: 'landing_page' }
    ],
    order: [[ 0, "desc" ]],
    columnDefs: [{ width: '20%', targets: 0,
                   render: (data) => {
                    const date = new Date(data);
                    return date.getFullYear() + '-' + (date.getMonth() + 1).toString().padStart(2, "0") + '-' + date.getDate().toString().padStart(2, "0") + ' ' + date.toTimeString();
                   }
                 },
                 { width: '40%', targets: 1 },
                 { width: '40%', targets: 2 }],
    });
  }

  if (document.getElementById('urlTable')) {
      url = document.getElementById('urlTable').dataset.url;
      new DataTable('#urlTable', {
        processing: true,
        serverSide: true,
        retrieve: true,
		drawCallback: function (settings) { newTabClickListener() },
        ajax: {
            url: `/tables/urlTable/${url}`,
            type: 'POST'
        },
        columns : [
            { data: 'capture_time' },
            { data: 'capture_title' },
            { data: 'landing_page' }
        ],
        order: [[ 0, "desc" ]],
        columnDefs: [{ width: '20%', targets: 0,
                       render: (data) => {
                        const date = new Date(data);
                        return date.getFullYear() + '-' + (date.getMonth() + 1).toString().padStart(2, "0") + '-' + date.getDate().toString().padStart(2, "0") + ' ' + date.toTimeString();
                       }
                     },
                     { width: '40%', targets: 1 },
                     { width: '40%', targets: 2 }],
      });
  }

  if (document.getElementById('faviconDetailsTable')) {
    favicon = document.getElementById('faviconDetailsTable').dataset.favicon;
    new DataTable('#faviconDetailsTable', {
      processing: true,
      serverSide: true,
      retrieve: true,
	  drawCallback: function (settings) { newTabClickListener() },
      ajax: {
          url: `/tables/faviconDetailsTable/${favicon}`,
          type: 'POST'
      },
      columns : [
          { data: 'capture_time' },
          { data: 'capture_title' },
          { data: 'landing_page' }
      ],
      order: [[ 0, "desc" ]],
      columnDefs: [{ width: '30%',
                     targets: 0,
                     render: (data) => {
                      const date = new Date(data);
                      return date.getFullYear() + '-' + (date.getMonth() + 1).toString().padStart(2, "0") + '-' + date.getDate().toString().padStart(2, "0") + ' ' + date.toTimeString();
                     }
                   },
                   { width: '30%', targets: 1 },
                   { width: '50%', targets: 2 }],

    });
  }

  // Other things to trigger in modals
  document.querySelectorAll(".downloadFaviconButton").forEach(el => el.addEventListener('click', event => {
      downloadBase64File(el.dataset.mimetype, el.dataset.b64favicon, el.dataset.filename);
  }))
}));
