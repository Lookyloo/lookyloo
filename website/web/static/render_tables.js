["DOMContentLoaded", "shown.bs.modal", "jquery.modal.rendered"].forEach(e => window.addEventListener(e, function() {

  if (document.getElementById('bodyHashDetailsTable')) {
    new DataTable('#bodyHashDetailsTable', {
                  retrieve: true,
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
  if (document.getElementById('hashTypeDetailsTable')) {
      new DataTable('#hashTypeDetailsTable', {
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

  if (document.getElementById('identifierDetailsTable')) {
      new DataTable('#identifierDetailsTable', {
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
        columnDefs: [{ width: '10%', targets: 0 },
                     { width: '40%', targets: 1 },
                     { width: '40%', targets: 2 },
                     { width: '10%', targets: 3 }],
      });
  }
  if (document.getElementById('treeHashesTable')) {
    new DataTable('#treeHashesTable', {
    retrieve: true,
    columnDefs: [{ width: '20%', targets: 0 },
                 { width: '40%', targets: 1 },
                 { width: '40%', targets: 2 }],
    });
  }
  if (document.getElementById('hostnamesTable')) {
      new DataTable('#hostnamesTable', {
      retrieve: true,
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
        columnDefs: [{ width: '20%', targets: 0 },
                     { width: '40%', targets: 1 },
                     { width: '40%', targets: 2 }],
      });
  }
  if (document.getElementById('urlsTable')) {
      new DataTable('#urlsTable', {
        retrieve: true,
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
      new DataTable('#cookieNameTable', {
        retrieve: true,
        order: [[ 0, "desc" ]],
        columnDefs: [{ width: '30%', targets: 0,
                       render: (data) => {
                        const date = new Date(data);
                        return date.getFullYear() + '-' + (date.getMonth() + 1).toString().padStart(2, "0") + '-' + date.getDate().toString().padStart(2, "0") + ' ' + date.toTimeString();
                       }
                     },
                     { width: '70%', targets: 1 }]
      });
  }

  if (document.getElementById('hostnameTable')) {
    new DataTable('#hostnameTable', {
    retrieve: true,
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
      new DataTable('#urlTable', {
        retrieve: true,
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
    new DataTable('#faviconDetailsTable', {
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

  // Other things to trigger in modals
  document.querySelectorAll(".downloadFaviconButton").forEach(el => el.addEventListener('click', event => {
      downloadBase64File(el.dataset.mimetype, el.dataset.b64favicon, el.dataset.filename);
  }))

}));
