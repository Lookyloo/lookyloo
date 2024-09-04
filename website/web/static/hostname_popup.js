const locateInTree = document.querySelectorAll(".locateInTree")
if (locateInTree) {
    locateInTree.forEach(el => el.addEventListener('click', event => {
        window.opener.LocateNode(el.dataset.hostnode);
    }));
}

let openTreeInNewTab = (capture_uuid, hostnode_uuid=Null) => {
  let success = window.opener.openTreeInNewTab(capture_uuid, hostnode_uuid);
  if (! success) {
      alert("Your browser doesn't allow Lookyloo to open a new tab. There should be an icon on the right side of your URL bar *in the main window* to allow it.");
  }
}

var openNewTabButtons = document.querySelectorAll('.openNewTab');
if (openNewTabButtons) {
    openNewTabButtons.forEach(el => el.addEventListener('click', event => {
      openTreeInNewTab(el.dataset.capture, el.dataset.hostnode);
  }));
}

document.addEventListener("DOMContentLoaded", () => {
  // Grab any text in the attribute 'data-copy' and pass it to the copy function
  $('.js-copy').tooltip();
  $('.js-copy').click(function() {
    const text = $(this).attr('data-copy');
    const el = $(this);
    copyToClipboard(text, el);
  });
});

document.addEventListener("DOMContentLoaded", () => {
  $(function () {
    $('[data-bs-toggle="tooltip"]').tooltip()
  })
});

function submit_pandora(node_uuid, ressource_hash){
  let data = {};
  if (node_uuid) {
      data.node_uuid = node_uuid;
  };
  if (ressource_hash) {
      data.ressource_hash = ressource_hash;
  };
  fetch("{{ url_for('pandora_submit', tree_uuid=tree_uuid)}}", {
      method: "POST",
      body: JSON.stringify(data),
    })
    .then(response => response.json())
    .then(data => {
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(data.link);
      }
      openURLInNewTab(data.link);
    })
    .catch((error) => {
        throw new Error(error);
    });
};

var submitPandoraButtons = document.querySelectorAll('.submitPandoraButton');
if (submitPandoraButtons) {
    submitPandoraButtons.forEach(el => el.addEventListener('click', event => {
      submit_pandora(el.dataset.hostnode, el.dataset.hash);
  }));
}

let openURLInNewTab = (url) => {
  let success = window.opener.openURLInNewTab(url);
  if (! success) {
      alert("Your browser doesn't allow Lookyloo to open a new tab. There should be an icon on the right side of your URL bar *in the main window* to allow it.");
  }
}
