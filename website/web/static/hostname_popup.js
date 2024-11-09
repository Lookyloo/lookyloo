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

document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll('.submitPandoraButton').forEach(
        el => el.addEventListener('click', event => {
          submit_pandora(el.dataset.hostnode, el.dataset.hash);
    }));
});
