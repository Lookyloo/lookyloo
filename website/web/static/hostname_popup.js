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
  const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]')
  const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl))

  document.querySelectorAll('.submitPandoraButton').forEach(
      el => el.addEventListener('click', event => {
        submit_pandora(el.dataset.hostnode, el.dataset.hash);
  }));
  document.querySelectorAll('.js-copy').forEach(
      el => el.addEventListener('click', event => {
        navigator.clipboard.writeText(el.dataset.copy).then(function() {
            el.setAttribute('data-bs-original-title', 'Copying to clipboard was successful!');
        }, function(err) {
            el.setAttribute('data-bs-original-title', 'Could not copy text: ' + err);
        });
      })
  );
});
