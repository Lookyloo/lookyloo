"use strict";
// Modals
document.addEventListener("DOMContentLoaded", () => {
    ["#JsonRenderModal"].forEach(modal => {
        $(modal).on('show.bs.modal', function(e) {
          var button = $(e.relatedTarget);
          var modal = $(this);
          modal.find('.modal-body').load(button.data("remote"), function(result){
            console.log('done');
          });
        })
    });
});


async function getData(url) {
  try {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Response status: ${response.status}`);
    }

    const result_text = await response.text();
    try {
        const data = JSON.parse(result_text);
        $('#json-renderer').jsonViewer(data, {withLinks: false});
    } catch(error) {
      document.getElementById("render_meta").classList.add("alert-warning");
      document.getElementById("render_meta").innerHTML = "The content isn't a JSON document, below is the URI encoded content. Download the blob to investigate.";
      document.getElementById("json-renderer").innerHTML = encodeURIComponent(result_text);
    }
  } catch (error) {
    document.getElementById("render_meta").classList.add("alert-danger");
    document.getElementById("render_meta").innerHTML = "Unable to get the data.";
  }
}
