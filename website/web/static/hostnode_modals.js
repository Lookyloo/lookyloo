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
        if (Array.isArray(data)) {
            const pretty_data_element = document.getElementById("pretty_data");
            // is it a multipart?
            const multipart_keys = ["headers", "content"];
            data.forEach((item, index) => {
              if (index > 0) {
                  // add a separator if we have more than one entry
                  pretty_data_element.appendChild(document.createElement("hr"))
              }

              let part = document.createElement("p");
              part.setAttribute("id", `part_${index}`);
              pretty_data_element.appendChild(part);

              if (multipart_keys.every(key => Object.keys(item).includes(key))) {
                  let header = document.createElement("p");
                  header.setAttribute("id", `part_header_${index}`);
                  part.appendChild(header)
                  $(`#part_header_${index}`).jsonViewer(item['headers'], {withLinks: false});

                  part.appendChild(document.createTextNode(item['content']))
              }
              else {
                  // insert as straight json
                  $(`#part_${index}`).jsonViewer(item, {withLinks: false});
              }
            })
        }
        else {
            $('#pretty_data').jsonViewer(data, {withLinks: false});
        }
    } catch(error) {
      document.getElementById("render_meta").classList.add("alert-info");
      document.getElementById("render_meta").innerHTML = "The content isn't a JSON document, below is the text content.";
      document.getElementById("pretty_data").appendChild(document.createTextNode(result_text));
    }
  } catch (error) {
    document.getElementById("render_meta").classList.add("alert-danger");
    document.getElementById("render_meta").innerHTML = "Unable to get the data.";
  }
}
