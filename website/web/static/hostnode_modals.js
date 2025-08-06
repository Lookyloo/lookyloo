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
