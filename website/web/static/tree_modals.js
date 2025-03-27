"use strict";
function mispSelector() {
  $('#mispSelector button').on('click', function(e){
      let thisBtn = $(this);
      thisBtn.addClass('active').siblings().removeClass('active');
      $(`#${thisBtn.val()}`).show().siblings().hide()
  });
}

// Modals
document.addEventListener("DOMContentLoaded", () => {
    ["#hashlookupModal", "#modulesModal", "#historyModal", "#categoriesModal", "#statsModal",
     "#identifiersModal", "#identifierDetailsModal",
     "#faviconsModal", "#faviconDetailsModal",
     "#faviconDetailsProbabilisticHashModal",
     "#captureHashesTypesModal", "#captureHashesTypesDetailsModal",
     "#bodyHashesModal", "#bodyHashDetailsModal",
     "#hostnamesModal", "#hostnameDetailsModal",
     "#urlsModal", "#urlDetailsModal",
     "#urlsInPageModal", "#storageStateModal",
     "#ipsModal", "#ipDetailsModal", "#cookieNameModal",
     "#mispPushModal", "#mispLookupModal"].forEach(modal => {
        $(modal).on('show.bs.modal', function(e) {
          var button = $(e.relatedTarget);
          var modal = $(this);
          modal.find('.modal-body').load(button.data("remote"), function(result){
            renderTables();
            submitPandoraListener();
            mispSelector();
          });
        })
    });

    // OnClicks
    document.getElementById("removeCapture")?.addEventListener("click", function (e) {
      e.preventDefault();
      if (confirm('Are you sure you want to remove the capture?')) {
        window.location = this.href;
      };
    }, false);

    document.getElementById("unbookmarkAllNodes")?.addEventListener("click", UnbookmarkAllNodes);

    document.getElementById("markAsKnown")?.addEventListener("click", function (e) {
      MarkAsKnown(treeUUID)
    });

    document.getElementById("blurScreenshot")?.addEventListener("click", function (e) {
      let blur_status = document.getElementById('screenshot').classList.toggle('blur');
      if (blur_status) {
        this.innerText = 'Unblur';
      } else {
        this.innerText = 'Blur';
      }
    });
});
