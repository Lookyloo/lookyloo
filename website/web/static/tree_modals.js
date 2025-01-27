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
     "#urlsInPageModal",
     "#ipsModal", "#ipDetailsModal"].forEach(modal => {
        $(modal).on('show.bs.modal', function(e) {
          var button = $(e.relatedTarget);
          var modal = $(this);
          modal.find('.modal-body').load(button.data("remote"));
        })
    });
});


document.addEventListener("DOMContentLoaded", () => {
    ["#mispPushModal", "#mispLookupModal"].forEach(modal => {
        $(modal).on('show.bs.modal', function(e) {
          var button = $(e.relatedTarget);
          var modal = $(this);
          modal.find('.modal-body').load(button.data("remote"), function(result){
              $('#mispSelector button').on('click', function(e){
                var thisBtn = $(this);
                thisBtn.addClass('active').siblings().removeClass('active');
                $(`#${thisBtn.val()}`).show().siblings().hide()
              });
          });
      });
    }
)});

// OnClicks

const removeCapture = document.getElementById("removeCapture")
if (removeCapture) {
  removeCapture.addEventListener("click", function (e) {
   e.preventDefault();
    if (confirm('Are you sure you want to remove the capture?')) {
      window.location = this.href;
    };
  }, false);
}

const unbookmarkAllNodes = document.getElementById("unbookmarkAllNodes")
if (unbookmarkAllNodes) {
  unbookmarkAllNodes.addEventListener("click", UnbookmarkAllNodes);
}

const markAsKnown = document.getElementById("markAsKnown")
if (markAsKnown) {
    markAsKnown.addEventListener("click", function (e) {
        MarkAsKnown(treeUUID)
    });
}

const blurScreenshot = document.getElementById("blurScreenshot")
if (blurScreenshot) {
    blurScreenshot.addEventListener("click", function (e) {
        let blur_status = document.getElementById('screenshot').classList.toggle('blur');
        if (blur_status) {
            this.innerText = 'Unblur';
        } else {
            this.innerText = 'Blur';
        }
    });
}
