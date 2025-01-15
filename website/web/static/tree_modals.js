// Modals

$('#hashlookupModal').on('show.bs.modal', function(e) {
  var button = $(e.relatedTarget);
  var modal = $(this);
  modal.find('.modal-body').load(button.data("remote")).trigger('jquery.modal.rendered');
});

$('#modulesModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote")).trigger('jquery.modal.rendered');
});
$('#historyModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote")).trigger('jquery.modal.rendered');
});

$('#categoriesModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote")).trigger('jquery.modal.rendered');
});

$('#statsModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote")).trigger('jquery.modal.rendered');
});

$('#identifiersModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote")).trigger('jquery.modal.rendered');
});

$('#identifierDetailsModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote")).trigger('jquery.modal.rendered');
});

$('#faviconsModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote")).trigger('jquery.modal.rendered');
});

$('#faviconDetailsModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote")).trigger('jquery.modal.rendered');
});

$('#captureHashesTypesModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote")).trigger('jquery.modal.rendered');
});

$('#captureHashesTypesDetailsModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote")).trigger('jquery.modal.rendered');
});

$('#faviconDetailsProbabilisticHashModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote")).trigger('jquery.modal.rendered');
});

$('#bodyHashesModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote")).trigger('jquery.modal.rendered');
});

$('#bodyHashDetailsModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote")).trigger('jquery.modal.rendered');
});

$('#hostnamesModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote")).trigger('jquery.modal.rendered');
});

$('#hostnameDetailsModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote")).trigger('jquery.modal.rendered');
});

$('#urlsModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote")).trigger('jquery.modal.rendered');
});

$('#urlDetailsModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote")).trigger('jquery.modal.rendered');
});

$('#mispPushModal').on('show.bs.modal', function(e) {
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

$('#mispLookupModal').on('show.bs.modal', function(e) {
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

$('#urlsInPageModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote")).trigger('jquery.modal.rendered');
});

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
