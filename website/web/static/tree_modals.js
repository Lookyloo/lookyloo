// Modals

$('#hashlookupModal').on('show.bs.modal', function(e) {
  var button = $(e.relatedTarget);
  var modal = $(this);
  modal.find('.modal-body').load(button.data("remote"));
});

$('#modulesModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote"));
});
$('#historyModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote"));
});

$('#categoriesModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote"));
});

$('#statsModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote"));
});

$('#identifiersModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote"));
});

$('#identifierDetailsModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote"));
});

$('#faviconsModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote"));
});

$('#faviconDetailsModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote"));
});

$('#captureHashesTypesModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote"));
});

$('#captureHashesTypesDetailsModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote"));
});

$('#faviconDetailsProbabilisticHashModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote"));
});

$('#bodyHashesModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote"));
});

$('#bodyHashDetailsModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote"));
});

$('#hostnamesModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote"));
});

$('#hostnameDetailsModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote"));
});

$('#urlsModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote"));
});

$('#urlDetailsModal').on('show.bs.modal', function(e) {
    var button = $(e.relatedTarget);
    var modal = $(this);
    modal.find('.modal-body').load(button.data("remote"));
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
    modal.find('.modal-body').load(button.data("remote"));
});

// Categories

document.getElementById("legitimate").addEventListener('change', function(){
  if (this.checked){
    disableInput(document.getElementById('malicious-categories'));
    enableInput(document.getElementById('legitimate-categories'));
  }
});
document.getElementById("malicious").addEventListener('change', function(){
  if (this.checked){
    enableInput(document.getElementById('malicious-categories'));
    disableInput(document.getElementById('legitimate-categories'));
  }
});
document.getElementById("unclear").addEventListener('change', function(){
  if (this.checked){
    disableInput(document.getElementById('malicious-categories'));
    disableInput(document.getElementById('legitimate-categories'));
  }
});
document.getElementById("legitimate-categories").addEventListener('click', function(){
   if (this.querySelectorAll('input[type="checkbox"]:checked').length > 0) {
     document.getElementById("legitimate").checked = true;
   }
});
document.getElementById("malicious-categories").addEventListener('click', function(){
   if (this.querySelectorAll('input[type="checkbox"]:checked').length > 0) {
     document.getElementById("malicious").checked = true;
   }
});

function disableInput(container) {
    const Input = container.querySelectorAll('input');
    Input.forEach(function(checkbox){
      checkbox.disabled = true;
      checkbox.checked = false;
    });
    container.hidden = true;
}

function enableInput(container) {
    const Input = container.querySelectorAll('input');
    Input.forEach(checkbox => checkbox.disabled = false);
    container.hidden = false;
}

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
