"use strict";
function mispSelector() {
  $('#mispSelector button').on('click', function(e){
      let thisBtn = $(this);
      thisBtn.addClass('active').siblings().removeClass('active');
      $(`#${thisBtn.val()}`).show().siblings().hide()
  });
}

//download the tree as png file
const downloadSvg = () => {
    const svg = document.querySelector('svg');
    const svgCopy = svg.cloneNode(true);
    const images = svgCopy.querySelectorAll('image');
    const promises = [];
    images.forEach((imageElement) => {
        const promise = new Promise((resolve, reject) => {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');

            const image = new Image();
            image.onload = function() {
                canvas.width = image.width;
                canvas.height = image.height;
                ctx.drawImage(image, 0, 0);
                const dataURL = canvas.toDataURL("image/svg+xml");
                imageElement.setAttribute('href', dataURL);
                resolve();
            };
            image.onerror = function() {
                reject(new Error('Error'));
            };
            image.src = imageElement.getAttribute('href');
        });
        promises.push(promise);
    });

    Promise.all(promises).then(() => {
        let svgData = new XMLSerializer().serializeToString(svgCopy);
        let svgBlob = new Blob([svgData], { type: "image/svg+xml;charset=utf-8" });
        let url = URL.createObjectURL(svgBlob);
        let img = new Image();
        img.onload = function() {
            let canvas = document.createElement('canvas');
            canvas.width = svgCopy.width.baseVal.value;
            canvas.height = svgCopy.height.baseVal.value;
            let ctx = canvas.getContext('2d');
            ctx.fillStyle='white';
            ctx.fillRect(0,0,canvas.width,canvas.height)
            ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

            let png = canvas.toDataURL('image/png');
            let a = document.createElement('a');
            a.download = 'tree.png';
            a.href = png;
            a.click();
            URL.revokeObjectURL(url);
        };
        img.src = url;
    }).catch((error) => {
        console.error('Error:', error);
    });
};

// Modals
document.addEventListener("DOMContentLoaded", () => {
    ["#hashlookupModal", "#modulesModal", "#historyModal", "#categoriesModal", "#statsModal", "#downloadModal",
     "#identifiersModal", "#identifierDetailsModal",
     "#faviconsModal", "#faviconDetailsModal",
     "#faviconDetailsProbabilisticHashModal",
     "#captureHashesTypesModal", "#captureHashesTypesDetailsModal",
     "#bodyHashesModal", "#bodyHashDetailsModal",
     "#hostnamesModal", "#hostnameDetailsModal",
     "#urlsModal", "#urlDetailsModal",
     "#urlsInPageModal", "#storageStateModal", "#downloadsModal",
     "#ipsModal", "#ipDetailsModal", "#cookieNameModal",
     "#mispPushModal", "#mispLookupModal"].forEach(modal => {
        $(modal).on('show.bs.modal', function(e) {
          var button = $(e.relatedTarget);
          var modal = $(this);
          modal.find('.modal-body').load(button.data("remote"), function(result){
            renderTables();
            submitPandoraListener();
            mispSelector();
            document.getElementById("dlTreeAsSVG")?.addEventListener("click", downloadSvg);
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
