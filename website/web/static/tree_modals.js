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

function LocateNode(hostnode_uuid) {
    let element = document.getElementById(`node_${hostnode_uuid}`);
    element.scrollIntoView({behavior: "smooth", block: "center", inline: "center"});

    let line_arrow = d3.select(`#node_${hostnode_uuid}`)
                       .append('g')
                        .attr('cursor', 'pointer')
                        .on('click', (event, d) => { event.currentTarget.remove(); });

    let line = d3.line()
                    // Other options: http://bl.ocks.org/d3indepth/raw/b6d4845973089bc1012dec1674d3aff8/
                    //.curve(d3.curveCardinal)
                    .curve(d3.curveBundle)
                    .x(point => point.lx)
                    .y(point => point.ly);

    let line_tip = d3.symbol()
                    .type(d3.symbolTriangle)
                    .size(200);


    let path = line_arrow
        .append("path")
        .attr("stroke-width", "3")
        .attr("stroke", "black")
        .attr("fill", "none")
        .data([{
            source: {x: 100, y: -100},
            target: {x: 50, y: -50}
        }])
        .attr("class", "line")
        .attr("d", d => line(
            [{lx: d.source.x, ly: d.source.y},
             {lx: d.target.x, ly: d.source.y},
             {lx: d.target.x, ly: d.target.y}
            ])
        );

    let arrow = line_arrow
        .append("path")
        .attr("d", line_tip)
        .attr("stroke", 'black')
        .style('stroke-width', '3')
        .attr("fill", 'white')
        .attr("transform", `translate(50, -50) rotate(60)`);

    let glow = () => {
        line_arrow.selectAll('path')
            .transition().duration(1000)  //Set transition
            .style('stroke-width', '7')
            .style('stroke', 'red')
            .transition().duration(1000)  //Set transition
            .style('stroke-width', '3')
            .style('stroke', 'black')
            .on("end", () => {
                if (++i > 15) {
                    line_arrow.remove();
                } else {
                    glow();
                }
            });
    };

    let i = 0;
    glow();
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
     "#ipsModal", "#ipDetailsModal", "#cookieNameModal", "#ollamaModal",
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
