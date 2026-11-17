"use strict";
function mispSelector() {
  let mispSelectorButtons = document.querySelectorAll('#mispSelector button');
  mispSelectorButtons.forEach((b) => {
    b.addEventListener('click', (e) => {
      e.currentTarget.parentNode.childNodes.forEach((s) => {
        if (s.nodeType !== 3) {
            // not text node
            s.classList.remove("active");
        }
      });
      document.getElementById(e.currentTarget.value).parentNode.childNodes.forEach((s) => {
        if (s.nodeType !== 3) {
          // not text node
          s.style.display = 'none';
        }
      });
      e.currentTarget.classList.add('active')
      document.getElementById(e.currentTarget.value).style.display = 'block';
    });
  });
};

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
    ["#hashlookupModal", "#modulesModal", "#historyModal", "#categoriesModal", "#statsModal",
     "#downloadModal", "#videoModal",
     "#identifiersModal", "#identifierDetailsModal",
     "#faviconsModal", "#faviconDetailsModal",
     "#faviconDetailsProbabilisticHashModal",
     "#captureHashesTypesModal", "#captureHashesTypesDetailsModal",
     "#cloudflareNSModal", "#cloudflareNSDetailsModal",
     "#bodyHashesModal", "#bodyHashDetailsModal",
     "#hostnamesModal", "#hostnameDetailsModal",
     "#urlsModal", "#urlDetailsModal", "#consoleMessagesModal",
     "#urlsInPageModal", "#storageStateModal", "#downloadsModal",
     "#ipsModal", "#ipDetailsModal", "#ollamaModal",
     "#mispPushModal", "#mispLookupModal"].forEach(modal => {
        document.querySelector(modal).addEventListener('show.bs.modal', function(e) {
          var curTarget = e.currentTarget;
          fetch(e.relatedTarget.dataset.remote)
            .then(response => response.text())
            .then(data => {
                curTarget.querySelector('.modal-body').innerHTML = data;
                renderTables();
                submitPandoraListener();
                mispSelector();
                document.getElementById("dlTreeAsSVG")?.addEventListener("click", downloadSvg);
            })
        });
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

    // Blur of the screenshot, blurred at first (tree/tree.html, doc/ui/screenshot-blur.md):
    // level in % (100% = 20px), presets, slow reveal, clear spot under the mouse.
    // The thumbnail of the landing node in the tree (js/tree.js) follows the level.
    setupScreenshotBlur();
});

function setupScreenshotBlur() {
  const shot = document.getElementById('screenshot');
  const level = document.getElementById('blurLevel');
  if (!shot || !level) return;
  const output = document.getElementById('blurLevelValue');
  const reveal = document.getElementById('revealScreenshot');
  const revealLabel = reveal?.querySelector('span');
  const spotlight = document.getElementById('spotlightScreenshot');
  const frame = document.getElementById('screenshotFrame');
  const spot = document.getElementById('screenshotSpot');
  const toggle = document.getElementById('blurScreenshot');
  const MAX_PX = 20, THUMB_MAX_PX = 3, REVEAL_MS = 8000;
  let revealing = null;

  const apply = (percent) => {
    percent = Math.max(0, Math.min(100, Math.round(percent)));
    level.value = percent;
    output.textContent = `${percent}%`;
    shot.classList.remove('blur');
    shot.style.filter = percent ? `blur(${MAX_PX * percent / 100}px)` : 'none';
    spot.style.filter = 'none';
    const thumb = document.getElementById('screenshot_thumbnail');
    if (thumb) {
      thumb.classList.remove('blur');
      thumb.style.filter = percent ? `blur(${THUMB_MAX_PX * percent / 100}px)` : 'none';
    }
    if (toggle) {
      toggle.setAttribute('aria-pressed', percent ? 'true' : 'false');
      toggle.querySelector('span').textContent = percent ? 'Unblur' : 'Blur';
    }
    document.querySelectorAll('[data-blur-preset]').forEach(b =>
      b.classList.toggle('active', Number(b.dataset.blurPreset) === percent));
    if (spotlight && !percent) setSpotlight(false);
  };
  const stopReveal = () => {
    if (revealing) cancelAnimationFrame(revealing.frame);
    revealing = null;
    if (revealLabel) revealLabel.textContent = 'Reveal slowly';
  };
  const setSpotlight = (on) => {
    spotlight.setAttribute('aria-pressed', on ? 'true' : 'false');
    spotlight.classList.toggle('active', on);
    frame.classList.toggle('is-spotlight', on);
    if (!on) spot.hidden = true;
  };

  // Unblur (0 %) / Blur (100 %) in one click
  toggle?.addEventListener('click', () => { stopReveal(); apply(Number(level.value) ? 0 : 100); });
  level.addEventListener('input', () => { stopReveal(); apply(level.value); });
  document.querySelectorAll('[data-blur-preset]').forEach(button =>
    button.addEventListener('click', () => { stopReveal(); apply(button.dataset.blurPreset); }));

  // From the current level down to 0 in REVEAL_MS (for 100%), at a steady pace
  reveal?.addEventListener('click', () => {
    if (revealing) { stopReveal(); return; }
    if (Number(level.value) === 0) apply(100);
    revealLabel.textContent = 'Pause';
    let last = performance.now();
    let next = Number(level.value);   // exact value: the slider rounds it
    const step = (now) => {
      next -= (now - last) / REVEAL_MS * 100;
      last = now;
      apply(next);
      if (next <= 0) { stopReveal(); return; }
      revealing.frame = requestAnimationFrame(step);
    };
    revealing = {frame: requestAnimationFrame(step)};
  });

  // Clear copy of the screenshot over the blurred one, masked to a circle at the mouse
  spotlight?.addEventListener('click', () => {
    const on = spotlight.getAttribute('aria-pressed') !== 'true';
    if (on && Number(level.value) === 0) apply(100);
    setSpotlight(on);
  });
  frame?.addEventListener('pointermove', (e) => {
    if (!frame.classList.contains('is-spotlight')) return;
    const box = frame.getBoundingClientRect();
    frame.style.setProperty('--lk-spot-x', `${e.clientX - box.left + frame.scrollLeft}px`);
    frame.style.setProperty('--lk-spot-y', `${e.clientY - box.top + frame.scrollTop}px`);
    spot.hidden = false;
  });
  frame?.addEventListener('pointerleave', () => { spot.hidden = true; });
}
