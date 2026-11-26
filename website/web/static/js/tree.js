"use strict";
// From : https://bl.ocks.org/d3noob/43a860bc0024792f8803bba8ca0d5ecd

// Set the dimensions and margins of the diagram
let margin = {
    top: document.getElementById('menu_horizontal_content').clientHeight + 30,
    right: 200,
    bottom: 10,
    left: 90
};

let menuHeight = document.getElementById('menu_vertical').clientHeight + 60;
let min_height = menuHeight * 2;

// The capture bar (#menu_vertical) is as wide as the page, the menus are in it
let min_width = document.getElementById('menu_vertical').clientWidth;

let node_width = 10;
let node_height = 55;
let center_node = null;

// Keys selected in the legend filter (tree/legend.html): the nodes having at
// least one of them are highlighted, the others dimmed.
const active_filters = new Set();

document.getElementById('tree_svg').style.width = min_width;
document.getElementById('tree_svg').style.height = min_height;

let main_svg = d3.select("#tree_svg").append("svg")
            .attr("width", min_width + margin.right + margin.left)
            .attr("height", min_height + margin.top + margin.bottom)

// Zoom of the tree (buttons of #tree-zoom, Ctrl + wheel): the SVG is drawn at its
// size times tree_zoom, its viewBox keeps the coordinates of the layout (svg_size).
// Limits: below, the cards are unreadable; above, a card no longer fits the window
const ZOOM_MIN = 0.25;
const ZOOM_MAX = 2;
let tree_zoom = 1;
let svg_size = {width: min_width + margin.right + margin.left, height: min_height + margin.top + margin.bottom};

function applyZoom() {
    main_svg.attr('viewBox', `0 0 ${svg_size.width} ${svg_size.height}`)
            .attr('width', svg_size.width * tree_zoom)
            .attr('height', svg_size.height * tree_zoom);
    updateColumns();
}

// Zoom, keeping the point under the pointer (or the centre of the window) in place
function setZoom(zoom, client_x=null, client_y=null) {
    zoom = Math.min(ZOOM_MAX, Math.max(ZOOM_MIN, Math.round(zoom * 100) / 100));
    if (zoom === tree_zoom) return;
    const rect = main_svg.node().getBoundingClientRect();
    const cx = client_x ?? window.innerWidth / 2;
    const cy = client_y ?? window.innerHeight / 2;
    const point_x = (cx - rect.left) / tree_zoom;
    const point_y = (cy - rect.top) / tree_zoom;
    const old_zoom = tree_zoom;
    tree_zoom = zoom;
    applyZoom();
    window.scrollTo({left: window.scrollX + point_x * (zoom - old_zoom), top: window.scrollY + point_y * (zoom - old_zoom), behavior: 'instant'});
    updateZoomButtons();
}

// Bring the first node of the tree (the root) to the middle of the window, under
// the capture bar (after a drag or a zoom that went far). As far as the free
// room around the tree (css/tree.css, half the window) allows.
// smooth: a short glide to the node (the Center button, the opening of the page);
// instant when the user prefers reduced motion
function centerOnRoot(align='middle', smooth=true) {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) smooth = false;
    // The first node of the tree: the one without parent (not the first <g> of
    // the SVG, whose order changes when nodes are expanded / collapsed)
    const root_node = node_container.selectAll('g.node').filter(d => !d.parent).node();
    if (!root_node) return;
    // The card of the node, not its group: Firefox gives the <g> a box that also
    // covers its hidden parts, and the view went far from the node
    const card = root_node.querySelector('.node_data > rect') || root_node;
    const box = card.getBoundingClientRect();
    const top = parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--lk-capture-top-height')) || 0;
    window.scrollTo({
        // align 'left': the node near the left edge (opening of the page)
        left: align === 'left' ? window.scrollX + box.left - 40
                               : window.scrollX + box.left + box.width / 2 - window.innerWidth / 2,
        top: window.scrollY + box.top + box.height / 2 - (top + window.innerHeight) / 2,
        behavior: smooth ? 'smooth' : 'instant'});
}

// Show the zoom, and disable - / + at the limits
function updateZoomButtons() {
    const reset = document.getElementById('tree-zoom-reset');
    if (reset) reset.textContent = `${Math.round(tree_zoom * 100)} %`;
    const zoom_out = document.getElementById('tree-zoom-out');
    if (zoom_out) zoom_out.disabled = tree_zoom <= ZOOM_MIN;
    const zoom_in = document.getElementById('tree-zoom-in');
    if (zoom_in) zoom_in.disabled = tree_zoom >= ZOOM_MAX;
}

function setupZoom() {
    document.getElementById('tree-zoom-in')?.addEventListener('click', () => setZoom(tree_zoom * 1.2));
    document.getElementById('tree-zoom-out')?.addEventListener('click', () => setZoom(tree_zoom / 1.2));
    document.getElementById('tree-zoom-reset')?.addEventListener('click', () => setZoom(1));
    document.getElementById('tree-center')?.addEventListener('click', () => centerOnRoot());
    // Ctrl + wheel over the tree: zoom the tree, not the page
    document.getElementById('tree_svg').addEventListener('wheel', (event) => {
        if (!event.ctrlKey) return;
        event.preventDefault();
        setZoom(tree_zoom * Math.exp(-event.deltaY * 0.0015), event.clientX, event.clientY);
    }, {passive: false});
}
setupZoom();

// dummy container for tooltip
d3.select('body')
    .append('div')
    .attr('id', 'tooltip')
    .attr('class', 'tooltip')
    .attr('style', 'position: absolute; opacity: 0;');

// Define SVGs
let defs = main_svg.append("defs");

// Add background pattern
let pattern = defs.append('pattern')
    .attr('id', 'backstripes')
    .attr('x', margin.left)
    .attr("width", node_width * 2)
    .attr("height", min_height)
    .attr('patternUnits', "userSpaceOnUse" )

pattern.append('rect')
    .attr('width', node_width)
    .attr('height', min_height)
    .attr("fill", "#EEEEEE");

// Background of the tree (#tree-background buttons): columns (default, one
// stripe per depth), dots or plain. All drawn by CSS on the body, so the whole
// page has them, not only the tree. Remembered in localStorage.
const BACKGROUNDS = {columns: 'none', dots: 'none', plain: 'none'};
const BACKGROUND_KEY = 'lk-tree-background';
let tree_background = 'columns';
// Width of one depth of the tree (layout coordinates), for the columns
let column_width = node_width;

// Columns on the body: aligned on the depths of the tree, at the current zoom
function updateColumns() {
    const svg = main_svg.node();
    const left = svg.getBoundingClientRect().left + window.scrollX + margin.left * tree_zoom;
    const style = document.body.style;
    style.setProperty('--lk-tree-column-width', `${column_width * tree_zoom}px`);
    style.setProperty('--lk-tree-column-left', `${left}px`);
}
window.addEventListener('resize', updateColumns);
try {
    const stored = localStorage.getItem(BACKGROUND_KEY);
    if (stored in BACKGROUNDS) tree_background = stored;
} catch (e) { /* storage unavailable: default */ }

function setBackground(name) {
    if (!(name in BACKGROUNDS)) return;
    tree_background = name;
    main_svg.select('#tree-background-rect').style('fill', BACKGROUNDS[name]);
    // On the body: its background fills the whole page, however far it scrolls
    document.body.classList.toggle('lk-bg-dots', name === 'dots');
    document.body.classList.toggle('lk-bg-columns', name === 'columns');
    if (name === 'columns') updateColumns();
    document.querySelectorAll('#tree-background [data-background]').forEach(button => {
        button.setAttribute('aria-pressed', button.dataset.background === name ? 'true' : 'false');
        button.classList.toggle('active', button.dataset.background === name);
    });
    try {
        localStorage.setItem(BACKGROUND_KEY, name);
    } catch (e) { /* not remembered */ }
}

document.querySelectorAll('#tree-background [data-background]').forEach(button => {
    button.addEventListener('click', () => setBackground(button.dataset.background));
});

// append the svg object to the body of the page
// appends a 'group' element to 'svg'
// moves the 'group' element to the top left margin
let node_container = main_svg.append("g")
                             .attr("transform", `translate(${margin.left}, ${margin.top})`);

// declares a tree layout
let tree = d3.tree();

try {
  const treeDumpURL = document.getElementById('tree_js').dataset.remote;
  const response = await fetch(treeDumpURL);
  if (!response.ok) {
    throw new Error(`Response status: ${response.status}`);
  }

  const treeData = await response.json();

  // Assigns parent, children, height, depth
  let root = d3.hierarchy(treeData);
  root.x0 = min_height / 2;
  root.y0 = 0;

  update(root);
  setupLegendFilter(root);
  document.getElementById("tree-loading").style.display = "none";

  if (document.getElementById('tree_js').dataset.urlnode != null){
    history.scrollRestoration = "manual";
    LocateNode(document.getElementById('tree_js').dataset.urlnode);
  } else {
    // Open on the first node, near the left edge, the tree going right (it used
    // to scroll smoothly to the node of the rendered page, at the bottom)
    history.scrollRestoration = "manual";
    centerOnRoot('left');
  }

  if (parent_uuid != null) {

      let parent_box_y = root.y - 70;
      let parent_box_x = root.x - 150;

      let parent_rect = node_container.append('rect')
        .attr("rx", 6)
        .attr("ry", 6)
        .attr("transform", `translate(${parent_box_y}, ${parent_box_x})`)
        .style("opacity", "0.5")
        .attr("stroke", 'black')
        .attr('stroke-opacity', "0.8")
        .attr("stroke-width", "2")
        .attr("stroke-linecap", "round")
        .attr("fill", "white")

      let text = node_container
          .data([
              {
                  "line1": 'This capture was triggered',
                  "line2": 'from a previous capture.',
                  "line3": 'See the parent',
                  "parent_uuid": parent_uuid
              }
          ])
          .append('text')
          .attr("dy", 0)
          .style("font-size", "12px")
          .style('text-align', 'center')
          .attr("transform", `translate(${parent_box_y + 3}, ${parent_box_x + 15})`);

      text
          .append('tspan')
          .text(d => d.line1);

      text
          .append('tspan')
          .attr("x", 8)
          .attr("dy", 18)
          .text(d => d.line2);

      text
          .append('tspan')
          .attr("x", 30)
          .attr("dy", 20)
          .text(d => d.line3)
          .style('fill', '#0000EE')
          .attr('cursor', 'pointer')
          .on('click', (event, d) => { openTreeInNewTab(d.parent_uuid) } );

      parent_rect
          .attr('width', text.node().getBBox().width + 6)
          .attr('height', text.node().getBBox().height + 10)

      let line_arrow = node_container
                         .append('g');
                         //.attr("transform", `translate(${root.y}, ${root.x})`);

      let line = d3.line()
                      // Other options: http://bl.ocks.org/d3indepth/raw/b6d4845973089bc1012dec1674d3aff8/
                      //.curve(d3.curveCardinal)
                      .curve(d3.curveBundle)
                      .x(point => point.lx)
                      .y(point => point.ly);

      let line_tip = d3.symbol()
                      .type(d3.symbolTriangle)
                      .size(200);

      line_arrow
          .append("path")
          .attr('stroke-opacity', "0.7")
          .attr("stroke-width", "2")
          .attr("stroke", "black")
          .attr("fill", "none")
          .data([{
              source: {x: 0, y: parent_box_x + parent_rect.node().getBBox().height},
              target: {x: 50, y: parent_box_x + parent_rect.node().getBBox().height + 42}
          }])
          .attr("class", "line")
          .attr("d", d => line(
              [{lx: d.source.x, ly: d.source.y},
               {lx: d.target.x, ly: d.source.y},
               {lx: d.target.x, ly: d.target.y}
              ])
          );

      line_arrow
          .append("path")
          .attr("d", line_tip)
          .attr("stroke", 'black')
          .attr('stroke-opacity', "0.8")
          .style('stroke-width', '1.5')
          .attr("fill-opacity", '0')
          .attr("transform", `translate(50, ${parent_box_x + parent_rect.node().getBBox().height + 48}) rotate(60)`);
  };
} catch (error) {
  console.error(error.message);
  document.getElementById("tree-loading").style.display = "none";
}


// ****************** Legend & icon filter (tree/legend.html) ******************

// Does the node have this icon? Same test as icon_list(): true, a non-empty
// string, a number > 0 or a non-empty list.
function nodeHas(d, key) {
    const value = d.data[key];
    if (value instanceof Array) return value.length > 0;
    if (typeof value === 'number') return value > 0;
    return Boolean(value);
}

function applyLegendFilter() {
    const filtering = active_filters.size > 0;
    let matches = 0;
    node_container.selectAll('g.node').each(function(d) {
        const match = filtering && [...active_filters].some(key => nodeHas(d, key));
        if (match) matches++;
        d3.select(this)
          .classed('is-filter-match', match)
          .classed('is-filter-dimmed', filtering && !match);
    });
    const active = document.getElementById('legend-active');
    if (active) {
        active.hidden = !filtering;
        active.textContent = filtering ? `${matches} node${matches === 1 ? '' : 's'}` : '';
    }
    const clear = document.getElementById('legend-clear');
    if (clear) clear.hidden = !filtering;
}

function setupLegendFilter(root) {
    const present = document.getElementById('legend-present');
    if (!present) return;
    const absent = document.getElementById('legend-absent');
    const nodes = root.descendants();
    let absent_count = 0;
    present.querySelectorAll('.lk-legend-item').forEach(button => {
        const key = button.dataset.key;
        const count = nodes.filter(d => nodeHas(d, key)).length;
        button.querySelector('.lk-legend-count').textContent = count;
        if (count === 0) {
            // Icons that are not in this capture: in the collapsed "Not in this capture"
            button.disabled = true;
            absent.appendChild(button.closest('li'));
            absent_count++;
            return;
        }
        button.title = `${button.title}: ${count} of ${nodes.length} nodes`;
        button.addEventListener('click', () => {
            if (active_filters.has(key)) active_filters.delete(key);
            else active_filters.add(key);
            button.setAttribute('aria-pressed', active_filters.has(key) ? 'true' : 'false');
            applyLegendFilter();
        });
    });
    // Most frequent first
    [...present.children]
        .sort((a, b) => b.querySelector('.lk-legend-count').textContent - a.querySelector('.lk-legend-count').textContent)
        .forEach(li => present.appendChild(li));
    document.getElementById('legend-absent-count').textContent = absent_count;
    document.getElementById('legend-absent-panel').hidden = absent_count === 0;
    document.getElementById('legend-clear').addEventListener('click', () => {
        active_filters.clear();
        present.querySelectorAll('.lk-legend-item').forEach(b => b.setAttribute('aria-pressed', 'false'));
        applyLegendFilter();
    });
    // The tree is drawn: the legend appears, open (css/tree.css, .is-ready)
    const legend = document.getElementById('legend');
    legend.open = true;
    requestAnimationFrame(() => legend.classList.add('is-ready'));
}

function open_hostnode_popup(hostnode_uuid) {
    // /tree is kept, append the paramaters (seed, if present)
    let win = window.open(`/tree/${treeUUID}/host/${hostnode_uuid}${document.location.search}`, '_blank', 'width=1024,height=768,left=200,top=100');
    if (win == null) {
        alert("The browser didn't allow Lookyloo to open a pop-up. There should be an icon on the right of your URL bar to allow it.");
    }
    win.focus();
}

function UnbookmarkAllNodes() {
    d3.selectAll('.node_data').select('rect').style('fill', 'white');
    d3.selectAll('.node_data').select('text').style('fill', 'black');
    d3.selectAll('.node_data').select("#bookmark")
        .text("🏁")
        .on('click', (event, d) => NodeHighlight(d.data.uuid))
        .on('mouseover', (event, d) => {
            d3.select('#tooltip')
                .style('opacity', 1)
                .style('left', `${event.pageX + 10}px`)
                .style('top', `${event.pageY + 10}px`)
                .text('Bookmark this node');
        })
        .on('mouseout', (event, d) => d3.select('#tooltip').style('opacity', 0));
};

function MarkAsKnown(capture_uuid, hostnode_uuid=null, urlnode_uuid=null) {
  let data = {};
  if (hostnode_uuid != null) { data['hostnode_uuid'] = hostnode_uuid; };
  if (urlnode_uuid != null) { data['urlnode_uuid'] = urlnode_uuid; };
  $.post(`/tree/${capture_uuid}/mark_as_legitimate`, data);
};

function UnbookmarkHostNode(hostnode_uuid) {
    d3.select(`#node_${hostnode_uuid}`).select('rect').style('fill', 'white');
    d3.select(`#node_${hostnode_uuid}`).select('text').style('fill', 'black');
    d3.select(`#node_${hostnode_uuid}`).select("#bookmark")
        .text("🏁")
        .on('click', (event, d) => NodeHighlight(d.data.uuid))
        .on('mouseover', (event, d) => {
            d3.select('#tooltip')
                .style('opacity', 1)
                .style('left', `${event.pageX + 10}px`)
                .style('top', `${event.pageY + 10}px`)
                .text('Bookmark this node');
        })
        .on('mouseout', (event, d) => d3.select('#tooltip').style('opacity', 0));
};

function NodeHighlight(hostnode_uuid) {
    let element = document.getElementById(`node_${hostnode_uuid}`);
    element.scrollIntoView({behavior: "smooth", block: "center", inline: "nearest"});

    d3.select(`#node_${hostnode_uuid}`).select('rect').style('fill', 'black');
    d3.select(`#node_${hostnode_uuid}`).select('text').style('fill', 'white');
    d3.select(`#node_${hostnode_uuid}`).select("#bookmark")
        .text('❌')
        .on('click', (event, d) => UnbookmarkHostNode(d.data.uuid))
        .on('mouseover', (event, d) => {
            d3.select('#tooltip')
                .style('opacity', 1)
                .style('left', `${event.pageX + 10}px`)
                .style('top', `${event.pageY + 10}px`)
                .text('Remove bookmark on this node');
        })
        .on('mouseout', (event, d) => d3.select('#tooltip').style('opacity', 0));
};

function icon_list(relative_x_pos, relative_y_pos, d) {
    const icon_size = 16;
    const icon_options = new Map([
        ['js', {path: "/static/images/ui/javascript.png", tooltip: "URL(s) loading Javascript"}],
        ['exe', {path: "/static/images/ui/exe.png", tooltip: "URL(s) loading executables"}],
        ['css', {path: "/static/images/ui/css.png", tooltip: "URL(s) loading CSS"}],
        ['font', {path: "/static/images/ui/font.png", tooltip: "URL(s) loading fonts"}],
        ['html', {path: "/static/images/ui/html.png", tooltip: "URL(s) loading HTML"}],
        ['json', {path: "/static/images/ui/json.png", tooltip: "URL(s) loading Json"}],
        ['iframe', {path: "/static/images/ui/ifr.png", tooltip: "URL(s) loaded from an Iframe"}],
        ['image', {path: "/static/images/ui/img.png", tooltip: "URL(s) loading images"}],
        ['unknown_mimetype', {path: "/static/images/ui/wtf.png", tooltip: "URL(s) loading contents of an unknown type"}],
        ['video', {path: "/static/images/ui/video.png", tooltip: "URL(s) loading videos"}],
        ['request_cookie', {path: "/static/images/ui/cookie_read.png", tooltip: "cookie(s) sent to the server in the request"}],
        ['response_cookie', {path: "/static/images/ui/cookie_received.png", tooltip: "cookie(s) received in the response"}],
        ['redirect', {path: "/static/images/ui/redirect.png", tooltip: "redirect(s)"}],
        ['redirect_to_nothing', {path: "/static/images/ui/cookie_in_url.png", tooltip: "redirect(s) to URL(s) missing in the capture"}],
        ['empty', {path: "/static/images/ui/empty.svg", tooltip: "URL(s) returning no content"}],
        ['downloaded_filename', {path: "/static/images/ui/download.png", tooltip: "contains a downloaded file."}],
        ['websocket_session', {path: "/static/images/ui/websocket.svg", tooltip: "contains a websocket session."}],
        ['posted_data', {path: "/static/images/ui/send-arrow-up.svg", tooltip: "POSTs content."}]
    ]);

    // Put all the icone in one sub svg document
    let icons = d3.create("svg")
          .attr('x', relative_x_pos)
          .attr('y', relative_y_pos)
          .attr('class', 'icons_list');

    icon_options.forEach(function(icon_details, key) {
        let has_icon = false;
        let counter = 0;
        if (typeof d.data[key] === 'boolean') {
          has_icon = d.data[key];
        } else if (typeof d.data[key] === 'string') {
            has_icon = d.data[key];
        } else if (typeof d.data[key] === 'number') {
          has_icon = d.data[key] > 0;
          counter = d.data[key];
        } else if (d.data[key] instanceof Array) {
          has_icon = d.data[key].length > 0;
          counter = d.data[key].length;
        };
        if (has_icon) {
          let icon_group = icons
                .append("svg")
                .attr('class', 'icon')
                .attr("id", `icons_${key}`);
          icon_group
              .append('image')
              .attr("width", icon_size)
              .attr("height", icon_size)
              .attr("xlink:href", icon_details.path)
              .on('mouseover', (event, d) => {
                  d3.select('#tooltip')
                      .style('opacity', 1)
                      .style('left', `${event.pageX + 10}px`)
                      .style('top', `${event.pageY + 10}px`)
                      .text(counter? `${counter} ${icon_details.tooltip}`:icon_details.tooltip);
              })
              .on('mouseout', (event, d) => d3.select('#tooltip').style('opacity', 0));
          if (counter > 0) {
            icon_group
                .append('text')
                .attr("dy", 8)
                .style("font-size", "10px")
                .attr('x', icon_size + 1)
                .text(counter);
          };
        };
    })
    return icons.node();
}

function text_entry(relative_x_pos, relative_y_pos, d) {
    // Avoid hiding the content after the circle
    let nodeContent = d3.create("svg")  // WARNING: svg is required there, "g" doesn't have getBBox
          .attr('height', node_height)
          .attr('x', relative_x_pos)
          .attr('y', relative_y_pos)
          .datum(d);

    // Add labels for the nodes
    nodeContent.append("text")
          .attr('dy', '.9em')
          .attr("stroke", "white")
          .style("font-size", "16px")
          .attr("stroke-width", ".2px")
          .style("opacity", .9)
          .attr('cursor', 'pointer')
          .on('click', (event, d) => open_hostnode_popup(d.data.uuid))
          .on('mouseover', (event, d) => {
              d3.select('#tooltip')
                  .style('opacity', 1)
                  .style('left', `${event.pageX + 10}px`)
                  .style('top', `${event.pageY + 10}px`)
                  .text('Open investigation pop-up.');
          })
          .on('mouseout', (event, d) => d3.select('#tooltip').style('opacity', 0))
          .text(d => {
            let to_print;
            if (d.data.idna) {
                to_print = d.data.idna;
            }
            else if (d.data.name.length > 50) {
                to_print = `[...] ${d.data.name.substring(d.data.name.length - 50, d.data.name.length)}`;
            } else {
                to_print = d.data.name
            };
            return to_print;
          });

    if (d.data.idna) {
    nodeContent.append("text")
          .attr('dy', '2.6em')
          .attr('dx', '2em')
          .attr("stroke", "white")
          .style("font-size", "10px")
          .attr("stroke-width", ".2px")
          .style("opacity", .9)
          .attr('cursor', 'pointer')
          .on('click', (event, d) => open_hostnode_popup(d.data.uuid))
          .on('mouseover', (event, d) => {
              d3.select('#tooltip')
                  .style('opacity', 1)
                  .style('left', `${event.pageX + 10}px`)
                  .style('top', `${event.pageY + 10}px`)
                  .text('Open investigation pop-up.');
          })
          .on('mouseout', (event, d) => d3.select('#tooltip').style('opacity', 0))
          .text(d => { return d.data.name }
      );
    }

    return nodeContent.node();
}

// Recursively generate the tree
function update(root, computed_node_width=0) {

  // Current height of the tree (cannot use height because it isn't recomputed when we rename children -> _children)
  let max_depth = 0
  root.each(d => {
    if (d.children){
      max_depth = d.depth > max_depth ? d.depth : max_depth;
    }
  });

  if (computed_node_width != 0) {
    computed_node_width += 30;
    // Re-compute SVG size depending on the generated tree
    let svgWidth = Math.max((max_depth + 1) * computed_node_width, node_width);
    // Update height
    // node_height is the height of a node, menuHeight * 3 is the minimum so the root node isn't behind the menu
    let svgHeight = Math.max(root.descendants().reverse().length * node_height, min_height);
    tree.size([svgHeight, svgWidth])

    // Set background based on the computed width and height
    main_svg.select('#tree-background-rect').remove();
    let background = main_svg.insert('rect', ':first-child')
      .attr('id', 'tree-background-rect')
      .attr('y', 0)
      // Note: We want the background width with an extra computed_node_width
      // in order to make sure the last node is completely covered
      .attr('width', svgWidth + (margin.right + margin.left + computed_node_width))
      .attr('height', svgHeight + margin.top + margin.bottom)
      .style('fill', BACKGROUNDS[tree_background]);
    setBackground(tree_background);

    // Update size
    svg_size = {width: svgWidth + (margin.right + margin.left)*2, height: svgHeight + margin.top + margin.bottom};
    applyZoom();

    column_width = computed_node_width;
    // Update pattern
    pattern
      .attr('width', `${computed_node_width * 2}px`)
    pattern.selectAll('rect')
      .attr('width', `${computed_node_width}px`)

    let tree_bbox = main_svg.node().getBBox()
    document.getElementById('tree_svg').style.width = Math.max(tree_bbox.width, min_width);
    document.getElementById('tree_svg').style.height = Math.max(tree_bbox.height, min_height);
  }

  // Assigns the x and y position for the nodes
  let treemap = tree(root);

  // Compute the new tree layout. => Note: Need d.x & d.y
  let nodes = treemap.descendants(),
      links = treemap.descendants().slice(1);

  // ****************** Nodes section ***************************

  // Toggle children on click.
  let toggle_children_collapse = (event, d) => {
    if (d.children) {
        d._children = d.children;
        d.children = null;
    }
    else {
        d.children = d._children;
        d._children = null;
    }
    // Call update on the whole Tree
    update(d.ancestors().reverse()[0]);
  };

  // Update the nodes...
  const tree_nodes = node_container.selectAll('g.node')
      .data(nodes, node => node.data.uuid);

  tree_nodes.join(
        // Enter any new modes at the parent's previous position.
        enter => {
            let node_group = enter.append('g')
                .attr('class', 'node')
                .attr("id", d => `node_${d.data.uuid}`)
                .attr("transform", `translate(${root.y0}, ${root.x0})`);

            let node_data = node_group
              .append('svg')
              .attr('class', 'node_data')
              .attr('x', 0)
              .attr('y', -30);

            node_data.append('rect')
              .attr("rx", 6)
              .attr("ry", 6)
              .attr('x', 0)
              .attr('y', 0)
              .attr('width', 10)
              .style("opacity", "0.5")
              .attr("stroke", 'black')
              .attr('stroke-opacity', "0.8")
              .attr("stroke-width", "2")
              .attr("stroke-linecap", "round")
              .attr("fill", "white")

            // Set Hostname text
            node_data
              .append(d => text_entry(10, 5, d));  // Popup
            // Set list of icons
            node_data
              .append(d => icon_list(12, 35, d));

            node_group.select('.node_data').each(function(d){
                // set position of icons based of their length
                let cur_icon_list_len = 0;
                d3.select(this).selectAll('.icon').each(function(){
                    d3.select(this).attr('x', cur_icon_list_len);
                    cur_icon_list_len += d3.select(this).node().getBBox().width;
                });

                // Rectangle around the domain name & icons
                d3.select(this).select('rect')
                  .attr('height', node_height + 5)
                  .attr('width', d3.select(this).node().getBBox().width + 60);

                // Set the width for all the nodes
                // Required, as the node width need to include the rectangle
                // Note: removing .select('rect') breaks rendering on firefox but not on chrome.
                let selected_node_bbox = d3.select(this).select('rect').node().getBBox();
                d.node_width = selected_node_bbox.width;
                node_width = node_width > selected_node_bbox.width ? node_width : selected_node_bbox.width;

                // Set number of URLs after the hostname
                if (d.data.urls_count > 1) {
                    d3.select(this).append("text")
                        .attr('x', d => d3.select(this).select('text').node().getBBox().width + 13)
                        .attr('y', 5)
                        .attr('dy', '.9em')
                        .attr("stroke", "white")
                        .style("font-size", "16px")
                        .attr("stroke-width", ".2px")
                        .style("opacity", .9)
                        .on('mouseover', (event, d) => {
                            d3.select('#tooltip')
                                .style('opacity', 1)
                                .style('left', `${event.pageX + 10}px`)
                                .style('top', `${event.pageY + 10}px`)
                                .text(`This node contains ${d.data.urls_count} URLs.`);
                        })
                        .on('mouseout', (event, d) => d3.select('#tooltip').style('opacity', 0))
                        .text(d => {
                            return `(${d.data.urls_count})`;
                        });
                };

                // Set Bookmark
                if (enable_bookmark) {
                    d3.select(this).append("text")
                        .attr('x', `${selected_node_bbox.width - 12}px`)
                        .attr('y', '20px')
                        .style("font-size", "16px")
                        .attr("id", "bookmark")
                        .text("🏁")
                        .attr('cursor', 'pointer')
                        .on('click', (event, d) => NodeHighlight(d.data.uuid))
                        .on('mouseover', (event, d) => {
                            d3.select('#tooltip')
                                .style('opacity', 1)
                                .style('left', `${event.pageX + 10}px`)
                                .style('top', `${event.pageY + 10}px`)
                                .text('Bookmark this node');
                        })
                        .on('mouseout', (event, d) => d3.select('#tooltip').style('opacity', 0));
                };

                const thumbnail_size = 64;
                if (d.data.contains_rendered_urlnode) {
                  center_node = d.data.uuid;
                  if (favicon) {
                    d3.select(this).append('image')
                      .attr('x', selected_node_bbox.width/6)
                      .attr('y', node_height - 1)
                      .attr('id', 'favicon')
                      .attr("width", 32)
                      .attr("height", 32)
                      .attr("xlink:href", `data:${mime_favicon};base64,${favicon}`)
                      .attr('cursor', 'pointer')
                      .on('mouseover', (event, d) => {
                          d3.select('#tooltip')
                            .style('opacity', 1)
                            .style('left', `${event.pageX + 10}px`)
                            .style('top', `${event.pageY + 10}px`)
                            .text('Potential favicon.');
                      });
                  }
                  d3.select(this).append("svg").append('rect')
                    .attr('x', selected_node_bbox.width/2)
                    .attr('y', node_height - 3)
                    .attr('width', thumbnail_size)
                    .attr('height', thumbnail_size)
                    .attr('fill', 'white')
                    .attr('stroke', 'black');

                  d3.select(this).append('image')
                    .attr('x', selected_node_bbox.width/2)
                    .attr('y', node_height - 3)
                    .attr('id', 'screenshot_thumbnail')
                    // blurred like the screenshot, until it is unblurred (js/tree_modals.js)
                    .attr('class', document.getElementById('screenshot')?.classList.contains('blur') === false ? null : 'blur')
                    .attr("width", thumbnail_size)
                    .attr("height", thumbnail_size)
                    .attr("xlink:href",`data:image/png;base64,${screenshot_thumbnail}`)
                    .attr('cursor', 'pointer')
                    .on('mouseover', (event, d) => {
                        d3.select('#tooltip')
                          .data(d)
                          .style('opacity', 1)
                          .style('left', `${event.pageX + 10}px`)
                          .style('top', `${event.pageY + 10}px`)
                          .text(d => d.data.downloaded_filename ? 'Contains the URL rendered in the browser. It also downloaded a file.': 'Contains the URL rendered in the browser.');
                    })
                    .on('click', (event, d) => {
                        new bootstrap.Modal('#screenshotModal')
                            .show(document.getElementById('screenshotModal'));
                    })
                    .on('mouseout', (event, d) => {
                        d3.select('#tooltip').style('opacity', 0)
                    });
                };

                const http_icon_size = 24;
                if (d.data.http_content) {
                    // set lock insecure connection
                    d3.select(this).append("svg").append('rect')
                        .attr('x', selected_node_bbox.width - 22)
                        .attr('y', selected_node_bbox.height - 13)
                        .attr('width', http_icon_size)
                        .attr('height', http_icon_size)
                        .attr('fill', 'white')
                        .attr('stroke', 'black');

                    d3.select(this).append('image')
                        .attr('x', selected_node_bbox.width - 22)
                        .attr('y', selected_node_bbox.height - 13)
                        .attr('id', 'insecure_image')
                        .attr("width", http_icon_size)
                        .attr("height", http_icon_size)
                        .attr("xlink:href", '/static/images/ui/insecure.svg')
                        .on('mouseover', (event, d) => {
                            d3.select('#tooltip')
                                .style('opacity', 1)
                                .style('left', `${event.pageX + 10}px`)
                                .style('top', `${event.pageY + 10}px`)
                                .text('This node containts insecure requests');
                        })
                        .on('mouseout', (event, d) => d3.select('#tooltip').style('opacity', 0));
                };
                const context_icon_size = 24;
                if (d.data.malicious) {
                    // set bomb
                    d3.select(this).append("svg").append('rect')
                        .attr('x', selected_node_bbox.width - 22 - http_icon_size)
                        .attr('y', selected_node_bbox.height - 13)
                        .attr('width', context_icon_size)
                        .attr('height', context_icon_size)
                        .attr('fill', 'white')
                        .attr('stroke', 'black');

                    d3.select(this).append('image')
                        .attr('x', selected_node_bbox.width - 22 - http_icon_size)
                        .attr('y', selected_node_bbox.height - 13)
                        .attr('id', 'malicious_image')
                        .attr("width", context_icon_size)
                        .attr("height", context_icon_size)
                        .attr("xlink:href", '/static/images/ui/bomb.svg')
                        .on('mouseover', (event, d) => {
                            d3.select('#tooltip')
                                .style('opacity', 1)
                                .style('left', `${event.pageX + 10}px`)
                                .style('top', `${event.pageY + 10}px`)
                                .text('This node containts known malicious content');
                        })
                        .on('mouseout', (event, d) => d3.select('#tooltip').style('opacity', 0));
                } else if (d.data.legitimate) {
                    // set checkmark
                    d3.select(this).append("svg").append('rect')
                        .attr('x', selected_node_bbox.width - 22 - http_icon_size)
                        .attr('y', selected_node_bbox.height - 13)
                        .attr('width', context_icon_size)
                        .attr('height', context_icon_size)
                        .attr('fill', 'white')
                        .attr('stroke', 'black');

                    d3.select(this).append('image')
                        .attr('x', selected_node_bbox.width - 22 - http_icon_size)
                        .attr('y', selected_node_bbox.height - 13)
                        .attr('id', 'known_image')
                        .attr("width", context_icon_size)
                        .attr("height", context_icon_size)
                        .attr("xlink:href", '/static/images/ui/check.svg')
                        .on('mouseover', (event, d) => {
                            d3.select('#tooltip')
                                .style('opacity', 1)
                                .style('left', `${event.pageX + 10}px`)
                                .style('top', `${event.pageY + 10}px`)
                                .text('This node has only known content');
                        })
                        .on('mouseout', (event, d) => d3.select('#tooltip').style('opacity', 0));
              } else if (d.data.all_empty && !d.data.contains_rendered_urlnode) {
                // set empty
                d3.select(this).append("svg").append('rect')
                    .attr('x', selected_node_bbox.width - 22 - http_icon_size)
                    .attr('y', selected_node_bbox.height - 13)
                    .attr('width', context_icon_size)
                    .attr('height', context_icon_size)
                    .attr('fill', 'white')
                    .attr('stroke', 'black');

                d3.select(this).append('image')
                    .attr('x', selected_node_bbox.width - 22 - http_icon_size)
                    .attr('y', selected_node_bbox.height - 13)
                    .attr('id', 'empty_image')
                    .attr("width", context_icon_size)
                    .attr("height", context_icon_size)
                    .attr("xlink:href", '/static/images/ui/empty.svg')
                    .on('mouseover', (event, d) => {
                        d3.select('#tooltip')
                            .style('opacity', 1)
                            .style('left', `${event.pageX + 10}px`)
                            .style('top', `${event.pageY + 10}px`)
                            .text('This node has only empty content');
                    })
                    .on('mouseout', (event, d) => d3.select('#tooltip').style('opacity', 0));
              };
              if (d.children || d._children) {
                d3.select(this)
                  // Add Circle for the nodes
                  .append('circle')
                  .attr('class', 'node')
                  .attr('r', 1e-6)
                  .attr('cx', d => d.node_width)
                  .attr('cy', d => node_height/2)
                  .style("fill", d => d._children ? "lightsteelblue" : "#fff")
                  .on('mouseover', (event, d) => {
                      if (d.children || d._children) {
                        d3.select('#tooltip')
                          .style('opacity', 1)
                          .style('left', `${event.pageX + 10}px`)
                          .style('top', `${event.pageY + 10}px`)
                          .text(d.children ? 'Collapse the URLs loaded by this node.' : 'Expand the URLs loaded by this node.');
                      };
                    }
                  )
                  .on('mouseout', (event, d) => {
                      if (d.children || d._children) {
                        d3.select('#tooltip').style('opacity', 0)
                      };
                    }
                  )
                  .on('click', (event, d) => {
                      if (d.children || d._children) {
                        toggle_children_collapse(event, d)
                      };
                    }
                  );
              };
            });

            return node_group;
        },
        update => update,
        exit => exit
            .transition()
              // Remove any exiting nodes
              .attr("transform", node => `translate(${node.y0}, ${node.x0})`)
              // On exit reduce the node circles size to 0
              .attr('r', 1e-6)
              // On exit reduce the opacity of text labels
              .style('fill-opacity', 1e-6)
              .remove()
    ).call(node => {
      node
        // Transition to the proper position for the node
        .attr("transform", node => `translate(${node.y}, ${node.x})`)
        // Update the node attributes and style
        .select('circle.node')
          .attr('r', 10)
          .style("fill", node => node._children ? "lightsteelblue" : "#fff")
          .attr('cursor', (d) => {
            if (d.children || d._children) {
              return 'pointer';
            }
          });

    });

  nodes.forEach(d => {
    // Store the old positions for transition.
    d.x0 = d.x;
    d.y0 = d.y;
  });

  // ****************** links section ***************************

  // Update the links...
  const link = node_container.selectAll('path.link').data(links, d => d.id);

  // Creates a curved (diagonal) path from parent to the child nodes
  let diagonal = d3.linkHorizontal()
                        .source(d => {return [d.y, d.x]})
                        .target(d => {return [d.parent.y + d.parent.node_width, d.parent.x]});

  link.join(
    enter => enter
        // Enter any new links at the parent's previous position.
        .insert('path', "g")
        .attr("class", "link")
        .attr('d', diagonal)
        .style('fill', 'none')
        .style('stroke', '#ccc')
        .style('stroke-width', '2px'),
    update => update,
    exit => exit.call(exit => exit.attr('d', diagonal).remove())
  ).call(link => link.attr('d', diagonal));

  if (computed_node_width === 0) {
    update(root, node_width)
  }
  // Nodes shown again after an expand keep the legend filter
  if (active_filters.size > 0) applyLegendFilter();
}
