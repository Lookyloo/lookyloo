// From : https://bl.ocks.org/d3noob/43a860bc0024792f8803bba8ca0d5ecd

// Set the dimensions and margins of the diagram
var margin = {top: 20, right: 200, bottom: 30, left: 90},
    width = 960 - margin.left - margin.right,
    height = 1000 - margin.top - margin.bottom;

var node_width = 0;
var max_overlay_width = 1500;
var default_max_overlay_height = 500;
var node_height = 55;
var t = d3.transition().duration(750);

var main_svg = d3.select("body").append("svg")
            .attr("width", width + margin.right + margin.left)
            .attr("height", height + margin.top + margin.bottom)

main_svg.append("clipPath")
    .attr("id", "textOverlay")
    .append("rect")
    .attr('width', max_overlay_width - 25)
    .attr('height', node_height);

main_svg.append("clipPath")
    .attr("id", "overlayHeight")
    .append("rect")
    .attr('width', max_overlay_width)
    .attr('height', default_max_overlay_height + 100);


// Add background pattern
var pattern = main_svg.append("defs").append('pattern')
    .attr('id', 'backstripes')
    .attr('x', margin.left)
    .attr("width", node_width * 2)
    .attr("height", 10)
    .attr('patternUnits', "userSpaceOnUse" )

pattern.append('rect')
    .attr('width', node_width)
    .attr('height', height)
    .attr("fill", "#EEEEEE");

// append the svg object to the body of the page
// appends a 'group' element to 'svg'
// moves the 'group' element to the top left margin
var node_container = main_svg
  .append("g")
  .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

var i = 0,
    duration = 750;

// Assigns parent, children, height, depth
var root = d3.hierarchy(treeData);
root.x0 = height / 2;  // middle of the page
root.y0 = 0;

// declares a tree layout
var tree = d3.tree();
update(root);

// Collapse the node and all it's children
function collapse(d) {
  if(d.children) {
    d._children = d.children
    d._children.forEach(collapse)
    d.children = null
  }
};

function urlnode_click(d) {
    var url = "/tree/url/" + d.data.uuid;
    d3.blob(url, {credentials: 'same-origin'}).then(data => {
        saveAs(data, 'file.zip');
    });
};

d3.selection.prototype.moveToFront = function() {
  return this.each(function() {
    this.parentNode.appendChild(this);
  });
};

d3.selection.prototype.moveToBack = function() {
    return this.each(function() {
        var firstChild = this.parentNode.firstChild;
        if (firstChild) {
            this.parentNode.insertBefore(this, firstChild);
        }
    });
};

// What happen when clicking on a domain (load a modal display)
function hostnode_click(d) {
    // Move the node to the front (end of the list)
    var cur_node = d3.select("#node_" + d.data.uuid).moveToFront();
    // Avoid duplicating overlays
    cur_node.selectAll('.overlay').remove();
    // Insert new svg element at this position
    var overlay_hostname = cur_node.append('g')
                                .attr('class', 'overlay');

    cur_node.append('line')
                .attr('id', 'overlay_link')
                .style("opacity", "0.95")
                .attr("stroke-width", "2")
                .style("stroke", "gray");

    var top_margin = 15;
    var overlay_header_height = 50;
    var left_margin = 30;

    overlay_hostname
        .datum({x: 0, y: 0, overlay_uuid: d.data.uuid})
        .attr('id', 'overlay_' + d.data.uuid)
        .attr("transform", "translate(" + 10 + "," + 15 + ")")
        .call(d3.drag().on("drag", function(d, i) {
            if (typeof d.x === 'undefined') { d.x = 0; }  // Any real JS dev would kill me fo that, right?
            if (typeof d.y === 'undefined') { d.y = 0; }  // Maybe even twice.
            d.x += d3.event.dx
            d.y += d3.event.dy
            d3.select(this)
                .attr("transform", "translate(" + d.x + "," + d.y + ")");
            cur_node.select('#overlay_link')
                .attr("x2", d.x + left_margin + 10)
                .attr("y2", d.y + top_margin + 15);
        }));

    overlay_hostname.append('rect')
        .attr("rx", 6)
        .attr("ry", 6)
        .attr('x', 15)
        .attr('y', 10)
        .style("opacity", "0.95")
        .attr("stroke", "black")
        .attr('stroke-opacity', "0.8")
        .attr("stroke-width", "2")
        .attr("stroke-linecap", "round")
        .attr("fill", "white");

    // Modal display
    var url = "/tree/hostname/" + d.data.uuid;
    d3.json(url, {credentials: 'same-origin'}).then(urls => {
        overlay_hostname
            .append('circle')
            .attr('id', 'overlay_circle_' + d.data.uuid)
            .attr('height', overlay_header_height)
            .attr('cx', left_margin + 10)
            .attr('cy', top_margin + 15)
            .attr('r', 2);

        overlay_hostname
            .append('text')
            .attr('id', 'overlay_close_' + d.data.uuid)
            .attr('height', overlay_header_height)
            .attr('x', left_margin + 500)  // Value updated based on the size of the rectangle max: max_overlay_width
            .attr('y', top_margin + 25)
            .style("font-size", '30px')
            .text('\u2716')
            .attr('cursor', 'pointer')
            .on("click", () => {
                    main_svg.selectAll('#overlay_' + d.data.uuid).remove();
                    cur_node.select('#overlay_link').remove();
                }
            );

        overlay_hostname.append('line')
            .attr('id', 'overlay_separator_header' + d.data.uuid)
            .style("stroke", "black")
            .style('stroke-width', "1px")
            .attr('x1', 20)
            .attr('y1', overlay_header_height)
            .attr('x2', 500)
            .attr('y2', overlay_header_height);

        var url_entries = overlay_hostname.append('svg');

        var interval_entries = 40;
        urls.forEach((url, index, array) => {
            var jdata = JSON.parse(url)
            url_entries.datum({'data': jdata});
            url_entries.append(d => text_entry(left_margin, top_margin + overlay_header_height + (interval_entries * index), urlnode_click, d));
            url_entries.append(d => icon_list(left_margin + 5, top_margin + 20 + overlay_header_height + (interval_entries * index), d));
        });

        var overlay_bbox = overlay_hostname.node().getBBox()
        overlay_hostname.append('line')
            .attr('id', 'overlay_separator_footer' + d.data.uuid)
            .style("stroke", "black")
            .style('stroke-width', "1px")
            .attr('x1', 20)
            .attr('y1', overlay_bbox.height + 20)
            .attr('x2', 500)
            .attr('y2', overlay_bbox.height + 20);

        var overlay_bbox = overlay_hostname.node().getBBox()
        overlay_hostname
            .append('text')
            .attr('id', 'overlay_download_' + d.data.uuid)
            .attr('height', overlay_header_height - 10)
            .attr('x', left_margin)
            .attr('y', overlay_bbox.height + overlay_header_height)
            .style("font-size", '20px')
            .text('Download URLs as text')
            .attr('cursor', 'pointer')
            .on("click", () => {
                var url = "/tree/hostname/" + d.data.uuid + '/text';
                d3.blob(url, {credentials: 'same-origin'}).then(data => {
                    saveAs(data, 'file.md');
                });
            });

        var overlay_bbox = overlay_hostname.node().getBBox();
        overlay_hostname.select('rect')
            .attr('width', () => {
                optimal_size = overlay_bbox.width + left_margin
                return optimal_size < max_overlay_width ? optimal_size : max_overlay_width;
            })
            .attr('height', overlay_bbox.height + overlay_header_height);

        overlay_hostname.select('#overlay_close_' + d.data.uuid)
            .attr('x', overlay_hostname.select('rect').node().getBBox().width - 20);

        overlay_hostname.select('#overlay_separator_header' + d.data.uuid)
            .attr('x2', overlay_hostname.select('rect').node().getBBox().width + 10);
        overlay_hostname.select('#overlay_separator_footer' + d.data.uuid)
            .attr('x2', overlay_hostname.select('rect').node().getBBox().width + 10);


        cur_node.select('#overlay_link')
                    .attr("x1", 10)
                    .attr("y1", 0)
                    .attr("x2", left_margin + 3)
                    .attr("y2", top_margin + 7);
    });
};

function icon(key, icon_path, d, icon_size){
    var iconContent = d3.create("svg") // WARNING: svg is required there, "g" doesn't have getBBox
                        .attr('class', 'icon');
    var has_icon = false;

    iconContent.datum(d);
    iconContent.filter(d => {
            if (typeof d.data[key] === 'boolean') {
                has_icon = d.data[key];
            } else if (typeof d.data[key] === 'number') {
                has_icon = d.data[key] > 0;
            } else if (d.data[key] instanceof Array) {
                has_icon = d.data[key].length > 0;
            }
            return has_icon;
        }).append('image')
            .attr("width", icon_size)
            .attr("height", icon_size)
            .attr("xlink:href", icon_path);


    iconContent.filter(d => {
            if (typeof d.data[key] === 'boolean') {
                return false;
                // return d.data[key];
            } else if (typeof d.data[key] === 'number') {
                d.to_print = d.data[key]
                return d.data[key] > 0;
            } else if (d.data[key] instanceof Array) {
                d.to_print = d.data[key].length
                return d.data[key].length > 0;
            }
            return false;
        }).append('text')
          .attr("dy", 8)
          .style("font-size", "10px")
          .attr('x', icon_size + 1)
          .text(d => d.to_print);
    if (has_icon) {
        return iconContent.node();
    }
    return false;
};

function icon_list(relative_x_pos, relative_y_pos, d) {
    var icon_size = 16;

    // Put all the icone in one sub svg document
    var icons = d3.create("svg")  // WARNING: svg is required there, "g" doesn't have getBBox
          .attr('x', relative_x_pos)
          .attr('y', relative_y_pos)
          .datum(d);
    icon_options = [
        ['js', "/static/javascript.png"],
        ['exe', "/static/exe.png"],
        ['css', "/static/css.png"],
        ['font', "/static/font.png"],
        ['html', "/static/html.png"],
        ['json', "/static/json.png"],
        ['iframe', "/static/ifr.png"],
        ['image', "/static/img.png"],
        ['unknown_mimetype', "/static/wtf.png"],
        ['video', "/static/video.png"],
        ['request_cookie', "/static/cookie_read.png"],
        ['response_cookie', "/static/cookie_received.png"],
        ['redirect', "/static/redirect.png"],
        ['redirect_to_nothing', "/static/cookie_in_url.png"]
    ];

    nb_icons = 0
    icon_options.forEach(entry => {
        bloc = icon(entry[0], entry[1], d, icon_size);
        if (bloc){
            icons.append(() => bloc);
        };
    })

    // FIXME: that need to move somewhere else, doesn't make sense here.
    icons.filter(d => {
        if (d.data.sane_js_details) {
            d.libinfo = d.data.sane_js_details[0];
            return d.data.sane_js_details;
        }
        return false;
    }).append('text')
      .attr('x', icon_size + 4)
      .attr('y', relative_y_pos + 7)
      .style("font-size", "15px")
      .text(d => 'Library information: ' + d.libinfo);

    return icons.node();
}

function text_entry(relative_x_pos, relative_y_pos, onclick_callback, d) {
    // Avoid hiding the content after the circle
    var nodeContent = d3.create("svg")  // WARNING: svg is required there, "g" doesn't have getBBox
          .attr('height', node_height)
          .attr('x', relative_x_pos)
          .attr('y', relative_y_pos)
          .datum(d);

    // Add labels for the nodes
    var text_nodes = nodeContent.append("text")
          .attr('dy', '.9em')
          .attr("stroke", "white")
          .style("font-size", "16px")
          .attr("stroke-width", ".2px")
          .style("opacity", .9)
          .attr('cursor', 'pointer')
          .attr("clip-path", "url(#textOverlay)")
          .text(d => {
            if (d.data.urls_count) {
              return d.data.name + ' (' + d.data.urls_count + ')'
            }
            return d.data.name
          })
          .on('click',onclick_callback);
    return nodeContent.node();
}

// Recursively generate the tree
function update(root, computed_node_width=0) {

  // Current height of the tree (cannot use height because it isn't recomputed when we rename children -> _children)
  var max_depth = 1
  root.each(d => {
    if (d.children){
      max_depth = d.depth > max_depth ? d.depth : max_depth;
    }
  });

  if (computed_node_width != 0) {
    computed_node_width += 30;
    // Re-compute SVG size depending on the generated tree
    var newWidth = Math.max((max_depth + 1) * computed_node_width, node_width);
    // Update height
    // node_height is the height of a node, node_height * 10 is the minimum so the root node isn't behind the lookyloo icon
    var newHeight = Math.max(root.descendants().reverse().length * node_height, 10 * node_height);
    tree.size([newHeight, newWidth])

    // Set background based on the computed width and height
    var background = main_svg.insert('rect', ':first-child')
      .attr('y', 0)
      // FIXME: + 200 doesn't make much sense...
      .attr('width', newWidth + margin.right + margin.left + 200)
      .attr('height', newHeight + margin.top + margin.bottom)
      .style('fill', "url(#backstripes)");

    // Update size
    d3.select("body svg")
      // FIXME: + 200 doesn't make much sense...
      .attr("width", newWidth + margin.right + margin.left + 200)
      .attr("height", newHeight + margin.top + margin.bottom)

    // Update pattern
    main_svg.selectAll('pattern')
      .attr('width', computed_node_width * 2)
    pattern.selectAll('rect')
      .attr('width', computed_node_width)

  }

  // Assigns the x and y position for the nodes
  var treemap = tree(root);

  // Compute the new tree layout. => Note: Need d.x & d.y
  var nodes = treemap.descendants(),
      links = treemap.descendants().slice(1);

  // ****************** Nodes section ***************************

  // Update the nodes...
  const tree_nodes = node_container.selectAll('g.node')
      .data(nodes, node => node.data.uuid);

  tree_nodes.join(
        // Enter any new modes at the parent's previous position.
        enter => {
            var node_group = enter.append('g')
                .attr('class', 'node')
                .attr("id", d => 'node_' + d.data.uuid)
                .attr("transform", "translate(" + root.y0 + "," + root.x0 + ")")

            node_group
                // Add Circle for the nodes
                .append('circle')
                .attr('class', 'node')
                .attr('r', 1e-6)
                .style("fill", d => d._children ? "lightsteelblue" : "#fff")
                .on('click', click);

            var node_data = node_group
              .append('svg')
              .attr('class', 'node_data')
              .attr('x', 0)
              .attr('y', -30);

            node_data.append('rect')
              .attr("rx", 6)
              .attr("ry", 6)
              .attr('x', 12)
              .attr('y', 0)
              .style("opacity", "0.5")
              .attr("stroke", "black")
              .attr('stroke-opacity', "0.8")
              .attr("stroke-width", "2")
              .attr("stroke-linecap", "round")
              .attr("fill", "white");

            // Set Hostname text
            node_data
              .append(d => text_entry(15, 5, hostnode_click, d));
            // Set list of icons
            node_data
              .append(d => icon_list(17, 35, d));


            node_group.select('.node_data').each(function(p, j){
                // set position of icons based of their length
                var cur_icon_list_len = 0;
                d3.select(this).selectAll('.icon').each(function(p, j){
                    d3.select(this).attr('x', cur_icon_list_len);
                    cur_icon_list_len += d3.select(this).node().getBBox().width;
                });


                // Rectangle around the domain name & icons
                var selected_node_bbox = d3.select(this).node().getBBox();
                d3.select(this).select('rect')
                  .attr('height', selected_node_bbox.height + 15)
                  .attr('width', selected_node_bbox.width + 50);

                // Set the width for all the nodes
                var selected_node_bbox = d3.select(this).node().getBBox();  // Required, as the node width need to include the rectangle
                node_width = node_width > selected_node_bbox.width ? node_width : selected_node_bbox.width;

            });
            return node_group;
        },
        update =>  update,
        exit => exit
            .transition(t)
              // Remove any exiting nodes
              .attr("transform", node => "translate(" + node.y0 + "," + node.x0 + ")")
              // On exit reduce the node circles size to 0
              .attr('r', 1e-6)
              // On exit reduce the opacity of text labels
              .style('fill-opacity', 1e-6)
              .remove()
    ).call(node => {
      node
        // Transition to the proper position for the node
        .attr("transform", node => "translate(" + node.y + "," + node.x + ")")
        // Update the node attributes and style
        .select('circle.node')
          .attr('r', 10)
          .style("fill", node => node._children ? "lightsteelblue" : "#fff")
          .attr('cursor', 'pointer');

    });

  nodes.forEach(d => {
    // Store the old positions for transition.
    d.x0 = d.x;
    d.y0 = d.y;
  });



  // ****************** links section ***************************

  // Update the links...
  const link = node_container.selectAll('path.link')
      .data(links, d => d.id);

  link.join(
    enter => enter
        // Enter any new links at the parent's previous position.
        .insert('path', "g")
        .attr("class", "link")
        .attr('d', d => {
          var o = {x: d.x0, y: d.y0}
          return diagonal(o, o)
        }),
    update => update,
    exit => exit
      .call(exit => exit
                .attr('d', d => {
                    var o = {x: d.x0, y: d.y0}
                    return diagonal(o, o)
                })
      .remove()
      )
  ).call(link => link
    .attr('d', d => diagonal(d, d.parent))
  );

  // Creates a curved (diagonal) path from parent to the child nodes
  function diagonal(s, d) {

    path = `M ${s.y} ${s.x}
            C ${(s.y + d.y) / 2} ${s.x},
              ${(s.y + d.y) / 2} ${d.x},
              ${d.y} ${d.x}`

    return path
  }

  // Toggle children on click.
  function click(d) {
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
  }

  if (computed_node_width === 0) {
    update(root, node_width)
  }
}
