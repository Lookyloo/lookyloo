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

// Define stuff
var defs = main_svg.append("defs");

// Add background pattern
var pattern = defs.append('pattern')
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
        var file = new File([data], "file.zip", {type: "application/zip"});
        saveAs(file);
    });
};

function hostnode_click_popup(d) {
    window.open('/tree/' + treeUUID + '/hostname_popup/' + d.data.uuid, '_blank', 'width=1024,height=768,left=200,top=100');
};

function LocateNode(urlnode_uuid) {
    var element = document.getElementById("node_" + urlnode_uuid);
    element.scrollIntoView({behavior: "smooth", block: "center", inline: "center"});

    var line_arrow = d3.select("#node_" + urlnode_uuid)
                        .append('g')
                            .attr('cursor', 'pointer')
                            .on('click', function() {
                                this.remove();
                            });

    function lineData(d){
        var points = [
            {lx: d.source.x, ly: d.source.y},
            {lx: d.target.x, ly: d.source.y},
            {lx: d.target.x, ly: d.target.y}
        ];
        return line(points);
    };

    var line = d3.line()
                    // Other options: http://bl.ocks.org/d3indepth/raw/b6d4845973089bc1012dec1674d3aff8/
                    //.curve(d3.curveCardinal)
                    .curve(d3.curveBundle)
                    .x( function(point) { return point.lx; })
                    .y( function(point) { return point.ly; });

    var line_tip = d3.symbol()
                    .type(d3.symbolTriangle)
                    .size(200);


    var path = line_arrow
        .append("path")
        .attr("stroke-width", "3")
        .attr("stroke", "black")
        .attr("fill", "none")
        .data([{source: {x : node_width/2, y : -100}, target: {x : node_width/4, y : -node_height/2}}])
        .attr("class", "line")
        .attr("d", lineData);

    var arrow = line_arrow
        .append("path")
        .attr("d", line_tip)
        .attr("stroke", 'black')
        .style('stroke-width', '3')
        .attr("fill", 'white')
        .attr("transform", function(d) { return "translate(" + node_width/4 + "," + -node_height/1.5 + ") rotate(60)"; });;

    function glow() {
        line_arrow.selectAll('path')
            .transition().duration(1000)  //Set transition
            .style('stroke-width', '7')
            .style('stroke', 'red')
            .transition().duration(1000)  //Set transition
            .style('stroke-width', '3')
            .style('stroke', 'black')
            .on("end", function() {
                if (++i > 15) line_arrow.remove();
                glow();
            });
    };

    var i = 0;
    glow();
};

function UnflagAllNodes() {
    d3.selectAll('.node_data').select('rect').style('fill', 'white');
    d3.selectAll('.node_data').select('text').style('fill', 'black');
    d3.selectAll('.node_data').select("#flag")
        .text("🏁")
        .on('click', function(d) {
            PermanentNodeHighlight(d.data.uuid);
        });
};

function UnflagHostNode(hostnode_uuid) {
    d3.select("#node_" + hostnode_uuid).select('rect').style('fill', 'white');
    d3.select("#node_" + hostnode_uuid).select('text').style('fill', 'black');
    d3.select("#node_" + hostnode_uuid).select("#flag")
        .text("🏁")
        .on('click', function(d) {
            PermanentNodeHighlight(d.data.uuid);
        });
};

function PermanentNodeHighlight(hostnode_uuid) {
    var element = document.getElementById("node_" + hostnode_uuid);
    element.scrollIntoView({behavior: "smooth", block: "center", inline: "nearest"});

    d3.select("#node_" + hostnode_uuid).select('rect').style('fill', 'black');
    d3.select("#node_" + hostnode_uuid).select('text').style('fill', 'white');
    d3.select("#node_" + hostnode_uuid).select("#flag")
        .text('❌')
        .on('click', function(d) {
            UnflagHostNode(d.data.uuid);
        });
};

function icon(key, icon_path, d, icon_size){
    var iconContent = d3.create("svg") // WARNING: svg is required there, "g" doesn't have getBBox
                        .attr('class', 'icon');
    var has_icon = false;

    iconContent.datum(d);
    iconContent.filter(d => {
            if (['cookies_sent', 'cookies_received'].includes(key)) {
                return false;
            }
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
            if (['cookies_sent', 'cookies_received'].includes(key)) {
                return false;
            }
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

function icon_list(relative_x_pos, relative_y_pos, d, url_view=false) {
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
        ['cookies_sent', "/static/cookie_read.png"],
        ['response_cookie', "/static/cookie_received.png"],
        ['cookies_received', "/static/cookie_received.png"],
        ['redirect', "/static/redirect.png"],
        ['redirect_to_nothing', "/static/cookie_in_url.png"]
    ];

    icon_options.forEach(entry => {
        bloc = icon(entry[0], entry[1], d, icon_size, url_view);
        if (bloc){
            icons.append(() => bloc);
        };
    })

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
          .attr("clip-path", "url(#textOverlay)")
          .text(d => {
            if (d.data.urls_count) {
              return d.data.name + ' (' + d.data.urls_count + ')'
            }
            return d.data.name
          });

    text_nodes
        .attr('cursor', 'pointer')
        .on('click', onclick_callback);
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
    // node_height is the height of a node, node_height * 25 is the minimum so the root node isn't behind the menu
    var newHeight = Math.max(root.descendants().reverse().length * node_height, 25 * node_height);
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
              .attr("stroke", d => {
                  if (d.data.http_content){
                      return "red";
                  }
                  return "black";
              })
              .attr('stroke-opacity', "0.8")
              .attr("stroke-width", d => {
                  if (d.data.http_content){
                      return "4";
                  }
                  return "2";
              })
              .attr("stroke-linecap", "round")
              .attr("fill", "white");

            // Set Hostname text
            node_data
              .append(d => text_entry(15, 5, hostnode_click_popup, d));  // Popup
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

                // Set Flag
                d3.select(this).append("text")
                    .attr('x', selected_node_bbox.width - 12)
                    .attr('y', 20)
                    .style("font-size", "16px")
                    .attr("id", "flag")
                    .text("🏁")
                    .attr('cursor', 'pointer')
                    .on('click', function(d) {
                        PermanentNodeHighlight(d.data.uuid);
                    });
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
