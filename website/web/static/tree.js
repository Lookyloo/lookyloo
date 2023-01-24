"use strict";
// From : https://bl.ocks.org/d3noob/43a860bc0024792f8803bba8ca0d5ecd

// Set the dimensions and margins of the diagram
let margin = {
    top: document.getElementById('menu_horizontal_content').clientHeight + 10,
    right: 200,
    bottom: 10,
    left: 90
};

let menuHeight = document.getElementById('menu_vertical').clientHeight;
let width = 960 - margin.left - margin.right;
let height = menuHeight * 2;

let node_width = 10;
let node_height = 55;
let center_node = null;

let main_svg = d3.select("body").append("svg")
            .attr("width", width + margin.right + margin.left)
            .attr("height", height + margin.top + margin.bottom)

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
    .attr("height", height)
    .attr('patternUnits', "userSpaceOnUse" )

pattern.append('rect')
    .attr('width', node_width)
    .attr('height', height)
    .attr("fill", "#EEEEEE");

// append the svg object to the body of the page
// appends a 'group' element to 'svg'
// moves the 'group' element to the top left margin
let node_container = main_svg.append("g")
                             .attr("transform", `translate(${margin.left}, ${margin.top})`);

// Assigns parent, children, height, depth
let root = d3.hierarchy(treeData);
root.x0 = height / 2;
root.y0 = 0;

// declares a tree layout
let tree = d3.tree();
update(root);

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


function openURLInNewTab(url) {
    let win = window.open(url, '_blank');
    if (win == null) {
        return false;
    }
    win.focus();
    return true;
}

function openTreeInNewTab(capture_uuid, hostnode_uuid=null) {
    let url = `/tree/${capture_uuid}`;
    if (hostnode_uuid != null) {
        url += `/${hostnode_uuid}`;
    }
    openURLInNewTab(url);
}

function open_hostnode_popup(hostnode_uuid) {
    let win = window.open(`/tree/${treeUUID}/host/${hostnode_uuid}`, '_blank', 'width=1024,height=768,left=200,top=100');
    if (win == null) {
        alert("The browser didn't allow Lookyloo to open a pop-up. There should be an icon on the right of your URL bar to allow it.");
    }
    win.focus();
}

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
            source: {x: node_width/2, y: -100},
            target: {x: node_width/4, y: -node_height/2}
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
        .attr("transform", `translate(${node_width / 4}, ${-node_height / 1.5}) rotate(60)`);

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
        ['js', {path: "/static/javascript.png", tooltip: "URL(s) loading Javascript"}],
        ['exe', {path: "/static/exe.png", tooltip: "URL(s) loading executables"}],
        ['css', {path: "/static/css.png", tooltip: "URL(s) loading CSS"}],
        ['font', {path: "/static/font.png", tooltip: "URL(s) loading fonts"}],
        ['html', {path: "/static/html.png", tooltip: "URL(s) loading HTML"}],
        ['json', {path: "/static/json.png", tooltip: "URL(s) loading Json"}],
        ['iframe', {path: "/static/ifr.png", tooltip: "URL(s) loaded from an Iframe"}],
        ['image', {path: "/static/img.png", tooltip: "URL(s) loading images"}],
        ['unknown_mimetype', {path: "/static/wtf.png", tooltip: "URL(s) loading contents of an unknown type"}],
        ['video', {path: "/static/video.png", tooltip: "URL(s) loading videos"}],
        ['request_cookie', {path: "/static/cookie_read.png", tooltip: "cookie(s) sent to the server in the request"}],
        ['response_cookie', {path: "/static/cookie_received.png", tooltip: "cookie(s) received in the response"}],
        ['redirect', {path: "/static/redirect.png", tooltip: "redirect(s)"}],
        ['redirect_to_nothing', {path: "/static/cookie_in_url.png", tooltip: "redirect(s) to URL(s) missing in the capture"}]
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
                      .text(`${counter} ${icon_details.tooltip}`);
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
            if (d.data.name.length > 50) {
                to_print = `[...] ${d.data.name.substring(d.data.name.length - 50, d.data.name.length)}`;
            } else {
                to_print = d.data.name
            };
            return to_print;
          });

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
    let newWidth = Math.max((max_depth + 1) * computed_node_width, node_width);
    // Update height
    // node_height is the height of a node, menuHeight * 3 is the minimum so the root node isn't behind the menu
    let newHeight = Math.max(root.descendants().reverse().length * node_height, menuHeight * 2.5);
    tree.size([newHeight, newWidth])

    // Set background based on the computed width and height
    let background = main_svg.insert('rect', ':first-child')
      .attr('y', 0)
      // Note: We want the background width with an extra computed_node_width
      // in order to make sure the last node is completely covered
      .attr('width', newWidth + (margin.right + margin.left + computed_node_width))
      .attr('height', newHeight + margin.top + margin.bottom)
      .style('fill', "url(#backstripes)");

    // Update size
    main_svg
      .attr("width", newWidth + (margin.right + margin.left)*2)
      .attr("height", newHeight + margin.top + margin.bottom)

    // Update pattern
    main_svg.selectAll('pattern')
      .attr('width', `${computed_node_width * 2}px`)
    pattern.selectAll('rect')
      .attr('width', `${computed_node_width}px`)

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
                  if (d.data.downloaded_filename) {
                    d3.select(this).append("svg").append('rect')
                        .attr('x', selected_node_bbox.width/3)
                        .attr('y', node_height - 3)
                        .attr('width', thumbnail_size)
                        .attr('height', thumbnail_size)
                        .attr('fill', 'white')
                        .attr('stroke', 'black');

                    d3.select(this).append('image')
                        .attr('x', selected_node_bbox.width/3)
                        .attr('y', node_height - 3)
                        .attr('id', 'screenshot_thumbnail')
                        .attr("width", thumbnail_size)
                        .attr("height", thumbnail_size)
                        .attr("xlink:href", '/static/download.svg')
                        .on('mouseover', (event, d) => {
                            d3.select('#tooltip')
                              .style('opacity', 1)
                              .style('left', `${event.pageX + 10}px`)
                              .style('top', `${event.pageY + 10}px`)
                              .text(`Contains the downloaded file (${d.data.downloaded_filename}).`);
                        })
                        .on('mouseout', (event, d) => {
                            d3.select('#tooltip').style('opacity', 0)
                        });
                  } else {
                    d3.select(this).append("svg").append('rect')
                        .attr('x', selected_node_bbox.width/3)
                        .attr('y', node_height - 3)
                        .attr('width', thumbnail_size)
                        .attr('height', thumbnail_size)
                        .attr('fill', 'white')
                        .attr('stroke', 'black');

                    d3.select(this).append('image')
                        .attr('x', selected_node_bbox.width/3)
                        .attr('y', node_height - 3)
                        .attr('id', 'screenshot_thumbnail')
                        .attr("width", thumbnail_size)
                        .attr("height", thumbnail_size)
                        .attr("xlink:href", `data:image/png;base64,${screenshot_thumbnail}`)
                        .attr('cursor', 'pointer')
                        .on('mouseover', (event, d) => {
                            d3.select('#tooltip')
                              .style('opacity', 1)
                              .style('left', `${event.pageX + 10}px`)
                              .style('top', `${event.pageY + 10}px`)
                              .text('Contains the URL rendered in the browser.');
                        })
                        .on('click', (event, d) => {
                            $("#screenshotModal").modal('toggle');
                        })
                        .on('mouseout', (event, d) => {
                            d3.select('#tooltip').style('opacity', 0)
                        });
                  }
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
                        .attr("xlink:href", '/static/insecure.svg')
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
                        .attr("xlink:href", '/static/bomb.svg')
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
                        .attr("xlink:href", '/static/check.svg')
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
                    .attr("xlink:href", '/static/empty.svg')
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
        .attr('d', diagonal),
    update => update,
    exit => exit.call(exit => exit.attr('d', diagonal).remove())
  ).call(link => link.attr('d', diagonal));

  if (computed_node_width === 0) {
    update(root, node_width)
  }
}
