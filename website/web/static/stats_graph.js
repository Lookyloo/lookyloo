"use strict";
var margin = {top: 50, right: 50, bottom: 50, left: 50};
var width = 1000;
var height = 100;

var xScale = d3.scaleLinear()
               .domain([0, 12])
               .range([0, width]);

d3.json('/json/stats').then(json => {
    json['years'].forEach(year => {
        var dataset = [];
        year['months'].forEach(month => {
            dataset.push([month['month_number'], month['analysis']]);
            height = Math.max(month['analysis'] + 50, height);
        });
        var yScale = d3.scaleLinear()
                       .domain([0, height])
                       .range([height, 0]);

        var line = d3.line()
                     .x(d => { return xScale(d[0]); })
                     .y(d => { return yScale(d[1]); })
                     .curve(d3.curveMonotoneX)

        var svg = d3.select(".graphs").append("svg")
                    .attr("width", width + margin.left + margin.right)
                    .attr("height", height + margin.top + margin.bottom)
                    .append("g")
                      .attr("transform", `translate(${margin.left}, ${margin.top})`);

        svg.append("text")
             .attr("x", (width / 2))
             .attr("y", 0 - (margin.top / 2))
             .attr("text-anchor", "middle")
             .style("font-size", "20px")
             .text(year['year']);

        svg.append("g")
             .attr("class", "x axis")
             .attr("transform", `translate(0, ${height})`)
             .call(d3.axisBottom(xScale));

        svg.append("g")
             .attr("class", "y axis")
             .call(d3.axisLeft(yScale));

        svg.append("path")
             .datum(dataset)
             .attr("class", "line")
             .attr("d", line);

        svg.selectAll(".dot")
           .data(dataset)
           .enter().append("circle")
             .attr("class", "dot")
             .attr("cx", d => { return xScale(d[0]) })
             .attr("cy", d => { return yScale(d[1]) })
             .attr("r", 5);
    });
});
