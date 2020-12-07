"use strict";
var margin = {top: 50, right: 150, bottom: 50, left: 50};
var width = 1000;
var height = 800;


d3.json('/json/stats').then(json => {
    var datasets = []
    json.years.forEach(year => {
        var submissions_year = { label: `Submissions ${year.year}`, x: [], y: [] }
        var unique_urls_year = { label: `Unique URLs ${year.year}`, x: [], y: [] }
        year.months.forEach(month => {
            submissions_year.x.push(month.month_number)
            unique_urls_year.x.push(month.month_number)

            submissions_year.y.push(month.submissions)
            unique_urls_year.y.push(month.uniq_urls)
        });
        datasets.push(submissions_year)
        datasets.push(unique_urls_year)
    });

    var x_scale = d3.scaleLinear()
                    .domain([1, 12])
                    .range([0, width]);
    var y_scale = d3.scaleLinear()
                    .domain([ 0,
                              d3.max(datasets, function(d) { return d3.max(d.y); })
                            ])
                    .range([height, 0]);

    var x_axis = d3.axisBottom(x_scale);
    var y_axis = d3.axisLeft(y_scale);
    var line = d3.line()
                 .x(d => { return x_scale(d[0]); })
                 .y(d => { return y_scale(d[1]); });

    var svg = d3.select(".graphs").append("svg")
                .attr("width", width + margin.right + margin.left)
                .attr("height", height + margin.top + margin.bottom)
                .append("g")
                    .attr("transform", `translate(${margin.left}, ${margin.top})`);

    svg.append("g")
        .attr("class", "x axis")
        .attr("transform", `translate(0, ${height})`)
        .call(x_axis);

    svg.append("g")
        .attr("class", "y axis")
        .call(y_axis);

    var data_lines = svg.selectAll(".d3_xy_chart_line")
                        .data(datasets.map(d => {return d3.zip(d.x, d.y);}))
                        .enter().append("g")
                        .attr("class", "d3_xy_chart_line") ;

    data_lines.append("path")
              .attr("class", "line")
              .attr("d", line)
              .attr("stroke", (_, i) => {return d3.schemeCategory10[i];});

    data_lines.append("text")
               .datum((d, i) => { return {name: datasets[i].label, final: d[d.length-1]}; })
               .attr("transform", d => {
                   return ( `translate(${x_scale(d.final[0])}, ${y_scale(d.final[1])})` ) ; })
               .attr("x", 3)
               .attr("dy", ".35em")
               .attr("fill", (_, i) =>{ return d3.schemeCategory10[i]; })
               .text(d => { return d.name; }) ;

});
