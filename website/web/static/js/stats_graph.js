"use strict";
// Admin statistics (admin/stats.html): one bar chart per year, captures per month.
// The data is in the page (data-months / data-month-numbers of .lk-stats-chart);
// the colours come from css/stats.css (tokens). Doc: doc/ui/stats.md
(() => {
    const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const margin = { top: 20, right: 16, bottom: 28, left: 40 };
    const height = 220;
    const reduce_motion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    // 'bars' or 'curve', remembered
    let mode = 'bars';
    try { if (localStorage.getItem('lk-stats-mode') === 'curve') mode = 'curve'; } catch (e) { /* default */ }

    // animate: bars growing from the axis (on arrival on the page, not on a resize)
    function draw(container, animate=false) {
        const counts = JSON.parse(container.dataset.months || '[]');
        const numbers = JSON.parse(container.dataset.monthNumbers || '[]');
        const by_month = new Map(numbers.map((m, i) => [m, counts[i]]));
        // Months still to come in the current year: no value (no bar, no point)
        const now = new Date();
        const last_month = Number(container.dataset.year) === now.getFullYear() ? now.getMonth() + 1 : 12;
        const data = MONTHS.map((name, i) => ({ name, value: i + 1 > last_month ? null : (by_month.get(i + 1) || 0) }));
        const past = data.filter(d => d.value !== null);

        container.textContent = '';
        const width = Math.max(container.clientWidth, 320);
        const svg = d3.select(container).append('svg')
            .attr('viewBox', `0 0 ${width} ${height}`).attr('width', width).attr('height', height);
        const x = d3.scaleBand().domain(MONTHS).range([margin.left, width - margin.right]).padding(0.25);
        const y = d3.scaleLinear().domain([0, Math.max(1, d3.max(past, d => d.value))]).nice()
            .range([height - margin.bottom, margin.top]);

        svg.append('g').attr('class', 'lk-stats-grid')
            .attr('transform', `translate(${margin.left},0)`)
            .call(d3.axisLeft(y).ticks(4).tickSize(-(width - margin.left - margin.right)).tickFormat(d3.format('~s')))
            .call(g => g.select('.domain').remove());
        svg.append('g').attr('class', 'lk-stats-axis')
            .attr('transform', `translate(0,${height - margin.bottom})`)
            .call(d3.axisBottom(x).tickSizeOuter(0));

        if (mode === 'curve') drawCurve(svg, past, x, y, animate);
        else drawBars(svg, past, x, y, animate);
    }

    const title = d => `${d.name}: ${d.value} capture${d.value === 1 ? '' : 's'}`;

    function drawBars(svg, data, x, y, animate) {
        const bars = svg.append('g').selectAll('g').data(data).join('g');
        const rects = bars.append('rect')
            .attr('class', d => d.value ? 'lk-stats-bar' : 'lk-stats-bar is-empty')
            .attr('x', d => x(d.name)).attr('width', x.bandwidth())
            .attr('rx', 4);
        rects.append('title').text(title);
        const labels = bars.filter(d => d.value > 0).append('text')
            .attr('class', 'lk-stats-bar-label')
            .attr('x', d => x(d.name) + x.bandwidth() / 2).attr('y', d => y(d.value) - 6)
            .attr('text-anchor', 'middle').text(d => d3.format(',')(d.value));
        if (animate && !reduce_motion) {
            rects.attr('y', y(0)).attr('height', 0)
                .transition().delay((_, i) => i * 45).duration(700).ease(d3.easeCubicOut)
                .attr('y', d => y(d.value)).attr('height', d => y(0) - y(d.value));
            labels.style('opacity', 0)
                .transition().delay((_, i) => 400 + i * 45).duration(400).style('opacity', 1);
        } else {
            rects.attr('y', d => y(d.value)).attr('height', d => y(0) - y(d.value));
        }
    }

    // Smooth curve through the months (middle of each band), the area under it, a dot per month
    function drawCurve(svg, data, x, y, animate) {
        const cx = d => x(d.name) + x.bandwidth() / 2;
        const curve = d3.curveMonotoneX;
        const area = svg.append('path').datum(data).attr('class', 'lk-stats-area')
            .attr('d', d3.area().x(cx).y0(y(0)).y1(d => y(d.value)).curve(curve));
        const line = svg.append('path').datum(data).attr('class', 'lk-stats-line')
            .attr('d', d3.line().x(cx).y(d => y(d.value)).curve(curve));
        const points = svg.append('g').selectAll('g').data(data).join('g');
        const dots = points.append('circle').attr('class', d => d.value ? 'lk-stats-dot' : 'lk-stats-dot is-empty')
            .attr('cx', cx).attr('cy', d => y(d.value)).attr('r', d => d.value ? 4 : 2.5);
        dots.append('title').text(title);
        const labels = points.filter(d => d.value > 0).append('text')
            .attr('class', 'lk-stats-bar-label')
            .attr('x', cx).attr('y', d => y(d.value) - 10)
            .attr('text-anchor', 'middle').text(d => d3.format(',')(d.value));
        if (animate && !reduce_motion) {
            // The line draws itself from left to right, the rest follows
            const length = line.node().getTotalLength();
            line.attr('stroke-dasharray', `${length} ${length}`).attr('stroke-dashoffset', length)
                .transition().duration(1100).ease(d3.easeCubicInOut).attr('stroke-dashoffset', 0)
                .on('end', () => line.attr('stroke-dasharray', null));
            area.style('opacity', 0).transition().delay(500).duration(700).style('opacity', 1);
            dots.attr('r', 0).transition().delay((_, i) => i * 90).duration(300).attr('r', d => d.value ? 4 : 2.5);
            labels.style('opacity', 0).transition().delay((_, i) => 300 + i * 90).duration(300).style('opacity', 1);
        }
    }

    // The numbers of the cards count up to their value
    function countUp(element) {
        const target = parseInt(element.dataset.value, 10);
        if (!Number.isFinite(target) || reduce_motion) return;
        const format = d3.format(',');
        d3.select(element).transition().duration(900).ease(d3.easeCubicOut)
            .tween('text', () => {
                const value = d3.interpolateRound(0, target);
                return t => { element.textContent = format(value(t)); };
            });
    }

    const charts = document.querySelectorAll('.lk-stats-chart');
    charts.forEach(chart => draw(chart, true));

    // Bars / Curve: drawn again, animated
    const mode_buttons = document.querySelectorAll('[data-stats-mode]');
    const showMode = () => mode_buttons.forEach(b => b.setAttribute('aria-pressed', b.dataset.statsMode === mode ? 'true' : 'false'));
    showMode();
    mode_buttons.forEach(button => button.addEventListener('click', () => {
        if (button.dataset.statsMode === mode) return;
        mode = button.dataset.statsMode;
        try { localStorage.setItem('lk-stats-mode', mode); } catch (e) { /* not kept */ }
        showMode();
        charts.forEach(chart => draw(chart, true));
    }));
    document.querySelectorAll('.lk-stats-card-value[data-value]').forEach(countUp);
    let timer = null;
    window.addEventListener('resize', () => {
        clearTimeout(timer);
        timer = setTimeout(() => charts.forEach(draw), 150);
    });
})();
