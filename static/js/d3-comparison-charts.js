// D3.js Charts for the AI vs Manual Rules Comparison page
document.addEventListener('DOMContentLoaded', function() {
    // Set up colors
    const colors = {
        manual: '#2563eb', // blue-600
        ai: '#059669'      // green-600
    };

    // 1. Precision Rate Chart
    renderBarChart('precisionRateChart', [
        {label: 'Manual Rules', value: parseFloat(document.getElementById('precisionRateChart').getAttribute('data-manual-precision') || 65.1), color: colors.manual},
        {label: 'AI Rules', value: parseFloat(document.getElementById('precisionRateChart').getAttribute('data-ai-precision') || 86.8), color: colors.ai}
    ], '%', 100);

    // 2. True Positives Chart
    renderBarChart('truePositivesChart', [
        {label: 'Manual Rules', value: parseInt(document.getElementById('truePositivesChart').getAttribute('data-manual-tp') || 177), color: colors.manual},
        {label: 'AI Rules', value: parseInt(document.getElementById('truePositivesChart').getAttribute('data-ai-tp') || 230), color: colors.ai}
    ]);

    // 3. False Positives Chart
    renderBarChart('falsePositivesChart', [
        {label: 'Manual Rules', value: parseInt(document.getElementById('falsePositivesChart').getAttribute('data-manual-fp') || 95), color: colors.manual},
        {label: 'AI Rules', value: parseInt(document.getElementById('falsePositivesChart').getAttribute('data-ai-fp') || 35), color: colors.ai}
    ]);

    // 4. Response Time Chart
    renderBarChart('responseTimeChart', [
        {label: 'Manual Rules', value: 12.5, color: colors.manual},
        {label: 'AI Rules', value: 3.8, color: colors.ai}
    ], 'min');

    // 5. Rule Matches Chart
    renderBarChart('ruleMatchesChart', [
        {label: 'Manual Rules', value: 272, color: colors.manual},
        {label: 'AI Rules', value: 265, color: colors.ai}
    ]);

    // 6. Security Mitigation Chart (Pie chart)
    renderPieChart('securityMitigationChart', [
        {label: 'SQL Injection', value: 42, color: '#ff6384'},
        {label: 'XSS', value: 35, color: '#36a2eb'},
        {label: 'CSRF', value: 28, color: '#ffce56'},
        {label: 'File Inclusion', value: 21, color: '#4bc0c0'},
        {label: 'Command Injection', value: 16, color: '#9966ff'}
    ]);

    // 7. Security Risk Trend Chart (Line chart)
    renderLineChart('securityRiskTrendChart', 
        ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
        [
            {name: 'Manual Rules', values: [65, 72, 68, 75, 79, 82], color: colors.manual},
            {name: 'AI Rules', values: [70, 78, 82, 89, 92, 95], color: colors.ai}
        ],
        '%'
    );

    // 8. Attack Type Comparison Chart (Radar-like)
    renderRadarChart('attackTypeComparisonChart', 
        ['SQL Injection', 'XSS', 'CSRF', 'File Inclusion', 'Command Injection'],
        [
            {name: 'Manual Rules', values: [75, 68, 82, 62, 58], color: colors.manual},
            {name: 'AI Rules', values: [92, 88, 85, 90, 95], color: colors.ai}
        ]
    );

    // Bar chart rendering function
    function renderBarChart(elementId, data, suffix = '', maxValue = null) {
        const chartElement = document.getElementById(elementId);
        if (!chartElement) return;
        
        // Clear any loading overlays
        const overlayId = elementId.replace('Chart', '-chart-overlay');
        const overlay = document.getElementById(overlayId);
        if (overlay) overlay.style.display = 'none';

        // Set dimensions
        const margin = {top: 20, right: 30, bottom: 40, left: 40};
        const width = chartElement.clientWidth - margin.left - margin.right;
        const height = chartElement.clientHeight - margin.top - margin.bottom;

        // Create SVG
        const svg = d3.select('#' + elementId)
            .append('svg')
            .attr('width', width + margin.left + margin.right)
            .attr('height', height + margin.top + margin.bottom)
            .append('g')
            .attr('transform', `translate(${margin.left},${margin.top})`);

        // Define scales
        const x = d3.scaleBand()
            .domain(data.map(d => d.label))
            .range([0, width])
            .padding(0.3);

        const y = d3.scaleLinear()
            .domain([0, maxValue ? maxValue : d3.max(data, d => d.value) * 1.1])
            .range([height, 0]);

        // Add bars
        svg.selectAll('.bar')
            .data(data)
            .enter()
            .append('rect')
            .attr('class', 'bar')
            .attr('x', d => x(d.label))
            .attr('width', x.bandwidth())
            .attr('y', d => y(d.value))
            .attr('height', d => height - y(d.value))
            .attr('fill', d => d.color)
            .attr('rx', 4)
            .attr('ry', 4);

        // Add value labels
        svg.selectAll('.label')
            .data(data)
            .enter()
            .append('text')
            .attr('class', 'label')
            .attr('x', d => x(d.label) + x.bandwidth() / 2)
            .attr('y', d => y(d.value) - 5)
            .attr('text-anchor', 'middle')
            .text(d => d.value + suffix)
            .attr('fill', '#4b5563')
            .attr('font-weight', 'bold');

        // Add x axis
        svg.append('g')
            .attr('transform', `translate(0,${height})`)
            .call(d3.axisBottom(x))
            .selectAll('text')
            .attr('font-size', '12px');

        // Add y axis
        svg.append('g')
            .call(d3.axisLeft(y).ticks(5))
            .selectAll('text')
            .attr('font-size', '12px');
    }

    // Pie chart rendering function
    function renderPieChart(elementId, data) {
        const chartElement = document.getElementById(elementId);
        if (!chartElement) return;

        // Set dimensions
        const width = chartElement.clientWidth;
        const height = chartElement.clientHeight;
        const radius = Math.min(width, height) / 2 - 40;

        // Create SVG
        const svg = d3.select('#' + elementId)
            .append('svg')
            .attr('width', width)
            .attr('height', height)
            .append('g')
            .attr('transform', `translate(${width / 2},${height / 2})`);

        // Create pie layout
        const pie = d3.pie()
            .value(d => d.value)
            .sort(null);

        // Create arc generator
        const arc = d3.arc()
            .innerRadius(0)
            .outerRadius(radius);

        // Create outer arc for labels
        const outerArc = d3.arc()
            .innerRadius(radius * 1.1)
            .outerRadius(radius * 1.1);

        // Add pie slices
        const slices = svg.selectAll('.slice')
            .data(pie(data))
            .enter()
            .append('g')
            .attr('class', 'slice');

        slices.append('path')
            .attr('d', arc)
            .attr('fill', d => d.data.color)
            .attr('stroke', 'white')
            .style('stroke-width', '2px');

        // Add labels
        const labelGroups = slices.append('g');

        labelGroups.append('polyline')
            .attr('points', function(d) {
                const pos = outerArc.centroid(d);
                const midAngle = d.startAngle + (d.endAngle - d.startAngle) / 2;
                pos[0] = radius * 0.95 * (midAngle < Math.PI ? 1 : -1);
                return [arc.centroid(d), outerArc.centroid(d), pos];
            })
            .attr('stroke', 'black')
            .attr('fill', 'none')
            .attr('stroke-width', 1);

        labelGroups.append('text')
            .attr('transform', function(d) {
                const pos = outerArc.centroid(d);
                const midAngle = d.startAngle + (d.endAngle - d.startAngle) / 2;
                pos[0] = radius * 1.05 * (midAngle < Math.PI ? 1 : -1);
                return `translate(${pos})`;
            })
            .attr('dy', '.35em')
            .style('text-anchor', d => {
                const midAngle = d.startAngle + (d.endAngle - d.startAngle) / 2;
                return midAngle < Math.PI ? 'start' : 'end';
            })
            .text(d => `${d.data.label} (${d.data.value})`)
            .attr('font-size', '12px');
    }

    // Line chart rendering function
    function renderLineChart(elementId, categories, datasets, suffix = '') {
        const chartElement = document.getElementById(elementId);
        if (!chartElement) return;

        // Set dimensions
        const margin = {top: 20, right: 60, bottom: 40, left: 40};
        const width = chartElement.clientWidth - margin.left - margin.right;
        const height = chartElement.clientHeight - margin.top - margin.bottom;

        // Create SVG
        const svg = d3.select('#' + elementId)
            .append('svg')
            .attr('width', width + margin.left + margin.right)
            .attr('height', height + margin.top + margin.bottom)
            .append('g')
            .attr('transform', `translate(${margin.left},${margin.top})`);

        // Define scales
        const x = d3.scaleBand()
            .domain(categories)
            .range([0, width])
            .padding(0.1);

        const y = d3.scaleLinear()
            .domain([
                Math.min(50, d3.min(datasets, d => d3.min(d.values))) * 0.9,
                Math.max(100, d3.max(datasets, d => d3.max(d.values))) * 1.1
            ])
            .range([height, 0]);

        // Create line generator
        const line = d3.line()
            .x((d, i) => x(categories[i]) + x.bandwidth() / 2)
            .y(d => y(d))
            .curve(d3.curveMonotoneX);

        // Add lines
        datasets.forEach(dataset => {
            // Add the line
            svg.append('path')
                .datum(dataset.values)
                .attr('fill', 'none')
                .attr('stroke', dataset.color)
                .attr('stroke-width', 3)
                .attr('d', line);
            
            // Add dots
            svg.selectAll(`dot-${dataset.name}`)
                .data(dataset.values)
                .enter()
                .append('circle')
                .attr('cx', (d, i) => x(categories[i]) + x.bandwidth() / 2)
                .attr('cy', d => y(d))
                .attr('r', 5)
                .attr('fill', dataset.color)
                .attr('stroke', 'white')
                .attr('stroke-width', 2);
        });

        // Add value labels
        datasets.forEach(dataset => {
            svg.selectAll(`.label-${dataset.name}`)
                .data(dataset.values)
                .enter()
                .append('text')
                .attr('class', `label-${dataset.name}`)
                .attr('x', (d, i) => x(categories[i]) + x.bandwidth() / 2)
                .attr('y', d => y(d) - 10)
                .attr('text-anchor', 'middle')
                .text(d => d + suffix)
                .attr('fill', dataset.color)
                .attr('font-weight', 'bold')
                .attr('font-size', '10px');
        });

        // Add x axis
        svg.append('g')
            .attr('transform', `translate(0,${height})`)
            .call(d3.axisBottom(x))
            .selectAll('text')
            .attr('font-size', '12px');

        // Add y axis
        svg.append('g')
            .call(d3.axisLeft(y).ticks(5))
            .selectAll('text')
            .attr('font-size', '12px');

        // Add legend
        const legend = svg.append('g')
            .attr('class', 'legend')
            .attr('transform', `translate(${width - 100}, 0)`);

        datasets.forEach((dataset, i) => {
            const legendRow = legend.append('g')
                .attr('transform', `translate(0, ${i * 20})`);
            
            legendRow.append('rect')
                .attr('width', 10)
                .attr('height', 10)
                .attr('fill', dataset.color);
            
            legendRow.append('text')
                .attr('x', 15)
                .attr('y', 10)
                .attr('text-anchor', 'start')
                .text(dataset.name)
                .attr('font-size', '12px');
        });
    }

    // Radar chart function (simplified version using d3)
    function renderRadarChart(elementId, categories, datasets) {
        const chartElement = document.getElementById(elementId);
        if (!chartElement) return;

        // Set dimensions
        const width = chartElement.clientWidth;
        const height = chartElement.clientHeight;
        const radius = Math.min(width, height) / 2 - 40;
        
        // Create SVG
        const svg = d3.select('#' + elementId)
            .append('svg')
            .attr('width', width)
            .attr('height', height)
            .append('g')
            .attr('transform', `translate(${width/2},${height/2})`);
        
        // Create scales
        const angleScale = d3.scaleLinear()
            .domain([0, categories.length])
            .range([0, Math.PI * 2]);
        
        const radiusScale = d3.scaleLinear()
            .domain([0, 100])
            .range([0, radius]);
        
        // Create background circles
        const circles = [20, 40, 60, 80, 100];
        circles.forEach(value => {
            svg.append('circle')
                .attr('cx', 0)
                .attr('cy', 0)
                .attr('r', radiusScale(value))
                .attr('fill', 'none')
                .attr('stroke', '#e5e7eb')
                .attr('stroke-width', 1);
            
            svg.append('text')
                .attr('x', 5)
                .attr('y', -radiusScale(value))
                .text(value + '%')
                .attr('fill', '#9ca3af')
                .attr('font-size', '10px');
        });
        
        // Create axes
        categories.forEach((category, i) => {
            const angle = angleScale(i);
            const line = svg.append('line')
                .attr('x1', 0)
                .attr('y1', 0)
                .attr('x2', radius * Math.sin(angle))
                .attr('y2', -radius * Math.cos(angle))
                .attr('stroke', '#e5e7eb')
                .attr('stroke-width', 1);
            
            const label = svg.append('text')
                .attr('x', (radius + 10) * Math.sin(angle))
                .attr('y', -(radius + 10) * Math.cos(angle))
                .attr('text-anchor', 'middle')
                .attr('dominant-baseline', 'middle')
                .text(category)
                .attr('font-size', '12px')
                .attr('fill', '#4b5563');
        });
        
        // Create radar paths
        datasets.forEach(dataset => {
            const points = dataset.values.map((value, i) => {
                const angle = angleScale(i);
                return {
                    x: radiusScale(value) * Math.sin(angle),
                    y: -radiusScale(value) * Math.cos(angle)
                };
            });
            
            // Close the path
            points.push(points[0]);
            
            // Line generator
            const lineGenerator = d3.line()
                .x(d => d.x)
                .y(d => d.y)
                .curve(d3.curveLinearClosed);
            
            // Draw path
            svg.append('path')
                .attr('d', lineGenerator(points))
                .attr('fill', dataset.color)
                .attr('fill-opacity', 0.2)
                .attr('stroke', dataset.color)
                .attr('stroke-width', 2);
            
            // Add dots
            svg.selectAll(`.dot-${dataset.name}`)
                .data(dataset.values)
                .enter()
                .append('circle')
                .attr('cx', (d, i) => {
                    const angle = angleScale(i);
                    return radiusScale(d) * Math.sin(angle);
                })
                .attr('cy', (d, i) => {
                    const angle = angleScale(i);
                    return -radiusScale(d) * Math.cos(angle);
                })
                .attr('r', 4)
                .attr('fill', dataset.color)
                .attr('stroke', 'white')
                .attr('stroke-width', 1);
        });
        
        // Add legend
        const legend = svg.append('g')
            .attr('class', 'legend')
            .attr('transform', `translate(${radius - 50}, ${-radius + 20})`);
        
        datasets.forEach((dataset, i) => {
            const legendRow = legend.append('g')
                .attr('transform', `translate(0, ${i * 20})`);
            
            legendRow.append('rect')
                .attr('width', 10)
                .attr('height', 10)
                .attr('fill', dataset.color);
            
            legendRow.append('text')
                .attr('x', 15)
                .attr('y', 10)
                .attr('text-anchor', 'start')
                .text(dataset.name)
                .attr('font-size', '12px');
        });
    }

    // Add refresh button functionality
    const refreshButton = document.getElementById('refresh-comparison');
    if (refreshButton) {
        refreshButton.addEventListener('click', function() {
            location.reload();
        });
    }
});