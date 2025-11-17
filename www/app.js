const API_BASE = 'http://localhost:8080';
const API_TOKEN = 'your_api_token_here';

let bandwidthData = [];
const svgWidth = 600, svgHeight = 300;
const margin = {top: 20, right: 20, bottom: 40, left: 50};

const svg = d3.select("#bandwidth-chart")
    .append("svg")
    .attr("width", svgWidth)
    .attr("height", svgHeight);

svg.append("g").attr("class", "x-axis")
    .attr("transform", `translate(0,${svgHeight - margin.bottom})`);
svg.append("g").attr("class", "y-axis")
    .attr("transform", `translate(${margin.left},0)`);
svg.append("path").attr("class", "line");

function fetchMetrics() {
    fetch(`${API_BASE}/metrics`, {
        headers: {'Authorization': `Bearer ${API_TOKEN}` }
    })
    .then(res => {
        if(!res.ok) {
            throw new Error(`API error: ${res.status} ${res.statusText}`);
        }
        return res.json();
    })
    
    .then(data => {
        // Success: Update status
        document.getElementById('status-text').textContent = 'Connected';
        document.getElementById('status-text').style.color = '#4caf50';
        // Add data point
        const now = new Date().toLocaleTimeString();
        bandwidthData.push({ time: now, bytes: data.total_bytes || 0 });
        if (bandwidthData.length > 20) bandwidthData.shift();

        updateBandwidthChart();
    })
    .catch(err => {
        // Error: Update status and log
        console.error('Failure to fetch metrics:', err);
        document.getElementById('status-text').textContent = 'Disconnected';
        document.getElementById('status-text').style.color = '#f44336';

        // Show error details as tooltip
        const chartContainer = document.getElementById('bandwidth-chart');
        chartContainer.title = `Error: ${err.message}`;
    });
}

function updateBandwidthChart() {
    const x = d3.scalePoint()
        .domain(bandwidthData.map(d => d.time))
        .range([margin.left, svgWidth - margin.right]);

    const y = d3.scaleLinear()
        .domain([0, d3.max(bandwidthData, d => d.bytes) || 1])
        .range([svgHeight - margin.bottom, margin.top]);

    const line = d3.line()
        .x(d => x(d.time))
        .y(d => y(d.bytes));

    svg.select(".line")
        .datum(bandwidthData)
        .attr("fill", "none")
        .attr("stroke", "#4caf50")
        .attr("stroke-width", 2)
        .attr("d", line);

    svg.select(".x-axis")
        .call(d3.axisBottom(x).tickValues(bandwidthData.map(d => d.time)));

    svg.select(".y-axis")
        .call(d3.axisLeft(y));
}

setInterval(fetchMetrics, 2000);
fetchMetrics();