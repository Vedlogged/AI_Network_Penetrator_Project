// Helper function to show/hide elements
function toggleVisibility(elementId, show) {
    const element = document.getElementById(elementId);
    if (element) {
        if (show) {
            element.classList.remove('d-none');
        } else {
            element.classList.add('d-none');
        }
    }
}

// Function to display status messages
function showStatus(message, type = 'info') {
    const statusDiv = document.getElementById('scan-status');
    statusDiv.textContent = message;
    statusDiv.className = `mt-3 alert alert-${type}`;
    toggleVisibility('scan-status', true);
}

// Function to hide status messages
function hideStatus() {
    toggleVisibility('scan-status', false);
}

// Chart.js instance variable
let scanChartInstance = null;

// Event listener for the scan form submission
document.getElementById('scan-form').addEventListener('submit', async function(event) {
    event.preventDefault();
    const targetIp = document.getElementById('target_ip').value;
    const portsToScan = document.getElementById('ports_to_scan').value;

    hideStatus();
    showStatus('Starting scan... This may take a moment.', 'warning');

    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `target_ip=${encodeURIComponent(targetIp)}&ports_to_scan=${encodeURIComponent(portsToScan)}`
        });

        const data = await response.json();

        if (response.ok && data.status === 'success') {
            showStatus('Scan completed successfully! Dashboard will update shortly.', 'success');
            fetchLatestData();
        } else {
            showStatus(`Error: ${data.message || 'Unknown error occurred.'}`, 'danger');
        }
    } catch (error) {
        console.error('Error during scan request:', error);
        showStatus('An unexpected error occurred while communicating with the server.', 'danger');
    }
});

// Event listener for Download Report button
document.getElementById('download-report-btn').addEventListener('click', async function() {
    showStatus('Generating report...', 'info');
    try {
        const response = await fetch('/generate_report');
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'scan_report.csv';
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
            showStatus('Report downloaded successfully!', 'success');
        } else {
            const errorText = await response.text();
            showStatus(`Failed to generate report: ${errorText}`, 'danger');
        }
    } catch (error) {
        console.error('Error generating report:', error);
        showStatus('An error occurred while generating the report.', 'danger');
    }
});


// Function to fetch and update all dashboard data
async function fetchLatestData() {
    try {
        const response = await fetch('/get_latest_data');
        const data = await response.json();

        const latestScanDiv = document.getElementById('latest-scan-results');
        const aiAnalysisDiv = document.getElementById('ai-analysis-results');
        const previousScansDiv = document.getElementById('previous-scans-list');
        const scanChartCanvas = document.getElementById('scanChart');

        // --- Update Latest Scan Results Section ---
        if (data.latest_scan && data.latest_scan.scan_details) {
            const latestScan = data.latest_scan;
            let latestScanHtml = `
                <p><strong>Scan ID:</strong> ${latestScan.scan_id}</p>
                <p><strong>Target IP:</strong> ${latestScan.target_ip}</p>
                <p><strong>Timestamp:</strong> ${latestScan.timestamp}</p>
            `;

            let openPortsCount = 0;
            let totalPortsScanned = 0;

            for (const host in latestScan.scan_details) {
                const hostDetails = latestScan.scan_details[host];
                latestScanHtml += `
                    <h3>Host: ${host}</h3>
                    <p><strong>Hostname:</strong> ${hostDetails.hostname}</p>
                    <p><strong>OS Details:</strong> ${hostDetails.os_details}</p>
                    <h4>Open Ports:</h4>
                    <ul>
                `;
                if (Object.keys(hostDetails.ports).length > 0) {
                    totalPortsScanned = Object.keys(latestScan.ports_to_scan || {}).length || Object.keys(hostDetails.ports).length;
                    for (const port in hostDetails.ports) {
                        const portInfo = hostDetails.ports[port];
                        if (portInfo.state === 'open') {
                            openPortsCount++;
                            latestScanHtml += `
                                <li><strong>Port ${port}</strong> - State: ${portInfo.state}, Service: ${portInfo.name}, Version: ${portInfo.version}</li>
                            `;
                        }
                    }
                }
                if (openPortsCount === 0) {
                    latestScanHtml += `<li>No open ports found.</li>`;
                }
                latestScanHtml += `</ul>`;
            }
            latestScanDiv.innerHTML = latestScanHtml;

            const closedPortsCount = totalPortsScanned - openPortsCount;

            // Update chart data
            if (scanChartInstance) {
                scanChartInstance.destroy();
            }

            scanChartInstance = new Chart(scanChartCanvas, {
                type: 'pie',
                data: {
                    labels: ['Open Ports', 'Closed/Filtered Ports'],
                    datasets: [{
                        data: [openPortsCount, closedPortsCount],
                        backgroundColor: ['#28a745', '#dc3545'],
                        hoverOffset: 4
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'top',
                        },
                        title: {
                            display: true,
                            text: 'Port Scan Summary'
                        }
                    }
                }
            });
        } else {
            latestScanDiv.innerHTML = '<p>No scan results available yet. Perform a scan above.</p>';
            if (scanChartInstance) {
                scanChartInstance.destroy();
                scanChartInstance = null;
            }
        }

        // --- Update AI Analysis Section ---
        if (data.analysis && data.analysis.vulnerabilities.length > 0) {
            let vulnerabilitiesHtml = '<h3>Potential Vulnerabilities:</h3><ul>';
            data.analysis.vulnerabilities.forEach(v => {
                vulnerabilitiesHtml += `<li>${v}</li>`;
            });
            vulnerabilitiesHtml += '</ul>';

            let recommendationsHtml = '<h3>Recommendations:</h3><ul>';
            data.analysis.recommendations.forEach(r => {
                recommendationsHtml += `<li>${r}</li>`;
            });
            recommendationsHtml += '</ul>';

            aiAnalysisDiv.innerHTML = `
                <p><strong>AI Status:</strong> ${data.analysis.ai_status}</p>
                ${vulnerabilitiesHtml}
                ${recommendationsHtml}
            `;
        } else {
            aiAnalysisDiv.innerHTML = '<p>No analysis results available or no vulnerabilities detected in the latest scan.</p>';
        }

        // --- Update Previous Scans Section ---
        if (data.all_scans && data.all_scans.length > 0) {
            let prevScansHtml = '<ul>';
            data.all_scans.forEach(scan => {
                prevScansHtml += `
                    <li>
                        <strong>Scan ID:</strong> ${scan.scan_id} |
                        <strong>Target:</strong> ${scan.target_ip} |
                        <strong>Status:</strong> ${scan.scan_details ? 'Scan completed' : 'Scan failed'}
                        <br><small>(${scan.timestamp})</small>
                    </li>
                `;
            });
            prevScansHtml += '</ul>';
            previousScansDiv.innerHTML = prevScansHtml;
        } else {
            previousScansDiv.innerHTML = '<p>No previous scans found.</p>';
        }

    } catch (error) {
        console.error('Error fetching latest data:', error);
        showStatus('Error loading latest data. Check console for details.', 'danger');
    }
}

document.addEventListener('DOMContentLoaded', fetchLatestData);