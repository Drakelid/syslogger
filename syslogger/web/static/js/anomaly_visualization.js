/**
 * Anomaly Detection Visualization - SysLogger
 * This file contains functions for visualizing ML-based network anomaly detection results
 */

// Initialize charts when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('anomalyDashboard')) {
        initAnomalyDashboard();
    }
});

// Socket.io connection for real-time updates
let anomalySocket = null;

/**
 * Initialize the anomaly detection dashboard
 */
function initAnomalyDashboard() {
    // Load initial data
    loadAnomalyStats();
    loadRecentAnomalies();
    
    // Set up real-time updates if socket.io is available
    if (typeof io !== 'undefined') {
        anomalySocket = io.connect('/anomaly');
        
        // Listen for new anomaly events
        anomalySocket.on('new_anomaly', function(data) {
            // Update charts and tables
            updateAnomalyCounters(data);
            addAnomalyToTable(data);
            
            // Display notification
            showAnomalyNotification(data);
        });
    }
    
    // Set up filter form
    setupAnomalyFilters();
}

/**
 * Load anomaly statistics and create charts
 */
function loadAnomalyStats() {
    fetch('/api/anomalies/stats')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                createAnomalyCharts(data);
                updateAnomalyStatistics(data);
            } else {
                console.error('Error loading anomaly stats:', data.message);
            }
        })
        .catch(error => {
            console.error('Error fetching anomaly stats:', error);
        });
}

/**
 * Load recent anomalies and populate table
 */
function loadRecentAnomalies(limit = 50) {
    fetch(`/api/anomalies/recent?limit=${limit}`)
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                populateAnomaliesTable(data.anomalies);
            } else {
                console.error('Error loading recent anomalies:', data.message);
            }
        })
        .catch(error => {
            console.error('Error fetching recent anomalies:', error);
        });
}

/**
 * Create charts for anomaly visualization
 */
function createAnomalyCharts(data) {
    // Daily anomaly count chart
    createDailyAnomalyChart(data.daily_counts);
    
    // Top source IPs chart
    createTopSourcesChart(data.top_sources);
    
    // Top destination IPs chart
    createTopDestinationsChart(data.top_destinations);
    
    // Score distribution chart
    createScoreDistributionChart(data);
}

/**
 * Create daily anomaly count chart
 */
function createDailyAnomalyChart(dailyCounts) {
    const ctx = document.getElementById('dailyAnomalyChart');
    if (!ctx) return;
    
    const labels = dailyCounts.map(item => item.day);
    const counts = dailyCounts.map(item => item.count);
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Anomalies Detected',
                data: counts,
                borderColor: 'rgba(255, 99, 132, 1)',
                backgroundColor: 'rgba(255, 99, 132, 0.2)',
                borderWidth: 2,
                fill: true,
                tension: 0.2
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Daily Anomaly Detections'
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Count'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Date'
                    }
                }
            }
        }
    });
}

/**
 * Create top source IPs chart
 */
function createTopSourcesChart(topSources) {
    const ctx = document.getElementById('topSourcesChart');
    if (!ctx) return;
    
    const labels = topSources.map(item => item.ip);
    const counts = topSources.map(item => item.count);
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Anomaly Count',
                data: counts,
                backgroundColor: 'rgba(54, 162, 235, 0.7)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Top Source IPs with Anomalies'
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Count'
                    }
                }
            }
        }
    });
}

/**
 * Create top destination IPs chart
 */
function createTopDestinationsChart(topDestinations) {
    const ctx = document.getElementById('topDestinationsChart');
    if (!ctx) return;
    
    const labels = topDestinations.map(item => item.ip);
    const counts = topDestinations.map(item => item.count);
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Anomaly Count',
                data: counts,
                backgroundColor: 'rgba(75, 192, 192, 0.7)',
                borderColor: 'rgba(75, 192, 192, 1)',
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Top Destination IPs with Anomalies'
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Count'
                    }
                }
            }
        }
    });
}

/**
 * Create score distribution chart
 */
function createScoreDistributionChart(data) {
    // This would typically use more data - either fetched separately
    // or calculated from the individual anomalies
    
    // For now, we just show average score as a gauge
    const ctx = document.getElementById('scoreDistributionChart');
    if (!ctx) return;
    
    // Normalize average score for gauge display (0-100)
    // Note: In Isolation Forest, more negative scores are more anomalous
    const normalizedScore = Math.min(100, Math.max(0, (data.avg_score + 1) * 50));
    
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Anomaly Score', 'Remaining'],
            datasets: [{
                data: [normalizedScore, 100 - normalizedScore],
                backgroundColor: [
                    getScoreColor(normalizedScore),
                    'rgba(220, 220, 220, 0.5)'
                ],
                borderWidth: 0
            }]
        },
        options: {
            circumference: 180,
            rotation: -90,
            cutout: '80%',
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Average Anomaly Score'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `Score: ${data.avg_score.toFixed(4)}`;
                        }
                    }
                }
            }
        }
    });
}

/**
 * Update statistics display
 */
function updateAnomalyStatistics(data) {
    const elements = {
        totalAnomalies: document.getElementById('totalAnomalies'),
        avgScore: document.getElementById('avgAnomalyScore'),
        timeRange: document.getElementById('anomalyTimeRange')
    };
    
    if (elements.totalAnomalies) {
        elements.totalAnomalies.textContent = data.total_anomalies;
    }
    
    if (elements.avgScore) {
        elements.avgScore.textContent = data.avg_score.toFixed(4);
    }
    
    if (elements.timeRange) {
        const start = new Date(data.time_range.start);
        const end = new Date(data.time_range.end);
        elements.timeRange.textContent = `${start.toLocaleDateString()} - ${end.toLocaleDateString()}`;
    }
}

/**
 * Populate anomalies table with data
 */
function populateAnomaliesTable(anomalies) {
    const tableBody = document.getElementById('anomalyTableBody');
    if (!tableBody) return;
    
    // Clear existing rows
    tableBody.innerHTML = '';
    
    // Add new rows
    anomalies.forEach(anomaly => {
        addAnomalyToTable(anomaly, tableBody);
    });
}

/**
 * Add a single anomaly to the table
 */
function addAnomalyToTable(anomaly, tableBody = null) {
    tableBody = tableBody || document.getElementById('anomalyTableBody');
    if (!tableBody) return;
    
    const row = document.createElement('tr');
    
    // Apply highlighting based on score
    if (anomaly.score < -0.5) {
        row.classList.add('table-danger');
    } else if (anomaly.score < -0.3) {
        row.classList.add('table-warning');
    }
    
    // Format timestamp
    const timestamp = new Date(anomaly.timestamp);
    const formattedTime = timestamp.toLocaleString();
    
    // Create row content
    row.innerHTML = `
        <td>${formattedTime}</td>
        <td>${anomaly.src_ip}</td>
        <td>${anomaly.dst_ip}</td>
        <td>${anomaly.score.toFixed(4)}</td>
        <td>
            <button class="btn btn-sm btn-info viewDetails" data-id="${anomaly.id || ''}">
                Details
            </button>
        </td>
    `;
    
    // Add click handler for details button
    const detailsBtn = row.querySelector('.viewDetails');
    if (detailsBtn) {
        detailsBtn.addEventListener('click', function() {
            // If we have an ID, fetch details from API, otherwise use the anomaly object
            if (anomaly.id) {
                showAnomalyDetails(anomaly.id);
            } else {
                showAnomalyDetailsModal(anomaly);
            }
        });
    }
    
    // Add to table (at the beginning for newest first)
    if (tableBody.firstChild) {
        tableBody.insertBefore(row, tableBody.firstChild);
    } else {
        tableBody.appendChild(row);
    }
}

/**
 * Fetch and display details for an anomaly
 */
function showAnomalyDetails(anomalyId) {
    fetch(`/api/anomalies/details/${anomalyId}`)
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                showAnomalyDetailsModal(data.anomaly);
            } else {
                console.error('Error loading anomaly details:', data.message);
            }
        })
        .catch(error => {
            console.error('Error fetching anomaly details:', error);
        });
}

/**
 * Display anomaly details in a modal
 */
function showAnomalyDetailsModal(anomaly) {
    const modal = document.getElementById('anomalyDetailModal');
    if (!modal) return;
    
    // Populate modal content
    document.getElementById('anomalyTimestamp').textContent = new Date(anomaly.timestamp).toLocaleString();
    document.getElementById('anomalySourceIP').textContent = anomaly.src_ip;
    document.getElementById('anomalyDestIP').textContent = anomaly.dst_ip;
    document.getElementById('anomalyScore').textContent = anomaly.score.toFixed(4);
    
    // Display features if available
    const featuresList = document.getElementById('anomalyFeaturesList');
    if (featuresList && anomaly.features) {
        featuresList.innerHTML = '';
        Object.entries(anomaly.features).forEach(([key, value]) => {
            const li = document.createElement('li');
            li.classList.add('list-group-item');
            li.innerHTML = `<strong>${key}:</strong> ${value}`;
            featuresList.appendChild(li);
        });
    }
    
    // Show the modal
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();
}

/**
 * Set up anomaly filter form
 */
function setupAnomalyFilters() {
    const filterForm = document.getElementById('anomalyFilterForm');
    if (!filterForm) return;
    
    filterForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Get form data
        const formData = new FormData(filterForm);
        const params = new URLSearchParams();
        
        // Add non-empty values to URL params
        for (const [key, value] of formData.entries()) {
            if (value) {
                params.append(key, value);
            }
        }
        
        // Fetch filtered results
        fetch(`/api/anomalies/search?${params.toString()}`)
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    populateAnomaliesTable(data.anomalies);
                    
                    // Update result count
                    const resultCount = document.getElementById('anomalyResultCount');
                    if (resultCount) {
                        resultCount.textContent = `${data.total} results found`;
                    }
                } else {
                    console.error('Error filtering anomalies:', data.message);
                }
            })
            .catch(error => {
                console.error('Error fetching filtered anomalies:', error);
            });
    });
    
    // Reset button
    const resetBtn = filterForm.querySelector('button[type="reset"]');
    if (resetBtn) {
        resetBtn.addEventListener('click', function() {
            setTimeout(() => {
                loadRecentAnomalies();
            }, 10);
        });
    }
}

/**
 * Show notification for new anomaly
 */
function showAnomalyNotification(anomaly) {
    // Only proceed if notifications container exists
    const container = document.getElementById('notificationContainer');
    if (!container) return;
    
    // Create notification element
    const notification = document.createElement('div');
    notification.classList.add('toast', 'show');
    
    // Set background color based on anomaly score
    const bgClass = anomaly.score < -0.5 ? 'bg-danger' : 'bg-warning';
    notification.classList.add(bgClass);
    
    notification.innerHTML = `
        <div class="toast-header">
            <strong class="me-auto">Network Anomaly Detected</strong>
            <small>Just now</small>
            <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
        </div>
        <div class="toast-body">
            <p><strong>Source:</strong> ${anomaly.src_ip}</p>
            <p><strong>Destination:</strong> ${anomaly.dst_ip}</p>
            <p><strong>Score:</strong> ${anomaly.score.toFixed(4)}</p>
        </div>
    `;
    
    // Add to container
    container.appendChild(notification);
    
    // Auto-remove after 10 seconds
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            container.removeChild(notification);
        }, 500);
    }, 10000);
}

/**
 * Get color for anomaly score visualization
 */
function getScoreColor(score) {
    if (score < 20) {
        return 'rgba(220, 53, 69, 0.8)'; // danger
    } else if (score < 40) {
        return 'rgba(255, 193, 7, 0.8)'; // warning
    } else if (score < 60) {
        return 'rgba(255, 193, 7, 0.6)'; // light warning
    } else if (score < 80) {
        return 'rgba(25, 135, 84, 0.6)'; // light success
    } else {
        return 'rgba(25, 135, 84, 0.8)'; // success
    }
}

/**
 * Update counters when new anomaly is detected
 */
function updateAnomalyCounters(anomaly) {
    const totalElement = document.getElementById('totalAnomalies');
    if (totalElement) {
        const currentCount = parseInt(totalElement.textContent) || 0;
        totalElement.textContent = currentCount + 1;
    }
}
