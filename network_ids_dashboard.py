"""
Web Dashboard for Standalone Network IDS
Real-time visualization of network attacks
"""

from flask import Flask, render_template_string, jsonify
from flask_socketio import SocketIO, emit
import threading
import json
import os
from datetime import datetime
from collections import defaultdict
import time

# Import the Network IDS
from network_ids import NetworkIDS

app = Flask(__name__)
app.config['SECRET_KEY'] = 'network-ids-secret'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global IDS instance
network_ids = None
ids_running = False


DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network IDS Dashboard</title>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0a0e27 0%, #1a1a2e 100%);
            color: #e0e0e0;
        }

        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            padding: 20px 40px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header h1 {
            font-size: 2em;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .status-badge {
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            animation: pulse 2s infinite;
        }

        .status-active {
            background: #27ae60;
            color: white;
            box-shadow: 0 0 15px rgba(39, 174, 96, 0.6);
        }

        .status-inactive {
            background: #e74c3c;
            color: white;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 30px;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: linear-gradient(135deg, #1e1e2f 0%, #2a2a3e 100%);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.4);
            border: 1px solid #3a3a4e;
            transition: transform 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-5px);
        }

        .stat-label {
            color: #95a5a6;
            font-size: 0.9em;
            margin-bottom: 10px;
        }

        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #fff;
        }

        .stat-icon {
            font-size: 2.5em;
            float: right;
        }

        .chart-container {
            background: linear-gradient(135deg, #1e1e2f 0%, #2a2a3e 100%);
            border-radius: 15px;
            padding: 15px;
            margin-bottom: 20px;
            box-shadow: 0 6px 20px rgba(0,0,0,0.4);
            height: 300px;  /* Increased height */
        }

        .chart-title {
            color: #4a90e2;
            margin-bottom: 20px;
            font-size: 1.3em;
            border-bottom: 2px solid #3a3a4e;
            padding-bottom: 10px;
        }

        .alerts-container {
            background: linear-gradient(135deg, #1e1e2f 0%, #2a2a3e 100%);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        }

        .alert-item {
            background: rgba(231, 76, 60, 0.1);
            border-left: 4px solid #e74c3c;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 8px;
            animation: slideIn 0.5s ease;
        }

        @keyframes slideIn {
            from {
                transform: translateX(-100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }

        .alert-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
        }

        .alert-type {
            font-weight: bold;
            color: #e74c3c;
            font-size: 1.1em;
        }

        .alert-severity {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
        }

        .severity-critical {
            background: #c0392b;
            color: white;
        }

        .severity-high {
            background: #e67e22;
            color: white;
        }

        .severity-medium {
            background: #f39c12;
            color: white;
        }

        .alert-details {
            color: #bdc3c7;
            font-size: 0.9em;
            margin-top: 10px;
        }

        .protocol-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }

        .protocol-item {
            background: rgba(74, 144, 226, 0.1);
            padding: 15px;
            border-radius: 10px;
            text-align: center;
        }

        .protocol-name {
            color: #4a90e2;
            font-size: 0.9em;
            margin-bottom: 5px;
        }

        .protocol-count {
            font-size: 1.8em;
            font-weight: bold;
            color: #fff;
        }

        .live-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            background: #27ae60;
            border-radius: 50%;
            animation: blink 1s infinite;
        }

        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>
            📡 Network Intrusion Detection System
        </h1>
        <div>
            <span class="status-badge" id="statusBadge">INITIALIZING</span>
            <span style="margin-left: 15px; color: #bdc3c7;">
                <span class="live-indicator"></span> Live Monitoring
            </span>
        </div>
    </div>

    <div class="container">
        <!-- Statistics Grid -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon">📦</div>
                <div class="stat-label">Total Packets</div>
                <div class="stat-value" id="totalPackets">0</div>
            </div>

            <div class="stat-card">
                <div class="stat-icon">🚨</div>
                <div class="stat-label">Alerts Generated</div>
                <div class="stat-value" id="totalAlerts" style="color: #e74c3c;">0</div>
            </div>

            <div class="stat-card">
                <div class="stat-icon">🌐</div>
                <div class="stat-label">Unique IPs</div>
                <div class="stat-value" id="uniqueIPs">0</div>
            </div>

            <div class="stat-card">
                <div class="stat-icon">⚡</div>
                <div class="stat-label">Packets/Second</div>
                <div class="stat-value" id="packetsPerSec">0</div>
            </div>

            <div class="stat-card">
                <div class="stat-icon">💾</div>
                <div class="stat-label">Data Processed</div>
                <div class="stat-value" id="totalBytes" style="font-size: 1.5em;">0 MB</div>
            </div>

            <div class="stat-card">
                <div class="stat-icon">⏱️</div>
                <div class="stat-label">Uptime</div>
                <div class="stat-value" id="uptime" style="font-size: 1.5em;">0m</div>
            </div>
        </div>

        <!-- Protocol Statistics -->
        <div class="chart-container">
            <div class="chart-title">📊 Protocol Distribution</div>
            <div class="protocol-stats">
                <div class="protocol-item">
                    <div class="protocol-name">TCP</div>
                    <div class="protocol-count" id="tcpCount">0</div>
                </div>
                <div class="protocol-item">
                    <div class="protocol-name">UDP</div>
                    <div class="protocol-count" id="udpCount">0</div>
                </div>
                <div class="protocol-item">
                    <div class="protocol-name">ICMP</div>
                    <div class="protocol-count" id="icmpCount">0</div>
                </div>
                <div class="protocol-item">
                    <div class="protocol-name">ARP</div>
                    <div class="protocol-count" id="arpCount">0</div>
                </div>
                <div class="protocol-item">
                    <div class="protocol-name">Other</div>
                    <div class="protocol-count" id="otherCount">0</div>
                </div>
            </div>
        </div>

        <!-- Charts -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px;">
            <div class="chart-container">
                <div class="chart-title">Attack Types Distribution</div>
                <canvas id="attackChart" height="150"></canvas>

            </div>

            <div class="chart-container">
                <div class="chart-title">Traffic Timeline</div>
                <canvas id="trafficChart" height="150"></canvas>
            </div>
        </div>

        <!-- Recent Alerts -->
        <div class="alerts-container">
            <div class="chart-title">🚨 Recent Alerts</div>
            <div id="alertsList">
                <p style="text-align: center; color: #7f8c8d; padding: 40px;">
                    Waiting for alerts...
                </p>
            </div>
        </div>
    </div>

    <script>
        const socket = io();
        let attackChart, trafficChart;
        let trafficData = [];
        let startTime = Date.now();

        // Initialize charts
        function initCharts() {
            const ctx1 = document.getElementById('attackChart').getContext('2d');
            attackChart = new Chart(ctx1, {
                type: 'doughnut',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        backgroundColor: [
                            '#e74c3c', '#3498db', '#f39c12', '#9b59b6',
                            '#1abc9c', '#e67e22', '#2ecc71', '#34495e'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: { color: '#e0e0e0' }
                        }
                    }
                }
            });

            const ctx2 = document.getElementById('trafficChart').getContext('2d');
            trafficChart = new Chart(ctx2, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Packets/sec',
                        data: [],
                        borderColor: '#3498db',
                        backgroundColor: 'rgba(52, 152, 219, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: { color: '#e0e0e0' }
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { color: '#e0e0e0' },
                            grid: { color: 'rgba(255,255,255,0.1)' }
                        },
                        x: {
                            ticks: { color: '#e0e0e0' },
                            grid: { color: 'rgba(255,255,255,0.1)' }
                        }
                    }
                }
            });
        }

        // Update statistics
        socket.on('stats_update', (stats) => {
            document.getElementById('totalPackets').textContent = stats.total_packets.toLocaleString();
            document.getElementById('totalAlerts').textContent = stats.alerts_generated.toLocaleString();
            document.getElementById('uniqueIPs').textContent = stats.unique_ips.toLocaleString();
            document.getElementById('totalBytes').textContent = (stats.total_bytes / (1024*1024)).toFixed(2) + ' MB';
            
            // Protocol counts
            document.getElementById('tcpCount').textContent = stats.tcp_packets.toLocaleString();
            document.getElementById('udpCount').textContent = stats.udp_packets.toLocaleString();
            document.getElementById('icmpCount').textContent = stats.icmp_packets.toLocaleString();
            document.getElementById('arpCount').textContent = stats.arp_packets.toLocaleString();
            document.getElementById('otherCount').textContent = stats.other_packets.toLocaleString();

            // Calculate packets per second
            const uptime = (Date.now() - startTime) / 1000;
            const pps = stats.total_packets / Math.max(uptime, 1);
            document.getElementById('packetsPerSec').textContent = pps.toFixed(1);

            // Uptime
            const minutes = Math.floor(uptime / 60);
            const hours = Math.floor(minutes / 60);
            const displayMinutes = minutes % 60;
            document.getElementById('uptime').textContent = hours > 0 
                ? `${hours}h ${displayMinutes}m`
                : `${minutes}m`;

            // Update traffic chart
            const now = new Date().toLocaleTimeString();
            trafficData.push({ time: now, pps: pps });
            if (trafficData.length > 20) trafficData.shift();

            trafficChart.data.labels = trafficData.map(d => d.time);
            trafficChart.data.datasets[0].data = trafficData.map(d => d.pps);
            trafficChart.update();
        });

        // Update attack distribution
        socket.on('attack_distribution', (distribution) => {
            if (Object.keys(distribution).length > 0) {
                attackChart.data.labels = Object.keys(distribution);
                attackChart.data.datasets[0].data = Object.values(distribution);
                attackChart.update();
            }
        });

        // New alert
        socket.on('new_alert', (alert) => {
            addAlert(alert);
            playAlertSound();
        });

        // Add alert to list
        function addAlert(alert) {
            const alertsList = document.getElementById('alertsList');
            
            // Remove "waiting" message
            if (alertsList.children.length === 1 && alertsList.children[0].tagName === 'P') {
                alertsList.innerHTML = '';
            }

            const alertDiv = document.createElement('div');
            alertDiv.className = 'alert-item';
            
            const severityClass = `severity-${alert.severity.toLowerCase()}`;
            
            alertDiv.innerHTML = `
                <div class="alert-header">
                    <div class="alert-type">${alert.attack_type}</div>
                    <div class="alert-severity ${severityClass}">${alert.severity}</div>
                </div>
                <div style="color: #95a5a6; font-size: 0.9em;">
                    <strong>Source IP:</strong> ${alert.src_ip} | 
                    <strong>Time:</strong> ${new Date(alert.timestamp).toLocaleTimeString()} |
                    <strong>Confidence:</strong> ${(alert.confidence * 100).toFixed(1)}%
                    <strong>Anomaly Score:</strong> ${alert.details.anomaly_score?.toFixed(4) || "N/A"}
                </div>
                <div class="alert-details">
                    ${alert.details.description || 'No description'}
                </div>
            `;

            alertsList.insertBefore(alertDiv, alertsList.firstChild);

            // Keep only last 20 alerts
            while (alertsList.children.length > 20) {
                alertsList.removeChild(alertsList.lastChild);
            }
        }

        function playAlertSound() {
            // Optional: Add sound notification
        }

        // Connection status
        socket.on('connect', () => {
            document.getElementById('statusBadge').textContent = 'CONNECTED';
            document.getElementById('statusBadge').className = 'status-badge status-active';
        });

        socket.on('disconnect', () => {
            document.getElementById('statusBadge').textContent = 'DISCONNECTED';
            document.getElementById('statusBadge').className = 'status-badge status-inactive';
        });

        // Initialize
        initCharts();
    </script>
</body>
</html>
"""


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template_string(DASHBOARD_HTML)


@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    if network_ids:
        return jsonify(network_ids.stats)
    return jsonify({'error': 'IDS not running'}), 503


@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts"""
    if network_ids:
        return jsonify(list(network_ids.alerts))
    return jsonify([])


@app.route('/api/alert_counts')
def get_alert_counts():
    """Get alert distribution"""
    if network_ids:
        return jsonify(dict(network_ids.alert_counts))
    return jsonify({})


def broadcast_stats():
    """Broadcast statistics to dashboard"""
    while ids_running:
        try:
            if network_ids:
                # Send stats
                safe_stats = network_ids._make_json_serializable(network_ids.stats)
                socketio.emit('stats_update', safe_stats)
                
                # Send attack distribution
                socketio.emit('attack_distribution', dict(network_ids.alert_counts))
            
            time.sleep(2)
        except Exception as e:
            print(f"Broadcast error: {e}")


def custom_alert_callback(alert: dict):
    """Custom callback to broadcast alerts to dashboard"""
    try:
        socketio.emit('new_alert', alert)
    except Exception as e:
        print(f"Alert broadcast error: {e}")


def start_network_ids(interface=None):
    """Start the Network IDS"""
    global network_ids, ids_running
    
    print("\n🚀 Initializing Network IDS...")
    
    # Create IDS instance
    network_ids = NetworkIDS(
        interface=interface,
        alert_file='network_alerts.json'
    )
    
    # Register custom callback for dashboard
    original_create_alert = network_ids._create_alert
    
    def wrapped_create_alert(*args, **kwargs):
        original_create_alert(*args, **kwargs)
        # Broadcast to dashboard
        if network_ids.alerts:
            custom_alert_callback(network_ids.alerts[-1])
    
    network_ids._create_alert = wrapped_create_alert
    
    # Start IDS
    if network_ids.start():
        ids_running = True
        print("✓ Network IDS started successfully")
        
        # Start stats broadcaster
        stats_thread = threading.Thread(target=broadcast_stats, daemon=True)
        stats_thread.start()
    else:
        print("❌ Failed to start Network IDS")


if __name__ == '__main__':
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description='Network IDS Dashboard')
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-p', '--port', type=int, default=5001, help='Dashboard port (default: 5001)')
    
    args = parser.parse_args()
    
    # Start Network IDS in background thread
    ids_thread = threading.Thread(
        target=start_network_ids,
        args=(args.interface,),
        daemon=True
    )
    ids_thread.start()
    
    # Wait a moment for initialization
    time.sleep(2)
    
    # Start Flask dashboard
    print(f"\n🌐 Starting dashboard on http://localhost:{args.port}")
    print(f"   Open in browser to view real-time monitoring")
    print(f"   Press Ctrl+C to stop\n")
    
    try:
        socketio.run(app, host='0.0.0.0', port=args.port, debug=False)
    except KeyboardInterrupt:
        print("\n\n⚠ Stopping...")
        ids_running = False
        if network_ids:
            network_ids.stop()