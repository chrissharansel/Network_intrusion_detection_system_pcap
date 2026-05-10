# """
# Web Dashboard for Standalone Network IDS
# Real-time visualization of network attacks
# """

# from flask import Flask, render_template_string, jsonify
# from flask_socketio import SocketIO, emit
# import threading
# import json
# import os
# from datetime import datetime
# from collections import defaultdict
# import time

# # Import the Network IDS
# from network_ids2 import NetworkIDS

# app = Flask(__name__)
# app.config['SECRET_KEY'] = 'network-ids-secret'
# socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# # Global IDS instance
# network_ids = None
# ids_running = False


# DASHBOARD_HTML = """
# <!DOCTYPE html>
# <html lang="en">
# <head>
#     <meta charset="UTF-8">
#     <meta name="viewport" content="width=device-width, initial-scale=1.0">
#     <title>Network IDS Dashboard</title>
#     <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
#     <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
#     <style>
#         * {
#             margin: 0;
#             padding: 0;
#             box-sizing: border-box;
#         }

#         body {
#             font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
#             background: linear-gradient(135deg, #0a0e27 0%, #1a1a2e 100%);
#             color: #e0e0e0;
#         }

#         .header {
#             background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
#             padding: 20px 40px;
#             box-shadow: 0 4px 20px rgba(0,0,0,0.3);
#             display: flex;
#             justify-content: space-between;
#             align-items: center;
#         }

#         .header h1 {
#             font-size: 2em;
#             color: #fff;
#             display: flex;
#             align-items: center;
#             gap: 15px;
#         }

#         .status-badge {
#             padding: 8px 16px;
#             border-radius: 20px;
#             font-size: 0.8em;
#             font-weight: bold;
#             animation: pulse 2s infinite;
#         }

#         .status-active {
#             background: #27ae60;
#             color: white;
#             box-shadow: 0 0 15px rgba(39, 174, 96, 0.6);
#         }

#         .status-inactive {
#             background: #e74c3c;
#             color: white;
#         }

#         @keyframes pulse {
#             0%, 100% { opacity: 1; }
#             50% { opacity: 0.7; }
#         }

#         .container {
#             max-width: 1600px;
#             margin: 0 auto;
#             padding: 30px;
#         }

#         .stats-grid {
#             display: grid;
#             grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
#             gap: 20px;
#             margin-bottom: 30px;
#         }

#         .stat-card {
#             background: linear-gradient(135deg, #1e1e2f 0%, #2a2a3e 100%);
#             border-radius: 15px;
#             padding: 25px;
#             box-shadow: 0 8px 32px rgba(0,0,0,0.4);
#             border: 1px solid #3a3a4e;
#             transition: transform 0.3s ease;
#         }

#         .stat-card:hover {
#             transform: translateY(-5px);
#         }

#         .stat-label {
#             color: #95a5a6;
#             font-size: 0.9em;
#             margin-bottom: 10px;
#         }

#         .stat-value {
#             font-size: 2.5em;
#             font-weight: bold;
#             color: #fff;
#         }

#         .stat-icon {
#             font-size: 2.5em;
#             float: right;
#         }

#         .chart-container {
#             background: linear-gradient(135deg, #1e1e2f 0%, #2a2a3e 100%);
#             border-radius: 15px;
#             padding: 15px;
#             margin-bottom: 20px;
#             box-shadow: 0 6px 20px rgba(0,0,0,0.4);
#             height: 300px;  /* Increased height */
#         }

#         .chart-title {
#             color: #4a90e2;
#             margin-bottom: 20px;
#             font-size: 1.3em;
#             border-bottom: 2px solid #3a3a4e;
#             padding-bottom: 10px;
#         }

#         .alerts-container {
#             background: linear-gradient(135deg, #1e1e2f 0%, #2a2a3e 100%);
#             border-radius: 15px;
#             padding: 25px;
#             box-shadow: 0 8px 32px rgba(0,0,0,0.4);
#         }

#         .alert-item {
#             background: rgba(231, 76, 60, 0.1);
#             border-left: 4px solid #e74c3c;
#             padding: 15px;
#             margin-bottom: 15px;
#             border-radius: 8px;
#             animation: slideIn 0.5s ease;
#         }

#         @keyframes slideIn {
#             from {
#                 transform: translateX(-100%);
#                 opacity: 0;
#             }
#             to {
#                 transform: translateX(0);
#                 opacity: 1;
#             }
#         }

#         .alert-header {
#             display: flex;
#             justify-content: space-between;
#             margin-bottom: 10px;
#         }

#         .alert-type {
#             font-weight: bold;
#             color: #e74c3c;
#             font-size: 1.1em;
#         }

#         .alert-severity {
#             padding: 4px 12px;
#             border-radius: 12px;
#             font-size: 0.8em;
#             font-weight: bold;
#         }

#         .severity-critical {
#             background: #c0392b;
#             color: white;
#         }

#         .severity-high {
#             background: #e67e22;
#             color: white;
#         }

#         .severity-medium {
#             background: #f39c12;
#             color: white;
#         }

#         .alert-details {
#             color: #bdc3c7;
#             font-size: 0.9em;
#             margin-top: 10px;
#         }

#         .protocol-stats {
#             display: grid;
#             grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
#             gap: 15px;
#             margin-top: 20px;
#         }

#         .protocol-item {
#             background: rgba(74, 144, 226, 0.1);
#             padding: 15px;
#             border-radius: 10px;
#             text-align: center;
#         }

#         .protocol-name {
#             color: #4a90e2;
#             font-size: 0.9em;
#             margin-bottom: 5px;
#         }

#         .protocol-count {
#             font-size: 1.8em;
#             font-weight: bold;
#             color: #fff;
#         }

#         .live-indicator {
#             display: inline-block;
#             width: 10px;
#             height: 10px;
#             background: #27ae60;
#             border-radius: 50%;
#             animation: blink 1s infinite;
#         }

#         @keyframes blink {
#             0%, 100% { opacity: 1; }
#             50% { opacity: 0.3; }
#         }
#     </style>
# </head>
# <body>
#     <div class="header">
#         <h1>
#             📡 Network Intrusion Detection System
#         </h1>
#         <div>
#             <span class="status-badge" id="statusBadge">INITIALIZING</span>
#             <span style="margin-left: 15px; color: #bdc3c7;">
#                 <span class="live-indicator"></span> Live Monitoring
#             </span>
#         </div>
#     </div>

#     <div class="container">
#         <!-- Statistics Grid -->
#         <div class="stats-grid">
#             <div class="stat-card">
#                 <div class="stat-icon">📦</div>
#                 <div class="stat-label">Total Packets</div>
#                 <div class="stat-value" id="totalPackets">0</div>
#             </div>

#             <div class="stat-card">
#                 <div class="stat-icon">🚨</div>
#                 <div class="stat-label">Alerts Generated</div>
#                 <div class="stat-value" id="totalAlerts" style="color: #e74c3c;">0</div>
#             </div>

#             <div class="stat-card">
#                 <div class="stat-icon">🌐</div>
#                 <div class="stat-label">Unique IPs</div>
#                 <div class="stat-value" id="uniqueIPs">0</div>
#             </div>

#             <div class="stat-card">
#                 <div class="stat-icon">⚡</div>
#                 <div class="stat-label">Packets/Second</div>
#                 <div class="stat-value" id="packetsPerSec">0</div>
#             </div>

#             <div class="stat-card">
#                 <div class="stat-icon">💾</div>
#                 <div class="stat-label">Data Processed</div>
#                 <div class="stat-value" id="totalBytes" style="font-size: 1.5em;">0 MB</div>
#             </div>

#             <div class="stat-card">
#                 <div class="stat-icon">⏱️</div>
#                 <div class="stat-label">Uptime</div>
#                 <div class="stat-value" id="uptime" style="font-size: 1.5em;">0m</div>
#             </div>
#         </div>

#         <!-- Protocol Statistics -->
#         <div class="chart-container">
#             <div class="chart-title">📊 Protocol Distribution</div>
#             <div class="protocol-stats">
#                 <div class="protocol-item">
#                     <div class="protocol-name">TCP</div>
#                     <div class="protocol-count" id="tcpCount">0</div>
#                 </div>
#                 <div class="protocol-item">
#                     <div class="protocol-name">UDP</div>
#                     <div class="protocol-count" id="udpCount">0</div>
#                 </div>
#                 <div class="protocol-item">
#                     <div class="protocol-name">ICMP</div>
#                     <div class="protocol-count" id="icmpCount">0</div>
#                 </div>
#                 <div class="protocol-item">
#                     <div class="protocol-name">ARP</div>
#                     <div class="protocol-count" id="arpCount">0</div>
#                 </div>
#                 <div class="protocol-item">
#                     <div class="protocol-name">Other</div>
#                     <div class="protocol-count" id="otherCount">0</div>
#                 </div>
#             </div>
#         </div>

#         <!-- Charts -->
#         <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px;">
#             <div class="chart-container">
#                 <div class="chart-title">Attack Types Distribution</div>
#                 <canvas id="attackChart" height="150"></canvas>

#             </div>

#             <div class="chart-container">
#                 <div class="chart-title">Traffic Timeline</div>
#                 <canvas id="trafficChart" height="150"></canvas>
#             </div>
#         </div>

#         <!-- Recent Alerts -->
#         <div class="alerts-container">
#             <div class="chart-title">🚨 Recent Alerts</div>
#             <div id="alertsList">
#                 <p style="text-align: center; color: #7f8c8d; padding: 40px;">
#                     Waiting for alerts...
#                 </p>
#             </div>
#         </div>
#     </div>

#     <script>
#         const socket = io();
#         let attackChart, trafficChart;
#         let trafficData = [];
#         let startTime = Date.now();

#         // Initialize charts
#         function initCharts() {
#             const ctx1 = document.getElementById('attackChart').getContext('2d');
#             attackChart = new Chart(ctx1, {
#                 type: 'doughnut',
#                 data: {
#                     labels: [],
#                     datasets: [{
#                         data: [],
#                         backgroundColor: [
#                             '#e74c3c', '#3498db', '#f39c12', '#9b59b6',
#                             '#1abc9c', '#e67e22', '#2ecc71', '#34495e'
#                         ]
#                     }]
#                 },
#                 options: {
#                     responsive: true,
#                     maintainAspectRatio: false,
#                     plugins: {
#                         legend: {
#                             position: 'right',
#                             labels: { color: '#e0e0e0' }
#                         }
#                     }
#                 }
#             });

#             const ctx2 = document.getElementById('trafficChart').getContext('2d');
#             trafficChart = new Chart(ctx2, {
#                 type: 'line',
#                 data: {
#                     labels: [],
#                     datasets: [{
#                         label: 'Packets/sec',
#                         data: [],
#                         borderColor: '#3498db',
#                         backgroundColor: 'rgba(52, 152, 219, 0.1)',
#                         tension: 0.4,
#                         fill: true
#                     }]
#                 },
#                 options: {
#                     responsive: true,
#                     maintainAspectRatio: false,
#                     plugins: {
#                         legend: {
#                             labels: { color: '#e0e0e0' }
#                         }
#                     },
#                     scales: {
#                         y: {
#                             beginAtZero: true,
#                             ticks: { color: '#e0e0e0' },
#                             grid: { color: 'rgba(255,255,255,0.1)' }
#                         },
#                         x: {
#                             ticks: { color: '#e0e0e0' },
#                             grid: { color: 'rgba(255,255,255,0.1)' }
#                         }
#                     }
#                 }
#             });
#         }

#         // Update statistics
#         socket.on('stats_update', (stats) => {
#             document.getElementById('totalPackets').textContent = stats.total_packets.toLocaleString();
#             document.getElementById('totalAlerts').textContent = stats.alerts_generated.toLocaleString();
#             document.getElementById('uniqueIPs').textContent = stats.unique_ips.toLocaleString();
#             document.getElementById('totalBytes').textContent = (stats.total_bytes / (1024*1024)).toFixed(2) + ' MB';
            
#             // Protocol counts
#             document.getElementById('tcpCount').textContent = stats.tcp_packets.toLocaleString();
#             document.getElementById('udpCount').textContent = stats.udp_packets.toLocaleString();
#             document.getElementById('icmpCount').textContent = stats.icmp_packets.toLocaleString();
#             document.getElementById('arpCount').textContent = stats.arp_packets.toLocaleString();
#             document.getElementById('otherCount').textContent = stats.other_packets.toLocaleString();

#             // Calculate packets per second
#             const uptime = (Date.now() - startTime) / 1000;
#             const pps = stats.total_packets / Math.max(uptime, 1);
#             document.getElementById('packetsPerSec').textContent = pps.toFixed(1);

#             // Uptime
#             const minutes = Math.floor(uptime / 60);
#             const hours = Math.floor(minutes / 60);
#             const displayMinutes = minutes % 60;
#             document.getElementById('uptime').textContent = hours > 0 
#                 ? `${hours}h ${displayMinutes}m`
#                 : `${minutes}m`;

#             // Update traffic chart
#             const now = new Date().toLocaleTimeString();
#             trafficData.push({ time: now, pps: pps });
#             if (trafficData.length > 20) trafficData.shift();

#             trafficChart.data.labels = trafficData.map(d => d.time);
#             trafficChart.data.datasets[0].data = trafficData.map(d => d.pps);
#             trafficChart.update();
#         });

#         // Update attack distribution
#         socket.on('attack_distribution', (distribution) => {
#             if (Object.keys(distribution).length > 0) {
#                 attackChart.data.labels = Object.keys(distribution);
#                 attackChart.data.datasets[0].data = Object.values(distribution);
#                 attackChart.update();
#             }
#         });

#         // New alert
#         socket.on('new_alert', (alert) => {
#             addAlert(alert);
#             playAlertSound();
#         });

#         // Add alert to list
#         function addAlert(alert) {
#             const alertsList = document.getElementById('alertsList');
            
#             // Remove "waiting" message
#             if (alertsList.children.length === 1 && alertsList.children[0].tagName === 'P') {
#                 alertsList.innerHTML = '';
#             }

#             const alertDiv = document.createElement('div');
#             alertDiv.className = 'alert-item';
            
#             const severityClass = `severity-${alert.severity.toLowerCase()}`;
            
#             alertDiv.innerHTML = `
#                 <div class="alert-header">
#                     <div class="alert-type">${alert.attack_type}</div>
#                     <div class="alert-severity ${severityClass}">${alert.severity}</div>
#                 </div>
#                 <div style="color: #95a5a6; font-size: 0.9em;">
#                     <strong>Source IP:</strong> ${alert.src_ip} | 
#                     <strong>Time:</strong> ${new Date(alert.timestamp).toLocaleTimeString()} |
#                     <strong>Confidence:</strong> ${(alert.confidence * 100).toFixed(1)}%
#                     <strong>Anomaly Score:</strong> ${alert.details.anomaly_score?.toFixed(4) || "N/A"}
#                 </div>
#                 <div class="alert-details">
#                     ${alert.details.description || 'No description'}
#                 </div>
#             `;

#             alertsList.insertBefore(alertDiv, alertsList.firstChild);

#             // Keep only last 20 alerts
#             while (alertsList.children.length > 20) {
#                 alertsList.removeChild(alertsList.lastChild);
#             }
#         }

#         function playAlertSound() {
#             // Optional: Add sound notification
#         }

#         // Connection status
#         socket.on('connect', () => {
#             document.getElementById('statusBadge').textContent = 'CONNECTED';
#             document.getElementById('statusBadge').className = 'status-badge status-active';
#         });

#         socket.on('disconnect', () => {
#             document.getElementById('statusBadge').textContent = 'DISCONNECTED';
#             document.getElementById('statusBadge').className = 'status-badge status-inactive';
#         });

#         // Initialize
#         initCharts();
#     </script>
# </body>
# </html>
# """


# @app.route('/')
# def index():
#     """Main dashboard page"""
#     return render_template_string(DASHBOARD_HTML)


# @app.route('/api/stats')
# def get_stats():
#     """Get current statistics"""
#     if network_ids:
#         return jsonify(network_ids.stats)
#     return jsonify({'error': 'IDS not running'}), 503


# @app.route('/api/alerts')
# def get_alerts():
#     """Get recent alerts"""
#     if network_ids:
#         return jsonify(list(network_ids.alerts))
#     return jsonify([])


# @app.route('/api/alert_counts')
# def get_alert_counts():
#     """Get alert distribution"""
#     if network_ids:
#         return jsonify(dict(network_ids.alert_counts))
#     return jsonify({})


# def broadcast_stats():
#     """Broadcast statistics to dashboard"""
#     while ids_running:
#         try:
#             if network_ids:
#                 # Send stats
#                 safe_stats = network_ids._make_json_serializable(network_ids.stats)
#                 socketio.emit('stats_update', safe_stats)
                
#                 # Send attack distribution
#                 socketio.emit('attack_distribution', dict(network_ids.alert_counts))
            
#             time.sleep(2)
#         except Exception as e:
#             print(f"Broadcast error: {e}")


# def custom_alert_callback(alert: dict):
#     """Custom callback to broadcast alerts to dashboard"""
#     try:
#         socketio.emit('new_alert', alert)
#     except Exception as e:
#         print(f"Alert broadcast error: {e}")


# def start_network_ids(interface=None):
#     """Start the Network IDS"""
#     global network_ids, ids_running
    
#     print("\n🚀 Initializing Network IDS...")
    
#     # Create IDS instance
#     network_ids = NetworkIDS(
#         interface=interface,
#         alert_file='network_alerts.json'
#     )
    
#     # Register custom callback for dashboard
#     original_create_alert = network_ids._create_alert
    
#     def wrapped_create_alert(*args, **kwargs):
#         original_create_alert(*args, **kwargs)
#         # Broadcast to dashboard
#         if network_ids.alerts:
#             custom_alert_callback(network_ids.alerts[-1])
    
#     network_ids._create_alert = wrapped_create_alert
    
#     # Start IDS
#     if network_ids.start():
#         ids_running = True
#         print("✓ Network IDS started successfully")
        
#         # Start stats broadcaster
#         stats_thread = threading.Thread(target=broadcast_stats, daemon=True)
#         stats_thread.start()
#     else:
#         print("❌ Failed to start Network IDS")


# if __name__ == '__main__':
#     import sys
#     import argparse
    
#     parser = argparse.ArgumentParser(description='Network IDS Dashboard')
#     parser.add_argument('-i', '--interface', help='Network interface to monitor')
#     parser.add_argument('-p', '--port', type=int, default=5001, help='Dashboard port (default: 5001)')
    
#     args = parser.parse_args()
    
#     # Start Network IDS in background thread
#     ids_thread = threading.Thread(
#         target=start_network_ids,
#         args=(args.interface,),
#         daemon=True
#     )
#     ids_thread.start()
    
#     # Wait a moment for initialization
#     time.sleep(2)
    
#     # Start Flask dashboard
#     print(f"\n🌐 Starting dashboard on http://localhost:{args.port}")
#     print(f"   Open in browser to view real-time monitoring")
#     print(f"   Press Ctrl+C to stop\n")
    
#     try:
#         socketio.run(app, host='0.0.0.0', port=args.port, debug=False)
#     except KeyboardInterrupt:
#         print("\n\n⚠ Stopping...")
#         ids_running = False
#         if network_ids:
#             network_ids.stop()


# """
# Advanced Network IDS — Web Dashboard v2.0
# Pairs with network_ids_advanced.py

# New backend features:
#   • Full integration with AdvancedNetworkIDS (composite scores, UEBA, beaconing, DNS, GeoIP)
#   • REST endpoints: /api/threats, /api/geo, /api/timeline, /api/top_ips, /api/pcap_files
#   • SocketIO rooms: alerts, stats, threats
#   • Alert severity rate-limiting for UI flood protection
#   • Timeline ring-buffer (last 120 data points, 1/sec resolution)
#   • JWT-ready SECRET_KEY slot (swap in your key)
#   • Graceful IDS lifecycle management (start/stop via API)

# Run:
#     pip install flask flask-socketio eventlet
#     sudo python3 dashboard.py -c config.yaml -p 5001
# """

# import threading
# import time
# import json
# import os
# import sys
# import argparse
# from datetime import datetime, timedelta
# from collections import defaultdict, deque
# from typing import Optional

# from flask import Flask, jsonify, request, abort
# from flask_socketio import SocketIO, emit

# # Import advanced IDS
# try:
#     from network_ids_advanced import AdvancedNetworkIDS, load_config
# except ImportError:
#     print("❌  network_ids_advanced.py not found in the same directory.")
#     sys.exit(1)

# # ─────────────────────────────────────────────────────────────────────
# app = Flask(__name__)
# app.config['SECRET_KEY'] = os.environ.get('IDS_SECRET', 'change-me-in-production')
# socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading',
#                     logger=False, engineio_logger=False)

# # ─────────────────────────────────────────────────────────────────────
# # Global state
# # ─────────────────────────────────────────────────────────────────────
# ids_instance: Optional[AdvancedNetworkIDS] = None
# ids_running   = False

# # Rolling 120-point timeline (1 update/sec)
# TIMELINE_LEN  = 120
# timeline_lock = threading.Lock()
# timeline_pps: deque  = deque([0.0] * TIMELINE_LEN, maxlen=TIMELINE_LEN)
# timeline_bps: deque  = deque([0.0] * TIMELINE_LEN, maxlen=TIMELINE_LEN)
# timeline_alerts: deque = deque([0]  * TIMELINE_LEN, maxlen=TIMELINE_LEN)
# timeline_labels: deque = deque([''] * TIMELINE_LEN, maxlen=TIMELINE_LEN)

# _last_pkt_count  = 0
# _last_byte_count = 0
# _last_alert_count = 0
# _last_tick_time  = time.time()


# # ─────────────────────────────────────────────────────────────────────
# # IDS alert hook
# # ─────────────────────────────────────────────────────────────────────
# def _alert_hook(alert: dict):
#     """Called by patched _create_alert; emits to all SocketIO clients."""
#     try:
#         socketio.emit('new_alert', alert, namespace='/')
#     except Exception:
#         pass


# def _patch_ids_alerts(ids: AdvancedNetworkIDS):
#     """Monkey-patch _create_alert to also fire our hook."""
#     original = ids._alert.__func__ if hasattr(ids._alert, '__func__') else None
#     _orig_method = ids._alert

#     def patched(attack_type, src_ip, severity, confidence, details, score_weight=10):
#         _orig_method(attack_type, src_ip, severity, confidence, details, score_weight)
#         if ids.alerts:
#             _alert_hook(dict(ids.alerts[-1]))

#     ids._alert = patched


# # ─────────────────────────────────────────────────────────────────────
# # Background broadcaster
# # ─────────────────────────────────────────────────────────────────────
# def _broadcaster():
#     global _last_pkt_count, _last_byte_count, _last_alert_count, _last_tick_time

#     while ids_running:
#         time.sleep(1)
#         if not ids_instance:
#             continue

#         now = time.time()
#         dt  = max(now - _last_tick_time, 0.001)
#         _last_tick_time = now

#         s = ids_instance.stats
#         cur_pkts   = s['total_packets']
#         cur_bytes  = s['total_bytes']
#         cur_alerts = s['alerts']

#         pps = (cur_pkts  - _last_pkt_count)  / dt
#         bps = (cur_bytes - _last_byte_count)  / dt
#         new_alerts = cur_alerts - _last_alert_count

#         _last_pkt_count   = cur_pkts
#         _last_byte_count  = cur_bytes
#         _last_alert_count = cur_alerts

#         ts_label = datetime.now().strftime('%H:%M:%S')
#         with timeline_lock:
#             timeline_pps.append(round(pps, 1))
#             timeline_bps.append(round(bps / 1024, 1))   # KB/s
#             timeline_alerts.append(new_alerts)
#             timeline_labels.append(ts_label)

#         # ── full stats payload ────────────────────────────────────────
#         up = (datetime.now() - s['start_time']).total_seconds()
#         threat_top = ids_instance.scoreboard.top_threats(5)

#         payload = {
#             # counters
#             'total_packets':  s['total_packets'],
#             'total_bytes':    s['total_bytes'],
#             'alerts':         s['alerts'],
#             'unique_ips':     len(ids_instance.connections),
#             'tcp':  s['tcp'],  'udp': s['udp'],
#             'icmp': s['icmp'], 'arp': s['arp'], 'dns': s['dns'],
#             # rates
#             'pps': round(pps, 1),
#             'bps_kb': round(bps / 1024, 1),
#             # meta
#             'uptime_s':      round(up, 0),
#             'ml_trained':    ids_instance.ensemble.trained,
#             'pcap_files':    len(ids_instance.pcap_mgr.list_files()),
#             'interface':     ids_instance.interface,
#             # alert breakdown
#             'alert_counts':  dict(ids_instance.alert_counts),
#             # top threats
#             'top_threats': [
#                 {'ip': ip, 'score': round(sc, 1), 'tags': list(set(ev))[:3]}
#                 for ip, sc, ev in threat_top
#             ],
#             # adaptive thresholds
#             'thresholds': ids_instance.adapt_thr.snapshot(),
#         }
#         socketio.emit('stats_update', payload, namespace='/')


# # ─────────────────────────────────────────────────────────────────────
# # REST API
# # ─────────────────────────────────────────────────────────────────────
# def _ids_required(f):
#     from functools import wraps
#     @wraps(f)
#     def wrapper(*args, **kwargs):
#         if not ids_instance:
#             return jsonify({'error': 'IDS not running'}), 503
#         return f(*args, **kwargs)
#     return wrapper


# @app.route('/')
# def index():
#     return DASHBOARD_HTML, 200, {'Content-Type': 'text/html'}


# @app.route('/api/stats')
# @_ids_required
# def api_stats():
#     s = ids_instance.stats
#     up = (datetime.now() - s['start_time']).total_seconds()
#     return jsonify({
#         **{k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in s.items()},
#         'uptime_s':   round(up, 1),
#         'unique_ips': len(ids_instance.connections),
#         'ml_trained': ids_instance.ensemble.trained,
#     })


# @app.route('/api/alerts')
# @_ids_required
# def api_alerts():
#     limit = min(int(request.args.get('limit', 50)), 500)
#     sev   = request.args.get('severity')
#     alerts = list(ids_instance.alerts)
#     if sev:
#         alerts = [a for a in alerts if a.get('severity', '').lower() == sev.lower()]
#     return jsonify(alerts[-limit:])


# @app.route('/api/threats')
# @_ids_required
# def api_threats():
#     n = int(request.args.get('n', 20))
#     return jsonify([
#         {'ip': ip, 'score': round(sc, 1),
#          'evidence': list(set(ev))[:10],
#          'reputation': round(ids_instance.threat_intel.get_reputation(ip), 3),
#          'geo': ids_instance.threat_intel.geolocate(ip)}
#         for ip, sc, ev in ids_instance.scoreboard.top_threats(n)
#     ])


# @app.route('/api/timeline')
# def api_timeline():
#     with timeline_lock:
#         return jsonify({
#             'labels':  list(timeline_labels),
#             'pps':     list(timeline_pps),
#             'bps_kb':  list(timeline_bps),
#             'alerts':  list(timeline_alerts),
#         })


# @app.route('/api/top_ips')
# @_ids_required
# def api_top_ips():
#     n = int(request.args.get('n', 10))
#     rows = sorted(ids_instance.connections.items(),
#                   key=lambda kv: kv[1]['pkt_count'], reverse=True)[:n]
#     return jsonify([
#         {'ip': ip,
#          'packets':  c['pkt_count'],
#          'bytes':    c['bytes'],
#          'ports':    len(c['ports']),
#          'score':    round(ids_instance.scoreboard.get_score(ip), 1),
#          'geo':      ids_instance.threat_intel.geolocate(ip)}
#         for ip, c in rows
#     ])


# @app.route('/api/alert_counts')
# @_ids_required
# def api_alert_counts():
#     return jsonify(dict(ids_instance.alert_counts))


# @app.route('/api/pcap_files')
# @_ids_required
# def api_pcap_files():
#     files = ids_instance.pcap_mgr.list_files()
#     return jsonify([
#         {'name': os.path.basename(f),
#          'size_kb': round(os.path.getsize(f) / 1024, 1),
#          'path': f}
#         for f in files
#     ])


# @app.route('/api/health')
# def api_health():
#     return jsonify({'status': 'ok', 'ids_running': ids_running,
#                     'version': '2.0.0'})


# @app.route('/api/thresholds')
# @_ids_required
# def api_thresholds():
#     return jsonify(ids_instance.adapt_thr.snapshot())


# # ─────────────────────────────────────────────────────────────────────
# # SocketIO events
# # ─────────────────────────────────────────────────────────────────────
# @socketio.on('connect')
# def on_connect():
#     if ids_instance:
#         emit('ids_status', {'running': ids_running,
#                              'interface': ids_instance.interface})


# @socketio.on('request_timeline')
# def on_request_timeline():
#     with timeline_lock:
#         emit('timeline_data', {
#             'labels': list(timeline_labels),
#             'pps':    list(timeline_pps),
#             'bps_kb': list(timeline_bps),
#             'alerts': list(timeline_alerts),
#         })


# @socketio.on('request_top_threats')
# def on_request_top_threats():
#     if ids_instance:
#         emit('top_threats', [
#             {'ip': ip, 'score': round(sc, 1), 'tags': list(set(ev))[:3]}
#             for ip, sc, ev in ids_instance.scoreboard.top_threats(10)
#         ])


# # ─────────────────────────────────────────────────────────────────────
# # IDS lifecycle
# # ─────────────────────────────────────────────────────────────────────
# def start_ids(cfg: dict):
#     global ids_instance, ids_running

#     ids_instance = AdvancedNetworkIDS(cfg)
#     _patch_ids_alerts(ids_instance)
#     ids_instance.start()
#     ids_running = True

#     broadcaster = threading.Thread(target=_broadcaster, daemon=True)
#     broadcaster.start()
#     print("✅  Dashboard broadcaster started")


# # ─────────────────────────────────────────────────────────────────────
# # ── DASHBOARD HTML (inline, no external files needed) ────────────────
# # ─────────────────────────────────────────────────────────────────────
# DASHBOARD_HTML = r"""<!DOCTYPE html>
# <html lang="en">
# <head>
# <meta charset="UTF-8">
# <meta name="viewport" content="width=device-width,initial-scale=1.0">
# <title>NIDS // SOC TERMINAL</title>
# <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
# <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
# <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
# <style>
# /* ── RESET & VARIABLES ── */
# *{margin:0;padding:0;box-sizing:border-box}
# :root{
#   --bg:       #020609;
#   --surface:  #060d12;
#   --panel:    #0a1520;
#   --border:   #0d2535;
#   --glow:     #00ff9d;
#   --glow2:    #00c4ff;
#   --red:      #ff3b5c;
#   --amber:    #ffb300;
#   --text:     #8ab8c8;
#   --text-hi:  #c8e8f8;
#   --mono:     'Share Tech Mono', monospace;
#   --display:  'Orbitron', sans-serif;
# }
# html,body{height:100%;background:var(--bg);color:var(--text);font-family:var(--mono);overflow-x:hidden}

# /* scanline overlay */
# body::before{
#   content:'';position:fixed;inset:0;
#   background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,157,.018) 2px,rgba(0,255,157,.018) 4px);
#   pointer-events:none;z-index:9999
# }
# /* vignette */
# body::after{
#   content:'';position:fixed;inset:0;
#   background:radial-gradient(ellipse at center,transparent 55%,rgba(0,0,0,.75) 100%);
#   pointer-events:none;z-index:9998
# }

# /* ── TOPBAR ── */
# #topbar{
#   position:sticky;top:0;z-index:100;
#   display:flex;align-items:center;justify-content:space-between;
#   padding:0 28px;height:52px;
#   background:rgba(6,13,18,.95);
#   border-bottom:1px solid var(--border);
#   backdrop-filter:blur(12px);
# }
# #topbar .logo{
#   font-family:var(--display);font-size:.95rem;font-weight:900;
#   letter-spacing:.25em;color:var(--glow);
#   text-shadow:0 0 18px var(--glow);
# }
# #topbar .logo span{color:var(--glow2);text-shadow:0 0 12px var(--glow2)}
# .topbar-meta{display:flex;gap:24px;align-items:center;font-size:.72rem;letter-spacing:.08em}
# .badge{
#   padding:3px 10px;border-radius:2px;font-size:.65rem;font-weight:700;
#   letter-spacing:.12em;text-transform:uppercase;
# }
# .badge-live{background:rgba(0,255,157,.12);color:var(--glow);border:1px solid rgba(0,255,157,.35);
#   box-shadow:0 0 10px rgba(0,255,157,.2);animation:blink 1.4s ease infinite}
# .badge-offline{background:rgba(255,59,92,.12);color:var(--red);border:1px solid rgba(255,59,92,.3)}
# @keyframes blink{0%,100%{opacity:1}50%{opacity:.5}}

# /* ── LAYOUT ── */
# #wrap{display:grid;grid-template-columns:260px 1fr;min-height:calc(100vh - 52px)}

# /* ── SIDEBAR ── */
# #sidebar{
#   background:var(--surface);border-right:1px solid var(--border);
#   padding:20px 0;display:flex;flex-direction:column;gap:0;
#   overflow-y:auto
# }
# .sidebar-section{padding:14px 20px 10px;border-bottom:1px solid var(--border)}
# .sidebar-label{font-size:.6rem;letter-spacing:.18em;color:rgba(138,184,200,.4);margin-bottom:12px;text-transform:uppercase}
# .kpi{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:8px}
# .kpi-name{font-size:.7rem;color:var(--text)}
# .kpi-val{font-size:1.05rem;color:var(--text-hi);font-family:var(--display);font-weight:700}
# .kpi-val.danger{color:var(--red);text-shadow:0 0 10px rgba(255,59,92,.4)}
# .kpi-val.warn{color:var(--amber)}
# .kpi-val.ok{color:var(--glow)}

# /* threat bar */
# .threat-bar-wrap{margin-bottom:10px}
# .threat-bar-header{display:flex;justify-content:space-between;font-size:.68rem;margin-bottom:4px}
# .threat-ip{color:var(--glow2)}
# .threat-score-label{color:var(--red)}
# .threat-bar-track{height:4px;background:rgba(255,255,255,.07);border-radius:2px;overflow:hidden}
# .threat-bar-fill{height:100%;border-radius:2px;background:linear-gradient(90deg,var(--glow2),var(--red));
#   transition:width .6s ease;box-shadow:0 0 6px var(--red)}

# /* proto pills */
# .proto-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px;padding:14px 20px}
# .proto-pill{background:rgba(10,21,32,.8);border:1px solid var(--border);border-radius:4px;
#   padding:8px 10px;display:flex;flex-direction:column;gap:2px}
# .proto-name{font-size:.6rem;letter-spacing:.12em;color:rgba(138,184,200,.5)}
# .proto-count{font-size:.95rem;color:var(--text-hi);font-family:var(--display)}

# /* ── MAIN CONTENT ── */
# #main{padding:20px;display:flex;flex-direction:column;gap:16px;overflow-y:auto}

# /* chart panels */
# .panel{background:var(--panel);border:1px solid var(--border);border-radius:6px;
#   padding:16px;position:relative;overflow:hidden}
# .panel::before{
#   content:'';position:absolute;top:0;left:0;right:0;height:1px;
#   background:linear-gradient(90deg,transparent,var(--glow),transparent);opacity:.35
# }
# .panel-title{
#   font-family:var(--display);font-size:.65rem;letter-spacing:.18em;
#   color:rgba(0,255,157,.6);margin-bottom:14px;text-transform:uppercase
# }
# .panel-title .accent{color:var(--glow2)}

# /* charts row */
# .charts-row{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}
# .chart-wrap{height:160px;position:relative}

# /* alerts table */
# #alerts-panel{flex:1;min-height:0}
# #alerts-list{display:flex;flex-direction:column;gap:6px;max-height:380px;overflow-y:auto}
# #alerts-list::-webkit-scrollbar{width:4px}
# #alerts-list::-webkit-scrollbar-track{background:transparent}
# #alerts-list::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}

# .alert-row{
#   background:rgba(255,59,92,.04);border:1px solid rgba(255,59,92,.15);
#   border-left:3px solid var(--red);border-radius:4px;
#   padding:10px 14px;display:grid;
#   grid-template-columns:auto 1fr auto;gap:10px;align-items:start;
#   animation:slideDown .35s ease;
# }
# .alert-row.high{border-left-color:var(--amber);background:rgba(255,179,0,.04)}
# .alert-row.medium{border-left-color:var(--glow2);background:rgba(0,196,255,.04)}
# @keyframes slideDown{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}
# .alert-time{font-size:.65rem;color:rgba(138,184,200,.5);white-space:nowrap;padding-top:2px}
# .alert-body{}
# .alert-type{font-size:.78rem;color:var(--text-hi);margin-bottom:3px}
# .alert-meta{font-size:.65rem;color:var(--text)}
# .alert-sev{
#   padding:2px 8px;border-radius:2px;font-size:.58rem;font-weight:700;
#   letter-spacing:.1em;text-transform:uppercase;white-space:nowrap;align-self:start
# }
# .sev-critical{background:rgba(255,59,92,.2);color:var(--red);border:1px solid rgba(255,59,92,.3)}
# .sev-high{background:rgba(255,179,0,.15);color:var(--amber);border:1px solid rgba(255,179,0,.3)}
# .sev-medium{background:rgba(0,196,255,.12);color:var(--glow2);border:1px solid rgba(0,196,255,.25)}
# .sev-low{background:rgba(0,255,157,.08);color:var(--glow);border:1px solid rgba(0,255,157,.2)}

# .empty-state{text-align:center;padding:40px;color:rgba(138,184,200,.3);font-size:.75rem;letter-spacing:.1em}

# /* status row */
# .status-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:4px}
# .status-chip{
#   font-size:.6rem;letter-spacing:.1em;padding:2px 8px;border-radius:2px;
#   background:rgba(0,255,157,.06);border:1px solid rgba(0,255,157,.2);color:var(--glow);
# }
# .status-chip.warn{background:rgba(255,179,0,.08);border-color:rgba(255,179,0,.25);color:var(--amber)}

# /* scrollbar global */
# ::-webkit-scrollbar{width:4px;height:4px}
# ::-webkit-scrollbar-track{background:transparent}
# ::-webkit-scrollbar-thumb{background:var(--border)}

# /* corner decoration */
# .corner-tl,.corner-tr{
#   position:absolute;width:12px;height:12px;
#   border-color:var(--glow);border-style:solid;opacity:.4;
# }
# .corner-tl{top:8px;left:8px;border-width:1px 0 0 1px}
# .corner-tr{top:8px;right:8px;border-width:1px 1px 0 0}
# </style>
# </head>
# <body>

# <!-- TOPBAR -->
# <div id="topbar">
#   <div class="logo">NIDS<span>//</span>SOC&nbsp;TERMINAL</div>
#   <div class="topbar-meta">
#     <span id="iface-label" style="color:var(--glow2)">IFACE: —</span>
#     <span id="uptime-label">UP: 0s</span>
#     <span id="ml-label" class="badge badge-offline">ML OFFLINE</span>
#     <span id="conn-badge" class="badge badge-offline">DISCONNECTED</span>
#   </div>
# </div>

# <div id="wrap">
# <!-- SIDEBAR -->
# <div id="sidebar">

#   <div class="sidebar-section">
#     <div class="sidebar-label">Traffic</div>
#     <div class="kpi"><span class="kpi-name">Packets</span><span class="kpi-val" id="s-pkts">0</span></div>
#     <div class="kpi"><span class="kpi-name">Bytes</span><span class="kpi-val" id="s-bytes">0 B</span></div>
#     <div class="kpi"><span class="kpi-name">PPS</span><span class="kpi-val ok" id="s-pps">0</span></div>
#     <div class="kpi"><span class="kpi-name">BW (KB/s)</span><span class="kpi-val" id="s-bps">0</span></div>
#   </div>

#   <div class="sidebar-section">
#     <div class="sidebar-label">Detection</div>
#     <div class="kpi"><span class="kpi-name">Alerts</span><span class="kpi-val danger" id="s-alerts">0</span></div>
#     <div class="kpi"><span class="kpi-name">Unique IPs</span><span class="kpi-val" id="s-ips">0</span></div>
#     <div class="kpi"><span class="kpi-name">PCAP Files</span><span class="kpi-val" id="s-pcap">0</span></div>
#   </div>

#   <div class="proto-grid">
#     <div class="proto-pill"><span class="proto-name">TCP</span><span class="proto-count" id="p-tcp">0</span></div>
#     <div class="proto-pill"><span class="proto-name">UDP</span><span class="proto-count" id="p-udp">0</span></div>
#     <div class="proto-pill"><span class="proto-name">ICMP</span><span class="proto-count" id="p-icmp">0</span></div>
#     <div class="proto-pill"><span class="proto-name">ARP</span><span class="proto-count" id="p-arp">0</span></div>
#     <div class="proto-pill"><span class="proto-name">DNS</span><span class="proto-count" id="p-dns">0</span></div>
#     <div class="proto-pill"><span class="proto-name">OTHER</span><span class="proto-count" id="p-other">0</span></div>
#   </div>

#   <div class="sidebar-section" style="flex:1">
#     <div class="sidebar-label">Top Threat IPs</div>
#     <div id="threat-bars"></div>
#   </div>

# </div><!-- /sidebar -->

# <!-- MAIN -->
# <div id="main">

#   <!-- status chips -->
#   <div class="status-row" id="status-chips">
#     <span class="status-chip" id="chip-sig">● SIG</span>
#     <span class="status-chip" id="chip-ml">● ML ENSEMBLE</span>
#     <span class="status-chip" id="chip-ueba">● UEBA</span>
#     <span class="status-chip" id="chip-beacon">● BEACONING</span>
#     <span class="status-chip" id="chip-dns">● DNS</span>
#     <span class="status-chip" id="chip-arp">● ARP SPOOF</span>
#     <span class="status-chip" id="chip-intel">● THREAT INTEL</span>
#   </div>

#   <!-- charts row -->
#   <div class="charts-row">
#     <div class="panel">
#       <div class="corner-tl"></div><div class="corner-tr"></div>
#       <div class="panel-title">PACKETS / SEC</div>
#       <div class="chart-wrap"><canvas id="c-pps"></canvas></div>
#     </div>
#     <div class="panel">
#       <div class="corner-tl"></div><div class="corner-tr"></div>
#       <div class="panel-title">BANDWIDTH <span class="accent">KB/S</span></div>
#       <div class="chart-wrap"><canvas id="c-bps"></canvas></div>
#     </div>
#     <div class="panel">
#       <div class="corner-tl"></div><div class="corner-tr"></div>
#       <div class="panel-title">ATTACK <span class="accent">DISTRIBUTION</span></div>
#       <div class="chart-wrap"><canvas id="c-attacks"></canvas></div>
#     </div>
#   </div>

#   <!-- alert timeline -->
#   <div class="panel">
#     <div class="corner-tl"></div><div class="corner-tr"></div>
#     <div class="panel-title">ALERT <span class="accent">TIMELINE</span></div>
#     <div style="height:100px;position:relative"><canvas id="c-timeline"></canvas></div>
#   </div>

#   <!-- alerts feed -->
#   <div class="panel" id="alerts-panel">
#     <div class="corner-tl"></div><div class="corner-tr"></div>
#     <div class="panel-title" style="display:flex;justify-content:space-between;align-items:center">
#       <span>ALERT <span class="accent">FEED</span></span>
#       <span id="alert-counter" style="font-size:.6rem;color:var(--text)">0 events</span>
#     </div>
#     <div id="alerts-list">
#       <div class="empty-state">▌ MONITORING — NO ALERTS YET</div>
#     </div>
#   </div>

# </div><!-- /main -->
# </div><!-- /wrap -->

# <script>
# /* ── SOCKET ── */
# const socket = io();
# let alertCount = 0;

# socket.on('connect', () => {
#   document.getElementById('conn-badge').textContent = 'LIVE';
#   document.getElementById('conn-badge').className = 'badge badge-live';
#   socket.emit('request_timeline');
# });
# socket.on('disconnect', () => {
#   document.getElementById('conn-badge').textContent = 'DISCONNECTED';
#   document.getElementById('conn-badge').className = 'badge badge-offline';
# });

# /* ── CHARTS SETUP ── */
# Chart.defaults.color = '#4a7a8a';
# Chart.defaults.font.family = "'Share Tech Mono', monospace";
# Chart.defaults.font.size = 10;

# const gridColor  = 'rgba(13,37,53,.9)';
# const glowGreen  = '#00ff9d';
# const glowBlue   = '#00c4ff';
# const glowRed    = '#ff3b5c';
# const glowAmber  = '#ffb300';

# function sparkLine(id, color, glow) {
#   const ctx = document.getElementById(id).getContext('2d');
#   return new Chart(ctx, {
#     type: 'line',
#     data: { labels: [], datasets: [{
#       data: [], borderColor: color, borderWidth: 1.5,
#       backgroundColor: color + '18', tension: 0.4, fill: true,
#       pointRadius: 0,
#     }]},
#     options: {
#       responsive: true, maintainAspectRatio: false, animation: false,
#       plugins: { legend: { display: false }, tooltip: { enabled: true } },
#       scales: {
#         x: { display: false },
#         y: { beginAtZero: true, grid: { color: gridColor },
#              ticks: { maxTicksLimit: 4, color: '#2a5a6a' } }
#       }
#     }
#   });
# }

# const chartPPS      = sparkLine('c-pps',      glowGreen, glowGreen);
# const chartBPS      = sparkLine('c-bps',      glowBlue,  glowBlue);
# const chartTimeline = sparkLine('c-timeline', glowRed,   glowRed);

# // Attack doughnut
# const ctxAtk = document.getElementById('c-attacks').getContext('2d');
# const chartAttacks = new Chart(ctxAtk, {
#   type: 'doughnut',
#   data: { labels: [], datasets: [{ data: [], borderWidth: 0,
#     backgroundColor: [glowRed, glowAmber, glowBlue, glowGreen,
#                        '#9b59b6','#1abc9c','#e67e22','#34495e'] }]},
#   options: {
#     responsive: true, maintainAspectRatio: false, animation: false,
#     cutout: '68%',
#     plugins: {
#       legend: { position: 'right',
#                 labels: { color: '#6a9aaa', boxWidth: 10, font: { size: 9 } } }
#     }
#   }
# });

# /* push data helpers */
# function pushSpark(chart, labels, values) {
#   chart.data.labels = labels;
#   chart.data.datasets[0].data = values;
#   chart.update('none');
# }

# /* ── STATS UPDATE ── */
# socket.on('stats_update', s => {
#   // sidebar numbers
#   setText('s-pkts',   fmt(s.total_packets));
#   setText('s-bytes',  fmtBytes(s.total_bytes));
#   setText('s-pps',    s.pps.toFixed(1));
#   setText('s-bps',    s.bps_kb.toFixed(1));
#   setText('s-alerts', s.alerts);
#   setText('s-ips',    s.unique_ips);
#   setText('s-pcap',   s.pcap_files);

#   // protos
#   setText('p-tcp',   fmt(s.tcp));
#   setText('p-udp',   fmt(s.udp));
#   setText('p-icmp',  fmt(s.icmp));
#   setText('p-arp',   fmt(s.arp));
#   setText('p-dns',   fmt(s.dns));
#   setText('p-other', fmt((s.total_packets - s.tcp - s.udp - s.icmp - s.arp - s.dns)));

#   // topbar
#   const up = s.uptime_s;
#   const h = Math.floor(up/3600), m = Math.floor((up%3600)/60), sec = Math.floor(up%60);
#   setText('uptime-label', `UP: ${h?h+'h ':''} ${m}m ${sec}s`);
#   setText('iface-label', `IFACE: ${s.interface || '—'}`);

#   // ML badge
#   const mlEl = document.getElementById('ml-label');
#   mlEl.textContent = s.ml_trained ? 'ML ACTIVE' : 'ML TRAINING';
#   mlEl.className = 'badge ' + (s.ml_trained ? 'badge-live' : 'badge-offline');

#   // chip: chips always "active" once IDS is up (engines always run)
#   ['chip-sig','chip-ml','chip-ueba','chip-beacon','chip-dns','chip-arp','chip-intel']
#     .forEach(id => document.getElementById(id).classList.remove('warn'));

#   // attack doughnut
#   const counts = s.alert_counts || {};
#   if (Object.keys(counts).length) {
#     chartAttacks.data.labels = Object.keys(counts);
#     chartAttacks.data.datasets[0].data = Object.values(counts);
#     chartAttacks.update('none');
#   }

#   // top threats sidebar
#   renderThreats(s.top_threats || []);
# });

# /* ── TIMELINE ── */
# socket.on('timeline_data', d => {
#   pushSpark(chartPPS,      d.labels, d.pps);
#   pushSpark(chartBPS,      d.labels, d.bps_kb);
#   pushSpark(chartTimeline, d.labels, d.alerts);
# });

# // Also piggyback on stats to update sparklines via /api/timeline every 2s
# let tlTimer = setInterval(() => {
#   fetch('/api/timeline').then(r=>r.json()).then(d => {
#     pushSpark(chartPPS,      d.labels, d.pps);
#     pushSpark(chartBPS,      d.labels, d.bps_kb);
#     pushSpark(chartTimeline, d.labels, d.alerts);
#   }).catch(()=>{});
# }, 2000);

# /* ── NEW ALERT ── */
# socket.on('new_alert', alert => {
#   alertCount++;
#   setText('alert-counter', alertCount + ' events');
#   prependAlert(alert);
# });

# function prependAlert(a) {
#   const list = document.getElementById('alerts-list');
#   // remove empty state
#   if (list.querySelector('.empty-state')) list.innerHTML = '';

#   const sev = (a.severity || 'low').toLowerCase();
#   const sevClass = { critical:'sev-critical', high:'sev-high',
#                      medium:'sev-medium', low:'sev-low' }[sev] || 'sev-low';
#   const rowClass = sev === 'critical' ? '' : sev === 'high' ? 'high' : sev === 'medium' ? 'medium' : '';

#   const ts = new Date(a.timestamp).toLocaleTimeString();
#   const geo = a.geo ? `${a.geo.city||''}${a.geo.country ? ' ['+a.geo.country+']':''} ` : '';
#   const score = a.composite_score != null ? ` · SCORE ${a.composite_score}` : '';
#   const desc  = (a.details && a.details.description) ? a.details.description : '';

#   const div = document.createElement('div');
#   div.className = `alert-row ${rowClass}`;
#   div.innerHTML = `
#     <span class="alert-time">${ts}</span>
#     <div class="alert-body">
#       <div class="alert-type">${esc(a.attack_type)}</div>
#       <div class="alert-meta">${esc(a.src_ip)} ${geo}${score}</div>
#       ${desc ? `<div class="alert-meta" style="color:rgba(138,184,200,.45);margin-top:2px">${esc(desc)}</div>` : ''}
#     </div>
#     <span class="alert-sev ${sevClass}">${a.severity}</span>`;
#   list.insertBefore(div, list.firstChild);
#   while (list.children.length > 60) list.removeChild(list.lastChild);
# }

# /* ── THREAT BARS ── */
# function renderThreats(threats) {
#   const el = document.getElementById('threat-bars');
#   if (!threats.length) { el.innerHTML = '<div class="empty-state" style="padding:12px 0;font-size:.65rem">No threats scored yet</div>'; return; }
#   el.innerHTML = threats.map(t => `
#     <div class="threat-bar-wrap">
#       <div class="threat-bar-header">
#         <span class="threat-ip">${t.ip}</span>
#         <span class="threat-score-label">${t.score.toFixed(0)}</span>
#       </div>
#       <div class="threat-bar-track">
#         <div class="threat-bar-fill" style="width:${Math.min(t.score,100)}%"></div>
#       </div>
#       <div style="font-size:.58rem;color:rgba(138,184,200,.35);margin-top:2px">
#         ${(t.tags||[]).slice(0,2).join(' · ')}
#       </div>
#     </div>`).join('');
# }

# /* ── UTILS ── */
# function setText(id, val) {
#   const el = document.getElementById(id);
#   if (el) el.textContent = val;
# }
# function fmt(n) {
#   if (n >= 1e9) return (n/1e9).toFixed(1)+'G';
#   if (n >= 1e6) return (n/1e6).toFixed(1)+'M';
#   if (n >= 1e3) return (n/1e3).toFixed(1)+'K';
#   return n;
# }
# function fmtBytes(b) {
#   if (b >= 1<<30) return (b/(1<<30)).toFixed(2)+' GB';
#   if (b >= 1<<20) return (b/(1<<20)).toFixed(1)+' MB';
#   if (b >= 1<<10) return (b/(1<<10)).toFixed(0)+' KB';
#   return b+' B';
# }
# function esc(s) {
#   return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
# }
# </script>
# </body>
# </html>
# """

# # ─────────────────────────────────────────────────────────────────────
# # ENTRY POINT
# # ─────────────────────────────────────────────────────────────────────
# if __name__ == '__main__':
#     ap = argparse.ArgumentParser(description='Advanced Network IDS Dashboard v2.0')
#     ap.add_argument('-c', '--config',    default=None,  help='YAML config file for IDS')
#     ap.add_argument('-i', '--interface', default=None,  help='Override network interface')
#     ap.add_argument('-p', '--port',      type=int, default=5001, help='Dashboard HTTP port')
#     ap.add_argument('--no-ids',          action='store_true',
#                     help='Start dashboard only (no IDS, for testing UI)')
#     args = ap.parse_args()

#     if not args.no_ids:
#         cfg = load_config(args.config)
#         if args.interface:
#             cfg['interface'] = args.interface
#         # Don't double-start the metrics API (dashboard IS the API)
#         cfg['enable_api']  = False

#         ids_thread = threading.Thread(
#             target=start_ids, args=(cfg,), daemon=True)
#         ids_thread.start()
#         time.sleep(2)   # let IDS initialize

#     print(f"\n🌐  Dashboard  →  http://localhost:{args.port}")
#     print(f"   API /api/stats | /api/alerts | /api/threats | /api/timeline")
#     print(f"   Press Ctrl+C to stop\n")

#     try:
#         socketio.run(app, host='0.0.0.0', port=args.port,
#                      debug=False, use_reloader=False)
#     except KeyboardInterrupt:
#         print("\n⚠  Shutting down…")
#         ids_running = False
#         if ids_instance:
#             ids_instance.stop()


# """
# Advanced Network IDS — Web Dashboard v2.1
# Clean modern UI edition.
# """

# import threading
# import time
# import json
# import os
# import sys
# import argparse
# from datetime import datetime, timedelta
# from collections import defaultdict, deque
# from typing import Optional

# from flask import Flask, jsonify, request
# from flask_socketio import SocketIO, emit

# try:
#     from network_ids_advanced import AdvancedNetworkIDS, load_config
# except ImportError:
#     print("❌  network_ids_advanced.py not found in the same directory.")
#     sys.exit(1)

# # ─────────────────────────────────────────────────────────────────────
# app = Flask(__name__)
# app.config['SECRET_KEY'] = os.environ.get('IDS_SECRET', 'change-me-in-production')
# socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading',
#                     logger=False, engineio_logger=False)

# ids_instance: Optional[AdvancedNetworkIDS] = None
# ids_running = False

# TIMELINE_LEN = 120
# timeline_lock = threading.Lock()
# timeline_pps:    deque = deque([0.0] * TIMELINE_LEN, maxlen=TIMELINE_LEN)
# timeline_bps:    deque = deque([0.0] * TIMELINE_LEN, maxlen=TIMELINE_LEN)
# timeline_alerts: deque = deque([0]   * TIMELINE_LEN, maxlen=TIMELINE_LEN)
# timeline_labels: deque = deque(['']  * TIMELINE_LEN, maxlen=TIMELINE_LEN)

# _last_pkt_count   = 0
# _last_byte_count  = 0
# _last_alert_count = 0
# _last_tick_time   = time.time()


# # ── Alert hook ────────────────────────────────────────────────────────
# def _alert_hook(alert: dict):
#     try:
#         socketio.emit('new_alert', alert, namespace='/')
#     except Exception:
#         pass


# def _patch_ids_alerts(ids: AdvancedNetworkIDS):
#     _orig = ids._alert

#     def patched(attack_type, src_ip, severity, confidence, details, score_weight=10):
#         _orig(attack_type, src_ip, severity, confidence, details, score_weight)
#         if ids.alerts:
#             _alert_hook(dict(ids.alerts[-1]))

#     ids._alert = patched


# # ── Background broadcaster ────────────────────────────────────────────
# def _broadcaster():
#     global _last_pkt_count, _last_byte_count, _last_alert_count, _last_tick_time

#     while ids_running:
#         time.sleep(1)
#         if not ids_instance:
#             continue

#         now = time.time()
#         dt  = max(now - _last_tick_time, 0.001)
#         _last_tick_time = now

#         s          = ids_instance.stats
#         cur_pkts   = s['total_packets']
#         cur_bytes  = s['total_bytes']
#         cur_alerts = s['alerts']

#         pps        = (cur_pkts  - _last_pkt_count)  / dt
#         bps        = (cur_bytes - _last_byte_count)  / dt
#         new_alerts = cur_alerts - _last_alert_count

#         _last_pkt_count   = cur_pkts
#         _last_byte_count  = cur_bytes
#         _last_alert_count = cur_alerts

#         with timeline_lock:
#             timeline_pps.append(round(pps, 1))
#             timeline_bps.append(round(bps / 1024, 1))
#             timeline_alerts.append(new_alerts)
#             timeline_labels.append(datetime.now().strftime('%H:%M:%S'))

#         up = (datetime.now() - s['start_time']).total_seconds()
#         payload = {
#             'total_packets': s['total_packets'],
#             'total_bytes':   s['total_bytes'],
#             'alerts':        s['alerts'],
#             'unique_ips':    len(ids_instance.connections),
#             'tcp':  s['tcp'],  'udp': s['udp'],
#             'icmp': s['icmp'], 'arp': s['arp'], 'dns': s['dns'],
#             'pps':     round(pps, 1),
#             'bps_kb':  round(bps / 1024, 1),
#             'uptime_s':   round(up, 0),
#             'ml_trained': ids_instance.ensemble.trained,
#             'pcap_files': len(ids_instance.pcap_mgr.list_files()),
#             'interface':  ids_instance.interface,
#             'alert_counts': dict(ids_instance.alert_counts),
#             'top_threats': [
#                 {'ip': ip, 'score': round(sc, 1), 'tags': list(set(ev))[:3]}
#                 for ip, sc, ev in ids_instance.scoreboard.top_threats(5)
#             ],
#         }
#         socketio.emit('stats_update', payload, namespace='/')


# # ── REST API ──────────────────────────────────────────────────────────
# def _ids_required(f):
#     from functools import wraps
#     @wraps(f)
#     def wrapper(*args, **kwargs):
#         if not ids_instance:
#             return jsonify({'error': 'IDS not running'}), 503
#         return f(*args, **kwargs)
#     return wrapper


# @app.route('/')
# def index():
#     return DASHBOARD_HTML, 200, {'Content-Type': 'text/html'}


# @app.route('/api/stats')
# @_ids_required
# def api_stats():
#     s  = ids_instance.stats
#     up = (datetime.now() - s['start_time']).total_seconds()
#     return jsonify({
#         **{k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in s.items()},
#         'uptime_s':   round(up, 1),
#         'unique_ips': len(ids_instance.connections),
#         'ml_trained': ids_instance.ensemble.trained,
#     })


# @app.route('/api/alerts')
# @_ids_required
# def api_alerts():
#     limit  = min(int(request.args.get('limit', 50)), 500)
#     sev    = request.args.get('severity')
#     alerts = list(ids_instance.alerts)
#     if sev:
#         alerts = [a for a in alerts if a.get('severity', '').lower() == sev.lower()]
#     return jsonify(alerts[-limit:])


# @app.route('/api/threats')
# @_ids_required
# def api_threats():
#     n = int(request.args.get('n', 20))
#     return jsonify([
#         {'ip': ip, 'score': round(sc, 1),
#          'evidence':   list(set(ev))[:10],
#          'reputation': round(ids_instance.threat_intel.get_reputation(ip), 3),
#          'geo':        ids_instance.threat_intel.geolocate(ip)}
#         for ip, sc, ev in ids_instance.scoreboard.top_threats(n)
#     ])


# @app.route('/api/timeline')
# def api_timeline():
#     with timeline_lock:
#         return jsonify({
#             'labels': list(timeline_labels),
#             'pps':    list(timeline_pps),
#             'bps_kb': list(timeline_bps),
#             'alerts': list(timeline_alerts),
#         })


# @app.route('/api/top_ips')
# @_ids_required
# def api_top_ips():
#     n    = int(request.args.get('n', 10))
#     rows = sorted(ids_instance.connections.items(),
#                   key=lambda kv: kv[1]['pkt_count'], reverse=True)[:n]
#     return jsonify([
#         {'ip': ip, 'packets': c['pkt_count'], 'bytes': c['bytes'],
#          'ports': len(c['ports']),
#          'score': round(ids_instance.scoreboard.get_score(ip), 1),
#          'geo':   ids_instance.threat_intel.geolocate(ip)}
#         for ip, c in rows
#     ])


# @app.route('/api/alert_counts')
# @_ids_required
# def api_alert_counts():
#     return jsonify(dict(ids_instance.alert_counts))


# @app.route('/api/pcap_files')
# @_ids_required
# def api_pcap_files():
#     files = ids_instance.pcap_mgr.list_files()
#     return jsonify([
#         {'name': os.path.basename(f),
#          'size_kb': round(os.path.getsize(f) / 1024, 1), 'path': f}
#         for f in files
#     ])


# @app.route('/api/health')
# def api_health():
#     return jsonify({'status': 'ok', 'ids_running': ids_running, 'version': '2.1.0'})


# @app.route('/api/thresholds')
# @_ids_required
# def api_thresholds():
#     return jsonify(ids_instance.adapt_thr.snapshot())


# # ── SocketIO ──────────────────────────────────────────────────────────
# @socketio.on('connect')
# def on_connect():
#     if ids_instance:
#         emit('ids_status', {'running': ids_running, 'interface': ids_instance.interface})


# @socketio.on('request_timeline')
# def on_request_timeline():
#     with timeline_lock:
#         emit('timeline_data', {
#             'labels': list(timeline_labels),
#             'pps':    list(timeline_pps),
#             'bps_kb': list(timeline_bps),
#             'alerts': list(timeline_alerts),
#         })


# @socketio.on('request_top_threats')
# def on_request_top_threats():
#     if ids_instance:
#         emit('top_threats', [
#             {'ip': ip, 'score': round(sc, 1), 'tags': list(set(ev))[:3]}
#             for ip, sc, ev in ids_instance.scoreboard.top_threats(10)
#         ])


# # ── IDS lifecycle ─────────────────────────────────────────────────────
# def start_ids(cfg: dict):
#     global ids_instance, ids_running
#     ids_instance = AdvancedNetworkIDS(cfg)
#     _patch_ids_alerts(ids_instance)
#     ids_instance.start()
#     ids_running = True
#     threading.Thread(target=_broadcaster, daemon=True).start()
#     print("✅  Dashboard broadcaster started")


# # ─────────────────────────────────────────────────────────────────────
# # DASHBOARD HTML
# # ─────────────────────────────────────────────────────────────────────
# DASHBOARD_HTML = """<!DOCTYPE html>
# <html lang="en">
# <head>
# <meta charset="UTF-8">
# <meta name="viewport" content="width=device-width, initial-scale=1.0">
# <title>Network IDS Dashboard</title>
# <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
# <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
# <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
# <style>
#   /* ── Base ── */
#   *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
#   :root {
#     --bg:         #f0f2f5;
#     --surface:    #ffffff;
#     --border:     #e2e6ea;
#     --text:       #1a1d23;
#     --text-muted: #6b7280;
#     --primary:    #2563eb;
#     --success:    #16a34a;
#     --warning:    #d97706;
#     --danger:     #dc2626;
#     --info:       #0891b2;
#     --radius:     10px;
#     --shadow:     0 1px 3px rgba(0,0,0,.08), 0 1px 2px rgba(0,0,0,.05);
#     --shadow-md:  0 4px 6px rgba(0,0,0,.07), 0 2px 4px rgba(0,0,0,.05);
#   }
#   html, body { height: 100%; background: var(--bg); color: var(--text);
#                font-family: 'Inter', system-ui, sans-serif; font-size: 14px; }

#   /* ── Layout ── */
#   .app { display: flex; flex-direction: column; min-height: 100vh; }

#   /* ── Topbar ── */
#   .topbar {
#     background: var(--surface); border-bottom: 1px solid var(--border);
#     padding: 0 24px; height: 56px;
#     display: flex; align-items: center; justify-content: space-between;
#     position: sticky; top: 0; z-index: 50;
#     box-shadow: var(--shadow);
#   }
#   .topbar-left { display: flex; align-items: center; gap: 12px; }
#   .topbar-logo { font-size: 16px; font-weight: 700; color: var(--text); letter-spacing: -.3px; }
#   .topbar-logo span { color: var(--primary); }
#   .topbar-right { display: flex; align-items: center; gap: 16px; }
#   .topbar-meta { font-size: 12px; color: var(--text-muted); }

#   .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%;
#          margin-right: 5px; vertical-align: middle; }
#   .dot-green { background: var(--success); box-shadow: 0 0 0 3px rgba(22,163,74,.15); }
#   .dot-red   { background: var(--danger); }
#   .dot-pulse { animation: pulse 2s ease infinite; }
#   @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.5} }

#   .badge {
#     display: inline-flex; align-items: center; gap: 5px;
#     padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600;
#     letter-spacing: .02em;
#   }
#   .badge-blue   { background: #eff6ff; color: var(--primary); border: 1px solid #bfdbfe; }
#   .badge-green  { background: #f0fdf4; color: var(--success); border: 1px solid #bbf7d0; }
#   .badge-red    { background: #fef2f2; color: var(--danger);  border: 1px solid #fecaca; }
#   .badge-amber  { background: #fffbeb; color: var(--warning); border: 1px solid #fde68a; }

#   /* ── Main grid ── */
#   .content { display: grid; grid-template-columns: 240px 1fr; gap: 0; flex: 1; }

#   /* ── Sidebar ── */
#   .sidebar {
#     background: var(--surface); border-right: 1px solid var(--border);
#     padding: 20px 16px; display: flex; flex-direction: column; gap: 20px;
#     overflow-y: auto;
#   }
#   .sidebar-section {}
#   .section-label {
#     font-size: 10px; font-weight: 600; letter-spacing: .08em;
#     text-transform: uppercase; color: var(--text-muted); margin-bottom: 12px;
#   }

#   /* KPI rows */
#   .kpi-row { display: flex; justify-content: space-between; align-items: center;
#              padding: 6px 0; border-bottom: 1px solid var(--border); }
#   .kpi-row:last-child { border-bottom: none; }
#   .kpi-label { font-size: 12px; color: var(--text-muted); }
#   .kpi-value { font-size: 15px; font-weight: 600; color: var(--text); }
#   .kpi-value.red    { color: var(--danger); }
#   .kpi-value.green  { color: var(--success); }
#   .kpi-value.blue   { color: var(--primary); }

#   /* Proto pills */
#   .proto-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; }
#   .proto-pill {
#     background: var(--bg); border: 1px solid var(--border); border-radius: 8px;
#     padding: 8px 10px; text-align: center;
#   }
#   .proto-name  { font-size: 10px; color: var(--text-muted); font-weight: 500;
#                  letter-spacing: .06em; text-transform: uppercase; }
#   .proto-value { font-size: 16px; font-weight: 700; color: var(--text); margin-top: 2px; }

#   /* Threat bars */
#   .threat-item { margin-bottom: 12px; }
#   .threat-header { display: flex; justify-content: space-between; align-items: baseline;
#                    margin-bottom: 4px; }
#   .threat-ip    { font-size: 12px; font-weight: 500; color: var(--text); font-family: monospace; }
#   .threat-score { font-size: 11px; font-weight: 600; color: var(--danger); }
#   .threat-track { height: 5px; background: var(--border); border-radius: 3px; overflow: hidden; }
#   .threat-fill  {
#     height: 100%; border-radius: 3px;
#     background: linear-gradient(90deg, var(--primary), var(--danger));
#     transition: width .5s ease;
#   }
#   .threat-tags  { font-size: 10px; color: var(--text-muted); margin-top: 3px; }

#   /* ── Main panel ── */
#   .main { padding: 20px; display: flex; flex-direction: column; gap: 16px; overflow-y: auto; }

#   /* Engine chips */
#   .chips { display: flex; gap: 6px; flex-wrap: wrap; }
#   .chip {
#     font-size: 11px; font-weight: 500; padding: 4px 10px;
#     border-radius: 20px; border: 1px solid var(--border);
#     background: var(--surface); color: var(--text-muted);
#     display: flex; align-items: center; gap: 5px;
#   }
#   .chip.active { background: #f0fdf4; color: var(--success); border-color: #bbf7d0; }
#   .chip .chip-dot { width: 6px; height: 6px; border-radius: 50%;
#                     background: currentColor; display: inline-block; }

#   /* Stat cards row */
#   .stat-cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
#   .stat-card {
#     background: var(--surface); border: 1px solid var(--border);
#     border-radius: var(--radius); padding: 16px 18px;
#     box-shadow: var(--shadow);
#   }
#   .stat-card-label { font-size: 11px; color: var(--text-muted); font-weight: 500;
#                      text-transform: uppercase; letter-spacing: .05em; margin-bottom: 6px; }
#   .stat-card-value { font-size: 26px; font-weight: 700; color: var(--text); line-height: 1; }
#   .stat-card-value.danger { color: var(--danger); }
#   .stat-card-value.success { color: var(--success); }
#   .stat-card-sub  { font-size: 11px; color: var(--text-muted); margin-top: 4px; }
#   .stat-card-icon { float: right; font-size: 20px; opacity: .5; }

#   /* Chart panels */
#   .panel {
#     background: var(--surface); border: 1px solid var(--border);
#     border-radius: var(--radius); padding: 16px 18px;
#     box-shadow: var(--shadow);
#   }
#   .panel-header {
#     display: flex; justify-content: space-between; align-items: center;
#     margin-bottom: 14px;
#   }
#   .panel-title { font-size: 13px; font-weight: 600; color: var(--text); }
#   .panel-sub   { font-size: 11px; color: var(--text-muted); }

#   .charts-row { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 14px; }
#   .chart-wrap { height: 150px; position: relative; }

#   /* Alert feed */
#   .alerts-list { display: flex; flex-direction: column; gap: 8px;
#                  max-height: 420px; overflow-y: auto; }
#   .alerts-list::-webkit-scrollbar { width: 4px; }
#   .alerts-list::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

#   .alert-item {
#     display: grid; grid-template-columns: auto 1fr auto;
#     gap: 12px; align-items: start;
#     padding: 11px 14px; border-radius: 8px;
#     border: 1px solid var(--border);
#     border-left: 3px solid var(--danger);
#     background: #fff9f9;
#     animation: fadeIn .3s ease;
#   }
#   .alert-item.high   { border-left-color: var(--warning); background: #fffdf5; }
#   .alert-item.medium { border-left-color: var(--info);    background: #f5fbff; }
#   .alert-item.low    { border-left-color: var(--success); background: #f6fef9; }

#   @keyframes fadeIn { from{opacity:0;transform:translateY(-4px)} to{opacity:1;transform:none} }

#   .alert-ts   { font-size: 11px; color: var(--text-muted); white-space: nowrap; padding-top: 1px;
#                 font-family: monospace; }
#   .alert-type { font-size: 13px; font-weight: 600; color: var(--text); margin-bottom: 2px; }
#   .alert-meta { font-size: 11px; color: var(--text-muted); }
#   .alert-desc { font-size: 11px; color: var(--text-muted); margin-top: 2px; font-style: italic; }

#   .sev-pill {
#     padding: 2px 9px; border-radius: 20px; font-size: 10px;
#     font-weight: 700; letter-spacing: .04em; white-space: nowrap; align-self: start;
#   }
#   .sev-critical { background: #fef2f2; color: var(--danger);  border: 1px solid #fecaca; }
#   .sev-high     { background: #fffbeb; color: var(--warning); border: 1px solid #fde68a; }
#   .sev-medium   { background: #ecfeff; color: var(--info);    border: 1px solid #a5f3fc; }
#   .sev-low      { background: #f0fdf4; color: var(--success); border: 1px solid #bbf7d0; }

#   .empty-state { text-align: center; padding: 40px; color: var(--text-muted); font-size: 13px; }

#   /* Divider */
#   hr { border: none; border-top: 1px solid var(--border); margin: 0; }

#   /* Scrollbars */
#   ::-webkit-scrollbar { width: 5px; }
#   ::-webkit-scrollbar-track { background: transparent; }
#   ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
# </style>
# </head>
# <body>
# <div class="app">

#   <!-- TOPBAR -->
#   <header class="topbar">
#     <div class="topbar-left">
#       <div class="topbar-logo">Network <span>IDS</span></div>
#       <span class="badge badge-blue" id="conn-badge">
#         <span class="dot dot-red" id="conn-dot"></span>
#         Connecting…
#       </span>
#     </div>
#     <div class="topbar-right">
#       <span class="topbar-meta" id="iface-label">Interface: —</span>
#       <span class="topbar-meta" id="uptime-label">Uptime: 0s</span>
#       <span class="badge badge-red" id="ml-badge">ML Training</span>
#     </div>
#   </header>

#   <div class="content">

#     <!-- SIDEBAR -->
#     <aside class="sidebar">

#       <div class="sidebar-section">
#         <div class="section-label">Traffic</div>
#         <div class="kpi-row"><span class="kpi-label">Packets</span>    <span class="kpi-value" id="s-pkts">0</span></div>
#         <div class="kpi-row"><span class="kpi-label">Bytes</span>       <span class="kpi-value" id="s-bytes">0 B</span></div>
#         <div class="kpi-row"><span class="kpi-label">Pkt/sec</span>     <span class="kpi-value green" id="s-pps">0</span></div>
#         <div class="kpi-row"><span class="kpi-label">BW (KB/s)</span>   <span class="kpi-value blue" id="s-bps">0</span></div>
#       </div>

#       <div class="sidebar-section">
#         <div class="section-label">Detection</div>
#         <div class="kpi-row"><span class="kpi-label">Alerts</span>      <span class="kpi-value red" id="s-alerts">0</span></div>
#         <div class="kpi-row"><span class="kpi-label">Unique IPs</span>  <span class="kpi-value" id="s-ips">0</span></div>
#         <div class="kpi-row"><span class="kpi-label">PCAP Files</span>  <span class="kpi-value" id="s-pcap">0</span></div>
#       </div>

#       <div class="sidebar-section">
#         <div class="section-label">Protocols</div>
#         <div class="proto-grid">
#           <div class="proto-pill"><div class="proto-name">TCP</div>  <div class="proto-value" id="p-tcp">0</div></div>
#           <div class="proto-pill"><div class="proto-name">UDP</div>  <div class="proto-value" id="p-udp">0</div></div>
#           <div class="proto-pill"><div class="proto-name">ICMP</div> <div class="proto-value" id="p-icmp">0</div></div>
#           <div class="proto-pill"><div class="proto-name">ARP</div>  <div class="proto-value" id="p-arp">0</div></div>
#           <div class="proto-pill"><div class="proto-name">DNS</div>  <div class="proto-value" id="p-dns">0</div></div>
#           <div class="proto-pill"><div class="proto-name">Other</div><div class="proto-value" id="p-other">0</div></div>
#         </div>
#       </div>

#       <div class="sidebar-section" style="flex:1">
#         <div class="section-label">Top Threat IPs</div>
#         <div id="threat-list"><p class="empty-state" style="padding:16px 0;font-size:11px">No threats yet</p></div>
#       </div>

#     </aside>

#     <!-- MAIN -->
#     <main class="main">

#       <!-- Engine chips -->
#       <div class="chips">
#         <div class="chip active" id="chip-sig">    <span class="chip-dot"></span> Signatures</div>
#         <div class="chip active" id="chip-ml">     <span class="chip-dot"></span> ML Ensemble</div>
#         <div class="chip active" id="chip-ueba">   <span class="chip-dot"></span> UEBA</div>
#         <div class="chip active" id="chip-beacon"> <span class="chip-dot"></span> Beaconing</div>
#         <div class="chip active" id="chip-dns">    <span class="chip-dot"></span> DNS Analysis</div>
#         <div class="chip active" id="chip-arp">    <span class="chip-dot"></span> ARP Spoof</div>
#         <div class="chip active" id="chip-intel">  <span class="chip-dot"></span> Threat Intel</div>
#       </div>

#       <!-- Stat cards -->
#       <div class="stat-cards">
#         <div class="stat-card">
#           <div class="stat-card-icon">📦</div>
#           <div class="stat-card-label">Total Packets</div>
#           <div class="stat-card-value" id="c-pkts">0</div>
#           <div class="stat-card-sub" id="c-pps-sub">0 pkt/s</div>
#         </div>
#         <div class="stat-card">
#           <div class="stat-card-icon">🚨</div>
#           <div class="stat-card-label">Alerts</div>
#           <div class="stat-card-value danger" id="c-alerts">0</div>
#           <div class="stat-card-sub" id="c-alert-sub">0 events</div>
#         </div>
#         <div class="stat-card">
#           <div class="stat-card-icon">🌐</div>
#           <div class="stat-card-label">Unique IPs</div>
#           <div class="stat-card-value" id="c-ips">0</div>
#           <div class="stat-card-sub">tracked hosts</div>
#         </div>
#         <div class="stat-card">
#           <div class="stat-card-icon">💾</div>
#           <div class="stat-card-label">Data Processed</div>
#           <div class="stat-card-value" id="c-bytes">0 B</div>
#           <div class="stat-card-sub" id="c-bps-sub">0 KB/s</div>
#         </div>
#       </div>

#       <!-- Charts row -->
#       <div class="charts-row">
#         <div class="panel">
#           <div class="panel-header">
#             <span class="panel-title">Packets / sec</span>
#             <span class="panel-sub" id="pps-current">0</span>
#           </div>
#           <div class="chart-wrap"><canvas id="ch-pps"></canvas></div>
#         </div>
#         <div class="panel">
#           <div class="panel-header">
#             <span class="panel-title">Bandwidth (KB/s)</span>
#             <span class="panel-sub" id="bps-current">0</span>
#           </div>
#           <div class="chart-wrap"><canvas id="ch-bps"></canvas></div>
#         </div>
#         <div class="panel">
#           <div class="panel-header">
#             <span class="panel-title">Attack Distribution</span>
#           </div>
#           <div class="chart-wrap"><canvas id="ch-atk"></canvas></div>
#         </div>
#       </div>

#       <!-- Alert timeline -->
#       <div class="panel">
#         <div class="panel-header">
#           <span class="panel-title">Alert Timeline</span>
#           <span class="panel-sub">last 120s</span>
#         </div>
#         <div style="height:90px;position:relative"><canvas id="ch-timeline"></canvas></div>
#       </div>

#       <!-- Alert feed -->
#       <div class="panel">
#         <div class="panel-header">
#           <span class="panel-title">Alert Feed</span>
#           <span class="panel-sub" id="alert-count">0 events</span>
#         </div>
#         <div class="alerts-list" id="alerts-list">
#           <div class="empty-state">Monitoring… no alerts yet.</div>
#         </div>
#       </div>

#     </main>
#   </div>
# </div>

# <script>
# const socket = io();
# let alertCount = 0;

# /* ── Connection ── */
# socket.on('connect', () => {
#   setConnected(true);
#   socket.emit('request_timeline');
# });
# socket.on('disconnect', () => setConnected(false));

# function setConnected(on) {
#   const badge = document.getElementById('conn-badge');
#   const dot   = document.getElementById('conn-dot');
#   badge.textContent = on ? '● Live' : '● Disconnected';
#   badge.className   = 'badge ' + (on ? 'badge-green' : 'badge-red');
#   dot.className     = 'dot ' + (on ? 'dot-green dot-pulse' : 'dot-red');
# }

# /* ── Charts ── */
# const BLUE   = '#2563eb';
# const GREEN  = '#16a34a';
# const RED    = '#dc2626';
# const AMBER  = '#d97706';
# const GRID   = 'rgba(0,0,0,.06)';
# const TICK   = '#9ca3af';

# Chart.defaults.font.family = "'Inter', system-ui, sans-serif";
# Chart.defaults.font.size   = 11;
# Chart.defaults.color       = TICK;

# function makeSparkline(id, color) {
#   return new Chart(document.getElementById(id), {
#     type: 'line',
#     data: { labels: [], datasets: [{ data: [], borderColor: color,
#       borderWidth: 2, backgroundColor: color + '18', tension: 0.4,
#       fill: true, pointRadius: 0 }] },
#     options: {
#       responsive: true, maintainAspectRatio: false, animation: false,
#       plugins: { legend: { display: false } },
#       scales: {
#         x: { display: false },
#         y: { beginAtZero: true, grid: { color: GRID },
#              ticks: { maxTicksLimit: 4, color: TICK } }
#       }
#     }
#   });
# }

# const chartPPS      = makeSparkline('ch-pps',      BLUE);
# const chartBPS      = makeSparkline('ch-bps',      GREEN);
# const chartTimeline = makeSparkline('ch-timeline', RED);

# const chartAtk = new Chart(document.getElementById('ch-atk'), {
#   type: 'doughnut',
#   data: { labels: [], datasets: [{ data: [], borderWidth: 2, borderColor: '#fff',
#     backgroundColor: [RED, AMBER, BLUE, GREEN, '#8b5cf6','#06b6d4','#f59e0b','#6b7280'] }] },
#   options: {
#     responsive: true, maintainAspectRatio: false, animation: false, cutout: '60%',
#     plugins: { legend: { position: 'right',
#       labels: { color: '#374151', boxWidth: 10, font: { size: 10 } } } }
#   }
# });

# function pushSpark(chart, labels, data) {
#   chart.data.labels = labels;
#   chart.data.datasets[0].data = data;
#   chart.update('none');
# }

# /* ── Stats ── */
# socket.on('stats_update', s => {
#   // sidebar
#   set('s-pkts',   fmt(s.total_packets));
#   set('s-bytes',  fmtBytes(s.total_bytes));
#   set('s-pps',    s.pps.toFixed(1));
#   set('s-bps',    s.bps_kb.toFixed(1));
#   set('s-alerts', s.alerts);
#   set('s-ips',    s.unique_ips);
#   set('s-pcap',   s.pcap_files);
#   set('p-tcp',    fmt(s.tcp));
#   set('p-udp',    fmt(s.udp));
#   set('p-icmp',   fmt(s.icmp));
#   set('p-arp',    fmt(s.arp));
#   set('p-dns',    fmt(s.dns));
#   set('p-other',  fmt(Math.max(0, s.total_packets - s.tcp - s.udp - s.icmp - s.arp - s.dns)));

#   // topbar
#   const up = s.uptime_s;
#   const h = Math.floor(up/3600), m = Math.floor((up%3600)/60), sc = Math.floor(up%60);
#   set('uptime-label',  `Uptime: ${h ? h+'h ' : ''}${m}m ${sc}s`);
#   set('iface-label',   `Interface: ${s.interface || '—'}`);

#   const mlBadge = document.getElementById('ml-badge');
#   mlBadge.textContent = s.ml_trained ? 'ML Active' : 'ML Training';
#   mlBadge.className   = 'badge ' + (s.ml_trained ? 'badge-green' : 'badge-amber');

#   // stat cards
#   set('c-pkts',     fmt(s.total_packets));
#   set('c-pps-sub',  s.pps.toFixed(1) + ' pkt/s');
#   set('c-alerts',   s.alerts);
#   set('c-alert-sub', dict2counts(s.alert_counts));
#   set('c-ips',      s.unique_ips);
#   set('c-bytes',    fmtBytes(s.total_bytes));
#   set('c-bps-sub',  s.bps_kb.toFixed(1) + ' KB/s');
#   set('pps-current', s.pps.toFixed(1) + ' pkt/s');
#   set('bps-current', s.bps_kb.toFixed(1) + ' KB/s');

#   // doughnut
#   const counts = s.alert_counts || {};
#   if (Object.keys(counts).length) {
#     chartAtk.data.labels = Object.keys(counts);
#     chartAtk.data.datasets[0].data = Object.values(counts);
#     chartAtk.update('none');
#   }

#   renderThreats(s.top_threats || []);
# });

# /* ── Timeline ── */
# socket.on('timeline_data', d => {
#   pushSpark(chartPPS,      d.labels, d.pps);
#   pushSpark(chartBPS,      d.labels, d.bps_kb);
#   pushSpark(chartTimeline, d.labels, d.alerts);
# });
# setInterval(() => {
#   fetch('/api/timeline').then(r => r.json()).then(d => {
#     pushSpark(chartPPS,      d.labels, d.pps);
#     pushSpark(chartBPS,      d.labels, d.bps_kb);
#     pushSpark(chartTimeline, d.labels, d.alerts);
#   }).catch(() => {});
# }, 2000);

# /* ── Alerts ── */
# socket.on('new_alert', a => {
#   alertCount++;
#   set('alert-count', alertCount + ' events');
#   prependAlert(a);
# });

# function prependAlert(a) {
#   const list = document.getElementById('alerts-list');
#   if (list.querySelector('.empty-state')) list.innerHTML = '';

#   const sev      = (a.severity || 'low').toLowerCase();
#   const rowClass = sev === 'critical' ? '' : sev;
#   const sevClass = 'sev-' + sev;
#   const ts   = new Date(a.timestamp).toLocaleTimeString();
#   const geo  = a.geo ? `${a.geo.city ? a.geo.city + ', ' : ''}${a.geo.country || ''}` : '';
#   const score = a.composite_score != null ? ` — Score: ${a.composite_score}` : '';
#   const desc  = a.details?.description || '';

#   const div = document.createElement('div');
#   div.className = 'alert-item ' + rowClass;
#   div.innerHTML = `
#     <span class="alert-ts">${ts}</span>
#     <div>
#       <div class="alert-type">${esc(a.attack_type)}</div>
#       <div class="alert-meta">${esc(a.src_ip)}${geo ? '  ·  ' + esc(geo) : ''}${score}</div>
#       ${desc ? `<div class="alert-desc">${esc(desc)}</div>` : ''}
#     </div>
#     <span class="sev-pill ${sevClass}">${a.severity}</span>`;
#   list.insertBefore(div, list.firstChild);
#   while (list.children.length > 60) list.removeChild(list.lastChild);
# }

# /* ── Threat bars ── */
# function renderThreats(threats) {
#   const el = document.getElementById('threat-list');
#   if (!threats.length) {
#     el.innerHTML = '<p class="empty-state" style="padding:12px 0;font-size:11px">No threats scored yet</p>';
#     return;
#   }
#   el.innerHTML = threats.map(t => `
#     <div class="threat-item">
#       <div class="threat-header">
#         <span class="threat-ip">${t.ip}</span>
#         <span class="threat-score">${t.score.toFixed(0)}/100</span>
#       </div>
#       <div class="threat-track">
#         <div class="threat-fill" style="width:${Math.min(t.score, 100)}%"></div>
#       </div>
#       <div class="threat-tags">${(t.tags || []).slice(0, 2).join(' · ')}</div>
#     </div>`).join('');
# }

# /* ── Helpers ── */
# function set(id, val) {
#   const el = document.getElementById(id);
#   if (el) el.textContent = val;
# }
# function fmt(n) {
#   n = Number(n) || 0;
#   if (n >= 1e9) return (n/1e9).toFixed(1) + 'G';
#   if (n >= 1e6) return (n/1e6).toFixed(1) + 'M';
#   if (n >= 1e3) return (n/1e3).toFixed(1) + 'K';
#   return n;
# }
# function fmtBytes(b) {
#   if (b >= 1<<30) return (b/(1<<30)).toFixed(2) + ' GB';
#   if (b >= 1<<20) return (b/(1<<20)).toFixed(1) + ' MB';
#   if (b >= 1<<10) return Math.round(b/(1<<10)) + ' KB';
#   return b + ' B';
# }
# function dict2counts(d) {
#   const total = Object.values(d || {}).reduce((a,b) => a+b, 0);
#   return total ? total + ' total types' : 'none yet';
# }
# function esc(s) {
#   return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
# }
# </script>
# </body>
# </html>
# """

# # ─────────────────────────────────────────────────────────────────────
# if __name__ == '__main__':
#     ap = argparse.ArgumentParser(description='Network IDS Dashboard v2.1')
#     ap.add_argument('-c', '--config',    default=None)
#     ap.add_argument('-i', '--interface', default=None)
#     ap.add_argument('-p', '--port',      type=int, default=5001)
#     ap.add_argument('--no-ids',          action='store_true')
#     args = ap.parse_args()

#     if not args.no_ids:
#         cfg = load_config(args.config)
#         if args.interface:
#             cfg['interface'] = args.interface
#         cfg['enable_api'] = False
#         ids_thread = threading.Thread(target=start_ids, args=(cfg,), daemon=True)
#         ids_thread.start()
#         time.sleep(2)

#     print(f"\n🌐  Dashboard  →  http://localhost:{args.port}")
#     print(f"   /api/stats | /api/alerts | /api/threats | /api/timeline")
#     print(f"   Press Ctrl+C to stop\n")

#     try:
#         socketio.run(app, host='0.0.0.0', port=args.port, debug=False, use_reloader=False)
#     except KeyboardInterrupt:
#         ids_running = False
#         if ids_instance:
#             ids_instance.stop()


# """
# Advanced Network IDS — Web Dashboard v2.1
# Fixed: _patch_ids_alerts now passes **kwargs so cooldown_key etc. work correctly.
# """

# import threading
# import time
# import json
# import os
# import sys
# import argparse
# from datetime import datetime
# from collections import defaultdict, deque
# from typing import Optional

# from flask import Flask, jsonify, request
# from flask_socketio import SocketIO, emit

# try:
#     from network_ids_advanced import AdvancedNetworkIDS, load_config
# except ImportError:
#     print("❌  network_ids_advanced.py not found in the same directory.")
#     sys.exit(1)

# # ─────────────────────────────────────────────────────────────────────
# app = Flask(__name__)
# app.config['SECRET_KEY'] = os.environ.get('IDS_SECRET', 'change-me-in-production')
# socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading',
#                     logger=False, engineio_logger=False)

# ids_instance: Optional[AdvancedNetworkIDS] = None
# ids_running = False

# TIMELINE_LEN = 120
# timeline_lock    = threading.Lock()
# timeline_pps:    deque = deque([0.0] * TIMELINE_LEN, maxlen=TIMELINE_LEN)
# timeline_bps:    deque = deque([0.0] * TIMELINE_LEN, maxlen=TIMELINE_LEN)
# timeline_alerts: deque = deque([0]   * TIMELINE_LEN, maxlen=TIMELINE_LEN)
# timeline_labels: deque = deque(['']  * TIMELINE_LEN, maxlen=TIMELINE_LEN)

# _last_pkt_count   = 0
# _last_byte_count  = 0
# _last_alert_count = 0
# _last_tick_time   = time.time()


# # ── Alert hook ────────────────────────────────────────────────────────
# def _alert_hook(alert: dict):
#     try:
#         socketio.emit('new_alert', alert, namespace='/')
#     except Exception:
#         pass


# def _patch_ids_alerts(ids: AdvancedNetworkIDS):
#     """
#     Wraps ids._alert so every fired alert is also broadcast to the dashboard.

#     IMPORTANT: the wrapper must accept *args and **kwargs so it is transparent
#     to any signature changes in _alert (e.g. the keyword-only cooldown_key,
#     cooldown_override args added in v2.1).
#     """
#     _orig = ids._alert

#     def patched(*args, **kwargs):
#         # Call the real _alert — this handles cooldown, dedup, saving, etc.
#         _orig(*args, **kwargs)
#         # After it returns, the last entry in ids.alerts (if any) is the new one.
#         if ids.alerts:
#             _alert_hook(dict(ids.alerts[-1]))

#     ids._alert = patched


# # ── Background broadcaster ────────────────────────────────────────────
# def _broadcaster():
#     global _last_pkt_count, _last_byte_count, _last_alert_count, _last_tick_time

#     while ids_running:
#         time.sleep(1)
#         if not ids_instance:
#             continue

#         now = time.time()
#         dt  = max(now - _last_tick_time, 0.001)
#         _last_tick_time = now

#         s          = ids_instance.stats
#         cur_pkts   = s['total_packets']
#         cur_bytes  = s['total_bytes']
#         cur_alerts = s['alerts']

#         pps        = (cur_pkts  - _last_pkt_count)  / dt
#         bps        = (cur_bytes - _last_byte_count)  / dt
#         new_alerts = cur_alerts - _last_alert_count

#         _last_pkt_count   = cur_pkts
#         _last_byte_count  = cur_bytes
#         _last_alert_count = cur_alerts

#         with timeline_lock:
#             timeline_pps.append(round(pps, 1))
#             timeline_bps.append(round(bps / 1024, 1))
#             timeline_alerts.append(new_alerts)
#             timeline_labels.append(datetime.now().strftime('%H:%M:%S'))

#         up = (datetime.now() - s['start_time']).total_seconds()
#         payload = {
#             'total_packets': s['total_packets'],
#             'total_bytes':   s['total_bytes'],
#             'alerts':        s['alerts'],
#             'unique_ips':    len(ids_instance.connections),
#             'tcp':  s['tcp'],  'udp': s['udp'],
#             'icmp': s['icmp'], 'arp': s['arp'], 'dns': s['dns'],
#             'pps':     round(pps, 1),
#             'bps_kb':  round(bps / 1024, 1),
#             'uptime_s':   round(up, 0),
#             'ml_trained': ids_instance.ensemble.trained,
#             'pcap_files': len(ids_instance.pcap_mgr.list_files()),
#             'interface':  ids_instance.interface,
#             'alert_counts': dict(ids_instance.alert_counts),
#             'top_threats': [
#                 {'ip': ip, 'score': round(sc, 1), 'tags': list(set(ev))[:3]}
#                 for ip, sc, ev in ids_instance.scoreboard.top_threats(5)
#             ],
#         }
#         socketio.emit('stats_update', payload, namespace='/')


# # ── REST API ──────────────────────────────────────────────────────────
# def _ids_required(f):
#     from functools import wraps
#     @wraps(f)
#     def wrapper(*args, **kwargs):
#         if not ids_instance:
#             return jsonify({'error': 'IDS not running'}), 503
#         return f(*args, **kwargs)
#     return wrapper


# @app.route('/')
# def index():
#     return DASHBOARD_HTML, 200, {'Content-Type': 'text/html'}


# @app.route('/api/stats')
# @_ids_required
# def api_stats():
#     s  = ids_instance.stats
#     up = (datetime.now() - s['start_time']).total_seconds()
#     return jsonify({
#         **{k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in s.items()},
#         'uptime_s':   round(up, 1),
#         'unique_ips': len(ids_instance.connections),
#         'ml_trained': ids_instance.ensemble.trained,
#     })


# @app.route('/api/alerts')
# @_ids_required
# def api_alerts():
#     limit  = min(int(request.args.get('limit', 50)), 500)
#     sev    = request.args.get('severity')
#     alerts = list(ids_instance.alerts)
#     if sev:
#         alerts = [a for a in alerts if a.get('severity', '').lower() == sev.lower()]
#     return jsonify(alerts[-limit:])


# @app.route('/api/threats')
# @_ids_required
# def api_threats():
#     n = int(request.args.get('n', 20))
#     return jsonify([
#         {'ip': ip, 'score': round(sc, 1),
#          'evidence':   list(set(ev))[:10],
#          'reputation': round(ids_instance.threat_intel.get_reputation(ip), 3),
#          'geo':        ids_instance.threat_intel.geolocate(ip)}
#         for ip, sc, ev in ids_instance.scoreboard.top_threats(n)
#     ])


# @app.route('/api/timeline')
# def api_timeline():
#     with timeline_lock:
#         return jsonify({
#             'labels': list(timeline_labels),
#             'pps':    list(timeline_pps),
#             'bps_kb': list(timeline_bps),
#             'alerts': list(timeline_alerts),
#         })


# @app.route('/api/top_ips')
# @_ids_required
# def api_top_ips():
#     n    = int(request.args.get('n', 10))
#     rows = sorted(ids_instance.connections.items(),
#                   key=lambda kv: kv[1]['pkt_count'], reverse=True)[:n]
#     return jsonify([
#         {'ip': ip, 'packets': c['pkt_count'], 'bytes': c['bytes'],
#          'ports': len(c['ports']),
#          'score': round(ids_instance.scoreboard.get_score(ip), 1),
#          'geo':   ids_instance.threat_intel.geolocate(ip)}
#         for ip, c in rows
#     ])


# @app.route('/api/alert_counts')
# @_ids_required
# def api_alert_counts():
#     return jsonify(dict(ids_instance.alert_counts))


# @app.route('/api/pcap_files')
# @_ids_required
# def api_pcap_files():
#     files = ids_instance.pcap_mgr.list_files()
#     return jsonify([
#         {'name': os.path.basename(f),
#          'size_kb': round(os.path.getsize(f) / 1024, 1), 'path': f}
#         for f in files
#     ])


# @app.route('/api/health')
# def api_health():
#     return jsonify({'status': 'ok', 'ids_running': ids_running, 'version': '2.1.0'})


# @app.route('/api/thresholds')
# @_ids_required
# def api_thresholds():
#     return jsonify(ids_instance.adapt_thr.snapshot())


# # ── SocketIO ──────────────────────────────────────────────────────────
# @socketio.on('connect')
# def on_connect():
#     if ids_instance:
#         emit('ids_status', {'running': ids_running, 'interface': ids_instance.interface})


# @socketio.on('request_timeline')
# def on_request_timeline():
#     with timeline_lock:
#         emit('timeline_data', {
#             'labels': list(timeline_labels),
#             'pps':    list(timeline_pps),
#             'bps_kb': list(timeline_bps),
#             'alerts': list(timeline_alerts),
#         })


# @socketio.on('request_top_threats')
# def on_request_top_threats():
#     if ids_instance:
#         emit('top_threats', [
#             {'ip': ip, 'score': round(sc, 1), 'tags': list(set(ev))[:3]}
#             for ip, sc, ev in ids_instance.scoreboard.top_threats(10)
#         ])


# # ── IDS lifecycle ─────────────────────────────────────────────────────
# def start_ids(cfg: dict):
#     global ids_instance, ids_running
#     ids_instance = AdvancedNetworkIDS(cfg)
#     _patch_ids_alerts(ids_instance)
#     ids_instance.start()
#     ids_running = True
#     threading.Thread(target=_broadcaster, daemon=True).start()
#     print("✅  Dashboard broadcaster started")


# # ─────────────────────────────────────────────────────────────────────
# # DASHBOARD HTML
# # ─────────────────────────────────────────────────────────────────────
# DASHBOARD_HTML = """<!DOCTYPE html>
# <html lang="en">
# <head>
# <meta charset="UTF-8">
# <meta name="viewport" content="width=device-width, initial-scale=1.0">
# <title>Network IDS Dashboard</title>
# <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
# <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
# <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
# <style>
#   *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
#   :root {
#     --bg:         #f0f2f5;
#     --surface:    #ffffff;
#     --border:     #e2e6ea;
#     --text:       #1a1d23;
#     --text-muted: #6b7280;
#     --primary:    #2563eb;
#     --success:    #16a34a;
#     --warning:    #d97706;
#     --danger:     #dc2626;
#     --info:       #0891b2;
#     --radius:     10px;
#     --shadow:     0 1px 3px rgba(0,0,0,.08), 0 1px 2px rgba(0,0,0,.05);
#   }
#   html, body { height: 100%; background: var(--bg); color: var(--text);
#                font-family: 'Inter', system-ui, sans-serif; font-size: 14px; }
#   .app { display: flex; flex-direction: column; min-height: 100vh; }

#   /* Topbar */
#   .topbar {
#     background: var(--surface); border-bottom: 1px solid var(--border);
#     padding: 0 24px; height: 56px;
#     display: flex; align-items: center; justify-content: space-between;
#     position: sticky; top: 0; z-index: 50; box-shadow: var(--shadow);
#   }
#   .topbar-logo { font-size: 16px; font-weight: 700; }
#   .topbar-logo span { color: var(--primary); }
#   .topbar-right { display: flex; align-items: center; gap: 16px; }
#   .topbar-meta { font-size: 12px; color: var(--text-muted); }

#   .badge { display:inline-flex; align-items:center; gap:5px; padding:3px 10px;
#            border-radius:20px; font-size:11px; font-weight:600; }
#   .badge-blue  { background:#eff6ff; color:var(--primary); border:1px solid #bfdbfe; }
#   .badge-green { background:#f0fdf4; color:var(--success); border:1px solid #bbf7d0; }
#   .badge-red   { background:#fef2f2; color:var(--danger);  border:1px solid #fecaca; }
#   .badge-amber { background:#fffbeb; color:var(--warning); border:1px solid #fde68a; }

#   .dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:4px; }
#   .dot-green { background:var(--success); box-shadow:0 0 0 3px rgba(22,163,74,.15); }
#   .dot-red   { background:var(--danger); }
#   .dot-pulse { animation:pulse 2s ease infinite; }
#   @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.5} }

#   /* Layout */
#   .content { display:grid; grid-template-columns:240px 1fr; flex:1; }

#   /* Sidebar */
#   .sidebar { background:var(--surface); border-right:1px solid var(--border);
#              padding:20px 16px; display:flex; flex-direction:column; gap:20px; overflow-y:auto; }
#   .section-label { font-size:10px; font-weight:600; letter-spacing:.08em;
#                    text-transform:uppercase; color:var(--text-muted); margin-bottom:12px; }
#   .kpi-row { display:flex; justify-content:space-between; align-items:center;
#              padding:6px 0; border-bottom:1px solid var(--border); }
#   .kpi-row:last-child { border-bottom:none; }
#   .kpi-label { font-size:12px; color:var(--text-muted); }
#   .kpi-value { font-size:15px; font-weight:600; }
#   .kpi-value.red   { color:var(--danger); }
#   .kpi-value.green { color:var(--success); }
#   .kpi-value.blue  { color:var(--primary); }

#   .proto-grid { display:grid; grid-template-columns:1fr 1fr; gap:6px; }
#   .proto-pill { background:var(--bg); border:1px solid var(--border); border-radius:8px;
#                 padding:8px 10px; text-align:center; }
#   .proto-name  { font-size:10px; color:var(--text-muted); font-weight:500;
#                  text-transform:uppercase; }
#   .proto-value { font-size:16px; font-weight:700; margin-top:2px; }

#   .threat-item  { margin-bottom:12px; }
#   .threat-header { display:flex; justify-content:space-between; margin-bottom:4px; }
#   .threat-ip    { font-size:12px; font-weight:500; font-family:monospace; }
#   .threat-score { font-size:11px; font-weight:600; color:var(--danger); }
#   .threat-track { height:5px; background:var(--border); border-radius:3px; overflow:hidden; }
#   .threat-fill  { height:100%; border-radius:3px;
#                   background:linear-gradient(90deg,var(--primary),var(--danger));
#                   transition:width .5s ease; }
#   .threat-tags  { font-size:10px; color:var(--text-muted); margin-top:3px; }

#   /* Main */
#   .main { padding:20px; display:flex; flex-direction:column; gap:16px; overflow-y:auto; }

#   .chips { display:flex; gap:6px; flex-wrap:wrap; }
#   .chip  { font-size:11px; font-weight:500; padding:4px 10px; border-radius:20px;
#            border:1px solid var(--border); background:var(--surface); color:var(--text-muted);
#            display:flex; align-items:center; gap:5px; }
#   .chip.active { background:#f0fdf4; color:var(--success); border-color:#bbf7d0; }
#   .chip-dot { width:6px; height:6px; border-radius:50%; background:currentColor; }

#   .stat-cards { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; }
#   .stat-card  { background:var(--surface); border:1px solid var(--border);
#                 border-radius:var(--radius); padding:16px 18px; box-shadow:var(--shadow); }
#   .stat-card-label { font-size:11px; color:var(--text-muted); font-weight:500;
#                      text-transform:uppercase; letter-spacing:.05em; margin-bottom:6px; }
#   .stat-card-value { font-size:26px; font-weight:700; line-height:1; }
#   .stat-card-value.danger  { color:var(--danger); }
#   .stat-card-value.success { color:var(--success); }
#   .stat-card-sub  { font-size:11px; color:var(--text-muted); margin-top:4px; }
#   .stat-card-icon { float:right; font-size:20px; opacity:.5; }

#   .panel { background:var(--surface); border:1px solid var(--border);
#            border-radius:var(--radius); padding:16px 18px; box-shadow:var(--shadow); }
#   .panel-header { display:flex; justify-content:space-between; align-items:center;
#                   margin-bottom:14px; }
#   .panel-title { font-size:13px; font-weight:600; }
#   .panel-sub   { font-size:11px; color:var(--text-muted); }

#   .charts-row { display:grid; grid-template-columns:1fr 1fr 1fr; gap:14px; }
#   .chart-wrap { height:150px; position:relative; }

#   .alerts-list { display:flex; flex-direction:column; gap:8px;
#                  max-height:420px; overflow-y:auto; }
#   .alerts-list::-webkit-scrollbar { width:4px; }
#   .alerts-list::-webkit-scrollbar-thumb { background:var(--border); border-radius:2px; }

#   .alert-item { display:grid; grid-template-columns:auto 1fr auto; gap:12px;
#                 align-items:start; padding:11px 14px; border-radius:8px;
#                 border:1px solid var(--border); border-left:3px solid var(--danger);
#                 background:#fff9f9; animation:fadeIn .3s ease; }
#   .alert-item.high   { border-left-color:var(--warning); background:#fffdf5; }
#   .alert-item.medium { border-left-color:var(--info);    background:#f5fbff; }
#   .alert-item.low    { border-left-color:var(--success); background:#f6fef9; }
#   @keyframes fadeIn { from{opacity:0;transform:translateY(-4px)} to{opacity:1;transform:none} }

#   .alert-ts   { font-size:11px; color:var(--text-muted); white-space:nowrap;
#                 padding-top:1px; font-family:monospace; }
#   .alert-type { font-size:13px; font-weight:600; margin-bottom:2px; }
#   .alert-meta { font-size:11px; color:var(--text-muted); }
#   .alert-desc { font-size:11px; color:var(--text-muted); margin-top:2px; font-style:italic; }

#   .sev-pill { padding:2px 9px; border-radius:20px; font-size:10px;
#               font-weight:700; letter-spacing:.04em; white-space:nowrap; align-self:start; }
#   .sev-critical { background:#fef2f2; color:var(--danger);  border:1px solid #fecaca; }
#   .sev-high     { background:#fffbeb; color:var(--warning); border:1px solid #fde68a; }
#   .sev-medium   { background:#ecfeff; color:var(--info);    border:1px solid #a5f3fc; }
#   .sev-low      { background:#f0fdf4; color:var(--success); border:1px solid #bbf7d0; }

#   .empty-state { text-align:center; padding:40px; color:var(--text-muted); font-size:13px; }
#   ::-webkit-scrollbar { width:5px; }
#   ::-webkit-scrollbar-thumb { background:var(--border); border-radius:4px; }
# </style>
# </head>
# <body>
# <div class="app">

#   <header class="topbar">
#     <div style="display:flex;align-items:center;gap:12px">
#       <div class="topbar-logo">Network <span>IDS</span></div>
#       <span class="badge badge-red" id="conn-badge">
#         <span class="dot dot-red" id="conn-dot"></span>Connecting…
#       </span>
#     </div>
#     <div class="topbar-right">
#       <span class="topbar-meta" id="iface-label">Interface: —</span>
#       <span class="topbar-meta" id="uptime-label">Uptime: 0s</span>
#       <span class="badge badge-red" id="ml-badge">ML Training</span>
#     </div>
#   </header>

#   <div class="content">

#     <aside class="sidebar">
#       <div>
#         <div class="section-label">Traffic</div>
#         <div class="kpi-row"><span class="kpi-label">Packets</span>  <span class="kpi-value" id="s-pkts">0</span></div>
#         <div class="kpi-row"><span class="kpi-label">Bytes</span>    <span class="kpi-value" id="s-bytes">0 B</span></div>
#         <div class="kpi-row"><span class="kpi-label">Pkt/sec</span>  <span class="kpi-value green" id="s-pps">0</span></div>
#         <div class="kpi-row"><span class="kpi-label">KB/s</span>     <span class="kpi-value blue" id="s-bps">0</span></div>
#       </div>
#       <div>
#         <div class="section-label">Detection</div>
#         <div class="kpi-row"><span class="kpi-label">Alerts</span>     <span class="kpi-value red" id="s-alerts">0</span></div>
#         <div class="kpi-row"><span class="kpi-label">Unique IPs</span> <span class="kpi-value" id="s-ips">0</span></div>
#         <div class="kpi-row"><span class="kpi-label">PCAP Files</span> <span class="kpi-value" id="s-pcap">0</span></div>
#       </div>
#       <div>
#         <div class="section-label">Protocols</div>
#         <div class="proto-grid">
#           <div class="proto-pill"><div class="proto-name">TCP</div>  <div class="proto-value" id="p-tcp">0</div></div>
#           <div class="proto-pill"><div class="proto-name">UDP</div>  <div class="proto-value" id="p-udp">0</div></div>
#           <div class="proto-pill"><div class="proto-name">ICMP</div> <div class="proto-value" id="p-icmp">0</div></div>
#           <div class="proto-pill"><div class="proto-name">ARP</div>  <div class="proto-value" id="p-arp">0</div></div>
#           <div class="proto-pill"><div class="proto-name">DNS</div>  <div class="proto-value" id="p-dns">0</div></div>
#           <div class="proto-pill"><div class="proto-name">Other</div><div class="proto-value" id="p-other">0</div></div>
#         </div>
#       </div>
#       <div style="flex:1">
#         <div class="section-label">Top Threat IPs</div>
#         <div id="threat-list"><p class="empty-state" style="padding:16px 0;font-size:11px">No threats yet</p></div>
#       </div>
#     </aside>

#     <main class="main">

#       <div class="chips">
#         <div class="chip active"><span class="chip-dot"></span> Signatures</div>
#         <div class="chip active"><span class="chip-dot"></span> ML Ensemble</div>
#         <div class="chip active"><span class="chip-dot"></span> UEBA</div>
#         <div class="chip active"><span class="chip-dot"></span> Beaconing</div>
#         <div class="chip active"><span class="chip-dot"></span> DNS Analysis</div>
#         <div class="chip active"><span class="chip-dot"></span> ARP Spoof</div>
#         <div class="chip active"><span class="chip-dot"></span> Threat Intel</div>
#       </div>

#       <div class="stat-cards">
#         <div class="stat-card">
#           <div class="stat-card-icon">📦</div>
#           <div class="stat-card-label">Total Packets</div>
#           <div class="stat-card-value" id="c-pkts">0</div>
#           <div class="stat-card-sub" id="c-pps-sub">0 pkt/s</div>
#         </div>
#         <div class="stat-card">
#           <div class="stat-card-icon">🚨</div>
#           <div class="stat-card-label">Alerts</div>
#           <div class="stat-card-value danger" id="c-alerts">0</div>
#           <div class="stat-card-sub" id="c-alert-sub">none yet</div>
#         </div>
#         <div class="stat-card">
#           <div class="stat-card-icon">🌐</div>
#           <div class="stat-card-label">Unique IPs</div>
#           <div class="stat-card-value" id="c-ips">0</div>
#           <div class="stat-card-sub">tracked hosts</div>
#         </div>
#         <div class="stat-card">
#           <div class="stat-card-icon">💾</div>
#           <div class="stat-card-label">Data Processed</div>
#           <div class="stat-card-value" id="c-bytes">0 B</div>
#           <div class="stat-card-sub" id="c-bps-sub">0 KB/s</div>
#         </div>
#       </div>

#       <div class="charts-row">
#         <div class="panel">
#           <div class="panel-header">
#             <span class="panel-title">Packets / sec</span>
#             <span class="panel-sub" id="pps-current">0</span>
#           </div>
#           <div class="chart-wrap"><canvas id="ch-pps"></canvas></div>
#         </div>
#         <div class="panel">
#           <div class="panel-header">
#             <span class="panel-title">Bandwidth (KB/s)</span>
#             <span class="panel-sub" id="bps-current">0</span>
#           </div>
#           <div class="chart-wrap"><canvas id="ch-bps"></canvas></div>
#         </div>
#         <div class="panel">
#           <div class="panel-header"><span class="panel-title">Attack Distribution</span></div>
#           <div class="chart-wrap"><canvas id="ch-atk"></canvas></div>
#         </div>
#       </div>

#       <div class="panel">
#         <div class="panel-header">
#           <span class="panel-title">Alert Timeline</span>
#           <span class="panel-sub">last 120s</span>
#         </div>
#         <div style="height:90px;position:relative"><canvas id="ch-timeline"></canvas></div>
#       </div>

#       <div class="panel">
#         <div class="panel-header">
#           <span class="panel-title">Alert Feed</span>
#           <span class="panel-sub" id="alert-count">0 events</span>
#         </div>
#         <div class="alerts-list" id="alerts-list">
#           <div class="empty-state">Monitoring… no alerts yet.</div>
#         </div>
#       </div>

#     </main>
#   </div>
# </div>

# <script>
# const socket = io();
# let alertCount = 0;

# socket.on('connect',    () => setConn(true));
# socket.on('disconnect', () => setConn(false));
# socket.on('connect', () => socket.emit('request_timeline'));

# function setConn(on) {
#   const b = document.getElementById('conn-badge');
#   const d = document.getElementById('conn-dot');
#   b.textContent = on ? '● Live' : '● Disconnected';
#   b.className   = 'badge ' + (on ? 'badge-green' : 'badge-red');
#   d.className   = 'dot ' + (on ? 'dot-green dot-pulse' : 'dot-red');
# }

# /* Charts */
# const BLUE  = '#2563eb', GREEN = '#16a34a', RED = '#dc2626',
#       AMBER = '#d97706', GRID  = 'rgba(0,0,0,.06)', TICK = '#9ca3af';
# Chart.defaults.font.family = "'Inter', system-ui, sans-serif";
# Chart.defaults.font.size   = 11;
# Chart.defaults.color       = TICK;

# function makeSparkline(id, color) {
#   return new Chart(document.getElementById(id), {
#     type: 'line',
#     data: { labels: [], datasets: [{ data: [], borderColor: color,
#       borderWidth: 2, backgroundColor: color + '18', tension: 0.4,
#       fill: true, pointRadius: 0 }] },
#     options: {
#       responsive: true, maintainAspectRatio: false, animation: false,
#       plugins: { legend: { display: false } },
#       scales: {
#         x: { display: false },
#         y: { beginAtZero: true, grid: { color: GRID },
#              ticks: { maxTicksLimit: 4, color: TICK } }
#       }
#     }
#   });
# }

# const chartPPS      = makeSparkline('ch-pps',      BLUE);
# const chartBPS      = makeSparkline('ch-bps',      GREEN);
# const chartTimeline = makeSparkline('ch-timeline', RED);

# const chartAtk = new Chart(document.getElementById('ch-atk'), {
#   type: 'doughnut',
#   data: { labels: [], datasets: [{ data: [], borderWidth: 2, borderColor: '#fff',
#     backgroundColor: [RED, AMBER, BLUE, GREEN, '#8b5cf6','#06b6d4','#f59e0b','#6b7280'] }] },
#   options: {
#     responsive: true, maintainAspectRatio: false, animation: false, cutout: '60%',
#     plugins: { legend: { position: 'right',
#       labels: { color: '#374151', boxWidth: 10, font: { size: 10 } } } }
#   }
# });

# function pushSpark(chart, labels, data) {
#   chart.data.labels = labels;
#   chart.data.datasets[0].data = data;
#   chart.update('none');
# }

# /* Stats */
# socket.on('stats_update', s => {
#   set('s-pkts',   fmt(s.total_packets));
#   set('s-bytes',  fmtBytes(s.total_bytes));
#   set('s-pps',    s.pps.toFixed(1));
#   set('s-bps',    s.bps_kb.toFixed(1));
#   set('s-alerts', s.alerts);
#   set('s-ips',    s.unique_ips);
#   set('s-pcap',   s.pcap_files);
#   set('p-tcp',    fmt(s.tcp));
#   set('p-udp',    fmt(s.udp));
#   set('p-icmp',   fmt(s.icmp));
#   set('p-arp',    fmt(s.arp));
#   set('p-dns',    fmt(s.dns));
#   set('p-other',  fmt(Math.max(0, s.total_packets - s.tcp - s.udp - s.icmp - s.arp - s.dns)));

#   const up = s.uptime_s;
#   const h = Math.floor(up/3600), m = Math.floor((up%3600)/60), sc = Math.floor(up%60);
#   set('uptime-label', `Uptime: ${h ? h+'h ' : ''}${m}m ${sc}s`);
#   set('iface-label',  `Interface: ${s.interface || '—'}`);

#   const ml = document.getElementById('ml-badge');
#   ml.textContent = s.ml_trained ? 'ML Active' : 'ML Training';
#   ml.className   = 'badge ' + (s.ml_trained ? 'badge-green' : 'badge-amber');

#   set('c-pkts',    fmt(s.total_packets));
#   set('c-pps-sub', s.pps.toFixed(1) + ' pkt/s');
#   set('c-alerts',  s.alerts);
#   set('c-ips',     s.unique_ips);
#   set('c-bytes',   fmtBytes(s.total_bytes));
#   set('c-bps-sub', s.bps_kb.toFixed(1) + ' KB/s');
#   set('pps-current', s.pps.toFixed(1) + ' pkt/s');
#   set('bps-current', s.bps_kb.toFixed(1) + ' KB/s');

#   const counts = s.alert_counts || {};
#   if (Object.keys(counts).length) {
#     chartAtk.data.labels = Object.keys(counts);
#     chartAtk.data.datasets[0].data = Object.values(counts);
#     chartAtk.update('none');
#   }

#   renderThreats(s.top_threats || []);
# });

# /* Timeline */
# socket.on('timeline_data', d => {
#   pushSpark(chartPPS,      d.labels, d.pps);
#   pushSpark(chartBPS,      d.labels, d.bps_kb);
#   pushSpark(chartTimeline, d.labels, d.alerts);
# });
# setInterval(() => {
#   fetch('/api/timeline').then(r => r.json()).then(d => {
#     pushSpark(chartPPS,      d.labels, d.pps);
#     pushSpark(chartBPS,      d.labels, d.bps_kb);
#     pushSpark(chartTimeline, d.labels, d.alerts);
#   }).catch(() => {});
# }, 2000);

# /* Alerts */
# socket.on('new_alert', a => {
#   alertCount++;
#   set('alert-count', alertCount + ' events');
#   prependAlert(a);
# });

# function prependAlert(a) {
#   const list = document.getElementById('alerts-list');
#   if (list.querySelector('.empty-state')) list.innerHTML = '';
#   const sev      = (a.severity || 'low').toLowerCase();
#   const rowCls   = sev === 'critical' ? '' : sev;
#   const sevCls   = 'sev-' + sev;
#   const ts       = new Date(a.timestamp).toLocaleTimeString();
#   const geo      = a.geo ? `${a.geo.city ? a.geo.city+', ' : ''}${a.geo.country || ''}` : '';
#   const score    = a.composite_score != null ? ` — Score: ${a.composite_score}` : '';
#   const desc     = a.details?.description || '';
#   const div = document.createElement('div');
#   div.className = 'alert-item ' + rowCls;
#   div.innerHTML = `
#     <span class="alert-ts">${ts}</span>
#     <div>
#       <div class="alert-type">${esc(a.attack_type)}</div>
#       <div class="alert-meta">${esc(a.src_ip)}${geo ? '  ·  '+esc(geo) : ''}${score}</div>
#       ${desc ? `<div class="alert-desc">${esc(desc)}</div>` : ''}
#     </div>
#     <span class="sev-pill ${sevCls}">${a.severity}</span>`;
#   list.insertBefore(div, list.firstChild);
#   while (list.children.length > 60) list.removeChild(list.lastChild);
# }

# function renderThreats(threats) {
#   const el = document.getElementById('threat-list');
#   if (!threats.length) {
#     el.innerHTML = '<p class="empty-state" style="padding:12px 0;font-size:11px">No threats scored yet</p>';
#     return;
#   }
#   el.innerHTML = threats.map(t => `
#     <div class="threat-item">
#       <div class="threat-header">
#         <span class="threat-ip">${t.ip}</span>
#         <span class="threat-score">${t.score.toFixed(0)}/100</span>
#       </div>
#       <div class="threat-track">
#         <div class="threat-fill" style="width:${Math.min(t.score,100)}%"></div>
#       </div>
#       <div class="threat-tags">${(t.tags||[]).slice(0,2).join(' · ')}</div>
#     </div>`).join('');
# }

# function set(id, val) { const e=document.getElementById(id); if(e) e.textContent=val; }
# function fmt(n) {
#   n = Number(n)||0;
#   if(n>=1e9) return (n/1e9).toFixed(1)+'G';
#   if(n>=1e6) return (n/1e6).toFixed(1)+'M';
#   if(n>=1e3) return (n/1e3).toFixed(1)+'K';
#   return n;
# }
# function fmtBytes(b) {
#   if(b>=1<<30) return (b/(1<<30)).toFixed(2)+' GB';
#   if(b>=1<<20) return (b/(1<<20)).toFixed(1)+' MB';
#   if(b>=1<<10) return Math.round(b/(1<<10))+' KB';
#   return b+' B';
# }
# function esc(s) {
#   return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
# }
# </script>
# </body>
# </html>
# """

# # ─────────────────────────────────────────────────────────────────────
# if __name__ == '__main__':
#     ap = argparse.ArgumentParser(description='Network IDS Dashboard v2.1')
#     ap.add_argument('-c', '--config',    default=None)
#     ap.add_argument('-i', '--interface', default=None)
#     ap.add_argument('-p', '--port',      type=int, default=5001)
#     ap.add_argument('--no-ids',          action='store_true')
#     args = ap.parse_args()

#     if not args.no_ids:
#         cfg = load_config(args.config)
#         if args.interface:
#             cfg['interface'] = args.interface
#         cfg['enable_api'] = False
#         ids_thread = threading.Thread(target=start_ids, args=(cfg,), daemon=True)
#         ids_thread.start()
#         time.sleep(2)

#     print(f"\n🌐  Dashboard  →  http://localhost:{args.port}")
#     print(f"   /api/stats | /api/alerts | /api/threats | /api/timeline")
#     print(f"   Press Ctrl+C to stop\n")

#     try:
#         socketio.run(app, host='0.0.0.0', port=args.port, debug=False, use_reloader=False)
#     except KeyboardInterrupt:
#         ids_running = False
#         if ids_instance:
#             ids_instance.stop()



"""
Advanced Network IDS — Web Dashboard v2.1
Fixed: _patch_ids_alerts now passes **kwargs so cooldown_key etc. work correctly.
"""

import threading
import time
import json
import os
import sys
import argparse
from datetime import datetime
from collections import defaultdict, deque
from typing import Optional

from flask import Flask, jsonify, request
from flask_socketio import SocketIO, emit

try:
    from network_ids_advanced import AdvancedNetworkIDS, load_config
except ImportError:
    print("❌  network_ids_advanced.py not found in the same directory.")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('IDS_SECRET', 'change-me-in-production')
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading',
                    logger=False, engineio_logger=False)

ids_instance: Optional[AdvancedNetworkIDS] = None
ids_running = False

TIMELINE_LEN = 120
timeline_lock    = threading.Lock()
timeline_pps:    deque = deque([0.0] * TIMELINE_LEN, maxlen=TIMELINE_LEN)
timeline_bps:    deque = deque([0.0] * TIMELINE_LEN, maxlen=TIMELINE_LEN)
timeline_alerts: deque = deque([0]   * TIMELINE_LEN, maxlen=TIMELINE_LEN)
timeline_labels: deque = deque(['']  * TIMELINE_LEN, maxlen=TIMELINE_LEN)

_last_pkt_count   = 0
_last_byte_count  = 0
_last_alert_count = 0
_last_tick_time   = time.time()


# ── Alert hook ────────────────────────────────────────────────────────
def _alert_hook(alert: dict):
    try:
        socketio.emit('new_alert', alert, namespace='/')
    except Exception:
        pass


def _patch_ids_alerts(ids: AdvancedNetworkIDS):
    """
    Wraps ids._alert so every NEW alert is broadcast to the dashboard exactly once.

    Key fix: snapshot len(ids.alerts) BEFORE calling _orig. If it grew by 1
    after the call, a real alert was appended and we emit it. If _orig returned
    early (cooldown suppressed it), len stays the same and we emit nothing.
    """
    _orig = ids._alert

    def patched(*args, **kwargs):
        count_before = len(ids.alerts)
        _orig(*args, **kwargs)
        # Only broadcast if a new alert was actually appended
        if len(ids.alerts) > count_before:
            _alert_hook(dict(ids.alerts[-1]))

    ids._alert = patched


# ── Background broadcaster ────────────────────────────────────────────
def _broadcaster():
    global _last_pkt_count, _last_byte_count, _last_alert_count, _last_tick_time

    while ids_running:
        time.sleep(1)
        if not ids_instance:
            continue

        now = time.time()
        dt  = max(now - _last_tick_time, 0.001)
        _last_tick_time = now

        s          = ids_instance.stats
        cur_pkts   = s['total_packets']
        cur_bytes  = s['total_bytes']
        cur_alerts = s['alerts']

        pps        = (cur_pkts  - _last_pkt_count)  / dt
        bps        = (cur_bytes - _last_byte_count)  / dt
        new_alerts = cur_alerts - _last_alert_count

        _last_pkt_count   = cur_pkts
        _last_byte_count  = cur_bytes
        _last_alert_count = cur_alerts

        with timeline_lock:
            timeline_pps.append(round(pps, 1))
            timeline_bps.append(round(bps / 1024, 1))
            timeline_alerts.append(new_alerts)
            timeline_labels.append(datetime.now().strftime('%H:%M:%S'))

        up = (datetime.now() - s['start_time']).total_seconds()
        payload = {
            'total_packets': s['total_packets'],
            'total_bytes':   s['total_bytes'],
            'alerts':        s['alerts'],
            'unique_ips':    len(ids_instance.connections),
            'tcp':  s['tcp'],  'udp': s['udp'],
            'icmp': s['icmp'], 'arp': s['arp'], 'dns': s['dns'],
            'pps':     round(pps, 1),
            'bps_kb':  round(bps / 1024, 1),
            'uptime_s':   round(up, 0),
            'ml_trained': ids_instance.ensemble.trained,
            'pcap_files': len(ids_instance.pcap_mgr.list_files()) + (1 if ids_instance.pcap_mgr._buf else 0),
            'interface':  ids_instance.interface,
            'alert_counts': dict(ids_instance.alert_counts),
            'top_threats': [
                {'ip': ip, 'score': round(sc, 1), 'tags': list(set(ev))[:3]}
                for ip, sc, ev in ids_instance.scoreboard.top_threats(5)
            ],
        }
        socketio.emit('stats_update', payload, namespace='/')


# ── REST API ──────────────────────────────────────────────────────────
def _ids_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not ids_instance:
            return jsonify({'error': 'IDS not running'}), 503
        return f(*args, **kwargs)
    return wrapper


@app.route('/')
def index():
    return DASHBOARD_HTML, 200, {'Content-Type': 'text/html'}


@app.route('/api/stats')
@_ids_required
def api_stats():
    s  = ids_instance.stats
    up = (datetime.now() - s['start_time']).total_seconds()
    return jsonify({
        **{k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in s.items()},
        'uptime_s':   round(up, 1),
        'unique_ips': len(ids_instance.connections),
        'ml_trained': ids_instance.ensemble.trained,
    })


@app.route('/api/alerts')
@_ids_required
def api_alerts():
    limit  = min(int(request.args.get('limit', 50)), 500)
    sev    = request.args.get('severity')
    alerts = list(ids_instance.alerts)
    if sev:
        alerts = [a for a in alerts if a.get('severity', '').lower() == sev.lower()]
    return jsonify(alerts[-limit:])


@app.route('/api/threats')
@_ids_required
def api_threats():
    n = int(request.args.get('n', 20))
    return jsonify([
        {'ip': ip, 'score': round(sc, 1),
         'evidence':   list(set(ev))[:10],
         'reputation': round(ids_instance.threat_intel.get_reputation(ip), 3),
         'geo':        ids_instance.threat_intel.geolocate(ip)}
        for ip, sc, ev in ids_instance.scoreboard.top_threats(n)
    ])


@app.route('/api/timeline')
def api_timeline():
    with timeline_lock:
        return jsonify({
            'labels': list(timeline_labels),
            'pps':    list(timeline_pps),
            'bps_kb': list(timeline_bps),
            'alerts': list(timeline_alerts),
        })


@app.route('/api/top_ips')
@_ids_required
def api_top_ips():
    n    = int(request.args.get('n', 10))
    rows = sorted(ids_instance.connections.items(),
                  key=lambda kv: kv[1]['pkt_count'], reverse=True)[:n]
    return jsonify([
        {'ip': ip, 'packets': c['pkt_count'], 'bytes': c['bytes'],
         'ports': len(c['ports']),
         'score': round(ids_instance.scoreboard.get_score(ip), 1),
         'geo':   ids_instance.threat_intel.geolocate(ip)}
        for ip, c in rows
    ])


@app.route('/api/alert_counts')
@_ids_required
def api_alert_counts():
    return jsonify(dict(ids_instance.alert_counts))


@app.route('/api/pcap_files')
@_ids_required
def api_pcap_files():
    files = ids_instance.pcap_mgr.list_files()
    return jsonify([
        {'name': os.path.basename(f),
         'size_kb': round(os.path.getsize(f) / 1024, 1), 'path': f}
        for f in files
    ])


@app.route('/api/health')
def api_health():
    return jsonify({'status': 'ok', 'ids_running': ids_running, 'version': '2.1.0'})


@app.route('/api/thresholds')
@_ids_required
def api_thresholds():
    return jsonify(ids_instance.adapt_thr.snapshot())


# ── SocketIO ──────────────────────────────────────────────────────────
@socketio.on('connect')
def on_connect():
    if ids_instance:
        emit('ids_status', {'running': ids_running, 'interface': ids_instance.interface})
        # Send the last 50 alerts so the feed is populated immediately on (re)connect
        recent = list(ids_instance.alerts)[-50:]
        for a in recent:
            emit('new_alert', dict(a))


@socketio.on('request_timeline')
def on_request_timeline():
    with timeline_lock:
        emit('timeline_data', {
            'labels': list(timeline_labels),
            'pps':    list(timeline_pps),
            'bps_kb': list(timeline_bps),
            'alerts': list(timeline_alerts),
        })


@socketio.on('request_top_threats')
def on_request_top_threats():
    if ids_instance:
        emit('top_threats', [
            {'ip': ip, 'score': round(sc, 1), 'tags': list(set(ev))[:3]}
            for ip, sc, ev in ids_instance.scoreboard.top_threats(10)
        ])


# ── IDS lifecycle ─────────────────────────────────────────────────────
def start_ids(cfg: dict):
    global ids_instance, ids_running
    ids_instance = AdvancedNetworkIDS(cfg)
    _patch_ids_alerts(ids_instance)
    ids_instance.start()
    ids_running = True
    threading.Thread(target=_broadcaster, daemon=True).start()
    print("✅  Dashboard broadcaster started")


# ─────────────────────────────────────────────────────────────────────
# DASHBOARD HTML
# ─────────────────────────────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network IDS Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg:         #f0f2f5;
    --surface:    #ffffff;
    --border:     #e2e6ea;
    --text:       #1a1d23;
    --text-muted: #6b7280;
    --primary:    #2563eb;
    --success:    #16a34a;
    --warning:    #d97706;
    --danger:     #dc2626;
    --info:       #0891b2;
    --radius:     10px;
    --shadow:     0 1px 3px rgba(0,0,0,.08), 0 1px 2px rgba(0,0,0,.05);
  }
  html, body { height: 100%; background: var(--bg); color: var(--text);
               font-family: 'Inter', system-ui, sans-serif; font-size: 14px; }
  .app { display: flex; flex-direction: column; min-height: 100vh; }

  /* Topbar */
  .topbar {
    background: var(--surface); border-bottom: 1px solid var(--border);
    padding: 0 24px; height: 56px;
    display: flex; align-items: center; justify-content: space-between;
    position: sticky; top: 0; z-index: 50; box-shadow: var(--shadow);
  }
  .topbar-logo { font-size: 16px; font-weight: 700; }
  .topbar-logo span { color: var(--primary); }
  .topbar-right { display: flex; align-items: center; gap: 16px; }
  .topbar-meta { font-size: 12px; color: var(--text-muted); }

  .badge { display:inline-flex; align-items:center; gap:5px; padding:3px 10px;
           border-radius:20px; font-size:11px; font-weight:600; }
  .badge-blue  { background:#eff6ff; color:var(--primary); border:1px solid #bfdbfe; }
  .badge-green { background:#f0fdf4; color:var(--success); border:1px solid #bbf7d0; }
  .badge-red   { background:#fef2f2; color:var(--danger);  border:1px solid #fecaca; }
  .badge-amber { background:#fffbeb; color:var(--warning); border:1px solid #fde68a; }

  .dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:4px; }
  .dot-green { background:var(--success); box-shadow:0 0 0 3px rgba(22,163,74,.15); }
  .dot-red   { background:var(--danger); }
  .dot-pulse { animation:pulse 2s ease infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.5} }

  /* Layout */
  .content { display:grid; grid-template-columns:240px 1fr; flex:1; }

  /* Sidebar */
  .sidebar { background:var(--surface); border-right:1px solid var(--border);
             padding:20px 16px; display:flex; flex-direction:column; gap:20px; overflow-y:auto; }
  .section-label { font-size:10px; font-weight:600; letter-spacing:.08em;
                   text-transform:uppercase; color:var(--text-muted); margin-bottom:12px; }
  .kpi-row { display:flex; justify-content:space-between; align-items:center;
             padding:6px 0; border-bottom:1px solid var(--border); }
  .kpi-row:last-child { border-bottom:none; }
  .kpi-label { font-size:12px; color:var(--text-muted); }
  .kpi-value { font-size:15px; font-weight:600; }
  .kpi-value.red   { color:var(--danger); }
  .kpi-value.green { color:var(--success); }
  .kpi-value.blue  { color:var(--primary); }

  .proto-grid { display:grid; grid-template-columns:1fr 1fr; gap:6px; }
  .proto-pill { background:var(--bg); border:1px solid var(--border); border-radius:8px;
                padding:8px 10px; text-align:center; }
  .proto-name  { font-size:10px; color:var(--text-muted); font-weight:500;
                 text-transform:uppercase; }
  .proto-value { font-size:16px; font-weight:700; margin-top:2px; }

  .threat-item  { margin-bottom:12px; }
  .threat-header { display:flex; justify-content:space-between; margin-bottom:4px; }
  .threat-ip    { font-size:12px; font-weight:500; font-family:monospace; }
  .threat-score { font-size:11px; font-weight:600; color:var(--danger); }
  .threat-track { height:5px; background:var(--border); border-radius:3px; overflow:hidden; }
  .threat-fill  { height:100%; border-radius:3px;
                  background:linear-gradient(90deg,var(--primary),var(--danger));
                  transition:width .5s ease; }
  .threat-tags  { font-size:10px; color:var(--text-muted); margin-top:3px; }

  /* Main */
  .main { padding:20px; display:flex; flex-direction:column; gap:16px; overflow-y:auto; }

  .chips { display:flex; gap:6px; flex-wrap:wrap; }
  .chip  { font-size:11px; font-weight:500; padding:4px 10px; border-radius:20px;
           border:1px solid var(--border); background:var(--surface); color:var(--text-muted);
           display:flex; align-items:center; gap:5px; }
  .chip.active { background:#f0fdf4; color:var(--success); border-color:#bbf7d0; }
  .chip-dot { width:6px; height:6px; border-radius:50%; background:currentColor; }

  .stat-cards { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; }
  .stat-card  { background:var(--surface); border:1px solid var(--border);
                border-radius:var(--radius); padding:16px 18px; box-shadow:var(--shadow); }
  .stat-card-label { font-size:11px; color:var(--text-muted); font-weight:500;
                     text-transform:uppercase; letter-spacing:.05em; margin-bottom:6px; }
  .stat-card-value { font-size:26px; font-weight:700; line-height:1; }
  .stat-card-value.danger  { color:var(--danger); }
  .stat-card-value.success { color:var(--success); }
  .stat-card-sub  { font-size:11px; color:var(--text-muted); margin-top:4px; }
  .stat-card-icon { float:right; font-size:20px; opacity:.5; }

  .panel { background:var(--surface); border:1px solid var(--border);
           border-radius:var(--radius); padding:16px 18px; box-shadow:var(--shadow); }
  .panel-header { display:flex; justify-content:space-between; align-items:center;
                  margin-bottom:14px; }
  .panel-title { font-size:13px; font-weight:600; }
  .panel-sub   { font-size:11px; color:var(--text-muted); }

  .charts-row { display:grid; grid-template-columns:1fr 1fr 1fr; gap:14px; }
  .chart-wrap { height:150px; position:relative; }

  .alerts-list { display:flex; flex-direction:column; gap:8px;
                 max-height:420px; overflow-y:auto; }
  .alerts-list::-webkit-scrollbar { width:4px; }
  .alerts-list::-webkit-scrollbar-thumb { background:var(--border); border-radius:2px; }

  .alert-item { display:grid; grid-template-columns:auto 1fr auto; gap:12px;
                align-items:start; padding:11px 14px; border-radius:8px;
                border:1px solid var(--border); border-left:3px solid var(--danger);
                background:#fff9f9; animation:fadeIn .3s ease; }
  .alert-item.high   { border-left-color:var(--warning); background:#fffdf5; }
  .alert-item.medium { border-left-color:var(--info);    background:#f5fbff; }
  .alert-item.low    { border-left-color:var(--success); background:#f6fef9; }
  @keyframes fadeIn { from{opacity:0;transform:translateY(-4px)} to{opacity:1;transform:none} }

  .alert-ts   { font-size:11px; color:var(--text-muted); white-space:nowrap;
                padding-top:1px; font-family:monospace; }
  .alert-type { font-size:13px; font-weight:600; margin-bottom:2px; }
  .alert-meta { font-size:11px; color:var(--text-muted); }
  .alert-desc { font-size:11px; color:var(--text-muted); margin-top:2px; font-style:italic; }

  .sev-pill { padding:2px 9px; border-radius:20px; font-size:10px;
              font-weight:700; letter-spacing:.04em; white-space:nowrap; align-self:start; }
  .sev-critical { background:#fef2f2; color:var(--danger);  border:1px solid #fecaca; }
  .sev-high     { background:#fffbeb; color:var(--warning); border:1px solid #fde68a; }
  .sev-medium   { background:#ecfeff; color:var(--info);    border:1px solid #a5f3fc; }
  .sev-low      { background:#f0fdf4; color:var(--success); border:1px solid #bbf7d0; }

  .empty-state { text-align:center; padding:40px; color:var(--text-muted); font-size:13px; }
  ::-webkit-scrollbar { width:5px; }
  ::-webkit-scrollbar-thumb { background:var(--border); border-radius:4px; }
</style>
</head>
<body>
<div class="app">

  <header class="topbar">
    <div style="display:flex;align-items:center;gap:12px">
      <div class="topbar-logo">Network <span>IDS</span></div>
      <span class="badge badge-red" id="conn-badge">
        <span class="dot dot-red" id="conn-dot"></span>Connecting…
      </span>
    </div>
    <div class="topbar-right">
      <span class="topbar-meta" id="iface-label">Interface: —</span>
      <span class="topbar-meta" id="uptime-label">Uptime: 0s</span>
      <span class="badge badge-red" id="ml-badge">ML Training</span>
    </div>
  </header>

  <div class="content">

    <aside class="sidebar">
      <div>
        <div class="section-label">Traffic</div>
        <div class="kpi-row"><span class="kpi-label">Packets</span>  <span class="kpi-value" id="s-pkts">0</span></div>
        <div class="kpi-row"><span class="kpi-label">Bytes</span>    <span class="kpi-value" id="s-bytes">0 B</span></div>
        <div class="kpi-row"><span class="kpi-label">Pkt/sec</span>  <span class="kpi-value green" id="s-pps">0</span></div>
        <div class="kpi-row"><span class="kpi-label">KB/s</span>     <span class="kpi-value blue" id="s-bps">0</span></div>
      </div>
      <div>
        <div class="section-label">Detection</div>
        <div class="kpi-row"><span class="kpi-label">Alerts</span>     <span class="kpi-value red" id="s-alerts">0</span></div>
        <div class="kpi-row"><span class="kpi-label">Unique IPs</span> <span class="kpi-value" id="s-ips">0</span></div>
        <div class="kpi-row"><span class="kpi-label">PCAP Files</span> <span class="kpi-value" id="s-pcap">0</span></div>
      </div>
      <div>
        <div class="section-label">Protocols</div>
        <div class="proto-grid">
          <div class="proto-pill"><div class="proto-name">TCP</div>  <div class="proto-value" id="p-tcp">0</div></div>
          <div class="proto-pill"><div class="proto-name">UDP</div>  <div class="proto-value" id="p-udp">0</div></div>
          <div class="proto-pill"><div class="proto-name">ICMP</div> <div class="proto-value" id="p-icmp">0</div></div>
          <div class="proto-pill"><div class="proto-name">ARP</div>  <div class="proto-value" id="p-arp">0</div></div>
          <div class="proto-pill"><div class="proto-name">DNS</div>  <div class="proto-value" id="p-dns">0</div></div>
          <div class="proto-pill"><div class="proto-name">Other</div><div class="proto-value" id="p-other">0</div></div>
        </div>
      </div>
      <div style="flex:1">
        <div class="section-label">Top Threat IPs</div>
        <div id="threat-list"><p class="empty-state" style="padding:16px 0;font-size:11px">No threats yet</p></div>
      </div>
    </aside>

    <main class="main">

      <div class="chips">
        <div class="chip active"><span class="chip-dot"></span> Signatures</div>
        <div class="chip active"><span class="chip-dot"></span> ML Ensemble</div>
        <div class="chip active"><span class="chip-dot"></span> UEBA</div>
        <div class="chip active"><span class="chip-dot"></span> Beaconing</div>
        <div class="chip active"><span class="chip-dot"></span> DNS Analysis</div>
        <div class="chip active"><span class="chip-dot"></span> ARP Spoof</div>
        <div class="chip active"><span class="chip-dot"></span> Threat Intel</div>
      </div>

      <div class="stat-cards">
        <div class="stat-card">
          <div class="stat-card-icon">📦</div>
          <div class="stat-card-label">Total Packets</div>
          <div class="stat-card-value" id="c-pkts">0</div>
          <div class="stat-card-sub" id="c-pps-sub">0 pkt/s</div>
        </div>
        <div class="stat-card">
          <div class="stat-card-icon">🚨</div>
          <div class="stat-card-label">Alerts</div>
          <div class="stat-card-value danger" id="c-alerts">0</div>
          <div class="stat-card-sub" id="c-alert-sub">none yet</div>
        </div>
        <div class="stat-card">
          <div class="stat-card-icon">🌐</div>
          <div class="stat-card-label">Unique IPs</div>
          <div class="stat-card-value" id="c-ips">0</div>
          <div class="stat-card-sub">tracked hosts</div>
        </div>
        <div class="stat-card">
          <div class="stat-card-icon">💾</div>
          <div class="stat-card-label">Data Processed</div>
          <div class="stat-card-value" id="c-bytes">0 B</div>
          <div class="stat-card-sub" id="c-bps-sub">0 KB/s</div>
        </div>
      </div>

      <div class="charts-row">
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">Packets / sec</span>
            <span class="panel-sub" id="pps-current">0</span>
          </div>
          <div class="chart-wrap"><canvas id="ch-pps"></canvas></div>
        </div>
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">Bandwidth (KB/s)</span>
            <span class="panel-sub" id="bps-current">0</span>
          </div>
          <div class="chart-wrap"><canvas id="ch-bps"></canvas></div>
        </div>
        <div class="panel">
          <div class="panel-header"><span class="panel-title">Attack Distribution</span></div>
          <div class="chart-wrap"><canvas id="ch-atk"></canvas></div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Alert Timeline</span>
          <span class="panel-sub">last 120s</span>
        </div>
        <div style="height:90px;position:relative"><canvas id="ch-timeline"></canvas></div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Alert Feed</span>
          <span class="panel-sub" id="alert-count">0 events</span>
        </div>
        <div class="alerts-list" id="alerts-list">
          <div class="empty-state">Monitoring… no alerts yet.</div>
        </div>
      </div>

    </main>
  </div>
</div>

<script>
const socket = io();
let alertCount = 0;

socket.on('connect',    () => setConn(true));
socket.on('disconnect', () => setConn(false));
socket.on('connect', () => socket.emit('request_timeline'));

function setConn(on) {
  const b = document.getElementById('conn-badge');
  const d = document.getElementById('conn-dot');
  b.textContent = on ? '● Live' : '● Disconnected';
  b.className   = 'badge ' + (on ? 'badge-green' : 'badge-red');
  d.className   = 'dot ' + (on ? 'dot-green dot-pulse' : 'dot-red');
}

/* Charts */
const BLUE  = '#2563eb', GREEN = '#16a34a', RED = '#dc2626',
      AMBER = '#d97706', GRID  = 'rgba(0,0,0,.06)', TICK = '#9ca3af';
Chart.defaults.font.family = "'Inter', system-ui, sans-serif";
Chart.defaults.font.size   = 11;
Chart.defaults.color       = TICK;

function makeSparkline(id, color) {
  return new Chart(document.getElementById(id), {
    type: 'line',
    data: { labels: [], datasets: [{ data: [], borderColor: color,
      borderWidth: 2, backgroundColor: color + '18', tension: 0.4,
      fill: true, pointRadius: 0 }] },
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { display: false },
        y: { beginAtZero: true, grid: { color: GRID },
             ticks: { maxTicksLimit: 4, color: TICK } }
      }
    }
  });
}

const chartPPS      = makeSparkline('ch-pps',      BLUE);
const chartBPS      = makeSparkline('ch-bps',      GREEN);
const chartTimeline = makeSparkline('ch-timeline', RED);

const chartAtk = new Chart(document.getElementById('ch-atk'), {
  type: 'doughnut',
  data: { labels: [], datasets: [{ data: [], borderWidth: 2, borderColor: '#fff',
    backgroundColor: [RED, AMBER, BLUE, GREEN, '#8b5cf6','#06b6d4','#f59e0b','#6b7280'] }] },
  options: {
    responsive: true, maintainAspectRatio: false, animation: false, cutout: '60%',
    plugins: { legend: { position: 'right',
      labels: { color: '#374151', boxWidth: 10, font: { size: 10 } } } }
  }
});

function pushSpark(chart, labels, data) {
  chart.data.labels = labels;
  chart.data.datasets[0].data = data;
  chart.update('none');
}

/* Stats */
socket.on('stats_update', s => {
  set('s-pkts',   fmt(s.total_packets));
  set('s-bytes',  fmtBytes(s.total_bytes));
  set('s-pps',    s.pps.toFixed(1));
  set('s-bps',    s.bps_kb.toFixed(1));
  set('s-alerts', s.alerts);
  set('s-ips',    s.unique_ips);
  set('s-pcap',   s.pcap_files);
  set('p-tcp',    fmt(s.tcp));
  set('p-udp',    fmt(s.udp));
  set('p-icmp',   fmt(s.icmp));
  set('p-arp',    fmt(s.arp));
  set('p-dns',    fmt(s.dns));
  set('p-other',  fmt(Math.max(0, s.total_packets - s.tcp - s.udp - s.icmp - s.arp - s.dns)));

  const up = s.uptime_s;
  const h = Math.floor(up/3600), m = Math.floor((up%3600)/60), sc = Math.floor(up%60);
  set('uptime-label', `Uptime: ${h ? h+'h ' : ''}${m}m ${sc}s`);
  set('iface-label',  `Interface: ${s.interface || '—'}`);

  const ml = document.getElementById('ml-badge');
  ml.textContent = s.ml_trained ? 'ML Active' : 'ML Training';
  ml.className   = 'badge ' + (s.ml_trained ? 'badge-green' : 'badge-amber');

  set('c-pkts',    fmt(s.total_packets));
  set('c-pps-sub', s.pps.toFixed(1) + ' pkt/s');
  set('c-alerts',  s.alerts);
  set('c-ips',     s.unique_ips);
  set('c-bytes',   fmtBytes(s.total_bytes));
  set('c-bps-sub', s.bps_kb.toFixed(1) + ' KB/s');
  set('pps-current', s.pps.toFixed(1) + ' pkt/s');
  set('bps-current', s.bps_kb.toFixed(1) + ' KB/s');

  const counts = s.alert_counts || {};
  if (Object.keys(counts).length) {
    chartAtk.data.labels = Object.keys(counts);
    chartAtk.data.datasets[0].data = Object.values(counts);
    chartAtk.update('none');
  }

  renderThreats(s.top_threats || []);
});

/* Timeline */
socket.on('timeline_data', d => {
  pushSpark(chartPPS,      d.labels, d.pps);
  pushSpark(chartBPS,      d.labels, d.bps_kb);
  pushSpark(chartTimeline, d.labels, d.alerts);
});
setInterval(() => {
  fetch('/api/timeline').then(r => r.json()).then(d => {
    pushSpark(chartPPS,      d.labels, d.pps);
    pushSpark(chartBPS,      d.labels, d.bps_kb);
    pushSpark(chartTimeline, d.labels, d.alerts);
  }).catch(() => {});
}, 2000);

/* Alerts */
socket.on('new_alert', a => {
  alertCount++;
  set('alert-count', alertCount + ' events');
  prependAlert(a);
});

function prependAlert(a) {
  const list = document.getElementById('alerts-list');
  if (list.querySelector('.empty-state')) list.innerHTML = '';
  const sev      = (a.severity || 'low').toLowerCase();
  const rowCls   = sev === 'critical' ? '' : sev;
  const sevCls   = 'sev-' + sev;
  const ts       = new Date(a.timestamp).toLocaleTimeString();
  const geo      = a.geo ? `${a.geo.city ? a.geo.city+', ' : ''}${a.geo.country || ''}` : '';
  const score    = a.composite_score != null ? ` — Score: ${a.composite_score}` : '';
  const desc     = a.details?.description || '';
  const div = document.createElement('div');
  div.className = 'alert-item ' + rowCls;
  div.innerHTML = `
    <span class="alert-ts">${ts}</span>
    <div>
      <div class="alert-type">${esc(a.attack_type)}</div>
      <div class="alert-meta">${esc(a.src_ip)}${geo ? '  ·  '+esc(geo) : ''}${score}</div>
      ${desc ? `<div class="alert-desc">${esc(desc)}</div>` : ''}
    </div>
    <span class="sev-pill ${sevCls}">${a.severity}</span>`;
  list.insertBefore(div, list.firstChild);
  while (list.children.length > 60) list.removeChild(list.lastChild);
}

function renderThreats(threats) {
  const el = document.getElementById('threat-list');
  if (!threats.length) {
    el.innerHTML = '<p class="empty-state" style="padding:12px 0;font-size:11px">No threats scored yet</p>';
    return;
  }
  el.innerHTML = threats.map(t => `
    <div class="threat-item">
      <div class="threat-header">
        <span class="threat-ip">${t.ip}</span>
        <span class="threat-score">${t.score.toFixed(0)}/100</span>
      </div>
      <div class="threat-track">
        <div class="threat-fill" style="width:${Math.min(t.score,100)}%"></div>
      </div>
      <div class="threat-tags">${(t.tags||[]).slice(0,2).join(' · ')}</div>
    </div>`).join('');
}

function set(id, val) { const e=document.getElementById(id); if(e) e.textContent=val; }
function fmt(n) {
  n = Number(n)||0;
  if(n>=1e9) return (n/1e9).toFixed(1)+'G';
  if(n>=1e6) return (n/1e6).toFixed(1)+'M';
  if(n>=1e3) return (n/1e3).toFixed(1)+'K';
  return n;
}
function fmtBytes(b) {
  if(b>=1<<30) return (b/(1<<30)).toFixed(2)+' GB';
  if(b>=1<<20) return (b/(1<<20)).toFixed(1)+' MB';
  if(b>=1<<10) return Math.round(b/(1<<10))+' KB';
  return b+' B';
}
function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
</script>
</body>
</html>
"""

# ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Network IDS Dashboard v2.1')
    ap.add_argument('-c', '--config',    default=None)
    ap.add_argument('-i', '--interface', default=None)
    ap.add_argument('-p', '--port',      type=int, default=5001)
    ap.add_argument('--no-ids',          action='store_true')
    args = ap.parse_args()

    if not args.no_ids:
        cfg = load_config(args.config)
        if args.interface:
            cfg['interface'] = args.interface
        cfg['enable_api'] = False
        ids_thread = threading.Thread(target=start_ids, args=(cfg,), daemon=True)
        ids_thread.start()
        time.sleep(2)

    print(f"\n🌐  Dashboard  →  http://localhost:{args.port}")
    print(f"   /api/stats | /api/alerts | /api/threats | /api/timeline")
    print(f"   Press Ctrl+C to stop\n")

    try:
        socketio.run(app, host='0.0.0.0', port=args.port, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        ids_running = False
        if ids_instance:
            ids_instance.stop()

