// Network Security Dashboard JavaScript

let currentPage = 'overview';

// Toast notification
function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast ${type} show`;
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

// Page navigation
function showPage(pageName) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    
    // Remove active from all nav buttons
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show selected page
    document.getElementById(`page-${pageName}`).classList.add('active');
    
    // Set active nav button
    event.target.classList.add('active');
    
    currentPage = pageName;
    
    // Refresh data for the page
    if (pageName === 'network-map') {
        refreshNetworkMap();
    } else if (pageName === 'monitor') {
        refreshMonitorStatus();
    } else if (pageName === 'devices') {
        refreshDevices();
    } else if (pageName === 'beelzebub') {
        refreshBeelzebubStats();
        refreshReroutes();  // Also refresh isolated devices list
    } else if (pageName === 'logs') {
        refreshDeviceData();
    }
}

// Refresh all data
function refreshAll() {
    refreshStatus();
    refreshDevices();
    refreshDeviceRegistry();
    showToast('Refreshed all data', 'success');
}

// Refresh status
async function refreshStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();

        // Update network status
        const networkStatus = document.getElementById('network-status');
        if (data.network.exists) {
            networkStatus.textContent = 'ON';
            networkStatus.className = 'status-badge status-on';
            document.getElementById('stat-network').textContent = 'ON';
        } else {
            networkStatus.textContent = 'OFF';
            networkStatus.className = 'status-badge status-off';
            document.getElementById('stat-network').textContent = 'OFF';
        }

        // Update device count
        document.getElementById('stat-devices').textContent = data.devices.count;
        document.getElementById('device-count-badge').textContent = `${data.devices.count} Devices`;

        // Update Beelzebub
        const beelzebubStatus = document.getElementById('beelzebub-status');
        if (data.beelzebub.running) {
            beelzebubStatus.textContent = 'RUNNING';
            beelzebubStatus.className = 'status-badge status-on';
            document.getElementById('stat-beelzebub').textContent = 'ON';
        } else {
            beelzebubStatus.textContent = 'OFF';
            beelzebubStatus.className = 'status-badge status-off';
            document.getElementById('stat-beelzebub').textContent = 'OFF';
        }

        // Update DOS attacker status
        const attackerStatus = document.getElementById('attacker-status');
        if (attackerStatus) {
            if (data.attackers.dos_running) {
                attackerStatus.textContent = 'ON';
                attackerStatus.className = 'status-badge status-on';
            } else {
                attackerStatus.textContent = 'OFF';
                attackerStatus.className = 'status-badge status-off';
            }
        }

        // Update SSH attacker status
        const sshAttackerStatus = document.getElementById('ssh-attacker-status');
        if (sshAttackerStatus) {
            if (data.attackers.ssh_running) {
                sshAttackerStatus.textContent = 'ON';
                sshAttackerStatus.className = 'status-badge status-on';
            } else {
                sshAttackerStatus.textContent = 'OFF';
                sshAttackerStatus.className = 'status-badge status-off';
            }
        }

        // Update malware attacker status
        const malwareAttackerStatus = document.getElementById('malware-attacker-status');
        if (malwareAttackerStatus) {
            if (data.attackers.malware_running) {
                malwareAttackerStatus.textContent = 'ACTIVE';
                malwareAttackerStatus.className = 'status-badge status-on';
            } else {
                malwareAttackerStatus.textContent = 'OFF';
                malwareAttackerStatus.className = 'status-badge status-off';
            }
        }

        // Update container count
        document.getElementById('stat-containers').textContent = data.all_containers.length;

        // Update monitor status
        const monitorStatus = document.getElementById('monitor-status');
        if (data.monitor && data.monitor.running) {
            monitorStatus.textContent = 'RUNNING';
            monitorStatus.className = 'status-badge status-on';
            document.getElementById('stat-monitor').textContent = 'ON';
        } else {
            monitorStatus.textContent = 'OFF';
            monitorStatus.className = 'status-badge status-off';
            document.getElementById('stat-monitor').textContent = 'OFF';
        }

    } catch (error) {
        console.error('Error refreshing status:', error);
    }
}

// Network control
async function createNetwork() {
    showToast('Creating network...', 'success');
    try {
        const response = await fetch('/api/network/create', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        refreshStatus();
    } catch (error) {
        showToast('Error creating network', 'error');
    }
}

async function deleteNetwork() {
    if (!confirm('Delete network? This will stop all containers!')) return;
    showToast('Deleting network...', 'success');
    try {
        const response = await fetch('/api/network/delete', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        refreshStatus();
        refreshDevices();
    } catch (error) {
        showToast('Error deleting network', 'error');
    }
}

// Device management
async function refreshDevices() {
    try {
        // Use /api/status to get per-network device information
        const response = await fetch('/api/status');
        const data = await response.json();

        const container = document.getElementById('devices-container');

        // Build professional production and Beelzebub sections
        const prod = data.production_devices || data.production_devices === undefined ? (data.production_devices || []) : [];
        const beelzebub = data.beelzebub && data.beelzebub.devices ? data.beelzebub.devices : (data.honeypot_devices || []);

        let html = '';
        html += `<div class="grid">`;

        // Production Network Column
        html += `<div class="card">
                    <div class="card-header">
                        <div class="card-title">Production Network — custom_net (192.168.6.0/24)</div>
                        <span class="status-badge">${prod.length} Nodes</span>
                    </div>
                    <div style="padding: 15px;">
                        <div class="device-grid">`;

        if (prod.length === 0) {
            html += `<div style="color: #6b7280; padding: 20px;">No active devices on production network</div>`;
        } else {
            prod.forEach((d, idx) => {
                const name = d.name || 'Device';
                const ip = d.ip || 'N/A';
                html += `
                    <div class="device-card">
                        <div class="device-header">
                            <div>
                                <div class="device-name">� ${escapeHtml(name)}</div>
                                <div class="device-type">IP: ${ip}</div>
                            </div>
                        </div>
                        <div class="device-info">
                            <div><strong>Status:</strong> ${escapeHtml(d.status || 'Unknown')}</div>
                            <div><strong>Image:</strong> ${escapeHtml(d.image || 'N/A')}</div>
                            <div><strong>Networks:</strong> ${escapeHtml((d.networks || []).join(', ') || 'N/A')}</div>
                        </div>
                        <div class="device-actions">
                            <button class="btn btn-danger btn-small" onclick="deleteDevice('${escapeHtml(name)}')">Delete</button>
                        </div>
                    </div>`;
            });
        }

        html += `</div></div></div>`;

        // Beelzebub Column
        html += `<div class="card">
                    <div class="card-header">
                        <div class="card-title">Beelzebub Network — honeypot_net (192.168.7.0/24)</div>
                        <span class="status-badge">${beelzebub.length} Isolated</span>
                    </div>
                    <div style="padding: 15px;">
                        <div class="device-grid">`;

        if (beelzebub.length === 0) {
            html += `<div style="color: #6b7280; padding: 20px;">No devices currently isolated</div>`;
        } else {
            beelzebub.forEach((d, idx) => {
                const name = d.name || 'Isolated Device';
                const ip = d.ip || 'N/A';
                html += `
                    <div class="device-card" style="border-left: 4px solid #fb923c;">
                        <div class="device-header">
                            <div>
                                <div class="device-name">${escapeHtml(name)}</div>
                                <div class="device-type">Isolated</div>
                            </div>
                        </div>
                        <div class="device-info">
                            <div><strong>IP:</strong> ${ip}</div>
                            <div><strong>Status:</strong> ${escapeHtml(d.status || 'Unknown')}</div>
                            <div><strong>Image:</strong> ${escapeHtml(d.image || 'N/A')}</div>
                        </div>
                        <div class="device-actions">
                            <button class="btn btn-success btn-small" onclick="restoreDevice('${escapeHtml(d.name)}')">Restore to Network</button>
                        </div>
                    </div>`;
            });
        }

        html += `</div></div></div>`;

        html += `</div>`; // grid

        container.innerHTML = html;

        refreshStatus();
    } catch (error) {
        showToast('Error loading devices', 'error');
    }
}

async function createDevice() {
    const deviceType = document.getElementById('device-type').value;
    showToast('Creating device... (this may take a moment)', 'success');
    try {
        const response = await fetch('/api/devices/create', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: deviceType })
        });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        if (data.success) {
            setTimeout(refreshDevices, 2000);
        }
    } catch (error) {
        showToast('Error creating device', 'error');
    }
}

async function deleteDevice(deviceId) {
    if (!confirm(`Delete device_${deviceId}?`)) return;
    showToast('Deleting device...', 'success');
    try {
        const response = await fetch(`/api/devices/delete/${deviceId}`, {
            method: 'DELETE'
        });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        refreshDevices();
    } catch (error) {
        showToast('Error deleting device', 'error');
    }
}

async function cleanupDevices() {
    showToast('Cleaning up stopped containers...', 'success');
    try {
        const response = await fetch('/api/devices/cleanup', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, 'success');
        refreshDevices();
    } catch (error) {
        showToast('Error during cleanup', 'error');
    }
}

// Restore an isolated honeypot device back to production network
async function restoreDevice(containerName) {
    if (!confirm(`Restore ${containerName} to production network?`)) return;
    showToast(`Restoring ${containerName}...`, 'success');
    try {
        const response = await fetch('/api/beelzebub/remove_reroute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ container_name: containerName })
        });
        const data = await response.json();
        if (data.success) {
            showToast(data.message || 'Restored', 'success');
            setTimeout(() => {
                refreshDevices();
                refreshStatus();
            }, 1000);
        } else {
            showToast(data.message || 'Failed to restore', 'error');
        }
    } catch (error) {
        console.error('Error restoring device:', error);
        showToast('Error restoring device', 'error');
    }
}

async function viewDeviceLogs(deviceName) {
    try {
        const response = await fetch(`/api/containers/logs/${deviceName}`);
        const data = await response.json();
        
        if (data.success) {
            alert(`Logs for ${deviceName}:\n\n${data.logs}`);
        } else {
            showToast('Error loading logs', 'error');
        }
    } catch (error) {
        showToast('Error loading logs', 'error');
    }
}

// Device Registry
async function refreshDeviceRegistry() {
    try {
        const response = await fetch('/api/devices/registry');
        const data = await response.json();
        
        document.getElementById('stat-registered').textContent = data.count;
    } catch (error) {
        console.error('Error loading device registry:', error);
    }
}

// Device Data
async function refreshDeviceData() {
    try {
        const response = await fetch('/api/devices/data/latest?count=50');
        const data = await response.json();
        
        const tbody = document.getElementById('device-data-body');
        
        if (data.data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 40px;">No device data yet. Devices will appear here once they start sending data.</td></tr>';
            return;
        }

        tbody.innerHTML = data.data.reverse().map(entry => {
            const time = new Date(entry.timestamp).toLocaleTimeString();
            const sensorData = JSON.stringify(entry.sensor_data).substring(0, 100);
            return `
                <tr>
                    <td>${time}</td>
                    <td>${entry.device_id}</td>
                    <td>${entry.device_type}</td>
                    <td>${entry.ip_address}</td>
                    <td style="font-family: monospace; font-size: 0.85em;">${sensorData}...</td>
                </tr>
            `;
        }).join('');

    } catch (error) {
        console.error('Error loading device data:', error);
    }
}

// Beelzebub control
async function startBeelzebub() {
    showToast('Starting Beelzebub...', 'success');
    try {
        const response = await fetch('/api/beelzebub/start', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        setTimeout(refreshStatus, 2000);
    } catch (error) {
        showToast('Error starting Beelzebub', 'error');
    }
}

async function stopBeelzebub() {
    showToast('Stopping Beelzebub...', 'success');
    try {
        const response = await fetch('/api/beelzebub/stop', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        setTimeout(refreshStatus, 2000);
    } catch (error) {
        showToast('Error stopping Beelzebub', 'error');
    }
}

async function viewBeelzebubLogs() {
    try {
        const response = await fetch('/api/beelzebub/logs');
        const data = await response.json();
        
        const logsDisplay = document.getElementById('beelzebub-logs');
        
        if (!data.success) {
            logsDisplay.innerHTML = `<div class="log-entry" style="color: #f87171;">Error: ${data.message || data.error || 'Failed to load logs'}</div>`;
            return;
        }
        
        if (data.logs.length === 0) {
            logsDisplay.innerHTML = `<div class="log-entry">${data.message || 'No attacker interactions logged yet. Waiting for attacks...'}</div>`;
            return;
        }

        // Display Beelzebub logs with proper formatting
        logsDisplay.innerHTML = data.logs.map(log => {
            // Check if it's a raw text log or JSON structured log
            if (log.raw) {
                return `
                    <div class="log-entry">
                        <span style="color: #94a3b8;">${log.time || ''}</span> | 
                        <span style="color: #cbd5e1;">${escapeHtml(log.msg || '')}</span>
                    </div>
                `;
            }
            
            // Format JSON log entry
            const time = log.time || log.timestamp || 'N/A';
            const level = log.level || 'info';
            const message = log.msg || log.message || '';
            const port = log.port || '';
            const commands = log.commands !== undefined ? log.commands : '';
            const banner = log.banner || '';
            
            // Color based on log level
            let levelColor = '#60a5fa'; // blue for info
            if (level === 'error') levelColor = '#f87171'; // red
            if (level === 'warn') levelColor = '#fbbf24'; // yellow
            if (level === 'debug') levelColor = '#94a3b8'; // gray
            
            return `
                <div class="log-entry">
                    <span style="color: #94a3b8;">${time}</span> | 
                    <span style="color: ${levelColor}; font-weight: bold;">[${level.toUpperCase()}]</span> |
                    <span style="color: #cbd5e1;">${escapeHtml(message)}</span>
                    ${port ? `<span style="color: #fbbf24;"> | Port: ${port}</span>` : ''}
                    ${commands !== '' ? `<span style="color: #8b5cf6;"> | Commands: ${commands}</span>` : ''}
                    ${banner ? `<span style="color: #10b981;"> | Banner: ${banner}</span>` : ''}
                </div>
            `;
        }).join('');
        
        // Auto-scroll to bottom to show latest logs
        logsDisplay.scrollTop = logsDisplay.scrollHeight;
        
    } catch (error) {
        const logsDisplay = document.getElementById('beelzebub-logs');
        logsDisplay.innerHTML = `<div class="log-entry" style="color: #f87171;">Error loading logs: ${error.message}</div>`;
        console.error('Error loading Beelzebub logs:', error);
    }
}

async function refreshBeelzebubStats() {
    try {
        const response = await fetch('/api/beelzebub/stats');
        const data = await response.json();
        
        // Update interaction count
        document.getElementById('beelzebub-interactions').textContent = 
            `${data.total_interactions} Interactions`;
        
        // Update services count
        document.getElementById('beelzebub-services-count').textContent = 
            `${data.services.length} Active`;
        
        // Update status badge
        const statusBadge = document.getElementById('beelzebub-status');
        if (data.running) {
            statusBadge.textContent = 'RUNNING';
            statusBadge.className = 'status-badge status-on';
        } else {
            statusBadge.textContent = 'OFF';
            statusBadge.className = 'status-badge status-off';
        }
        
        // Refresh logs
        viewBeelzebubLogs();
        
        // Refresh attacker details
        refreshAttackerDetails();
        
    } catch (error) {
        showToast('Error refreshing Beelzebub stats', 'error');
    }
}

// Attacker Details - Comprehensive Tracking
async function refreshAttackerDetails() {
    try {
        const response = await fetch('/api/beelzebub/attackers');
        const data = await response.json();
        
        // Update stat counters
        document.getElementById('attacker-total-attacks').textContent = data.total_attacks || 0;
        document.getElementById('attacker-unique-ips').textContent = data.unique_ips || 0;
        document.getElementById('attacker-credentials').textContent = data.credentials_tried.length || 0;
        document.getElementById('attacker-commands').textContent = data.commands_executed.length || 0;
        
        // Display all sections
        displayAttackersList(data.attackers || []);
        displayCredentialsList(data.credentials_tried || []);
        displayCommandsList(data.commands_executed || []);
        displayHttpRequestsList(data.http_requests || []);
        
    } catch (error) {
        console.error('Error refreshing attacker details:', error);
        // Set fallback values
        document.getElementById('attacker-total-attacks').textContent = '0';
        document.getElementById('attacker-unique-ips').textContent = '0';
        document.getElementById('attacker-credentials').textContent = '0';
        document.getElementById('attacker-commands').textContent = '0';
    }
}

function displayAttackersList(attackers) {
    const container = document.getElementById('attacker-list');
    
    if (!attackers || attackers.length === 0) {
        container.innerHTML = `
            <div style="padding: 20px; text-align: center; color: #888;">
                <i class="fas fa-info-circle" style="font-size: 2em; margin-bottom: 10px;"></i>
                <p>No attackers detected yet</p>
                <p style="font-size: 0.9em; margin-top: 5px;">Attack data will appear here when honeypot detects activity</p>
            </div>
        `;
        return;
    }
    
    let html = '';
    attackers.forEach(attacker => {
        const protocols = attacker.protocols.join(', ') || 'Unknown';
        const ports = attacker.ports.join(', ') || 'N/A';
        const firstSeen = new Date(attacker.first_seen).toLocaleString();
        const lastSeen = new Date(attacker.last_seen).toLocaleString();
        
        html += `
            <div style="background: rgba(255,255,255,0.05); border-left: 3px solid #e74c3c; padding: 15px; margin-bottom: 10px; border-radius: 4px;">
                <div style="display: flex; justify-content: space-between; align-items: start;">
                    <div style="flex: 1;">
                        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                            <i class="fas fa-skull-crossbones" style="color: #e74c3c;"></i>
                            <strong style="font-size: 1.1em; color: #e74c3c;">${attacker.ip}</strong>
                            <span style="background: rgba(231, 76, 60, 0.2); color: #e74c3c; padding: 2px 8px; border-radius: 3px; font-size: 0.85em;">
                                ${attacker.total_interactions} interactions
                            </span>
                        </div>
                        <div style="margin-left: 30px; color: #ccc; font-size: 0.9em;">
                            <div style="margin-bottom: 5px;">
                                <i class="fas fa-network-wired" style="width: 16px; color: #3498db;"></i>
                                <strong>Protocols:</strong> ${protocols}
                            </div>
                            <div style="margin-bottom: 5px;">
                                <i class="fas fa-plug" style="width: 16px; color: #9b59b6;"></i>
                                <strong>Ports:</strong> ${ports}
                            </div>
                            <div style="margin-bottom: 5px;">
                                <i class="fas fa-clock" style="width: 16px; color: #95a5a6;"></i>
                                <strong>First Seen:</strong> ${firstSeen}
                            </div>
                            <div>
                                <i class="fas fa-clock" style="width: 16px; color: #95a5a6;"></i>
                                <strong>Last Seen:</strong> ${lastSeen}
                            </div>
                        </div>
                    </div>
                </div>
                ${attacker.credentials && attacker.credentials.length > 0 ? `
                    <div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid rgba(255,255,255,0.1);">
                        <div style="font-size: 0.85em; color: #f39c12;">
                            <i class="fas fa-key"></i> Tried credentials: ${attacker.credentials.length}
                        </div>
                    </div>
                ` : ''}
                ${attacker.commands && attacker.commands.length > 0 ? `
                    <div style="margin-top: 5px;">
                        <div style="font-size: 0.85em; color: #e67e22;">
                            <i class="fas fa-terminal"></i> Executed commands: ${attacker.commands.length}
                        </div>
                    </div>
                ` : ''}
                ${attacker.http_requests && attacker.http_requests.length > 0 ? `
                    <div style="margin-top: 5px;">
                        <div style="font-size: 0.85em; color: #1abc9c;">
                            <i class="fas fa-globe"></i> HTTP requests: ${attacker.http_requests.length}
                        </div>
                    </div>
                ` : ''}
            </div>
        `;
    });
    
    container.innerHTML = html;
}

function displayCredentialsList(credentials) {
    const container = document.getElementById('credentials-list');
    
    if (!credentials || credentials.length === 0) {
        container.innerHTML = `
            <div style="padding: 20px; text-align: center; color: #888;">
                <i class="fas fa-shield-alt" style="font-size: 2em; margin-bottom: 10px;"></i>
                <p>No credential attempts captured</p>
                <p style="font-size: 0.9em; margin-top: 5px;">Honeypot will log authentication attempts here</p>
            </div>
        `;
        return;
    }
    
    let html = '';
    credentials.forEach(cred => {
        const timestamp = cred.timestamp ? new Date(cred.timestamp).toLocaleString() : 'Unknown time';
        const username = cred.username || 'N/A';
        const password = cred.password || 'N/A';
        const protocol = cred.protocol || 'Unknown';
        const count = cred.count || 1;
        
        html += `
            <div style="background: rgba(241, 196, 15, 0.1); border-left: 3px solid #f1c40f; padding: 12px; margin-bottom: 8px; border-radius: 4px;">
                <div style="display: flex; justify-content: space-between; align-items: start;">
                    <div style="flex: 1;">
                        <div style="margin-bottom: 6px;">
                            <i class="fas fa-user" style="color: #f39c12; width: 16px;"></i>
                            <strong style="color: #f1c40f;">Username:</strong>
                            <code style="background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 3px; margin-left: 5px;">${username}</code>
                        </div>
                        <div style="margin-bottom: 6px;">
                            <i class="fas fa-key" style="color: #e67e22; width: 16px;"></i>
                            <strong style="color: #f1c40f;">Password:</strong>
                            <code style="background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 3px; margin-left: 5px;">${password}</code>
                        </div>
                        <div style="font-size: 0.85em; color: #bbb;">
                            <i class="fas fa-network-wired" style="width: 16px;"></i> ${protocol.toUpperCase()}
                            <span style="margin-left: 15px;">
                                <i class="fas fa-clock" style="width: 16px;"></i> ${timestamp}
                            </span>
                            ${count > 1 ? `
                                <span style="margin-left: 15px; color: #e74c3c;">
                                    <i class="fas fa-redo"></i> Tried ${count}x
                                </span>
                            ` : ''}
                        </div>
                    </div>
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

function displayCommandsList(commands) {
    const container = document.getElementById('commands-list');
    
    if (!commands || commands.length === 0) {
        container.innerHTML = `
            <div style="padding: 20px; text-align: center; color: #888;">
                <i class="fas fa-terminal" style="font-size: 2em; margin-bottom: 10px;"></i>
                <p>No SSH commands executed yet</p>
                <p style="font-size: 0.9em; margin-top: 5px;">Command history will appear when attackers interact with SSH</p>
            </div>
        `;
        return;
    }
    
    let html = '';
    commands.forEach(cmd => {
        const timestamp = cmd.timestamp ? new Date(cmd.timestamp).toLocaleString() : 'Unknown time';
        const command = cmd.command || 'N/A';
        const count = cmd.count || 1;
        
        // Color code based on command type
        let cmdColor = '#3498db';
        let cmdIcon = 'fa-terminal';
        if (command.includes('rm ') || command.includes('delete')) {
            cmdColor = '#e74c3c';
            cmdIcon = 'fa-trash';
        } else if (command.includes('wget') || command.includes('curl')) {
            cmdColor = '#e67e22';
            cmdIcon = 'fa-download';
        } else if (command.includes('cat') || command.includes('ls')) {
            cmdColor = '#2ecc71';
            cmdIcon = 'fa-eye';
        } else if (command.includes('chmod') || command.includes('sudo')) {
            cmdColor = '#9b59b6';
            cmdIcon = 'fa-user-shield';
        }
        
        html += `
            <div style="background: rgba(52, 152, 219, 0.1); border-left: 3px solid ${cmdColor}; padding: 12px; margin-bottom: 8px; border-radius: 4px;">
                <div style="display: flex; align-items: start; gap: 10px;">
                    <i class="fas ${cmdIcon}" style="color: ${cmdColor}; margin-top: 3px;"></i>
                    <div style="flex: 1;">
                        <code style="background: rgba(0,0,0,0.4); color: #1abc9c; padding: 4px 8px; border-radius: 3px; display: block; font-family: 'Courier New', monospace; font-size: 0.95em;">$ ${command}</code>
                        <div style="margin-top: 8px; font-size: 0.85em; color: #bbb;">
                            <i class="fas fa-clock" style="width: 16px;"></i> ${timestamp}
                            ${count > 1 ? `
                                <span style="margin-left: 15px; color: #e67e22;">
                                    <i class="fas fa-redo"></i> Executed ${count}x
                                </span>
                            ` : ''}
                        </div>
                    </div>
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

function displayHttpRequestsList(requests) {
    const container = document.getElementById('http-requests-list');
    
    if (!requests || requests.length === 0) {
        container.innerHTML = `
            <div style="padding: 20px; text-align: center; color: #888;">
                <i class="fas fa-globe" style="font-size: 2em; margin-bottom: 10px;"></i>
                <p>No HTTP requests captured</p>
                <p style="font-size: 0.9em; margin-top: 5px;">HTTP traffic will be logged when attackers probe web services</p>
            </div>
        `;
        return;
    }
    
    let html = '';
    requests.forEach(req => {
        const timestamp = req.timestamp ? new Date(req.timestamp).toLocaleString() : 'Unknown time';
        const method = req.method || 'GET';
        const url = req.url || '/';
        const userAgent = req.user_agent || 'Unknown';
        const count = req.count || 1;
        
        // Color code by HTTP method
        let methodColor = '#3498db';
        if (method === 'POST') methodColor = '#2ecc71';
        else if (method === 'PUT') methodColor = '#f39c12';
        else if (method === 'DELETE') methodColor = '#e74c3c';
        else if (method === 'PATCH') methodColor = '#9b59b6';
        
        html += `
            <div style="background: rgba(26, 188, 156, 0.1); border-left: 3px solid #1abc9c; padding: 12px; margin-bottom: 8px; border-radius: 4px;">
                <div style="display: flex; align-items: start; gap: 10px;">
                    <i class="fas fa-globe" style="color: #1abc9c; margin-top: 3px;"></i>
                    <div style="flex: 1;">
                        <div style="margin-bottom: 6px;">
                            <span style="background: ${methodColor}; color: white; padding: 2px 8px; border-radius: 3px; font-weight: bold; font-size: 0.85em;">${method}</span>
                            <code style="background: rgba(0,0,0,0.4); padding: 4px 8px; border-radius: 3px; margin-left: 8px; color: #16a085;">${url}</code>
                        </div>
                        <div style="margin-bottom: 6px; font-size: 0.85em; color: #bbb;">
                            <i class="fas fa-user-secret" style="width: 16px;"></i>
                            <strong>User-Agent:</strong>
                            <span style="font-family: 'Courier New', monospace; margin-left: 5px;">${userAgent}</span>
                        </div>
                        <div style="font-size: 0.85em; color: #bbb;">
                            <i class="fas fa-clock" style="width: 16px;"></i> ${timestamp}
                            ${count > 1 ? `
                                <span style="margin-left: 15px; color: #e67e22;">
                                    <i class="fas fa-redo"></i> Requested ${count}x
                                </span>
                            ` : ''}
                        </div>
                    </div>
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

// IP Rerouting to Beelzebub
async function rerouteIPToBeelzebub() {
    const ipInput = document.getElementById('reroute-ip');
    const ipAddress = ipInput.value.trim();
    
    if (!ipAddress) {
        showToast('Please enter an IP address', 'error');
        return;
    }
    
    // Validate IP format
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipPattern.test(ipAddress)) {
        showToast('Invalid IP address format', 'error');
        return;
    }
    
    if (!confirm(`Are you sure you want to reroute to Beelzebub?\n\nAll traffic from this IP will be redirected to the isolated honeypot network.`)) {
        return;
    }
    
    showToast(`Rerouting ${ipAddress} to honeypot...`, 'success');
    
    try {
        const response = await fetch('/api/beelzebub/reroute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip_address: ipAddress })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast(`✅ ${ipAddress} successfully rerouted to Beelzebub!`, 'success');
            ipInput.value = '';  // Clear input
            
            // Refresh reroutes list
            setTimeout(refreshReroutes, 1000);
        } else {
            showToast(`Failed to reroute: ${data.message}`, 'error');
        }
    } catch (error) {
        showToast('Error rerouting IP to honeypot', 'error');
        console.error('Reroute error:', error);
    }
}

async function refreshReroutes() {
    try {
        const response = await fetch('/api/beelzebub/reroutes');
        const data = await response.json();
        
        const listDiv = document.getElementById('rerouted-ips-list');
        const countBadge = document.getElementById('reroute-count');
        
        if (data.success) {
            const reroutes = data.active_reroutes || [];
            
            // Update count
            countBadge.textContent = `${reroutes.length} Rerouted`;
            countBadge.className = reroutes.length > 0 ? 'status-badge status-on' : 'status-badge status-off';
            
            if (reroutes.length > 0) {
                listDiv.innerHTML = reroutes.map(reroute => `
                    <div style="
                        background: linear-gradient(135deg, rgba(239, 68, 68, 0.1) 0%, rgba(251, 146, 60, 0.1) 100%);
                        border: 1px solid rgba(251, 146, 60, 0.3);
                        border-left: 4px solid #ef4444;
                        border-radius: 8px;
                        padding: 15px;
                        margin-bottom: 12px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    ">
                        <div style="display: flex; justify-content: space-between; align-items: start;">
                            <div style="flex: 1;">
                                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
                                    <span style="font-size: 1.5em;">🚨</span>
                                    <strong style="color: #dc2626; font-size: 1.1em;">${reroute.container}</strong>
                                    <span style="
                                        background: #ef4444;
                                        color: white;
                                        padding: 2px 8px;
                                        border-radius: 12px;
                                        font-size: 0.75em;
                                        font-weight: bold;
                                    ">ISOLATED</span>
                                </div>
                                <div style="display: grid; grid-template-columns: auto 1fr; gap: 8px; font-size: 0.9em; color: #4b5563; margin-left: 35px;">
                                    <span>📍 Original IP:</span>
                                    <strong>${reroute.ip}</strong>
                                    <span>🍯 Current Status:</span>
                                    <strong style="color: #fb923c;">${reroute.network}</strong>
                                    <span>🔒 Isolation Method:</span>
                                    <strong style="color: #8b5cf6;">${reroute.method === 'iptables_dnat' ? 'Iptables DNAT Redirect' : 'Network Move'}</strong>
                                    <span>⚠️ Status:</span>
                                    <strong style="color: #ef4444;">Isolated - Traffic redirected to honeypot</strong>
                                </div>
                            </div>
                            <button 
                                class="btn btn-success btn-small" 
                                onclick="removeReroute('${reroute.container}')"
                                style="min-width: 120px; margin-left: 15px;"
                            >
                                Restore to Network
                            </button>
                        </div>
                    </div>
                `).join('');
            } else {
                listDiv.innerHTML = '<div style="color: #6b7280; text-align: center; padding: 20px;">No devices isolated. All devices on main network.</div>';
            }
            
            // Show recent log entries
            if (data.reroutes_log && data.reroutes_log.length > 0) {
                const logEntries = data.reroutes_log.slice(-5).reverse().map(entry => 
                    `<div style="font-size: 11px; color: #9ca3af; padding: 3px 0;">${entry}</div>`
                ).join('');
                
                listDiv.innerHTML += `
                    <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #e5e7eb;">
                        <div style="font-size: 12px; color: #6b7280; margin-bottom: 5px;"><strong>Recent Activity:</strong></div>
                        ${logEntries}
                    </div>
                `;
            }
        }
    } catch (error) {
        console.error('Error refreshing reroutes:', error);
    }
}

async function removeReroute(containerName) {
    if (!confirm(`🔄 Restore ${containerName} to Main Network?\n\n` +
                 `This will:\n` +
                 `✅ Disconnect from honeypot_net (192.168.7.0/24)\n` +
                 `✅ Reconnect to custom_net (192.168.6.0/24)\n` +
                 `✅ Resume normal network communication\n\n` +
                 `Continue?`)) {
        return;
    }
    
    showToast(`🔄 Restoring ${containerName} to main network...`, 'success');
    
    try {
        const response = await fetch('/api/beelzebub/remove_reroute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ container_name: containerName })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast(`✅ ${containerName} successfully restored to main network!`, 'success');
            setTimeout(refreshReroutes, 1000);
        } else {
            showToast(`❌ Failed to restore: ${data.message}`, 'error');
        }
    } catch (error) {
        showToast('❌ Error restoring container', 'error');
        console.error('Remove reroute error:', error);
    }
}

// Attacker control
async function startAttackers() {
    showToast('Starting DOS attackers...', 'success');
    try {
        const response = await fetch('/api/attackers/start', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        setTimeout(refreshStatus, 2000);
    } catch (error) {
        showToast('Error starting attackers', 'error');
    }
}

async function stopAttackers() {
    showToast('Stopping attackers...', 'success');
    try {
        const response = await fetch('/api/attackers/stop', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        setTimeout(refreshStatus, 2000);
    } catch (error) {
        showToast('Error stopping attackers', 'error');
    }
}

// SSH Attacker control
async function startSSHAttacker() {
    showToast('Starting SSH brute force attacker...', 'success');
    try {
        const response = await fetch('/api/ssh_attacker/start', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        setTimeout(refreshStatus, 2000);
    } catch (error) {
        showToast('Error starting SSH attacker', 'error');
    }
}

async function stopSSHAttacker() {
    showToast('Stopping SSH attacker and cleaning iptables...', 'success');
    try {
        const response = await fetch('/api/ssh_attacker/stop', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        setTimeout(refreshStatus, 2000);
    } catch (error) {
        showToast('Error stopping SSH attacker', 'error');
    }
}

async function viewSSHLogs() {
    const logsContainer = document.getElementById('ssh-logs-container');
    const logsOutput = document.getElementById('ssh-logs-output');
    
    if (logsContainer.style.display === 'none') {
        showToast('Loading SSH logs...', 'info');
        try {
            const response = await fetch('/api/ssh_attacker/logs');
            const data = await response.json();
            
            if (data.success) {
                logsOutput.textContent = 
                    '=== Container Logs ===\n\n' + data.container_logs + 
                    '\n\n=== Summary Log ===\n\n' + data.summary_logs;
                logsContainer.style.display = 'block';
            } else {
                showToast('Failed to load logs', 'error');
            }
        } catch (error) {
            showToast('Error loading SSH logs', 'error');
        }
    } else {
        logsContainer.style.display = 'none';
    }
}

// Malware Attacker Control Functions
async function startMalwareAttacker() {
    showToast('Starting malware behavior simulator...', 'success');
    try {
        const response = await fetch('/api/malware_attacker/start', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        setTimeout(() => {
            refreshStatus();
            checkMalwareStatus();
        }, 2000);
    } catch (error) {
        showToast('Error starting malware attacker', 'error');
    }
}

async function stopMalwareAttacker() {
    showToast('Stopping malware simulator and cleaning iptables...', 'success');
    try {
        const response = await fetch('/api/malware_attacker/stop', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        setTimeout(() => {
            refreshStatus();
            checkMalwareStatus();
        }, 2000);
    } catch (error) {
        showToast('Error stopping malware attacker', 'error');
    }
}

async function checkMalwareStatus() {
    try {
        const response = await fetch('/api/malware_attacker/status');
        const data = await response.json();
        
        // Update main status badge
        const statusBadge = document.getElementById('malware-attacker-status');
        if (data.running) {
            statusBadge.textContent = 'ACTIVE';
            statusBadge.className = 'status-badge status-on';
        } else {
            statusBadge.textContent = 'OFF';
            statusBadge.className = 'status-badge status-off';
        }
        
        // Update individual behavior statuses
        const behaviors = data.behaviors || {};
        
        const beaconStatus = document.getElementById('malware-beacon-status');
        if (beaconStatus) {
            beaconStatus.textContent = behaviors.c2_beacon === 'Active' ? '🟢 Active' : '⚫ Inactive';
            beaconStatus.style.color = behaviors.c2_beacon === 'Active' ? '#10b981' : '#6b7280';
        }
        
        const exfilStatus = document.getElementById('malware-exfil-status');
        if (exfilStatus) {
            exfilStatus.textContent = behaviors.exfiltration === 'Active' ? '🟢 Active' : '⚫ Inactive';
            exfilStatus.style.color = behaviors.exfiltration === 'Active' ? '#10b981' : '#6b7280';
        }
        
        const eicarStatus = document.getElementById('malware-eicar-status');
        if (eicarStatus) {
            eicarStatus.textContent = behaviors.eicar_upload === 'Active' ? '🟢 Active' : '⚫ Inactive';
            eicarStatus.style.color = behaviors.eicar_upload === 'Active' ? '#10b981' : '#6b7280';
        }
        
        const dnsStatus = document.getElementById('malware-dns-status');
        if (dnsStatus) {
            dnsStatus.textContent = behaviors.dns_dga === 'Active' ? '🟢 Active' : '⚫ Inactive';
            dnsStatus.style.color = behaviors.dns_dga === 'Active' ? '#10b981' : '#6b7280';
        }
        
    } catch (error) {
        console.error('Error checking malware status:', error);
    }
}

async function viewMalwareLogs() {
    const logsContainer = document.getElementById('malware-logs-container');
    
    if (logsContainer.style.display === 'none') {
        showToast('Loading malware logs...', 'info');
        try {
            const response = await fetch('/api/malware_attacker/logs');
            const data = await response.json();
            
            if (data.success) {
                // Update all log sections
                document.getElementById('malware-logs-output').textContent = data.container_logs;
                document.getElementById('malware-beacon-logs').textContent = data.beacon_logs;
                document.getElementById('malware-exfil-logs').textContent = data.exfil_logs;
                document.getElementById('malware-eicar-logs').textContent = data.eicar_logs;
                document.getElementById('malware-dns-logs').textContent = data.dns_logs;
                
                logsContainer.style.display = 'block';
            } else {
                showToast('Failed to load logs', 'error');
            }
        } catch (error) {
            showToast('Error loading malware logs', 'error');
        }
    } else {
        logsContainer.style.display = 'none';
    }
}

function showMalwareLog(logType) {
    // Hide all log sections
    document.querySelectorAll('.malware-log-section').forEach(section => {
        section.style.display = 'none';
    });
    
    // Show selected log section
    document.getElementById(`malware-log-${logType}`).style.display = 'block';
}

// Monitor server control
async function startMonitor() {
    showToast('Starting network monitor server... (this may take 30 seconds)', 'success');
    try {
        const response = await fetch('/api/monitor/start', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        setTimeout(refreshStatus, 3000);
    } catch (error) {
        showToast('Error starting monitor', 'error');
    }
}

async function stopMonitor() {
    showToast('Stopping monitor server...', 'success');
    try {
        const response = await fetch('/api/monitor/stop', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        setTimeout(refreshStatus, 2000);
    } catch (error) {
        showToast('Error stopping monitor', 'error');
    }
}

async function refreshMonitorStatus() {
    try {
        const response = await fetch('/api/monitor/status');
        const data = await response.json();
        
        const statusBadge = document.getElementById('monitor-status');
        if (data.running) {
            statusBadge.textContent = 'RUNNING';
            statusBadge.className = 'status-badge status-on';
        } else {
            statusBadge.textContent = 'OFF';
            statusBadge.className = 'status-badge status-off';
        }
        
        refreshStatus();
    } catch (error) {
        console.error('Error checking monitor status:', error);
    }
}

async function refreshMonitorLogs() {
    try {
        const response = await fetch('/api/monitor/logs');
        const data = await response.json();
        
        const logsDisplay = document.getElementById('monitor-logs');
        
        if (!data.success || !data.logs) {
            logsDisplay.innerHTML = '<div class="log-entry">No logs available. Start the monitor server first.</div>';
            return;
        }

        // Split logs into lines and display
        const logLines = data.logs.split('\n').filter(line => line.trim());
        
        if (logLines.length === 0) {
            logsDisplay.innerHTML = '<div class="log-entry">No logs yet</div>';
            return;
        }

        logsDisplay.innerHTML = logLines.slice(-100).map(line => `
            <div class="log-entry">${escapeHtml(line)}</div>
        `).join('');
        
        // Scroll to bottom
        logsDisplay.scrollTop = logsDisplay.scrollHeight;

    } catch (error) {
        showToast('Error loading monitor logs', 'error');
    }
}

async function checkMonitorHealth() {
    showToast('Checking monitor health...', 'success');
    try {
        // Check Flask API
        const flaskResponse = await fetch('http://localhost:5002/health');
        if (flaskResponse.ok) {
            const data = await flaskResponse.json();
            showToast(`Monitor is healthy! Status: ${data.status}`, 'success');
        } else {
            showToast('Monitor not responding on port 5002', 'error');
        }
    } catch (error) {
        showToast('Monitor is not running or not accessible', 'error');
    }
}

// Helper function to escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Tab switching
function switchTab(tabName) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    
    // Remove active from all tabs
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Show selected tab content
    document.getElementById(`tab-${tabName}`).classList.add('active');
    
    // Set active tab button
    event.target.classList.add('active');
    
    // Load data for the tab
    if (tabName === 'device-data') {
        refreshDeviceData();
    } else if (tabName === 'monitor-logs') {
        refreshMonitorLogsInTab();
    } else if (tabName === 'beelzebub-logs') {
        viewBeelzebubLogsInTab();
    } else if (tabName === 'device-containers') {
        refreshDeviceContainerLogs();
    }
}

// Refresh monitor logs in tab
async function refreshMonitorLogsInTab() {
    try {
        const response = await fetch('/api/monitor/logs');
        const data = await response.json();
        
        const logsDisplay = document.getElementById('monitor-logs-tab');
        
        if (!data.success || !data.logs) {
            logsDisplay.innerHTML = '<div class="log-entry">No logs available. Start the monitor server first.</div>';
            return;
        }

        const logLines = data.logs.split('\n').filter(line => line.trim());
        
        if (logLines.length === 0) {
            logsDisplay.innerHTML = '<div class="log-entry">No logs yet</div>';
            return;
        }

        logsDisplay.innerHTML = logLines.slice(-100).map(line => `
            <div class="log-entry">${escapeHtml(line)}</div>
        `).join('');
        
        logsDisplay.scrollTop = logsDisplay.scrollHeight;

    } catch (error) {
        showToast('Error loading monitor logs', 'error');
    }
}

// View honeypot logs in tab
async function viewBeelzebubLogsInTab() {
    try {
        const response = await fetch('/api/beelzebub/logs');
        const data = await response.json();
        
        const logsDisplay = document.getElementById('beelzebub-logs-tab');
        
        if (!data.success) {
            logsDisplay.innerHTML = `<div class="log-entry" style="color: #f87171;">Error: ${data.message || data.error || 'Failed to load logs'}</div>`;
            return;
        }
        
        if (data.logs.length === 0) {
            logsDisplay.innerHTML = `<div class="log-entry">${data.message || 'No attacks logged yet. Start honeypot and wait for attacks.'}</div>`;
            return;
        }

        logsDisplay.innerHTML = data.logs.map(log => {
            // Check if it's a raw text log or JSON structured log
            if (log.raw) {
                return `
                    <div class="log-entry">
                        <span style="color: #94a3b8;">${log.time || ''}</span> | 
                        <span style="color: #cbd5e1;">${escapeHtml(log.msg || '')}</span>
                    </div>
                `;
            }
            
            // Format JSON log entry
            const time = log.time || log.timestamp || 'N/A';
            const level = log.level || 'info';
            const message = log.msg || log.message || '';
            const port = log.port || '';
            const commands = log.commands !== undefined ? log.commands : '';
            const banner = log.banner || '';
            
            // Color based on log level
            let levelColor = '#60a5fa'; // blue for info
            if (level === 'error') levelColor = '#f87171'; // red
            if (level === 'warn') levelColor = '#fbbf24'; // yellow
            if (level === 'debug') levelColor = '#94a3b8'; // gray
            
            return `
                <div class="log-entry">
                    <span style="color: #94a3b8;">${time}</span> | 
                    <span style="color: ${levelColor}; font-weight: bold;">[${level.toUpperCase()}]</span> |
                    <span style="color: #cbd5e1;">${escapeHtml(message)}</span>
                    ${port ? `<span style="color: #fbbf24;"> | Port: ${port}</span>` : ''}
                    ${commands !== '' ? `<span style="color: #8b5cf6;"> | Commands: ${commands}</span>` : ''}
                    ${banner ? `<span style="color: #10b981;"> | Banner: ${banner}</span>` : ''}
                </div>
            `;
        }).join('');
        
        // Auto-scroll to bottom to show latest logs
        logsDisplay.scrollTop = logsDisplay.scrollHeight;
        
    } catch (error) {
        const logsDisplay = document.getElementById('beelzebub-logs-tab');
        logsDisplay.innerHTML = `<div class="log-entry" style="color: #f87171;">Error loading Beelzebub logs: ${error.message}</div>`;
        console.error('Error loading Beelzebub logs:', error);
    }
}

// Refresh device container logs list
async function refreshDeviceContainerLogs() {
    try {
        const response = await fetch('/api/devices/list');
        const data = await response.json();

        const container = document.getElementById('device-container-list');
        
        if (data.devices.length === 0) {
            container.innerHTML = '<p style="color: rgba(255,255,255,0.6);">No devices created yet. Go to Devices page to create some.</p>';
            return;
        }

        container.innerHTML = `
            <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                ${data.devices.map(device => `
                    <button class="btn btn-primary btn-small" onclick="viewDeviceContainerLogs('${device.name}')">
                        📦 ${device.name}
                    </button>
                `).join('')}
            </div>
        `;

    } catch (error) {
        showToast('Error loading device list', 'error');
    }
}

// View logs for specific device container
async function viewDeviceContainerLogs(deviceName) {
    showToast(`Loading logs for ${deviceName}...`, 'success');
    try {
        const response = await fetch(`/api/containers/logs/${deviceName}`);
        const data = await response.json();
        
        const logsDisplay = document.getElementById('device-container-logs');
        
        if (!data.success || !data.logs) {
            logsDisplay.innerHTML = `<div class="log-entry">No logs available for ${deviceName}</div>`;
            return;
        }

        const logLines = data.logs.split('\n').filter(line => line.trim());
        
        if (logLines.length === 0) {
            logsDisplay.innerHTML = `<div class="log-entry">${deviceName} has no logs yet</div>`;
            return;
        }

        logsDisplay.innerHTML = `
            <div class="log-entry" style="color: #fbbf24; font-weight: bold;">
                === Logs for ${deviceName} ===
            </div>
            ${logLines.slice(-100).map(line => `
                <div class="log-entry">${escapeHtml(line)}</div>
            `).join('')}
        `;
        
        logsDisplay.scrollTop = logsDisplay.scrollHeight;

    } catch (error) {
        showToast('Error loading container logs', 'error');
    }
}

// STOP ALL - Nuclear cleanup
function confirmStopAll() {
    const confirmed = confirm(
        '🚨 NUCLEAR OPTION - COMPLETE CLEANUP 🚨\n\n' +
        'This will PERMANENTLY DELETE:\n\n' +
        '✗ ALL containers (devices, honeypots, attackers, monitors)\n' +
        '✗ ALL images (device-simulator, malware-attacker, beelzebub, etc.)\n' +
        '✗ ALL networks (custom_net, honeypot_net, etc.)\n' +
        '✗ ALL volumes and build cache\n' +
        '✗ The ENTIRE Docker environment for this project\n\n' +
        '⚠️ YOU WILL NEED TO REBUILD EVERYTHING FROM SCRATCH!\n\n' +
        'This action CANNOT be undone!\n\n' +
        'Are you absolutely sure?'
    );
    
    if (!confirmed) return;
    
    // Double confirmation
    const doubleConfirm = confirm(
        '🔥 FINAL WARNING 🔥\n\n' +
        'This will:\n' +
        '• Stop ALL running containers immediately\n' +
        '• Delete ALL Docker images (devices, malware, honeypots)\n' +
        '• Remove ALL networks and volumes\n' +
        '• Wipe the entire project environment\n\n' +
        'After this, you must rebuild with docker-compose up!\n\n' +
        'Click OK to proceed with TOTAL ANNIHILATION.'
    );
    
    if (!doubleConfirm) return;
    
    stopAll();
}

async function stopAll() {
    showToast('🧨 Starting complete cleanup... This may take a minute.', 'info');
    
    try {
        const response = await fetch('/api/cleanup/all', {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('✅ ' + data.message, 'success');
            
            // Show details in console
            console.log('Cleanup details:', data.details);
            
            // Refresh status after cleanup
            setTimeout(() => {
                refreshStatus();
                refreshDevices();
            }, 2000);
            
            alert(
                '🧨 COMPLETE CLEANUP FINISHED!\n\n' +
                'All containers, images, and networks have been removed.\n\n' +
                'Details:\n' + data.details.join('\n')
            );
        } else {
            showToast('❌ Cleanup failed', 'error');
        }
    } catch (error) {
        showToast('Error during cleanup: ' + error.message, 'error');
    }
}

// ===== Network Map Functions =====
let networkMapData = { nodes: [], connections: [] };

async function refreshNetworkMap() {
    try {
        const response = await fetch('/api/network/map');
        const data = await response.json();
        
        if (data.success) {
            networkMapData = data;
            drawNetworkMap(data);
            document.getElementById('map-node-count').textContent = data.nodes.length;
        }
    } catch (error) {
        console.error('Error refreshing network map:', error);
    }
}

function drawNetworkMap(data) {
    const svg = document.getElementById('network-svg');
    const width = svg.clientWidth || 1200;
    const height = 600;
    
    svg.setAttribute('width', width);
    svg.setAttribute('height', height);
    
    // Clear existing content
    svg.innerHTML = '';
    
    const { nodes, connections } = data;
    
    // Define node colors by type
    const nodeColors = {
        'gateway': '#10b981',
        'device': '#3b82f6',
        'honeypot': '#f59e0b',
        'monitor': '#8b5cf6',
        'attacker': '#ef4444',
        'honeypot_network': '#fb923c',
        'honeypot_device': '#fdba74',
        'other': '#6b7280'
    };
    
    // Calculate positions (circular layout around gateway)
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) * 0.35;
    
    const positions = {};
    
    // Place gateway in center
    positions['gateway'] = { x: centerX, y: centerY };
    
    // Place other nodes in circle around gateway
    const otherNodes = nodes.filter(n => n.id !== 'gateway');
    const angleStep = (2 * Math.PI) / (otherNodes.length || 1);
    
    otherNodes.forEach((node, index) => {
        const angle = index * angleStep;
        positions[node.id] = {
            x: centerX + radius * Math.cos(angle),
            y: centerY + radius * Math.sin(angle)
        };
    });
    
    // Draw connections first (so they're behind nodes)
    connections.forEach(conn => {
        const from = positions[conn.from];
        const to = positions[conn.to];
        
        if (from && to) {
            const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
            line.setAttribute('x1', from.x);
            line.setAttribute('y1', from.y);
            line.setAttribute('x2', to.x);
            line.setAttribute('y2', to.y);
            // Color code connections
            let strokeColor = '#374151';
            let strokeDash = '';
            if (conn.type === 'data') {
                strokeDash = '5,5';
            } else if (conn.type === 'honeypot_network') {
                strokeColor = '#fb923c';  // Orange for honeypot network
                strokeDash = '3,3';
            }
            
            line.setAttribute('stroke', strokeColor);
            line.setAttribute('stroke-width', '2');
            line.setAttribute('stroke-dasharray', strokeDash);
            svg.appendChild(line);
        }
    });
    
    // Draw nodes
    nodes.forEach(node => {
        const pos = positions[node.id];
        if (!pos) return;
        
        // Node circle
        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', pos.x);
        circle.setAttribute('cy', pos.y);
        circle.setAttribute('r', node.type === 'gateway' ? 40 : 30);
        circle.setAttribute('fill', nodeColors[node.type] || nodeColors.other);
        circle.setAttribute('stroke', '#fff');
        circle.setAttribute('stroke-width', '3');
        circle.setAttribute('cursor', 'pointer');
        circle.setAttribute('data-node-id', node.id);
        
        // Add hover effect
        circle.addEventListener('mouseenter', function() {
            this.setAttribute('r', node.type === 'gateway' ? 45 : 35);
        });
        circle.addEventListener('mouseleave', function() {
            this.setAttribute('r', node.type === 'gateway' ? 40 : 30);
        });
        
        // Add click handler
        circle.addEventListener('click', () => showNodeDetails(node));
        
        svg.appendChild(circle);
        
        // Node label (name)
        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', pos.x);
        text.setAttribute('y', pos.y - (node.type === 'gateway' ? 50 : 40));
        text.setAttribute('text-anchor', 'middle');
        text.setAttribute('fill', '#fff');
        text.setAttribute('font-size', '12');
        text.setAttribute('font-weight', 'bold');
        text.textContent = node.name.length > 25 ? node.name.substring(0, 25) + '...' : node.name;
        svg.appendChild(text);
        
        // Node IP
        const ipText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        ipText.setAttribute('x', pos.x);
        ipText.setAttribute('y', pos.y + (node.type === 'gateway' ? 55 : 45));
        ipText.setAttribute('text-anchor', 'middle');
        ipText.setAttribute('fill', '#9ca3af');
        ipText.setAttribute('font-size', '10');
        ipText.textContent = node.ip;
        svg.appendChild(ipText);
    });
}

function showNodeDetails(node) {
    const detailsDiv = document.getElementById('node-details');
    
    const nodeData = networkMapData.nodes.find(n => n.id === node.id);
    
    let html = `
        <div style="padding: 15px; background: #f3f4f6; border-radius: 8px; margin-bottom: 10px;">
            <h4 style="margin: 0 0 10px 0; color: #1f2937; display: flex; align-items: center; gap: 8px;">
                ${node.type === 'attacker' ? '<i class="fas fa-skull-crossbones" style="color: #ef4444;"></i>' : ''}
                ${node.type === 'device' ? '<i class="fas fa-mobile-alt" style="color: #3b82f6;"></i>' : ''}
                ${node.type === 'gateway' ? '<i class="fas fa-network-wired" style="color: #10b981;"></i>' : ''}
                ${node.type === 'honeypot' ? '<i class="fas fa-shield-alt" style="color: #f59e0b;"></i>' : ''}
                ${node.type === 'monitor' ? '<i class="fas fa-eye" style="color: #8b5cf6;"></i>' : ''}
                ${escapeHtml(node.name)}
            </h4>
            <div style="display: grid; grid-template-columns: auto 1fr; gap: 10px; font-size: 0.9em;">
                <strong>ID:</strong> <span>${escapeHtml(node.id)}</span>
                <strong>Type:</strong> <span style="text-transform: capitalize;">${escapeHtml(node.type)}</span>
                <strong>IP Address:</strong> <span style="font-family: monospace; background: #e5e7eb; padding: 2px 6px; border-radius: 3px;">${escapeHtml(node.ip)}</span>
                <strong>Status:</strong> <span style="color: ${node.status === 'running' ? '#10b981' : '#6b7280'}; font-weight: bold;">${escapeHtml(node.status.toUpperCase())}</span>
    `;
    
    if (node.container_id) {
        html += `<strong>Container ID:</strong> <span style="font-family: monospace; font-size: 0.85em;">${escapeHtml(node.container_id)}</span>`;
    }
    
    // Show network information
    if (node.on_honeypot_network) {
        html += `<strong>Network:</strong> <span style="color: #f59e0b; font-weight: bold;">🍯 Honeypot Network (ISOLATED)</span>`;
        if (node.honeypot_ip) {
            html += `<strong>Honeypot IP:</strong> <span style="font-family: monospace; background: #fef3c7; padding: 2px 6px; border-radius: 3px;">${escapeHtml(node.honeypot_ip)}</span>`;
        }
    } else if (node.type !== 'honeypot_network' && node.type !== 'gateway') {
        html += `<strong>Network:</strong> <span style="color: #10b981;">📡 Production Network (custom_net)</span>`;
    }
    
    if (node.last_seen) {
        html += `<strong>Last Seen:</strong> <span>${escapeHtml(node.last_seen)}</span>`;
    }
    
    // Show attacker-specific information
    if (node.type === 'attacker' && node.attacker_info) {
        html += `
            </div>
            <div style="margin-top: 15px; padding-top: 15px; border-top: 2px solid #ef4444;">
                <h5 style="margin: 0 0 10px 0; color: #ef4444; display: flex; align-items: center; gap: 8px;">
                    <i class="fas fa-exclamation-triangle"></i> Attacker Information
                </h5>
                <div style="display: grid; grid-template-columns: auto 1fr; gap: 10px; font-size: 0.9em;">
                    <strong>Attack Type:</strong> <span style="color: #ef4444; font-weight: bold;">${escapeHtml(node.attacker_info.attack_type)}</span>
                    <strong>Target:</strong> <span>${escapeHtml(node.attacker_info.target)}</span>
                    <strong>Threat Level:</strong> 
                    <span style="
                        background: ${node.attacker_info.threat_level === 'CRITICAL' ? '#dc2626' : node.attacker_info.threat_level === 'HIGH' ? '#ef4444' : '#f59e0b'}; 
                        color: white; 
                        padding: 2px 8px; 
                        border-radius: 3px; 
                        font-weight: bold;
                        font-size: 0.85em;
                    ">${escapeHtml(node.attacker_info.threat_level)}</span>
                    <strong>Description:</strong> <span>${escapeHtml(node.attacker_info.description)}</span>
                </div>
            </div>
            <div style="margin-top: 15px; padding: 10px; background: #fef2f2; border-left: 3px solid #ef4444; border-radius: 4px;">
                <div style="color: #991b1b; font-size: 0.85em;">
                    <strong>⚠️ Security Notice:</strong> This is a simulated attacker for testing network security responses. 
                    ${node.on_honeypot_network ? '<br><strong style="color: #16a34a;">✅ ISOLATED:</strong> Device has been moved to honeypot network and cannot harm production systems.' : '<br><strong style="color: #dc2626;">⚠️ ACTIVE:</strong> This attacker is currently on the production network.'}
                </div>
            </div>
        `;
    } else {
        html += `
            </div>
        `;
    }
    
    html += `
        </div>
    `;
    
    detailsDiv.innerHTML = html;
}

// ===== Analytics Functions =====

// ==================== AI AGENT FUNCTIONS ====================

let agentQueriesCount = 0;

// Send query to AI agent
async function sendAgentQuery() {
    const input = document.getElementById('agent-query-input');
    const query = input.value.trim();
    
    if (!query) {
        showToast('Please enter a query', 'error');
        return;
    }
    
    // Clear input
    input.value = '';
    
    // Add user message to chat
    addAgentMessage('user', query);
    
    // Show thinking indicator
    const thinkingId = addAgentMessage('agent', '🤔 Thinking...', true);
    
    try {
        const response = await fetch('/api/agent/query', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ query })
        });
        
        const data = await response.json();
        
        // Remove thinking indicator
        removeAgentMessage(thinkingId);
        
        if (data.success) {
            // Add agent response
            addAgentMessage('agent', data.response);
            agentQueriesCount++;
            document.getElementById('agent-queries-count').textContent = agentQueriesCount;
            showToast('Query processed successfully', 'success');
        } else {
            addAgentMessage('agent', `❌ Error: ${data.error}`);
            showToast('Query failed', 'error');
        }
    } catch (error) {
        removeAgentMessage(thinkingId);
        addAgentMessage('agent', `❌ Error: ${error.message}`);
        showToast('Connection error', 'error');
    }
}

// Quick query shortcuts
function quickAgentQuery(query) {
    document.getElementById('agent-query-input').value = query;
    sendAgentQuery();
}

// Add message to chat
function addAgentMessage(role, content, isThinking = false) {
    const chatContainer = document.getElementById('agent-chat-messages');
    const messageId = `msg-${Date.now()}`;
    
    const messageDiv = document.createElement('div');
    messageDiv.id = messageId;
    messageDiv.className = 'agent-message';
    
    if (role === 'user') {
        messageDiv.style.cssText = `
            background: linear-gradient(135deg, rgba(46, 204, 113, 0.2), rgba(46, 204, 113, 0.1));
            border-left: 4px solid #2ecc71;
            padding: 18px;
            border-radius: 8px;
            margin-bottom: 15px;
            box-shadow: 0 2px 6px rgba(46, 204, 113, 0.1);
        `;
        messageDiv.innerHTML = `
            <div style="display: flex; align-items: start; gap: 15px;">
                <i class="fas fa-user-circle" style="color: #52d788; font-size: 1.5em; margin-top: 3px;"></i>
                <div style="flex: 1;">
                    <div style="color: #52d788; font-weight: bold; font-size: 1.05em; margin-bottom: 10px;">You</div>
                    <div style="color: #f0f0f0; white-space: pre-wrap; line-height: 1.5;">${escapeHtml(content)}</div>
                </div>
            </div>
        `;
    } else {
        const color = isThinking ? '#f39c12' : '#5dade2';
        const bgColor = isThinking ? 'rgba(243, 156, 18, 0.15)' : 'rgba(52, 152, 219, 0.15)';
        messageDiv.style.cssText = `
            background: linear-gradient(135deg, ${bgColor}, rgba(52, 152, 219, 0.05));
            border-left: 4px solid ${color};
            padding: 18px;
            border-radius: 8px;
            margin-bottom: 15px;
            box-shadow: 0 2px 6px rgba(52, 152, 219, 0.1);
        `;
        messageDiv.innerHTML = `
            <div style="display: flex; align-items: start; gap: 15px;">
                <i class="fas fa-robot" style="color: ${color}; font-size: 1.5em; margin-top: 3px;"></i>
                <div style="flex: 1;">
                    <div style="color: ${color}; font-weight: bold; font-size: 1.05em; margin-bottom: 10px;">AI Agent</div>
                    <div style="color: #e8e8e8; white-space: pre-wrap; line-height: 1.6;">${formatAgentResponse(content)}</div>
                </div>
            </div>
        `;
    }
    
    chatContainer.appendChild(messageDiv);
    chatContainer.scrollTop = chatContainer.scrollHeight;
    
    return messageId;
}

// Remove message from chat
function removeAgentMessage(messageId) {
    const message = document.getElementById(messageId);
    if (message) {
        message.remove();
    }
}

// Format agent response with syntax highlighting
function formatAgentResponse(text) {
    // Escape HTML first
    let formatted = escapeHtml(text);
    
    // Highlight IP addresses
    formatted = formatted.replace(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g, 
        '<code style="background: rgba(52,152,219,0.3); padding: 2px 6px; border-radius: 3px; color: #3498db;">$1</code>');
    
    // Highlight device names
    formatted = formatted.replace(/device_\w+/gi, 
        '<code style="background: rgba(46,204,113,0.3); padding: 2px 6px; border-radius: 3px; color: #2ecc71;">$&</code>');
    
    // Highlight threats/attacks
    formatted = formatted.replace(/\b(threat|attack|malicious|suspicious|anomaly|intrusion)\b/gi, 
        '<span style="color: #e74c3c; font-weight: bold;">$&</span>');
    
    return formatted;
}

// Clear chat history
function clearAgentChat() {
    const chatContainer = document.getElementById('agent-chat-messages');
    const welcomeMsg = chatContainer.querySelector('.agent-message');
    chatContainer.innerHTML = '';
    if (welcomeMsg) {
        chatContainer.appendChild(welcomeMsg.cloneNode(true));
    }
    agentQueriesCount = 0;
    document.getElementById('agent-queries-count').textContent = '0';
    showToast('Chat cleared', 'success');
}

// Download chat history
function downloadChatHistory() {
    const chatContainer = document.getElementById('agent-chat-messages');
    const messages = chatContainer.querySelectorAll('.user-message, .agent-message');
    
    if (messages.length === 0) {
        showToast('No chat history to download', 'error');
        return;
    }
    
    let chatText = '=================================================\n';
    chatText += 'Network Security AI Agent - Chat History\n';
    chatText += `Downloaded: ${new Date().toLocaleString()}\n`;
    chatText += '=================================================\n\n';
    
    messages.forEach((msg, index) => {
        const isUser = msg.classList.contains('user-message');
        const sender = isUser ? 'YOU' : 'AI AGENT';
        const text = msg.textContent.trim();
        
        chatText += `[${sender}]\n`;
        chatText += `${text}\n\n`;
        chatText += '-------------------------------------------------\n\n';
    });
    
    chatText += '=================================================\n';
    chatText += `Total Messages: ${messages.length}\n`;
    chatText += '=================================================\n';
    
    // Create blob and download
    const blob = new Blob([chatText], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ai_chat_history_${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    
    showToast('Chat history downloaded', 'success');
}

// Test API key
async function testAPIKey() {
    const infoDiv = document.getElementById('api-key-info');
    infoDiv.innerHTML = '<div style="color: #f39c12;"><i class="fas fa-spinner fa-spin"></i> Testing API key...</div>';
    
    try {
        const response = await fetch('/api/agent/test-key', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            infoDiv.innerHTML = `
                <div style="color: #2ecc71;">
                    <div style="margin-bottom: 10px;"><i class="fas fa-check-circle"></i> <strong>API Key Valid!</strong></div>
                    <div style="color: #bbb; font-size: 0.9em;">
                        <div><strong>Model:</strong> ${data.model}</div>
                        <div><strong>Key:</strong> ${data.key_preview}</div>
                        <div><strong>Test Response:</strong> "${data.response}"</div>
                    </div>
                </div>
            `;
            showToast('API key is working correctly', 'success');
        } else {
            const isSubscriptionError = data.is_subscription_error;
            const errorColor = isSubscriptionError ? '#e67e22' : '#e74c3c';
            
            infoDiv.innerHTML = `
                <div style="color: ${errorColor};">
                    <div style="margin-bottom: 10px;">
                        <i class="fas fa-exclamation-triangle"></i> 
                        <strong>${isSubscriptionError ? 'Subscription Issue' : 'API Key Error'}</strong>
                    </div>
                    <div style="color: #bbb; font-size: 0.9em;">
                        <div><strong>Key:</strong> ${data.key_preview || 'Not set'}</div>
                        <div><strong>Error:</strong> ${data.error}</div>
                        ${isSubscriptionError ? `
                            <div style="margin-top: 10px; padding: 10px; background: rgba(230, 126, 34, 0.2); border-left: 3px solid #e67e22; border-radius: 4px;">
                                <strong>Action Required:</strong><br>
                                1. Renew subscription at <a href="https://z.ai/subscribe" target="_blank" style="color: #3498db;">https://z.ai/subscribe</a><br>
                                2. Update .env file if you have a new key<br>
                                3. Restart the dashboard to reload the key
                            </div>
                        ` : ''}
                    </div>
                </div>
            `;
            showToast(isSubscriptionError ? 'Subscription expired or inactive' : 'API key test failed', 'error');
        }
    } catch (error) {
        infoDiv.innerHTML = `
            <div style="color: #e74c3c;">
                <div style="margin-bottom: 10px;"><i class="fas fa-times-circle"></i> <strong>Connection Error</strong></div>
                <div style="color: #bbb; font-size: 0.9em;">
                    <div><strong>Error:</strong> ${error.message}</div>
                    <div style="margin-top: 5px;">Make sure the dashboard is running and connected to the internet.</div>
                </div>
            </div>
        `;
        showToast('Failed to test API key', 'error');
    }
}

// Quick reroute to honeypot
async function quickRerouteToBeelzebub() {
    const input = document.getElementById('quick-reroute-ip');
    const deviceIp = input.value.trim();
    
    if (!deviceIp) {
        showToast('Please enter a device IP', 'error');
        return;
    }
    
    // Validate IP format
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipPattern.test(deviceIp)) {
        showToast('Invalid IP address format', 'error');
        return;
    }
    
    if (!confirm(`Reroute device ${deviceIp} to honeypot network?\n\nThis will isolate the device from the main network.`)) {
        return;
    }
    
    try {
        const response = await fetch('/api/agent/reroute', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ device_ip: deviceIp })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast(data.message, 'success');
            input.value = '';
            
            // Add to chat
            addAgentMessage('agent', `✅ Successfully rerouted device ${data.device} (${deviceIp}) to honeypot network`);
            
            // Refresh network map and honeypot page
            refreshNetworkMap();
            refreshReroutes();
        } else {
            showToast(`Reroute failed: ${data.error}`, 'error');
            addAgentMessage('agent', `❌ Failed to reroute ${deviceIp}: ${data.error}`);
        }
    } catch (error) {
        showToast('Connection error', 'error');
        addAgentMessage('agent', `❌ Error: ${error.message}`);
    }
}

// Auto-refresh
setInterval(() => {
    refreshStatus();
    refreshDeviceRegistry();
    
    if (currentPage === 'network-map') {
        refreshNetworkMap();
    } else if (currentPage === 'monitor') {
        refreshMonitorStatus();
    } else if (currentPage === 'devices') {
        refreshDevices();
    } else if (currentPage === 'honeypot') {
        refreshBeelzebubStats();
        refreshReroutes();
    } else if (currentPage === 'logs') {
        // Auto-refresh active tab in logs page
        const activeTab = document.querySelector('#page-logs .tab.active');
        if (activeTab) {
            const tabText = activeTab.textContent.trim();
            if (tabText.includes('Device Data')) {
                refreshDeviceData();
            } else if (tabText.includes('Monitor')) {
                refreshMonitorLogsInTab();
            } else if (tabText.includes('Honeypot')) {
                viewBeelzebubLogsInTab();
            }
        }
    }
}, 5000);

// Initial load
refreshStatus();
refreshDeviceRegistry();
