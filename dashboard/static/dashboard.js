// Network Security Dashboard JavaScript - Professional Edition

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
        updateStatusBadge('network-status', data.network.exists, 'stat-network');

        // Update device count
        document.getElementById('stat-devices').textContent = data.devices.count;
        document.getElementById('device-count-badge').textContent = `${data.devices.count} Devices`;

        // Update Beelzebub
        updateStatusBadge('beelzebub-status', data.beelzebub.running, 'stat-beelzebub');

        // Update DOS attacker status
        const attackerStatus = document.getElementById('attacker-status');
        if (attackerStatus) {
            updateStatusBadge('attacker-status', data.attackers.dos_running);
        }

        // Update SSH attacker status
        const sshAttackerStatus = document.getElementById('ssh-attacker-status');
        if (sshAttackerStatus) {
            updateStatusBadge('ssh-attacker-status', data.attackers.ssh_running);
        }

        // Update malware attacker status
        const malwareAttackerStatus = document.getElementById('malware-attacker-status');
        if (malwareAttackerStatus) {
            updateStatusBadge('malware-attacker-status', data.attackers.malware_running);
        }

        // Update endpoint behavior attacker status
        const endpointBehaviorAttackerStatus = document.getElementById('endpoint-behavior-attacker-status');
        if (endpointBehaviorAttackerStatus) {
            updateStatusBadge('endpoint-behavior-attacker-status', data.attackers.endpoint_behavior_running);
        }

        // Update container count
        document.getElementById('stat-containers').textContent = data.all_containers.length;

        // Update monitor status
        const monitorStatus = document.getElementById('monitor-status');
        if (data.monitor) {
            updateStatusBadge('monitor-status', data.monitor.running, 'stat-monitor');
        }

    } catch (error) {
        console.error('Error refreshing status:', error);
    }
}

function updateStatusBadge(elementId, isActive, textElementId = null) {
    const element = document.getElementById(elementId);
    if (!element) return;

    if (isActive) {
        element.textContent = 'ACTIVE';
        element.className = 'status-badge status-on';
        if (textElementId) document.getElementById(textElementId).textContent = 'ON';
    } else {
        element.textContent = 'OFFLINE';
        element.className = 'status-badge status-off';
        if (textElementId) document.getElementById(textElementId).textContent = 'OFF';
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
        const response = await fetch('/api/status');
        const data = await response.json();

        const container = document.getElementById('devices-container');
        const prod = data.production_devices || [];
        const beelzebub = data.beelzebub && data.beelzebub.devices ? data.beelzebub.devices : (data.honeypot_devices || []);
        const blocked = data.blocked_devices || [];

        let html = `<div class="grid">`;

        // Production Network Column
        html += `
            <div class="card">
                <div class="card-header">
                    <div class="card-title">
                        <i class="fas fa-network-wired text-info"></i>
                        Production Network (custom_net)
                    </div>
                    <span class="status-badge">${prod.length} Nodes</span>
                </div>
                <div class="device-grid">`;

        if (prod.length === 0) {
            html += `<div class="text-muted" style="grid-column: 1/-1; text-align: center; padding: 2rem;">No active devices on production network</div>`;
        } else {
            prod.forEach(d => {
                html += `
                    <div class="device-card">
                        <div class="device-header">
                            <div>
                                <div class="device-name">📱 ${escapeHtml(d.name || 'Device')}</div>
                                <div class="device-type font-mono">${d.ip || 'N/A'}</div>
                            </div>
                            <div class="status-badge status-on" style="font-size: 0.6rem;">ACTIVE</div>
                        </div>
                        <div class="device-info">
                            <div><span class="text-muted">Image:</span> ${escapeHtml(d.image || 'N/A')}</div>
                            <div><span class="text-muted">Net:</span> ${escapeHtml((d.networks || []).join(', ') || 'N/A')}</div>
                        </div>
                        <div class="device-actions">
                            <button class="btn btn-danger btn-small" onclick="deleteDevice('${escapeHtml(d.name)}')">
                                <i class="fas fa-trash"></i> Delete
                            </button>
                        </div>
                    </div>`;
            });
        }
        html += `</div></div>`;

        // Beelzebub Column
        html += `
            <div class="card" style="border-color: rgba(245, 158, 11, 0.3);">
                <div class="card-header">
                    <div class="card-title">
                        <i class="fas fa-shield-alt text-warning"></i>
                        Honeypot Network (Isolated)
                    </div>
                    <span class="status-badge status-warning" style="color: var(--warning); border-color: var(--warning);">${beelzebub.length} Isolated</span>
                </div>
                <div class="device-grid">`;

        if (beelzebub.length === 0) {
            html += `<div class="text-muted" style="grid-column: 1/-1; text-align: center; padding: 2rem;">No devices currently isolated</div>`;
        } else {
            beelzebub.forEach(d => {
                html += `
                    <div class="device-card isolated">
                        <div class="device-header">
                            <div>
                                <div class="device-name">🍯 ${escapeHtml(d.name || 'Isolated Device')}</div>
                                <div class="device-type font-mono text-warning">ISOLATED</div>
                            </div>
                        </div>
                        <div class="device-info">
                            <div><span class="text-muted">IP:</span> ${d.ip || 'N/A'}</div>
                            <div><span class="text-muted">Image:</span> ${escapeHtml(d.image || 'N/A')}</div>
                        </div>
                        <div class="device-actions">
                            <button class="btn btn-success btn-small" onclick="restoreDevice('${escapeHtml(d.name)}')">
                                <i class="fas fa-undo"></i> Restore
                            </button>
                        </div>
                    </div>`;
            });
        }
        html += `</div></div>`;

        // Blocked Devices Column
        html += `
            <div class="card" style="border-color: rgba(239, 68, 68, 0.5);">
                <div class="card-header">
                    <div class="card-title">
                        <i class="fas fa-ban text-danger"></i>
                        Blocked Devices
                    </div>
                    <span class="status-badge status-off">${blocked.length} Blocked</span>
                </div>
                <div class="device-grid">`;

        if (blocked.length === 0) {
            html += `<div class="text-muted" style="grid-column: 1/-1; text-align: center; padding: 2rem;">No blocked devices</div>`;
        } else {
            blocked.forEach(d => {
                const blockedDate = new Date(d.blocked_at).toLocaleString();
                // Extract simple reason (remove hash details)
                let simpleReason = d.reason || 'Security threat detected';
                if (simpleReason.includes('SHA256:')) {
                    simpleReason = simpleReason.split('(SHA256:')[0].trim();
                }
                if (simpleReason.includes('in file')) {
                    const parts = simpleReason.split('in file');
                    simpleReason = parts[0].trim();
                    if (parts[1]) {
                        const filename = parts[1].trim();
                        simpleReason += ` (${filename})`;
                    }
                }
                
                html += `
                    <div class="device-card" style="border-color: var(--danger); background: rgba(239, 68, 68, 0.1);">
                        <div class="device-header">
                            <div>
                                <div class="device-name">🚫 ${escapeHtml(d.ip)}</div>
                                <div class="device-type font-mono text-danger">BLOCKED</div>
                            </div>
                        </div>
                        <div class="device-info" style="font-size: 0.85rem;">
                            <div style="margin-bottom: 0.3rem;"><span class="text-muted">Reason:</span> <strong>${escapeHtml(simpleReason)}</strong></div>
                            <div style="margin-bottom: 0.3rem;"><span class="text-muted">Blocked:</span> ${blockedDate}</div>
                            <div><span class="text-danger">⛔ Network Access Denied</span></div>
                        </div>
                        <div class="device-actions">
                            <button class="btn btn-success btn-small" onclick="unblockDevice('${escapeHtml(d.ip)}')">
                                <i class="fas fa-unlock"></i> Unblock
                            </button>
                        </div>
                    </div>`;
            });
        }
        html += `</div></div></div>`; // End grid

        container.innerHTML = html;
        refreshStatus();
    } catch (error) {
        console.error(error);
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
        const response = await fetch(`/api/devices/delete/${deviceId}`, { method: 'DELETE' });
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

async function unblockDevice(ip) {
    if (!confirm(`Unblock device ${ip}? This will allow it to rejoin the network.`)) return;
    showToast(`Unblocking ${ip}...`, 'success');
    try {
        const response = await fetch('/api/devices/unblock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        if (data.success) {
            setTimeout(refreshDevices, 1000);
        }
    } catch (error) {
        showToast('Error unblocking device', 'error');
    }
}

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
        showToast('Error restoring device', 'error');
    }
}

// Device Registry & Data
async function refreshDeviceRegistry() {
    try {
        const response = await fetch('/api/devices/registry');
        const data = await response.json();
        document.getElementById('stat-registered').textContent = data.count;
    } catch (error) {
        console.error('Error loading device registry:', error);
    }
}

async function refreshDeviceData() {
    try {
        const response = await fetch('/api/devices/data/latest?count=50');
        const data = await response.json();
        const tbody = document.getElementById('device-data-body');
        
        if (data.data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-muted" style="text-align: center; padding: 2rem;">No device data yet.</td></tr>';
            return;
        }

        tbody.innerHTML = data.data.reverse().map(entry => {
            const time = new Date(entry.timestamp).toLocaleTimeString();
            const sensorData = JSON.stringify(entry.sensor_data).substring(0, 100);
            return `
                <tr>
                    <td class="font-mono text-muted">${time}</td>
                    <td class="font-mono text-info">${entry.device_id}</td>
                    <td>${entry.device_type}</td>
                    <td class="font-mono">${entry.ip_address}</td>
                    <td class="font-mono text-muted" style="font-size: 0.85em;">${sensorData}...</td>
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
            logsDisplay.innerHTML = `<div class="log-entry text-danger">Error: ${data.message || 'Failed to load logs'}</div>`;
            return;
        }
        
        if (data.logs.length === 0) {
            logsDisplay.innerHTML = `<div class="log-entry text-muted">No attacker interactions logged yet. Waiting for attacks...</div>`;
            return;
        }

        logsDisplay.innerHTML = data.logs.map(log => {
            if (log.raw) {
                return `<div class="log-entry"><span class="text-muted">${log.time || ''}</span> | ${escapeHtml(log.msg || '')}</div>`;
            }
            
            const time = log.time || log.timestamp || 'N/A';
            const level = (log.level || 'info').toUpperCase();
            const message = log.msg || log.message || '';
            
            let levelClass = 'text-info';
            if (level === 'ERROR') levelClass = 'text-danger';
            if (level === 'WARN') levelClass = 'text-warning';
            
            return `
                <div class="log-entry">
                    <span class="text-muted">${time}</span> | 
                    <span class="${levelClass} font-bold">[${level}]</span> |
                    <span>${escapeHtml(message)}</span>
                    ${log.port ? `<span class="text-warning"> | Port: ${log.port}</span>` : ''}
                    ${log.commands ? `<span class="text-info"> | Cmd: ${log.commands}</span>` : ''}
                </div>
            `;
        }).join('');
        
        logsDisplay.scrollTop = logsDisplay.scrollHeight;
    } catch (error) {
        console.error('Error loading Beelzebub logs:', error);
    }
}

async function refreshBeelzebubStats() {
    try {
        const response = await fetch('/api/beelzebub/stats');
        const data = await response.json();
        
        document.getElementById('beelzebub-interactions').textContent = `${data.total_interactions} Interactions`;
        document.getElementById('beelzebub-services-count').textContent = `${data.services.length} Active`;
        
        updateStatusBadge('beelzebub-status', data.running);
        viewBeelzebubLogs();
        refreshAttackerDetails();
    } catch (error) {
        showToast('Error refreshing Beelzebub stats', 'error');
    }
}

// Attacker Details
async function refreshAttackerDetails() {
    try {
        const response = await fetch('/api/beelzebub/attackers');
        const data = await response.json();
        
        document.getElementById('attacker-total-attacks').textContent = data.total_attacks || 0;
        document.getElementById('attacker-unique-ips').textContent = data.unique_ips || 0;
        document.getElementById('attacker-credentials').textContent = data.credentials_tried.length || 0;
        document.getElementById('attacker-commands').textContent = data.commands_executed.length || 0;
        
        displayAttackersList(data.attackers || []);
        displayCredentialsList(data.credentials_tried || []);
        displayCommandsList(data.commands_executed || []);
        displayHttpRequestsList(data.http_requests || []);
    } catch (error) {
        console.error('Error refreshing attacker details:', error);
    }
}

function displayAttackersList(attackers) {
    const container = document.getElementById('attacker-list');
    if (!attackers || attackers.length === 0) {
        container.innerHTML = `<div class="text-muted" style="text-align: center; padding: 2rem;">No attackers detected yet</div>`;
        return;
    }
    
    container.innerHTML = attackers.map(attacker => `
        <div class="card" style="margin-bottom: 1rem; border-left: 4px solid var(--danger);">
            <div style="display: flex; justify-content: space-between; align-items: start;">
                <div>
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 0.5rem;">
                        <i class="fas fa-skull-crossbones text-danger"></i>
                        <strong class="text-danger" style="font-size: 1.1em;">${attacker.ip}</strong>
                        <span class="status-badge status-off">${attacker.total_interactions} interactions</span>
                    </div>
                    <div class="text-muted" style="font-size: 0.9em;">
                        <div><i class="fas fa-network-wired text-info"></i> Protocols: ${attacker.protocols.join(', ') || 'Unknown'}</div>
                        <div><i class="fas fa-clock"></i> Last Seen: ${new Date(attacker.last_seen).toLocaleString()}</div>
                    </div>
                </div>
            </div>
        </div>
    `).join('');
}

function displayCredentialsList(credentials) {
    const container = document.getElementById('credentials-list');
    if (!credentials || credentials.length === 0) {
        container.innerHTML = `<div class="text-muted" style="text-align: center; padding: 2rem;">No credential attempts captured</div>`;
        return;
    }
    
    container.innerHTML = credentials.map(cred => `
        <div style="background: rgba(245, 158, 11, 0.1); border-left: 3px solid var(--warning); padding: 1rem; margin-bottom: 0.5rem; border-radius: var(--radius-sm);">
            <div style="margin-bottom: 0.25rem;">
                <i class="fas fa-user text-warning"></i> <strong class="text-warning">User:</strong> <code class="font-mono">${cred.username || 'N/A'}</code>
            </div>
            <div>
                <i class="fas fa-key text-warning"></i> <strong class="text-warning">Pass:</strong> <code class="font-mono">${cred.password || 'N/A'}</code>
            </div>
        </div>
    `).join('');
}

function displayCommandsList(commands) {
    const container = document.getElementById('commands-list');
    if (!commands || commands.length === 0) {
        container.innerHTML = `<div class="text-muted" style="text-align: center; padding: 2rem;">No commands executed yet</div>`;
        return;
    }
    
    container.innerHTML = commands.map(cmd => `
        <div style="background: rgba(59, 130, 246, 0.1); border-left: 3px solid var(--info); padding: 1rem; margin-bottom: 0.5rem; border-radius: var(--radius-sm);">
            <div style="display: flex; align-items: center; gap: 0.5rem;">
                <i class="fas fa-terminal text-info"></i>
                <code class="font-mono text-info">$ ${cmd.command}</code>
            </div>
            <div class="text-muted" style="font-size: 0.8rem; margin-top: 0.25rem;">
                ${new Date(cmd.timestamp).toLocaleString()}
            </div>
        </div>
    `).join('');
}

function displayHttpRequestsList(requests) {
    const container = document.getElementById('http-requests-list');
    if (!requests || requests.length === 0) {
        container.innerHTML = `<div class="text-muted" style="text-align: center; padding: 2rem;">No HTTP requests captured</div>`;
        return;
    }
    
    container.innerHTML = requests.map(req => `
        <div style="background: rgba(16, 185, 129, 0.1); border-left: 3px solid var(--success); padding: 1rem; margin-bottom: 0.5rem; border-radius: var(--radius-sm);">
            <div style="display: flex; align-items: center; gap: 0.5rem;">
                <span class="status-badge status-on">${req.method || 'GET'}</span>
                <code class="font-mono text-success">${req.url || '/'}</code>
            </div>
            <div class="text-muted" style="font-size: 0.8rem; margin-top: 0.25rem;">
                UA: ${req.user_agent || 'Unknown'}
            </div>
        </div>
    `).join('');
}

// IP Rerouting
async function rerouteIPToBeelzebub() {
    const ipInput = document.getElementById('reroute-ip');
    const ipAddress = ipInput.value.trim();
    
    if (!ipAddress) { showToast('Please enter an IP address', 'error'); return; }
    if (!confirm(`Reroute ${ipAddress} to honeypot?`)) return;
    
    showToast(`Rerouting ${ipAddress}...`, 'success');
    try {
        const response = await fetch('/api/beelzebub/reroute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip_address: ipAddress })
        });
        const data = await response.json();
        if (data.success) {
            showToast('Successfully rerouted!', 'success');
            ipInput.value = '';
            setTimeout(refreshReroutes, 1000);
        } else {
            showToast(`Failed: ${data.message}`, 'error');
        }
    } catch (error) {
        showToast('Error rerouting IP', 'error');
    }
}

async function refreshReroutes() {
    try {
        const response = await fetch('/api/beelzebub/reroutes');
        const data = await response.json();
        
        const listDiv = document.getElementById('rerouted-ips-list');
        const countBadge = document.getElementById('reroute-count');
        const reroutes = data.active_reroutes || [];
        
        countBadge.textContent = `${reroutes.length} Rerouted`;
        countBadge.className = reroutes.length > 0 ? 'status-badge status-on' : 'status-badge status-off';
        
        if (reroutes.length > 0) {
            listDiv.innerHTML = reroutes.map(reroute => `
                <div class="card" style="margin-bottom: 1rem; border-left: 4px solid var(--danger); background: rgba(239, 68, 68, 0.05);">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
                                <strong class="text-danger">${reroute.container}</strong>
                                <span class="status-badge status-off">ISOLATED</span>
                            </div>
                            <div class="text-muted" style="font-size: 0.9em;">
                                <div>Original IP: ${reroute.ip}</div>
                                <div>Method: ${reroute.method}</div>
                            </div>
                        </div>
                        <button class="btn btn-success btn-small" onclick="removeReroute('${reroute.container}')">
                            Restore
                        </button>
                    </div>
                </div>
            `).join('');
        } else {
            listDiv.innerHTML = '<div class="text-muted" style="text-align: center; padding: 1rem;">No devices isolated.</div>';
        }
    } catch (error) {
        console.error('Error refreshing reroutes:', error);
    }
}

async function removeReroute(containerName) {
    if (!confirm(`Restore ${containerName} to Main Network?`)) return;
    showToast(`Restoring ${containerName}...`, 'success');
    try {
        const response = await fetch('/api/beelzebub/remove_reroute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ container_name: containerName })
        });
        const data = await response.json();
        if (data.success) {
            showToast('Restored successfully!', 'success');
            setTimeout(refreshReroutes, 1000);
        } else {
            showToast(`Failed: ${data.message}`, 'error');
        }
    } catch (error) {
        showToast('Error restoring container', 'error');
    }
}

// Attacker Controls
async function startAttackers() {
    showToast('Starting DOS attackers...', 'success');
    try {
        const response = await fetch('/api/attackers/start', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        setTimeout(refreshStatus, 2000);
    } catch (error) { showToast('Error starting attackers', 'error'); }
}

async function stopAttackers() {
    showToast('Stopping attackers...', 'success');
    try {
        const response = await fetch('/api/attackers/stop', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        setTimeout(refreshStatus, 2000);
    } catch (error) { showToast('Error stopping attackers', 'error'); }
}

async function startSSHAttacker() {
    showToast('Starting SSH brute force attacker...', 'success');
    try {
        const response = await fetch('/api/ssh_attacker/start', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        setTimeout(refreshStatus, 2000);
    } catch (error) { showToast('Error starting SSH attacker', 'error'); }
}

async function stopSSHAttacker() {
    showToast('Stopping SSH attacker...', 'success');
    try {
        const response = await fetch('/api/ssh_attacker/stop', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        setTimeout(refreshStatus, 2000);
    } catch (error) { showToast('Error stopping SSH attacker', 'error'); }
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
                logsOutput.textContent = `=== Container Logs ===\n\n${data.container_logs}\n\n=== Summary Log ===\n\n${data.summary_logs}`;
                logsContainer.style.display = 'block';
            } else { showToast('Failed to load logs', 'error'); }
        } catch (error) { showToast('Error loading SSH logs', 'error'); }
    } else { logsContainer.style.display = 'none'; }
}

// Malware Attacker
async function startMalwareAttacker() {
    showToast('Starting malware simulator...', 'success');
    try {
        const response = await fetch('/api/malware_attacker/start', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        setTimeout(() => { refreshStatus(); checkMalwareStatus(); }, 2000);
    } catch (error) { showToast('Error starting malware attacker', 'error'); }
}

async function stopMalwareAttacker() {
    showToast('Stopping malware simulator...', 'success');
    try {
        const response = await fetch('/api/malware_attacker/stop', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        setTimeout(() => { refreshStatus(); checkMalwareStatus(); }, 2000);
    } catch (error) { showToast('Error stopping malware attacker', 'error'); }
}

async function checkMalwareStatus() {
    try {
        const response = await fetch('/api/malware_attacker/status');
        const data = await response.json();
        updateStatusBadge('malware-attacker-status', data.running);
        
        const uploadStatus = document.getElementById('malware-upload-status');
        if (uploadStatus && data.behaviors) {
            const active = data.behaviors.malware_upload === 'Active';
            uploadStatus.textContent = active ? 'ACTIVE' : 'INACTIVE';
            uploadStatus.className = active ? 'text-success font-bold' : 'text-muted';
        }
    } catch (error) { console.error('Error checking malware status:', error); }
}

async function viewMalwareLogs() {
    const logsContainer = document.getElementById('malware-logs-container');
    if (logsContainer.style.display === 'none') {
        showToast('Loading malware logs...', 'info');
        try {
            const response = await fetch('/api/malware_attacker/logs');
            const data = await response.json();
            if (data.success) {
                document.getElementById('malware-logs-output').textContent = data.container_logs;
                document.getElementById('malware-beacon-logs').textContent = data.beacon_logs;
                document.getElementById('malware-exfil-logs').textContent = data.exfil_logs;
                document.getElementById('malware-eicar-logs').textContent = data.eicar_logs;
                document.getElementById('malware-dns-logs').textContent = data.dns_logs;
                logsContainer.style.display = 'block';
            } else { showToast('Failed to load logs', 'error'); }
        } catch (error) { showToast('Error loading malware logs', 'error'); }
    } else { logsContainer.style.display = 'none'; }
}

function showMalwareLog(logType) {
    document.querySelectorAll('.malware-log-section').forEach(s => s.style.display = 'none');
    document.getElementById(`malware-log-${logType}`).style.display = 'block';
}

// Endpoint Behavior Attacker
async function startEndpointBehaviorAttacker() {
    showToast('Starting endpoint behavior attacker...', 'success');
    try {
        const response = await fetch('/api/endpoint_behavior_attacker/start', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        setTimeout(() => { refreshStatus(); checkEndpointBehaviorStatus(); }, 2000);
    } catch (error) { showToast('Error starting endpoint behavior attacker', 'error'); }
}

async function stopEndpointBehaviorAttacker() {
    showToast('Stopping endpoint behavior attacker...', 'success');
    try {
        const response = await fetch('/api/endpoint_behavior_attacker/stop', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        setTimeout(() => { refreshStatus(); checkEndpointBehaviorStatus(); }, 2000);
    } catch (error) { showToast('Error stopping endpoint behavior attacker', 'error'); }
}

async function checkEndpointBehaviorStatus() {
    try {
        const response = await fetch('/api/endpoint_behavior_attacker/status');
        const data = await response.json();
        updateStatusBadge('endpoint-behavior-attacker-status', data.running);
        
        const behaviors = data.behaviors || {};
        const statusElements = {
            'endpoint-c2-status': 'c2_beacon',
            'endpoint-exfil-status': 'data_exfiltration',
            'endpoint-dns-status': 'dns_dga',
            'endpoint-portscan-status': 'port_scanning',
            'endpoint-api-status': 'api_abuse',
            'endpoint-cred-status': 'credential_harvesting',
            'endpoint-priv-status': 'privilege_escalation',
            'endpoint-lateral-status': 'lateral_movement',
            'endpoint-staging-status': 'data_staging'
        };
        
        Object.entries(statusElements).forEach(([elementId, behaviorKey]) => {
            const element = document.getElementById(elementId);
            if (element) {
                const isActive = behaviors[behaviorKey] === 'Active';
                element.textContent = isActive ? 'ACTIVE' : 'INACTIVE';
                element.className = isActive ? 'text-success font-bold' : 'text-muted';
            }
        });
    } catch (error) { console.error('Error checking endpoint behavior status:', error); }
}

async function viewEndpointBehaviorLogs() {
    const logsContainer = document.getElementById('endpoint-behavior-logs-container');
    if (logsContainer.style.display === 'none') {
        showToast('Loading logs...', 'info');
        try {
            const response = await fetch('/api/endpoint_behavior_attacker/logs');
            const data = await response.json();
            if (data.success) {
                document.getElementById('endpoint-behavior-logs-output').textContent = `${data.container_logs}\n\n${data.file_logs}`;
                logsContainer.style.display = 'block';
            } else { showToast('Failed to load logs', 'error'); }
        } catch (error) { showToast('Error loading logs', 'error'); }
    } else { logsContainer.style.display = 'none'; }
}

// Monitor Server
async function startMonitor() {
    showToast('Starting monitor...', 'success');
    try {
        const response = await fetch('/api/monitor/start', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        setTimeout(refreshStatus, 5000);
    } catch (error) { showToast('Error starting monitor', 'error'); }
}

async function stopMonitor() {
    showToast('Stopping monitor...', 'success');
    try {
        const response = await fetch('/api/monitor/stop', { method: 'POST' });
        const data = await response.json();
        showToast(data.message, data.success ? 'success' : 'error');
        setTimeout(refreshStatus, 2000);
    } catch (error) { showToast('Error stopping monitor', 'error'); }
}

async function refreshMonitorStatus() {
    try {
        const response = await fetch('/api/monitor/status');
        const data = await response.json();
        updateStatusBadge('monitor-status', data.running, 'stat-monitor');
        refreshStatus();
    } catch (error) { console.error('Error checking monitor status:', error); }
}

async function refreshMonitorLogs() {
    try {
        const response = await fetch('/api/monitor/logs');
        const data = await response.json();
        const logsDisplay = document.getElementById('monitor-logs');
        
        if (!data.success || !data.logs) {
            logsDisplay.innerHTML = '<div class="log-entry text-muted">No logs available.</div>';
            return;
        }

        const logLines = data.logs.split('\n').filter(line => line.trim());
        logsDisplay.innerHTML = logLines.slice(-100).map(line => `<div class="log-entry">${escapeHtml(line)}</div>`).join('');
        logsDisplay.scrollTop = logsDisplay.scrollHeight;
    } catch (error) { showToast('Error loading monitor logs', 'error'); }
}

async function checkMonitorHealth() {
    showToast('Checking monitor health...', 'success');
    try {
        const flaskResponse = await fetch('http://localhost:5002/health');
        if (flaskResponse.ok) {
            const data = await flaskResponse.json();
            showToast(`Monitor is healthy! Status: ${data.status}`, 'success');
        } else { showToast('Monitor not responding on port 5002', 'error'); }
    } catch (error) { showToast('Monitor is not running or not accessible', 'error'); }
}

// Helper function to escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Tab switching
function switchTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    
    const tabContent = document.getElementById(`tab-${tabName}`);
    if (tabContent) tabContent.classList.add('active');
    event.target.classList.add('active');
    
    if (tabName === 'device-data') refreshDeviceData();
    else if (tabName === 'monitor-logs') refreshMonitorLogsInTab();
    else if (tabName === 'beelzebub-logs') viewBeelzebubLogsInTab();
    else if (tabName === 'device-containers') refreshDeviceContainerLogs();
}

async function refreshMonitorLogsInTab() {
    try {
        const response = await fetch('/api/monitor/logs');
        const data = await response.json();
        const logsDisplay = document.getElementById('monitor-logs-tab');
        
        if (!data.success || !data.logs) {
            logsDisplay.innerHTML = '<div class="log-entry text-muted">No logs available.</div>';
            return;
        }
        const logLines = data.logs.split('\n').filter(line => line.trim());
        logsDisplay.innerHTML = logLines.slice(-100).map(line => `<div class="log-entry">${escapeHtml(line)}</div>`).join('');
        logsDisplay.scrollTop = logsDisplay.scrollHeight;
    } catch (error) { console.error('Error loading monitor logs:', error); }
}

// Page navigation
function showPage(pageName, event) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    
    document.getElementById(`page-${pageName}`).classList.add('active');
    if (event && event.target) event.target.classList.add('active');
    
    currentPage = pageName;
    if (pageName === 'network-map') refreshNetworkMap();
    else if (pageName === 'monitor') refreshMonitorStatus();
    else if (pageName === 'devices') refreshDevices();
    else if (pageName === 'beelzebub') { refreshBeelzebubStats(); refreshReroutes(); }
    else if (pageName === 'logs') refreshDeviceData();
}

async function viewBeelzebubLogsInTab() {
    try {
        const response = await fetch('/api/beelzebub/logs');
        const data = await response.json();
        const logsDisplay = document.getElementById('beelzebub-logs-tab');
        
        if (!data.success) {
            logsDisplay.innerHTML = `<div class="log-entry text-danger">Error: ${data.message || 'Failed to load logs'}</div>`;
            return;
        }
        if (data.logs.length === 0) {
            logsDisplay.innerHTML = `<div class="log-entry text-muted">No attacks logged yet.</div>`;
            return;
        }

        logsDisplay.innerHTML = data.logs.map(log => {
            if (log.raw) return `<div class="log-entry"><span class="text-muted">${log.time || ''}</span> | ${escapeHtml(log.msg || '')}</div>`;
            
            const level = (log.level || 'info').toUpperCase();
            let levelClass = 'text-info';
            if (level === 'ERROR') levelClass = 'text-danger';
            if (level === 'WARN') levelClass = 'text-warning';
            
            return `
                <div class="log-entry">
                    <span class="text-muted">${log.time || log.timestamp || 'N/A'}</span> | 
                    <span class="${levelClass} font-bold">[${level}]</span> |
                    <span>${escapeHtml(log.msg || log.message || '')}</span>
                </div>
            `;
        }).join('');
        logsDisplay.scrollTop = logsDisplay.scrollHeight;
    } catch (error) { console.error('Error loading Beelzebub logs:', error); }
}

async function refreshDeviceContainerLogs() {
    try {
        const response = await fetch('/api/devices/list');
        const data = await response.json();
        const container = document.getElementById('device-container-list');
        
        if (data.devices.length === 0) {
            container.innerHTML = '<p class="text-muted">No devices created yet.</p>';
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
    } catch (error) { showToast('Error loading device list', 'error'); }
}

async function viewDeviceContainerLogs(deviceName) {
    showToast(`Loading logs for ${deviceName}...`, 'success');
    try {
        const response = await fetch(`/api/containers/logs/${deviceName}`);
        const data = await response.json();
        const logsDisplay = document.getElementById('device-container-logs');
        
        if (!data.success || !data.logs) {
            logsDisplay.innerHTML = `<div class="log-entry text-muted">No logs available for ${deviceName}</div>`;
            return;
        }

        const logLines = data.logs.split('\n').filter(line => line.trim());
        logsDisplay.innerHTML = `
            <div class="log-entry text-warning font-bold">=== Logs for ${deviceName} ===</div>
            ${logLines.slice(-100).map(line => `<div class="log-entry">${escapeHtml(line)}</div>`).join('')}
        `;
        logsDisplay.scrollTop = logsDisplay.scrollHeight;
    } catch (error) { showToast('Error loading container logs', 'error'); }
}

// STOP ALL
function confirmStopAll() {
    if (!confirm('🚨 NUCLEAR OPTION - COMPLETE CLEANUP 🚨\n\nThis will PERMANENTLY DELETE ALL containers, images, and networks.\n\nAre you sure?')) return;
    if (!confirm('🔥 FINAL WARNING 🔥\n\nThis action CANNOT be undone. Proceed?')) return;
    stopAll();
}

async function stopAll() {
    showToast('🧨 Starting complete cleanup...', 'info');
    try {
        const response = await fetch('/api/cleanup/all', { method: 'POST' });
        const data = await response.json();
        if (data.success) {
            showToast('✅ Cleanup finished!', 'success');
            setTimeout(() => { refreshStatus(); refreshDevices(); }, 2000);
            alert('Cleanup complete. You must rebuild with docker-compose up!');
        } else { showToast('❌ Cleanup failed', 'error'); }
    } catch (error) { showToast('Error during cleanup', 'error'); }
}

// Network Map
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
    } catch (error) { console.error('Error refreshing network map:', error); }
}

function drawNetworkMap(data) {
    const svg = document.getElementById('network-svg');
    const width = svg.clientWidth || 1200;
    const height = 600;
    svg.setAttribute('width', width);
    svg.setAttribute('height', height);
    svg.innerHTML = '';
    
    const { nodes, connections } = data;
    const nodeColors = {
        'gateway': '#10b981', 'device': '#3b82f6', 'honeypot': '#f59e0b',
        'monitor': '#8b5cf6', 'attacker': '#ef4444', 'honeypot_network': '#fb923c',
        'honeypot_device': '#fdba74', 'other': '#6b7280'
    };
    
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) * 0.35;
    const positions = { 'gateway': { x: centerX, y: centerY } };
    
    const otherNodes = nodes.filter(n => n.id !== 'gateway');
    const angleStep = (2 * Math.PI) / (otherNodes.length || 1);
    
    otherNodes.forEach((node, index) => {
        const angle = index * angleStep;
        positions[node.id] = {
            x: centerX + radius * Math.cos(angle),
            y: centerY + radius * Math.sin(angle)
        };
    });
    
    connections.forEach(conn => {
        const from = positions[conn.from];
        const to = positions[conn.to];
        if (from && to) {
            const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
            line.setAttribute('x1', from.x); line.setAttribute('y1', from.y);
            line.setAttribute('x2', to.x); line.setAttribute('y2', to.y);
            line.setAttribute('stroke', conn.type === 'honeypot_network' ? '#fb923c' : '#374151');
            line.setAttribute('stroke-width', '2');
            if (conn.type === 'data') line.setAttribute('stroke-dasharray', '5,5');
            svg.appendChild(line);
        }
    });
    
    nodes.forEach(node => {
        const pos = positions[node.id];
        if (!pos) return;
        
        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', pos.x); circle.setAttribute('cy', pos.y);
        circle.setAttribute('r', node.type === 'gateway' ? 40 : 30);
        circle.setAttribute('fill', nodeColors[node.type] || nodeColors.other);
        circle.setAttribute('stroke', '#fff');
        circle.setAttribute('stroke-width', '3');
        circle.setAttribute('cursor', 'pointer');
        circle.addEventListener('click', () => showNodeDetails(node));
        svg.appendChild(circle);
        
        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', pos.x); text.setAttribute('y', pos.y - (node.type === 'gateway' ? 50 : 40));
        text.setAttribute('text-anchor', 'middle');
        text.setAttribute('fill', '#fff');
        text.setAttribute('font-size', '12');
        text.setAttribute('font-weight', 'bold');
        text.textContent = node.name.length > 25 ? node.name.substring(0, 25) + '...' : node.name;
        svg.appendChild(text);
    });
}

function showNodeDetails(node) {
    const detailsDiv = document.getElementById('node-details');
    detailsDiv.innerHTML = `
        <div class="card" style="padding: 1rem;">
            <h4 style="margin-bottom: 0.5rem; display: flex; align-items: center; gap: 0.5rem;">
                ${node.type === 'attacker' ? '💀' : node.type === 'device' ? '📱' : '🖥️'}
                ${escapeHtml(node.name)}
            </h4>
            <div style="display: grid; grid-template-columns: auto 1fr; gap: 0.5rem; font-size: 0.9em;">
                <span class="text-muted">ID:</span> <span>${escapeHtml(node.id)}</span>
                <span class="text-muted">Type:</span> <span style="text-transform: capitalize;">${escapeHtml(node.type)}</span>
                <span class="text-muted">IP:</span> <code class="font-mono">${escapeHtml(node.ip)}</code>
                <span class="text-muted">Status:</span> <span class="${node.status === 'running' ? 'text-success' : 'text-muted'} font-bold">${escapeHtml(node.status.toUpperCase())}</span>
            </div>
        </div>
    `;
}

// AI Agent
let agentQueriesCount = 0;

async function sendAgentQuery() {
    const input = document.getElementById('agent-query-input');
    const query = input.value.trim();
    if (!query) { showToast('Please enter a query', 'error'); return; }
    
    input.value = '';
    addAgentMessage('user', query);
    
    // Add tool progress tracking message
    const progressHtml = `
        <div class="tool-progress-container">
            <strong>🤖 Processing Query...</strong>
            <div id="tools-progress-list" class="tools-list"></div>
        </div>
    `;
    const thinkingId = addAgentMessage('agent', progressHtml, true);
    
    try {
        const response = await fetch('/api/agent/query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query })
        });
        
        const data = await response.json();
        
        removeAgentMessage(thinkingId);
        
        if (data.success) {
            // Parse tools from full_output if available
            if (data.full_output) {
                const toolMatches = data.full_output.match(/🔧\s+(\w+)/g);
                if (toolMatches && toolMatches.length > 0) {
                    // Show tools used (filter out DEBUG and duplicates)
                    const toolsUsed = [...new Set(toolMatches
                        .map(m => m.replace('🔧 ', '').trim())
                        .filter(t => t !== 'DEBUG' && t !== 'Tool' && !t.startsWith('DEBUG'))
                    )];
                    
                    if (toolsUsed.length > 0) {
                        const toolsText = '🔧 **Tools Used:**\n\n' + toolsUsed.map(t => `✅ ${t}`).join('\n');
                        addAgentMessage('agent', toolsText);
                    }
                }
            }
            
            // Show final response
            addAgentMessage('agent', data.response);
            agentQueriesCount++;
            document.getElementById('agent-queries-count').textContent = agentQueriesCount;
        } else {
            addAgentMessage('agent', `❌ Error: ${data.error}`);
        }
    } catch (error) {
        removeAgentMessage(thinkingId);
        addAgentMessage('agent', `❌ Error: ${error.message}`);
    }
}

function quickAgentQuery(query) {
    document.getElementById('agent-query-input').value = query;
    sendAgentQuery();
}

function addAgentMessage(role, content, isThinking = false) {
    const chatContainer = document.getElementById('agent-chat-messages');
    const messageId = `msg-${Date.now()}`;
    const messageDiv = document.createElement('div');
    
    // Check for warning keywords to apply orange style
    let isWarning = false;
    if (role === 'agent' && !isThinking) {
        const lowerContent = content.toLowerCase();
        if (lowerContent.includes('threat') || 
            lowerContent.includes('malware') || 
            lowerContent.includes('attack') || 
            lowerContent.includes('alert') ||
            lowerContent.includes('critical') ||
            lowerContent.includes('orange')) {
            isWarning = true;
        }
    }

    messageDiv.id = messageId;
    messageDiv.className = `agent-message ${role} ${isWarning ? 'warning' : ''}`;
    
    if (isThinking) messageDiv.style.opacity = '0.7';
    
    const icon = role === 'user' ? 'fa-user' : 'fa-robot';
    const title = role === 'user' ? 'You' : 'AI Security Agent';
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    
    messageDiv.innerHTML = `
        <div class="message-header">
            <i class="fas ${icon}"></i>
            <strong>${title}</strong>
            <span class="message-time">${time}</span>
        </div>
        <div class="message-content">
            ${role === 'agent' ? formatAgentResponse(content) : escapeHtml(content)}
        </div>
    `;
    
    chatContainer.appendChild(messageDiv);
    chatContainer.scrollTop = chatContainer.scrollHeight;
    return messageId;
}

function removeAgentMessage(messageId) {
    const message = document.getElementById(messageId);
    if (message) message.remove();
}

function formatAgentResponse(text) {
    // Use marked.js to parse markdown if available
    if (typeof marked !== 'undefined') {
        // Configure marked to break on single newlines
        marked.setOptions({
            breaks: true,
            gfm: true
        });
        
        let html = marked.parse(text);
        
        // Post-process for specific highlighting (IPs, devices)
        html = html.replace(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g, '<code class="font-mono text-info" style="background: rgba(59,130,246,0.1); padding: 2px 4px; border-radius: 3px;">$1</code>');
        html = html.replace(/device_\w+/gi, '<code class="font-mono text-success" style="background: rgba(16,185,129,0.1); padding: 2px 4px; border-radius: 3px;">$&</code>');
        
        return html;
    }

    // Fallback if marked is not loaded
    let formatted = escapeHtml(text);
    formatted = formatted.replace(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g, '<code class="font-mono text-info" style="background: rgba(59,130,246,0.1); padding: 2px 4px; border-radius: 3px;">$1</code>');
    formatted = formatted.replace(/device_\w+/gi, '<code class="font-mono text-success" style="background: rgba(16,185,129,0.1); padding: 2px 4px; border-radius: 3px;">$&</code>');
    return formatted;
}

function updateToolProgress(toolName, status = 'running') {
    const toolsList = document.getElementById('tools-progress-list');
    if (!toolsList) return;
    
    const toolId = `tool-${toolName.replace(/[^a-zA-Z0-9]/g, '-')}`;
    let toolItem = document.getElementById(toolId);
    
    if (!toolItem) {
        toolItem = document.createElement('div');
        toolItem.id = toolId;
        toolItem.className = 'tool-item';
        toolsList.appendChild(toolItem);
    }
    
    const icon = status === 'completed' ? '✅' : status === 'error' ? '❌' : '⚙️';
    const statusClass = status === 'completed' ? 'text-success' : status === 'error' ? 'text-danger' : 'text-info';
    
    toolItem.innerHTML = `<span class="${statusClass}">${icon} ${toolName}</span>`;
    
    if (status === 'completed' || status === 'error') {
        setTimeout(() => {
            toolItem.style.opacity = '0.6';
        }, 500);
    }
}

function clearAgentChat() {
    const chatContainer = document.getElementById('agent-chat-messages');
    chatContainer.innerHTML = '';
    agentQueriesCount = 0;
    document.getElementById('agent-queries-count').textContent = '0';
    showToast('Chat cleared', 'success');
}

function downloadChatHistory() {
    const messages = document.querySelectorAll('.agent-message');
    if (messages.length === 0) { showToast('No history', 'error'); return; }
    
    // Download as HTML with full styling (default)
    downloadChatAsHTML(messages);
}

function downloadChatAsHTML(messages) {
    const timestamp = new Date().toISOString().split('T')[0];
    
    // Build HTML with embedded CSS
    let html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Agent Chat History - ${timestamp}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
            padding: 2rem;
            line-height: 1.6;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
            background: #1e293b;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            padding: 2rem;
            text-align: center;
            color: white;
        }
        .header h1 { font-size: 1.8rem; margin-bottom: 0.5rem; }
        .header p { opacity: 0.9; font-size: 0.9rem; }
        .chat-messages {
            padding: 2rem;
            max-height: none;
            overflow-y: visible;
        }
        .agent-message {
            margin-bottom: 1.5rem;
            padding: 1.2rem;
            border-radius: 12px;
            animation: slideIn 0.3s ease;
        }
        .agent-message.user {
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            margin-left: 20%;
            border-bottom-right-radius: 4px;
        }
        .agent-message.agent {
            background: rgba(51, 65, 85, 0.8);
            border: 1px solid rgba(100, 116, 139, 0.3);
            margin-right: 20%;
            border-bottom-left-radius: 4px;
        }
        .agent-message.warning {
            border-left: 4px solid #f97316;
            background: rgba(251, 146, 60, 0.1);
        }
        .message-header {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.8rem;
            font-size: 0.85rem;
            opacity: 0.9;
        }
        .message-header i { font-size: 1rem; }
        .message-header strong { font-weight: 600; }
        .message-time {
            margin-left: auto;
            font-size: 0.75rem;
            opacity: 0.7;
        }
        .message-content {
            font-size: 0.95rem;
            line-height: 1.7;
        }
        .message-content h2, .message-content h3 {
            margin: 1rem 0 0.5rem 0;
            color: #60a5fa;
        }
        .message-content ul, .message-content ol {
            margin: 0.5rem 0;
            padding-left: 1.5rem;
        }
        .message-content li { margin: 0.3rem 0; }
        .message-content code {
            background: rgba(15, 23, 42, 0.6);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: #fbbf24;
        }
        .message-content pre {
            background: rgba(15, 23, 42, 0.8);
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            margin: 0.5rem 0;
            border-left: 3px solid #6366f1;
        }
        .message-content pre code {
            background: none;
            padding: 0;
            color: #e2e8f0;
        }
        .tool-progress-container {
            margin-top: 0.8rem;
            padding: 0.8rem;
            background: rgba(16, 185, 129, 0.1);
            border-left: 3px solid #10b981;
            border-radius: 6px;
        }
        .footer {
            text-align: center;
            padding: 1.5rem;
            background: rgba(15, 23, 42, 0.8);
            color: #94a3b8;
            font-size: 0.85rem;
            border-top: 1px solid rgba(100, 116, 139, 0.3);
        }
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🤖 AI Agent Chat History</h1>
            <p>Network Security Analysis Session - ${timestamp}</p>
        </div>
        <div class="chat-messages">
`;
    
    // Add each message with preserved HTML structure
    messages.forEach(msg => {
        html += msg.outerHTML + '\n';
    });
    
    html += `        </div>
        <div class="footer">
            Generated from Malware Detection Dashboard | ${new Date().toLocaleString()}
        </div>
    </div>
</body>
</html>`;
    
    // Download HTML file
    const blob = new Blob([html], { type: 'text/html' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `chat_history_${Date.now()}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    showToast('Downloaded as HTML (styled)', 'success');
}

function downloadChatAsTXT(messages) {
    let text = 'AI Agent Chat History\n=====================\n\n';
    messages.forEach(msg => {
        const isUser = msg.classList.contains('user');
        text += `[${isUser ? 'USER' : 'AGENT'}]\n${msg.innerText}\n\n----------------\n\n`;
    });
    
    const blob = new Blob([text], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `chat_history_${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    showToast('Downloaded as TXT (plain text)', 'success');
}

// Auto-refresh
setInterval(() => {
    refreshStatus();
    refreshDeviceRegistry();
    if (currentPage === 'network-map') refreshNetworkMap();
    else if (currentPage === 'monitor') refreshMonitorStatus();
    else if (currentPage === 'devices') refreshDevices();
    else if (currentPage === 'honeypot') { refreshBeelzebubStats(); refreshReroutes(); }
    else if (currentPage === 'logs') {
        const activeTab = document.querySelector('#page-logs .tab.active');
        if (activeTab) {
            const text = activeTab.textContent.trim();
            if (text.includes('Device Data')) refreshDeviceData();
            else if (text.includes('Monitor')) refreshMonitorLogsInTab();
            else if (text.includes('Honeypot')) viewBeelzebubLogsInTab();
        }
    }
}, 5000);

// Initial load
refreshStatus();
refreshDeviceRegistry();
