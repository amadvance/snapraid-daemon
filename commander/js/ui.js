
import { formatBytes, formatTime, formatSeconds, formatRelativeTime, formatDuration, formatAgoMins, formatAgoDays, formatSignal, Icons } from './utils.js';

/* --- Shared Components --- */
const badge = (text, color) => `<span class="badge badge-${color}">${text}</span>`;

const esc = (str) => str.replace(/'/g, "\\'");


const healthBadge = (health) => {
    const map = { passed: 'green', prefail: 'yellow', failing: 'red', pending: 'grey' };
    return badge(health, map[health] || 'grey');
};

const statusBadge = (task) => {
    const map = {
        queued: 'grey', starting: 'yellow', processing: 'blue',
        stopping: 'purple', finalizing: 'purple', terminated: 'green', canceled: 'red', signaled: 'red'
    };
    let color = map[task.status] || 'grey';

    if (task.status === 'terminated' && task.command === 'diff' && task.exit_code === 2) {
        return badge('differences', 'yellow');
    }

    if (task.status === 'terminated' && task.exit_code !== 0) {
        color = 'red';
    }

    return badge(task.status, color);
};

/**
 * Renders a temperature sparkline by measuring its parent container
 * to ensure a 1:1 pixel-accurate render.
 * * @param {string} containerId - The ID of the div to fill.
 * @param {Array} temperaturaArray - Array of integers (0 for standby).
 */
export function renderTempSparkline(containerId, temperaturaArray) {
    const container = document.getElementById(containerId);
    if (!container || !temperaturaArray || temperaturaArray.length === 0) return;

    // 1. Capture actual pixel dimensions
    const width = container.clientWidth;
    const height = container.clientHeight;

    // 2. Define Layout (Padding for labels)
    const margin = { top: 10, right: 10, bottom: 10, left: 35 };
    const chartWidth = width - margin.left - margin.right;
    const chartHeight = height - margin.top - margin.bottom;

    const dataLen = temperaturaArray.length;
    const maxIndex = dataLen > 1 ? dataLen - 1 : 1;

    // 3. Coordinate Math (Actual Pixels)
    const getY = (temp) => {
        const normalized = (temp - 20) / (70 - 20);
        return chartHeight - (normalized * chartHeight) + margin.top;
    };

    const getX = (index) => (index / maxIndex) * chartWidth + margin.left;

    const getColor = (temp) => {
        if (temp < 40) return '#00d2ff'; // Cyan
        if (temp < 50) return '#ffcc00'; // Amber
        return '#ff4d4d';                // Red
    };

    // 4. Build SVG String
    let svg = `<svg width="${width}" height="${height}" class="temp-sparkline">`;

    // Guide Rails & Labels (20, 45, 70)
    [20, 45, 70].forEach(level => {
        const yPos = getY(level);
        svg += `
            <text x="5" y="${yPos + 4}" font-size="10" fill="rgba(255,255,255,0.4)" style="font-family:sans-serif;">${level}°</text>
            <line x1="${margin.left}" y1="${yPos}" x2="${width - margin.right}" y2="${yPos}" 
                  stroke="rgba(255,255,255,0.3)" stroke-dasharray="2" />
        `;
    });

    // Render Dots
    temperaturaArray.forEach((temp, i) => {
        if (temp <= 0) return; // Handle Standby

        const x = getX(i);
        const y = getY(temp);

        // Calculate time based on 24h window (total 1440 mins)

        const minsAgo = Math.floor((maxIndex - i) * (1440 / maxIndex));

        svg += `<circle cx="${x}" cy="${y}" r="3.5" fill="${getColor(temp)}" data-tooltip="${formatAgoMins(minsAgo)}: ${temp}°C"></circle>`;
    });

    svg += `</svg>`;

    // 5. Inject into DOM
    container.innerHTML = svg;
}

/**
 * Renders a stacked histogram for scrub history.
 * @param {string} containerId - The ID of the div to fill.
 * @param {Object} history - The scrub history object from API.
 */
export function renderScrubHistory(containerId, history) {
    const container = document.getElementById(containerId);
    if (!container || !history || !history.points) return;

    const width = container.clientWidth;
    const height = 200; // Fixed vertical size

    const margin = { top: 20, right: 10, bottom: 30, left: 35 };
    const chartWidth = width - margin.left - margin.right;
    const chartHeight = height - margin.top - margin.bottom;

    const yMax = history.y_axis_high || 100;
    const xMin = history.x_axis_low;
    const xMax = history.x_axis_high;

    const getY = (val) => chartHeight - (val / yMax * chartHeight) + margin.top;
    const getX = (ago) => {
        // ago: oldest is xMin, current is xMax (0)
        const range = xMin - xMax;
        if (range === 0) return margin.left + chartWidth / 2;
        const normalized = (ago - xMax) / range;
        // Shift range so bars are fully to the right of the Y axis
        const availableWidth = chartWidth - barWidth;
        return (1 - normalized) * availableWidth + margin.left + barWidth / 2;
    };

    const barWidth = history.points.length > 1 ? (chartWidth / history.points.length) * 0.8 : 20;

    let svg = `<svg width="${width}" height="${height}" class="scrub-history">`;

    // Horizontal grid lines every 5%
    for (let i = 5; i <= yMax; i += 5) {
        const yPos = getY(i);
        svg += `
            <line x1="${margin.left}" y1="${yPos}" x2="${width - margin.right}" y2="${yPos}" 
                  stroke="rgba(255,255,255,0.30)" stroke-dasharray="4" />
        `;
    }

    // Horizontal grid lines every 1%
    for (let i = 1; i <= yMax; i += 1) {
        const yPos = getY(i);
        if (i % 5 != 0)
            svg += `
            <line x1="${margin.left}" y1="${yPos}" x2="${width - margin.right}" y2="${yPos}" 
                  stroke="rgba(255,255,255,0.10)" stroke-dasharray="2" />
        `;
    }


    // Draw Axes
    svg += `
        <line x1="${margin.left}" y1="${margin.top}" x2="${margin.left}" y2="${height - margin.bottom}" stroke="rgba(255,255,255,0.4)" stroke-width="1" />
        <line x1="${margin.left}" y1="${height - margin.bottom}" x2="${width - margin.right}" y2="${height - margin.bottom}" stroke="rgba(255,255,255,0.4)" stroke-width="1" />
    `;

    // Y Axis High Label
    svg += `<text x="${margin.left - 5}" y="${getY(yMax) + 4}" font-size="12" fill="rgba(255,255,255,0.6)" text-anchor="end" style="font-family:sans-serif; font-weight:bold;">${Math.floor(yMax)}%</text>`;

    // X Axis Labels
    svg += `
        <text x="${margin.left}" y="${height - 10}" font-size="12" fill="rgba(255,255,255,0.6)" text-anchor="start" style="font-family:sans-serif; font-weight:bold;">${xMin}</text>
        <text x="${margin.left + chartWidth / 2}" y="${height - 10}" font-size="12" fill="rgba(255,255,255,0.6)" text-anchor="middle" style="font-family:sans-serif; font-weight:bold;">days ago</text>
        <text x="${margin.left + chartWidth}" y="${height - 10}" font-size="12" fill="rgba(255,255,255,0.6)" text-anchor="end" style="font-family:sans-serif; font-weight:bold;">${xMax}</text>
    `;

    // Render Bars
    history.points.forEach(p => {
        // If both are 0, the prompt says "do try to draw the bar". 
        // We'll proceed but it will have 0 height unless we force it.
        // Usually "do try" means don't skip the logic.

        const x = getX(p.ago) - barWidth / 2;

        const hScrubbed = (p.scrubbed / yMax) * chartHeight;
        const hNew = (p.new / yMax) * chartHeight;

        const yScrubbed = chartHeight - hScrubbed + margin.top;
        const yNew = chartHeight - hScrubbed - hNew + margin.top;

        if (p.scrubbed > 0) {
            svg += `<rect x="${x}" y="${yScrubbed}" width="${barWidth}" height="${hScrubbed}" fill="#10b981" stroke="rgba(0,0,0,0.5)" stroke-width="1" data-tooltip="${formatAgoDays(p.ago)}: ${p.scrubbed.toFixed(1)}% scrub"></rect>`;
        }
        if (p.new > 0) {
            svg += `<rect x="${x}" y="${yNew}" width="${barWidth}" height="${hNew}" fill="#3b82f6" stroke="rgba(0,0,0,0.5)" stroke-width="1" data-tooltip="${formatAgoDays(p.ago)}: ${p.new.toFixed(1)}% sync"></rect>`;
        }
    });

    svg += `</svg>`;
    container.innerHTML = svg;
}

const renderSystemCard = (system) => {
    if (!system) return '';

    const totalMem = system.memory_total_bytes || 0;
    const freeMem = system.memory_free_bytes || 0;
    const usedMem = totalMem - freeMem;
    const memPercent = totalMem > 0 ? (usedMem / totalMem * 100) : 0;

    return `
        <div class="card">
            <h3 class="font-bold mb-4 border-b border-slate-700 pb-2 text-cyan">System</h3>
            <div class="property-list">
                 <div class="property-row">
                    <div class="property-label">Uptime</div>
                    <div class="property-value">${formatSeconds(system.uptime_seconds)}</div>
                 </div>
                 <div class="property-row">
                    <div class="property-label">Memory</div>
                    <div class="property-value">
                        <div class="flex justify-between text-xs mb-1">
                            <span>${formatBytes(usedMem)} / ${formatBytes(totalMem)}</span>
                            <span>${system.is_ecc ? '(ECC)' : ''}</span>
                        </div>
                        <div class="progress-container" style="height: 6px; margin: 0;">
                            <div class="progress-bar" style="width: ${memPercent}%"></div>
                        </div>
                    </div>
                 </div>
                 <div class="property-row">
                    <div class="property-label">Hostname</div>
                    <div class="property-value text-sm">${system.hostname}</div>
                 </div>
                 <div class="property-row">
                    <div class="property-label">OS</div>
                    <div class="property-value text-sm">${system.os_distribution}</div>
                 </div>
                 <div class="property-row">
                    <div class="property-label">Kernel</div>
                    <div class="property-value text-sm font-mono">${system.os_kernel_version}</div>
                 </div>
                 <div class="property-row">
                    <div class="property-label">CPU</div>
                    <div class="property-value text-xs">${system.cpu_model}</div>
                 </div>
                 <div class="property-row">
                    <div class="property-label">Motherboard</div>
                    <div class="property-value text-xs">${system.motherboard || 'Unknown'}</div>
                 </div>
            </div>
        </div>
    `;
};

/* --- Dashboard --- */
export const renderDashboard = (arrayInfo, activity, systemInfo) => {
    const pulseAt = arrayInfo.pulse?.current_at;
    // 1. Hero: Activity
    let heroHtml = '';
    const active = activity && activity.status !== 'terminated' && activity.status !== 'signaled' && activity.status !== 'canceled';

    if (active) {
        heroHtml = `
            <div class="card glow">
                <div class="flex justify-between mb-4">
                    <div>
                        <h3 class="text-xl font-bold text-cyan">ACTIVE: ${activity.command.toUpperCase()}</h3>
                        <div class="text-sm text-muted">Started: ${formatTime(activity.started_at, pulseAt)}</div>
                    </div>
                    <div>${statusBadge(activity)}</div>
                </div>
                
                ${activity.status === 'processing' ? `
                <div class="progress-container">
                    <div class="progress-bar" style="width: ${activity.progress || 0}%"></div>
                </div>
                <div class="flex justify-between text-sm mb-4">
                    <span>${activity.progress || 0}% Complete</span>
                    <span>ETA: ${formatSeconds(activity.eta_seconds)}</span>
                </div>

                <div class="grid-4 mb-4">
                    <div><span class="text-muted block text-xs">Speed</span><span class="font-bold"> ${activity.speed_mbs || 0} MB/s</span></div>
                    <div><span class="text-muted block text-xs">Processed</span><span class="font-bold"> ${formatBytes(activity.size_done_bytes || 0)}</span></div>
                    <div><span class="text-muted block text-xs">CPU</span><span class="font-bold"> ${activity.cpu_usage || 0}%</span></div>
                </div>
                ` : ''}

                <div class="log-window">
                    <div class="text-xs text-muted mb-2">LIVE MESSAGES</div>
                    ${(activity.messages || []).map(m => {
            const isError = m.level === 'error' || m.level === 'fatal';
            const colorClass = isError ? 'text-red' : 'text-cyan';
            const typeBadge = m.type === 'hardware' ? `<span class="badge badge-red text-[10px] mr-1">HARDWARE FAILURE</span>` : '';
            return `<div class="log-line ${colorClass}">${typeBadge} ${m.text}</div>`;
        }).join('')}
                </div>
            </div>
        `;
    } else {
        // Show Last Activity
        const last = activity;
        heroHtml = `
            <div class="card">
                <h3 class="text-lg font-bold mb-2 text-cyan">System Idle</h3>
                <p class="text-muted text-sm mb-4">Last task finished execution.</p>
                ${last ? `
                    <div class="flex items-center gap-4 text-sm bg-slate-800 p-3 rounded">
                        <span class="font-bold text-cyan">${last.command.toUpperCase()}</span>
                        ${healthBadge(last.health)} ${statusBadge(last)}
                        <span class="text-muted">${formatDuration(last.started_at, last.finished_at)} duration</span>
                        <span class="text-muted">Ended: ${formatTime(last.finished_at, pulseAt)}</span>
                    </div>
                ` : '<p class="text-muted">No history available.</p>'}
            </div>
        `;
    }

    // 2. Array Summary Card
    const totalSpace = arrayInfo.total_space_bytes || 0;
    const freeSpace = arrayInfo.free_space_bytes || 0;
    const usedSpace = totalSpace - freeSpace;
    const percentUsed = totalSpace > 0 ? (usedSpace / totalSpace * 100) : 0;

    const parityLabels = [
        '', 'SINGLE PARITY', 'DOUBLE PARITY', 'TRIPLE PARITY',
        'QUAD PARITY', 'PENTA PARITY', 'HEXA PARITY'
    ];
    let parityColor = 'yellow'; // default to gold
    if (arrayInfo.parity_disks_count === 1)
        parityColor = 'purple';
    else if (arrayInfo.parity_disks_count === 2)
        parityColor = 'blue';

    const parityBadgeHtml = arrayInfo.parity_disks_count > 0
        ? badge(parityLabels[arrayInfo.parity_disks_count] || `${arrayInfo.parity_disks_count}-LEVEL PARITY`, parityColor)
        : '';

    const arrayStatusHtml = `
        <div class="card">
            <div class="flex gap-4 items-center mb-4">
                <h3 class="text-xl font-bold text-cyan">Array</h3>
                <div class="text-2xl font-bold flex gap-4 items-center">${healthBadge(arrayInfo.health)} ${parityBadgeHtml}</div>
            </div>

            <div class="mb-6">
                <div class="flex justify-between text-sm mb-2">
                    <span class="text-muted">Storage Usage</span>
                    <span class="font-mono">${formatBytes(usedSpace)} / ${formatBytes(totalSpace)}</span>
                </div>
                <div class="progress-container">
                    <div class="progress-bar" style="width: ${percentUsed}%"></div>
                </div>
                <div class="text-right text-xs text-muted mt-1">
                    ${formatBytes(freeSpace)} free
                </div>
            </div>

            <div class="property-list">
                <div class="property-row">
                    <div class="property-label">Bad Blocks</div>
                    <div class="property-value ${arrayInfo.blocks_bad > 0 ? 'text-red' : 'text-emerald'}">
                        ${arrayInfo.blocks_bad}
                        ${arrayInfo.blocks_bad > 0 ? `<span class="text-xs text-muted ml-2">(${formatBytes(arrayInfo.blocks_bad * arrayInfo.block_size_bytes * arrayInfo.data_disks_count)})</span>` : ''}
                    </div>
                </div>
                <div class="property-row">
                    <div class="property-label">Unsynced Blocks</div>
                    <div class="property-value ${arrayInfo.blocks_unsynced > 0 ? 'text-yellow' : 'text-emerald'}">
                        ${arrayInfo.blocks_unsynced}
                        ${arrayInfo.blocks_unsynced > 0 ? `<span class="text-xs text-muted ml-2">(${formatBytes(arrayInfo.blocks_unsynced * arrayInfo.block_size_bytes * arrayInfo.data_disks_count)})</span>` : ''}
                    </div>
                </div>
                <div class="property-row">
                    <div class="property-label">Failure Probability (1yr)</div>
                    <div class="property-value text-cyan">${arrayInfo.failure_probability
            ? `${(arrayInfo.failure_probability * 100).toFixed(0)}%`
            : healthBadge('pending')}</div>
                </div>
                <div class="property-row">
                    <div class="property-label">Scrubbed</div>
                    <div class="property-value text-cyan">
                        ${arrayInfo.blocks_count > 0 ? (100 * (1 - arrayInfo.blocks_unscrubbed / arrayInfo.blocks_count)).toFixed(0) : 0}%
                    </div>
                </div>
                <div class="property-row">
                    <div class="property-label">Total Files</div>
                    <div class="property-value text-cyan">${arrayInfo.files_count.toLocaleString()}</div>
                </div>
            </div>
        </div>
    `;

    const configHtml = `
        <div class="card">
            <h3 class="font-bold mb-4 border-b border-slate-700 pb-2 text-cyan">Configuration</h3>
            <div class="property-list">
                 <div class="property-row">
                    <div class="property-label">Daemon Version</div>
                    <div class="property-value">${arrayInfo.daemon_version}</div>
                 </div>
                 <div class="property-row">
                    <div class="property-label">Daemon Configuration</div>
                    <div class="property-value font-mono text-xs">${arrayInfo.daemon_conf}</div>
                 </div>
                 <div class="property-row">
                    <div class="property-label">Engine Version</div>
                    <div class="property-value">${arrayInfo.engine_version}</div>
                 </div>
                 <div class="property-row">
                    <div class="property-label">Engine Configuration</div>
                    <div class="property-value font-mono text-xs">${arrayInfo.engine_conf}</div>
                 </div>
                 <div class="property-row">
                    <div class="property-label">Engine Content</div>
                    <div class="property-value font-mono text-xs">${arrayInfo.engine_content}</div>
                 </div>
            </div>
        </div>
    `;

    const scrubHistoryHtml = arrayInfo.scrub_history ? `
        <div class="card mt-4">
            <h3 class="font-bold mb-4 text-cyan">Maintenance History</h3>
            <div id="scrub-history-graph" class="scrub-history-container" style="height: 200px; width: 100%;"></div>
            <div class="property-list mt-4 border-t border-slate-800 pt-4">
                <div class="property-row">
                    <div class="property-label">Oldest block</div>
                    <div class="property-value text-cyan">
                        ${arrayInfo.scrub_history.x_axis_low > 0 ? arrayInfo.scrub_history.x_axis_low : 0} <span class="text-sm">days ago</span>
                    </div>
                </div>
                <div class="property-row">
                    <div class="property-label">Median block</div>
                    <div class="property-value text-cyan">
                        ${arrayInfo.scrub_history.x_axis_median > 0 ? arrayInfo.scrub_history.x_axis_median : 0} <span class="text-sm">days ago</span>
                    </div>
                </div>
            </div>
        </div>
    ` : '';

    const summaryHtml = `
        <div class="grid-2">
            ${arrayStatusHtml}
            ${scrubHistoryHtml}
            ${renderSystemCard(systemInfo)}
            ${configHtml}
        </div>
    `;

    return `
        <div class="fade-in">
            ${heroHtml}
            ${summaryHtml}
        </div>
    `;
};

/* --- Differences --- */
export const renderDifferences = (arrayInfo) => {
    const diffColorMap = {
        added: 'text-emerald',
        removed: 'text-red',
        updated: 'text-amber',
        moved: 'text-cyan',
        copied: 'text-cyan',
        restored: 'text-emerald',
        equal: 'text-muted'
    };

    const diffFilesRows = (arrayInfo.diffs || []).map(d => {
        const colorClass = diffColorMap[d.change] || 'text-muted';
        const isRemoved = d.change === 'removed';
        return `
            <tr>
                <td class="text-xs font-bold ${colorClass}">${d.change.toUpperCase()}</td>
                <td class="text-xs font-mono">${d.disk}</td>
                <td class="text-xs break-all">
                    <div class="flex justify-between items-center">
                        <span>${d.path}</span>
                        ${isRemoved ? `<button class="btn btn-primary btn-sm ml-2" data-tooltip="Restore only this specific deleted file" onclick="app.triggerUndelete('${esc(d.path)}')">Undelete</button>` : ''}
                    </div>
                </td>
            </tr>
        `;
    }).join('');

    return `
        <div class="fade-in">
            <div class="card">
                <div class="mb-4 border-b border-slate-700 pb-2">
                    <h3 class="font-bold text-cyan">Change Summary</h3>
                    <div class="text-sm text-muted mt-2 italic">
                        These differences represent changes since the last sync. They will be cleared once the next maintenance cycle completes.
                    </div>
                    <div class="text-sm text-muted mt-1">Last updated: ${formatRelativeTime(arrayInfo.last_diff_at, arrayInfo.pulse?.current_at)}</div>
                </div>
                <div class="property-list mt-0 pt-0 border-t-0">
                    <div class="property-row">
                        <div class="property-label">Equal</div>
                        <div class="property-value">${arrayInfo.diff_equal}</div>
                    </div>
                    ${arrayInfo.diff_restored > 0 ? `
                    <div class="property-row">
                        <div class="property-label">Restored</div>
                        <div class="property-value text-emerald">${arrayInfo.diff_restored}</div>
                    </div>` : ''}
                    ${arrayInfo.diff_added > 0 ? `
                    <div class="property-row">
                        <div class="property-label">Added</div>
                        <div class="property-value text-emerald">${arrayInfo.diff_added}</div>
                    </div>` : ''}
                    ${arrayInfo.diff_removed > 0 ? `
                    <div class="property-row">
                        <div class="property-label">Removed</div>
                        <div class="property-value text-red">${arrayInfo.diff_removed}</div>
                    </div>` : ''}
                    ${arrayInfo.diff_updated > 0 ? `
                    <div class="property-row">
                        <div class="property-label">Updated</div>
                        <div class="property-value text-amber">${arrayInfo.diff_updated}</div>
                    </div>` : ''}
                    ${arrayInfo.diff_moved > 0 ? `
                    <div class="property-row">
                        <div class="property-label">Moved</div>
                        <div class="property-value text-cyan">${arrayInfo.diff_moved}</div>
                    </div>` : ''}
                    ${arrayInfo.diff_copied > 0 ? `
                    <div class="property-row">
                        <div class="property-label">Copied</div>
                        <div class="property-value text-cyan">${arrayInfo.diff_copied}</div>
                    </div>` : ''}
                </div>

                <h4 class="text-xs font-bold text-muted uppercase mb-2 mt-6">Changed Files</h4>
                <div class="overflow-x-auto">
                    <table class="data-table dense">
                        <thead>
                            <tr>
                                <th style="width: 80px">Change</th>
                                <th style="width: 100px">Disk</th>
                                <th>Path</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${diffFilesRows || '<tr><td colspan="3" class="text-center text-muted p-4">No file changes recorded</td></tr>'}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    `;
};

/* --- Disks --- */
const renderDiskCard = (disk, type, pulseAt) => {
    const borderClass = type === 'parity' ? 'card-border-purple' : 'card-border-blue';

    const errorBadges = [];
    if (disk.error_io > 0) errorBadges.push(`<div class="text-xs text-red font-bold">I/O Errors: ${disk.error_io}</div>`);
    if (disk.error_data > 0) errorBadges.push(`<div class="text-xs text-amber font-bold">Data Errors: ${disk.error_data}</div>`);

    const percentUsed = (disk.total_space_bytes - disk.free_space_bytes) / disk.total_space_bytes * 100;

    const devicesHtml = disk.devices.map(dev => {
        const smartIssues = [];
        if (dev.error_medium > 0) {
            smartIssues.push(`error_medium: ${dev.error_medium}`);
        }
        if (dev.error_protocol > 0) {
            smartIssues.push(`error_protocol: ${dev.error_protocol}`);
        }
        if (dev.smart) {
            ['reallocated_sector_count', 'uncorrectable_error_cnt', 'command_timeout', 'current_pending_sector', 'offline_uncorrectable'].forEach(k => {
                if (dev.smart[k] > 0) smartIssues.push(`${k}: ${dev.smart[k]}`);
            });
        }

        let smartStatus = '<span class="text-emerald font-bold text-xs">SMART PASSED</span>';
        if (dev.smart && dev.smart.failing)
            smartStatus = `<span class="badge badge-red">SMART FAILING</span>`;
        else if (dev.smart && dev.smart.prefail)
            smartStatus = `<span class="badge badge-yellow">SMART PREFAIL</span>`;
        else if (dev.smart && dev.smart.prefail_logged)
            smartStatus = `<span class="text-grey font-bold text-xs">SMART PASSED (but PREFAIL logged)</span>`;
        else if (dev.smart && dev.smart.error_logged)
            smartStatus = `<span class="text-grey font-bold text-xs">SMART PASSED (but ERROR logged)</span>`;
        else if (dev.smart && dev.smart.selftest_error_logged)
            smartStatus = `<span class="text-grey font-bold text-xs">SMART PASSED (but SELFTEST ERROR logged)</span>`;

        if (smartIssues.length > 0) smartStatus += `<div class="text-amber text-xs">${smartIssues.join('<br>')}</div>`;

        const temp = dev.smart?.temperature_celsius;
        const tempClass = temp >= 50 ? 'text-red font-bold' : (temp >= 40 ? 'text-yellow font-bold' : '');
        const powerClass = temp >= 50 ? 'active-red' : (temp >= 40 ? 'active-yellow' : 'active-cyan');
        const tempStr = temp !== undefined ? `${temp}°C` : '-';

        let sparklinePlaceholder = '';
        if (dev.temp_history_24h) {
            const safeId = dev.device_node.replace(/[^a-z0-9]/gi, '-');
            sparklinePlaceholder = `<div id="sparkline-${safeId}" class="temp-sparkline-row temp-sparkline-container" style="width: 100%;"></div>`;
        }

        return `
            <div class="bg-slate-950 p-3 rounded mt-2 border border-slate-800 text-sm">
                <div class="flex justify-between mb-1">
                     <span class="font-mono text-cyan">${dev.device_node}</span>
                     <div>${badge(dev.power, dev.power === 'active' ? powerClass : 'blue')} ${healthBadge(dev.health)}</div>
                </div>
                <div class="text-xs text-muted mb-2">${dev.model || 'Unknown Model'} (${dev.serial || '-'})</div>
                
                <div class="flex gap-4 mb-2 temp-sparkline-row" style="align-items: center;">
                    <div style="flex-shrink: 0; white-space: nowrap;" class="text-xs text-muted">
                         <div><span class="${tempClass}">${tempStr}</span> <span class="text-muted ml-1">(${formatRelativeTime(dev.smart?.measured_at, pulseAt)})</span></div>
                         <div class="text-muted mt-1">
                            ${dev.rotational ? 'HDD' : 'SSD'} (${dev.rotational ? (dev.failure_probability * 100).toFixed(0) + '% Fail Prob' : dev.wear_level + '% Wear'})
                         </div>
                    </div>
                    <div style="flex: 1; height: 100%; min-width: 0;">
                        ${sparklinePlaceholder}
                    </div>
                </div>

                ${smartStatus}
            </div>
        `;
    }).join('');

    return `
        <div class="card card-disk ${borderClass}">
            <div class="flex justify-between mb-2">
                <h3 class="font-bold text-lg">${disk.name}</h3>
                ${healthBadge(disk.health)}
            </div>
            <div class="text-xs font-mono text-muted mb-3 break-all">${disk.splits.map(s => {
        const labelPart = s.label ? `${s.label}:` : '';
        const typePart = s.type ? ` (${s.type})` : '';
        return `${labelPart}${s.path}${typePart}`;
    }).join(', ')}</div>
            
            ${errorBadges.join('')}

            <div class="mb-1 flex justify-between text-xs">
                <span>Usage</span>
                <span>${formatBytes(disk.total_space_bytes - disk.free_space_bytes)} / ${formatBytes(disk.total_space_bytes)}</span>
            </div>
            <div class="progress-container mb-4">
                <div class="progress-bar" style="width: ${percentUsed}%"></div>
            </div>

            ${devicesHtml}
        </div>
    `;
};

export const renderDisks = (data) => {
    const pulseAt = data.pulse?.current_at;
    return `
        <h3 class="text-xl font-bold mb-4">Parity Disks</h3>
        <div class="grid-fill-2 mb-8">${data.parity_disks.map(d => renderDiskCard(d, 'parity', pulseAt)).join('')}</div>
        
        <h3 class="text-xl font-bold mb-4">Data Disks</h3>
        <div class="grid-fill-2">${data.data_disks.map(d => renderDiskCard(d, 'data', pulseAt)).join('')}</div>
    `;
};

/* --- Tasks --- */
export const renderTasks = (data, hidePeriodic) => {
    const { active, pending, history } = data;
    const pulseAt = data.pulse?.current_at;

    const filteredHistory = hidePeriodic
        ? history.filter(t => t.command !== 'probe')
        : history;

    const queueRows = pending.length ? pending.reverse().map(t => `
        <tr>
            <td class="font-mono text-muted">#${t.number}</td>
            <td class="font-bold text-cyan">${t.command}</td>
            <td>${statusBadge(t)}</td>
            <td class="text-muted">${formatTime(t.scheduled_at, pulseAt)}</td>
        </tr>
    `).join('') : `<tr><td colspan="4" class="text-center text-muted p-4">No tasks in queue</td></tr>`;

    const activeRows = active.length ? active.map(t => {
        const now = new Date();
        const duration = t.started_at ? formatDuration(t.started_at, now) : '-';
        const progress = t.progress !== undefined ? `${t.progress}%` : '';
        const eta = t.eta_seconds !== undefined ? formatSeconds(t.eta_seconds) : '-';

        return `
            <tr>
                <td class="font-mono text-muted">#${t.number}</td>
                <td class="font-bold text-cyan">${t.command}</td>
                <td>${statusBadge(t)}</td>
                <td class="text-muted">${formatTime(t.started_at, pulseAt)}</td>
                <td class="text-muted">${duration}</td>
                <td class="font-bold">${progress}</td>
                <td class="text-cyan">${eta}</td>
            </tr>
        `;
    }).join('') : `<tr><td colspan="7" class="text-center text-muted p-4">No active tasks</td></tr>`;

    const historyRows = filteredHistory.length ? filteredHistory.reverse().map(t => {
        let exitStatus = '';
        if (t.status === 'terminated' && t.exit_code !== 0) {
            exitStatus = `<div class="text-yellow mb-1">Exit Code: ${t.exit_code}</div>`;
        } else if (t.status === 'signaled') {
            exitStatus = `<div class="text-yellow mb-1">Exit Signal: ${formatSignal(t.exit_sig)}</div>`;
        }

        return `
        <tr>
            <td class="font-mono text-muted">#${t.number}</td>
            <td class="font-bold text-cyan">${t.command}</td>
            <td>${healthBadge(t.health)}</td>
            <td>${statusBadge(t)}</td>
            <td class="text-muted text-xs">${formatTime(t.started_at, pulseAt)}</td>
            <td class="text-muted text-xs">${formatDuration(t.started_at, t.finished_at)}</td>
            <td>
                <button class="btn btn-secondary btn-xs" data-tooltip="View execution logs and exit status"
                    onclick="document.getElementById('log-${t.number}').classList.toggle('hidden')">
                    Details
                </button>
            </td>
        </tr>
        <tr id="log-${t.number}" class="hidden bg-slate-900">
            <td colspan="7" style="padding: 0;">
                <div class="text-xs font-mono bg-slate-950 p-4 border-b border-slate-800 shadow-inner">
                     ${exitStatus}
                      ${t.log_file && t.log_file !== 'N/A' ? `
                      <div class="text-muted mb-2 border-b border-slate-800 pb-2">
                         <span class="font-bold">Log File: ${t.log_file}</span>
                      </div>
                      ` : ''}
                     <div class="overflow-x-auto">
                        ${(t.messages || []).length > 0
                ? (t.messages || []).map(m => {
                    const isError = m.level === 'error' || m.level === 'fatal';
                    const colorClass = isError ? 'text-red' : 'text-cyan';
                    const typeBadge = m.type === 'hardware' ? `<span class="badge badge-red text-[10px] mr-1">HARDWARE FAILURE</span>` : '';
                    return `<div class="${colorClass} break-all mb-1 font-mono">${typeBadge} ${m.text}</div>`;
                }).join('')
                : (t.report_output ? '' : '<div class="text-cyan">No logged messages.</div>')}
                        ${t.report_output ? `
                        <div class="mt-4 pt-4 border-t border-slate-800 font-mono text-cyan whitespace-pre-wrap">${t.report_output}</div>
                        ` : ''}
                     </div>
                </div>
            </td>
        </tr>
    `;
    }).join('') : `<tr><td colspan="7" class="text-center text-muted p-4">No tasks in history</td></tr>`;

    return `
        <div class="card">
            <h3 class="font-bold mb-4 flex items-center gap-2 text-cyan">
                <span class="icon-sm">${Icons.activity}</span> Queue
                <span class="badge badge-grey text-xs ml-auto">${pending.length}</span>
            </h3>
            <div class="overflow-x-auto">
                <table class="data-table dense">
                    <thead><tr><th style="width:50px">ID</th><th>Command</th><th>Status</th><th>Scheduled</th></tr></thead>
                    <tbody>${queueRows}</tbody>
                </table>
            </div>
        </div>

        <div class="card">
            <h3 class="font-bold mb-4 flex items-center gap-2 text-cyan">
                <span class="icon-sm">${Icons.activity}</span> Active
                <span class="badge badge-grey text-xs ml-auto">${active.length}</span>
            </h3>
            <div class="overflow-x-auto">
                <table class="data-table dense">
                    <thead><tr><th style="width:50px">ID</th><th>Command</th><th>Status</th><th>Started</th><th>Duration</th><th>%</th><th>ETA</th></tr></thead>
                    <tbody>${activeRows}</tbody>
                </table>
            </div>
        </div>

        <div class="card">
            <div class="flex items-center justify-between mb-4">
                <h3 class="font-bold flex items-center gap-2 text-cyan">
                    <span class="icon-sm">${Icons.activity}</span> History
                    <span class="badge badge-grey text-xs">${filteredHistory.length}</span>
                </h3>
                <label class="text-xs font-normal text-muted flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" onchange="app.toggleHidePeriodic(this.checked)" ${hidePeriodic ? 'checked' : ''}>
                    Hide automatic probes
                </label>
            </div>
             <div class="overflow-x-auto">
                <table class="data-table dense">
                    <thead><tr><th style="width:50px">ID</th><th>Cmd</th><th>Health</th><th>Result</th><th>Started</th><th>Duration</th><th style="width:60px">Details</th></tr></thead>
                    <tbody>${historyRows}</tbody>
                </table>
            </div>
        </div>
    `;
};

/* --- Settings --- */
export const renderSettings = (config) => {
    const fullAccess = config.config_full_access !== false;
    const boolField = (key, label, disabled = false) => `
        <div class="form-group flex items-center gap-4 ${disabled ? 'disabled-control' : ''}">
            <input type="checkbox" id="${key}" name="${key}" ${config[key] ? 'checked' : ''} ${disabled ? 'disabled' : ''}>
            <label for="${key}" class="mb-0 ${disabled ? '' : 'cursor-pointer'}">${label}</label>
        </div>
    `;

    const inputField = (key, label, type = "text", desc = "", disabled = false) => `
        <div class="form-group ${disabled ? 'disabled-control' : ''}">
            <label for="${key}">${label}</label>
            <input type="${type}" id="${key}" name="${key}" class="form-control" value="${config[key] !== undefined ? config[key] : ''}" ${disabled ? 'disabled' : ''}>
            ${desc ? `<div class="text-xs text-muted mt-1">${desc}</div>` : ''}
        </div>
    `;

    const selectField = (key, label, options, disabled = false) => `
        <div class="form-group ${disabled ? 'disabled-control' : ''}">
            <label for="${key}">${label}</label>
            <select id="${key}" name="${key}" class="form-control" ${disabled ? 'disabled' : ''}>
                ${options.map(opt => `<option value="${opt}" ${config[key] === opt ? 'selected' : ''}>${opt}</option>`).join('')}
            </select>
        </div>
    `;

    const logLevels = ['critical', 'error', 'warning', 'info'];

    return `
        <form id="settings-form" class="grid-2">
            <!-- Automation -->
            <div class="card">
                <h3 class="font-bold mb-4 text-cyan">Automation</h3>
                ${inputField('maintenance_schedule', 'Maintenance Schedule', 'text', 'e.g., daily 02:00')}
                <div class="form-row">
                    ${inputField('sync_threshold_deletes', 'Deletes Threshold', 'number')}
                    ${inputField('sync_threshold_updates', 'Updates Threshold', 'number')}
                </div>
                ${inputField('scrub_percentage', 'Scrub %', 'number')}
                ${inputField('scrub_older_than', 'Scrub Older Than (Days)', 'number')}
                ${boolField('sync_prehash', 'Enable Pre-hash')}
                ${boolField('sync_force_zero', 'Enable Force Zero')}
            </div>

            <!-- Monitor & Log -->
            <div class="card">
                <h3 class="font-bold mb-4 text-cyan">Monitor & Log</h3>
                ${inputField('probe_interval_minutes', 'Probe Interval (min)', 'number')}
                ${inputField('spindown_idle_minutes', 'Disk Spindown Timeout (min)', 'number')}
                ${inputField('log_directory', 'Log Directory', 'text', '', !fullAccess)}
                ${inputField('log_retention_days', 'Log Retention (Days)', 'number', '', !fullAccess)}
            </div>

            <!-- Script -->
            <div class="card">
                <h3 class="font-bold mb-4 text-cyan">Script</h3>
                ${inputField('script_pre_run', 'Script Pre-Run', 'text', '', !fullAccess)}
                ${inputField('script_post_run', 'Script Post-Run', 'text', '', !fullAccess)}
                ${inputField('script_run_as_user', 'Run Scripts As User', 'text', '', !fullAccess)}
            </div>

             <!-- Notifications -->
            <div class="card" style="grid-column: span 2;">
                <h3 class="font-bold mb-4 text-cyan">Notifications</h3>
                
                <h4 class="font-bold border-b border-slate-700 pb-2 mb-3 mt-1">Syslog</h4>
                <div class="form-row">
                     ${boolField('notify_syslog_enabled', 'Enable Syslog')}
                     ${selectField('notify_syslog_level', 'Log Level', logLevels)}
                </div>

                <h4 class="font-bold border-b border-slate-700 pb-2 mb-3 mt-4">Email</h4>
                <div class="form-row">
                    ${inputField('notify_email_recipient', 'Recipient', 'email')}
                    ${selectField('notify_email_level', 'Log Level', logLevels)}
                </div>

                <h4 class="font-bold border-b border-slate-700 pb-2 mb-3 mt-4">Hooks</h4>
                ${inputField('notify_heartbeat', 'Heartbeat Command (On Success)', 'text', '', !fullAccess)}
                <div class="form-row mt-2">
                     ${inputField('notify_result', 'Result Command (On Report)', 'text', '', !fullAccess)}
                     ${selectField('notify_result_level', 'Result Level', logLevels, !fullAccess)}
                </div>
                
                 <div class="form-row mt-2">
                     ${inputField('notify_run_as_user', 'Run Notification As User', 'text', '', !fullAccess)}
                     ${boolField('notify_differences', 'Include Differences')}
                </div>
            </div>
        </form>
    `;
};

/* --- Recovery --- */
export const renderRecovery = (arrayInfo) => {
    const fixes = arrayInfo.fixes || [];
    const fixFilesRows = fixes.length ? fixes.map(f => {
        const result = (f && f.result) ? f.result : 'unknown';
        const isRecovered = result === 'recovered';
        const colorClass = isRecovered ? 'text-emerald' : 'text-red';
        return `
            <tr>
                <td class="text-xs font-bold ${colorClass}">${result.toUpperCase()}</td>
                <td class="text-xs font-mono">${(f && f.disk) || ''}</td>
                <td class="text-xs break-all">${(f && f.path) || ''}</td>
            </tr>
        `;
    }).join('') : `<tr><td colspan="3" class="text-center text-muted p-4">No recent recovery history</td></tr>`;

    return `
        <div class="fade-in">
             <div class="grid-2">
                <!-- Undelete Card -->
                <div class="card">
                    <h3 class="font-bold mb-4 text-cyan flex items-center gap-2">
                        <span class="icon-sm">${Icons.trash}</span> Undelete Files
                    </h3>
                    <p class="text-sm text-muted mb-4">
                        Recover accidentally deleted files. Enter file path patterns/globbing (e.g. *.mp4), one per line.
                    </p>
                    <textarea id="undelete-patterns" class="form-control mb-4 font-mono text-sm bg-slate-950 border-slate-700 text-slate-200" rows="5" placeholder="*.mp4&#10;family_docs/*&#10;lost_file.txt"></textarea>
                    <button class="btn btn-primary w-full" data-tooltip="Undelete the specified file patterns in all disks" onclick="app.triggerUndeleteBatch()">
                        Undelete Files
                    </button>
                </div>

                <!-- Silent Errors Card -->
                <div class="card">
                     <h3 class="font-bold mb-4 text-cyan flex items-center gap-2">
                        <span class="icon-sm">${Icons.shield}</span> Silent Data Errors
                    </h3>
                    <p class="text-sm text-muted mb-4">
                        Detect and heal silent data corruption using parity information.
                    </p>
                    <div class="property-list mt-0 pt-0 border-t-0 mb-6">
                        <div class="property-row">
                            <div class="property-label">Bad Blocks</div>
                            <div class="property-value ${arrayInfo.blocks_bad > 0 ? 'text-red' : 'text-emerald'}">${arrayInfo.blocks_bad}</div>
                        </div>
                    </div>
                    
                    <button class="btn ${arrayInfo.blocks_bad > 0 ? 'btn-danger w-full' : 'btn-disabled w-full'}" 
                            data-tooltip="Repair silent data corruption on all data disks"
                            onclick="${arrayInfo.blocks_bad > 0 ? 'app.triggerHeal()' : ''}"
                            ${arrayInfo.blocks_bad === 0 ? 'disabled' : ''}>
                        Heal Silent Errors
                    </button>
                    ${arrayInfo.blocks_bad === 0 ? '<p class="text-xs text-center text-muted mt-2">No silent errors detected. Array is healthy.</p>' : ''}
                </div>
            </div>

            <!-- Recovery Summary -->
            <div class="card mt-4">
                <div class="mb-4 border-b border-slate-700 pb-2">
                     <h3 class="font-bold text-cyan">Recovery Summary</h3>
                     <div class="text-sm text-muted mt-2 italic">
                        These differences represent fixes since the last sync. They will be cleared once the next maintenance cycle completes.
                     </div>
                     <div class="text-sm text-muted mt-1">Last updated: ${arrayInfo.last_fix_at ? formatTime(arrayInfo.last_fix_at, arrayInfo.pulse?.current_at) : formatTime(arrayInfo.last_sync_at, arrayInfo.pulse?.current_at)}</div>
                </div>
                
                 <div class="property-list mt-0 pt-0 border-t-0">
                    <div class="property-row">
                        <div class="property-label">Recovered</div>
                        <div class="property-value text-emerald">${arrayInfo.fix_recovered || 0}</div>
                    </div>
                    <div class="property-row">
                        <div class="property-label">Unrecoverable</div>
                        <div class="property-value text-red">${arrayInfo.fix_unrecoverable || 0}</div>
                    </div>
                </div>

                <h4 class="text-xs font-bold text-muted uppercase mb-2 mt-6">Processed Files</h4>
                <div class="overflow-x-auto">
                    <table class="data-table dense">
                        <thead>
                            <tr>
                                <th style="width: 100px">Status</th>
                                <th style="width: 100px">Disk</th>
                                <th>Path</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${fixFilesRows}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    `;
};
