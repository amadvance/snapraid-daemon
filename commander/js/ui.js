
import { formatBytes, formatTime, formatSeconds, formatDuration, formatSignal, Icons } from './utils.js';

/* --- Shared Components --- */
const badge = (text, color) => `<span class="badge badge-${color}">${text}</span>`;

const healthBadge = (health) => {
    const map = { passed: 'green', prefail: 'yellow', failing: 'red', pending: 'grey' };
    return badge(health, map[health] || 'grey');
};

const statusBadge = (task) => {
    const map = {
        queued: 'grey', starting: 'yellow', processing: 'blue',
        finalizing: 'purple', terminated: 'green', canceled: 'red', signaled: 'red'
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

/* --- Dashboard --- */
export const renderDashboard = (arrayInfo, activity) => {
    // 1. Hero: Activity
    let heroHtml = '';
    const active = activity && activity.status !== 'terminated' && activity.status !== 'signaled' && activity.status !== 'canceled';

    if (active) {
        heroHtml = `
            <div class="card glow">
                <div class="flex justify-between mb-4">
                    <div>
                        <h3 class="text-xl font-bold text-cyan">ACTIVE: ${activity.command.toUpperCase()}</h3>
                        <div class="text-sm text-muted">Started: ${formatTime(activity.started_at)}</div>
                    </div>
                    <div>${statusBadge(activity)}</div>
                </div>
                
                <div class="progress-container">
                    <div class="progress-bar" style="width: ${activity.progress || 0}%"></div>
                </div>
                <div class="flex justify-between text-sm mb-4">
                    <span>${activity.progress || 0}% Complete</span>
                    <span>ETA: ${formatSeconds(activity.eta_seconds)}</span>
                </div>

                <div class="grid-4 mb-4">
                    <div><span class="text-muted block text-xs">Speed</span><span class="font-bold">${activity.speed_mbs || 0} MB/s</span></div>
                    <div><span class="text-muted block text-xs">Processed</span><span class="font-bold">${formatBytes(activity.size_done_bytes || 0)}</span></div>
                    <div><span class="text-muted block text-xs">CPU</span><span class="font-bold">${activity.cpu_usage || 0}%</span></div>
                    <div><span class="text-muted block text-xs">Blocks</span><span class="font-bold">${activity.blocks_done} / ${activity.blocks_count}</span></div>
                </div>

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
                        <span class="text-muted">Ended: ${formatTime(last.finished_at)}</span>
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

    const arrayStatusHtml = `
        <div class="card">
            <div class="flex gap-4 items-center mb-4">
                <h3 class="text-xl font-bold text-cyan">Array</h3>
                <div class="text-2xl font-bold">${healthBadge(arrayInfo.health)}</div>
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
                    <div class="property-label">Failure Probability (1yr)</div>
                    <div class="property-value text-cyan">${arrayInfo.failure_probability
            ? `${(arrayInfo.failure_probability * 100).toFixed(0)}%`
            : healthBadge('pending')}</div>
                </div>
                <div class="property-row">
                    <div class="property-label">Bad Blocks</div>
                    <div class="property-value ${arrayInfo.blocks_bad > 0 ? 'text-red' : 'text-emerald'}">
                        ${arrayInfo.blocks_bad}
                        ${arrayInfo.blocks_bad > 0 ? `<span class="text-xs text-muted ml-2">(${formatBytes(arrayInfo.blocks_bad * arrayInfo.block_size_bytes)})</span>` : ''}
                    </div>
                </div>
                <div class="property-row">
                    <div class="property-label">Unsynced Blocks</div>
                    <div class="property-value ${arrayInfo.blocks_unsynced > 0 ? 'text-yellow' : 'text-emerald'}">
                        ${arrayInfo.blocks_unsynced}
                        ${arrayInfo.blocks_unsynced > 0 ? `<span class="text-xs text-muted ml-2">(${formatBytes(arrayInfo.blocks_unsynced * arrayInfo.block_size_bytes)})</span>` : ''}
                    </div>
                </div>
                <div class="property-row">
                    <div class="property-label">Total Files</div>
                    <div class="property-value text-cyan">${arrayInfo.files_count.toLocaleString()}</div>
                </div>
                <div class="property-row">
                    <div class="property-label">Scrubbed</div>
                    <div class="property-value text-cyan">
                        ${arrayInfo.blocks_count > 0 ? (100 * (1 - arrayInfo.blocks_unscrubbed / arrayInfo.blocks_count)).toFixed(0) : 0}%
                    </div>
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

    const summaryHtml = `
        <div class="grid-2">
            ${arrayStatusHtml}
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
        return `
            <tr>
                <td class="text-xs font-bold ${colorClass}">${d.change.toUpperCase()}</td>
                <td class="text-xs font-mono">${d.disk}</td>
                <td class="text-xs break-all">${d.path}</td>
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
                    <div class="text-sm text-muted mt-1">Last updated: ${formatTime(arrayInfo.last_diff_at)}</div>
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
const renderDiskCard = (disk, type) => {
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
        if (smartIssues.length > 0) smartStatus = `<div class="text-amber text-xs">${smartIssues.join('<br>')}</div>`;

        if (dev.smart && dev.smart.failing)
            smartStatus = `<span class="badge badge-red">SMART FAILING</span>` + smartStatus;
        else if (dev.smart && dev.smart.prefail)
            smartStatus = `<span class="badge badge-yellow">SMART PREFAIL</span>` + smartStatus;
        else if (dev.smart && dev.smart.prefail_logged)
            smartStatus = `<span class="text-grey font-bold text-xs">SMART PASSED (but PREFAIL logged)</span>` + smartStatus;
        else if (dev.smart && dev.smart.error_logged)
            smartStatus = `<span class="text-grey font-bold text-xs">SMART PASSED (but ERROR logged)</span>` + smartStatus;
        else if (dev.smart && dev.smart.selftest_error_logged)
            smartStatus = `<span class="text-grey font-bold text-xs">SMART PASSED (but SELFTEST ERROR logged)</span>` + smartStatus;

        const temp = dev.smart?.temperature_celsius;
        const tempClass = temp >= 50 ? 'text-red font-bold' : (temp >= 40 ? 'text-yellow font-bold' : '');
        const tempStr = temp !== undefined ? `${temp}°C` : '-';

        return `
            <div class="bg-slate-950 p-3 rounded mt-2 border border-slate-800 text-sm">
                <div class="flex justify-between mb-1">
                     <span class="font-mono text-cyan">${dev.device_node}</span>
                     <div>${badge(dev.power, dev.power === 'active' ? 'green' : 'blue')} ${healthBadge(dev.health)}</div>
                </div>
                <div class="text-xs text-muted mb-2">${dev.model || 'Unknown Model'} (${dev.serial || '-'})</div>
                <div class="flex justify-between text-xs mb-2">
                    <span>Temp: <span class="${tempClass}">${tempStr}</span></span>
                    <span>${dev.rotational ? 'HDD' : 'SSD'} (${dev.rotational ? (dev.failure_probability * 100).toFixed(0) + '% Fail Prob' : dev.wear_level + '% Wear'})</span>
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

            <h4 class="text-xs text-muted uppercase font-bold mb-1">Devices</h4>
            ${devicesHtml}
        </div>
    `;
};

export const renderDisks = (data) => {
    return `
        <h3 class="text-xl font-bold mb-4">Parity Disks</h3>
        <div class="grid-fill-2 mb-8">${data.parity_disks.map(d => renderDiskCard(d, 'parity')).join('')}</div>
        
        <h3 class="text-xl font-bold mb-4">Data Disks</h3>
        <div class="grid-fill-2">${data.data_disks.map(d => renderDiskCard(d, 'data')).join('')}</div>
    `;
};

/* --- Tasks --- */
export const renderTasks = (data) => {
    const { active, pending, history } = data;

    const queueRows = pending.length ? pending.reverse().map(t => `
        <tr>
            <td class="font-mono text-muted">#${t.number}</td>
            <td class="font-bold text-cyan">${t.command}</td>
            <td>${statusBadge(t)}</td>
            <td class="text-muted">${formatTime(t.scheduled_at)}</td>
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
                <td class="text-muted">${formatTime(t.started_at)}</td>
                <td class="text-muted">${duration}</td>
                <td class="font-bold">${progress}</td>
                <td class="text-cyan">${eta}</td>
            </tr>
        `;
    }).join('') : `<tr><td colspan="7" class="text-center text-muted p-4">No active tasks</td></tr>`;

    const historyRows = history.length ? history.reverse().map(t => {
        let exitStatus = '';
        if (t.status === 'terminated' && t.exit_code !== 0) {
            exitStatus = `<div class="text-yellow mb-1">Exit Code: ${t.exit_code}</div>`;
        } else if (t.status === 'signaled') {
            exitStatus = `<div class="text-yellow mb-1">Exit Signal: ${formatSignal(t.exit_sig)}</div>`;
        }

        return `
        <tr>
            <td class="font-mono text-muted">#${t.number}</td>
            <td class="font-bold">${t.command}</td>
            <td>${healthBadge(t.health)}</td>
            <td>${statusBadge(t)}</td>
            <td class="text-muted text-xs">${formatTime(t.started_at)}</td>
            <td class="text-muted text-xs">${formatDuration(t.started_at, t.finished_at)}</td>
            <td>
                <button class="text-cyan text-xs hover:underline cursor-pointer" style="background:none; border:none;"
                    onclick="document.getElementById('log-${t.number}').classList.toggle('hidden')">
                    Details
                </button>
            </td>
        </tr>
        <tr id="log-${t.number}" class="hidden bg-slate-900">
            <td colspan="7" style="padding: 0;">
                <div class="text-xs font-mono bg-slate-950 p-4 border-b border-slate-800 shadow-inner">
                     ${exitStatus}
                     <div class="text-muted mb-2 border-b border-slate-800 pb-2">
                        <span class="font-bold">Log File: ${t.log_file || 'N/A'}</span>
                     </div>
                     <div class="overflow-x-auto">
                        ${(t.messages || []).length > 0
                ? (t.messages || []).map(m => {
                    const isError = m.level === 'error' || m.level === 'fatal';
                    const colorClass = isError ? 'text-red' : 'text-cyan';
                    const typeBadge = m.type === 'hardware' ? `<span class="badge badge-red text-[10px] mr-1">HARDWARE FAILURE</span>` : '';
                    return `<div class="${colorClass} break-all mb-1 font-mono">${typeBadge} ${m.text}</div>`;
                }).join('')
                : '<div class="text-cyan">No logged messages.</div>'}
                     </div>
                </div>
            </td>
        </tr>
    `;
    }).join('') : `<tr><td colspan="4" class="text-center text-muted p-4">No tasks in history</td></tr>`;

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
            <h3 class="font-bold mb-4 flex items-center gap-2 text-cyan">
                <span class="icon-sm">${Icons.activity}</span> History
                 <span class="badge badge-grey text-xs ml-auto">${history.length}</span>
            </h3>
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
                    ${inputField('sync_threshold_deletes', 'Del. Threshold', 'number')}
                    ${inputField('sync_threshold_updates', 'Upd. Threshold', 'number')}
                </div>
                ${inputField('scrub_percentage', 'Scrub %', 'number')}
                ${inputField('scrub_older_than', 'Scrub Older Than (Days)', 'number')}
                ${boolField('sync_prehash', 'Enable Pre-hash')}
                ${boolField('sync_force_zero', 'Force Zero')}
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
