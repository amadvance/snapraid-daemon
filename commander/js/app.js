
import { API } from './api.js';
import { Icons, showToast, showConfirm, formatSeconds } from './utils.js';
import { renderDashboard, renderDisks, renderTasks, renderDifferences, renderRecovery, renderSettings, renderTempSparkline, renderScrubHistory } from './ui.js';

const app = {
    state: {
        currentRoute: '',

        pulse: {},
        pollingInterval: null,
        isConnected: true,
        hidePeriodic: false,
        system: null,
        lastSystemRefresh: 0,
        dashboardArray: null,
        dashboardActivity: null,
        disks: null
    },

    init: () => {
        // Render Icons
        document.querySelectorAll('[id^="icon-"]').forEach(el => {
            const iconName = el.id.replace('icon-', '');
            if (Icons[iconName]) el.innerHTML = Icons[iconName];
        });

        // Navigation
        window.addEventListener('hashchange', app.handleRoute);
        app.handleRoute();

        // Mobile Menu
        document.getElementById('mobile-menu-btn').addEventListener('click', () => {
            document.getElementById('sidebar').classList.toggle('open');
        });

        // Global Action: Close sidebar on link click (mobile)
        document.querySelectorAll('.nav-item').forEach(l => {
            l.addEventListener('click', () => {
                if (window.innerWidth < 768) document.getElementById('sidebar').classList.remove('open');
            });
        });

        // Expose triggerStop to window for UI buttons
        window.app = app;

        // Resize handler for graphs
        let resizeTimer;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(app.redrawGraphs, 100);
        });
    },

    redrawGraphs: () => {
        const hash = app.state.currentRoute;
        if (hash === '#/' && app.state.dashboardArray?.scrub_history) {
            renderScrubHistory('scrub-history-graph', app.state.dashboardArray.scrub_history);
        } else if (hash === '#/disks' && app.state.disks) {
            const data = app.state.disks;
            [...data.parity_disks, ...data.data_disks].forEach(disk => {
                disk.devices.forEach(dev => {
                    if (dev.temp_history_24h) {
                        const safeId = dev.device_node.replace(/[^a-z0-9]/gi, '-');
                        renderTempSparkline(`sparkline-${safeId}`, dev.temp_history_24h);
                    }
                });
            });
        }
    },

    stopPolling: () => {
        if (app.state.pollingInterval) clearInterval(app.state.pollingInterval);
        app.state.pollingInterval = null;
    },

    pollState: async () => {
        try {
            const state = await API.getState();
            const pulse = state.pulse;
            const oldPulse = app.state.pulse || {};
            const wasDisconnected = !app.state.isConnected;

            if (wasDisconnected) {
                app.setConnection(true);
            }

            let needsRefresh = false;
            let needsSystemRefresh = false;

            const now = Date.now();
            if (app.state.currentRoute === '#/' && (now - app.state.lastSystemRefresh) > 60000) {
                needsSystemRefresh = true;
            }

            switch (app.state.currentRoute) {
                case '#/': // Dashboard - check array and activity
                    if (pulse.array !== oldPulse.array || pulse.activity !== oldPulse.activity) needsRefresh = true;
                    break;
                case '#/disks': // Disks - check disks
                    if (pulse.disks !== oldPulse.disks) needsRefresh = true;
                    break;
                case '#/tasks': // Tasks - check tasks
                    if (pulse.tasks !== oldPulse.tasks) needsRefresh = true;
                    break;
                case '#/diff': // Difference - check array
                    if (pulse.array !== oldPulse.array) needsRefresh = true;
                    break;
                case '#/recovery': // Recovery - check array (fixes/bad blocks are in array)
                    if (pulse.array !== oldPulse.array) needsRefresh = true;
                    break;
                case '#/settings': // Settings - check config
                    if (pulse.config !== oldPulse.config) needsRefresh = true;
                    break;
            }

            // Also refresh if we reconnected and are currently showing an error
            const isShowingError = !!document.querySelector('#view-container .border-red-500');

            if (needsRefresh || needsSystemRefresh || (wasDisconnected && isShowingError)) {
                const hash = app.state.currentRoute;
                if (hash === '#/') {
                    await app.loadDashboard({
                        array: (pulse.array !== oldPulse.array) || wasDisconnected,
                        activity: (pulse.activity !== oldPulse.activity) || wasDisconnected,
                        system: needsSystemRefresh || wasDisconnected
                    });
                }
                else if (hash === '#/disks') await app.loadDisks();
                else if (hash === '#/tasks') await app.loadTasks();
                else if (hash === '#/diff') await app.loadDifferences();
                else if (hash === '#/recovery') await app.loadRecovery();
                else if (hash === '#/settings') await app.loadSettings();
            }

            // Update Sidebar Status
            const statusBar = document.getElementById('sidebar-status');
            if (statusBar && state) {
                if (state.active_command) {
                    const hasProgress = state.progress !== undefined;
                    const hasEta = state.eta_seconds !== undefined;

                    let html = `
                        <div class="status-title">
                            <span class="status-command flex items-center">
                                <span class="status-icon icon-spin">${Icons.refresh}</span>
                                ${state.active_command.toUpperCase()}
                                ${state.next_command ? `
                                    <span class="status-separator">${Icons.arrowRight}</span>
                                    <span class="status-next">${state.next_command.toUpperCase()}</span>
                                ` : ''}
                            </span>
                            ${hasProgress ? `<span>${state.progress}%</span>` : ''}
                        </div>
                    `;

                    if (hasProgress) {
                        html += `
                        <div class="progress-container" style="height: 4px; background-color: var(--c-slate-800); margin: 4px 0;">
                            <div class="progress-bar" style="width: ${state.progress}%"></div>
                        </div>`;
                    }

                    if (hasEta) {
                        html += `
                        <div class="status-meta">
                            <span>ETA: ${formatSeconds(state.eta_seconds)}</span>
                        </div>`;
                    }

                    statusBar.innerHTML = html;
                } else {
                    statusBar.innerHTML = '';
                }
            }

            app.state.pulse = pulse;
        } catch (e) {
            console.error("Pulse check failed", e);
            app.setConnection(false);
        }
    },

    setConnection: (isConnected) => {
        if (app.state.isConnected === isConnected) return;
        app.state.isConnected = isConnected;

        const dot = document.querySelector('.pulse-dot');
        const text = document.getElementById('connection-text');

        if (isConnected) {
            dot.classList.remove('disconnected');
            text.innerText = 'Connected';
            text.classList.remove('text-red');
        } else {
            dot.classList.add('disconnected');
            text.innerText = 'Disconnected';
            text.classList.add('text-red');
        }
    },

    handleRoute: async () => {
        app.stopPolling();

        // Start Pulse Polling (Global for all pages)
        app.state.pollingInterval = setInterval(app.pollState, 3000);

        const hash = window.location.hash || '#/';
        app.state.currentRoute = hash;

        // Update Sidebar
        document.querySelectorAll('.nav-item').forEach(el => {
            el.classList.toggle('active', el.getAttribute('href') === hash);
        });

        const view = document.getElementById('view-container');
        const actions = document.getElementById('header-actions');
        const title = document.getElementById('page-title');

        view.innerHTML = '<div class="loading-spinner"></div>';
        actions.innerHTML = '';

        try {
            switch (hash) {
                case '#/':
                    title.innerText = 'Dashboard';
                    actions.innerHTML = `
                        <button class="btn btn-primary" data-tooltip="Trigger full maintenance sequence and generate a report" data-tooltip-pos="bottom-left" onclick="app.triggerMaintenance()">Maintenance</button>
                    `;
                    await app.loadDashboard({ array: true, activity: true, system: true });
                    break;
                case '#/disks':
                    title.innerText = 'Disks';
                    actions.innerHTML = `
                        <button class="btn btn-primary" data-tooltip="Spin up all array disks" data-tooltip-pos="bottom-left" onclick="app.triggerCommand('spinUp')">Up</button>
                        <button class="btn btn-primary" data-tooltip="Spin down all array disks" data-tooltip-pos="bottom-left" onclick="app.triggerCommand('spinDown')">Down</button>
                    `;
                    await app.loadDisks();
                    break;
                case '#/tasks':
                    title.innerText = 'Tasks';
                    actions.innerHTML = '';
                    await app.loadTasks();
                    break;
                case '#/diff':
                    title.innerText = 'Differences';
                    actions.innerHTML = `
                        <button class="btn btn-primary" data-tooltip="Trigger a new differences check" data-tooltip-pos="bottom-left" onclick="app.triggerDiff()">Differences</button>
                    `;
                    await app.loadDifferences();
                    break;
                case '#/recovery':
                    title.innerText = 'Recovery';
                    actions.innerHTML = '';
                    await app.loadRecovery();
                    break;
                case '#/settings':
                    title.innerText = 'Settings';
                    actions.innerHTML = `
                        <button class="btn btn-secondary" data-tooltip="Discard changes and refresh settings" data-tooltip-pos="bottom-left" onclick="app.handleRoute()">Cancel</button>
                        <button class="btn btn-primary" data-tooltip="Save configuration changes to server" data-tooltip-pos="bottom-left" onclick="app.saveSettings()">Save</button>
                    `;
                    await app.loadSettings();
                    break;
                default:
                    view.innerHTML = '<p class="text-center mt-4">Page Not Found</p>';
            }
        } catch (e) {
            view.innerHTML = `<div class="card border-red-500"><h3 class="text-red">Error</h3><p>${e.message}</p></div>`;
        }
    },

    /* --- Page Loaders --- */

    loadDashboard: async (refreshFlags = { array: true, activity: true, system: true }) => {
        try {
            const promises = [];

            if (refreshFlags.array) promises.push(API.getArray());
            else promises.push(Promise.resolve(app.state.dashboardArray));

            if (refreshFlags.activity) promises.push(API.getActivity());
            else promises.push(Promise.resolve(app.state.dashboardActivity));

            if (refreshFlags.system) promises.push(API.getSystem());
            else promises.push(Promise.resolve(app.state.system));

            const [array, activity, system] = await Promise.all(promises);

            // Update pulse state (use most recent)
            if (array && array.pulse) app.state.pulse = array.pulse;
            if (activity && activity.pulse) app.state.pulse = activity.pulse;

            app.state.dashboardArray = array;
            app.state.dashboardActivity = activity;
            app.state.system = system;
            if (refreshFlags.system) app.state.lastSystemRefresh = Date.now();

            app.setConnection(true);

            // Only re-render if we are still on the dashboard
            if (app.state.currentRoute === '#/') {
                const active = activity && activity.status !== 'terminated' && activity.status !== 'signaled' && activity.status !== 'canceled';
                const actions = document.getElementById('header-actions');
                actions.innerHTML = `
                    ${active ? `<button class="btn btn-danger" data-tooltip="Abort the currently running task" data-tooltip-pos="bottom-left" onclick="app.triggerStop()">Stop Task</button>` : ''}
                    <button class="btn btn-primary" data-tooltip="Trigger full maintenance sequence and generate a report" data-tooltip-pos="bottom-left" onclick="app.triggerMaintenance()">Maintenance</button>
                `;
                document.getElementById('view-container').innerHTML = renderDashboard(array, activity, app.state.system);

                // Draw graphs
                app.redrawGraphs();

                // Auto-scroll logs
                const logWindow = document.querySelector('.log-window');
                if (logWindow) {
                    logWindow.scrollTop = logWindow.scrollHeight;
                }
            }
        } catch (e) {
            app.setConnection(false);
            throw e;
        }
    },

    loadDisks: async () => {
        try {
            const data = await API.getDisks();
            if (data.pulse) app.state.pulse = data.pulse;
            app.setConnection(true);
            app.state.disks = data;
            document.getElementById('view-container').innerHTML = renderDisks(data);

            // Post-render: Draw graphs
            app.redrawGraphs();
        } catch (e) {
            app.setConnection(false);
            throw e;
        }
    },

    loadTasks: async () => {
        try {
            const data = await API.getTasks();
            if (data.pulse) app.state.pulse = data.pulse;
            app.setConnection(true);
            document.getElementById('view-container').innerHTML = renderTasks(data, app.state.hidePeriodic);
        } catch (e) {
            app.setConnection(false);
            throw e;
        }
    },

    loadDifferences: async () => {
        try {
            const array = await API.getArray();
            if (array.pulse) app.state.pulse = array.pulse;
            app.setConnection(true);
            document.getElementById('view-container').innerHTML = renderDifferences(array);
        } catch (e) {
            app.setConnection(false);
            throw e;
        }
    },

    loadRecovery: async () => {
        try {
            const array = await API.getArray();
            if (array.pulse) app.state.pulse = array.pulse;
            app.setConnection(true);
            // Dynamic import to avoid circular dependency issues if any, though we can likely just use the import at top
            // Assuming renderRecovery is exported from ui.js and we imported it.
            // Wait, I need to update the import statement at the top of the file too.
            // I'll assume I update the import in a separate tool call if needed or just use consistent updates.
            // But since I can't update multiple files in one go easily without separate tool calls...
            document.getElementById('view-container').innerHTML = renderRecovery(array);
        } catch (e) {
            app.setConnection(false);
            throw e;
        }
    },

    loadSettings: async () => {
        try {
            const config = await API.getConfig();
            if (config.pulse) app.state.pulse = config.pulse;
            app.setConnection(true);
            app.state.config = config;
            document.getElementById('view-container').innerHTML = renderSettings(config);
        } catch (e) {
            app.setConnection(false);
            throw e;
        }
    },

    /* --- Actions --- */

    triggerMaintenance: async () => {
        if (await showConfirm('Start full maintenance sequence?')) {
            await API.startMaintenance();
            showToast('Maintenance Triggered', 'success');
            setTimeout(app.loadDashboard, 500);
        }
    },

    triggerStop: async () => {
        if (await showConfirm('Are you sure you want to STOP the running task?', 'Stop Task')) {
            await API.stopTask();
            showToast('Stop Signal Sent', 'info');
        }
    },

    triggerDiff: async () => {
        await API.startDiff();
        showToast('Diff Command Triggered', 'success');
        setTimeout(app.loadDifferences, 500);
    },

    toggleHidePeriodic: (checked) => {
        app.state.hidePeriodic = checked;
        app.loadTasks();
    },

    triggerHeal: async () => {
        if (await showConfirm('Start healing sequence for silent errors?', 'Heal Errors')) {
            await API.startHeal();
            showToast('Heal Command Triggered', 'success');
        }
    },

    triggerUndeleteBatch: async () => {
        const input = document.getElementById('undelete-patterns');
        if (!input) return;

        const text = input.value.trim();
        if (!text) {
            showToast('Please enter at least one file pattern', 'warning');
            return;
        }

        const filters = text.split('\n').map(l => l.trim()).filter(l => l);

        if (await showConfirm(`Recover files matching ${filters.length} patterns?`, 'Undelete Files')) {
            try {
                await API.undelete(filters);
                showToast(`Undelete queued for ${filters.length} patterns`, 'success');
                input.value = ''; // Clear input on success
            } catch (e) {
                showToast('Failed to start undelete: ' + e.message, 'error');
            }
        }
    },

    triggerUndelete: async (path) => {
        if (await showConfirm(`Recover missing file?\n${path}`, 'Undelete File')) {
            try {
                await API.undelete([path]);
                showToast('Undelete Task Queued', 'success');
            } catch (e) {
                showToast('Failed to start undelete: ' + e.message, 'error');
            }
        }
    },

    triggerCommand: async (cmd) => {
        await API[cmd]();
        showToast(`Command ${cmd} sent`, 'info');
    },

    saveSettings: async () => {
        const form = document.getElementById('settings-form');
        const formData = new FormData(form);
        const updates = {};

        const fullAccess = app.state.config?.config_full_access !== false;
        const protectedFields = [
            'script_run_as_user', 'script_pre_run', 'script_post_run',
            'log_directory', 'log_retention_days', 'notify_run_as_user', 'notify_heartbeat', 'notify_result', 'notify_result_level'
        ];

        // Manual conversion to handle types correctly
        for (let [key, value] of formData.entries()) {
            if (!fullAccess && protectedFields.includes(key)) continue;

            // Check if it should be a number
            if (['sync_threshold_deletes', 'sync_threshold_updates', 'scrub_percentage',
                'scrub_older_than', 'probe_interval_minutes', 'spindown_idle_minutes',
                'log_retention_days'].includes(key)) {
                updates[key] = parseInt(value, 10);
            } else {
                updates[key] = value;
            }
        }

        // Handle unchecked booleans (FormData doesn't include them)
        ['sync_prehash', 'sync_force_zero', 'notify_syslog_enabled', 'notify_differences'].forEach(key => {
            if (!fullAccess && protectedFields.includes(key)) return;
            updates[key] = form.querySelector(`[name="${key}"]`).checked;
        });

        try {
            await API.updateConfig(updates);
            showToast('Configuration Saved', 'success');
        } catch (e) {
            showToast('Failed to save: ' + e.message, 'error');
        }
    }
};

// Initialize
document.addEventListener('DOMContentLoaded', app.init);
