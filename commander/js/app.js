// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

import { API } from './api.js';
import { Icons, showToast, showConfirm, showConfirmDown, showModal, formatElapsedTime, formatDiskSize, formatSeconds, formatAttr } from './utils.js';
import { renderDashboard, renderDisks, renderTasks, renderDifferences, renderRecovery, renderSettings, renderTempSparkline, renderScrubHistory, renderHealthBanner } from './ui.js';

const app = {
    state: {
        currentRoute: '',
        pulse: {},
        pollingInterval: null,
        isConnected: true,
        hidePeriodic: true,
        system: null,
        lastSystemRefresh: 0,
        dashboardArray: null,
        dashboardActivity: null,
        disks: null
    },

    init: () => {
        // Theme Init
        const savedTheme = localStorage.getItem('theme') || 'dark';
        document.documentElement.dataset.theme = savedTheme;

        // Render Icons
        document.querySelectorAll('[id^="icon-"]').forEach(el => {
            const iconName = el.id.replace('icon-', '');
            if (iconName === 'theme') {
                el.innerHTML = savedTheme === 'light' ? Icons.moon : Icons.sun;
            } else if (Icons[iconName]) {
                el.innerHTML = Icons[iconName];
            }
        });

        // Theme Toggle Handler
        document.getElementById('theme-toggle').addEventListener('click', () => {
            const current = document.documentElement.dataset.theme;
            const next = current === 'light' ? 'dark' : 'light';
            document.documentElement.dataset.theme = next;
            localStorage.setItem('theme', next);

            // Update Icon
            const iconEl = document.querySelector('#icon-theme');
            if (iconEl) iconEl.innerHTML = next === 'light' ? Icons.moon : Icons.sun;

            // Redraw graphs to match theme colors if needed (sparklines use hardcoded colors but maybe background changes?)
            // Sparklines have transparent backgrounds, but axes lines are white with opacity.
            // We might need to re-render them if we want to change axis colors.
            // For now, let's just redraw.
            app.redrawGraphs();
        });

        // Global Tooltip Manager
        const tooltip = document.createElement('div');
        tooltip.className = 'tooltip-floating';
        document.body.appendChild(tooltip);

        document.addEventListener('mouseover', (e) => {
            const el = e.target.closest('[data-tooltip]');
            if (!el) {
                tooltip.classList.remove('active');
                return;
            }

            // On touch devices, do not show tooltips for buttons to avoid them sticking after click
            const isTouch = !window.matchMedia('(hover: hover)').matches;
            const isButton = el.tagName === 'BUTTON' || el.classList.contains('btn');
            if (isTouch && isButton) return;

            tooltip.innerText = el.getAttribute('data-tooltip');
            tooltip.classList.add('active');

            const updatePos = (me) => {
                const padding = 15;
                let x = me.clientX + padding;
                let y = me.clientY + padding;

                // Flip if near edges
                if (x + tooltip.offsetWidth > window.innerWidth) x = me.clientX - tooltip.offsetWidth - padding;
                if (y + tooltip.offsetHeight > window.innerHeight) y = me.clientY - tooltip.offsetHeight - padding;

                tooltip.style.left = `${x}px`;
                tooltip.style.top = `${y}px`;
            };

            updatePos(e);
            el._tooltipHandler = updatePos;
            el.addEventListener('mousemove', updatePos);
        });

        document.addEventListener('mouseout', (e) => {
            const el = e.target.closest('[data-tooltip]');
            if (el && el._tooltipHandler) {
                el.removeEventListener('mousemove', el._tooltipHandler);
                delete el._tooltipHandler;
            }
            tooltip.classList.remove('active');
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

        // Centralized Event Dispatcher (for CSP compliance)
        document.addEventListener('click', (e) => {
            const el = e.target.closest('[data-action]');
            if (!el) return;

            const action = el.dataset.action;
            const ds = el.dataset;

            switch (action) {
                case 'maintenance': app.triggerMaintenance(); break;
                case 'refresh': app.triggerRefresh(); break;
                case 'stop-task': app.triggerStop(); break;
                case 'spin-up': app.triggerUp(); break;
                case 'spin-down': app.triggerDown(); break;
                case 'diff': app.triggerDiff(); break;
                case 'recovery-cancel':
                    app.handleRoute();
                    showToast('Refreshed settings', 'info');
                    break;
                case 'settings-save': app.saveSettings(); break;
                case 'undelete': app.triggerUndelete(ds.path); break;
                case 'undelete-batch': app.triggerUndeleteBatch(); break;
                case 'heal': app.triggerHeal(); break;
                case 'smart-details': app.showSmartDetails(ds.node); break;
                case 'toggle-log':
                    document.getElementById(ds.target).classList.toggle('hidden');
                    break;
            }
        });

        document.addEventListener('change', (e) => {
            const el = e.target.closest('[data-action]');
            if (!el) return;

            const action = el.dataset.action;
            if (action === 'toggle-periodic') {
                app.toggleHidePeriodic(el.checked);
            } else if (action === 'hold-off') {
                app.toggleHoldOff(el.checked);
            }
        });

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
            [...data.parity_disks, ...data.data_disks, ...data.extra_disks].forEach(disk => {
                disk.devices.forEach(dev => {
                    if (dev.temp_history_24h) {
                        const safeId = dev.node.replace(/[^a-z0-9]/gi, '-');
                        renderTempSparkline(`sparkline-${safeId}`, dev.temp_history_24h, dev.smart?.temperature_min_celsius, dev.smart?.temperature_max_celsius);
                    }
                });
            });
        }
    },

    applyDynamicStyles: (container) => {
        if (!container) return;
        container.querySelectorAll('[data-style-width]').forEach(el => {
            el.style.width = el.dataset.styleWidth;
        });
        container.querySelectorAll('[data-style-height]').forEach(el => {
            el.style.height = el.dataset.styleHeight;
        });
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
                        <div class="progress-container">
                            <div class="progress-bar" data-style-width="${state.progress}%"></div>
                        </div>`;
                    }

                    if (hasEta) {
                        html += `
                        <div class="status-meta">
                            <span>ETA: ${formatSeconds(state.eta_seconds)}</span>
                        </div>`;
                    }

                    statusBar.innerHTML = html;
                    app.applyDynamicStyles(statusBar);
                } else {
                    statusBar.innerHTML = '';
                }
            }

            // Global Health Banner
            const globalAlerts = document.getElementById('global-alerts');
            if (globalAlerts && state) {
                globalAlerts.innerHTML = renderHealthBanner(state);
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
                    const health = app.state.dashboardArray?.health;
                    const isBad = health === 'failing' || health === 'prefail';
                    actions.innerHTML = isBad ? `
                        <button class="btn btn-primary" data-tooltip="Refresh array state" data-action="refresh">Refresh</button>
                    ` : `
                        <button class="btn btn-primary" data-tooltip="Trigger full maintenance sequence and generate a report" data-action="maintenance">Maintenance</button>
                    `;
                    await app.loadDashboard({ array: true, activity: true, system: true });
                    break;
                case '#/disks':
                    title.innerText = 'Disks';
                    actions.innerHTML = `
                        <button class="btn btn-primary" data-tooltip="Spin up all array disks" data-action="spin-up">Up</button>
                        <button class="btn btn-primary" data-tooltip="Spin down all array disks" data-action="spin-down">Down</button>
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
                        <button class="btn btn-primary" data-tooltip="Trigger a new differences check" data-action="diff">Differences</button>
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
                        <button class="btn btn-secondary" data-tooltip="Discard changes and refresh settings" data-action="recovery-cancel">Cancel</button>
                        <button class="btn btn-primary" data-tooltip="Save configuration changes to server" data-action="settings-save">Save</button>
                    `;
                    await app.loadSettings();
                    break;
                default:
                    view.innerHTML = '<p>Page Not Found</p>';
            }
        } catch (e) {
            view.innerHTML = `<div class="card border-red"><h3 class="text-red">Error</h3><p>${e.message}</p></div>`;
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

            // Track if messages changed
            const oldMessages = app.state.dashboardActivity?.messages || [];
            const newMessages = activity?.messages || [];
            const messagesChanged = oldMessages.length !== newMessages.length;

            app.state.dashboardArray = array;
            app.state.dashboardActivity = activity;
            app.state.system = system;
            if (refreshFlags.system) app.state.lastSystemRefresh = Date.now();

            app.setConnection(true);

            // Only re-render if we are still on the dashboard
            if (app.state.currentRoute === '#/') {
                const active = activity && activity.status !== 'terminated' && activity.status !== 'signaled' && activity.status !== 'canceled';
                const actions = document.getElementById('header-actions');
                const isBad = array && (array.health === 'failing' || array.health === 'prefail');
                actions.innerHTML = `
                    ${active ? `<button class="btn btn-danger" data-tooltip="Stop the current running task" data-action="stop-task">Stop</button>` : ''}
                    ${isBad ? `
                        <button class="btn btn-primary" data-tooltip="Refresh array state" data-action="refresh">Refresh</button>
                    ` : `
                        <button class="btn btn-primary" data-tooltip="Trigger full maintenance sequence and generate a report" data-action="maintenance">Maintenance</button>
                    `}
                `;

                // Capture scroll state
                const logWindowBefore = document.querySelector('.log-window');
                let scrollPos = 0;
                let isAtBottom = true;
                if (logWindowBefore) {
                    scrollPos = logWindowBefore.scrollTop;
                    isAtBottom = (logWindowBefore.scrollHeight - logWindowBefore.scrollTop - logWindowBefore.clientHeight) < 50;
                }

                const view = document.getElementById('view-container');
                view.innerHTML = renderDashboard(array, activity, app.state.system);
                app.applyDynamicStyles(view);

                // Draw graphs
                app.redrawGraphs();

                // Restore scroll state
                const logWindowAfter = document.querySelector('.log-window');
                if (logWindowAfter) {
                    if (isAtBottom) {
                        logWindowAfter.scrollTop = logWindowAfter.scrollHeight;
                    } else {
                        logWindowAfter.scrollTop = scrollPos;
                    }
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
            const view = document.getElementById('view-container');
            view.innerHTML = renderDisks(data);
            app.applyDynamicStyles(view);

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
            const view = document.getElementById('view-container');
            view.innerHTML = renderTasks(data, app.state.hidePeriodic);
            app.applyDynamicStyles(view);
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
            const view = document.getElementById('view-container');
            view.innerHTML = renderDifferences(array);
            app.applyDynamicStyles(view);
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
            const view = document.getElementById('view-container');
            view.innerHTML = renderRecovery(array);
            app.applyDynamicStyles(view);
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
            const view = document.getElementById('view-container');
            view.innerHTML = renderSettings(config);
            app.applyDynamicStyles(view);
        } catch (e) {
            app.setConnection(false);
            throw e;
        }
    },

    /* --- Actions --- */

    triggerMaintenance: async () => {
        const res = await showConfirmDown('Start full maintenance sequence?');
        if (res) {
            try {
                await API.startMaintenance({ spindown_on_finish: res === 'spindown' });
                showToast('Maintenance Triggered', 'info');
                setTimeout(app.loadDashboard, 500);
            } catch (e) {
                showToast('Failed to start maintenance: ' + e.message, 'error');
            }
        }
    },

    triggerRefresh: async () => {
        try {
            await API.refreshArray();
            showToast('Refresh Triggered', 'info');
            setTimeout(app.loadDashboard, 500);
        } catch (e) {
            showToast('Refresh failed: ' + e.message, 'error');
        }
    },

    triggerStop: async () => {
        if (await showConfirm('Are you sure you want to STOP the running task?', 'Stop Task')) {
            try {
                await API.stopTask();
                showToast('Stop Signal Sent', 'info');
            } catch (e) {
                showToast('Failed to stop: ' + e.message, 'error');
            }
        }
    },

    triggerDiff: async () => {
        if (await showConfirm('Trigger a new differences check?', 'Differences')) {
            try {
                await API.startDiff();
                showToast('Diff Command Triggered', 'info');
                setTimeout(app.loadDifferences, 500);
            } catch (e) {
                showToast('Failed to start diff: ' + e.message, 'error');
            }
        }
    },

    toggleHidePeriodic: (checked) => {
        app.state.hidePeriodic = checked;
        app.loadTasks();
    },

    toggleHoldOff: async (checked) => {
        try {
            await API.setHoldOff(checked);
            showToast(checked ? 'Maintenance Hold-Off Enabled' : 'Maintenance Hold-Off Disabled', 'info');
        } catch (e) {
            showToast('Failed to toggle hold-off: ' + e.message, 'error');
            app.loadDashboard({ array: true, activity: false, system: false });
        }
    },

    triggerHeal: async () => {
        const res = await showConfirmDown('Start healing sequence for silent errors?', 'Heal Errors');
        if (res) {
            try {
                await API.startHeal({ spindown_on_finish: res === 'spindown' });
                showToast('Heal Command Triggered', 'info');
            } catch (e) {
                showToast('Failed to start heal: ' + e.message, 'error');
            }
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
        const confirmRes = await showConfirmDown(`Recover files matching ${filters.length} patterns?`, 'Undelete Files');

        if (confirmRes) {
            try {
                await API.undelete(filters, { spindown_on_finish: confirmRes === 'spindown' });
                showToast(`Undelete queued for ${filters.length} patterns`, 'info');
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
                showToast('Undelete Task Queued', 'info');
            } catch (e) {
                showToast('Failed to start undelete: ' + e.message, 'error');
            }
        }
    },

    triggerUp: async () => {
        try {
            await API.spinUp();
            showToast(`Command Up sent`, 'info');
        } catch (e) {
            showToast('Failed to start Up command: ' + e.message, 'error');
        }
    },
    
    triggerDown: async () => {
        try {
            await API.spinDown();
            showToast(`Command Down sent`, 'info');
        } catch (e) {
            showToast('Failed to start Down command: ' + e.message, 'error');
        }
    },

    saveSettings: async () => {
        try {
            const form = document.getElementById('settings-form');
            const formData = new FormData(form);
            const updates = {};

            const fullAccess = app.state.config?.config_full_access !== false;
            const protectedFields = [
                'hook_run_as_user', 'hook_script',
                'notify_run_as_user', 'notify_heartbeat', 'notify_result', 'notify_result_level',
            ];

            // Manual conversion to handle types correctly
            for (let [key, value] of formData.entries()) {
                if (!fullAccess && protectedFields.includes(key)) continue;

                // Check if it should be a number
                if (['sync_threshold_deletes', 'sync_threshold_updates',
                    'scrub_older_than', 'probe_interval_minutes', 'spindown_idle_minutes'].includes(key)) {
                    updates[key] = parseInt(value, 10);
                } else if (key === 'scrub_percentage') {
                    updates[key] = parseFloat(value);
                } else {
                    updates[key] = value;
                }
            }

            // Handle unchecked booleans (FormData doesn't include them)
            ['sync_prehash', 'sync_prevent_truncations', 'touch_zero_subseconds', 'notify_syslog_enabled', 'notify_differences'].forEach(key => {
                if (!fullAccess && protectedFields.includes(key)) return;
                const el = form.querySelector(`[name="${key}"]`);
                if (el) updates[key] = el.checked;
            });

            await API.updateConfig(updates);
            showToast('Configuration Saved', 'info');
        } catch (e) {
            showToast('Failed to save: ' + e.message, 'error');
        }
    },

    showSmartDetails: async (deviceNode) => {
        if (!app.state.disks) return;

        let device = null;
        [...app.state.disks.parity_disks, ...app.state.disks.data_disks, ...app.state.disks.extra_disks].forEach(disk => {
            disk.devices.forEach(dev => {
                if (dev.node === deviceNode) device = dev;
            });
        });

        if (!device || !device.smart) {
            showToast('SMART data not available for this device', 'warning');
            return;
        }

        const s = device.smart;
        const criticalRows = [];
        const statusRows = [];
        const otherRows = [];

        // Add protocol and medium errors manually to critical metrics
        if (device.error_protocol != null) {
            const rowClass = device.error_protocol > 0 ? 'text-amber' : 'text-emerald';
            criticalRows.push(`
                <tr>
                    <td class="font-bold text-xs">PROTOCOL ERRORS</td>
                    <td class="${rowClass} font-mono text-xs font-bold">${device.error_protocol}</td>
                    <td class="${rowClass} font-mono text-xs">-</td>
                    <td class="${rowClass} font-mono text-xs">-</td>
                    <td class="${rowClass} font-mono text-xs">-</td>
                    <td class="${rowClass} font-mono text-xs font-bold uppercase">-</td>
                </tr>
            `);
        }
        if (device.error_medium != null) {
            const rowClass = device.error_medium > 0 ? 'text-amber' : 'text-emerald';
            criticalRows.push(`
                <tr>
                    <td class="font-bold text-xs">MEDIUM ERRORS</td>
                    <td class="${rowClass} font-mono text-xs font-bold">${device.error_medium}</td>
                    <td class="${rowClass} font-mono text-xs">-</td>
                    <td class="${rowClass} font-mono text-xs">-</td>
                    <td class="${rowClass} font-mono text-xs">-</td>
                    <td class="${rowClass} font-mono text-xs font-bold uppercase">-</td>
                </tr>
            `);
        }

        // 1. Process top-level boolean flags for statusRows
        Object.entries(s).forEach(([key, value]) => {
            if (key === 'attributes' || typeof value !== 'boolean') return;
            const label = key.replace(/_/g, ' ').toUpperCase();
            const valStr = value ? 'YES' : 'NO';
            const valClass = value ? 'text-amber' : 'text-emerald';
            statusRows.push(`<tr><td class="font-bold text-xs">${label}</td><td class="font-mono font-bold text-xs ${valClass}">${valStr}</td></tr>`);
        });

        if (device.failure_probability != null) {
            otherRows.push(`
                        <tr>
                            <td class="font-bold text-xs">FAILURE PROBABILITY</td>
                            <td class="font-mono text-xs">${(device.failure_probability * 100).toFixed(0)}% (in one year)</td>
                        </tr>
            `);
        }

        if (device.wear_level != null) {
            otherRows.push(`
                        <tr>
                            <td class="font-bold text-xs">WEAR LEVEL</td>
                            <td class="font-mono text-xs">${device.wear_level}% &uarr;</td>
                        </tr>
            `);
        }

        // 2. Process attributes array for criticalRows and otherRows
        if (s.attributes) {
            s.attributes.forEach(attr => {
                const label = attr.name.replace(/_/g, ' ').toUpperCase();
                if (attr.critical || attr.when_failed === 'now' || attr.when_failed === 'past') {
                    let rowClass = 'text-emerald';
                    if (attr.when_failed === 'now')
                        rowClass = 'text-red';
                    else if (attr.when_failed === 'past' || (attr.measure == 'count' && attr.raw > 0))
                        rowClass = 'text-amber';
                    let attrClass = rowClass;
                    if (attr.measure == 'vendor')
                        attrClass = 'text-muted';
                    else
                        attrClass += ' font-bold'

                    criticalRows.push(`
                        <tr>
                            <td class="font-bold text-xs">${label}</td>
                            <td class="${attrClass} font-mono text-xs">${formatAttr(attr)}</td>
                            <td class="${rowClass} font-mono text-xs">${attr.norm != null ? attr.norm : '-'}</td>
                            <td class="${rowClass} font-mono text-xs">${attr.worst != null ? attr.worst : '-'}</td>
                            <td class="${rowClass} font-mono text-xs">${attr.thresh != null ? attr.thresh : '-'}</td>
                            <td class="${rowClass} font-mono text-xs font-bold uppercase">${attr.when_failed != null ? attr.when_failed : '-'}</td>
                        </tr>
                    `);
                } else {
                    let valStr = formatAttr(attr);

                    otherRows.push(`
                        <tr>
                            <td class="font-bold text-xs">${label}</td>
                            <td class="font-mono text-xs">${valStr}</td>
                        </tr>
                    `);
                }
            });
        }

        const html = `<div>
            ${criticalRows.length ? `
                <h4 class="text-xs font-bold text-muted uppercase mb-1">Critical Metrics</h4>
                <div class="overflow-x-auto mb-2">
                    <table class="data-table v-dense">
                        <thead>
                            <tr>
                                <th>Attribute</th>
                                <th>Raw</th>
                                <th>Norm</th>
                                <th>Worst</th>
                                <th>Thresh</th>
                                <th>Failed</th>
                            </tr>
                        </thead>
                        <tbody>${criticalRows.join('')}</tbody>
                    </table>
                </div>` : ''}
            ${statusRows.length ? `
                <h4 class="text-xs font-bold text-muted uppercase mb-1">SMART Health Flags</h4>
                <table class="data-table v-dense mb-2">
                    <tbody>${statusRows.join('')}</tbody>
                </table>` : ''}
            ${otherRows.length ? `
                <h4 class="text-xs font-bold text-muted uppercase mb-1">Other Info</h4>
                <div class="overflow-x-auto">
                    <table class="data-table v-dense">
                        <thead>
                            <tr>
                                <th>Attribute</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>${otherRows.join('')}</tbody>
                    </table>
                </div>` : ''}
        </div>`;

        showModal(`SMART Details for ${deviceNode}`, html, true);
    }
};

// Initialize
document.addEventListener('DOMContentLoaded', app.init);
