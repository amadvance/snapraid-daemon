// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

const BASE_URL = '/snapraid/v1';

async function request(endpoint, options = {}) {
    try {
        const response = await fetch(`${BASE_URL}${endpoint}`, {
            headers: { 'Content-Type': 'application/json', 'X-Pinggy-No-Screen': 'true' },
            ...options
        });

        if (response.status === 204)
            return null; // No Content

        if (!response.ok) {
            const errorText = await response.text();
            let errorMessage = `API Error ${response.status}: ${errorText}`;
            try {
                const errorJson = JSON.parse(errorText);
                if (errorJson && errorJson.message) {
                    errorMessage = errorJson.message;
                }
            } catch (ignore) { }
            throw new Error(errorMessage);
        }

        const contentType = response.headers.get("content-type");
        if (contentType && contentType.indexOf("application/json") !== -1) {
            return await response.json();
        }
        return await response.text();
    } catch (error) {
        console.error('Request failed:', error);
        throw error;
    }
}

export const API = {
    getArray: (params = {}) => {
        const query = new URLSearchParams(params).toString();
        return request(`/array${query ? `?${query}` : ''}`);
    },
    getState: () => request('/state'),
    getDisks: () => request('/disks'),
    getActivity: (params = {}) => {
        const query = new URLSearchParams(params).toString();
        return request(`/activity${query ? `?${query}` : ''}`);
    },
    getTasks: (params = {}) => {
        const query = new URLSearchParams(params).toString();
        return request(`/tasks${query ? `?${query}` : ''}`);
    },
    getConfig: () => request('/config'),
    getSystem: () => request('/system'),
    updateConfig: (config) => request('/config', { method: 'PATCH', body: JSON.stringify(config) }),

    schedule: (tasks) => request('/schedule', { method: 'POST', body: JSON.stringify({ tasks }) }),

    // Commands
    startMaintenance: (options = {}) => request('/maintenance', { method: 'POST', body: JSON.stringify(options) }),
    startProbe: () => API.schedule([{ command: 'probe' }]),
    startHeal: (options = {}) => request('/heal', { method: 'POST', body: JSON.stringify(options) }),
    startDiff: () => API.schedule([{ command: 'up' }, { command: 'diff' }]),
    spinUp: () => API.schedule([{ command: 'up' }]),
    spinDown: () => API.schedule([{ command: 'down' }]),
    spinDownIdle: () => request('/suspend_idle', { method: 'POST' }),
    undelete: (filters, options = {}) => {
        const sanitizeFilter = (f) => {
            if (typeof f !== 'string') throw new Error('Invalid filter type');
            if (/[;&|`$<>\\(){}\n!]/.test(f)) throw new Error(`Invalid characters in filter: ${f}`);
            return f;
        };
        const safeFilters = Array.isArray(filters) ? filters.map(sanitizeFilter) : sanitizeFilter(filters);
        return request('/undelete', { method: 'POST', body: JSON.stringify({ filters: safeFilters, ...options }) });
    },
    stopTask: () => request('/stop', { method: 'POST' }),
    refreshArray: () => request('/refresh', { method: 'POST' }),
    setHoldOff: (enabled) => request('/hold_off', { method: 'POST', body: JSON.stringify({ enabled }) })
};
