
const BASE_URL = '/snapraid/v1';

async function request(endpoint, options = {}) {
    try {
        const response = await fetch(`${BASE_URL}${endpoint}`, {
            headers: { 'Content-Type': 'application/json' },
            ...options
        });

        if (response.status === 204) return null; // No Content

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`API Error ${response.status}: ${errorText}`);
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
    getArray: () => request('/array'),
    getState: () => request('/state'),
    getDisks: () => request('/disks'),
    getActivity: () => request('/activity'),
    getTasks: () => request('/tasks'),
    getConfig: () => request('/config'),
    getSystem: () => request('/system'),
    updateConfig: (config) => request('/config', { method: 'PATCH', body: JSON.stringify(config) }),

    schedule: (tasks) => request('/schedule', { method: 'POST', body: JSON.stringify({ tasks }) }),

    // Commands
    startMaintenance: () => request('/maintenance', { method: 'POST' }),
    startProbe: () => API.schedule([{ command: 'probe' }]),
    startHeal: () => request('/heal', { method: 'POST' }),
    startDiff: () => API.schedule([{ command: 'up' }, { command: 'diff' }]),
    spinUp: () => API.schedule([{ command: 'up' }]),
    spinDown: () => API.schedule([{ command: 'down' }]),
    spinDownIdle: () => request('/suspend_idle', { method: 'POST' }),
    undelete: (filters) => request('/undelete', { method: 'POST', body: JSON.stringify({ filters }) }),
    stopTask: () => request('/stop', { method: 'POST' })
};
