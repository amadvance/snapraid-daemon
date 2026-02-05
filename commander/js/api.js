
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
    updateConfig: (config) => request('/config', { method: 'PATCH', body: JSON.stringify(config) }),

    // Commands
    startMaintenance: () => request('/maintenance', { method: 'POST' }),
    startProbe: () => request('/probe', { method: 'POST' }),
    startHeal: () => request('/heal', { method: 'POST' }),
    startDiff: () => request('/diff', { method: 'POST' }),
    spinUp: () => request('/up', { method: 'POST' }),
    spinDown: () => request('/down', { method: 'POST' }),
    spinDownIdle: () => request('/down_idle', { method: 'POST' }),
    undelete: (filters) => request('/undelete', { method: 'POST', body: JSON.stringify({ filters }) }),
    stopTask: () => request('/stop', { method: 'POST' })
};
