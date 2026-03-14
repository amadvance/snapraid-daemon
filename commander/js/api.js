
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
    startMaintenance: (options = {}) => request('/maintenance', { method: 'POST', body: JSON.stringify(options) }),
    startProbe: () => API.schedule([{ command: 'probe' }]),
    startHeal: (options = {}) => request('/heal', { method: 'POST', body: JSON.stringify(options) }),
    startDiff: () => API.schedule([{ command: 'up' }, { command: 'diff' }]),
    spinUp: () => API.schedule([{ command: 'up' }]),
    spinDown: () => API.schedule([{ command: 'down' }]),
    spinDownIdle: () => request('/suspend_idle', { method: 'POST' }),
    undelete: (filters, options = {}) => request('/undelete', { method: 'POST', body: JSON.stringify({ filters, ...options }) }),
    stopTask: () => request('/stop', { method: 'POST' }),
    refreshArray: () => request('/refresh', { method: 'POST' }),
    setHoldOff: (enabled) => request('/hold_off', { method: 'POST', body: JSON.stringify({ enabled }) })
};
