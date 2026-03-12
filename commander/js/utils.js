export const formatFullTime = (isoString, referenceIsoString) => {
    if (!isoString || !referenceIsoString)
        return '-';

    const date = new Date(isoString);
    const now = new Date(referenceIsoString);

    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);

    const taskDate = new Date(date.getFullYear(), date.getMonth(), date.getDate());

    let datePart;
    if (taskDate.getTime() === today.getTime()) {
        datePart = 'Today at';
    } else if (taskDate.getTime() === yesterday.getTime()) {
        datePart = 'Yesterday at';
    } else {
        const day = String(date.getDate()).padStart(2, '0');
        const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        const month = months[date.getMonth()];
        const year = date.getFullYear();
        datePart = `${day} ${month} ${year} -`;
    }

    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');
    return `${datePart} ${hours}:${minutes}:${seconds}`;
};

export const formatRelativeTime = (isoString, referenceIsoString) => {
    if (!isoString || !referenceIsoString)
        return 'unknown';

    const date = new Date(isoString);
    const reference = new Date(referenceIsoString);
    const diffSeconds = Math.floor((reference - date) / 1000);

    if (diffSeconds < 60) return 'now';
    if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)}m ago`;
    if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)}h ago`;
    return `${Math.floor(diffSeconds / 86400)}d ago`;
};

export const formatElapsedTime = (seconds) => {
    if (seconds < 60) return 'now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours`;
    if (seconds < 86400 * 30) return `${Math.floor(seconds / 86400)} days`;
    if (seconds < 86400 * 365) return `${Math.floor(seconds / (86400 * 30))} months`;
    return `${(seconds / (86400 * 365)).toFixed(1)} years`;
};

const formatWithSigFigs = (val, reference_val) => {
    if (reference_val >= 100) return val.toFixed(0);
    if (reference_val >= 10) return val.toFixed(1);
    return val.toFixed(2);
};

export const formatMemorySize = (bytes, reference_bytes = bytes) => {
    if (bytes === 0) return '0 bytes';
    if (bytes === 1) return '1 byte';

    const units = [' bytes', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
    const k = 1024;

    let i = Math.min(
        Math.floor(Math.log(Math.abs(reference_bytes)) / Math.log(k)),
        units.length - 1
    );

    let reference_value = reference_bytes / Math.pow(k, i);
    let value = bytes / Math.pow(k, i);

    return `${formatWithSigFigs(value, reference_value)} ${units[i]}`;
};

export const formatDiskSize = (bytes, reference_bytes = bytes) => {
    if (bytes === 0) return '0 bytes';
    if (bytes === 1) return '1 byte';

    const units = [' bytes', 'kB', 'MB', 'GB', 'TB', 'PB'];
    const k = 1000;

    let i = Math.min(
        Math.floor(Math.log(Math.abs(reference_bytes)) / Math.log(k)),
        units.length - 1
    );

    let refecence_value = reference_bytes / Math.pow(k, i);
    let value = bytes / Math.pow(k, i);

    // toPrecision(3) can round up to the next unit (e.g. 999.99 → 1000)
    if (parseFloat(refecence_value.toPrecision(3)) >= k && i < units.length - 1) {
        i += 1;
        value /= k;
        refecence_value /= k;
    }

    return `${formatWithSigFigs(value, refecence_value)} ${units[i]}`;
};

export const formatAgoMins = (mins) => {
    const seconds = mins * 60;
    if (seconds < 60) return 'now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)} days ago`;
};

export const formatAgoDays = (days) => {
    if (days < 7)
        return "past week";
    return `${Math.floor(days)} days ago`;
};

export const formatDuration = (start, end) => {
    if (!start || !end) return '-';
    const diff = Math.floor((new Date(end) - new Date(start)) / 1000);
    return formatSeconds(diff);
};

export const formatSeconds = (seconds) => {
    if (!seconds && seconds !== 0) return '-';
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);

    if (d > 0) return `${d}d ${h}h ${m}m`;
    return `${h}h ${m}m`;
};

export const formatSignal = (sig) => {
    const signals = {
        1: 'SIGHUP',
        2: 'SIGINT',
        3: 'SIGQUIT',
        4: 'SIGILL',
        5: 'SIGTRAP',
        6: 'SIGABRT',
        7: 'SIGBUS',
        8: 'SIGFPE',
        9: 'SIGKILL',
        11: 'SIGSEGV',
        13: 'SIGPIPE',
        14: 'SIGALRM',
        15: 'SIGTERM'
    };
    return signals[sig] || sig;
};

export const formatHistory = (value, history, pulseAt) => {
    let label = '';
    if (history?.prev && history?.prev_at) {
        if (history.prev < value) {
            label += ` (+${value - history.prev}, ${formatRelativeTime(history.prev_at, pulseAt)})`;
        } else if (history.prev > value) {
            label += ` (-${history.prev - value}, ${formatRelativeTime(history.prev_at, pulseAt)})`;
        }
    }
    return label;
}

// SVG Icons (Strings)
export const Icons = {
    logo: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
    dashboard: `<svg viewBox="0 0 24 24"><path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/></svg>`,
    harddrive: `<svg viewBox="0 0 24 24"><path d="M6 2h12c1.1 0 2 .9 2 2v16c0 1.1-.9 2-2 2H6c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2zm0 2v16h12V4H6zm2 4h8v2H8V8zm0 4h8v2H8v-2z"/></svg>`,
    activity: `<svg viewBox="0 0 24 24"><path d="M22 12c0-5.52-4.48-10-10-10S2 6.48 2 12c0 4.84 3.44 8.87 8 9.8V22h4v-2.2c4.56-.93 8-4.96 8-9.8zM12 4c4.41 0 8 3.59 8 8s-3.59 8-8 8-8-3.59-8-8 3.59-8 8-8zm-1 4h2v6h-2zm0 8h2v2h-2z"/></svg>`,
    settings: `<svg viewBox="0 0 24 24"><path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 0 0 .12-.61l-1.92-3.32a.488.488 0 0 0-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 0 0-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58a.49.49 0 0 0-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/></svg>`,
    menu: `<svg viewBox="0 0 24 24"><path d="M3 18h18v-2H3v2zm0-5h18v-2H3v2zm0-7v2h18V6H3z"/></svg>`,
    play: `<svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>`,
    stop: `<svg viewBox="0 0 24 24"><path d="M6 6h12v12H6z"/></svg>`,
    refresh: `<svg viewBox="0 0 24 24"><path d="M17.65 6.35C16.2 4.9 14.21 4 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08c-.82 2.33-3.04 4-5.65 4-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/></svg>`,
    check: `<svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>`,
    alert: `<svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>`,
    shield: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
    trash: `<svg viewBox="0 0 24 24" stroke="currentColor" fill="none" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>`,
    arrowRight: `<svg viewBox="0 0 24 24"><path d="M12 4l-1.41 1.41L16.17 11H4v2h12.17l-5.58 5.59L12 20l8-8z"/></svg>`,
    moon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>`,
    sun: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>`
};

export const showToast = (message, type = 'info') => {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `<span class="font-bold">${type.toUpperCase()}:</span> ${message}`;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 7000);
};

export const showConfirm = (message, title = 'Confirmation Required') => {
    return new Promise((resolve) => {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.innerHTML = `
            <div class="modal-container">
                <div class="modal-title">${title}</div>
                <div class="modal-body">${message}</div>
                <div class="modal-actions">
                    <button class="btn btn-secondary" id="modal-cancel">Cancel</button>
                    <button class="btn btn-primary" id="modal-confirm">Confirm</button>
                </div>
            </div>
        `;

        document.body.appendChild(overlay);

        // Force reflow for animation
        overlay.offsetHeight;
        overlay.classList.add('active');

        const cleanup = (result) => {
            overlay.classList.remove('active');
            setTimeout(() => {
                overlay.remove();
                resolve(result);
            }, 200);
        };

        overlay.querySelector('#modal-cancel').addEventListener('click', () => cleanup(false));
        overlay.querySelector('#modal-confirm').addEventListener('click', () => cleanup(true));

        // Close on overlay click
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) cleanup(false);
        });
    });
};

export const showConfirmDown = (message, title = 'Confirmation Required') => {
    return new Promise((resolve) => {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.innerHTML = `
            <div class="modal-container">
                <div class="modal-title">${title}</div>
                <div class="modal-body">${message}</div>
                <div class="modal-actions">
                    <button class="btn btn-secondary" id="modal-cancel">Cancel</button>
                    <button class="btn btn-primary" id="modal-confirm">Run</button>
                    <button class="btn btn-primary" id="modal-spindown">Run & SpinDown</button>
                </div>
            </div>
        `;

        document.body.appendChild(overlay);

        // Force reflow for animation
        overlay.offsetHeight;
        overlay.classList.add('active');

        const cleanup = (result) => {
            overlay.classList.remove('active');
            setTimeout(() => {
                overlay.remove();
                resolve(result);
            }, 200);
        };

        overlay.querySelector('#modal-cancel').addEventListener('click', () => cleanup(null));
        overlay.querySelector('#modal-confirm').addEventListener('click', () => cleanup('confirm'));
        overlay.querySelector('#modal-spindown').addEventListener('click', () => cleanup('spindown'));

        // Close on overlay click
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) cleanup(null);
        });
    });
};

export const showModal = (title, content, large = false) => {
    return new Promise((resolve) => {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.innerHTML = `
            <div class="modal-container ${large ? 'large' : ''}">
                <div class="modal-title">${title}</div>
                <div class="modal-body">${content}</div>
                <div class="modal-actions">
                    <button class="btn btn-secondary" id="modal-close">Close</button>
                </div>
            </div>
        `;

        document.body.appendChild(overlay);
        overlay.offsetHeight;
        overlay.classList.add('active');

        const cleanup = () => {
            overlay.classList.remove('active');
            setTimeout(() => {
                overlay.remove();
                resolve();
            }, 200);
        };

        overlay.querySelector('#modal-close').addEventListener('click', cleanup);
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) cleanup();
        });
    });
};

