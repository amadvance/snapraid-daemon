# SnapRAID Commander Web UI

## Overview
This application is a lightweight, frontend-only Single Page Application (SPA) designed to interface with the SnapRAID Commander daemon. It provides a web interface for monitoring disk arrays, managing maintenance tasks, viewing history, and configuring system settings.

## Technology Stack
*   **HTML5**: Semantic structure.
*   **CSS3**: Native CSS variables for theming, Flexbox/Grid for layout. No preprocessors (Sass/Less) used.
*   **JavaScript (ES6+)**: Native ES Modules. No build tools (Webpack/Vite/Parcel) or frameworks (React/Vue) are required. The browser loads modules directly via `<script type="module">`.
*   **Icons**: Inline SVG strings to avoid external dependencies.

## File Structure

```text
/
├── index.html          # Application Shell (Sidebar, Header, View Container)
├── css/
│   └── style.css       # Global styles, variables, component definitions
├── js/
│   ├── app.js          # Entry point, Router, Global State, Event Delegation
│   ├── api.js          # API Client / Data Access Layer
│   ├── ui.js           # View Layer (HTML Generators / "Components")
│   └── utils.js        # Helper functions (Formatting, Icons)
└── metadata.json       # Application metadata
```

## Architectural Patterns

### 1. The Controller (`js/app.js`)
*   **Role**: Orchestrates the application lifecycle.
*   **Routing**: Implements a custom Hash-based router (`#/`, `#/disks`, etc.).
*   **State**: Holds transient UI state (current route, polling intervals).
*   **Initialization**: Handles DOMContentLoaded, global event listeners (navigation, mobile menu).
*   **Execution**: Calls `API` methods to fetch data and passes that data to `UI` render functions to update the DOM.

### 2. The View (`js/ui.js`)
*   **Role**: Pure functions that transform data into HTML strings.
*   **Pattern**: Template Literal interpolation.
*   **Reactivity**: There is no fine-grained reactivity. When data updates, the specific view container (`#view-container`) is completely re-rendered.
*   **Components**: Functions like `renderDashboard`, `renderDiskCard` act as components.

### 3. Data Access (`js/api.js`)
*   **Role**: Abstraction layer for HTTP requests.
*   **Base URL**: `/snapraid/v1`
*   **Error Handling**: Centralized error throwing for non-2xx responses.

### 4. Styling (`css/style.css`)
*   **Theme**: Deep Dark Mode using CSS Variables (e.g., `--c-slate-950`).
*   **System**: A hybrid of semantic class names (`.sidebar`, `.card`) and utility-like helper classes (`.flex`, `.text-sm`, `.mb-4`).
*   **Responsiveness**: Mobile-first media queries (`@media (max-width: 768px)`).

## Page Breakdown

### 1. Dashboard (`#/`)
The central hub for monitoring current system status.
*   **Hero Section**: Displays the active running task (if any) with:
    *   Progress bar and percentage.
    *   ETA, Speed (MB/s), Processed Bytes, CPU Usage, Block Counts.
    *   Live scrolling log of process messages.
    *   *Idle State*: Shows the last executed task's summary.
*   **Array Card**:
    *   Overall Health Status (Passed/Prefail/Failing).
    *   Storage Usage (Total/Free/Used with progress bar).
    *   Key Stats: Failure Probability, Bad Blocks, Unsynced Blocks (with size), Total Files, Scrub Percentage.
*   **Configuration Card**:
    *   Versions (Daemon, Engine).
    *   Configuration paths and content summaries.
*   **Actions**: Stop active task, Trigger full maintenance.

### 2. Disks (`#/disks`)
Detailed breakdown of all physical drives in the array.
*   **Grouping**: Separates `Parity Disks` and `Data Disks`.
*   **Disk Cards**:
    *   Disk usage visualization.
    *   I/O and Data error counters (highlighted if non-zero).
    *   **Devices**: Lists physical devices per disk with:
        *   Power status (Active/Standby).
        *   Temperature (color-coded).
        *   SMART status (Passed/Failing/Prefail with specific error details).
        *   Device Model, Serial, Type (HDD/SSD).
*   **Actions**: Spin Up, Spin Down, Spin Down Idle.

### 3. Tasks (`#/tasks`)
Comprehensive view of the job queue and history.
*   **Queue**: List of pending tasks awaiting execution.
*   **Active**: Currently running tasks with real-time stats (Duration, %, ETA).
*   **History**: Completed tasks with:
    *   Exit Status (Code/Signal).
    *   Duration and timestamps.
    *   Expandable details view containing full execution logs.

### 4. Differences (`#/diff`)
Visualizes the "diff" state (changes since last sync).
*   **Summary Stats**: Counts of Added, Removed, Updated, Moved, Copied, Restored, and Equal files.
*   **File List**: Table of specific file paths changed, color-coded by change type.
*   **Actions**: Trigger new Diff generation.

### 5. Settings (`#/settings`)
Form to view and modify `snapraidd.conf` and daemon settings.
*   **Sections**: Automation (Schedule, Thresholds), Monitor & Log (Probe interval, Spindown timeout), Script Hooks, Notifications (Syslog, Email, Webhooks).
*   **Security**: Some fields may be read-only based on the `config_full_access` backend setting.

## Real-Time Updates

### Polling Mechanism
The application maintains a synchronized state with the backend via a polling loop managed in `js/app.js`:

*   **Frequency**: Polls `GET /state` every 3 seconds (active window).
*   **State Object**: The backend returns a light `state` object containing a `pulse` property.
*   **Reactivity**: The app compares the new `pulse` data (checksums/timestamps for different subsystems) against its local state.
    *   If `pulse.array` changes -> Refreshes Dashboard/Diff.
    *   If `pulse.activity` changes -> Refreshes Dashboard.
    *   If `pulse.disks` changes -> Refreshes Disks page.
    *   If `pulse.tasks` changes -> Refreshes Tasks page.
*   **Efficiency**: Full data fetches (`loadDashboard`, `loadDisks`, etc.) only occur when the pulse indicates a change.

### Connection State
*   **Heartbeat**: The sidebar displays a "Connected" status with a pulsing green dot.
*   **Error Handling**: If the poll fails, the app transitions to "Disconnected" (red dot), halts updates, and continuously attempts to reconnect.
*   **Global Status Bar**: The sidebar permanently displays any active running command (with spinner and progress %), allowing monitoring regardless of the current view.

## Technical Reference

### CSS Utility System
The project uses a custom, lightweight utility-first CSS framework defined in `css/style.css`. Do NOT use Tailwind classes that are not explicitly defined here.

*   **Layout**: `.flex`, `.grid-2`, `.grid-3`, `.grid-4`, `.grid-fill-*`, `.items-center`, `.justify-between`, `.gap-2`, `.gap-4`.
*   **Spacing**: `.m[t/b/l/r]-[1/2/4/6/8]`, `.p-[...]` (limited set).
*   **Typography**: `.text-xs`, `.text-sm`, `.text-lg`, `.text-xl`, `.font-bold`, `.font-mono`.
*   **Colors**: `.text-cyan`, `.text-red`, `.text-emerald`, `.text-amber`, `.text-muted`.
*   **Components**: `.card`, `.btn`, `.btn-primary/secondary/danger`, `.badge`, `.table`.

## Development Guidelines

To successfully extend this project, strictly adhere to these constraints:

1.  **Zero-Build Environment**:
    *   **Rule**: The output **MUST** work directly in a browser by opening `index.html`.
    *   **Forbidden**: `package.json`, `npm install`, `webpack`, `react`, `vue`, `.ts` files, `require()`.
    *   **Allowed**: ES Modules (`import ... from './file.js'`), native DOM API.

2.  **State Management**:
    *   **Pattern**: Centralized polling in `app.js` updates a global `state` object.
    *   **Reactivity**: Do not implement event listeners for data changes. Instead, rely on the `pollState` loop (~3s) to detect changes in `pulse` hash and trigger full-page re-renders (`load*` functions).

3.  **Styling & Theming**:
    *   **Variables**: ALWAYS use CSS variables (e.g., `var(--c-slate-900)`) for colors. Never hardcode hex values.
    *   **Dark Mode**: The app is "Deep Dark" only. Use the defined palette (`slate-950` for backgrounds, `slate-800` for cards).

When modifying this application, adhere to the following rules:

1.  **No Build Step**: Do not introduce `npm` dependencies, TypeScript compilation, or bundlers. Code must run natively in modern browsers.
2.  **ES Modules**: Use `import`/`export` syntax. Ensure file paths in imports include the extension (e.g., `import ... from './utils.js'`).
3.  **State Management**: If adding a new page, update the `switch(hash)` statement in `app.js` to handle the route and data fetching.
4.  **UI Updates**:
    *   Create a new render function in `ui.js`.
    *   Use Template Literals for HTML generation.
    *   Use existing CSS utility classes where possible.
5.  **Icons**: Add new SVG icons to the `Icons` object in `js/utils.js` rather than using `<img>` tags or external libraries.

## Future Extensibility

### Adding a New View
1.  **Update `index.html`**: Add a link to the sidebar navigation.
2.  **Update `app.js`**: Add a `case` in `handleRoute` to fetch data and call the renderer.
3.  **Update `ui.js`**: Create the `renderNewPage(data)` function.

### Adding a New Setting
1.  **Update `ui.js`**: Add the input field to `renderSettings` HTML.
2.  **Update `app.js`**: Ensure the `saveSettings` function parses the new field correctly (especially for booleans or numbers).
