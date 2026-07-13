# SnapRAID Daemon Project Documentation

SnapRAID-Daemon is a specialized companion service that transforms SnapRAID from a manual command-line interface (CLI) workflow into an 'always-on' background service. It provides automated maintenance, health monitoring, power management, and a REST API for remote control and monitoring.

The daemon doesn't reimplement SnapRAID's core functionality. Instead, it manages and orchestrates the existing SnapRAID CLI binary, providing the same level of reliability with enhanced automation and monitoring capabilities.

## Project Structure

### Core Source Files (`daemon/`)

The daemon is organized into focused C modules:

| Module | Purpose |
|--------|---------|
| `daemon.c` | Main entry point, CLI options parsing, daemon initialization and control |
| `app.h` | System and daemon interface declarations (e.g. system info, path finding) |
| `state.c/h` | Global state management, threading primitives (mutex/rwlock) |
| `runner.c/h` | Task execution engine, spawns SnapRAID processes, parses output |
| `scheduler.c/h` | Cron-like scheduling thread for automated maintenance |
| `parser.c/h` | Parses SnapRAID CLI output to extract progress, errors, and SMART telemetry |
| `rest.c/h` | REST API endpoints implementation (OpenAPI 3.1.0 compliant) |
| `web.c/h` | Static file serving, MIME types, compression support |
| `conf.c/h` | Configuration file parser and runtime config PATCH support |
| `log.c/h` | Logging subsystem |
| `elem.c/h` | Memory management for data structures (disks, tasks, messages) |
| `report.c/h` | Text report generation for notifications |
| `memory.c/h` | Safe memory allocation helper functions (abort on failure) |
| `support.c/h` | Utility functions (string handling, file paths, time) |
| `str.c/h` | String functions |
| `smart.c/h` | SMART monitoring, health classification, failure prediction |
| `notify.c/h` | Notification system (syslog, webhooks, result scripts) |
| `version.c/h` | Upstream version checking (queries GitHub API) |
| `zio.c/h` | Compressed and normal file I/O abstraction layer (zlib wrapper) |
| `zip.c/h` | ZIP archive parsing, used for serving bundled web assets |
| `unixapp.c` | UNIX-specific platform implementation of `app.h` and daemonization/signal handling setup |
| `mingwapp.c` | Windows-specific platform implementation of `app.h` and service wrapper |

### OS Abstraction Files (`os/`)

The platform abstraction layer is separated into `os/`:

| Module | Purpose |
|--------|---------|
| `os.h` | Core OS-independent interface declarations (syslog, signals, execution, threads, mutexes) |
| `portable.h` | Platform detection macros and compatibility definitions |
| `unix.c/h` | UNIX implementation of OS abstraction layer (fork, exec, signals, thread primitives) |
| `mingw.c/h` | Windows implementation of OS abstraction layer (process creation, registry, thread primitives) |

### State Management (`daemon/state.h`)

The daemon maintains a centralized `struct snapraid_state` protected by thread synchronization primitives.

#### Synchronization Primitives
- A **Mutex** (`state_lock`, type `thread_mutex_t`) protects the overall runtime state (excluding the web and log components).
- A **Read-Write Lock** (`web_lock`, type `thread_rwlock_t`) protects the in-memory web asset cache (`page_list`), allowing concurrent reads by worker threads while serving static files, and exclusive write access when reloading assets.
- A **Mutex** (`log_lock`, type `thread_mutex_t`) protects logging configurations and buffer queues.
- **Condition Variables** (`thread_cond_t`) are used by the runner and scheduler threads for efficient waiting and signaling.

#### Lock Management Strategy
- **Lock Hierarchy**: To prevent deadlocks, mutex acquisition follows a strict single-direction hierarchy: `state_lock` -> `log_lock` and `web_lock` -> `log_lock`. Code holding `state_lock` or `web_lock` may acquire `log_lock` (e.g. for logging or updating settings), but code holding `log_lock` must **never** acquire `state_lock` or `web_lock`. `state_lock` and `web_lock` remain independent.
- **State Lock Yielding**: To ensure high responsiveness of the REST API, the `state_lock` must not be held during slow operations like disk I/O, config file reloading, executing subprocesses, or network communication.
- **Function Naming Conventions**:
  - `_locked`: Function must be called while holding `state_lock`, and holds it continuously throughout execution without releasing it.
  - `_locked_yield`: Function must be called while holding `state_lock`, but temporarily releases `state_lock` during execution (e.g., for I/O, script execution, or network calls) and re-acquires `state_lock` before returning.
  - *(no postfix)*: Function is called without holding `state_lock` (or handles its own locking internally).

#### Core State Components

- **`pulse`**: Monotonic counters for cache invalidation (array, config, disks, tasks, activity)
- **`runner`**: Task queue manager with worker thread
- **`scheduler`**: Automated maintenance scheduler with dedicated thread
- **`global`**: Array metadata (sync/scrub timestamps, block counters, diff stats)
- **`config`**: Runtime configuration (network, maintenance, monitoring, notifications)
- **`data_list` / `parity_list`**: Disk inventory with SMART telemetry
- **`page_list`**: In-memory cache of web assets (if `net_web_root` is configured)

#### Threading Model

The daemon uses a multi-threaded architecture:

1. **Main Thread**: Handles signals, config reload (SIGHUP), REST API requests
2. **Runner Thread**: Sequential task executor (one task at a time)
3. **Scheduler Thread**: Wakes up periodically to check maintenance schedule
4. **CivetWeb Threads**: HTTP request handlers (thread pool)

All access to shared state is protected by `state_lock()` / `state_unlock()`.

### API Architecture (`snapraidd.yaml`)

The REST API is defined using **OpenAPI 3.1.0** specification (1830 lines). This file serves as the **primary functional documentation** for the daemon, providing detailed descriptions of endpoint behaviors, asynchronous task flows, and safety mechanisms (like the `maintenance` and `heal` sequences).

### Build System

- `configure.ac`: Autoconf script (detects systemd vs BSD init)
- `Makefile.am`: Source file lists, dependencies, install hooks (including rules for generating documentation)
- `uncrustify.cfg`: Code formatting rules (C style enforcement)
- Run `make doc` to regenerate all manual pages (`*.1`) and text manuals (`*.txt`)

### Development Guidelines

#### Code Style

- **Language**: The codebase uses **C99 standard** (not C11/C++)
- **Format**: Enforce via `uncrustify -c uncrustify.cfg --no-backup *.c *.h`
- **Naming**: Snake_case for functions, UPPER_CASE for macros/constants
- **Indentation**: Tabs for indentation, no alignment (existing codebase style)
- **Comments**: C-style `/** */` for multiline comments; C `/* first letter lowercase */` for single-line inline notes
- **Headers**: All `.h` files have include guards (`#ifndef __NAME_H`)
- **Preferences**: Use 0 instead of NULL and '\0'
- **Preferences**: Use prefix ++variable and --variable instead of postfix variable++ and variable-- where both are equivalent
- **Safety Checks**: Avoid adding safety checks for conditions that never happen
- **Commit Messages**: Every time a change is done, a single line commit description should be provided for that change
- **Git Commits**: Never commit changes to git.
 
#### Frontend UI Guidelines

- **JS Synchronization**: The JavaScript files in `brutale/js/` must remain completely identical to the ones in `commander/js/`. When updating the web interface logic, apply changes to `commander/js/` first, and then copy the modified files to `brutale/js/`.

#### API & Coding Guidelines

- **Safe String & Integer Utilities**:
  - Prefer `sncpy(dst, size, src)` and `sncat(dst, size, src)` over standard C library string functions.
  - Use safe number parsing wrappers: `strint()`, `struint()`, `stri64()`, `stru64()`, and `strdouble()` instead of `atoi`, `strtol`, or `sscanf`.
  - Use the string stream wrapper `ss_t` (functions `ss_init`, `ss_write`, `ss_printf`, and `ss_extract`/`ss_dup`) for dynamic string buffers.
- **String Lists (`sl_t`)**: Built on `tommy_list`. Initialize with `sl_init(&list)` and free memory with `sl_free(&list)`. Use `sl_insert_str`, `sl_insert_int`, or `sl_insert_double` to append values.
- **State Mutation & Cache Invalidation**: When modifying global configurations, disk states, active activities, or tasks, increment the corresponding monotonic pulse counter under `state->pulse` (e.g. `array`, `config`, `disks`, `tasks`, `activity`) to trigger UI updates and invalidate state cache.
