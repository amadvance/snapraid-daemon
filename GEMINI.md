# SnapRAID Daemon Project Documentation

## Overview

SnapRAID-Daemon is a specialized companion service that transforms SnapRAID from a manual command-line interface (CLI) workflow into an 'always-on' background service. It provides automated maintenance, health monitoring, power management, and a REST API for remote control and monitoring.

The daemon doesn't reimplement SnapRAID's core functionality. Instead, it manages and orchestrates the existing SnapRAID CLI binary, providing the same level of reliability with enhanced automation and monitoring capabilities.

### Key Features

- **Automated Maintenance**: Scheduled sync and scrub operations with configurable thresholds
- **SMART Monitoring**: Continuous disk health monitoring with predictive failure analysis
- **Power Management**: Automatic disk spindown during inactivity
- **Task Queue**: Sequential task execution with progress tracking and logging
- **REST API**: HTTP interface for monitoring and control
- **Web Server**: Embedded CivetWeb serving static dashboard files
- **Notification System**: Syslog, webhooks, and custom script hooks
- **State Persistence**: Task history and logs survive daemon restarts

##Project Structure

### Core Source Files (`daemon/`)

The daemon is organized into focused C modules:

| Module | Purpose |
|--------|---------|
| `daemon.c` | Main entry point, daemonization, signal handling |
| `state.c/h` | Global state management, threading primitives (mutex/rwlock) |
| `runner.c/h` | Task execution engine, spawns SnapRAID processes, parses output |
| `scheduler.c/h` | Cron-like scheduling thread for automated maintenance |
| `parser.c/h` | Parses SnapRAID CLI output to extract progress, errors, SMART data |
| `rest.c/h` | REST API endpoints implementation (OpenAPI 3.1.0 compliant) |
| `web.c/h` | Static file serving, MIME types, compression support |
| `conf.c/h` | Configuration file parser and runtime config PATCH support |
| `log.c/h` | Logging subsystem (syslog integration) |
| `elem.c/h` | Memory management for data structures (disks, tasks, messages) |
| `report.c/h` | Text report generation for notifications |
| `support.c/h` | Utility functions (string handling, SMART analysis, disk probing) |
| `unix.c` | UNIX-specific system calls (fork, exec, user switching) |

### State Management (`daemon/state.h`)

The daemon maintains a centralized `struct snapraid_state` protected by thread synchronization primitives:
- A **Mutex** (`thread_mutex_t`) protects the overall state, accessed via `state_lock()` / `state_unlock()`.
- A **Read-Write Lock** (`thread_rwlock_t`) protects the in-memory web asset cache (`page_list`), allowing concurrent reads while serving static files.
- **Condition Variables** (`thread_cond_t`) are used by the runner and scheduler threads for efficient waiting and signaling.

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

### Task Execution Model (`daemon/runner.h`)

The `runner` subsystem implements a queue-based task manager:

#### Task Lifecycle

```
QUEUE → START → RUN → (SIGNAL|TERM|CANCEL)
```

- **QUEUE**: Task waiting in `waiting_list`
- **START**: Task initializing (loading content file)
- **RUN**: Task processing blocks (progress percentage available)
- **SIGNAL**: Task received SIGTERM
- **TERM**: Task exited with status code
- **CANCEL**: Task skipped due to dependency failure or threshold violation

#### Task Structure (`struct snapraid_task`)

Key fields:
- `cmd`: Command ID (sync, scrub, diff, status, etc.)
- `pid`: Process ID of running SnapRAID instance
- `progress`, `eta_seconds`, `speed_mbs`: Real-time telemetry
- `message_list`: Structured log messages (fatal, error, info)
- `error_io`, `error_data`, `error_soft`: Error counters
-`block_*`: Block processing metrics (begin, end, idx, done)

### API Architecture (`snapraidd.yaml`)

The REST API is defined using **OpenAPI 3.1.0** specification (1830 lines). This file serves as the **primary functional documentation** for the daemon, providing detailed descriptions of endpoint behaviors, asynchronous task flows, and safety mechanisms (like the `maintenance` and `heal` sequences).

#### Endpoint Categories

1. **Command Execution**:
   - `/snapraid/v1/sync`, `/scrub`, `/check`, `/fix` - Manual SnapRAID operations
   - `/snapraid/v1/maintenance` - Automated sync → scrub → report sequence
   - `/snapraid/v1/heal` - Silent error recovery (`fix -e` → `scrub -p bad`)
   - `/snapraid/v1/undelete` - Restore missing files (`fix -m`)
   - `/snapraid/v1/stop` - Terminate running task (SIGTERM)

2. **Power Management**:
   - `/snapraid/v1/up`, `/down` - Bulk spin-up/down
   - `/snapraid/v1/down_idle` - Conditional spindown based on idle threshold
   - `/snapraid/v1/probe`, `/smart` - Disk state discovery

3. **State Queries**:
   - `/snapraid/v1/state` - Lightweight pulse counters + active command
   - `/snapraid/v1/array` - Array metadata (versions, timestamps, diff stats)
   - `/snapraid/v1/disks` - Disk inventory with SMART attributes
   - `/snapraid/v1/tasks` - Queue, active, and history views
   - `/snapraid/v1/activity` - Real-time task telemetry

4. **Configuration**:
   - `GET /snapraid/v1/config` - Read current settings
   - `PATCH /snapraid/v1/config` - Update and persist settings

#### Pulse Mechanism

The `Pulse` schema provides cache invalidation counters:
- Clients poll `/state` every 3-5 seconds
- If `pulse.disks` incremented → refresh `/disks`
- If `pulse.tasks` incremented → refresh `/tasks`
- If `pulse.activity` incremented → refresh `/activity`

This minimizes bandwidth while maintaining near-real-time UI updates.

### Configuration System (`snapraidd.conf.example`)

The configuration file template is a **comprehensive guide** to the daemon's features. It includes exhaustive inline documentation for every parameter, covering automation schedules, safety thresholds, disk monitoring intervals, power management, and security-sensitive script hooks.

The configuration file supports:
- **Live Reload**: SIGHUP preserves comments during API writes
- **Security Layers**: `net_config_full_access` flag controls write permissions
- **Network Control**: IP binding (`net_port`), ACL (`net_acl`), CORS (`net_allowed_origin`)

#### Restricted Parameters

These require `net_config_full_access = 1` to modify via API:
- `hook_script`, `hook_run_as_user`
- `notify_heartbeat`, `notify_result`, `notify_result_level`, `notify_run_as_user`

These are **immutable** via API (require manual edit + reload):
- `net_enabled`, `net_port`, `net_acl`, `net_config_full_access`, `net_web_root`

### Dependencies

#### Embedded Libraries

- **CivetWeb** (`civetweb/`): HTTP/HTTPS server (v1.15+)
  - Modified with external hooks for logging (`external_log_access.inl`)
  - Support for zlib/zstd compression
- **TommyDS** (`tommyds/`): High-performance hashtables and linked lists
  - Used for disk inventory, task lists, message queues
- **JSMN** (`jsmn/`): Minimal JSON parser for SnapRAID output parsing

#### System Libraries (detected by `configure.ac`)

- **pthreads**: Threading primitives
- **zlib**: Gzip compression (optional, for HTTP responses)
- **libzstd**: Zstandard compression (optional, for HTTP responses)
- **math (libm)**: Failure probability calculations

### Build System

#### Autotools Workflow

```bash
./autogen.sh         # Generate configure script
./configure          # Detect dependencies, select init system
make                 # Compile binary
sudo make install    # Install to /usr/local/bin
```

#### Key Build Files

- `configure.ac`: Autoconf script (detects systemd vs BSD init)
- `Makefile.am`: Source file lists, dependencies, install hooks
- `uncrustify.cfg`: Code formatting rules (C style enforcement)

#### Installation

The build system auto-detects init type:
- **systemd**: Installs to `/lib/systemd/system/snapraidd.service`
- **BSD**: Installs to `/etc/rc.d/rc.snapraidd`

Post-install hook provides systemctl commands.

### SMART Monitoring

The daemon integrates with `smartctl` (from smartmontools) to extract:

#### Attributes Tracked (`state.h` lines 51-60)

- **ID 5**: Reallocated Sector Count
- **ID 187**: Uncorrectable Error Count
- **ID 188**: Command Timeout
- **ID 197**: Current Pending Sector
- **ID 198**: Offline Uncorrectable
- **ID 4**: Start/Stop Count (spindown wear)
- **ID 9**: Power-On Hours
- **ID 193**: Load Cycle Count
- **ID 194**: Temperature Celsius

#### Health Classification

- **Passed**: No errors, SMART within specs
- **Prefail**: Predictive failure attributes ≤ threshold OR protocol errors
- **Failing**: Medium errors (bad sectors) OR I/O failures OR SMART failing bit
- **Pending**: Data unavailable (disk in standby or not yet probed)

#### Failure Probability

The daemon computes **Annual Failure Rate (AFR)** using a proprietary formula based on SMART IDs 5, 187, 188, 197, 198, then derives **Poisson probability** of at least one failure within one year.

### Notification System

#### Channels

1. **Syslog**: Daemon lifecycle + task results (filtered by `notify_syslog_level`)
2. **Heartbeat**: `curl` ping on success (for dead man's switch services)
3. **Result Hook**: Shell command receiving text report via stdin

#### Report Format (`daemon/report.c`)

Generated reports include:
- Array health summary (passed/prefail/failing)
- Sync/scrub timestamps and duration
- Error counters (I/O, data, soft)
- Bad block count and unsynced size
- Per-disk SMART summary (model, serial, errors)
- Optional diff list (if `notify_differences = 1`)

### Security Considerations

1. **Script Sandboxing**: `hook_run_as_user` / `notify_run_as_user` drop privileges
2. **Path Validation**: Absolute paths required, `..` rejected in web root
3. **API Access Control**: `net_acl` IP filtering, CORS policy
4. **Config Immutability**: Critical settings require manual file edit
5. **User Context**: `daemon_command()` uses `setuid()` for privilege separation

### Development Guidelines

#### Code Style

- **Format**: Enforce via `uncrustify -c uncrustify.cfg --no-backup *.c *.h`
- **Naming**: Snake_case for functions, UPPER_CASE for macros/constants
- **Headers**: All `.h` files have include guards (`#ifndef __NAME_H`)

#### Adding a New API Endpoint

1. Update `snapraidd.yaml` with OpenAPI schema
2. Add route handler in `daemon/rest.c` (follow existing patterns)
3. Implement business logic in appropriate module (runner, scheduler, support)
4. Increment relevant `pulse` counter (e.g., `pulse.tasks++`)
5. Test with `curl` or web dashboard

#### Extending Task Types

1. Add `CMD_*` constant in `daemon/state.h`
2. Implement command mapping in `runner_cmd()` (`daemon/runner.c`)
3. Add SnapRAID argument builder logic
4. Update parser to handle command-specific output patterns

#### Testing Approach

The project currently lacks automated tests. Verification is manual:
- Functional testing via web dashboard
- Log inspection in `/var/log/snapraid/`
- Daemon logs via `journalctl -u snapraidd -f` (systemd)

### Common Workflows

#### Starting the Daemon

```bash
# Foreground mode (for debugging)
sudo ./snapraidd -f -v

# Background mode (systemd)
sudo systemctl start snapraidd
sudo journalctl -u snapraidd -f
```

#### Triggering Maintenance

```bash
# Via API
curl -X POST http://127.0.0.1:7627/snapraid/v1/maintenance

# Via schedule (in snapraidd.conf)
maintenance_schedule = 02:00
```

#### Monitoring Task Progress

```bash
# Get active task
curl http://127.0.0.1:7627/snapraid/v1/activity | jq

# Check pulse counters
curl http://127.0.0.1:7627/snapraid/v1/state | jq .pulse
```

### File Locations

| Path | Description |
|------|-------------|
| `/etc/snapraidd.conf` | Daemon configuration |
| `/etc/snapraid.conf` | SnapRAID array configuration |
| `/var/log/snapraid/` | Task logs (YYYYMMDD-command.log) |
| `/run/snapraidd.pid` | Process ID file (when daemonized) |
| `/usr/local/bin/snapraidd` | Installed binary (default prefix) |

### Future Development

When extending this project:

#### For New Developers

- Read `README` first for high-level architecture
- Study `daemon/state.h` to understand data structures
- Review `snapraidd.yaml` for API contracts
- Check `snapraidd.conf.example` for all configuration options
- Use `valgrind` target in Makefile for memory leak detection

#### For LLM-Assisted Development

- The codebase uses **C99 standard** (not C11/C++)
- All strings are **null-terminated** (`char[]` or `char*`)
- Memory is manually managed (`malloc`/`free`, no garbage collection)
- Thread safety requires explicit `state_lock()` / `state_unlock()`
- The daemon **never modifies SnapRAID array data** directly
- All SnapRAID operations go through `daemon_spawn()` → separate process
- Parser logic in `daemon/parser.c` is fragile—changes to SnapRAID output format may break parsing

#### Architecture Constraints

- **Single Runner Thread**: Only one SnapRAID task executes at a time (by design)
- **Stateful HTTP**: CivetWeb handles keep-alive, but state is per-request
- **No Database**: All state is in-memory + file-based (logs, content file)
- **Content File**: Owned by SnapRAID, daemon treats as read-only except during sync

### Key Insights

1. **Separation of Concerns**: The daemon is a **coordinator**, not a reimplementation of SnapRAID algorithms
2. **Reliability**: By using the official SnapRAID binary, compatibility is guaranteed
3. **Observability**: The pulse mechanism + structured logging enable responsive UIs without complex pub-sub
4. **Progressive Power-Off**: Idle detection + spindown save energy on low-activity NAS setups
5. **Safety Thresholds**: `sync_threshold_deletes` / `sync_threshold_updates` prevent runaway parity updates from accidental bulk deletions

### Additional Resources

- **SnapRAID Documentation**: https://www.snapraid.it/manual
- **API Spec (Functional Docs)**: `snapraidd.yaml` (Detailed endpoint behavior and state transitions)
- **Config Template (Feature Guide)**: `snapraidd.conf.example` (Exhaustive parameter documentation)
- **OpenAPI Validator**: `npx @redocly/cli lint snapraidd.yaml`
- **CivetWeb Repository**: https://github.com/civetweb/civetweb
-**TommyDS Algorithms**: https://www.tommyds.it/

### Version Information

The version is auto-generated from git tags via `autover.sh`:
```bash
git describe --always --dirty
```

This ensures binaries can be traced back to specific commits.
