Name{number}
	snapraidd - A background companion daemon for SnapRAID.

Synopsis
	:snapraidd [-c, --conf CONFIG] [-f, --foreground] [-p, --pidfile FILE]
		[-N, --no-cache] [-v, --verbose]

	:snapraidd [-V, --version] [-H, --help]

Description
	SnapRAID-Daemon is a specialized companion service designed to move SnapRAID
	from a manual, command-line interface (CLI) workflow to an 'always-on'
	background service.

	Under the hood, the daemon uses the same SnapRAID CLI binary, providing the
	same level of reliability.

	The daemon automates critical maintenance tasks, including the scheduling of
	sync and scrub operations. It further enhances array reliability by monitoring
	SMART values and providing a robust notification engine for real-time health
	updates. For energy efficiency, it manages automatic disk spindown during
	periods of inactivity.

	The daemon provides a modern REST API interface along with an integrated Web UI.
	This allows you to monitor array health, trigger maintenance tasks, and
	configure the daemon through a user-friendly browser interface or programmatically
	via the API.

Options
	The SnapRAID Daemon provides the following options:

	-c, --conf CONFIG
		Specifies the path to the configuration file. Default:
		`$PREFIX/etc/snapraidd.conf` and `/etc/snapraidd.conf` if
		not found. The $PREFIX variable represents the installation
		path chosen at build time (typically via the `--prefix`
		argument to the configure script).

	-f, --foreground
		Runs the process in the foreground. This prevents the
		daemon from detaching from the terminal (daemonizing).

	-p, --pidfile FILE
		Overrides the default location for the PID file. Default:
		`/run/snapraidd.pid`.

	-N, --no-cache
		Forces the daemon to load web interface assets directly from the
		filesystem for every request, bypassing internal memory caching.
		This is intended for development environments to allow real-time
		testing of UI changes.
		This option is not recommended for production use due to the
		increased I/O overhead and for security reasons, as it could
		potentially expose the system to directory traversal
		vulnerabilities if not properly isolated.

	-v, --verbose
		Verbose logging including all HTTP requests.

	-H, --help
		Prints a short help screen.

	-V, --version
		Prints the program version.

Configuration
	The SnapRAID Daemon is configured via a plain-text .conf file,
	defaulting to $PREFIX/etc/snapraidd.conf and if not found to
	/etc/snapraidd.conf. The $PREFIX variable represents the installation
	path chosen at build time (typically via the `--prefix` argument to
	the configure script).

	This file governs the behavior of the automation engine, network
	accessibility, safety interlocks, and hardware monitoring parameters.

	The configuration system is designed with a "hybrid" management
	philosophy to balance convenience with system security:

	Static_Parameters - Critical security and networking settings, such
		as the listening port (net_port) and the system user for
		scripts (script_run_as_user), are immutable via the REST API.
		These require manual file edits followed by a SIGHUP signal
		(e.g., systemctl reload snapraidd) to take effect.

	Dynamic_Parameters - Operational settings, like the maintenance
		schedule or scrub percentages, can be modified in real-time
		via the PATCH /snapraid/v1/config endpoint. Changes made through
		the API are instantly applied to the running process and
		persisted back to the configuration file, preserving any
		manual comments.

	To prevent race conditions, users should avoid editing the
	configuration file manually while simultaneously issuing configuration
	updates via the REST API. If a manual edit is performed while the
	daemon is active, ensure a reload is triggered immediately to
	synchronize the daemon's internal memory state with the disk.

	For complete technical documentation, please refer to the
	`snapraidd.conf.example` file.

  Network & REST API
	These settings control the network interface. These options are not
	visible from the REST API and can be set only in the snapraidd.conf
	file.

    net_enabled
	Master toggle for the HTTP interface.
	Set to 1 to enable the REST API, otherwise, the daemon operates in
	local-only mode.

    net_port
	Defines the IP address and port the daemon binds to (e.g., `127.0.0.1:8080`).
	Supports IPv4, IPv6, and multiple ports.

    net_acl
	Restricts API access to specific client IPs using a comma-separated
	list of allow (+) or deny (-) rules.

    net_security_headers
	When enabled (1), injects security headers like CSP and X-Frame-Options
	to harden the API against browser-based attacks.

    net_allowed_origin
	Configures CORS. Use `self` for standard setups, `none` to block
	browser access, or a specific URL for custom dashboards.

    net_config_full_access
	Determines if restricted parameters (like scripts and log paths) can
	be modified via the REST API. Defaults to 0 (Read-only).

    net_web_root
	Specifies the local path where the web dashboard assets are located.
	This option supports both a standard directory and a single compressed
	ZIP file. If a ZIP file is provided, the internal HTTP server will
	serve assets directly from the archive without requiring extraction to
	the disk.

	The daemon resolves the location of the assets based on the following
	rules:

	ZIP_Filename - If only a filename is provided (e.g., commander.zip),
		the daemon initiates a search within the standard installation
		data directories. It first checks the directory associated
		with the configured installation prefix, located at
		$PREFIX/share/snapraidd/, and then the system-wide data
		directory at /usr/share/snapraidd/.
	ZIP_Path - If a path to a ZIP file is provided, it must be absolute
		(e.g., /opt/snapraid/ui.zip). The daemon will attempt to use
		this specific file exclusively and will not perform a search
		in system directories.
	Directories - If the target is a directory rather than a ZIP archive,
		the path must be absolute (e.g., /var/www/snapraid-ui/).

	If the specified path or filename cannot be resolved, if a directory
	path is not absolute, or if the ZIP archive is inaccessible or
	malformed, the built-in HTTP server will be unable to serve the web
	interface.

  Automation & Maintenance
	These settings control the automation and maintenance tasks run by
	the SnapRAID daemon.

	For security reasons, some of them can be set via the REST API only if the
	net_config_full_access option is enabled.

    maintenance_schedule
	Defines when the automated sync, scrub, and report sequence occurs
	(e.g., `daily 02:00` or `weekly Mon 03:00`).

    sync_threshold_deletes
	Maximum number of deleted/missing files allowed before a scheduled
	sync is aborted to prevent accidental parity loss.

    sync_threshold_updates
	Maximum number of modified files allowed before a scheduled sync is
	suspended.

    sync_prehash
	Enables the SnapRAID prehash option to verify files before updating
	parity, protecting against faulty RAM or cables.

    sync_force_zero
	Permits synchronization even if protected files have unexpectedly
	shrunk to zero bytes.

    scrub_percentage
	The percentage of the array verified during the scrub phase of
	automated maintenance.

    scrub_older_than
	Restricts scrubbing to blocks that have not been verified within the
	specified number of days.

    probe_interval_minutes
	Interval for background health checks. SMART attributes are only
	queried if disks are already active to avoid waking them.

    spindown_idle_minutes
	Inactivity threshold (in minutes) after which the daemon will issue a
	spindown command to the disks.

    script_run_as_user
	The system user account utilized for the execution of pre- and
	post-run hooks.

    script_pre_run/script_post_run
	Absolute paths to executable shell scripts triggered before or after
	SnapRAID activity.

  Logging & Notifications
	These settings control the logging and notification operations performed
	by the SnapRAID daemon.

    log_directory
	Path where individual SnapRAID command outputs are stored as `.log`
	files. Default: `/var/log/snapraid`.

    log_retention_days
	Number of days to keep log files before they are purged.

    notify_syslog_enabled
	Enables logging of daemon activity to the OS system log (syslog/journald).

    notify_syslog_level
	Sets the minimum severity for syslog task entries.
	Possible values: info, warning, error, critical. Default: error.

    notify_heartbeat
	A shell command (e.g., `curl`) executed only upon task success, ideal
	for "dead man's switch" monitoring.

    notify_result
	A shell command triggered after task completion; it receives the task
	report via stdin.

    notify_result_level
	Controls the filter for `notify_result`. The notification is sent only
	if the task result is equal to or more severe than this level.
	Possible values: info, warning, error, critical. Default: error.

    notify_email_recipient
	Local system email address for receiving health reports.

    notify_email_level
	Sets the minimum severity for email reports.
	Possible values: info, warning, error, critical. Default: error.

    notify_differences
	If enabled, includes a detailed list of file changes (added/removed/modified)
	in the notification reports.

Rest API
	The SnapRAID Daemon provides a comprehensive RESTful JSON interface
	for monitoring and controlling the parity array.

	For complete technical documentation, including request schemas and
	specific error codes, please refer to the snapraidd.yaml OpenAPI
	specification file.

  Maintenance & Recovery
	The API prioritizes orchestrated workflows over raw command execution.
	These high-level endpoints encapsulate complex SnapRAID logic into
	single, automated tasks that manage the lifecycle of the array and the
	recovery of data.
	They typically end with a `report` command that generates a notification
	with a full report of the result of the operation.

    /snapraid/v1/maintenance
	Triggers the complete automated maintenance sequence. It orchestrates
	a parity synchronization, followed by a data integrity scrub, and
	concludes by issuing a system-wide health report.
	This is the primary endpoint for routine array upkeep.
	This task is subject to the 'sync_threshold_deletes' and
	'sync_threshold_update' safety checks defined in the configuration.
	The percentage of the array checked and the age filter are determined
	by the 'scrub_percentage' and 'scrub_older_than' settings.

	Example:
		:curl -X POST http://localhost:8080/snapraid/v1/maintenance

	It is implemented with the sequence of commands: up, diff, sync, scrub, and
	report.

    /snapraid/v1/heal
	Executes a specialized silent error recovery workflow. The daemon
	automatically runs a targeted fix operation to repair detected corruption,
	immediately follows up with a verification scrub of the affected
	blocks to ensure the recovery was successful, and concludes by issuing
	a report of the result.

	Example:
		:curl -X POST http://localhost:8080/snapraid/v1/heal

	It is implemented with the sequence of commands: up, fix -e, scrub -p bad,
	and report.

    /snapraid/v1/undelete
	Invokes the SnapRAID restoration engine to recover files that have been
	deleted from data disks but still exist in the parity information.
	This is used to roll back accidental deletions to the state of the
	last successful synchronization.

	Example:
		:curl -s -X POST http://localhost:8080/snapraid/v1/undelete \
		:	-H "Content-Type: application/json" \
		:	-d '{ "filters": [ "*.txt" ] }'

	It is implemented with the sequence of commands: up, fix -m -f ...,
	diff, and report.

    /snapraid/v1/suspend_idle
	Probes the disks to gather their latest activity state and executes a
	conditional spindown operation. The daemon will only issue the
	down_idle command to disks that have exceeded the
	'spindown_idle_minutes' threshold. In this case, no report is
	generated.

	Example:
		:curl -X POST http://localhost:8080/snapraid/v1/suspend_idle

	It is implemented with the sequence of commands: probe, down_idle.

  Monitoring & Inventory
	These endpoints provide high-level visibility into the global state of
	the storage stack and the health of the underlying physical hardware.

    /snapraid/v1/array
	Provides a high-level telemetry summary of the entire parity array.
	This includes global metadata such as total capacity across all disks,
	aggregate space utilization, the current state of parity protection,
	and the timestamp of the last successful maintenance.

	Example:
		:curl -s http://localhost:8080/snapraid/v1/array | jq

    /snapraid/v1/disks
	Returns a comprehensive inventory of every physical disk associated
	with the SnapRAID configuration. It reports real-time hardware
	metrics including SMART health status, temperature, and the current
	power state (Active/Spin-up vs. Standby/Spin-down).

	Example:
		:curl -s http://localhost:8080/snapraid/v1/disks | jq

  Configuration
	Provides a programmatic interface to retrieve and modify the
	operational parameters of the daemon in real-time.

    /snapraid/v1/config
	Retrieves and updates the current runtime configuration parameters of
	the snapraidd service. Changes are applied instantly to memory and
	persisted to the configuration file.
	Note that certain networking and security settings are read-only and
	require a manual edit and SIGHUP.

	Example:
		:curl -X GET http://localhost:8080/snapraid/v1/config | jq
		:curl -X PATCH http://localhost:8080/snapraid/v1/config \
		:	-d '{ "probe_interval_minutes": 10 }'

  Activity Control
	All operations that modify the array state are asynchronous; they
	return an HTTP 202 Accepted status and queue a task for background
	execution.

	Because tasks run in the background, these endpoints are used to
	monitor progress and manage the execution lifecycle.

    /snapraid/v1/activity
	Provides real-time telemetry for the currently executing task,
	including a progress percentage, estimated time of completion (ETA),
	and a live stream of the process log output.
	If no task is in execution, it returns the last completed task.

	Example:
		:curl -s http://localhost:8080/snapraid/v1/activity | jq

    /snapraid/v1/tasks
	Lists all tasks waiting, the task currently active, and the task
	execution history. The response from this entry point can be very long,
	as the history may span up to a month.

	Example:
		:curl -s http://localhost:8080/snapraid/v1/tasks | jq

    /snapraid/v1/stop
	Terminates the currently running task (such as sync or scrub) by
	sending a SIGTERM signal to the background process.

	Example:
		:curl -X POST http://localhost:8080/snapraid/v1/stop

  State and Cache Management
	To optimize performance and support lightweight monitoring (such as
	desktop status bars), the daemon implements a state synchronization
	mechanism via the /v1/state endpoint.

    /snapraid/v1/state
	The response provides a high-level summary of the daemon's current
	operation and health, alongside a pulse object containing sequence
	counters.

	The pulse object contains counters used for cache invalidation. Each
	field corresponds directly to a data-heavy API entry point.

	If a counter has not changed since the last request, the corresponding
	entry point is guaranteed to return the same data. If a counter is
	different, the underlying subsystem state has evolved, and the entry
	point will potentially return updated information.

	Note that the counters are not necessarily monotonically increasing
	because they are reset if the daemon restarts. You should compare
	them only for equality.

	Example:
		:curl -X GET http://localhost:8080/snapraid/v1/state | jq

  Schedule
	The schedule entry point allows batching multiple SnapRAID commands
	into a single sequential session. Upon submission, the daemon executes
	tasks in the order provided, maintaining a single-threaded execution
	flow.

	The daemon enforces strict serialization for all operations. Only one
	task can access the array at a time. All scheduled tasks are placed
	in an execution queue and executed in their scheduled order.

	To ensure data safety, the daemon employs a fail-fast policy where any
	command failure triggers the immediate cancellation of all subsequent
	tasks within the same schedule request. This prevents operations from
	running against an unstable or inconsistent array state while
	preserving any independent tasks previously queued in the system.

	The only exception is the report command, which acts as a mandatory
	finalizer. It will execute regardless of previous failures to ensure
	the generation of a report that reflects the final state of the system.

    /snapraid/v1/schedule
	Queues a sequence of standard SnapRAID operations.

	Example:
		:curl -X POST http://localhost:8080/snapraid/v1/schedule \
		:	-d '{"tasks": [{"command": "diff"}, {"command": "report"}]}'

	Supported Commands:

	up - Spins up all drives in the array.
	down - Spins down array drives to save power.
	probe - Verifies the power status of all configured disks and gathers
		SMART information for those already spinning.
	smart - Collects and parses SMART attributes from all drives to assess
		physical health.
	diff - Scans the array to identify changed, added, or deleted files
		since the last sync.
	status - Provides a summary of the array state, including parity
		levels and data distribution.
	sync - Updates the parity information to match the current state of
		the data disks.
	scrub - Verifies the integrity of the data and parity by recalculating
		checksums for a portion of the array.
	check - Performs a full verification of the array integrity without
		modifying any data.
	fix - Attempts to recover deleted files or repair corrupted data using
		the parity information.
	report - Generates a comprehensive summary of the last operations and
		array statistics.
	down_idle - Executes a conditional spindown operation of the disks that
		have exceeded the 'spindown_idle_minutes' threshold.

Signals
	SIGHUP
		Reloads the configuration file and resets the internal state.
		This is the recommended way to apply changes to static
		parameters without restarting the service.

	SIGTERM, SIGINT
		Initiates a graceful shutdown. If a task is currently
		running, the daemon attempts to terminate the child process
		before exiting.

Copyright
	This file is Copyright (C) 2026 Andrea Mazzoleni

Files
	$PREFIX/etc/snapraidd.conf
		The primary configuration file location. The $PREFIX variable
		represents the installation path chosen at build time (typically
		via the `--prefix` argument to the configure script). Common
		values include `/usr/local` or `/usr`. If this file does not
		exist, the daemon falls back to `/etc/snapraidd.conf`.

	$PREFIX/share/snapraidd
		The primary system data directory. This is the first location
		searched for the web dashboard ZIP file (e.g., commander.zip).
		If not found here, the daemon falls back to `/usr/share/snapraidd`.

	/etc/snapraidd.conf
		The secondary/system-wide configuration file location, used if
		the prefix-specific file is missing.

	/usr/share/snapraidd
		The secondary/system-wide data directory, used as a fallback for
		web assets.

	/run/snapraidd.pid
		Default PID file location.

	/var/log/snapraid
		Default directory for SnapRAID command execution logs. This
		directory contains the output of the SnapRAID binary itself,
		rather than the daemon's service logs.

See Also
	snapraid(1)
