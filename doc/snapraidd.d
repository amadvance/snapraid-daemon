Name{number}
	snapraidd - A background companion daemon for SnapRAID.

Synopsis
	:snapraidd [-c, --conf CONFIG] [-f, --foreground] [-p, --pidfile FILE]
	:	[-N, --no-cache] [-v, --verbose]

	:snapraidd [-V, --version] [-H, --help]

Description
	SnapRAID Daemon is a specialized companion service designed to move SnapRAID
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
		This option is only effective when `net_web_root` is configured
		to point to an expanded directory on the filesystem.
		It has no effect if the web assets are being served from a
		compressed .zip file, as the daemon must crawl and index the
		archive's contents at startup regardless of this flag.
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

Getting Started
	The daemon acts as a management layer for the SnapRAID CLI. Therefore,
	SnapRAID must be installed and fully configured before starting the
	service. All interactions with the underlying parity array are handled
	through the standard SnapRAID binary.

	During the installation process, a default configuration file is
	provisioned to enable the REST API and the Web UI. For users installing
	via binary packages, this file is typically placed at `/etc/snapraidd.conf`.
	If you are installing from source, it is recommended to run
	`./configure --sysconfdir=/etc` during the build process to ensure the
	configuration is placed in the standard `/etc` directory.

	Using this default configuration file, the UI is accessible locally
	via a web browser at the following address:

		+http://127.0.0.1:7627

	The default port, 7627, was chosen as a mnemonic, representing the
	word "SNAP" as typed on a standard telephone keypad.

	At startup, the daemon parses historical logs from `/var/log/snapraid`
	to reconstruct the current state of the array. These logs are
	generated and saved by the daemon itself during the execution
	of SnapRAID CLI commands. Consequently, on the very first run, this
	directory will be empty.

	In this initial scenario, the daemon automatically triggers a SnapRAID
	`read` command. This allows SnapRAID to process its internal `content`
	files and provide the daemon with the necessary metadata to establish
	the array's baseline state.

	Once the service is running, you should review `/etc/snapraidd.conf`
	or use the `Settings` panel in the UI to tailor the behavior to your
	environment.

	Typical post-installation steps include:

	* Defining a `maintenance_schedule` for automated sync and scrub
		operations.
	* Setting `spindown_idle_minutes` to optimize energy usage for
		disks not in active use.
	* Configuring the `notify_result` system to receive alerts
		regarding array health and task outcomes.

	To make manual changes to the `/etc/snapraidd.conf` file effective,
	you must either restart the daemon or send a `SIGHUP` signal to the
	running process.

	Example:
		:sudo killall -HUP snapraidd

	Unlike manual file edits, changes made through the UI are applied to
	the running process and saved to the configuration file pressing the
	`Save` button.

	By default, the daemon binds to the loopback interface, meaning the
	UI is accessible only from the local machine and not from other devices
	on the network. To allow access from other devices on the network,
	you must modify the `net_*` options to bind the daemon to a reachable
	network interface.

Health
	The array's aggregate health is determined by evaluating historical log
	data alongside real-time hardware telemetry.

	If the array transitions into a problematic state, the daemon issues
	an alert through the configured notification system. Note that the
	detection of such states is not instantaneous, it occurs during the
	telemetry collection cycle, the frequency of which is determined by
	the `probe_interval_minutes` option.

	In the REST API, the health state is reported by the `health` field.
	Whenever the health is not PASSED, a supplementary `health_reason` field
	is provided to give a discursive explanation of the specific condition or
	failure detected.

	The Web UI also reflects these states by displaying a prominent top
	banner across all pages if the health is in a problematic state. This
	ensures that critical issues are visible regardless of the specific
	dashboard view being accessed.

	The possible health states are:

	PENDING - The health has not yet been assessed. The daemon requires a
		successful hardware probe where all disks are spinning at
		least once to read SMART attributes.
		Issuing an `up` command is sufficient to satisfy this.
	PASSED - The array is fully healthy. All disks report positive SMART
		status and the last scrub found no data corruption.
	CORRUPT - Silent errors (hash or parity mismatches) were detected, though
		no physical hardware issues were identified.
		In this state, scheduled maintenance remains active.
	PREFAIL - The SMART telemetry reports a pre-failing condition (e.g.,
		reallocated sectors), or a task encountered input/output errors
		while accessing files.
		File input/output errors are temporary and they are cleared
		automatically after a successful sync.
		Automated maintenance is suspended in this state, and manual
		intervention is required.
	FAILING - The SMART telemetry reports a critical failing condition, or a
		disk has disappeared from the system.
		Automated maintenance is suspended in this state, and immediate
		manual intervention is required.

	Individual tasks also maintain a health state reflecting only the
	problems identified during that specific operation.
	For example, an array in a CORRUPT state may still produce a PASSED
	result for a `probe` task if that operation encountered no specific
	errors.

Configuration
	The SnapRAID Daemon is configured via a plain-text .conf file,
	defaulting to $PREFIX/etc/snapraidd.conf and if not found to
	/etc/snapraidd.conf. The $PREFIX variable represents the installation
	path chosen at build time (typically via the `--prefix` argument to
	the configure script).

	This file governs the behavior of the automation engine, network
	accessibility, safety interlocks, and hardware monitoring parameters.

	The configuration system is designed with a "triple-tier" management
	philosophy to balance operational convenience with rigorous system
	security:

	Tier 1 Core Network (Immutable) - This tier includes critical security
		and networking parameters, such as the master API toggle, port
		bindings, and access control lists. These settings are completely
		inaccessible via the REST API.
		To modify them, you must perform a manual file edit followed
		by a SIGHUP signal to reload the configuration into memory.
	Tier 2 Protected Operations (Secured) - These parameters involve
		security-sensitive automation, such as system user assignments,
		external script paths, and logging policies. By default, these
		options are read-only via the REST API. They can only be
		modified via API PATCH requests if the `net_config_full_access`
		flag is manually enabled in this file.
	Tier 3 Dynamic Logic (Live) - This tier consists of standard
		operational settings like maintenance schedules, scrub intensities,
		and disk monitoring intervals. These parameters are fully
		accessible and can be modified in real-time via the API.
		Changes made through the REST interface are instantly applied
		to the running process and persisted back to this file while
		preserving all existing manual comments.

	To make changes to the `/etc/snapraidd.conf` file effective, you must
	either restart the daemon or send a SIGHUP signal to the running process.
	This is required for any manual edit to ensure the daemon's memory state
	stays in sync with the file and to prevent the API from accidentally
	overwriting your changes.

	Example:
		:sudo killall -HUP snapraidd

	For a comprehensive view of how these settings are applied in a
	real-world environment, refer to the comments in the `snapraidd.conf`
	file installed.

  Network & REST API
	These settings control the network interface. These options are not
	visible from the REST API. They require a manual edit of the
	configuration file and a configuration reload (SIGHUP) to apply.

    net_enabled
	Acts as the master toggle for the network interface. When set to 1,
	the daemon enables the REST API and prepares to serve the web dashboard.
	If set to 0 or left blank, the daemon operates in a secure, local-only
	mode, and no network ports are opened.

    net_port
	Defines the specific IP address and port(s) to which the daemon binds.
	The format follows [IP_ADDRESS:]PORT[s].

	IPv4/IPv6 - Bind to specific local addresses (e.g., 127.0.0.1:7627 or
		[::1]:7627).
	Port - Providing only a port (e.g., 7627) binds to all available
		interfaces (0.0.0.0).
	Multiple_Ports - Multiple listeners can be configured by providing a
		comma-separated list.

	If left unset, the daemon defaults to 127.0.0.1:7627.

	To export the service to a VPN like Tailscale or a local network, you
	should bind to all interfaces by specifying only the port number.

	Examples:
		:net_port=127.0.0.1:7627       - IPv4 localhost only (Recommended).
		:net_port=7627                 - All IPv4 interfaces (Required for Tailscale/LAN).
		:net_port=[::1]:7627           - IPv6 loopback only.
		:net_port=127.0.0.1:7627,8080  - Listen on multiple ports on localhost.

    net_acl
	Restricts API and dashboard access to specific client IP addresses or
	subnets using a comma-separated Access Control List (ACL).

	The syntax uses + to allow and - to deny, supporting CIDR notation
	(e.g., /24). If any rules are defined, the daemon adopts a "deny by default"
	stance. The rules are processed sequentially, and the last matching rule
	determines the outcome.
	If unset, it defaults to +127.0.0.1.

	To allow access via Tailscale or similar services, ensure you add the
	relevant network prefix (e.g., +100.0.0.0/8).

	Examples:
		:net_acl=+127.0.0.1,+::1          - Allow IPv4 and IPv6 loopback.
		:net_acl=+100.0.0.0/8,+127.0.0.1  - Allow Tailscale and localhost.
		:net_acl=+192.168.1.0/24          - Allow local subnet only.

    net_security_headers
	When enabled (1), the daemon injects several browser-level security
	hardening headers into every HTTP response. These include
	Content-Security-Policy (restricting resource loading),
	X-Frame-Options (preventing clickjacking via iframes),
	X-Content-Type-Options (disabling MIME-sniffing),
	and Referrer-Policy.

	This should only be disabled (0) if the daemon is behind a reverse
	proxy (like Nginx or Traefik) that is already configured to handle
	these security headers.

    net_allowed_origin
	Configures Cross-Origin Resource Sharing (CORS) to determine which web
	applications can interact with the API.

	self - (Default/Recommended) Dynamically reflects the 'Host' header
		of the request, allowing the built-in UI to work across various hostnames or IPs.
	none - Omits CORS headers entirely, blocking browser-based access from any origin.
	URL - Restricts access to a specific origin (e.g., http://192.168.1.50:3000).

    net_config_full_access
	A security flag that determines whether sensitive configuration parameters
	can be modified via the REST API.

	By default (0), security-sensitive options are strictly read-only to
	prevent unauthorized system modifications or privilege escalation
	through the web interface.

	When set to 1, the following configuration options become accessible
	for modification via PATCH requests:

	script_run_as_user - The account used for executing pre/post scripts.
	script_pre_run - The absolute path to the pre-execution script.
	script_post_run - The absolute path to the post-execution script.
	log_directory - The persistent storage path for command outputs.
	log_retention_days - The duration for which log files are kept.
	notify_run_as_user - The account used for notification commands.
	notify_heartbeat - The command used for health monitoring pings.
	notify_result - The command used for sending task reports.
	notify_result_level -  The severity threshold for sending notifications.

    net_web_root
	Specifies the source of the web dashboard assets. The daemon supports
	both a standard directory and a single compressed ZIP file for asset
	delivery.

	The daemon resolves the location of the assets based on the following
	rules:

	ZIP_Filename - If a simple filename is provided (e.g., commander.zip),
		the daemon searches for it in $PREFIX/share/snapraidd/ or
		/usr/share/snapraidd/.
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

	The daemon recursively crawls the directory or archive at startup to
	provide high-performance, compressed delivery of the UI.

	When a directory is specified, assets are cached in memory, as a result,
	manual changes to asset files on the disk will not be reflected in the
	UI until the daemon is restarted. This behavior can be bypassed by using
	the -N, --no-cache option during daemon startup, which is recommended
	for development environments only.

  Automation & Maintenance
	These settings control the automation and maintenance tasks run by
	the SnapRAID Daemon.

	For security reasons, some of them can be set via the REST API only if the
	net_config_full_access option is enabled.

    maintenance_schedule
	Defines the timing for the automated maintenance sequence, which
	consists of a sync, followed by a scrub, and concluding with a report.
	If this option is unset, automated maintenance is disabled.

	The format must be either "HH:MM" or "Day HH:MM".
	Hours are specified in a 24-hour format (00-23), and days are
	represented by their short names (Mon, Tue, Wed, Thu, Fri, Sat, Sun).

    sync_threshold_deletes
	Sets the maximum number of deleted or missing files allowed before a
	sync operation is automatically aborted. This serves as a safety
	mechanism to prevent accidental parity loss due to unintended mass
	deletions. This safety check is enforced during automated maintenance
	schedules and tasks initiated through the Web UI.

    sync_threshold_updates
	Sets the maximum number of modified or updated files allowed before a
	sync operation is aborted. Similar to the delete threshold, this
	prevents the parity from being overwritten if an unexpected number
	of files have changed. This safety check is enforced during automated
	maintenance schedules and tasks initiated through the Web UI.

    sync_prehash
	If set to 1, the sync command is executed with the --prehash option.
	This calculates the hash of all files before the synchronization process
	begins. By hashing data before the system is subjected to the high
	CPU and I/O load typical of a sync operation, it protects against
	silent data corruption caused by faulty memory that may only trigger
	under critical system stress.
	If missing or set to 0, no pre-hashing is performed.

    sync_force_zero
	If set to 1, the daemon allows a sync to proceed even if it detects
	files that have shrunk to zero size since the last run.
	By default (missing or 0), the daemon will halt the sync to protect
	against potential data corruption or accidental file clearing.
	This setting is particularly useful for detecting and acknowledging
	instances where files, accessed during a system crash, have been
	truncated to zero bytes by the filesystem.

    scrub_percentage
	Determines the portion of the array verified after a successful sync.
	You may use decimal points to specify fractions of a percent
	(e.g., 0.7 to verify 0.7% of the array).
	If missing or set to 0, the scrub phase is skipped entirely.

    scrub_older_than
	Specifies that only blocks older than the defined number of days
	should be scrubbed. This allows the daemon to focus verification on
	older data while skipping recently synced blocks.
	If missing or set to 0, no age-based filtering is applied.

  Disk Monitoring & Power
	The following settings manage how the daemon interacts with physical
	hardware to monitor disk health and optimize energy consumption

    probe_interval_minutes
	Controls the frequency at which the daemon checks disk SMART attributes.
	To prevent unnecessary disk wear, the daemon only performs this check
	if the disks are already spinning.
	If set to 0 or left blank, SMART monitoring is disabled.

    spindown_idle_minutes
	Manages power consumption by automatically spinning down disks after
	the specified duration of inactivity.

	This timer monitors the global activity of the disks across the entire
	operating system. A disk will only be spun down if it has remained
	completely idle for the specified period. If any other application,
	service, or system process accesses the disk, the idle timer is reset.

	If this option is unset, the daemon will not manage disk power states,
	relying instead on the OS or hardware controllers.

    script_pre_run/script_post_run
	Defines absolute paths to custom scripts to be executed immediately before
	or after the sync, scrub, check, or fix commands. These scripts allow
	for custom logic such as mounting drives or sending custom alerts.

	* The path must be absolute (starting with /).
	* The script must not be world-writable (recommended permissions: 700 or 755).
	* The script owner must match the daemon user or be root.
	* The script must contain a valid shebang (e.g., #!/bin/sh).

    script_run_as_user
	Specifies the user account used to execute the pre-run and post-run
	scripts. If this is missing or blank, scripts are executed with the
	same privileges as the daemon process.

	On Linux, "nobody" is the standard choice for maximum isolation.
	On Windows, "LocalService" is the preferred choice as it provides
	minimal local access while maintaining network capabilities.
	Alternatively, "NetworkService" can be used if the script specifically
	requires the computer's network identity to access remote resources.

  Logging & Notifications
	These settings control the logging and notification operations performed
	by the SnapRAID Daemon.

    log_directory
	The log_directory defines where the output of individual SnapRAID
	commands is stored. If left unset, the daemon defaults to
	/var/log/snapraid.

	Setting this option to an empty value (log_directory = ) will
	explicitly disable the saving of command output to persistent files.

	IMPORTANT: While it is possible to leave this empty to avoid saving files,
	these logs are used by the daemon to reconstruct the past state of the
	array (e.g., tracking the last successful sync or scrub). If no log
	directory is provided, the daemon will lose its "memory" of previous
	task results every time it is restarted.

    log_retention_days
	To prevent your storage from filling up, log_retention_days sets the
	age at which old command logs are deleted. Logs are kept indefinitely
	if this is set to 0 or left unset.

    notify_syslog_enabled
	When set to 1, daemon activity is sent to the operating system system
	log (syslog/journald). While lifecycle events like starting and
	stopping are always captured, task-related messages are filtered by
	`notify_syslog_level`.

    notify_syslog_level
	Sets the minimum severity for syslog task entries.
	Possible values are `info`, `warning`, `error`, and `critical`.
	The default is `error`.

    notify_heartbeat
	Defines a command to run ONLY if the maintenance task was successful
	(it is not triggered by other tasks, such as heal or undelete).
	This is ideal for external monitoring services like "Dead Man's Snitch"
	or Healthchecks.io. If this ping stops, it indicates the server is down
	or the task is failing.

    notify_result
	Specifies a command triggered after every report task generated by
	high-level tasks or by a SMART telemetry change. The command is only
	executed if the task's result matches the `notify_result_level`.
	The daemon pipes a structured, plain-text task report directly into
	the command's stdin.

	The daemon automatically chooses a wide (80-col) or narrow (32-col)
	report based on the command and arguments used (e.g., presence of "mail"
	or "smtps" strings). Users can manually override this by adding --wide or
	--narrow to the command string. These tags are stripped before execution.

	Before execution, the daemon scans the command string and replaces the
	following tokens with dynamic values corresponding to the current
	task's state and results:

	%s - Subject string (e.g., "[ERROR] SnapRAID Maintenance").
	%l - Task level (critical, error, warning, info, debug).
	%n - ntfy priority (urgent, high, default, low, min).
	%t - ntfy tag (rotating_light, warning, default, -1, +1, heavy_check_mark).

	If the command contains --mail-from or --mail-rcpt, the daemon
	automatically prepends standard email headers (From, To, Subject)
	followed by a blank line to the report text. This ensures
	compatibility with curl's SMTP engine.

	When using curl for SMTP, it is recommended to use the --netrc flag.
	This allows curl to read credentials from a local file rather than
	exposing passwords in the command line or process list.

	File format (~/.netrc):
		:machine smtp.gmail.com
		:login your_email@gmail.com
		:password your-16-char-app-password

	If `notify_run_as_user` is configured, ensure that user has a valid
	home directory containing a .netrc file with 600 permissions for SMTP
	authentication. Failure to do so may result in authentication errors
	(e.g., curl error 55).

    notify_result_level
	Controls the filter for `notify_result`. The notification is sent only
	if the task result is equal to or more severe than this level.
	Valid values are `info` (always send), `warning`, `error`, and `critical`.
	The default is `error`.

    notify_run_as_user
	The user account used for notify_heartbeat, notify_result and mail
	notifications. If missing or left blank, the task runs with the
	daemon's current privileges.

	On Linux, "nobody" is the standard choice for maximum isolation.
	On Windows, "LocalService" is the preferred choice as it provides
	minimal local access while maintaining network capabilities.
	Alternatively, "NetworkService" can be used if the script specifically
	requires the computer's network identity to access remote resources.

    notify_differences
	If set to 1, the daemon logs a detailed list of file changes discovered
	before a sync begins. If set to 0 or missing, no difference report is
	generated.

  Notification Examples
	The following examples demonstrate common notification and heartbeat
	configurations

    External Heartbeat Monitoring (Healthchecks.io)
	To monitor that automated maintenance is running successfully, use a service
	like Healthchecks.io.

	In this example, curl sends a simple GET request to a unique monitoring URL.
	The flags ensure that curl fails silently on server errors (-f), does not hang
	indefinitely (--max-time), and attempts to overcome transient network issues (--retry).

	:notify_heartbeat = curl -f --max-time 30 --retry 3 https://hc-ping.com/your_private_uuid

    Push Notifications (ntfy.sh)
	This uses curl to send the report as a POST request to a push notification service.
	It utilizes the --narrow flag to ensure the report is readable on mobile devices
	and maps SnapRAID status to ntfy titles, priorities, and emojis via placeholders.

	:notify_result = curl --narrow -f --max-time 30 --retry 3 -H "Title: %s" -H "Priority: %n" -H "Tag: %t" -H "Email: your_email@example.com" --data-binary @- https://ntfy.sh/your_private_topic

    Local System Mail (mail)
	A traditional approach using the standard Linux mail utility. This is
	ideal if you have a local Mail Transfer Agent (MTA) like Postfix or
	Exim already configured on your system.

	:notify_result = mail -s "%s" your_user@localhost

    Direct Delivery (SMTP-over-SSL)
	This leverages curl's built-in SMTP engine for direct delivery to an
	external provider. By using the --netrc option, login credentials
	remain secured in a separate file rather than being exposed in the
	process list or logs.

	:notify_result = curl --netrc --url smtps://smtp.gmail.com:465 --ssl-reqd --mail-from your_email@gmail.com --mail-rcpt your_email@gmail.com --upload-file -

REST API
	The SnapRAID Daemon provides a comprehensive RESTful JSON interface
	for monitoring and controlling the parity array.

	For complete technical documentation, including request schemas and
	specific error codes, please refer to the `snapraidd.yaml` OpenAPI
	specification file typically located in the documentation directory of
	the installation.

  Maintenance & Recovery
	The API prioritizes orchestrated workflows over raw command execution.
	These high-level endpoints encapsulate complex SnapRAID logic into
	single, automated tasks that manage the lifecycle of the array and the
	recovery of data.
	They typically conclude with a `report` command that generates a
	notification containing the operation's results.

    /snapraid/v1/maintenance
	Triggers the complete automated maintenance sequence. It orchestrates
	a parity synchronization, followed by a data integrity scrub, and
	concludes by issuing a system-wide health report.
	This is the primary endpoint for routine array upkeep.
	This task is subject to the 'sync_threshold_deletes' and
	'sync_threshold_updates' safety checks defined in the configuration.
	The percentage of the array checked and the age filter are determined
	by the 'scrub_percentage' and 'scrub_older_than' settings.

	Example:
		:curl -X POST http://localhost:7627/snapraid/v1/maintenance

	It is implemented with the sequence of commands: up, diff, sync, scrub, and
	report.

    /snapraid/v1/heal
	Executes a specialized silent error recovery workflow. The daemon
	automatically runs a targeted fix operation to repair detected corruption,
	immediately follows up with a verification scrub of the affected
	blocks to ensure the recovery was successful, and concludes by issuing
	a report of the result.

	Example:
		:curl -X POST http://localhost:7627/snapraid/v1/heal

	It is implemented with the sequence of commands: up, fix -e, scrub -p bad,
	and report.

    /snapraid/v1/undelete
	Invokes the SnapRAID restoration engine to recover files that have been
	deleted from data disks but still exist in the parity information.
	This is used to roll back accidental deletions to the state of the
	last successful synchronization.

	Example:
		:curl -s -X POST http://localhost:7627/snapraid/v1/undelete \
		:	-H "Content-Type: application/json" \
		:	-d '{ "filters": [ "*.txt" ] }'

	It is implemented with the sequence of commands: up, fix -m -f ...,
	and report.

    /snapraid/v1/suspend_idle
	Probes the disks to gather their latest activity state and executes a
	conditional spindown operation. The daemon will only issue the
	down_idle command to disks that have exceeded the
	'spindown_idle_minutes' threshold. In this case, no report is
	generated.

	Example:
		:curl -X POST http://localhost:7627/snapraid/v1/suspend_idle

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
		:curl -s http://localhost:7627/snapraid/v1/array | jq

    /snapraid/v1/disks
	Returns a comprehensive inventory of every physical disk associated
	with the SnapRAID configuration. It reports real-time hardware
	metrics including SMART health status, temperature, and the current
	power state (Active/Spin-up vs. Standby/Spin-down).

	Example:
		:curl -s http://localhost:7627/snapraid/v1/disks | jq

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
		:curl -X GET http://localhost:7627/snapraid/v1/config | jq
		:curl -X PATCH http://localhost:7627/snapraid/v1/config \
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
		:curl -s http://localhost:7627/snapraid/v1/activity | jq

    /snapraid/v1/tasks
	Lists all tasks waiting, the task currently active, and the task
	execution history. The response from this entry point can be very long,
	as the history may span up to a month.

	Example:
		:curl -s http://localhost:7627/snapraid/v1/tasks | jq

    /snapraid/v1/stop
	Terminates the currently running task (such as sync or scrub) by
	sending a SIGTERM signal to the background process.

	Example:
		:curl -X POST http://localhost:7627/snapraid/v1/stop

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
		:curl -X GET http://localhost:7627/snapraid/v1/state | jq

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
		:curl -X POST http://localhost:7627/snapraid/v1/schedule \
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
	This section defines how the daemon responds to standard Unix signals,
	allowing for external process control and graceful management of the
	service lifecycle.

    SIGHUP
	Reloads the configuration file and resets the internal state.
	It also reloads the Web UI. This is the recommended way to
	apply changes to static	parameters without restarting the
	service.

    SIGTERM, SIGINT
	Initiates a graceful shutdown. If a task is currently
	running, the daemon attempts to terminate the child process
	before exiting.

    SIGQUIT
	Immediately terminates the process using the default signal
	action and may generate a core dump. This signal is intended
	for emergency debugging and post mortem analysis of a hung
	or misbehaving daemon. No cleanup or graceful shutdown is
	performed.

Files
	The following list specifies the default filesystem paths used by the
	daemon for configuration, data persistence, and inter-process communication.

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

Copyright
	This file is Copyright (C) 2026 Andrea Mazzoleni

See Also
	snapraid(1)
