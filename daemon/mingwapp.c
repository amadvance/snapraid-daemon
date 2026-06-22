// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#include "portable.h"

#ifdef __MINGW32__ /* Only for MingW */

#include "os.h"
#include "app.h"
#include "support.h"
#include "log.h"

/****************************************************************************/
/* global */

static char path_snapraid[PATH_MAX];
static char path_conf[PATH_MAX];
static char path_log[PATH_MAX];
static char path_data[PATH_MAX];

/****************************************************************************/
/* app */

const char* app_find_engine(const char* sys_engine)
{
	wchar_t conv[CONV_MAX];
	const char* path;

	if (sys_engine && sys_engine[0])
		path = sys_engine;
	else
		path = path_snapraid;

	DWORD attrib = GetFileAttributesW(u8tou16(conv, path));

	/* check for existence every time in case it's installed at later time */
	if (attrib == INVALID_FILE_ATTRIBUTES)
		return 0;

	return path;
}

const char* app_find_curl(void)
{
	static char path_curl_resolved[PATH_MAX];
	wchar_t path_buf[PATH_MAX];

	if (windows_is_wine()) {
		return "/usr/bin/curl";
	}

	if (SearchPathW(NULL, L"curl.exe", NULL, PATH_MAX, path_buf, NULL) != 0) {
		u16tou8(path_curl_resolved, path_buf);
		return path_curl_resolved;
	}

	return 0;
}

const char* app_find_docker(void)
{
	static char path_docker[PATH_MAX];
	wchar_t path_buf[PATH_MAX];

	if (windows_is_wine()) {
		return "/usr/bin/docker";
	}

	if (SearchPathW(NULL, L"docker.exe", NULL, PATH_MAX, path_buf, NULL) != 0) {
		u16tou8(path_docker, path_buf);
		return path_docker;
	}

	return 0;
}

const char* app_find_poweroff(void)
{
	return 0;
}

void app_default_log(char* dst, size_t dst_size)
{
	sncpy(dst, dst_size, path_log);
}

void app_default_conf(char* dst, size_t dst_size)
{
	sncpy(dst, dst_size, path_conf);
}

void app_default_data(char* dst, size_t dst_size, const char* root)
{
	snprintf(dst, dst_size, "%s%s", path_data, root);
}

void get_windows_version(struct snapraid_system* system)
{
	/* fallback */
	snprintf(system->os_distribution, MSG_MAX, "Windows (Unknown)");
	snprintf(system->kernel_version, KEYWORD_MAX, "(Unknown)");

	HMODULE h = GetModuleHandleW(L"ntdll.dll");
	if (!h)
		return;

	NTSTATUS(WINAPI * ptr_RtlGetVersion)(RTL_OSVERSIONINFOW*);
	ptr_RtlGetVersion = (void*)GetProcAddress(h, "RtlGetVersion");
	if (!ptr_RtlGetVersion)
		return;

	RTL_OSVERSIONINFOW rovi = { 0 };
	rovi.dwOSVersionInfoSize = sizeof(rovi);
	if (ptr_RtlGetVersion(&rovi) != 0)
		return;

	const char* name = "Windows";
	if (rovi.dwMajorVersion == 10) {
		/* Windows 11 is technically Major 10, but Build >= 22000 */
		name = (rovi.dwBuildNumber >= 22000) ? "Windows 11" : "Windows 10";
	} else if (rovi.dwMajorVersion == 6) {
		if (rovi.dwMinorVersion == 3)
			name = "Windows 8.1";
		else if (rovi.dwMinorVersion == 2)
			name = "Windows 8";
		else if (rovi.dwMinorVersion == 1)
			name = "Windows 7";
	}

	snprintf(system->os_distribution, MSG_MAX, "%s", name);
	snprintf(system->kernel_version, KEYWORD_MAX, "Build %lu", rovi.dwBuildNumber);
}

void app_system_info(struct snapraid_system* system)
{
	DWORD size = KEYWORD_MAX;
	if (!GetComputerNameA(system->hostname, &size)) {
		strncpy(system->hostname, "Unknown", KEYWORD_MAX);
	}

	get_windows_version(system);

	HKEY hKey;
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		DWORD cpu_model_size = sizeof(system->cpu_model) - 1; /* space for terminator not necessarely added by RegQueryValueExA */
		if (RegQueryValueExA(hKey, "ProcessorNameString", NULL, NULL, (LPBYTE)system->cpu_model, &cpu_model_size) != ERROR_SUCCESS)
			cpu_model_size = 0;
		system->cpu_model[cpu_model_size] = 0;
		RegCloseKey(hKey);
	}

	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		char vendor[128];
		char product[128];
		DWORD vendor_size = sizeof(vendor) - 1; /* space for terminator not necessarely added by RegQueryValueExA */
		DWORD product_size = sizeof(product) - 1; /* space for terminator not necessarely added by RegQueryValueExA */
		if (RegQueryValueExA(hKey, "BaseBoardManufacturer", NULL, NULL, (LPBYTE)vendor, &vendor_size) != ERROR_SUCCESS)
			vendor_size = 0;
		if (RegQueryValueExA(hKey, "BaseBoardProduct", NULL, NULL, (LPBYTE)product, &product_size) != ERROR_SUCCESS)
			product_size = 0;
		vendor[vendor_size] = 0;
		product[product_size] = 0;
		snprintf(system->motherboard, sizeof(system->motherboard), "%s %s", vendor, product);
		RegCloseKey(hKey);
	}

	MEMORYSTATUSEX memInfo;
	memInfo.dwLength = sizeof(MEMORYSTATUSEX);
	if (GlobalMemoryStatusEx(&memInfo)) {
		system->memory_total_bytes = memInfo.ullTotalPhys;
	}

	/* ECC detection in plain C without WMI is complex. Defaulting to 0 for standard API. */
	system->is_ecc = 0;
}

void app_system_refresh(struct snapraid_system* system)
{
	/* GetTickCount64 returns milliseconds since boot */
	system->uptime_seconds = GetTickCount64() / 1000;

	MEMORYSTATUSEX memInfo;
	memInfo.dwLength = sizeof(MEMORYSTATUSEX);
	if (GlobalMemoryStatusEx(&memInfo)) {
		system->memory_free_bytes = memInfo.ullAvailPhys;
	}
}

int os_shutdown(void)
{
	HANDLE h_token;
	TOKEN_PRIVILEGES tkp;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &h_token)) {
		LookupPrivilegeValueW(0, L"SeShutdownPrivilege", &tkp.Privileges[0].Luid);
		tkp.PrivilegeCount = 1;
		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(h_token, 0, &tkp, 0, (PTOKEN_PRIVILEGES)0, 0);
		CloseHandle(h_token);
	}

	if (!InitiateSystemShutdownExW(
			0,
			0,
			0,
			1,
			0,
			0
		)) {
		DWORD err = GetLastError();
		windows_errno(err);
		log_task(LVL_ERROR, "failed to initiate system shutdown, error=%lu", (unsigned long)err);
		return -1;
	}

	return 0;
}

void app_init(void)
{
	WCHAR conv[CONV_MAX];

	if (windows_is_wine()) {
		strcpy(path_log, "log");
		strcpy(path_conf, "/etc/snapraidd.conf");
		strcpy(path_data, "/usr/share/snapraidd/");
		strcpy(path_snapraid, "/usr/bin/snapraid");
	} else {
		snwprintf(conv, PATH_MAX, L"%lslog", windows_exedir());
		u16tou8(path_log, conv);

		snwprintf(conv, PATH_MAX, L"%lssnapraidd.conf", windows_exedir());
		u16tou8(path_conf, conv);

		snwprintf(conv, PATH_MAX, L"%ls", windows_exedir());
		u16tou8(path_data, conv);

		snwprintf(conv, PATH_MAX, L"%lssnapraid.exe", windows_exedir());
		u16tou8(path_snapraid, conv);
	}
}

void app_done(void)
{
}

/****************************************************************************/
/* daemon */

#include "messages.h"

SERVICE_STATUS g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
static DWORD dwCheckPoint = 1;
/**
 * log_event - A printf-like wrapper for the Windows Event Log
 * @type:   The Windows event type (EVENTLOG_INFORMATION_TYPE, etc.)
 * @format: The format string (standard printf style)
 */
void windows_eventlog(int level, const char* msg)
{
	HANDLE h;
	const char* strings[1];
	DWORD id;
	DWORD type;

	if (!g_StatusHandle) {
		fprintf(stderr, "%s\n", msg);
		return;
	}

	/* determine the MessageId from messages.mc based on the log level */
	switch (level) {
	case LVL_CRITICAL :
	case LVL_ERROR :
		id = MSG_ERROR;
		type = EVENTLOG_ERROR_TYPE;
		break;
	case LVL_WARNING :
		id = MSG_WARN;
		type = EVENTLOG_WARNING_TYPE;
		break;
	default :
	case LVL_INFO :
	case LVL_DEBUG :
		id = MSG_INFO;
		type = EVENTLOG_INFORMATION_TYPE;
		break;
	}

	h = RegisterEventSource(NULL, DAEMON_NAME);
	if (!h)
		return;

	strings[0] = msg;

	ReportEvent(h,
		type,
		0,
		id,
		NULL,
		1, /* one string */
		0,
		strings,
		NULL);

	DeregisterEventSource(h);
}

/* Console control handler - forwards Ctrl+C, Ctrl+Break to child */
static BOOL WINAPI console_handler(DWORD ctrl_type)
{
	switch (ctrl_type) {
	case CTRL_C_EVENT :
	case CTRL_BREAK_EVENT :
		/*
		 * Return TRUE to prevent parent termination. The child process
		 * will receive these events automatically because it's attached
		 * to the same console, so we don't need to forward them.
		 */
		state_ptr()->daemon_running = DAEMON_QUIT;
		state_ptr()->daemon_sig = SIGINT;
		return TRUE; /* signal handled, don't terminate parent */
	case CTRL_CLOSE_EVENT :
	case CTRL_LOGOFF_EVENT :
	case CTRL_SHUTDOWN_EVENT :
		/*
		 * Return TRUE to prevent our termination while child handles shutdown.
		 * The child receives these events automatically (same console).
		 * Note: Windows will forcibly kill us after a timeout regardless
		 * of returning TRUE: ~5 seconds for CLOSE_EVENT and LOGOFF_EVENT,
		 * ~5-20 seconds for SHUTDOWN_EVENT (configurable in registry).
		 */
		state_ptr()->daemon_running = DAEMON_QUIT;
		state_ptr()->daemon_sig = SIGTERM;
		return TRUE; /* signal handled, but Windows will kill us after timeout */
	default :
		return FALSE;
	}
}

void report_progress(DWORD currentState, DWORD exitCode, DWORD waitHint)
{
	g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	g_ServiceStatus.dwCurrentState = currentState;

	if (currentState == SERVICE_START_PENDING) {
		g_ServiceStatus.dwControlsAccepted = 0;
	} else {
		g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	}

	g_ServiceStatus.dwWin32ExitCode = exitCode;
	if (exitCode == ERROR_SERVICE_SPECIFIC_ERROR) {
		g_ServiceStatus.dwServiceSpecificExitCode = 1;
	} else {
		g_ServiceStatus.dwServiceSpecificExitCode = 0;
	}

	if (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED) {
		g_ServiceStatus.dwCheckPoint = 0;
		g_ServiceStatus.dwWaitHint = 0;
		dwCheckPoint = 1; /* reset value for the next pending case */
	} else {
		/* increment checkpoint to prove we aren't "frozen" during PENDING states */
		g_ServiceStatus.dwCheckPoint = dwCheckPoint++;
		g_ServiceStatus.dwWaitHint = waitHint;
	}

	SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode)
{
	switch (CtrlCode) {
	case SERVICE_CONTROL_STOP :
	case SERVICE_CONTROL_SHUTDOWN :
		if (g_ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
			/* signal the runner to stop */
			state_ptr()->daemon_running = DAEMON_QUIT;
			state_ptr()->daemon_sig = SIGTERM;

			/* tell the OS we are trying to stop */
			report_progress(SERVICE_STOP_PENDING, NO_ERROR, 5000);
		}
		break;
	default :
		break;
	}
}

VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv)
{
	(void)argc;
	(void)argv;

	struct snapraid_state* state = state_ptr();

	g_StatusHandle = RegisterServiceCtrlHandler(DAEMON_NAME, ServiceCtrlHandler);
	if (g_StatusHandle == NULL)
		return;

	windows_eventlog(LVL_INFO, "Service starting");
	report_progress(SERVICE_START_PENDING, NO_ERROR, 5000);

	if (daemon_init(state) != 0) {
		windows_eventlog(LVL_ERROR, "Service startup failed");
		report_progress(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
		return;
	}

	windows_eventlog(LVL_INFO, "Service started");
	report_progress(SERVICE_RUNNING, NO_ERROR, 0);

	daemon_run(state);

	windows_eventlog(LVL_INFO, "Service stopping");
	daemon_done(state);

	state_done(state);

	windows_eventlog(LVL_INFO, "Service stopped");
	report_progress(SERVICE_STOPPED, NO_ERROR, 0);

	os_done();
}

void windows_starting(void)
{
	if (!g_StatusHandle)
		return;

	report_progress(SERVICE_START_PENDING, NO_ERROR, 3000);
}

int main(int argc, char* argv[])
{
	struct snapraid_state* state = state_init();

	os_init();
	app_init();

	daemon_options(state, argc, argv);

	if (state->log.foreground) {
		if (!SetConsoleCtrlHandler(console_handler, TRUE)) {
			exit(EXIT_FAILURE);
		}

		if (daemon_init(state) != 0)
			exit(EXIT_FAILURE);

		daemon_run(state);

		daemon_done(state);

		state_done(state);

		app_done();
		os_done();
	} else {
		SERVICE_TABLE_ENTRY ServiceTable[] = {
			{ (char*)DAEMON_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
			{ NULL, NULL }
		};

		if (StartServiceCtrlDispatcher(ServiceTable) == FALSE) {
			DWORD err = GetLastError();
			if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
				fprintf(stderr, "This program must be run as a service. Use -f, --foreground to run as an application.\n");
			}
			return err;
		}
	}

	return 0;
}
#endif

