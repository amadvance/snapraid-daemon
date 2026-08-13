// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#include "os/portable.h"

#ifdef __MINGW32__ /* Only for MingW */

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
/* signal */

int os_signal_interrupt(void)
{
	return !state_ptr()->daemon_running;
}

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

	if (SearchPathW(0, L"curl.exe", 0, PATH_MAX, path_buf, 0) != 0) {
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

	if (SearchPathW(0, L"docker.exe", 0, PATH_MAX, path_buf, 0) != 0) {
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
		if (RegQueryValueExA(hKey, "ProcessorNameString", 0, 0, (LPBYTE)system->cpu_model, &cpu_model_size) != ERROR_SUCCESS)
			cpu_model_size = 0;
		system->cpu_model[cpu_model_size] = 0;
		RegCloseKey(hKey);
	}

	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		char vendor[128];
		char product[128];
		DWORD vendor_size = sizeof(vendor) - 1; /* space for terminator not necessarely added by RegQueryValueExA */
		DWORD product_size = sizeof(product) - 1; /* space for terminator not necessarely added by RegQueryValueExA */
		if (RegQueryValueExA(hKey, "BaseBoardManufacturer", 0, 0, (LPBYTE)vendor, &vendor_size) != ERROR_SUCCESS)
			vendor_size = 0;
		if (RegQueryValueExA(hKey, "BaseBoardProduct", 0, 0, (LPBYTE)product, &product_size) != ERROR_SUCCESS)
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

static int is_our_service(const char* name)
{
	size_t len = strlen(DAEMON_NAME);
	if (strncmp(name, DAEMON_NAME, len) != 0)
		return 0;
	if (name[len] == 0 || name[len] == '-')
		return 1;
	return 0;
}

static int wait_for_service_stop(SC_HANDLE schService)
{
	SERVICE_STATUS_PROCESS ssp;
	DWORD dwBytesNeeded;
	int count = 0;

	while (count < 300) {
		if (!QueryServiceStatusEx(
				schService,
				SC_STATUS_PROCESS_INFO,
				(LPBYTE)&ssp,
				sizeof(SERVICE_STATUS_PROCESS),
				&dwBytesNeeded
			)) {
			return -1;
		}

		if (ssp.dwCurrentState == SERVICE_STOPPED) {
			return 0;
		}

		Sleep(100);
		++count;
	}

	return -1;
}

static SC_HANDLE open_sc_manager(void)
{
	SC_HANDLE schSCManager = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	if (0 == schSCManager) {
		DWORD err = GetLastError();
		if (err == ERROR_ACCESS_DENIED) {
			fprintf(stderr, "Error: Access denied. You must run this command as Administrator.\n");
		} else {
			fprintf(stderr, "OpenSCManager failed (%lu)\n", err);
		}
	}
	return schSCManager;
}

static int enum_services_status(SC_HANDLE schSCManager, ENUM_SERVICE_STATUS_PROCESSW** out_services, DWORD* out_count)
{
	DWORD dwBytesNeeded = 0;
	DWORD dwServicesReturned = 0;
	DWORD dwResumeHandle = 0;
	LPBYTE lpBuffer = 0;

	*out_services = 0;
	*out_count = 0;

	while (1) {
		BOOL ok = EnumServicesStatusExW(
			schSCManager,
			SC_ENUM_PROCESS_INFO,
			SERVICE_WIN32,
			SERVICE_STATE_ALL,
			lpBuffer,
			dwBytesNeeded,
			&dwBytesNeeded,
			&dwServicesReturned,
			&dwResumeHandle,
			0
		);

		if (ok) {
			*out_services = (ENUM_SERVICE_STATUS_PROCESSW*)lpBuffer;
			*out_count = dwServicesReturned;
			return 0;
		}

		DWORD err = GetLastError();
		if (err == ERROR_MORE_DATA) {
			/*
			 * Reallocate lpBuffer with dwBytesNeeded and reset dwResumeHandle to 0 to fetch all services
			 * in a single call. If new services are registered concurrently, the loop reallocates and retries
			 * until it successfully completes.
			 */
			free(lpBuffer);
			lpBuffer = malloc_nofail(dwBytesNeeded);
			dwResumeHandle = 0;
			continue;
		}

		fprintf(stderr, "EnumServicesStatusEx failed (%lu)\n", err);
		free(lpBuffer);
		return -1;
	}
}

static int do_service_start_all(void)
{
	SC_HANDLE schSCManager;
	ENUM_SERVICE_STATUS_PROCESSW* services = 0;
	DWORD dwServicesReturned = 0;
	int overall_success = 0;

	schSCManager = open_sc_manager();
	if (0 == schSCManager) {
		return -1;
	}

	if (enum_services_status(schSCManager, &services, &dwServicesReturned) != 0) {
		CloseServiceHandle(schSCManager);
		return -1;
	}

	for (DWORD i = 0; i < dwServicesReturned; ++i) {
		const wchar_t* wname = services[i].lpServiceName;
		char name[128];
		u16tou8(name, wname);
		if (is_our_service(name)) {
			printf("Starting service %s...\n", name);
			SC_HANDLE schService = OpenServiceW(schSCManager, wname, SERVICE_START);
			if (schService != 0) {
				if (!StartServiceW(schService, 0, 0)) {
					DWORD err = GetLastError();
					if (err == ERROR_SERVICE_ALREADY_RUNNING) {
						printf("Service %s is already running.\n", name);
					} else {
						fprintf(stderr, "StartService %s failed (%lu)\n", name, err);
						overall_success = -1;
					}
				} else {
					printf("Service %s started successfully.\n", name);
				}
				CloseServiceHandle(schService);
			} else {
				fprintf(stderr, "OpenService %s failed (%lu)\n", name, GetLastError());
				overall_success = -1;
			}
		}
	}

	free(services);
	CloseServiceHandle(schSCManager);
	return overall_success;
}

static int do_service_stop_all(void)
{
	SC_HANDLE schSCManager;
	ENUM_SERVICE_STATUS_PROCESSW* services = 0;
	DWORD dwServicesReturned = 0;
	int overall_success = 0;

	schSCManager = open_sc_manager();
	if (0 == schSCManager) {
		return -1;
	}

	if (enum_services_status(schSCManager, &services, &dwServicesReturned) != 0) {
		CloseServiceHandle(schSCManager);
		return -1;
	}

	for (DWORD i = 0; i < dwServicesReturned; ++i) {
		const wchar_t* wname = services[i].lpServiceName;
		char name[128];
		u16tou8(name, wname);
		if (is_our_service(name)) {
			printf("Stopping service %s...\n", name);
			SC_HANDLE schService = OpenServiceW(schSCManager, wname, SERVICE_STOP | SERVICE_QUERY_STATUS);
			if (schService != 0) {
				SERVICE_STATUS status;
				if (!ControlService(schService, SERVICE_CONTROL_STOP, &status)) {
					DWORD err = GetLastError();
					if (err == ERROR_SERVICE_NOT_ACTIVE) {
						printf("Service %s is not active.\n", name);
					} else {
						fprintf(stderr, "ControlService %s failed (%lu)\n", name, err);
						overall_success = -1;
					}
				} else {
					if (wait_for_service_stop(schService) != 0) {
						fprintf(stderr, "Service %s failed to stop within 30 seconds.\n", name);
						overall_success = -1;
					} else {
						printf("Service %s stopped successfully.\n", name);
					}
				}
				CloseServiceHandle(schService);
			} else {
				fprintf(stderr, "OpenService %s failed (%lu)\n", name, GetLastError());
				overall_success = -1;
			}
		}
	}

	free(services);
	CloseServiceHandle(schSCManager);
	return overall_success;
}

static int do_service_remove_all(void)
{
	SC_HANDLE schSCManager;
	ENUM_SERVICE_STATUS_PROCESSW* services = 0;
	DWORD dwServicesReturned = 0;
	int overall_success = 0;

	schSCManager = open_sc_manager();
	if (0 == schSCManager) {
		return -1;
	}

	if (enum_services_status(schSCManager, &services, &dwServicesReturned) != 0) {
		CloseServiceHandle(schSCManager);
		return -1;
	}

	for (DWORD i = 0; i < dwServicesReturned; ++i) {
		const wchar_t* wname = services[i].lpServiceName;
		char name[128];
		u16tou8(name, wname);
		if (is_our_service(name)) {
			printf("Removing service %s...\n", name);
			SC_HANDLE schService = OpenServiceW(schSCManager, wname, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
			if (schService != 0) {
				SERVICE_STATUS status;
				int stopped = 1;
				ControlService(schService, SERVICE_CONTROL_STOP, &status);
				if (wait_for_service_stop(schService) != 0) {
					fprintf(stderr, "Service %s failed to stop within 30 seconds for removal.\n", name);
					overall_success = -1;
					stopped = 0;
				}
				if (!DeleteService(schService)) {
					fprintf(stderr, "DeleteService %s failed (%lu)\n", name, GetLastError());
					overall_success = -1;
				} else if (!stopped) {
					printf("Service %s is running. It has been marked for deletion and will be removed once it stops.\n", name);
				}
				CloseServiceHandle(schService);

				char reg_path[PATH_MAX];
				wchar_t wreg_path[PATH_MAX];
				snprintf(reg_path, sizeof(reg_path), "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\%s", name);
				if (u8tou16_mayfail(wreg_path, sizeof(wreg_path) / sizeof(wreg_path[0]), reg_path, strlen(reg_path) + 1, 0))
					RegDeleteKeyW(HKEY_LOCAL_MACHINE, wreg_path);
			} else {
				fprintf(stderr, "OpenService %s failed (%lu)\n", name, GetLastError());
				overall_success = -1;
			}
		}
	}

	free(services);
	CloseServiceHandle(schSCManager);
	return overall_success;
}

static int do_service_list(void)
{
	SC_HANDLE schSCManager;
	ENUM_SERVICE_STATUS_PROCESSW* services = 0;
	DWORD dwServicesReturned = 0;
	int count = 0;

	schSCManager = OpenSCManagerW(0, 0, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
	if (0 == schSCManager) {
		fprintf(stderr, "OpenSCManager failed (%lu)\n", GetLastError());
		return -1;
	}

	if (enum_services_status(schSCManager, &services, &dwServicesReturned) != 0) {
		CloseServiceHandle(schSCManager);
		return -1;
	}

	printf("Registered SnapRAID Daemon services:\n\n");
	printf("%-24s %-32s %-12s\n", "Service Name", "Display Name", "Status");
	printf("----------------------------------------------------------------------\n");

	for (DWORD i = 0; i < dwServicesReturned; ++i) {
		const wchar_t* wname = services[i].lpServiceName;
		char name[128];
		u16tou8(name, wname);
		if (is_our_service(name)) {
			char display[128];
			u16tou8(display, services[i].lpDisplayName);
			const char* status_str;
			switch (services[i].ServiceStatusProcess.dwCurrentState) {
			case SERVICE_STOPPED : status_str = "Stopped"; break;
			case SERVICE_START_PENDING : status_str = "Starting"; break;
			case SERVICE_STOP_PENDING : status_str = "Stopping"; break;
			case SERVICE_RUNNING : status_str = "Running"; break;
			case SERVICE_CONTINUE_PENDING : status_str = "Continue Pending"; break;
			case SERVICE_PAUSE_PENDING : status_str = "Pause Pending"; break;
			case SERVICE_PAUSED : status_str = "Paused"; break;
			default : status_str = "Unknown"; break;
			}

			printf("%-24s %-32s %-12s\n", name, display, status_str);
			++count;
		}
	}

	if (count == 0) {
		printf("No services found.\n");
	} else {
		printf("\nTotal: %d service(s) found.\n", count);
	}

	free(services);
	CloseServiceHandle(schSCManager);
	return 0;
}

static char service_name[128] = DAEMON_NAME;
static char service_display[128] = "SnapRAID Daemon";
static char service_desc[256] = "SnapRAID Daemon Service";

void app_instance(const char* instance)
{
	if (instance && instance[0]) {
		snprintf(service_name, sizeof(service_name), "%s-%s", DAEMON_NAME, instance);
		snprintf(service_display, sizeof(service_display), "SnapRAID Daemon - %s", instance);
		snprintf(service_desc, sizeof(service_desc), "SnapRAID Daemon Service - '%s'", instance);
	} else {
		sncpy(service_name, sizeof(service_name), DAEMON_NAME);
		sncpy(service_display, sizeof(service_display), "SnapRAID Daemon");
		sncpy(service_desc, sizeof(service_desc), "SnapRAID Daemon Service");
	}
}

static int do_service_install(const struct snapraid_state* state)
{
	wchar_t wpath[PATH_MAX];
	char path[PATH_MAX];
	char bin_path[PATH_MAX * 4];
	wchar_t wservice_name[128];
	wchar_t wservice_display[128];
	wchar_t wbin_path[PATH_MAX * 4];
	SC_HANDLE schSCManager;
	SC_HANDLE schService;
	HKEY hk;

	GetModuleFileNameW(0, wpath, PATH_MAX);
	u16tou8(path, wpath);

	if (state->config.conf[0]) {
		wchar_t wconf[PATH_MAX];
		if (!u8tou16_mayfail(wconf, sizeof(wconf) / sizeof(wconf[0]), state->config.conf, strlen(state->config.conf) + 1, 0)) {
			fprintf(stderr, "Failed conversion of configuration file\n");
			return -1;
		}

		DWORD attrib = GetFileAttributesW(wconf);
		if (attrib == INVALID_FILE_ATTRIBUTES || (attrib & FILE_ATTRIBUTE_DIRECTORY)) {
			fprintf(stderr, "Warning: config file '%s' not found\n", state->config.conf);
		}
	}

	sncpy(bin_path, sizeof(bin_path), "\"");
	sncat(bin_path, sizeof(bin_path), path);
	sncat(bin_path, sizeof(bin_path), "\"");

	if (state->instance[0]) {
		sncat(bin_path, sizeof(bin_path), " -i ");
		sncat(bin_path, sizeof(bin_path), state->instance);
	}
	if (state->config.conf[0]) {
		sncat(bin_path, sizeof(bin_path), " -c \"");
		sncat(bin_path, sizeof(bin_path), state->config.conf);
		sncat(bin_path, sizeof(bin_path), "\"");
	}
	if (state->array.engine_conf[0]) {
		sncat(bin_path, sizeof(bin_path), " -C \"");
		sncat(bin_path, sizeof(bin_path), state->array.engine_conf);
		sncat(bin_path, sizeof(bin_path), "\"");
	}

	if (!u8tou16_mayfail(wservice_name, sizeof(wservice_name) / sizeof(wservice_name[0]), service_name, strlen(service_name) + 1, 0)
		|| !u8tou16_mayfail(wservice_display, sizeof(wservice_display) / sizeof(wservice_display[0]), service_display, strlen(service_display) + 1, 0)
		|| !u8tou16_mayfail(wbin_path, sizeof(wbin_path) / sizeof(wbin_path[0]), bin_path, strlen(bin_path) + 1, 0)) {
		fprintf(stderr, "Failed conversion of Service Name/Display/Path\n");
		return -1;
	}

	schSCManager = open_sc_manager();
	if (0 == schSCManager) {
		return -1;
	}

	schService = CreateServiceW(
		schSCManager,
		wservice_name,
		wservice_display,
		SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS,
		SERVICE_AUTO_START,
		SERVICE_ERROR_NORMAL,
		wbin_path,
		0,
		0,
		0,
		0,
		0);

	if (schService == 0) {
		DWORD err = GetLastError();
		if (err == ERROR_SERVICE_EXISTS) {
			schService = OpenServiceW(schSCManager, wservice_name, SERVICE_CHANGE_CONFIG | SERVICE_START);
			if (schService != 0) {
				if (!ChangeServiceConfigW(schService,
					SERVICE_NO_CHANGE,
					SERVICE_NO_CHANGE,
					SERVICE_NO_CHANGE,
					wbin_path,
					0,
					0,
					0,
					0,
					0,
					wservice_display)) {
					fprintf(stderr, "ChangeServiceConfig failed (%lu)\n", GetLastError());
					CloseServiceHandle(schService);
					CloseServiceHandle(schSCManager);
					return -1;
				}
			} else {
				fprintf(stderr, "OpenService failed (%lu)\n", GetLastError());
				CloseServiceHandle(schSCManager);
				return -1;
			}
		} else {
			fprintf(stderr, "CreateService failed (%lu)\n", err);
			CloseServiceHandle(schSCManager);
			return -1;
		}
	}

	SERVICE_DESCRIPTIONW sd;
	wchar_t wservice_desc[256];
	if (u8tou16_mayfail(wservice_desc, sizeof(wservice_desc) / sizeof(wservice_desc[0]), service_desc, strlen(service_desc) + 1, 0)) {
		sd.lpDescription = wservice_desc;
		ChangeServiceConfig2W(schService, SERVICE_CONFIG_DESCRIPTION, &sd);
	}

	SERVICE_FAILURE_ACTIONS sfa;
	SC_ACTION actions[2];
	actions[0].Type = SC_ACTION_RESTART;
	actions[0].Delay = 5000; /* restart after 5 seconds */
	actions[1].Type = SC_ACTION_RESTART;
	actions[1].Delay = 5000; /* restart after 5 seconds */
	sfa.dwResetPeriod = 86400; /* reset failure count after 1 day */
	sfa.lpRebootMsg = 0;
	sfa.lpCommand = 0;
	sfa.cActions = 2;
	sfa.lpsaActions = actions;
	ChangeServiceConfig2W(schService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa);

	char reg_path[PATH_MAX];
	wchar_t wreg_path[PATH_MAX];
	snprintf(reg_path, sizeof(reg_path), "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\%s", service_name);
	if (u8tou16_mayfail(wreg_path, sizeof(wreg_path) / sizeof(wreg_path[0]), reg_path, strlen(reg_path) + 1, 0)) {
		if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, wreg_path, 0, 0, REG_OPTION_NON_VOLATILE, KEY_WRITE, 0, &hk, 0) == ERROR_SUCCESS) {
			DWORD types = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
			RegSetValueExW(hk, L"EventMessageFile", 0, REG_SZ, (const BYTE*)wpath, (wcslen(wpath) + 1) * sizeof(wchar_t));
			RegSetValueExW(hk, L"TypesSupported", 0, REG_DWORD, (const BYTE*)&types, sizeof(types));
			RegCloseKey(hk);
		}
	}

	int ret = 0;

	if (!StartServiceW(schService, 0, 0)) {
		DWORD err = GetLastError();
		if (err != ERROR_SERVICE_ALREADY_RUNNING) {
			fprintf(stderr, "StartService failed (%lu)\n", err);
			ret = -1;
		}
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);

	if (ret == 0) {
		printf("Service %s installed successfully.\n", service_name);
	}
	return ret;
}

static int do_service_remove(void)
{
	SC_HANDLE schSCManager;
	SC_HANDLE schService;
	SERVICE_STATUS status;
	int ret = 0;
	wchar_t wservice_name[128];

	schSCManager = open_sc_manager();
	if (0 == schSCManager) {
		return -1;
	}

	if (!u8tou16_mayfail(wservice_name, sizeof(wservice_name) / sizeof(wservice_name[0]), service_name, strlen(service_name) + 1, 0)) {
		CloseServiceHandle(schSCManager);
		return -1;
	}
	schService = OpenServiceW(schSCManager, wservice_name, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
	if (schService == 0) {
		fprintf(stderr, "OpenService failed (%lu)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return -1;
	}

	int stopped = 1;
	ControlService(schService, SERVICE_CONTROL_STOP, &status);
	if (wait_for_service_stop(schService) != 0) {
		fprintf(stderr, "Service %s failed to stop within 30 seconds.\n", service_name);
		ret = -1;
		stopped = 0;
	}

	if (!DeleteService(schService)) {
		fprintf(stderr, "DeleteService failed (%lu)\n", GetLastError());
		ret = -1;
	} else if (!stopped) {
		printf("Service %s is running. It has been marked for deletion and will be removed once it stops.\n", service_name);
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);

	char reg_path[PATH_MAX];
	wchar_t wreg_path[PATH_MAX];
	snprintf(reg_path, sizeof(reg_path), "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\%s", service_name);
	if (u8tou16_mayfail(wreg_path, sizeof(wreg_path) / sizeof(wreg_path[0]), reg_path, strlen(reg_path) + 1, 0)) {
		RegDeleteKeyW(HKEY_LOCAL_MACHINE, wreg_path);
	}

	if (ret == 0) {
		printf("Service %s removed successfully.\n", service_name);
	}
	return ret;
}

SERVICE_STATUS g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = 0;
static DWORD dwCheckPoint = 0;
/**
 * log_event - A printf-like wrapper for the Windows Event Log
 * @type:   The Windows event type (EVENTLOG_INFORMATION_TYPE, etc.)
 * @format: The format string (standard printf style)
 */
void windows_eventlog(int level, const char* msg)
{
	HANDLE h;
	wchar_t wmsg[4096];
	const wchar_t* strings[1];
	DWORD id;
	DWORD type;
	wchar_t wservice_name[128];

	if (!g_StatusHandle) {
		fprintf(stderr, "%s\n", msg);
		return;
	}

	if (!u8tou16_mayfail(wmsg, sizeof(wmsg) / sizeof(wmsg[0]), msg, strlen(msg) + 1, 0)) {
		fprintf(stderr, "%s\n", msg);
		return;
	}
	strings[0] = wmsg;

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

	u8tou16(wservice_name, service_name);
	h = RegisterEventSourceW(0, wservice_name);
	if (!h)
		return;

	ReportEventW(h,
		type,
		0,
		id,
		0,
		1, /* one string */
		0,
		strings,
		0);

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
		state_ptr()->daemon_sig = SIGINT;
		state_ptr()->daemon_running = 0;
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
		state_ptr()->daemon_sig = SIGTERM;
		state_ptr()->daemon_running = 0;
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
		dwCheckPoint = 0; /* reset value for the next pending case */
	} else {
		/* increment checkpoint to prove we aren't "frozen" during PENDING states */
		g_ServiceStatus.dwCheckPoint = ++dwCheckPoint;
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
			state_ptr()->daemon_sig = SIGTERM;
			state_ptr()->daemon_running = 0;

			/* tell the OS we are trying to stop */
			report_progress(SERVICE_STOP_PENDING, NO_ERROR, 5000);
		}
		break;
	default :
		break;
	}
}

VOID WINAPI ServiceMain(DWORD argc, LPWSTR* argv)
{
	(void)argc;
	(void)argv;

	struct snapraid_state* state = state_ptr();
	wchar_t wservice_name[128];

	if (!u8tou16_mayfail(wservice_name, sizeof(wservice_name) / sizeof(wservice_name[0]), service_name, strlen(service_name) + 1, 0))
		return;
	g_StatusHandle = RegisterServiceCtrlHandlerW(wservice_name, ServiceCtrlHandler);
	if (g_StatusHandle == 0)
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

	os_init(OS_INIT_OPT_WINFIND);
	app_init();

	daemon_options(state, argc, argv);

	if (state->service_install) {
		int ret = do_service_install(state);
		state_done(state);
		app_done();
		os_done();
		return ret != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
	}

	if (state->service_remove) {
		int ret = do_service_remove();
		state_done(state);
		app_done();
		os_done();
		return ret != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
	}

	if (state->service_start_all) {
		int ret = do_service_start_all();
		state_done(state);
		app_done();
		os_done();
		return ret != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
	}

	if (state->service_stop_all) {
		int ret = do_service_stop_all();
		state_done(state);
		app_done();
		os_done();
		return ret != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
	}

	if (state->service_remove_all) {
		int ret = do_service_remove_all();
		state_done(state);
		app_done();
		os_done();
		return ret != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
	}

	if (state->service_list) {
		int ret = do_service_list();
		state_done(state);
		app_done();
		os_done();
		return ret != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
	}

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
		wchar_t wservice_name[128];
		if (!u8tou16_mayfail(wservice_name, sizeof(wservice_name) / sizeof(wservice_name[0]), service_name, strlen(service_name) + 1, 0))
			return 1;
		SERVICE_TABLE_ENTRYW ServiceTable[] = {
			{ wservice_name, (LPSERVICE_MAIN_FUNCTIONW)ServiceMain },
			{ 0, 0 }
		};

		if (StartServiceCtrlDispatcherW(ServiceTable) == FALSE) {
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

