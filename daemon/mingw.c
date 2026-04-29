// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#include "portable.h"

#ifdef __MINGW32__ /* Only for MingW */

#include "state.h"
#include "daemon.h"
#include "support.h"
#include "log.h"

#include <userenv.h> /* CreateEnvironmentBlock */

/**
 * Description of the last error.
 * It's stored in the thread local storage.
 */
static windows_key_t last_error;

/**
 * If we are running in Wine.
 */
static int is_wine;

/**
 * Executable dir.
 *
 * Or empty or terminating with '\'.
 */
static WCHAR exedir[MAX_PATH];

/**
 * Set the executable dir.
 */
static void exedir_init(void)
{
	DWORD size;
	WCHAR* slash;

	size = GetModuleFileNameW(0, exedir, MAX_PATH);
	if (size == 0 || size == MAX_PATH) {
		/* use empty dir */
		exedir[0] = 0;
		return;
	}

	slash = wcsrchr(exedir, L'\\');
	if (!slash) {
		/* use empty dir */
		exedir[0] = 0;
		return;
	}

	/* cut exe name */
	slash[1] = 0;
}

/**
 * Size in chars of conversion buffers for u8to16() and u16to8().
 */
#define CONV_MAX PATH_MAX

/**
 * Convert a generic string from UTF8 to UTF16.
 */
static wchar_t* u8tou16(wchar_t* conv_buf, const char* src)
{
	int ret;

	ret = MultiByteToWideChar(CP_UTF8, 0, src, -1, conv_buf, CONV_MAX);

	if (ret <= 0) {
		exit(EXIT_FAILURE);
	}

	return conv_buf;
}

/**
 * Convert a generic string from UTF16 to UTF8.
 */
static char* u16tou8ex(char* conv_buf, const wchar_t* src, size_t number_of_wchar, size_t* result_length_without_terminator)
{
	int ret;

	ret = WideCharToMultiByte(CP_UTF8, 0, src, number_of_wchar, conv_buf, CONV_MAX, 0, 0);
	if (ret <= 0) {
		exit(EXIT_FAILURE);
	}

	*result_length_without_terminator = ret;

	return conv_buf;
}

static char* u16tou8(char* conv_buf, const wchar_t* src)
{
	size_t len;

	/* convert also the 0 terminator */
	return u16tou8ex(conv_buf, src, wcslen(src) + 1, &len);
}

static char path_snapraid[PATH_MAX];
static char path_conf[PATH_MAX];
static char path_log[PATH_MAX];
static char path_data[PATH_MAX];

void os_init(void)
{
	HMODULE ntdll;
	WCHAR conv[CONV_MAX];

	/* initialize the thread local storage for strerror(), using free() as destructor */
	if (windows_key_create(&last_error, free) != 0) {
		exit(EXIT_FAILURE);
	}

	ntdll = GetModuleHandle("NTDLL.DLL");
	if (!ntdll) {
		exit(EXIT_FAILURE);
	}

	/* check for Wine presence */
	is_wine = GetProcAddress(ntdll, "wine_get_version") != 0;

	exedir_init();

	if (is_wine) {
		strcpy(path_log, "log");
		strcpy(path_conf, "/etc/snapraidd.conf");
		strcpy(path_data, "/usr/share/snapraidd/");
		strcpy(path_snapraid, "/usr/bin/snapraid");
	} else {
		snwprintf(conv, PATH_MAX, L"%lslog", exedir);
		u16tou8(path_log, conv);

		snwprintf(conv, PATH_MAX, L"%lssnapraidd.conf", exedir);
		u16tou8(path_conf, conv);

		snwprintf(conv, PATH_MAX, L"%ls", exedir);
		u16tou8(path_data, conv);

		snwprintf(conv, PATH_MAX, L"%lssnapraid.exe", exedir);
		u16tou8(path_snapraid, conv);
	}
}

void os_done(void)
{
	/* delete the thread local storage for strerror() */
	windows_key_delete(last_error);
}

/**
 * Check if the char is a forward or back slash.
 */
static int is_slash(char c)
{
	return c == '/' || c == '\\';
}

/**
 * Convert a path to the Windows format.
 *
 * If only_is_required is 1, the extended-length format is used only if required.
 *
 * The exact operation done is:
 * - If it's a '\\?\' or '\\.\' path, convert any '/' to '\'.
 * - If it's a disk designator path, like 'D:\' or 'D:/', it prepends '\\?\' to the path and convert any '/' to '\'.
 * - If it's a UNC path, like ''\\server'', it prepends '\\?\UNC\' to the path and convert any '/' to '\'.
 * - Otherwise, only the UTF conversion is done. In this case Windows imposes a limit of 260 chars, and automatically convert any '/' to '\'.
 *
 * For more details see:
 * Naming Files, Paths, and Namespaces
 * http://msdn.microsoft.com/en-us/library/windows/desktop/aa365247%28v=vs.85%29.aspx#maxpath
 */
static wchar_t* convert_arg(wchar_t* conv_buf, const char* src, int only_if_required)
{
	int ret;
	wchar_t* dst;
	int count;

	dst = conv_buf;

	/* note that we always check for both / and \ because the path is blindly */
	/* converted to unix format by path_import() */

	if (only_if_required && strlen(src) < 260 - 12) {
		/* it's a short path */
		/* 260 is the MAX_PATH, note that it includes the space for the terminating NUL */
		/* 12 is an additional space for filename, required when creating directory */

		/* do nothing */
	} else if (is_slash(src[0]) && is_slash(src[1]) && (src[2] == '?' || src[2] == '.') && is_slash(src[3])) {
		/* if it's already a '\\?\' or '\\.\' path */

		/* do nothing */
	} else if (is_slash(src[0]) && is_slash(src[1])) {
		/* if it is a UNC path, like '\\server' */

		/* prefix with '\\?\UNC\' */
		*dst++ = L'\\';
		*dst++ = L'\\';
		*dst++ = L'?';
		*dst++ = L'\\';
		*dst++ = L'U';
		*dst++ = L'N';
		*dst++ = L'C';
		*dst++ = L'\\';

		/* skip initial '\\' */
		src += 2;
	} else if (src[0] != 0 && src[1] == ':' && is_slash(src[2])) {
		/* if it is a disk designator path, like 'D:\' or 'D:/' */

		/* prefix with '\\?\' */
		*dst++ = L'\\';
		*dst++ = L'\\';
		*dst++ = L'?';
		*dst++ = L'\\';
	}

	/* chars already used */
	count = dst - conv_buf;

	ret = MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, CONV_MAX - count);

	if (ret <= 0) {
		exit(EXIT_FAILURE);
	}

	/* convert any / to \ */
	/* note that in UTF-16, it's not possible to have '/' used as part */
	/* of a pair of codes representing a single UNICODE char */
	/* See: http://en.wikipedia.org/wiki/UTF-16 */
	while (*dst) {
		if (*dst == L'/')
			*dst = L'\\';
		++dst;
	}

	return conv_buf;
}

#define convert(buf, a) convert_arg(buf, a, 0)
#define convert_if_required(buf, a) convert_arg(buf, a, 1)

static BOOL GetReparseTagInfoByHandle(HANDLE hFile, FILE_ATTRIBUTE_TAG_INFO* lpFileAttributeTagInfo, DWORD dwFileAttributes)
{
	/* if not a reparse point, return no info */
	if ((dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
		lpFileAttributeTagInfo->FileAttributes = dwFileAttributes;
		lpFileAttributeTagInfo->ReparseTag = 0;
		return TRUE;
	}

	/* do the real call */
	return GetFileInformationByHandleEx(hFile, FileAttributeTagInfo, lpFileAttributeTagInfo, sizeof(FILE_ATTRIBUTE_TAG_INFO));
}

/**
 * Convert Windows error to errno.
 */
static void windows_errno(DWORD error)
{
	switch (error) {
	case ERROR_INVALID_HANDLE :
		/* we check for a bad handle calling _get_osfhandle() */
		/* and in such case we return EBADF */
		/* Other cases are here identified with EINVAL */
		errno = EINVAL;
		break;
	case ERROR_HANDLE_EOF : /* in ReadFile() over the end of the file */
		errno = EINVAL;
		break;
	case ERROR_FILE_NOT_FOUND :
	case ERROR_PATH_NOT_FOUND : /* in GetFileAttributeW() if internal path not found */
		errno = ENOENT;
		break;
	case ERROR_ACCESS_DENIED : /* in CreateDirectoryW() if dir is scheduled for deletion */
	case ERROR_CURRENT_DIRECTORY : /* in RemoveDirectoryW() if removing the current directory */
	case ERROR_SHARING_VIOLATION : /* in RemoveDirectoryW() if in use */
	case ERROR_WRITE_PROTECT : /* when dealing with read-only media/snapshot and trying to write to them */
		errno = EACCES;
		break;
	case ERROR_ALREADY_EXISTS : /* in CreateDirectoryW() if already exists */
		errno = EEXIST;
		break;
	case ERROR_DISK_FULL :
		errno = ENOSPC;
		break;
	case ERROR_BUFFER_OVERFLOW :
		errno = ENAMETOOLONG;
		break;
	case ERROR_NOT_ENOUGH_MEMORY :
		errno = ENOMEM;
		break;
	case ERROR_NOT_SUPPORTED : /* in CreateSymlinkW() if not present in kernel32 */
		errno = ENOSYS;
		break;
	case ERROR_PRIVILEGE_NOT_HELD : /* in CreateSymlinkW() if no SeCreateSymbolicLinkPrivilige permission */
		errno = EPERM;
		break;
	case ERROR_IO_DEVICE : /* in ReadFile() and WriteFile() */
	case ERROR_CRC : /* in ReadFile() */
		errno = EIO;
		break;
	case WSAEADDRINUSE :
		errno = EADDRINUSE;
		break;
	default :
		errno = ENXIO;
		break;
	}
}

/* ensure to call the real C strerror() */
#undef strerror

const char* windows_strerror(int err)
{
	/* get the normal C error from the specified err */
	char* error;
	char* previous;
	const char* str = strerror(err);
	size_t len = strlen(str);

	/* adds space for GetLastError() */
	len += 32;

	/* allocate a new one */
	error = malloc(len);
	if (!error)
		return str;
	snprintf(error, len, "%s [%d/%u]", str, err, (unsigned)GetLastError());

	/* get previous one, if any */
	previous = windows_getspecific(last_error);

	/* store in the thread local storage */
	if (windows_setspecific(last_error, error) != 0) {
		free(error);
		return str;
	}

	free(previous);
	return error;
}

/* restore the define used later */
#define  strerror windows_strerror

/**
 * Convert Windows attr to the Unix stat format.
 */
static void windows_attr2stat(DWORD FileAttributes, DWORD ReparseTag, struct windows_stat* st)
{
	/* Convert special attributes */
	if ((FileAttributes & FILE_ATTRIBUTE_DEVICE) != 0) {
		st->st_mode = S_IFBLK;
		st->st_desc = "device";
	} else if ((FileAttributes & FILE_ATTRIBUTE_OFFLINE) != 0) { /* Offline */
		st->st_mode = S_IFCHR;
		st->st_desc = "offline";
	} else if ((FileAttributes & FILE_ATTRIBUTE_TEMPORARY) != 0) { /* Temporary */
		st->st_mode = S_IFCHR;
		st->st_desc = "temporary";
	} else if ((FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) { /* Reparse point */
		switch (ReparseTag) {
		/* if we don't have the ReparseTag information */
		case 0 :
			/* don't set the st_mode, to set it later calling lstat_sync() */
			st->st_mode = 0;
			st->st_desc = "unknown";
			break;
		/* for deduplicated files, assume that they are regular ones */
		case IO_REPARSE_TAG_DEDUP :
			if ((FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
				st->st_mode = S_IFDIR;
				st->st_desc = "directory-dedup";
			} else {
				st->st_mode = S_IFREG;
				st->st_desc = "regular-dedup";
			}
			break;
		case IO_REPARSE_TAG_SYMLINK :
			if ((FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
				st->st_mode = S_IFLNKDIR;
				st->st_desc = "reparse-point-symlink-dir";
			} else {
				st->st_mode = S_IFLNK;
				st->st_desc = "reparse-point-symlink-file";
			}
			break;
		/* all the other are skipped as reparse-point */
		case IO_REPARSE_TAG_MOUNT_POINT :
			st->st_mode = S_IFCHR;
			st->st_desc = "reparse-point-mount";
			break;
		case IO_REPARSE_TAG_NFS :
			st->st_mode = S_IFCHR;
			st->st_desc = "reparse-point-nfs";
			break;
		default :
			st->st_mode = S_IFCHR;
			st->st_desc = "reparse-point";
			break;
		}
	} else if ((FileAttributes & FILE_ATTRIBUTE_SYSTEM) != 0) { /* System */
		if ((FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
			st->st_mode = S_IFCHR;
			st->st_desc = "system-directory";
		} else {
			st->st_mode = S_IFREG;
			st->st_desc = "system-file";
		}
	} else {
		if ((FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
			st->st_mode = S_IFDIR;
			st->st_desc = "directory";
		} else {
			st->st_mode = S_IFREG;
			st->st_desc = "regular";
		}
	}

	/* store the HIDDEN attribute in a separate field */
	st->st_hidden = (FileAttributes & FILE_ATTRIBUTE_HIDDEN) != 0;
}

/**
 * Convert Windows info to the Unix stat format.
 */
static int windows_info2stat(const BY_HANDLE_FILE_INFORMATION* info, const FILE_ATTRIBUTE_TAG_INFO* tag, struct windows_stat* st)
{
	int64_t mtime;

	windows_attr2stat(info->dwFileAttributes, tag->ReparseTag, st);

	st->st_size = info->nFileSizeHigh;
	st->st_size <<= 32;
	st->st_size |= info->nFileSizeLow;

	mtime = info->ftLastWriteTime.dwHighDateTime;
	mtime <<= 32;
	mtime |= info->ftLastWriteTime.dwLowDateTime;

	/*
	 * Convert to unix time
	 *
	 * How To Convert a UNIX time_t to a Win32 FILETIME or SYSTEMTIME
	 * http://support.microsoft.com/kb/167296
	 */
	mtime -= 116444736000000000LL;
	st->st_mtime = mtime / 10000000;
	st->st_mtimensec = (mtime % 10000000) * 100;

	st->st_ino = info->nFileIndexHigh;
	st->st_ino <<= 32;
	st->st_ino |= info->nFileIndexLow;

	st->st_nlink = info->nNumberOfLinks;

	st->st_dev = info->dwVolumeSerialNumber;

	/* GetFileInformationByHandle() ensures to return synced information */
	st->st_sync = 1;

	/**
	 * In ReFS the IDs are 128 bit, and the 64 bit interface may fail.
	 *
	 * From Microsoft "Application Compatibility with ReFS"
	 * http://download.microsoft.com/download/C/B/3/CB3561DC-6BF6-443D-B5B9-9676ACDF7F75/Application%20Compatibility%20with%20ReFS.docx
	 * "64-bit file identifier can be obtained from GetFileInformationByHandle in"
	 * "the nFileIndexHigh and nFileIndexLow members. This API is an extended version"
	 * "that includes 128-bit file identifiers.  If GetFileInformationByHandle returns"
	 * "FILE_INVALID_FILE_ID, the identifier may only be described in 128 bit form."
	 */
	if (st->st_ino == (uint64_t)FILE_INVALID_FILE_ID) {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

/**
 * Convert Windows findfirst info to the Unix stat format.
 */
static void windows_finddata2stat(const WIN32_FIND_DATAW* info, struct windows_stat* st)
{
	int64_t mtime;

	windows_attr2stat(info->dwFileAttributes, info->dwReserved0, st);

	st->st_size = info->nFileSizeHigh;
	st->st_size <<= 32;
	st->st_size |= info->nFileSizeLow;

	mtime = info->ftLastWriteTime.dwHighDateTime;
	mtime <<= 32;
	mtime |= info->ftLastWriteTime.dwLowDateTime;

	/*
	 * Convert to unix time
	 *
	 * How To Convert a UNIX time_t to a Win32 FILETIME or SYSTEMTIME
	 * http://support.microsoft.com/kb/167296
	 */
	mtime -= 116444736000000000LL;
	st->st_mtime = mtime / 10000000;
	st->st_mtimensec = (mtime % 10000000) * 100;

	/* No inode information available */
	st->st_ino = 0;

	/* No link information available */
	st->st_nlink = 0;

	/* No device information available */
	st->st_dev = 0;

	/* directory listing doesn't ensure to return synced information */
	st->st_sync = 0;
}

static void windows_finddata2dirent(const WIN32_FIND_DATAW* info, struct windows_dirent* dirent)
{
	char conv_buf[CONV_MAX];
	const char* name;
	size_t len;

	name = u16tou8ex(conv_buf, info->cFileName, wcslen(info->cFileName), &len);

	if (len + 1 >= sizeof(dirent->d_name)) {
		exit(EXIT_FAILURE);
	}

	memcpy(dirent->d_name, name, len);
	dirent->d_name[len] = 0;

	windows_finddata2stat(info, &dirent->d_stat);
}

int windows_remove(const char* file)
{
	wchar_t conv_buf[CONV_MAX];

	if (!DeleteFileW(convert(conv_buf, file))) {
		windows_errno(GetLastError());
		return -1;
	}

	return 0;
}

FILE* windows_fopen(const char* file, const char* mode)
{
	wchar_t conv_buf_file[CONV_MAX];
	wchar_t conv_buf_mode[CONV_MAX];

	return _wfopen(convert(conv_buf_file, file), u8tou16(conv_buf_mode, mode));
}

int windows_open(const char* file, int flags, ...)
{
	wchar_t conv_buf[CONV_MAX];
	HANDLE h;
	int f;
	DWORD access;
	DWORD share;
	DWORD create;
	DWORD attr;

	switch (flags & O_ACCMODE) {
	case O_RDONLY :
		access = GENERIC_READ;
		break;
	case O_WRONLY :
		access = GENERIC_WRITE;
		break;
	case O_RDWR :
		access = GENERIC_READ | GENERIC_WRITE;
		break;
	default :
		errno = EINVAL;
		return -1;
	}

	share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

	switch (flags & (O_CREAT | O_EXCL | O_TRUNC)) {
	case 0 :
		create = OPEN_EXISTING;
		break;
	case O_CREAT :
		create = OPEN_ALWAYS;
		break;
	case O_CREAT | O_EXCL :
	case O_CREAT | O_EXCL | O_TRUNC :
		create = CREATE_NEW;
		break;
	case O_CREAT | O_TRUNC :
		create = CREATE_ALWAYS;
		break;
	case O_TRUNC :
		create = TRUNCATE_EXISTING;
		break;
	default :
		errno = EINVAL;
		return -1;
	}

	attr = FILE_ATTRIBUTE_NORMAL;
	if ((flags & O_DIRECT) != 0)
		attr |= FILE_FLAG_NO_BUFFERING;
	if ((flags & O_DSYNC) != 0)
		attr |= FILE_FLAG_WRITE_THROUGH;
	if ((flags & O_RANDOM) != 0)
		attr |= FILE_FLAG_RANDOM_ACCESS;
	if ((flags & O_SEQUENTIAL) != 0)
		attr |= FILE_FLAG_SEQUENTIAL_SCAN;
	if ((flags & _O_SHORT_LIVED) != 0)
		attr |= FILE_ATTRIBUTE_TEMPORARY;
	if ((flags & O_TEMPORARY) != 0)
		attr |= FILE_FLAG_DELETE_ON_CLOSE;

	h = CreateFileW(convert(conv_buf, file), access, share, 0, create, attr, 0);
	if (h == INVALID_HANDLE_VALUE) {
		windows_errno(GetLastError());
		return -1;
	}

	/* mask out flags unknown by Windows */
	flags &= ~(O_DIRECT | O_DSYNC);

	f = _open_osfhandle((intptr_t)h, flags);
	if (f == -1) {
		CloseHandle(h);
		return -1;
	}

	return f;
}

ssize_t windows_read(int fd, void* buffer, size_t size)
{
	HANDLE h;
	DWORD count;

	if (fd == -1) {
		errno = EBADF;
		return -1;
	}

	h = (HANDLE)_get_osfhandle(fd);
	if (h == INVALID_HANDLE_VALUE) {
		errno = EBADF;
		return -1;
	}

	if (!ReadFile(h, buffer, size, &count, 0)) {
		windows_errno(GetLastError());
		return -1;
	}

	return count;
}

struct windows_dir_struct {
	BY_HANDLE_FILE_INFORMATION info;
	WIN32_FIND_DATAW find;
	HANDLE h;
	struct windows_dirent entry;
	unsigned char* buffer;
	unsigned buffer_size;
	unsigned buffer_pos;
	int state;
};

#define DIR_STATE_EOF -1 /**< End of the dir stream */
#define DIR_STATE_EMPTY 0 /**< The entry is empty. */
#define DIR_STATE_FILLED 1 /**< The entry is valid. */

windows_dir* windows_opendir(const char* dir)
{
	wchar_t conv_buf[CONV_MAX];
	wchar_t* wdir;
	windows_dir* dirstream;
	size_t len;

	dirstream = malloc(sizeof(windows_dir));
	if (!dirstream) {
		exit(EXIT_FAILURE);
	}

	wdir = convert(conv_buf, dir);

	/* add final / and * */
	len = wcslen(wdir);
	if (len != 0 && wdir[len - 1] != '\\')
		wdir[len++] = L'\\';
	wdir[len++] = L'*';
	wdir[len++] = 0;

	dirstream->h = FindFirstFileW(wdir, &dirstream->find);
	if (dirstream->h == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();

		if (error == ERROR_FILE_NOT_FOUND) {
			dirstream->state = DIR_STATE_EOF;
			return dirstream;
		}

		free(dirstream);
		windows_errno(error);
		return 0;
	}

	windows_finddata2dirent(&dirstream->find, &dirstream->entry);
	dirstream->state = DIR_STATE_FILLED;

	return dirstream;
}

struct windows_dirent* windows_readdir(windows_dir* dirstream)
{
	if (dirstream->state == DIR_STATE_EMPTY) {
		if (!FindNextFileW(dirstream->h, &dirstream->find)) {
			DWORD error = GetLastError();

			if (error != ERROR_NO_MORE_FILES) {
				windows_errno(error);
				return 0;
			}

			dirstream->state = DIR_STATE_EOF;
		} else {
			windows_finddata2dirent(&dirstream->find, &dirstream->entry);
			dirstream->state = DIR_STATE_FILLED;
		}
	}

	if (dirstream->state == DIR_STATE_FILLED) {
		dirstream->state = DIR_STATE_EMPTY;
		return &dirstream->entry;
	}

	/* otherwise it's the end of stream */
	assert(dirstream->state == DIR_STATE_EOF);
	errno = 0;

	return 0;
}

int windows_closedir(windows_dir* dirstream)
{
	if (dirstream->h != INVALID_HANDLE_VALUE) {
		if (!FindClose(dirstream->h)) {
			DWORD error = GetLastError();

			free(dirstream);

			windows_errno(error);
			return -1;
		}
	}

	free(dirstream);

	return 0;
}

int windows_fstat(int fd, struct windows_stat* st)
{
	BY_HANDLE_FILE_INFORMATION info;
	FILE_ATTRIBUTE_TAG_INFO tag;
	HANDLE h;

	h = (HANDLE)_get_osfhandle(fd);
	if (h == INVALID_HANDLE_VALUE) {
		errno = EBADF;
		return -1;
	}

	if (!GetFileInformationByHandle(h, &info)) {
		windows_errno(GetLastError());
		return -1;
	}

	if (!GetReparseTagInfoByHandle(h, &tag, info.dwFileAttributes)) {
		windows_errno(GetLastError());
		return -1;
	}

	return windows_info2stat(&info, &tag, st);
}

int windows_lstat(const char* file, struct windows_stat* st)
{
	wchar_t conv_buf[CONV_MAX];
	HANDLE h;
	WIN32_FIND_DATAW data;

	/* FindFirstFileW by default gets information of symbolic links and not of their targets */
	h = FindFirstFileW(convert(conv_buf, file), &data);
	if (h == INVALID_HANDLE_VALUE) {
		windows_errno(GetLastError());
		return -1;
	}

	if (!FindClose(h)) {
		windows_errno(GetLastError());
		return -1;
	}

	windows_finddata2stat(&data, st);

	return 0;
}

int windows_mkdir(const char* file)
{
	wchar_t conv_buf[CONV_MAX];

	if (!CreateDirectoryW(convert(conv_buf, file), 0)) {
		windows_errno(GetLastError());
		return -1;
	}

	return 0;
}

uint64_t os_tick_sec(void)
{
	return GetTickCount64() / 1000;
}

unsigned windows_sleep(unsigned seconds)
{
	Sleep(seconds);
	return 0;
}

struct tm* windows_gmtime_r(const time_t* timer, struct tm* result)
{
	/* Windows returns 0 on success, unlike POSIX which returns the pointer */
	if (gmtime_s(result, timer) == 0) {
		return result;
	}
	return NULL;
}

struct tm* windows_localtime_r(const time_t* timer, struct tm* result)
{
	/* Windows returns 0 on success, unlike POSIX which returns the pointer */
	if (localtime_s(result, timer) == 0) {
		return result;
	}
	return NULL;
}

char* windows_realpath(const char* path, char* resolved_path)
{
	wchar_t conv_buf[CONV_MAX];
	HANDLE h = CreateFileW(convert(conv_buf, path), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		windows_errno(GetLastError());
		return 0;
	}

	DWORD result = GetFinalPathNameByHandleW(h, conv_buf, CONV_MAX, FILE_NAME_NORMALIZED);

	CloseHandle(h);

	if (result == 0 || result >= CONV_MAX) {
		windows_errno(GetLastError());
		return 0;
	}

	resolved_path = u16tou8(resolved_path, conv_buf);

	/* Windows prefixes paths with "\\?\" (UNC). Skip it if you want a standard path */
	if (strncmp(resolved_path, "\\\\?\\", 4) == 0) {
		memmove(resolved_path, resolved_path + 4, strlen(resolved_path) - 3);
	}

	return resolved_path;
}

/****************************************************************************/
/* pthread like interface */

int windows_mutex_init(windows_mutex_t* mutex, void* attr)
{
	(void)attr;

	InitializeCriticalSection(mutex);

	return 0;
}

int windows_mutex_destroy(windows_mutex_t* mutex)
{
	DeleteCriticalSection(mutex);

	return 0;
}

int windows_mutex_lock(windows_mutex_t* mutex)
{
	EnterCriticalSection(mutex);

	return 0;
}

int windows_mutex_unlock(windows_mutex_t* mutex)
{
	LeaveCriticalSection(mutex);

	return 0;
}

int windows_rwlock_init(windows_rwlock_t* rwlock, void* attr)
{
	(void)attr;
	InitializeSRWLock(&rwlock->srw);
	rwlock->exclusive = 0;

	return 0;
}

int windows_rwlock_destroy(windows_rwlock_t* rwlock)
{
	(void)rwlock;

	return 0;
}

int windows_rwlock_rdlock(windows_rwlock_t* rwlock)
{
	AcquireSRWLockShared(&rwlock->srw);

	return 0;
}

int windows_rwlock_wrlock(windows_rwlock_t* rwlock)
{
	AcquireSRWLockExclusive(&rwlock->srw);
	rwlock->exclusive = 1;

	return 0;
}

int windows_rwlock_unlock(windows_rwlock_t* rwlock)
{
	if (rwlock->exclusive) {
		rwlock->exclusive = 0;
		ReleaseSRWLockExclusive(&rwlock->srw);
	} else {
		ReleaseSRWLockShared(&rwlock->srw);
	}

	return 0;
}

int windows_cond_init(windows_cond_t* cond, void* attr)
{
	(void)attr;

	InitializeConditionVariable(cond);

	return 0;
}

int windows_cond_destroy(windows_cond_t* cond)
{
	/* note that in Windows there is no DeleteConditionVariable() to call */
	(void)cond;

	return 0;
}

int windows_cond_signal(windows_cond_t* cond)
{
	WakeConditionVariable(cond);

	return 0;
}

int windows_cond_broadcast(windows_cond_t* cond)
{
	WakeAllConditionVariable(cond);

	return 0;
}

int windows_cond_wait(windows_cond_t* cond, windows_mutex_t* mutex)
{
	if (!SleepConditionVariableCS(cond, mutex, INFINITE))
		return -1;

	return 0;
}

struct windows_key_context {
	void (*func)(void*);
	DWORD key;
	tommy_node node;
};

/* list of all keys with destructor */
static tommy_list windows_key_list = { 0 };

int windows_key_create(windows_key_t* key, void (*destructor)(void*))
{
	struct windows_key_context* context;

	context = malloc(sizeof(struct windows_key_context));
	if (!context)
		return -1;

	context->func = destructor;
	context->key = TlsAlloc();
	if (context->key == 0xFFFFFFFF) {
		windows_errno(GetLastError());
		free(context);
		return -1;
	}

	/* insert in the list of destructors */
	if (context->func)
		tommy_list_insert_tail(&windows_key_list, &context->node, context);

	*key = context;

	return 0;
}

int windows_key_delete(windows_key_t key)
{
	struct windows_key_context* context = key;

	/* remove from the list of destructors */
	if (context->func)
		tommy_list_remove_existing(&windows_key_list, &context->node);

	TlsFree(context->key);

	free(context);

	return 0;
}

void* windows_getspecific(windows_key_t key)
{
	struct windows_key_context* context = key;

	return TlsGetValue(context->key);
}

int windows_setspecific(windows_key_t key, void* value)
{
	struct windows_key_context* context = key;

	if (!TlsSetValue(context->key, value)) {
		windows_errno(GetLastError());
		return -1;
	}

	return 0;
}

struct windows_thread_context {
	HANDLE h;
	unsigned id;
	void* (*func)(void*);
	void* arg;
	void* ret;
};

/* forwarder to change the function declaration */
static unsigned __stdcall windows_thread_func(void* arg)
{
	struct windows_thread_context* context = arg;
	tommy_node* i;

	context->ret = context->func(context->arg);

	/* call the destructor of all the keys */
	i = tommy_list_head(&windows_key_list);
	while (i) {
		struct windows_key_context* key = i->data;
		if (key->func) {
			void* value = windows_getspecific(key);
			if (value)
				key->func(value);
		}
		i = i->next;
	}

	return 0;
}

int windows_create(thread_id_t* thread, void* attr, void* (*func)(void*), void* arg)
{
	struct windows_thread_context* context;

	(void)attr;

	context = malloc(sizeof(struct windows_thread_context));
	if (!context)
		return -1;

	context->func = func;
	context->arg = arg;
	context->ret = 0;
	context->h = (void*)_beginthreadex(0, 0, windows_thread_func, context, 0, &context->id);

	if (context->h == 0) {
		free(context);
		return -1;
	}

	*thread = context;

	return 0;
}

int windows_join(thread_id_t thread, void** retval)
{
	struct windows_thread_context* context = thread;

	if (WaitForSingleObject(context->h, INFINITE) != WAIT_OBJECT_0) {
		windows_errno(GetLastError());
		return -1;
	}

	if (!CloseHandle(context->h)) {
		windows_errno(GetLastError());
		return -1;
	}

	*retval = context->ret;

	free(context);

	return 0;
}

/****************************************************************************/
/* exec */

const char* os_find_engine(const char* sys_engine)
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

void os_default_log(char* dst, size_t dst_size)
{
	sncpy(dst, dst_size, path_log);
}

void os_default_conf(char* dst, size_t dst_size)
{
	sncpy(dst, dst_size, path_conf);
}

void os_default_data(char* dst, size_t dst_size, const char* root)
{
	snprintf(dst, dst_size, "%s%s", path_data, root);
}

#define COMMAND_LINE_MAX 32767

static int needs_quote(const WCHAR* arg)
{
	while (*arg) {
		if (*arg == L' ' || *arg == L'\t' || *arg == L'"')
			return 1;
		++arg;
	}

	return 0;
}

#define charcat(c) \
	do { \
		if (pos + 1 >= size) { \
			return -1; \
		} \
		cmd[pos++] = (c); \
	} while (0)

static int fixcat(WCHAR* cmd, int size, int pos, const WCHAR* arg)
{
	while (*arg)
		charcat(*arg++);

	return pos;
}

static int argcat(WCHAR* cmd, int size, int pos, const WCHAR* arg)
{
	int has_quote;

	/* space separator */
	if (pos != 0)
		charcat(L' ');

	has_quote = needs_quote(arg);

	if (!has_quote) {
		while (*arg)
			charcat(*arg++);
	} else {
		/* starting quote */
		charcat(L'"');

		while (*arg) {
			int bl = 0;
			while (*arg == L'\\') {
				++arg;
				++bl;
			}

			if (*arg == 0) {
				/* double backslashes before closing quote */
				bl = bl * 2;
				while (bl--)
					charcat(L'\\');
			} else if (*arg == '"') {
				/* double backslashes + escape the quote */
				bl = bl * 2 + 1;
				while (bl--)
					charcat(L'\\');
				charcat(L'"');
				++arg;
			} else {
				/* normal backslashes */
				while (bl--)
					charcat(L'\\');
				charcat(*arg);
				++arg;
			}
		}

		/* ending quote */
		charcat(L'"');
	}

	return pos;
}

pid_t os_spawn(char** argv, int* stderr_read_int)
{
	wchar_t conv[CONV_MAX];
	HANDLE stderr_write_handle;
	HANDLE stderr_read_handle;
	SECURITY_ATTRIBUTES sa;
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
	BOOL ret;

	/* set the bInheritHandle flag so pipe handles are inherited */
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;

	/* create a pipe for the child process's STDERR */
	if (!CreatePipe(&stderr_read_handle, &stderr_write_handle, &sa, 0)) {
		windows_errno(GetLastError());
		log_task(LVL_ERROR, "failed to create pipe for spawn, errno=%s(%d)", strerror(errno), errno);
		return -1;
	}

	/* ensure the reading handle to the pipe is not inherited */
	if (!SetHandleInformation(stderr_read_handle, HANDLE_FLAG_INHERIT, 0)) {
		windows_errno(GetLastError());
		log_task(LVL_ERROR, "failed to handle information for spawn, errno=%s(%d)", strerror(errno), errno);
		CloseHandle(stderr_write_handle);
		CloseHandle(stderr_read_handle);
		return -1;
	}

	/* prepare command line string (Windows uses a single string, not an array) */
	WCHAR cmd_buffer[COMMAND_LINE_MAX];
	int pos = 0;
	for (int i = 0; argv[i]; ++i) {
		pos = argcat(cmd_buffer, COMMAND_LINE_MAX, pos, u8tou16(conv, argv[i]));
		if (pos < 0) {
			log_task(LVL_ERROR, "command to long for spawn");
			exit(EXIT_FAILURE);
		}
	}
	cmd_buffer[pos] = 0;

	/* set up members of the STARTUPINFO structure */
	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.hStdError = stderr_write_handle;
	si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	si.dwFlags |= STARTF_USESTDHANDLES;

	/*
	 * Set the Working Directory to the root of the C drive.
	 * For safety, we avoid defaulting to C:\Windows\System32.
	 */
	const wchar_t* cwd = L"C:\\";

	/* create the child process */
	ret = CreateProcessW(
		NULL,
		cmd_buffer,
		NULL, NULL,
		TRUE, /* inherit pipe handles */
		CREATE_NEW_PROCESS_GROUP,
		NULL, cwd,
		&si, &pi
	);
	if (!ret) {
		windows_errno(GetLastError());
		log_task(LVL_ERROR, "failed to create process for spawn, errno=%s(%d)", strerror(errno), errno);
		CloseHandle(stderr_write_handle);
		CloseHandle(stderr_read_handle);
		return -1;
	}

	/* close the write end of the pipe in the parent */
	CloseHandle(stderr_write_handle);

	/* close the handle to the primary thread, we don't need it */
	CloseHandle(pi.hThread);

	int f = _open_osfhandle((intptr_t)stderr_read_handle, O_RDONLY | O_BINARY);
	if (f == -1) {
		windows_errno(GetLastError());
		log_task(LVL_ERROR, "failed to open osfhandle for spawn, errno=%s(%d)", strerror(errno), errno);
		CloseHandle(stderr_read_handle);
		return -1;
	}

	*stderr_read_int = f;
	return (intptr_t)pi.hProcess;
}

int os_wait(pid_t pid, int* status)
{
	HANDLE h = (void*)pid;
	DWORD exit_code;

	WaitForSingleObject(h, INFINITE);

	if (GetExitCodeProcess(h, &exit_code)) {
		*status = exit_code;
		return 0;
	}

	return -1;
}

int os_term(pid_t pid)
{
	HANDLE h = (void*)pid;
	DWORD id = GetProcessId(h);

	if (id == 0)
		return -1;

	/* detach from current console (if any) */
	FreeConsole();

	/* attach to the child's console */
	if (!AttachConsole(id))
		return -1;

	/* Disable Ctrl-C for the PARENT so we don't kill ourselves */
	SetConsoleCtrlHandler(0, TRUE);

	/* This will now reach the child's SetConsoleCtrlHandler */
	GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, id);

	/* Clean up */
	FreeConsole();

	return 0;
}

int os_command(const char* command, const char* run_as_user, const char* stdin_text)
{
	wchar_t conv[CONV_MAX];
	HANDLE stdin_read_handle;
	HANDLE stdin_write_handle;
	SECURITY_ATTRIBUTES sa;
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
	BOOL ret;
	int64_t start, stop;

	start = os_tick_sec();

	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;

	/* create pipe for child's STDIN */
	if (!CreatePipe(&stdin_read_handle, &stdin_write_handle, &sa, 0)) {
		windows_errno(GetLastError());
		log_task(LVL_ERROR, "failed to create pipe for command, errno=%s(%d)", strerror(errno), errno);
		return -1;
	}

	/* ensure the parent's write end is NOT inherited */
	if (!SetHandleInformation(stdin_write_handle, HANDLE_FLAG_INHERIT, 0)) {
		windows_errno(GetLastError());
		log_task(LVL_ERROR, "failed to handle information for spawn, errno=%s(%d)", strerror(errno), errno);
		CloseHandle(stdin_read_handle);
		CloseHandle(stdin_write_handle);
		return -1;
	}

	/* create a handle to the NUL device */
	HANDLE nul = CreateFileW(
		L"NUL",
		GENERIC_WRITE,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		&sa,
		OPEN_EXISTING,
		0,
		NULL);
	if (nul == INVALID_HANDLE_VALUE) {
		windows_errno(GetLastError());
		log_task(LVL_ERROR, "failed to create nul device, errno=%s(%d)", strerror(errno), errno);
		CloseHandle(stdin_read_handle);
		CloseHandle(stdin_write_handle);
		return -1;
	}

	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.hStdInput = stdin_read_handle;
	si.hStdOutput = nul;
	si.hStdError = nul;
	si.dwFlags |= STARTF_USESTDHANDLES;

	/*
	 * Set the Working Directory to the root of the C drive.
	 * For safety, we avoid defaulting to C:\Windows\System32.
	 */
	const wchar_t* cwd = L"C:\\";

	/*
	 * No drop of privilege requested
	 * Run exactly as the parent daemon
	 */
	if (run_as_user == 0 || run_as_user[0] == 0) {
		/* create the child process */
		ret = CreateProcessW(
			NULL,
			u8tou16(conv, command),
			NULL, NULL,
			TRUE, /* inherit pipe handles */
			CREATE_NO_WINDOW,
			NULL, cwd,
			&si, &pi
		);
	} else {
		/*
		 * Drop to restricted service account.
		 */
		HANDLE h_token = NULL;

		/*
		 * Validate that the requested user is actually a supported
		 * Service Account before attempting logon.
		 */
		if (_stricmp(run_as_user, "LocalService") != 0 && _stricmp(run_as_user, "NetworkService") != 0) {
			log_task(LVL_ERROR, "only supported users are LocalService and NetworkService");
			CloseHandle(stdin_read_handle);
			CloseHandle(stdin_write_handle);
			CloseHandle(nul);
			return -1;
		}

		if (!LogonUserW(u8tou16(conv, run_as_user), L"NT AUTHORITY", NULL, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, &h_token)) {
			windows_errno(GetLastError());
			log_task(LVL_ERROR, "failed to logon user %s, errno=%s(%d)", run_as_user, strerror(errno), errno);
			CloseHandle(stdin_read_handle);
			CloseHandle(stdin_write_handle);
			CloseHandle(nul);
			return -1;
		}

		/*
		 * Create an environment block to ensure PATH is loaded.
		 */
		LPVOID env = NULL;
		if (!CreateEnvironmentBlock(&env, h_token, FALSE)) {
			windows_errno(GetLastError());
			log_task(LVL_ERROR, "failed to get user %s environment, errno=%s(%d)", run_as_user, strerror(errno), errno);
			CloseHandle(stdin_read_handle);
			CloseHandle(stdin_write_handle);
			CloseHandle(nul);
			CloseHandle(h_token);
			return -1;
		}

		ret = CreateProcessAsUserW(
			h_token,
			NULL,
			u8tou16(conv, command),
			NULL, NULL,
			TRUE, /* inherit pipe handles */
			CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
			env, cwd,
			&si, &pi
		);

		if (env)
			DestroyEnvironmentBlock(env);
		CloseHandle(h_token);
	}
	if (!ret) {
		windows_errno(GetLastError());
		log_task(LVL_ERROR, "failed to create process for command, errno=%s(%d)", strerror(errno), errno);
		CloseHandle(stdin_read_handle);
		CloseHandle(stdin_write_handle);
		CloseHandle(nul);
		return -1;
	}

	/* clode nul device */
	CloseHandle(nul);

	/* close the read end in the parent immediately */
	CloseHandle(stdin_read_handle);

	/* write the string to the child's STDIN */
	if (stdin_text && strlen(stdin_text) > 0) {
		DWORD written;
		WriteFile(stdin_write_handle, stdin_text, (DWORD)strlen(stdin_text), &written, NULL);
	}

	/* closing the write handle sends EOF to the child */
	CloseHandle(stdin_write_handle);

	/* wait for completion and get exit code */
	WaitForSingleObject(pi.hProcess, INFINITE);

	DWORD status;
	GetExitCodeProcess(pi.hProcess, &status);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	stop = os_tick_sec();
	int64_t execution_time = stop - start;
	if (execution_time > 30)
		log_task(LVL_WARNING, "command %s ran for %" PRId64 " seconds that is unexpectedly long", command, execution_time);

	if (WIFEXITED(status)) {
		int exit_code = WEXITSTATUS(status);
		if (exit_code == 0)
			log_task(LVL_INFO, "command %s terminated in %" PRId64 " seconds with success", command, execution_time);
		else
			log_task(LVL_ERROR, "command %s terminated in %" PRId64 " seconds with exit code %d", command, execution_time, exit_code);
		return exit_code;
	} else if (WIFSIGNALED(status)) {
		/* child died from a signal */
		int sig = WTERMSIG(status);
		log_task(LVL_ERROR, "command %s terminated in %" PRId64 " seconds with signal %s(%d)", command, execution_time, signal_name(sig), sig);
		return 128 + sig;
	} else {
		/* in Windows it can happen */
		log_task(LVL_ERROR, "command %s terminated in %" PRId64 " seconds for unknown reason, status=0x%08x", command, execution_time, (unsigned)status);
		return -1;
	}
}

int os_script(char** argv, const char* run_as_user)
{
	wchar_t conv[CONV_MAX];
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
	BOOL ret;
	char resolved_path[PATH_MAX];
	int64_t start, stop;
	const char* script_path = argv[0];

	/* resolve the script path to prevent symlink attacks */
	if (!realpath(script_path, resolved_path)) {
		log_task(LVL_ERROR, "failed to resolve script, path=%s, errno=%s(%d)", script_path, strerror(errno), errno);
		return -1;
	}

	start = os_tick_sec();

	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	/* prepare command line string (Windows uses a single string, not an array) */
	WCHAR cmd_buffer[COMMAND_LINE_MAX];
	int pos = 0;

	/*
	 * We add an extra set of quotes: cmd /c " "path with spaces" arg1 "arg 2" "
	 * This ensures cmd.exe parses the internal quotes correctly.
	 */
	pos = fixcat(cmd_buffer, COMMAND_LINE_MAX, pos, L"cmd.exe /c \" ");
	pos = argcat(cmd_buffer, COMMAND_LINE_MAX, pos, u8tou16(conv, resolved_path));
	if (pos < 0) {
		log_task(LVL_ERROR, "command to long for script");
		exit(EXIT_FAILURE);
	}
	for (int i = 1; argv[i]; ++i) {
		pos = argcat(cmd_buffer, COMMAND_LINE_MAX, pos, u8tou16(conv, argv[i]));
		if (pos < 0) {
			log_task(LVL_ERROR, "command to long for script");
			exit(EXIT_FAILURE);
		}
	}
	pos = fixcat(cmd_buffer, COMMAND_LINE_MAX, pos, L" \"");
	if (pos < 0) {
		log_task(LVL_ERROR, "command to long for script");
		exit(EXIT_FAILURE);
	}
	cmd_buffer[pos] = 0;

	/*
	 * Set the Working Directory to the root of the C drive.
	 * For safety, we avoid defaulting to C:\Windows\System32.
	 */
	const wchar_t* cwd = L"C:\\";

	/*
	 * No drop of privilege requested
	 * Run exactly as the parent daemon
	 */
	if (run_as_user == 0 || run_as_user[0] == 0) {
		/* create the child process */
		ret = CreateProcessW(
			NULL,
			cmd_buffer,
			NULL, NULL,
			FALSE, /* no need to inherit handles */
			CREATE_NO_WINDOW,
			NULL, cwd,
			&si, &pi
		);
	} else {
		/*
		 * Drop to restricted service account.
		 */
		HANDLE h_token = NULL;

		/*
		 * Validate that the requested user is actually a supported
		 * Service Account before attempting logon.
		 */
		if (_stricmp(run_as_user, "LocalService") != 0 && _stricmp(run_as_user, "NetworkService") != 0) {
			log_task(LVL_ERROR, "only supported users are LocalService and NetworkService");
			return -1;
		}

		if (!LogonUserW(u8tou16(conv, run_as_user), L"NT AUTHORITY", NULL, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, &h_token)) {
			windows_errno(GetLastError());
			log_task(LVL_ERROR, "failed to logon user %s, errno=%s(%d)", run_as_user, strerror(errno), errno);
			return -1;
		}

		/*
		 * Create an environment block to ensure PATH is loaded.
		 */
		LPVOID env = NULL;
		if (!CreateEnvironmentBlock(&env, h_token, FALSE)) {
			windows_errno(GetLastError());
			log_task(LVL_ERROR, "failed to get user %s environment, errno=%s(%d)", run_as_user, strerror(errno), errno);
			CloseHandle(h_token);
			return -1;
		}

		ret = CreateProcessAsUserW(
			h_token,
			NULL,
			cmd_buffer,
			NULL, NULL,
			FALSE, /* no need to inherit handles */
			CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
			env, cwd,
			&si, &pi
		);

		if (env)
			DestroyEnvironmentBlock(env);
		CloseHandle(h_token);
	}
	if (!ret) {
		windows_errno(GetLastError());
		log_task(LVL_ERROR, "failed to create process for script, errno=%s(%d)", strerror(errno), errno);
		return -1;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);

	DWORD status;
	GetExitCodeProcess(pi.hProcess, &status);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	stop = os_tick_sec();
	int64_t execution_time = stop - start;
	if (execution_time > 30)
		log_task(LVL_WARNING, "script %s took %" PRId64 " seconds", resolved_path, execution_time);

	if (WIFEXITED(status)) {
		int exit_code = WEXITSTATUS(status);
		if (exit_code == 0)
			log_task(LVL_INFO, "script %s terminated in %" PRId64 " seconds with success", resolved_path, execution_time);
		else
			log_task(LVL_ERROR, "script %s terminated in %" PRId64 " seconds with exit code %d", resolved_path, execution_time, exit_code);
		return exit_code;
	} else if (WIFSIGNALED(status)) {
		/* child died from a signal */
		int sig = WTERMSIG(status);
		log_task(LVL_ERROR, "script %s terminated in %" PRId64 " seconds with signal %s(%d)", resolved_path, execution_time, signal_name(sig), sig);
		return 128 + sig;
	} else {
		/* in Windows it can happen */
		log_task(LVL_ERROR, "script %s terminated in %" PRId64 " seconds for unknown reason, status=0x%08x", resolved_path, execution_time, (unsigned)status);
		return -1;
	}
}

/****************************************************************************/
/* system */

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

void os_system(struct snapraid_system* system)
{
	DWORD size = KEYWORD_MAX;
	if (!GetComputerNameA(system->hostname, &size)) {
		strncpy(system->hostname, "Unknown", KEYWORD_MAX);
	}

	get_windows_version(system);

	HKEY hKey;
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		DWORD cpuSize = MSG_MAX;
		RegQueryValueExA(hKey, "ProcessorNameString", NULL, NULL, (LPBYTE)system->cpu_model, &cpuSize);
		RegCloseKey(hKey);
	}

	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		char vendor[256] = { 0 };
		char product[256] = { 0 };
		DWORD vSize = 256, pSize = 256;
		RegQueryValueExA(hKey, "BaseBoardManufacturer", NULL, NULL, (LPBYTE)vendor, &vSize);
		RegQueryValueExA(hKey, "BaseBoardProduct", NULL, NULL, (LPBYTE)product, &pSize);
		snprintf(system->motherboard, MSG_MAX, "%s %s", vendor, product);
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

void os_system_refresh(struct snapraid_system* system)
{
	/* GetTickCount64 returns milliseconds since boot */
	system->uptime_seconds = GetTickCount64() / 1000;

	MEMORYSTATUSEX memInfo;
	memInfo.dwLength = sizeof(MEMORYSTATUSEX);
	if (GlobalMemoryStatusEx(&memInfo)) {
		system->memory_free_bytes = memInfo.ullAvailPhys;
	}
}

/****************************************************************************/
/* daemon */

#include "messages.h"

#define SERVICE_NAME "snapraidd"

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

	h = RegisterEventSource(NULL, SERVICE_NAME);
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

	g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
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

		os_done();
	} else {
		SERVICE_TABLE_ENTRY ServiceTable[] = {
			{ (char*)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
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

