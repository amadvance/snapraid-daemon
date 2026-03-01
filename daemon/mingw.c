/*
 * Copyright (C) 2025 Andrea Mazzoleni
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "portable.h"

#ifdef __MINGW32__ /* Only for MingW */

#include "state.h"
#include "daemon.h"
#include "support.h"

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

static WCHAR path_snapraidW[PATH_MAX];
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
		snwprintf(path_snapraidW, PATH_MAX, L"/usr/bin/snapraid");
		strcpy(path_data, "/usr/share/snapraidd/");
		strcpy(path_snapraid, "/usr/bin/snapraid");
	} else {
		snwprintf(conv, PATH_MAX, L"%lslog", exedir);
		u16tou8(path_log, conv);

		snwprintf(conv, PATH_MAX, L"%lssnapraidd.conf", exedir);
		u16tou8(path_conf, conv);

		snwprintf(conv, PATH_MAX, L"%ls", exedir);
		u16tou8(path_data, conv);

		snwprintf(path_snapraidW, PATH_MAX, L"%lssnapraid.exe", exedir);
		u16tou8(path_snapraid, path_snapraidW);
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

	/* set errno if not already set */
	if (errno == 0 && GetLastError() != 0)
		windows_errno(GetLastError());

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
	if (h == INVALID_HANDLE_VALUE)
		return 0;

	DWORD result = GetFinalPathNameByHandleW(h, conv_buf, CONV_MAX, FILE_NAME_NORMALIZED);

	CloseHandle(h);

	if (result == 0 || result >= CONV_MAX)
		return 0;

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

const char* os_find_snapraid(void)
{
	DWORD attrib = GetFileAttributesW(path_snapraidW);

	/* check for existence every time */
	if (attrib == INVALID_FILE_ATTRIBUTES)
		return 0;

	return path_snapraid;
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

	/* set the bInheritHandle flag so pipe handles are inherited */
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;

	/* create a pipe for the child process's STDERR */
	if (!CreatePipe(&stderr_read_handle, &stderr_write_handle, &sa, 0)) {
		return -1;
	}

	/* ensure the reading handle to the pipe is not inherited */
	if (!SetHandleInformation(stderr_read_handle, HANDLE_FLAG_INHERIT, 0)) {
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
			exit(EXIT_FAILURE);
		}
	}
	cmd_buffer[pos] = 0;

	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
	BOOL ret;

	/* set up members of the STARTUPINFO structure */
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&si, sizeof(STARTUPINFOA));
	si.cb = sizeof(STARTUPINFOA);
	si.hStdError = stderr_write_handle;
	si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	si.dwFlags |= STARTF_USESTDHANDLES;

	/* create the child process */
	ret = CreateProcessW(
		NULL,
		cmd_buffer,
		NULL,
		NULL,
		TRUE,
		CREATE_NEW_PROCESS_GROUP,
		NULL,
		NULL,
		&si,
		&pi
	);

	/* close the write end of the pipe in the parent */
	CloseHandle(stderr_write_handle);

	if (!ret) {
		CloseHandle(stderr_read_handle);
		return -1;
	}

	/* close the handle to the primary thread, we don't need it */
	CloseHandle(pi.hThread);

	int f = _open_osfhandle((intptr_t)stderr_read_handle, O_RDONLY | O_BINARY);
	if (f == -1) {
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

int os_command(const char* command, const char* target_user, const char* stdin_text)
{
	(void)command;
	(void)target_user;
	(void)stdin_text;
	return -1;
}

int os_script(const char* script_path, const char* run_as_user)
{
	(void)script_path;
	(void)run_as_user;
	return -1;
}

/****************************************************************************/
/* signal */

void os_signal_restore_after_fork(void)
{
}

void os_signal_set(int enable)
{
	(void)enable;
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

void os_signal_init(void)
{
	/* install console control handler */
	if (!SetConsoleCtrlHandler(console_handler, TRUE)) {
		exit(EXIT_FAILURE);
	}
}

int os_daemonize(char* pidfile_path, size_t pidfile_size, const char* pidfile_arg)
{
	(void)pidfile_path;
	(void)pidfile_size;
	(void)pidfile_arg;
	return -1;
}

/****************************************************************************/
/* system */

void os_system(struct snapraid_system* system)
{
	DWORD size = KEYWORD_MAX;
	if (!GetComputerNameA(system->hostname, &size)) {
		strncpy(system->hostname, "Unknown", KEYWORD_MAX);
	}

	snprintf(system->os_distribution, MSG_MAX, "Windows %d.%d",
		(int)HIBYTE(LOWORD(GetVersion())),
		(int)LOBYTE(LOWORD(GetVersion())));

	snprintf(system->kernel_version, KEYWORD_MAX, "Build %lu", GetVersion() >> 16);

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

#endif

