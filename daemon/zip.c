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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "portable.h"

#include "elem.h"
#include "support.h"
#include "log.h"
#include "zip.h"

/* ZIP Compression Methods */
#define ZIP_METHOD_STORE 0 /**< No compression; data is stored as-is */
#define ZIP_METHOD_DEFLATE 8 /**< Standard Deflate */
#define ZIP_METHOD_DEFLATE64 9 /**< Enhanced Deflate64 */
#define ZIP_METHOD_BZIP2 12 /**< BZIP2 compression */
#define ZIP_METHOD_LZMA 14 /**< LZMA compression */
#define ZIP_METHOD_PPMD 98 /**< PPMd version I, Rev 1 */

/* Constants and Signatures */
#define EOCD_SIGNATURE 0x06054b50
#define CD_SIGNATURE 0x02014b50
#define LOCAL_SIGNATURE 0x04034b50

/* Header Sizes (Fixed parts) */
#define EOCD_FIXED_SIZE 22
#define CD_FIXED_SIZE 46
#define LOCAL_FIXED_SIZE 30

/* Offsets into End of Central Directory (EOCD) */
#define OFF_EOCD_TOTAL_ENTRIES 10
#define OFF_EOCD_CD_SIZE 12
#define OFF_EOCD_CD_OFFSET 16

/* Offsets into Central Directory (CD) Header */
#define OFF_CD_SIGNATURE 0
#define OFF_CD_METHOD 10
#define OFF_CD_MOD_TIME 12
#define OFF_CD_MOD_DATE 14
#define OFF_CD_CRC32 16
#define OFF_CD_COMP_SIZE 20
#define OFF_CD_UNCOMP_SIZE 24
#define OFF_CD_FILENAME_LEN 28
#define OFF_CD_EXTRA_LEN 30
#define OFF_CD_COMMENT_LEN 32
#define OFF_CD_LOCAL_OFFSET 42

/* Offsets into Local File Header */
#define OFF_LOCAL_SIGNATURE 0
#define OFF_LOCAL_FILENAME_LEN 26
#define OFF_LOCAL_EXTRA_LEN 28

/* Helper Functions for Unaligned Access */

static inline uint16_t read16(const uint8_t* p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static inline uint32_t read32(const uint8_t* p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline time_t dos_to_time_t(uint16_t dos_date, uint16_t dos_time)
{
	struct tm tm_struct = { 0 };
	tm_struct.tm_mday = dos_date & 0x1F;
	tm_struct.tm_mon = ((dos_date >> 5) & 0x0F) - 1;
	tm_struct.tm_year = ((dos_date >> 9) & 0x7F) + 80;
	tm_struct.tm_sec = (dos_time & 0x1F) * 2;
	tm_struct.tm_min = (dos_time >> 5) & 0x3F;
	tm_struct.tm_hour = (dos_time >> 11) & 0x1F;
	tm_struct.tm_isdst = -1;
	return mktime(&tm_struct);
}

static void plain_content(tommy_list* page_list, const char* file, void* uncompressed_data, size_t uncompressed_size, time_t datetime)
{
	char root[PATH_MAX];

	(void)datetime;

	snprintf(root, sizeof(root), "/%s", file);

	struct snapraid_page* page = page_alloc(root, uncompressed_size);

	memcpy(page->content, uncompressed_data, uncompressed_size);

	page->mime_type = get_mime_type(file);
	if (!page->mime_type)
		page->mime_type = MIME_BINARY;

	tommy_list_insert_tail(page_list, &page->node, page);
}

static int unzip_content(tommy_list* page_list, const char* path, const char* file, void* compressed_data, size_t compressed_size,
	size_t uncompressed_size, int compression_method,
	time_t datetime, uint32_t crc32)
{
	if (compression_method == ZIP_METHOD_STORE) {
		/* data is already uncompressed */
		if (compressed_size != uncompressed_size) {
			log_msg(LVL_ERROR, "crawler zip %s invalid uncompressed data size for compression method %d for %s", path, compression_method, file);
			return -1;
		}
		plain_content(page_list, file, compressed_data, compressed_size, datetime);
#if HAVE_ZLIB
	} else if (compression_method == ZIP_METHOD_DEFLATE) {
		void* out_buf = malloc_nofail(uncompressed_size);

		z_stream strm;
		strm.zalloc = Z_NULL;
		strm.zfree = Z_NULL;
		strm.opaque = Z_NULL;
		strm.avail_in = (uInt)compressed_size;
		strm.next_in = (Bytef*)compressed_data;
		strm.avail_out = (uInt)uncompressed_size;
		strm.next_out = (Bytef*)out_buf;

		/*
		 * inflateInit2 with -15 is the "Raw Deflate" mode.
		 * ZIP stores raw deflate blocks without the ZLIB header (CMF/FLG).
		 */
		if (inflateInit2(&strm, -15) == Z_OK) {
			int ret = inflate(&strm, Z_FINISH);
			inflateEnd(&strm);

			if (ret == Z_STREAM_END) {
				/* verify integrity with the CRC32 we extracted earlier */
				uint32_t check = calculate_crc32(out_buf, uncompressed_size);
				if (crc32 != check) {
					log_msg(LVL_ERROR, "crawler zip %s invalid crc for file %s", path, file);
					free(out_buf);
					return -1;
				}

				plain_content(page_list, file, out_buf, uncompressed_size, datetime);
			} else {
				log_msg(LVL_ERROR, "crawler zip %s decompression failed for file %s", path, file);
				free(out_buf);
				return -1;
			}
		}

		free(out_buf);
#endif
	} else {
		log_msg(LVL_ERROR, "crawler zip %s unsupported compression method %d for %s", path, compression_method, file);
		return -1;
	}

	return 0;
}

int crawl_zip(tommy_list* page_list, const char* path)
{
	int f = open(path, O_RDONLY | O_BINARY);
	if (f == -1) {
		log_msg(LVL_ERROR, "crawler error opening %s, errno=%s(%d)", path, strerror(errno), errno);
		return -1;
	}

	struct stat st;
	if (fstat(f, &st) != 0) {
		log_msg(LVL_ERROR, "crawler error accessing %s, errno=%s(%d)", path, strerror(errno), errno);
		close(f);
		return -1;
	}

	size_t buf_size = st.st_size;
	uint8_t* buffer = malloc_nofail(buf_size);;

	ssize_t ret = read(f, buffer, buf_size);
	if (ret <= 0 || (size_t)ret != buf_size) {
		log_msg(LVL_ERROR, "crawler error reading %s, errno=%s(%d)", path, strerror(errno), errno);
		close(f);
		free(buffer);
		return -1;
	}

	close(f);

	/* find EOCD by scanning backwards */
	size_t scan_limit = (buf_size > 65535 + EOCD_FIXED_SIZE) ? 65535 + EOCD_FIXED_SIZE : buf_size;

	size_t eocd_pos = 0;
	int found = 0;

	for (size_t i = EOCD_FIXED_SIZE; i <= scan_limit; i++) {
		size_t pos = buf_size - i;
		if (read32(buffer + pos) == EOCD_SIGNATURE) {
			eocd_pos = pos;
			found = 1;
			break;
		}
	}

	if (!found) {
		log_msg(LVL_ERROR, "crawler invalid zip %s file (eocd missing)", path);
		free(buffer);
		return -1;
	}

	/* read Central Directory info */
	uint16_t num_records = read16(buffer + eocd_pos + OFF_EOCD_TOTAL_ENTRIES);
	uint32_t cd_offset = read32(buffer + eocd_pos + OFF_EOCD_CD_OFFSET);

	if (cd_offset >= buf_size) {
		log_msg(LVL_ERROR, "crawler zip %s central directory offset out of bounds", path);
		free(buffer);
		return -1;
	}

	size_t current_cd_pos = cd_offset;

	/* iterate over files */
	for (int i = 0; i < num_records; i++) {
		/* bounds check: Fixed CD header */
		if (current_cd_pos + CD_FIXED_SIZE > buf_size) {
			log_msg(LVL_ERROR, "crawler zip %s central directory truncated ", path);
			goto bail;
		}

		uint8_t* cd_ptr = buffer + current_cd_pos;

		if (read32(cd_ptr + OFF_CD_SIGNATURE) != CD_SIGNATURE) {
			log_msg(LVL_ERROR, "crawler zip %s bad central directory signature at record %d ", path, i);
			goto bail;
		}

		/* read variable lengths */
		size_t name_len = read16(cd_ptr + OFF_CD_FILENAME_LEN);
		size_t extra_len = read16(cd_ptr + OFF_CD_EXTRA_LEN);
		size_t comment_len = read16(cd_ptr + OFF_CD_COMMENT_LEN);

		/* bounds check: Full CD record */
		size_t next_cd_pos = current_cd_pos + CD_FIXED_SIZE + name_len + extra_len + comment_len;
		if (next_cd_pos > buf_size) {
			log_msg(LVL_ERROR, "crawler zip %s central directory record %d truncated", path, i);
			goto bail;
		}

		/* extract filename */
		char name_buf[512];
		size_t copy_len = (name_len < sizeof(name_buf) - 1) ? name_len : sizeof(name_buf) - 1;
		memcpy(name_buf, cd_ptr + CD_FIXED_SIZE, copy_len);
		name_buf[copy_len] = 0;

		/* extract metadata */
		uint32_t crc32 = read32(cd_ptr + OFF_CD_CRC32);
		uint16_t method = read16(cd_ptr + OFF_CD_METHOD);
		size_t c_size = read32(cd_ptr + OFF_CD_COMP_SIZE);
		size_t u_size = read32(cd_ptr + OFF_CD_UNCOMP_SIZE);
		uint16_t mod_time = read16(cd_ptr + OFF_CD_MOD_TIME);
		uint16_t mod_date = read16(cd_ptr + OFF_CD_MOD_DATE);
		size_t local_off = read32(cd_ptr + OFF_CD_LOCAL_OFFSET);

		/* resolve data pointer via Local Header */
		if (local_off + LOCAL_FIXED_SIZE > buf_size) {
			log_msg(LVL_ERROR, "crawler zip %s local header offset out of bounds", path);
			goto bail;
		}

		uint8_t* local_ptr = buffer + local_off;
		if (read32(local_ptr + OFF_LOCAL_SIGNATURE) != LOCAL_SIGNATURE) {
			log_msg(LVL_ERROR, "crawler zip %s bad local signature", path);
			goto bail;
		}

		size_t loc_name_len = read16(local_ptr + OFF_LOCAL_FILENAME_LEN);
		size_t loc_extra_len = read16(local_ptr + OFF_LOCAL_EXTRA_LEN);

		size_t data_offset = local_off + LOCAL_FIXED_SIZE + loc_name_len + loc_extra_len;

		/* final bounds check: data */
		if (data_offset > buf_size || c_size > (buf_size - data_offset)) {
			log_msg(LVL_ERROR, "crawler zip %s data exceeds buffer bounds", path);
			goto bail;
		}

		if (unzip_content(
				page_list,
				path,
				name_buf,
				(void*)(buffer + data_offset),
				c_size,
				u_size,
				method,
				dos_to_time_t(mod_date, mod_time),
				crc32) != 0) {
			goto bail;
		}

		current_cd_pos = next_cd_pos;
	}

	free(buffer);
	return 0;

bail:
	free(buffer);
	return -1;
}

