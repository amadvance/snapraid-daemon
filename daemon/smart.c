// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#include "portable.h"

#include "elem.h"
#include "smart.h"


/****************************************************************************/
/* smart */

/**
 * Mask no bit
 */
#define MASK_64 0xFFFFFFFFFFFFFFFFULL
#define MASK_48 0xFFFFFFFFFFFFULL
#define MASK_32 0xFFFFFFFFULL

/**
 * Special format for attributes
 */
#define FORMAT_MASK 0xFF0000
#define FORMAT_8  0x10000 /**< 8 bits */
#define FORMAT_16 0x20000 /**< 16 bits */
#define FORMAT_24 0x30000 /**< 24 bits */
#define FORMAT_32 0x40000 /**< 32 bits */
#define FORMAT_48 0x50000 /**< 48 bits */
#define FORMAT_64 0x60000 /**< 64 bits */
#define FORMAT_16_MAXMINVAL 0x70000 /**< 16 bits nibbles MAX-MIN-VAL */
#define FORMAT_64_60 0x80000 /**< 64 bits * 60 (minutes) */
#define FORMAT_8_BM 0x90000 /**< Bit masks of lower 8 bits */
#define FORMAT_64_1000_512 0xA0000 /**< 64 bits * 1000 * 512 */
#define FORMAT_48_GB 0xB0000 /**< 48 bits * 1000^3 */
#define FORMAT_48_GIB 0xC0000 /**< 48 bits * 1024^3 */
#define FORMAT_48_MIB 0xD0000 /**< 48 bits * 1024^2 */
#define FORMAT_48_32MIB 0xE0000 /**< 48 bits * 32 * 1024^2 */
#define FORMAT_48_512 0xF0000 /**< 48 bits * 512 */
#define FORMAT_16_D1000_AVG 0x100000 /**< 16 bits / 1000, AVG-VAL */
#define FORMAT_16_MINVAL 0x200000 /**< 16 bits, nibbles MIN-VAL */

/* From: https://github.com/smartmontools/smartmontools/blob/main/drivedb/drivedb.h */
struct smart_entry {
	int index;
	int format;
	const char* name;
	int kind;
} SMART_ENTRIES[] = {
	/**
	 * Critical entries, selection from the following sources:
	 *
	 * From: https://github.com/linuxhw/SMART
	 *
	 * Number_Of_Important_Errors - number of important errors that can indicate a drive failure:
	 *
	 *     Current_Pending_Sector
	 *     ECC_Uncorr_Error_Count
	 *     End-to-End_Error
	 *     Offline_Uncorrectable
	 *     Reallocated_Event_Count
	 *     Reallocated_Sector_Ct
	 *     Reported_Uncorrect
	 *     Soft_Read_Error_Rate
	 *     Spin_Retry_Count
	 *     Total_Pending_Sectors
	 *     Unc_Soft_Read_Err_Rate
	 *
	 * From: https://www.backblaze.com/blog/hard-drive-smart-stats/
	 *
	 * From experience, we have found the following five SMART metrics indicate impending disk drive failure:
	 *
	 *     SMART 5: Reallocated_Sector_Count.
	 *     SMART 187: Reported_Uncorrectable_Errors.
	 *     SMART 188: Command_Timeout.
	 *     SMART 197: Current_Pending_Sector_Count.
	 *     SMART 198: Offline_Uncorrectable
	 *
	 * From: https://care.acronis.com/s/article/9264-Acronis-Drive-Monitor-Disk-Health-Calculation?language=en_US&ckattempt=1
	 *
	 * The following table contains the health related (critical) S.M.A.R.T. attributes affecting the health value with their weights and maximum limits.
	 *
	 * Table 1.
	 * Attribute ID	S.M.A.R.T. attribute			Weight	Limit %
	 * 05		Reallocated Sectors Count		2	70
	 * 10		Spin Retry Count			2	50
	 * 184		End-to-End Error			1	50
	 * 196		Reallocation Event Count		1	40
	 * 197		Current Pending Sectors Count		1	40
	 * 198		Offline uncorrectable Sectors Count	2	70
	 * 201		Soft Read Error Rate			1	20
	 *
	 */
	{ 5, FORMAT_16, "Reallocated_Sector_Ct", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE }, /* default entry */
	{ 5, FORMAT_16, "New_Bad_Blk_Count", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 5, FORMAT_16, "New_Bad_Block_Count", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 5, FORMAT_16, "Realloc_Flash_Blocks_Ct", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 5, FORMAT_16, "Retried_Blk_Ct", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 5, FORMAT_48, "Later_Bad_Block", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 5, FORMAT_48, "Reallocate_NAND_Blk_Cnt", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 5, FORMAT_48, "Reallocated_Block_Count", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 5, FORMAT_48, "Retired_Block_Count", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 5, FORMAT_48, "Runtime_Bad_Block", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },

	{ 10, FORMAT_48, "Spin_Retry_Count", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE }, /* default entry */
	{ 10, FORMAT_48, "Spin_Retry_Count,HDD", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },

	{ 184, FORMAT_48, "End-to-End_Error", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE }, /* default entry */
	{ 184, FORMAT_48, "End-to-End_Error_Count", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 184, FORMAT_48, "Error_Correction_Count", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 184, FORMAT_48, "IO_Error_Detect_Code_Ct", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },

	{ 187, FORMAT_48, "Reported_Uncorrect", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE }, /* default entry */
	{ 187, FORMAT_48, "Reported_UE_Counts", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 187, FORMAT_48, "Reported_Uncorr_Errors", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 187, FORMAT_48, "Total_Unc_NAND_Reads", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 187, FORMAT_48, "Uncorrectable_ECC_Ct", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 187, FORMAT_48, "Uncorrectable_Error_Cnt", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },

	/* adjusted from 48 to 16 */
	{ 188, FORMAT_16, "Command_Timeout", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE }, /* default entry */
	/* adjusted from 48 to 16 */
	{ 188, FORMAT_16, "Command_Timeouts", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },

#if 0
	/**
	 * Many entrys in https://github.com/linuxhw/SMART/ with "Hardware_ECC_Recovered" with high value
	 *
	 * From: https://en.wikipedia.org/wiki/Self-Monitoring,_Analysis_and_Reporting_Technology
	 *
	 * (Vendor-specific raw value.) The raw value has different structure for different
	 * vendors and is often not meaningful as a decimal number. For some drives, this
	 * number may increase during normal operation without necessarily signifying errors.[28]
	 */
	{ 195, FORMAT_48, "Hardware_ECC_Recovered", SMART_KIND_CRITICAL | SMART_KIND_PULSE }, /* default entry */
	{ 195, FORMAT_16, "RAISE_ECC_Cor_Ct", SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 195, FORMAT_24, "ECC_On_the_Fly_Count", SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 195, FORMAT_24, "ECC_Uncorr_Error_Count", SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 195, FORMAT_48, "ECC_Error_Rate", SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 195, FORMAT_48, "ECC_On_the_Fly_Count", SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 195, FORMAT_48, "ECC_on_the_Fly_Rate", SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	/* adjusted to 16 - not present in https://github.com/linuxhw/SMART and EnterpriseDrive */
	{ 195, FORMAT_16, "Uncorrectable_Err_Ct", SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	/* adjusted to 16 */
	{ 195, FORMAT_16, "Uncorrectable_Error_Cnt", SMART_KIND_CRITICAL | SMART_KIND_PULSE },
#endif

	{ 196, FORMAT_16, "Reallocated_Event_Count", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE }, /* default entry */
	{ 196, FORMAT_48, "Lifetime_Retried_Blk_Ct", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 196, FORMAT_48, "Total_Erase_Failures", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 196, FORMAT_48, "Total_Spare_Block_Cnt", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 196, FORMAT_64, "Erase_Failure_Blk_Ct", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },

	{ 197, FORMAT_48, "Current_Pending_Sector", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE }, /* default entry */
	{ 197, FORMAT_48, "Current_Pending_ECC_Cnt", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 197, FORMAT_48, "ECC_Error_Count", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 197, FORMAT_48, "Pending_Sector_Count", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 197, FORMAT_48, "Total_Unc_Read_Failures", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 197, FORMAT_64, "Read_Failure_Blk_Ct", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },

	{ 198, FORMAT_48, "Offline_Uncorrectable", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE }, /* default entry */
	{ 198, FORMAT_24, "Uncorrectable_Sector_Ct", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 198, FORMAT_48, "Offline_UErr_Media_Scan", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 198, FORMAT_48, "Uncor_Read_Error_Ct", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },

	{ 201, FORMAT_48, "Soft_Read_Error_Rate,HDD", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE }, /* default entry */
	{ 201, FORMAT_48, "Soft_Read_Error_Rate", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 201, FORMAT_24, "Unc_Soft_Read_Err_Rate", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 201, FORMAT_48, "Read_Error_Rate", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 201, FORMAT_48, "Unc_Read_Error_Rate", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 201, FORMAT_48, "Uncorr_Soft_Read_Err_Rt", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },

	/* spinup time, 3 (high 16 bit is average or 0) */
	{ 3, FORMAT_16_D1000_AVG, "Spin_Up_Time", SMART_KIND_TIME | SMART_KIND_CRITICAL | SMART_KIND_PULSE }, /* default entry */

	/* helium level (high 16 bit is min or 0), 22 */
	{ 22, FORMAT_16_MINVAL, "Helium_Level", SMART_KIND_LIFE_RATIO | SMART_KIND_CRITICAL | SMART_KIND_PULSE }, /* default entry */

	/* adjusted from 48 to 32 to avoid packed values in https://github.com/linuxhw/SMART */
	{ 179, FORMAT_32, "Used_Rsvd_Blk_Cnt_Tot", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE }, /* default entry */

	/* temperature, 190, 194, 231 */
	{ -1, FORMAT_16_MAXMINVAL, "Airflow_Temperature_Cel", SMART_KIND_TEMP | SMART_KIND_PULSE }, /* default entry */
	{ -1, FORMAT_16_MAXMINVAL, "Temperature_Celsius", SMART_KIND_TEMP | SMART_KIND_PULSE },  /* default entry */
	{ -1, FORMAT_16_MAXMINVAL, "Case_Temperature", SMART_KIND_TEMP | SMART_KIND_PULSE },
	{ -1, FORMAT_16_MAXMINVAL, "Drive_Temperature", SMART_KIND_TEMP | SMART_KIND_PULSE },
	{ -1, FORMAT_16_MAXMINVAL, "Temperature_Case", SMART_KIND_TEMP | SMART_KIND_PULSE },
	{ -1, FORMAT_16_MAXMINVAL, "Temperature_Internal", SMART_KIND_TEMP | SMART_KIND_PULSE },

	/* power on hours, 9 */
	{ 9, FORMAT_24, "Power_On_Hours", SMART_KIND_TIME }, /* default entry */
	{ 9, FORMAT_32, "Power_On_Hours_and_Msec", SMART_KIND_TIME }, /* hours are in the lower 32 bit */

	/* loaded hours */
	{ 222, FORMAT_32, "Loaded_Hours", SMART_KIND_TIME },

	/* size 241, 242 */
	{ -1, FORMAT_48_512, "Total_LBAs_Read", SMART_KIND_SIZE }, /* default entry */
	{ -1, FORMAT_48_512, "Total_LBAs_Written", SMART_KIND_SIZE }, /* default entry */
	{ -1, FORMAT_48_512, "Host_LBA_Read_Exp", SMART_KIND_SIZE },
	{ -1, FORMAT_48_512, "Host_LBA_Write_Exp", SMART_KIND_SIZE },
	{ -1, FORMAT_48_32MIB, "Host_Reads_32MiB", SMART_KIND_SIZE },
	{ -1, FORMAT_48_32MIB, "Host_Writes_32MiB", SMART_KIND_SIZE },
	{ -1, FORMAT_48_MIB, "Host_Reads_MiB", SMART_KIND_SIZE },
	{ -1, FORMAT_48_MIB, "Host_Writes_MiB", SMART_KIND_SIZE },
	{ -1, FORMAT_48_GIB, "Host_Reads_GiB", SMART_KIND_SIZE },
	{ -1, FORMAT_48_GIB, "Host_Writes_GiB", SMART_KIND_SIZE },
	{ -1, FORMAT_48_GIB, "Lifetime_Reads_GiB", SMART_KIND_SIZE },
	{ -1, FORMAT_48_GIB, "Lifetime_Writes_GiB", SMART_KIND_SIZE },
	{ -1, FORMAT_48_GB, "Lifetime_Wts_Frm_Hst_GB", SMART_KIND_SIZE },
	{ -1, FORMAT_48_GB, "Lifetime_Rds_Frm_Hst_GB", SMART_KIND_SIZE },
	{ -1, FORMAT_48_512, "Total_Host_LBA_Written", SMART_KIND_SIZE },
	{ -1, FORMAT_48_512, "Total_Host_LBA_Read", SMART_KIND_SIZE },
	{ -1, FORMAT_48_GB, "Total_Reads_GB", SMART_KIND_SIZE },
	{ -1, FORMAT_48_GIB, "Total_Reads_GiB", SMART_KIND_SIZE },
	{ -1, FORMAT_48_GB, "Total_Writes_GB", SMART_KIND_SIZE },
	{ -1, FORMAT_48_GIB, "Total_Writes_GiB", SMART_KIND_SIZE },

	/* other entries */
	{ 12, FORMAT_48, "Power_Cycle_Count", SMART_KIND_COUNT }, /* default entry */
	{ 4, FORMAT_48, "Start_Stop_Count", SMART_KIND_COUNT }, /* default entry */
	{ 193, FORMAT_48, "Load_Cycle_Count", SMART_KIND_COUNT }, /* default entry */

	/* from SnapRAID SCSI mapping, see smartctl_attribute() */
	{ 5, FORMAT_16, "Elements_In_Grown_Defect_List", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 194, FORMAT_16, "Current_Drive_Temperature", SMART_KIND_TEMP | SMART_KIND_PULSE },
	{ 190, FORMAT_16, "Drive_Trip_Temperature", SMART_KIND_TEMP | SMART_KIND_PULSE },
	{ 4, FORMAT_32, "Accumulated_Start-Stop_Cycles", SMART_KIND_COUNT },
	{ 193, FORMAT_32, "Accumulated_Load-Unload_Cycles", SMART_KIND_COUNT },
	{ 12, FORMAT_32, "Number_Of_Hours_Powered_Up", SMART_KIND_TIME },

	/* from SnapRAID NVME mapping, see smartctl_attribute() */
	{ 194, FORMAT_16, "Temperature", SMART_KIND_TEMP | SMART_KIND_PULSE },
	{ 12, FORMAT_48, "Power_Cycles", SMART_KIND_COUNT },
	{ -1, FORMAT_8_BM, "Critical_Warning", SMART_KIND_COUNT | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ -1, FORMAT_64, "Available_Spare", SMART_KIND_LIFE_RATIO },
	{ -1, FORMAT_64_1000_512, "Data_Units_Read", SMART_KIND_SIZE },
	{ -1, FORMAT_64_1000_512, "Data_Units_Written", SMART_KIND_SIZE },
	{ -1, FORMAT_64, "Host_Read_Commands", SMART_KIND_COUNT },
	{ -1, FORMAT_64, "Host_Write_Commands", SMART_KIND_COUNT },
	{ -1, FORMAT_64_60, "Controller_Busy_Time", SMART_KIND_TIME },
	{ -1, FORMAT_64, "Unsafe_Shutdowns", SMART_KIND_COUNT },
	{ -1, FORMAT_64_60, "Warning_Comp_Temperature_Time", SMART_KIND_TIME | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ -1, FORMAT_64_60, "Critical_Comp_Temperature_Time", SMART_KIND_TIME | SMART_KIND_CRITICAL | SMART_KIND_PULSE },
	{ 0 }
};

uint64_t smart_conv(uint64_t raw, int format)
{
	format &= FORMAT_MASK;

	switch (format) {
	case FORMAT_8 :
		return raw & 0xFF;
	case FORMAT_16 :
	case FORMAT_16_MAXMINVAL :
	case FORMAT_16_MINVAL :
	case FORMAT_16_D1000_AVG :
		return raw & 0xFFFF;
	case FORMAT_24 :
		return raw & 0xFFFFFF;
	case FORMAT_32 :
		return raw & MASK_32;
	case FORMAT_48_GB :
	case FORMAT_48_GIB :
	case FORMAT_48_MIB :
	case FORMAT_48_32MIB :
	case FORMAT_48_512 :
	case FORMAT_48 :
		return raw & MASK_48;
	case FORMAT_64 :
	case FORMAT_64_1000_512 :
	case FORMAT_64_60 :
		return raw;
	case FORMAT_8_BM :
		/* count bits */
		unsigned counter = 0;
		for (int i = 0; i < 8; ++i)
			if (raw & (1ULL << i))
				++counter;
		return counter;
	}

	return raw;
}

static struct smart_entry* find_entry(int index, const char* name)
{
	for (int i = 0; SMART_ENTRIES[i].index; ++i) {
		if (((SMART_ENTRIES[i].index < 0) || SMART_ENTRIES[i].index == index)
			&& strcmp(SMART_ENTRIES[i].name, name) == 0) {
			return &SMART_ENTRIES[i];
		}
	}

	return 0;
}

int smart_kind(int index, const char* name)
{
	struct smart_entry* entry = find_entry(index, name);
	if (!entry)
		return 0;

	return entry->kind | entry->format;
}

void smart_temperature_range(struct snapraid_device* dev, uint64_t* temp, uint64_t* temp_min, uint64_t* temp_max)
{
	uint64_t l, h, r;

	/* first 190 */
	r = dev->smart[190].raw.value;
	if (r != SMART_UNASSIGNED) {
		*temp = r & 0xFFFF;
		l = (r >> 16) & 0xFFFF;
		h = (r >> 32) & 0xFFFF;
		if (l <= *temp && *temp <= h) {
			*temp_min = l;
			*temp_max = h;
		}
	}

	/* then 194 that overwrite 190 */
	r = dev->smart[194].raw.value;
	if (r != SMART_UNASSIGNED) {
		*temp = r & 0xFFFF;
		l = (r >> 16) & 0xFFFF;
		h = (r >> 32) & 0xFFFF;
		if (l <= *temp && *temp <= h) {
			*temp_min = l;
			*temp_max = h;
		}
	}
}

void json_tracked(ss_t* s, int level, const char* name, struct snapraid_tracked* tracked, int format)
{
	ss_json_u64(s, level, name, smart_conv(tracked->value, format));

	if (tracked->prev != SMART_UNASSIGNED) {
		char history[KEYWORD_MAX];
		snprintf(history, sizeof(history), "%s_history", name);
		ss_json_object_open(s, &level, history);
		ss_json_u64(s, level, "prev", smart_conv(tracked->prev, format));
		ss_json_pair_iso8601(s, level, "prev_at", tracked->prev_last);
		if (tracked->lowest != SMART_UNASSIGNED
			&& smart_conv(tracked->lowest, format) != smart_conv(tracked->value, format)) {
			ss_json_u64(s, level, "lowest", smart_conv(tracked->lowest, format));
			ss_json_pair_iso8601(s, level, "lowest_at", tracked->lowest_last);
		}
		ss_json_close(s, &level);
	}
}

static void json_attr(ss_t* s, int* level, int kind_and_format, struct smart_attr* attr)
{
	int kind = kind_and_format;
	int format = kind_and_format & FORMAT_MASK;

	ss_json_open(s, level);
	ss_json_str(s, *level, "name", attr->name);
	ss_json_bool(s, *level, "critical", (kind & SMART_KIND_CRITICAL) != 0);
	if (attr->flags & SMART_ATTR_TYPE_PREFAIL)
		ss_json_str(s, *level, "type", "prefail");
	else
		ss_json_str(s, *level, "type", "oldage");
	if (attr->flags & SMART_ATTR_WHEN_FAILED_NOW)
		ss_json_str(s, *level, "when_failed", "now");
	else if (attr->flags & SMART_ATTR_WHEN_FAILED_PAST)
		ss_json_str(s, *level, "when_failed", "past");
	else if (attr->flags & SMART_ATTR_WHEN_FAILED_NEVER)
		ss_json_str(s, *level, "when_failed", "never");
	json_tracked(s, *level, "raw", &attr->raw, format);
	if (attr->norm != SMART_UNASSIGNED) {
		ss_json_u64(s, *level, "norm", attr->norm);
		if (attr->worst != SMART_UNASSIGNED)
			ss_json_u64(s, *level, "worst", attr->worst);
		if (attr->thresh != SMART_UNASSIGNED)
			ss_json_u64(s, *level, "thresh", attr->thresh);
	}
	if (format == FORMAT_16_MAXMINVAL) {
		uint64_t value = attr->raw.value & 0xFFFF;
		uint64_t min = (attr->raw.value >> 16) & 0xFFFF;
		uint64_t max = (attr->raw.value >> 32) & 0xFFFF;
		if (min <= value && value <= max) {
			ss_json_u64(s, *level, "min", min);
			ss_json_u64(s, *level, "max", max);
		}
	}
	if (format == FORMAT_16_MINVAL) {
		uint64_t value = attr->raw.value & 0xFFFF;
		uint64_t min = (attr->raw.value >> 16) & 0xFFFF;
		if (min != 0 && min <= value) {
			ss_json_u64(s, *level, "min", min);
		}
	}
	if (format == FORMAT_16_D1000_AVG) {
		uint64_t avg = (attr->raw.value >> 16) & 0xFFFF;
		if (avg != 0)
			ss_json_u64(s, *level, "avg", avg);
	}
	if (kind & SMART_KIND_SIZE) {
		ss_json_str(s, *level, "measure", "size");
		switch (format) {
		case FORMAT_64_1000_512 :
			ss_json_u64(s, *level, "unit", 1000 * 512);
			break;
		case FORMAT_48_GB :
			ss_json_u64(s, *level, "unit", 1000 * 1000 * 1000);
			break;
		case FORMAT_48_GIB :
			ss_json_u64(s, *level, "unit", 1024 * 1024 * 1024);
			break;
		case FORMAT_48_MIB :
			ss_json_u64(s, *level, "unit", 1024 * 1024);
			break;
		case FORMAT_48_32MIB :
			ss_json_u64(s, *level, "unit", 32 * 1024 * 1024);
			break;
		case FORMAT_48_512 :
			ss_json_u64(s, *level, "unit", 512);
			break;
		default :
			ss_json_u64(s, *level, "unit", 1);
			break;
		}
	} else if (kind & SMART_KIND_TIME) {
		ss_json_str(s, *level, "measure", "time");
		switch (format) {
		case FORMAT_64_60 :
			ss_json_u64(s, *level, "unit", 60);
			break;
		case FORMAT_16_D1000_AVG :
			ss_json_double(s, *level, "unit", 0.001);
			break;
		default :
			/* default hours */
			ss_json_u64(s, *level, "unit", 3600);
			break;
		}
	} else if (kind & SMART_KIND_TEMP) {
		ss_json_str(s, *level, "measure", "temperature");
		ss_json_u64(s, *level, "unit", 1);
	} else if (kind & SMART_KIND_LIFE_RATIO) {
		ss_json_str(s, *level, "measure", "life_ratio");
		ss_json_u64(s, *level, "unit", 1);
	} else if (kind & SMART_KIND_USE_RATIO) {
		ss_json_str(s, *level, "measure", "use_ratio");
		ss_json_u64(s, *level, "unit", 1);
	} else if (kind & SMART_KIND_COUNT) {
		ss_json_str(s, *level, "measure", "count");
		ss_json_u64(s, *level, "unit", 1);
	} else {
		ss_json_str(s, *level, "measure", "vendor");
		ss_json_u64(s, *level, "unit", 1);
	}
	ss_json_close(s, level);
}

void json_smart_list(ss_t* s, int level, struct snapraid_device* dev)
{
	char processed[SMART_COUNT];

	memset(processed, 0, sizeof(processed));

	ss_json_array_open(s, &level, "attributes");

	/* output known entry in the specific order listed */
	for (int i = 0; SMART_ENTRIES[i].index; ++i) {
		struct smart_entry* entry = &SMART_ENTRIES[i];
		struct smart_attr* attr = 0;
		int id = 0;

		if (entry->index > 0) {
			/* if the entry has a specific ID, check only that SMART ID */
			struct smart_attr* pos = &dev->smart[entry->index];
			if (strcmp(pos->name, entry->name) == 0) {
				attr = pos;
				id = entry->index;
			}
		} else {
			/* if the entry has a negative ID (-1), search it by name */
			for (int j = 1; j < SMART_COUNT; ++j) {
				struct smart_attr* pos = &dev->smart[j];
				if (pos->raw.value == SMART_UNASSIGNED)
					continue;
				if (strcmp(pos->name, entry->name) == 0) {
					attr = pos;
					id = j;
					break;
				}
			}
		}
		if (!attr)
			continue;

		processed[id] = 1;

		json_attr(s, &level, entry->kind | entry->format, attr);
	}

	/* output all PREFAIL that are not yet processed */
	for (int j = 1; j < SMART_COUNT; ++j) {
		struct smart_attr* attr = &dev->smart[j];

		/* if alredy processed, skip it */
		if (processed[j])
			continue;

		/* if not prefail, skip it */
		if ((attr->flags & SMART_ATTR_TYPE_PREFAIL) == 0)
			continue;

		/* if unassigned, skip it */
		if (attr->raw.value == SMART_UNASSIGNED)
			continue;

		json_attr(s, &level, SMART_KIND_CRITICAL | SMART_KIND_VENDOR, attr);
	}

	ss_json_array_close(s, &level);
}

