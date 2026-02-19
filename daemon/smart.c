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
#include "smart.h"


/****************************************************************************/
/* smart */

/* From: https://github.com/smartmontools/smartmontools/blob/main/drivedb/drivedb.h */
struct smart_entry {
	int index;
	int bit; /* -1 is for temperature current/min/max */
	const char* name;
	int flags;
} SMART_ENTRIES[] = {
	/* critical entries */
	{ 5, 16, "New_Bad_Blk_Count", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 5, 16, "New_Bad_Block_Count", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 5, 16, "Realloc_Flash_Blocks_Ct", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 5, 16, "Reallocated_Sector_Ct", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 5, 16, "Retried_Blk_Ct", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 5, 48, "Later_Bad_Block", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 5, 48, "Reallocate_NAND_Blk_Cnt", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 5, 48, "Reallocated_Block_Count", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 5, 48, "Retired_Block_Count", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 5, 48, "Runtime_Bad_Block", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
//	{ 10, 48, "Not_In_Use", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 10, 48, "Spin_Retry_Count", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 10, 48, "Spin_Retry_Count,HDD", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
//	{ 10, 48, "Unknown_JMF_Attribute", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
//	{ 10, 48, "Unknown_Maxio_Attribute", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 184, 48, "End-to-End_Error", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 184, 48, "End-to-End_Error_Count", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 184, 48, "Error_Correction_Count", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
//	{ 184, 48, "Factory_Bad_Block_Count", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 184, 48, "IO_Error_Detect_Code_Ct", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
//	{ 184, 64, "Initial_Bad_Block_Count", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 187, 48, "Reported_UE_Counts", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 187, 48, "Reported_Uncorr_Errors", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 187, 48, "Reported_Uncorrect", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 187, 48, "Total_Unc_NAND_Reads", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 187, 48, "Uncorrectable_ECC_Ct", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 187, 48, "Uncorrectable_Error_Cnt", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
//	{ 187, 48, "Unknown_JMF_Attribute", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 188, 16, "Command_Timeout", SMART_KIND_PREFAIL | SMART_KIND_PULSE }, /* adjusted to 16 */
	{ 188, 16, "Command_Timeouts", SMART_KIND_PREFAIL | SMART_KIND_PULSE }, /* adjusted to 16 */
	{ 195, 16, "RAISE_ECC_Cor_Ct", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 195, 24, "ECC_On_the_Fly_Count", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 195, 24, "ECC_On_the_Fly_Count", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 195, 24, "ECC_Uncorr_Error_Count", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
//	{ 195, 24, "Hardware_ECC_Recovered", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
//	{ 195, 48, "Cumulativ_Corrected_ECC", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 195, 48, "ECC_Error_Rate", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 195, 48, "ECC_On_the_Fly_Count", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 195, 48, "ECC_on_the_Fly_Rate", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
//	{ 195, 48, "Hardware_ECC_Recovered", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
//	{ 195, 48, "Power_Fail_Health", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
//	{ 195, 48, "Total_Prog_Failures", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 195, 16, "Uncorrectable_Err_Ct", SMART_KIND_PREFAIL | SMART_KIND_PULSE }, /* adjusted to 16 */  /* not present in https://github.com/linuxhw/SMART and EnterpriseDrive */
	{ 195, 16, "Uncorrectable_Error_Cnt", SMART_KIND_PREFAIL | SMART_KIND_PULSE }, /* adjusted to 16 */
//	{ 195, 64, "Program_Failure_Blk_Ct", SMART_KIND_PREFAIL | SMART_KIND_PULSE }, /* not a error counter */
//	{ 195,  8, "Hardware_ECC_Recovered", SMART_KIND_PREFAIL | SMART_KIND_PULSE }, /* not a error counter */
	{ 196, 16, "Reallocated_Event_Count", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
//	{ 196, 24 "Spare_Blocks", SMART_KIND_PREFAIL | SMART_KIND_PULSE }, /* not a error counter */
	{ 196, 48, "Lifetime_Retried_Blk_Ct", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
//	{ 196, 48, "Not_In_Use", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 196, 48, "Reallocated_Event_Count", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 196, 48, "Total_Erase_Failures", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 196, 48, "Total_Spare_Block_Cnt", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 196, 64, "Erase_Failure_Blk_Ct", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 197, 48, "Current_Pending_ECC_Cnt", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 197, 48, "Current_Pending_Sector", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 197, 48, "ECC_Error_Count", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
//	{ 197, 48, "Not_In_Use", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 197, 48, "Pending_Sector_Count", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 197, 48, "Total_Unc_Read_Failures", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 197, 64, "Read_Failure_Blk_Ct", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 198, 24, "Uncorrectable_Sector_Ct", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
//	{ 198, 48, "Host_Reads_GiB", SMART_KIND_PREFAIL | SMART_KIND_PULSE }, /* not a error counter */
//	{ 198, 48, "Not_In_Use", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 198, 48, "Offline_UErr_Media_Scan", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 198, 48, "Offline_Uncorrectable", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 198, 48, "Uncor_Read_Error_Ct", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
//	{ 198, 64, "Read_Sectors_Tot_Ct", SMART_KIND_PREFAIL | SMART_KIND_PULSE }, /* not a error counter */
//	{ 201, 16, "Power_Loss_Cap_Test", SMART_KIND_PREFAIL | SMART_KIND_PULSE }, /* not a error counter */
	{ 201, 24, "Unc_Soft_Read_Err_Rate", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
//	{ 201, 48, "Lifetime_Remaining%", SMART_KIND_PREFAIL | SMART_KIND_PULSE }, /* not a error counter */
//	{ 201, 48, "Percent_Lifetime_Remain", SMART_KIND_PREFAIL | SMART_KIND_PULSE }, /* not a error counter */
	{ 201, 48, "Read_Error_Rate", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 201, 48, "Soft_Read_Error_Rate,HDD", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
//	{ 201, 48, "Supercap_Status", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 201, 48, "Unc_Read_Error_Rate", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
	{ 201, 48, "Uncorr_Soft_Read_Err_Rt", SMART_KIND_PREFAIL | SMART_KIND_PULSE },
//	{ 201, 64, "Write_Commands_Tot_Ct", SMART_KIND_PREFAIL | SMART_KIND_PULSE }, /* not a error counter */

	/* temperature */
//	{ 190, 48, "Drive_Temp_Warning", SMART_KIND_TEMP | SMART_KIND_PULSE }, /* not a temperature,  https://github.com/linuxhw/EnterpriseDrive/blob/66faf203c101ca6b6bb96b5eb84610374b37e7ad/SSD/SanDisk/SDLFOCAM-800/SDLFOCAM-800G-1HA1/0336B2AD416B#L76 */
//	{ 190, 48, "SATA_Error_Ct", SMART_KIND_TEMP | SMART_KIND_PULSE },
	{ 190, -1, "Airflow_Temperature_Cel", SMART_KIND_TEMP | SMART_KIND_PULSE },
	{ 190, -1, "Case_Temperature", SMART_KIND_TEMP | SMART_KIND_PULSE },
	{ 190, -1, "Drive_Temperature", SMART_KIND_TEMP | SMART_KIND_PULSE },
	{ 190, -1, "Temperature_Case", SMART_KIND_TEMP | SMART_KIND_PULSE },
	{ 190, -1, "Temperature_Celsius", SMART_KIND_TEMP | SMART_KIND_PULSE },
//	{ 194, 48, "Device_Temperature", SMART_KIND_TEMP | SMART_KIND_PULSE }, /* not present in https://github.com/linuxhw/SMART and EnterpriseDrive */
	{ 194, -1, "Drive_Temperature", SMART_KIND_TEMP | SMART_KIND_PULSE },
	{ 194, -1, "Temperature_Celsius", SMART_KIND_TEMP | SMART_KIND_PULSE },
	{ 194, -1, "Temperature_Internal", SMART_KIND_TEMP | SMART_KIND_PULSE },

	/* other entries */
	{ 4, 48, "Start_Stop_Count", SMART_KIND_INFO },
	{ 9, 32, "Power_On_Hours_and_Msec", SMART_KIND_INFO }, /* hours are in the lower 32 bit */
	{ 9, 24, "Power_On_Hours", SMART_KIND_INFO },
	{ 12, 48, "Power_Cycle_Count", SMART_KIND_INFO },
//	{ 193,raw48,Dynamic_Remaps", SMART_KIND_INFO },
	{ 193, 48, "Load_Cycle_Count", SMART_KIND_INFO },
//	{ 193, 48, "Power_Fail_Uncompl_Cnt", SMART_KIND_INFO },
	{ 0 }
};

int smart_kind(int index, const char* name)
{
	for (int i = 0; SMART_ENTRIES[i].index; ++i) {
		if (SMART_ENTRIES[i].index == index && strcmp(SMART_ENTRIES[i].name, name) == 0)
			return SMART_ENTRIES[i].flags;
	}

	return 0;
}

void smart_temperature_range(struct snapraid_device* dev, uint64_t* temp, uint64_t* temp_min, uint64_t* temp_max)
{
	uint64_t l, h, r;

	/* first 190 */
	r = dev->smart[190].raw;
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
	r = dev->smart[194].raw;
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

void json_smart_list(ss_t* s, int level, struct snapraid_device* dev)
{
	ss_json_array_open(s, &level, "attributes");

	for (int i = 1; i < SMART_COUNT; ++i) {
		struct smart_attr* attr = &dev->smart[i];
		if (attr->raw == SMART_UNASSIGNED)
			continue;

		int j;
		for (j = 0; SMART_ENTRIES[j].index; ++j) {
			if (SMART_ENTRIES[j].index == i && strcmp(SMART_ENTRIES[j].name, attr->name) == 0)
				break;
		}

		struct smart_entry* entry = &SMART_ENTRIES[j];

		if (entry->index != 0) {
			uint64_t value = SMART_UNASSIGNED;

			switch (entry->bit) {
			case 8 :
				value = attr->raw & 0xFFUL;
				break;
			case 16 :
				value = attr->raw & 0xFFFFUL;
				break;
			case 24 :
				value = attr->raw & 0xFFFFFFUL;
				break;
			case 32 :
				value = attr->raw & 0xFFFFFFFFUL;
				break;
			case 48 :
				value = attr->raw & 0xFFFFFFFFFFFFUL;
				break;
			case -1 :
				value = attr->raw & 0xFFFFUL;
				break;
			}

			if (value != SMART_UNASSIGNED) {
				ss_json_open(s, &level);
				ss_json_str(s, level, "name", attr->name);
				int flags = entry->flags;
				if (flags & SMART_KIND_PREFAIL)
					ss_json_str(s, level, "type", "prefail");
				else if (flags & SMART_KIND_TEMP)
					ss_json_str(s, level, "type", "temperature");
				else
					ss_json_str(s, level, "type", "oldage");
				if (attr->flags & SMART_ATTR_WHEN_FAILED_NOW)
					ss_json_str(s, level, "when_failed", "now");
				else if (attr->flags & SMART_ATTR_WHEN_FAILED_PAST)
					ss_json_str(s, level, "when_failed", "past");
				else if (attr->flags & SMART_ATTR_WHEN_FAILED_NEVER)
					ss_json_str(s, level, "when_failed", "never");
				ss_json_u64(s, level, "raw", value);
				ss_json_u64(s, level, "norm", attr->norm);
				ss_json_u64(s, level, "worst", attr->worst);
				ss_json_u64(s, level, "thresh", attr->thresh);
				if (entry->bit == -1) {
					uint64_t min = (attr->raw >> 16) & 0xFFFFUL;
					uint64_t max = (attr->raw >> 32) & 0xFFFFUL;
					if (min <= value && value <= max) {
						ss_json_u64(s, level, "min", min);
						ss_json_u64(s, level, "max", max);
					}
				}
				ss_json_close(s, &level);
			}
		}
	}

	ss_json_array_close(s, &level);
}

