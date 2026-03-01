/*
 * Rufus: The Reliable USB Formatting Utility
 * SMART HDD vs Flash detection - Linux implementation
 * Copyright © 2013-2023 Pete Batard <pete@akeo.ie>
 * Linux port: Rufus Linux contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <mm_malloc.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>
#include <stdint.h>

#include "rufus.h"
#include "drive.h"
#include "smart.h"
#include "hdd_vs_ufd.h"

/* Recover POSIX fd from opaque HANDLE */
#define HANDLE_TO_FD(h) ((int)(intptr_t)(h))

/* Helper to determine ATA data direction from command + features */
static uint8_t GetAtaDirection(uint8_t AtaCmd, uint8_t Features)
{
	BOOL smart_out = (AtaCmd == ATA_SMART_CMD) &&
		((Features == ATA_SMART_STATUS) || (Features == ATA_SMART_WRITE_LOG_SECTOR));

	switch (AtaCmd) {
	case ATA_IDENTIFY_DEVICE:
	case ATA_READ_LOG_EXT:
		return ATA_PASSTHROUGH_DATA_IN;
	case ATA_SMART_CMD:
		if (!smart_out)
			return ATA_PASSTHROUGH_DATA_IN;
		/* fall through */
	case ATA_DATA_SET_MANAGEMENT:
		return ATA_PASSTHROUGH_DATA_OUT;
	default:
		return ATA_PASSTHROUGH_DATA_NONE;
	}
}

const char* SptStrerr(int errcode)
{
	static char scsi_err[64];

	if ((errcode > 0) && (errcode <= 0xff)) {
		static_sprintf(scsi_err, "SCSI status: 0x%02X", (uint8_t)errcode);
		return (const char*)scsi_err;
	}

	switch (errcode) {
	case SPT_SUCCESS:
		return "Success";
	case SPT_ERROR_CDB_LENGTH:
		return "Invalid CDB length";
	case SPT_ERROR_BUFFER:
		return "Buffer must be aligned to a page boundary and less than 64KB in size";
	case SPT_ERROR_DIRECTION:
		return "Invalid Direction";
	case SPT_ERROR_EXTENDED_CDB:
		return "Extended and variable length CDB commands are not supported";
	case SPT_ERROR_CDB_OPCODE:
		return "Opcodes above 0xC0 are not supported";
	case SPT_ERROR_TIMEOUT:
		return "Timeout";
	case SPT_ERROR_INVALID_PARAMETER:
		return "Invalid DeviceIoControl parameter";
	case SPT_ERROR_CHECK_STATUS:
		return "SCSI error (check Status)";
	default:
		return "Unknown error";
	}
}

/*
 * SCSI Passthrough via SG_IO ioctl.
 * Non-static when RUFUS_TEST is defined so tests can call it directly.
 */
#ifdef RUFUS_TEST
int ScsiPassthroughDirect(HANDLE hPhysical, uint8_t* Cdb, size_t CdbLen,
	uint8_t Direction, void* DataBuffer, size_t BufLen, uint32_t Timeout)
#else
static int ScsiPassthroughDirect(HANDLE hPhysical, uint8_t* Cdb, size_t CdbLen,
	uint8_t Direction, void* DataBuffer, size_t BufLen, uint32_t Timeout)
#endif
{
	struct sg_io_hdr io_hdr;
	uint8_t sense[SPT_SENSE_LENGTH];
	int fd = HANDLE_TO_FD(hPhysical);

	if ((CdbLen == 0) || (CdbLen > SPT_CDB_LENGTH))
		return SPT_ERROR_CDB_LENGTH;

	if (((uintptr_t)DataBuffer % 0x10 != 0) || (BufLen > 0xFFFF))
		return SPT_ERROR_BUFFER;

	if (Direction > SCSI_IOCTL_DATA_UNSPECIFIED)
		return SPT_ERROR_DIRECTION;

	if ((Cdb[0] == 0x7e) || (Cdb[0] == 0x7f))
		return SPT_ERROR_EXTENDED_CDB;

	if ((Cdb[0] >= 0xc0) && (Cdb[0] != USB_JMICRON_ATA_PASSTHROUGH)
	  && (Cdb[0] != USB_SUNPLUS_ATA_PASSTHROUGH))
		return SPT_ERROR_CDB_OPCODE;

	memset(&io_hdr, 0, sizeof(io_hdr));
	memset(sense, 0, sizeof(sense));

	io_hdr.interface_id = 'S';
	io_hdr.cmd_len      = (uint8_t)CdbLen;
	io_hdr.cmdp         = Cdb;
	io_hdr.dxfer_direction = (Direction == SCSI_IOCTL_DATA_IN)  ? SG_DXFER_FROM_DEV :
	                          (Direction == SCSI_IOCTL_DATA_OUT) ? SG_DXFER_TO_DEV   :
	                                                               SG_DXFER_NONE;
	io_hdr.dxfer_len    = (unsigned int)BufLen;
	io_hdr.dxferp       = DataBuffer;
	io_hdr.mx_sb_len    = SPT_SENSE_LENGTH;
	io_hdr.sbp          = sense;
	io_hdr.timeout      = Timeout * 1000; /* seconds → milliseconds */

	if (ioctl(fd, SG_IO, &io_hdr) < 0) {
		if (errno == ETIMEDOUT)
			return SPT_ERROR_TIMEOUT;
		return SPT_ERROR_UNKNOWN_ERROR;
	}
	if (io_hdr.status != 0)
		return (int)io_hdr.status;
	return SPT_SUCCESS;
}

static int SatAtaPassthrough(HANDLE hPhysical, ATA_PASSTHROUGH_CMD* Command,
	void* DataBuffer, size_t BufLen, uint32_t Timeout)
{
	uint8_t Cdb[12] = {0};
	int extend      = 0;
	int ck_cond     = 0;
	int protocol    = 3;   /* Non-data */
	int t_dir       = 1;   /* 0 → to device, 1 → from device */
	int byte_block  = 1;   /* 0 → bytes, 1 → 512 byte blocks */
	int t_length    = 0;   /* 0 → no data transferred */
	uint8_t Direction;

	if (BufLen % SelectedDrive.SectorSize != 0) {
		uprintf("SatAtaPassthrough: BufLen must be a multiple of <block size>\n");
		return SPT_ERROR_BUFFER;
	}

	Direction = GetAtaDirection(Command->AtaCmd, Command->Features);
	if (BufLen != 0) {
		switch (Direction) {
		case ATA_PASSTHROUGH_DATA_NONE:
			break;
		case ATA_PASSTHROUGH_DATA_IN:
			protocol = 4;
			t_length = 2;
			break;
		case ATA_PASSTHROUGH_DATA_OUT:
			protocol = 5;
			t_length = 2;
			t_dir    = 0;
			break;
		}
	}

	Cdb[0] = SAT_ATA_PASSTHROUGH_12;
	Cdb[1] = (protocol << 1) | extend;
	Cdb[2] = (ck_cond << 5) | (t_dir << 3) | (byte_block << 2) | t_length;
	Cdb[3] = Command->Features;
	Cdb[4] = (uint8_t)(BufLen >> SECTOR_SIZE_SHIFT_BIT);
	Cdb[5] = Command->Lba_low;
	Cdb[6] = Command->Lba_mid;
	Cdb[7] = Command->Lba_high;
	Cdb[8] = Command->Device;
	Cdb[9] = Command->AtaCmd;

	return ScsiPassthroughDirect(hPhysical, Cdb, sizeof(Cdb), Direction, DataBuffer, BufLen, Timeout);
}

static int _UsbJMPLAtaPassthrough(HANDLE hPhysical, ATA_PASSTHROUGH_CMD* Command,
	void* DataBuffer, size_t BufLen, uint32_t Timeout, BOOL prolific)
{
	uint8_t Cdb[14] = {0};
	uint8_t Direction;

	Direction = GetAtaDirection(Command->AtaCmd, Command->Features);

	Cdb[0]  = USB_JMICRON_ATA_PASSTHROUGH;
	Cdb[1]  = ((BufLen != 0) && (Direction == ATA_PASSTHROUGH_DATA_OUT)) ? 0x00 : 0x10;
	Cdb[3]  = (uint8_t)(BufLen >> 8);
	Cdb[4]  = (uint8_t)(BufLen);
	Cdb[5]  = Command->Features;
	Cdb[6]  = (uint8_t)(BufLen >> SECTOR_SIZE_SHIFT_BIT);
	Cdb[7]  = Command->Lba_low;
	Cdb[8]  = Command->Lba_mid;
	Cdb[9]  = Command->Lba_high;
	Cdb[10] = Command->Device;
	Cdb[11] = Command->AtaCmd;
	Cdb[12] = 0x06;
	Cdb[13] = 0x7b;

	return ScsiPassthroughDirect(hPhysical, Cdb, sizeof(Cdb) - (prolific ? 2 : 0),
	                             Direction, DataBuffer, BufLen, Timeout);
}

static int UsbJmicronAtaPassthrough(HANDLE hPhysical, ATA_PASSTHROUGH_CMD* Command,
	void* DataBuffer, size_t BufLen, uint32_t Timeout)
{
	return _UsbJMPLAtaPassthrough(hPhysical, Command, DataBuffer, BufLen, Timeout, FALSE);
}

/* UNTESTED!!! */
static int UsbProlificAtaPassthrough(HANDLE hPhysical, ATA_PASSTHROUGH_CMD* Command,
	void* DataBuffer, size_t BufLen, uint32_t Timeout)
{
	return _UsbJMPLAtaPassthrough(hPhysical, Command, DataBuffer, BufLen, Timeout, TRUE);
}

/* UNTESTED!!! */
static int UsbSunPlusAtaPassthrough(HANDLE hPhysical, ATA_PASSTHROUGH_CMD* Command,
	void* DataBuffer, size_t BufLen, uint32_t Timeout)
{
	uint8_t Cdb[12] = {0};
	uint8_t Direction;

	Direction = GetAtaDirection(Command->AtaCmd, Command->Features);

	Cdb[0]  = USB_SUNPLUS_ATA_PASSTHROUGH;
	Cdb[2]  = 0x22;
	if (BufLen != 0) {
		if (Direction == ATA_PASSTHROUGH_DATA_IN)
			Cdb[3] = 0x10;
		else if (Direction == ATA_PASSTHROUGH_DATA_OUT)
			Cdb[3] = 0x11;
	}
	Cdb[4]  = (uint8_t)(BufLen >> SECTOR_SIZE_SHIFT_BIT);
	Cdb[5]  = Command->Features;
	Cdb[6]  = (uint8_t)(BufLen >> SECTOR_SIZE_SHIFT_BIT);
	Cdb[7]  = Command->Lba_low;
	Cdb[8]  = Command->Lba_mid;
	Cdb[9]  = Command->Lba_high;
	Cdb[10] = Command->Device | 0xa0;
	Cdb[11] = Command->AtaCmd;

	return ScsiPassthroughDirect(hPhysical, Cdb, sizeof(Cdb), Direction, DataBuffer, BufLen, Timeout);
}

/* UNTESTED!!! */
static int UsbCypressAtaPassthrough(HANDLE hPhysical, ATA_PASSTHROUGH_CMD* Command,
	void* DataBuffer, size_t BufLen, uint32_t Timeout)
{
	uint8_t Cdb[16] = {0};
	uint8_t Direction;

	Direction = GetAtaDirection(Command->AtaCmd, Command->Features);

	Cdb[0]  = USB_CYPRESS_ATA_PASSTHROUGH;
	Cdb[1]  = USB_CYPRESS_ATA_PASSTHROUGH;
	if (Command->AtaCmd == ATA_IDENTIFY_DEVICE || Command->AtaCmd == ATA_IDENTIFY_PACKET_DEVICE)
		Cdb[2] = (1 << 7);
	Cdb[3]  = 0xff - (1 << 0) - (1 << 6);
	Cdb[4]  = 1;
	Cdb[6]  = Command->Features;
	Cdb[7]  = (uint8_t)(BufLen >> SECTOR_SIZE_SHIFT_BIT);
	Cdb[8]  = Command->Lba_low;
	Cdb[9]  = Command->Lba_mid;
	Cdb[10] = Command->Lba_high;
	Cdb[11] = Command->Device;
	Cdb[12] = Command->AtaCmd;

	return ScsiPassthroughDirect(hPhysical, Cdb, sizeof(Cdb), Direction, DataBuffer, BufLen, Timeout);
}

static AtaPassThroughType ata_pt[] = {
	{ SatAtaPassthrough,      "SAT"      },
	{ UsbJmicronAtaPassthrough, "JMicron" },
	{ UsbProlificAtaPassthrough, "Prolific" },
	{ UsbSunPlusAtaPassthrough, "SunPlus"  },
	{ UsbCypressAtaPassthrough, "Cypress"  },
};

#if defined(RUFUS_TEST)
BOOL Identify(HANDLE hPhysical)
{
	ATA_PASSTHROUGH_CMD Command = {0};
	IDENTIFY_DEVICE_DATA* idd;
	int i, r;

	Command.AtaCmd = ATA_IDENTIFY_DEVICE;

	COMPILE_TIME_ASSERT(sizeof(IDENTIFY_DEVICE_DATA) == 512);

	idd = (IDENTIFY_DEVICE_DATA*)_mm_malloc(sizeof(IDENTIFY_DEVICE_DATA), 0x10);
	if (idd == NULL)
		return FALSE;

	for (i = 0; i < ARRAYSIZE(ata_pt); i++) {
		r = ata_pt[i].fn(hPhysical, &Command, idd, sizeof(IDENTIFY_DEVICE_DATA), SPT_TIMEOUT_VALUE);
		if (r == SPT_SUCCESS) {
			uprintf("Success using %s\n", ata_pt[i].type);
			if (idd->CommandSetSupport.SmartCommands) {
				uprintf("SMART support detected!\n");
			} else {
				uprintf("No SMART support\n");
			}
			break;
		}
		uprintf("No joy with: %s (%s)\n", ata_pt[i].type, SptStrerr(r));
	}
	if (i >= ARRAYSIZE(ata_pt))
		uprintf("NO ATA FOR YOU!\n");

	_mm_free(idd);
	return (i < (int)ARRAYSIZE(ata_pt));
}
#endif /* RUFUS_TEST */

BOOL SmartGetVersion(HANDLE hdevice)
{
	(void)hdevice;
	return FALSE;
}

int IsHDD(DWORD DriveIndex, uint16_t vid, uint16_t pid, const char* strid)
{
	int score = 0;
	size_t i, mlen, ilen, score_list_size = 0;
	BOOL wc;
	uint64_t drive_size;
	int8_t score_list[16];
	char str[64] = { 0 };

	if (GetDriveTypeFromIndex(DriveIndex) == DRIVE_FIXED) {
		score_list[score_list_size] = 3;
		score += score_list[score_list_size++];
	}

	drive_size = GetDriveSize(DriveIndex);
	if (drive_size > 800 * GB) {
		score_list[score_list_size] = 15;
		score += score_list[score_list_size++];
		if (drive_size > 1800 * GB) {
			score_list[score_list_size] = 15;
			score += score_list[score_list_size++];
		}
	} else if (drive_size < 128 * GB) {
		score_list[score_list_size] = -15;
		score += score_list[score_list_size++];
	}

	if (strid != NULL) {
		ilen = strlen(strid);
		for (i = 0; i < ARRAYSIZE(str_score); i++) {
			mlen = strlen(str_score[i].name);
			if (mlen > ilen)
				break;
			wc = (str_score[i].name[mlen - 1] == '#');
			if ((_strnicmp(strid, str_score[i].name, mlen - ((wc) ? 1 : 0)) == 0)
			  && ((!wc) || ((strid[mlen] >= '0') && (strid[mlen] <= '9')))) {
				score_list[score_list_size] = str_score[i].score;
				score += score_list[score_list_size++];
				break;
			}
		}
	}

	if (strid != NULL) {
		for (i = 0; i < ARRAYSIZE(str_adjust); i++)
			if (StrStrIA(strid, str_adjust[i].name) != NULL) {
				score_list[score_list_size] = str_adjust[i].score;
				score += score_list[score_list_size++];
			}
	}

	for (i = 0; i < ARRAYSIZE(vid_score); i++) {
		if (vid == vid_score[i].vid) {
			score_list[score_list_size] = vid_score[i].score;
			score += score_list[score_list_size++];
			break;
		}
	}

	for (i = 0; i < ARRAYSIZE(vidpid_score); i++) {
		if ((vid == vidpid_score[i].vid) && (pid == vidpid_score[i].pid)) {
			score_list[score_list_size] = vidpid_score[i].score;
			score += score_list[score_list_size++];
			break;
		}
	}

	if (usb_debug) {
		static_strcat(str, "Device score: ");
		for (i = 0; i < score_list_size; i++)
			safe_sprintf(&str[strlen(str)], sizeof(str) - strlen(str), "%+d", score_list[i]);
		uprintf("%s=%+d → Detected as %s", str, score, (score > 0) ? "HDD" : "UFD");
	}

	return score;
}
