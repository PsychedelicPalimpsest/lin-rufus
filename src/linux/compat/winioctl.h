/* Linux compat stub for winioctl.h */
#pragma once
#ifndef _WIN32
#include "windows.h"

/* DEVICE_TYPE */
typedef DWORD DEVICE_TYPE;
#define FILE_DEVICE_BEEP                0x00000001
#define FILE_DEVICE_CD_ROM              0x00000002
#define FILE_DEVICE_CD_ROM_FILE_SYSTEM  0x00000003
#define FILE_DEVICE_CONTROLLER          0x00000004
#define FILE_DEVICE_DATALINK            0x00000005
#define FILE_DEVICE_DFS                 0x00000006
#define FILE_DEVICE_DISK                0x00000007
#define FILE_DEVICE_DISK_FILE_SYSTEM    0x00000008
#define FILE_DEVICE_FILE_SYSTEM         0x00000009
#define FILE_DEVICE_INPORT_PORT         0x0000000a
#define FILE_DEVICE_KEYBOARD            0x0000000b
#define FILE_DEVICE_MAILSLOT            0x0000000c
#define FILE_DEVICE_MIDI_IN             0x0000000d
#define FILE_DEVICE_MIDI_OUT            0x0000000e
#define FILE_DEVICE_MOUSE               0x0000000f
#define FILE_DEVICE_MULTI_UNC_PROVIDER  0x00000010
#define FILE_DEVICE_NAMED_PIPE          0x00000011
#define FILE_DEVICE_NETWORK             0x00000012
#define FILE_DEVICE_NETWORK_BROWSER     0x00000013
#define FILE_DEVICE_NETWORK_FILE_SYSTEM 0x00000014
#define FILE_DEVICE_NULL                0x00000015
#define FILE_DEVICE_PARALLEL_PORT       0x00000016
#define FILE_DEVICE_PHYSICAL_NETCARD    0x00000017
#define FILE_DEVICE_PRINTER             0x00000018
#define FILE_DEVICE_SCANNER             0x00000019
#define FILE_DEVICE_SERIAL_MOUSE_PORT   0x0000001a
#define FILE_DEVICE_SERIAL_PORT         0x0000001b
#define FILE_DEVICE_SCREEN              0x0000001c
#define FILE_DEVICE_SOUND               0x0000001d
#define FILE_DEVICE_STREAMS             0x0000001e
#define FILE_DEVICE_TAPE                0x0000001f
#define FILE_DEVICE_TAPE_FILE_SYSTEM    0x00000020
#define FILE_DEVICE_TRANSPORT           0x00000021
#define FILE_DEVICE_UNKNOWN             0x00000022
#define FILE_DEVICE_VIDEO               0x00000023
#define FILE_DEVICE_VIRTUAL_DISK        0x00000024
#define FILE_DEVICE_WAVE_IN             0x00000025
#define FILE_DEVICE_WAVE_OUT            0x00000026
#define FILE_DEVICE_8042_PORT           0x00000027
#define FILE_DEVICE_NETWORK_REDIRECTOR  0x00000028
#define FILE_DEVICE_BATTERY             0x00000029
#define FILE_DEVICE_BUS_EXTENDER        0x0000002a
#define FILE_DEVICE_MODEM               0x0000002b
#define FILE_DEVICE_VDM                 0x0000002c
#define FILE_DEVICE_MASS_STORAGE        0x0000002d
#define FILE_DEVICE_SMB                 0x0000002e
#define FILE_DEVICE_KS                  0x0000002f
#define FILE_DEVICE_CHANGER             0x00000030
#define FILE_DEVICE_SMARTCARD           0x00000031
#define FILE_DEVICE_ACPI                0x00000032
#define FILE_DEVICE_DVD                 0x00000033
#define FILE_DEVICE_FULLSCREEN_VIDEO    0x00000034
#define FILE_DEVICE_DFS_FILE_SYSTEM     0x00000035
#define FILE_DEVICE_DFS_VOLUME          0x00000036
#define FILE_DEVICE_SERENUM             0x00000037
#define FILE_DEVICE_TERMSRV             0x00000038
#define FILE_DEVICE_KSEC                0x00000039
#define FILE_DEVICE_FIPS                0x0000003a
#define FILE_DEVICE_INFINIBAND          0x0000003b
#define FILE_DEVICE_VMBUS               0x0000003e
#define FILE_DEVICE_CRYPT_PROVIDER      0x0000003f
#define FILE_DEVICE_WPD                 0x00000040
#define FILE_DEVICE_BLUETOOTH           0x00000041
#define FILE_DEVICE_MT_COMPOSITE        0x00000042
#define FILE_DEVICE_MT_TRANSPORT        0x00000043
#define FILE_DEVICE_BIOMETRIC           0x00000044
#define FILE_DEVICE_PMI                 0x00000045
#define FILE_DEVICE_EHSTOR              0x00000046
#define FILE_DEVICE_DEVAPI              0x00000047
#define FILE_DEVICE_GPIO                0x00000048
#define FILE_DEVICE_USBEX               0x00000049
#define FILE_DEVICE_CONSOLE             0x00000050
#define FILE_DEVICE_NFP                 0x00000051
#define FILE_DEVICE_SYSENV              0x00000052
#define FILE_DEVICE_VIRTUAL_BLOCK       0x00000053
#define FILE_DEVICE_POINT_OF_SERVICE    0x00000054
#define FILE_DEVICE_STORAGE_REPLICATION 0x00000055
#define FILE_DEVICE_VOLUME              0x00000056

/* IOCTL control codes */
#define CTL_CODE(dev,fn,method,access) (((dev)<<16)|((access)<<14)|((fn)<<2)|(method))
#define METHOD_BUFFERED   0
#define METHOD_IN_DIRECT  1
#define METHOD_OUT_DIRECT 2
#define METHOD_NEITHER    3
#define FILE_ANY_ACCESS   0
#define FILE_READ_ACCESS  1
#define FILE_WRITE_ACCESS 2
#define FILE_DEVICE_DISK  0x00000007
#define FILE_DEVICE_FILE_SYSTEM 0x00000009
#define FILE_DEVICE_VOLUME 0x00000056
#define IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS CTL_CODE(FILE_DEVICE_VOLUME,1,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define FSCTL_GET_NTFS_VOLUME_DATA          CTL_CODE(FILE_DEVICE_FILE_SYSTEM,25,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define FSCTL_GET_RETRIEVAL_POINTERS        CTL_CODE(FILE_DEVICE_FILE_SYSTEM,28,METHOD_NEITHER,FILE_ANY_ACCESS)
#define FSCTL_LOCK_VOLUME                   CTL_CODE(FILE_DEVICE_FILE_SYSTEM,6,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define FSCTL_UNLOCK_VOLUME                 CTL_CODE(FILE_DEVICE_FILE_SYSTEM,7,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define FSCTL_DISMOUNT_VOLUME               CTL_CODE(FILE_DEVICE_FILE_SYSTEM,8,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define FSCTL_IS_VOLUME_MOUNTED             CTL_CODE(FILE_DEVICE_FILE_SYSTEM,10,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_DISK_GET_DRIVE_GEOMETRY       CTL_CODE(FILE_DEVICE_DISK,0,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_DISK_GET_DRIVE_GEOMETRY_EX    CTL_CODE(FILE_DEVICE_DISK,28,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_DISK_GET_PARTITION_INFO_EX    CTL_CODE(FILE_DEVICE_DISK,12,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_DISK_SET_PARTITION_INFO_EX    CTL_CODE(FILE_DEVICE_DISK,13,METHOD_BUFFERED,FILE_READ_ACCESS|FILE_WRITE_ACCESS)
#define IOCTL_DISK_GET_DRIVE_LAYOUT_EX      CTL_CODE(FILE_DEVICE_DISK,14,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_DISK_SET_DRIVE_LAYOUT_EX      CTL_CODE(FILE_DEVICE_DISK,15,METHOD_BUFFERED,FILE_READ_ACCESS|FILE_WRITE_ACCESS)
#define IOCTL_DISK_CREATE_DISK              CTL_CODE(FILE_DEVICE_DISK,16,METHOD_BUFFERED,FILE_READ_ACCESS|FILE_WRITE_ACCESS)
#define IOCTL_STORAGE_QUERY_PROPERTY        CTL_CODE(0x0000002d,0x500,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_STORAGE_GET_DEVICE_NUMBER     CTL_CODE(0x0000002d,0x420,METHOD_BUFFERED,FILE_ANY_ACCESS)

/* NO_ERROR */
#ifndef NO_ERROR
#define NO_ERROR 0L
#endif

/* DISK_EXTENT */
typedef struct _DISK_EXTENT {
    DWORD DiskNumber;
    LARGE_INTEGER StartingOffset, ExtentLength;
} DISK_EXTENT, *PDISK_EXTENT;

/* VOLUME_DISK_EXTENTS */
typedef struct _VOLUME_DISK_EXTENTS {
    DWORD      NumberOfDiskExtents;
    DISK_EXTENT Extents[1];
} VOLUME_DISK_EXTENTS, *PVOLUME_DISK_EXTENTS;

/* RETRIEVAL_POINTERS_BUFFER */
typedef struct _STARTING_VCN_INPUT_BUFFER {
    LARGE_INTEGER StartingVcn;
} STARTING_VCN_INPUT_BUFFER, *PSTARTING_VCN_INPUT_BUFFER;

typedef struct _RETRIEVAL_POINTERS_BUFFER {
    DWORD ExtentCount;
    LARGE_INTEGER StartingVcn;
    struct { LARGE_INTEGER NextVcn, Lcn; } Extents[1];
} RETRIEVAL_POINTERS_BUFFER, *PRETRIEVAL_POINTERS_BUFFER;

/* NTFS_VOLUME_DATA_BUFFER */
typedef struct _NTFS_VOLUME_DATA_BUFFER {
    LARGE_INTEGER VolumeSerialNumber;
    LARGE_INTEGER NumberSectors, TotalClusters, FreeClusters, TotalReserved;
    DWORD         BytesPerSector, BytesPerCluster, BytesPerFileRecordSegment;
    DWORD         ClustersPerFileRecordSegment;
    LARGE_INTEGER MftValidDataLength, MftStartLcn, Mft2StartLcn, MftZoneStart, MftZoneEnd;
} NTFS_VOLUME_DATA_BUFFER, *PNTFS_VOLUME_DATA_BUFFER;

/* DISK_GEOMETRY */
typedef enum { Unknown=0, F5_1Pt2_512, F3_1Pt44_512, F3_2Pt88_512, F3_20Pt8_512, F3_720_512,
    F5_360_512, F5_320_512, F5_320_1024, F5_180_512, F5_160_512, RemovableMedia,
    FixedMedia, F3_120M_512, F3_640_512, F5_640_512, F5_720_512, F3_1Pt2_512,
    F3_1Pt23_1024, F5_1Pt23_1024, F3_128Mb_512, F3_230Mb_512, F8_256_128,
    F3_200Mb_512, F3_240M_512, F3_32M_512 } MEDIA_TYPE;

typedef struct _DISK_GEOMETRY {
    LARGE_INTEGER Cylinders;
    MEDIA_TYPE    MediaType;
    DWORD         TracksPerCylinder, SectorsPerTrack, BytesPerSector;
} DISK_GEOMETRY, *PDISK_GEOMETRY;

typedef struct _DISK_GEOMETRY_EX {
    DISK_GEOMETRY Geometry;
    LARGE_INTEGER DiskSize;
    BYTE          Data[1];
} DISK_GEOMETRY_EX, *PDISK_GEOMETRY_EX;

/* Partition types */
typedef enum { PARTITION_STYLE_MBR, PARTITION_STYLE_GPT, PARTITION_STYLE_RAW } PARTITION_STYLE;
typedef struct _PARTITION_INFORMATION_MBR {
    BYTE  PartitionType;
    BOOLEAN BootIndicator, RecognizedPartition;
    DWORD HiddenSectors;
} PARTITION_INFORMATION_MBR;
typedef struct _PARTITION_INFORMATION_GPT {
    GUID  PartitionType, PartitionId;
    DWORD64 Attributes;
    WCHAR Name[36];
} PARTITION_INFORMATION_GPT;
typedef struct _PARTITION_INFORMATION_EX {
    PARTITION_STYLE PartitionStyle;
    LARGE_INTEGER StartingOffset, PartitionLength;
    DWORD PartitionNumber, RewritePartition, IsServicePartition;
    union { PARTITION_INFORMATION_MBR Mbr; PARTITION_INFORMATION_GPT Gpt; };
} PARTITION_INFORMATION_EX, *PPARTITION_INFORMATION_EX;
typedef struct _DRIVE_LAYOUT_INFORMATION_MBR {
    DWORD Signature, CheckSum;
} DRIVE_LAYOUT_INFORMATION_MBR;
typedef struct _DRIVE_LAYOUT_INFORMATION_GPT {
    GUID  DiskId;
    LARGE_INTEGER StartingUsableOffset, UsableLength;
    DWORD MaxPartitionCount;
} DRIVE_LAYOUT_INFORMATION_GPT;
typedef struct _DRIVE_LAYOUT_INFORMATION_EX {
    DWORD PartitionStyle, PartitionCount;
    union { DRIVE_LAYOUT_INFORMATION_MBR Mbr; DRIVE_LAYOUT_INFORMATION_GPT Gpt; };
    PARTITION_INFORMATION_EX PartitionEntry[1];
} DRIVE_LAYOUT_INFORMATION_EX, *PDRIVE_LAYOUT_INFORMATION_EX;

/* CREATE_DISK */
typedef struct _CREATE_DISK_MBR { DWORD Signature; } CREATE_DISK_MBR;
typedef struct _CREATE_DISK_GPT { GUID  DiskId; DWORD MaxPartitionCount; } CREATE_DISK_GPT;
typedef struct _CREATE_DISK {
    PARTITION_STYLE PartitionStyle;
    union { CREATE_DISK_MBR Mbr; CREATE_DISK_GPT Gpt; };
} CREATE_DISK, *PCREATE_DISK;

/* Storage query */
typedef enum { StorageDeviceProperty = 0, StorageAdapterProperty, StorageDeviceIdProperty,
    StorageDeviceUniqueIdProperty, StorageDeviceWriteCacheProperty, StorageMiniportProperty,
    StorageAccessAlignmentProperty, StorageDeviceSeekPenaltyProperty, StorageDeviceTrimProperty,
    StorageDeviceWriteAggregationProperty, StorageDeviceDeviceTelemetryProperty,
    StorageDeviceLBProvisioningProperty, StorageDeviceZeroCostInformationProperty,
    StorageDeviceCopyOffloadProperty, StorageDeviceResiliencyProperty,
    StorageDevicePhysicalTopologyProperty, StorageDeviceAttributesProperty,
    StorageDeviceManagementStatus, StorageAdapterSerialNumberProperty,
    StorageDeviceLocationProperty, StorageDeviceNumaProperty, StorageDeviceZoneProperty,
    StorageDeviceUnsafeShutdownCount, StorageDeviceEnduranceProperty,
    StorageDeviceSMARTBufferSizeProperty, StorageAdapterRaidGroupProperty,
    StorageDeviceFirmwareProperty, StorageAdapterTemperatureProperty,
    StorageDeviceTemperatureProperty, StorageAdapterPhysicalTopologyProperty } STORAGE_PROPERTY_ID;

typedef enum { PropertyStandardQuery = 0, PropertyExistsQuery, PropertyMaskQuery,
    PropertyQueryMaxDefined } STORAGE_QUERY_TYPE;

typedef struct _STORAGE_PROPERTY_QUERY {
    STORAGE_PROPERTY_ID PropertyId;
    STORAGE_QUERY_TYPE  QueryType;
    BYTE AdditionalParameters[1];
} STORAGE_PROPERTY_QUERY, *PSTORAGE_PROPERTY_QUERY;

typedef struct _STORAGE_DESCRIPTOR_HEADER {
    DWORD Version, Size;
} STORAGE_DESCRIPTOR_HEADER, *PSTORAGE_DESCRIPTOR_HEADER;

typedef struct _STORAGE_DEVICE_DESCRIPTOR {
    DWORD Version, Size;
    BYTE  DeviceType, DeviceTypeModifier;
    BOOLEAN RemovableMedia, CommandQueueing;
    DWORD VendorIdOffset, ProductIdOffset, ProductRevisionOffset, SerialNumberOffset;
    DWORD BusType;
    DWORD RawPropertiesLength;
    BYTE  RawDeviceProperties[1];
} STORAGE_DEVICE_DESCRIPTOR, *PSTORAGE_DEVICE_DESCRIPTOR;

typedef struct _STORAGE_DEVICE_NUMBER {
    DWORD DeviceType, DeviceNumber, PartitionNumber;
} STORAGE_DEVICE_NUMBER, *PSTORAGE_DEVICE_NUMBER;

#endif /* !_WIN32 */
