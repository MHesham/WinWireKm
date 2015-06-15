/*++

Module Name:

    driver.h

Abstract:

    This file contains the driver definitions.

Environment:

    Kernel-mode Driver Framework

--*/

#define INITGUID

#include <ntddk.h>
#include <wdf.h>

#include "Trace.h"
#include "WinWireKm.h"
EXTERN_C_START

//
// WDFDRIVER Events
//

#define WINWIRE_POOL_TAG 'PMDD'

//
// Represents a memory resource that can be mapped into one or more
// usermode processes. Stores the physical address, kernel mode virtual
// address, and list of processes that the resource is mapped into.
//
typedef struct _WINWIRE_KERNEL_MEMORY_MAPPING
{
	//
	// List entry in list of kernel mappings structures
	//
	LIST_ENTRY Entry;

	//
	// Physical address of memory address received from an MMAP IOCTL
	//
	PVOID PhysicalAddress;

	//
	// Base virtual address in system memory for the device registers
	// that was returned by MmMapIoSpace
	//
	PVOID KernelAddress;

	//
	// Length of the memory descriptor
	//
	UINT32 Length;

	//
	// Mdl used to set up mapping
	//
	PMDL Mdl;

} WINWIRE_KERNEL_MEMORY_MAPPING, *PWINWIRE_KERNEL_MEMORY_MAPPING;

typedef struct _WINWIREKM_USER_MEMORY_MAPPING
{
	//
	// List entry in list of memory mappings structures
	//
	LIST_ENTRY Entry;

	//
	// This is the usermode address that the memory resource 
	// is mapped to.
	//
	PVOID UserAddress;

	//
	// Length of the memory region
	//
	UINT32 Length;

	//
	// Pointer back to the kernel and physcial memory mapping
	//
	WINWIRE_KERNEL_MEMORY_MAPPING *KernelMapping;

} WINWIREKM_USER_MEMORY_MAPPING, *PWINWIREKM_USER_MEMORY_MAPPING;
//
// Stores the per-process usermode virtual address. The refcount keeps track
// of how many open file handles within the process refer to the memory
// resource. When the refcount goes to zero, the memory is unmapped from
// the usermode process and the structure is freed.
//
typedef struct _WINWIREKM_PROCESS_DATA
{
	//
	// List entry in list of per-process structures
	//
	LIST_ENTRY Entry;

	//
	// The process that this structure stores information for
	//
	PEPROCESS Process;

	//
	// List of memory mappings created per process
	//
	LIST_ENTRY UserMemoryMappingsHead;

	//
	// Number of references to the memory mappings
	//
	LONG RefCount;

} WINWIREKM_PROCESS_DATA, *PWINWIREKM_PROCESS_DATA;

//
// The device context stores all of the memory resources
// that were passed to the driver in OnPrepareHardware
//
typedef struct _DEVICE_CONTEXT
{
	//
	// List of in effect kernel memory mappings
	//
	LIST_ENTRY KernelMemoryMappingsHead;

	//
	// List of processes that has amappings
	//
	LIST_ENTRY ProcessDataHead;

} DEVICE_CONTEXT, *PDEVICE_CONTEXT;


//
// The file context points back to the per-process data structure
// for the memory resource. The RefCount member of the per-process
// structure keeps track of how many files within a process 
// refer to the memory resource.
//
typedef struct _FILE_CONTEXT
{
	PWINWIREKM_PROCESS_DATA ProcessData;

} FILE_CONTEXT, *PFILE_CONTEXT;

//
// This macro will generate an inline function called DeviceGetContext
// which will be used to get a pointer to the device context memory
// in a type safe manner.
//
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, DeviceGetContext)
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(FILE_CONTEXT, FileGetContext)


DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD OnDriverUnload;
EVT_WDF_DRIVER_DEVICE_ADD OnDeviceAdd;
_IRQL_requires_max_(PASSIVE_LEVEL)
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL OnDeviceIoControl;
EVT_WDF_DEVICE_FILE_CREATE OnFileCreate;
EVT_WDF_FILE_CLEANUP OnFileCleanup;
EVT_WDF_DEVICE_CONTEXT_CLEANUP OnDeviceContextCleanup;

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
BuildKernelMapping(
	_In_ PVOID PhysicalAddress,
	_In_ PVOID KernelAddress,
	_In_ ULONG Length,
	_Out_ PWINWIRE_KERNEL_MEMORY_MAPPING KernelMapping
	);

_IRQL_requires_max_(APC_LEVEL)
PWINWIREKM_PROCESS_DATA
FindProcessData(
	_In_ PEPROCESS Process,
	_In_ PLIST_ENTRY ProcessDataHead
	);

_IRQL_requires_max_(APC_LEVEL)
PWINWIRE_KERNEL_MEMORY_MAPPING
FindKernelMappingByPhysicalAddress(
	_In_ PVOID Address,
	_In_ PLIST_ENTRY KernelMappingsHead
	);

_IRQL_requires_max_(APC_LEVEL)
PWINWIREKM_USER_MEMORY_MAPPING
FindUserMappingByPhysicalAddress(
	_In_ PVOID Address,
	_In_ PLIST_ENTRY UserMappingsHead
	);

_IRQL_requires_max_(APC_LEVEL)
VOID
FreeUserMappingsList(
	_In_ PLIST_ENTRY UserMappingsHead
	);

NTSTATUS
MMap(
	_In_ PDEVICE_CONTEXT deviceCtx,
	_In_ PFILE_CONTEXT fileCtx,
	_In_ PWINWIREKM_MMAP_INPUT_BUFFER In,
	_Out_ PWINWIREKM_MMAP_OUTPUT_BUFFER Out
	);

EXTERN_C_END
