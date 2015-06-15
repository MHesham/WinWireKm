/*
Copyright 2015 Muhamad Lotfy

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


#include "Driver.h"
#include "Driver.tmh"

#pragma code_seg(push, "INIT")

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath
	)
{
	NTSTATUS status;
	WDF_DRIVER_CONFIG config;
	WDF_OBJECT_ATTRIBUTES attributes;

	//
	// Initialize WPP Tracing
	//
	WPP_INIT_TRACING(DriverObject, RegistryPath);

	TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

	//
	// Register a cleanup callback so that we can call WPP_CLEANUP when
	// the framework driver object is deleted during driver unload.
	//
	WDF_OBJECT_ATTRIBUTES_INIT(&attributes);

	WDF_DRIVER_CONFIG_INIT(&config, OnDeviceAdd);
	config.EvtDriverUnload = OnDriverUnload;

	status = WdfDriverCreate(
		DriverObject,
		RegistryPath,
		&attributes,
		&config,
		WDF_NO_HANDLE);

	if (!NT_SUCCESS(status))
	{
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WdfDriverCreate failed %!STATUS!", status);
		goto end;
	}

end:

	TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");

	if (!NT_SUCCESS(status))
	{
		WPP_CLEANUP(DriverObject);
	}

	return status;
}

#pragma code_seg(pop) // INIT

#pragma code_seg(push, "PAGE")

VOID
OnDriverUnload(
	_In_ WDFDRIVER Driver
	)
{
	PDRIVER_OBJECT driverObject;

	PAGED_CODE();

	TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC!: Driver unloaded");

	driverObject = WdfDriverWdmGetDriverObject(Driver);
	WPP_CLEANUP(driverObject);
}

_Use_decl_annotations_
NTSTATUS
OnDeviceAdd(
	_In_    WDFDRIVER       Driver,
	_Inout_ PWDFDEVICE_INIT DeviceInit
	)
{
	NTSTATUS status;
	WDF_FILEOBJECT_CONFIG fileConfig;
	WDF_OBJECT_ATTRIBUTES   deviceAttributes;
	PDEVICE_CONTEXT deviceContext;
	WDFDEVICE device;
	WDF_IO_QUEUE_CONFIG ioqConfig;
	WDF_OBJECT_ATTRIBUTES ioqAttributes;
	WDFQUEUE queue;
	WDF_OBJECT_ATTRIBUTES fileAttributes;

	UNREFERENCED_PARAMETER(Driver);

	PAGED_CODE();

	DECLARE_CONST_UNICODE_STRING(dosDeviceName, WINWIREKM_SYMBOLIC_LINK_NAME);

	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);

	//
	// Use device level synchronization because we want file creation and
	// cleanup to execute serially. IOCTL's can execute in parallel.
	//
	deviceAttributes.SynchronizationScope = WdfSynchronizationScopeDevice;
	deviceAttributes.ExecutionLevel = WdfExecutionLevelPassive;

	deviceAttributes.EvtCleanupCallback = OnDeviceContextCleanup;

	//
	// Initialize file object handling
	//
	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&fileAttributes, FILE_CONTEXT);

	WDF_FILEOBJECT_CONFIG_INIT(
		&fileConfig,
		OnFileCreate,
		WDF_NO_EVENT_CALLBACK,      // OnFileClose
		OnFileCleanup);

	WdfDeviceInitSetFileObjectConfig(DeviceInit, &fileConfig, &fileAttributes);

	status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);

	if (!NT_SUCCESS(status))
	{
		TraceEvents(
			TRACE_LEVEL_ERROR,
			TRACE_DEVICE,
			"WdfDdeviceCreate failed %!STATUS!",
			status);

		goto end;
	}

	//
	// Initialize the device context
	//
	deviceContext = DeviceGetContext(device);
	RtlZeroMemory(deviceContext, sizeof(*deviceContext));
	InitializeListHead(&deviceContext->KernelMemoryMappingsHead);
	InitializeListHead(&deviceContext->ProcessDataHead);

	//
	// Set up an queue to handle DeviceIoControl requests
	//
	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
		&ioqConfig,
		WdfIoQueueDispatchParallel);

	ioqConfig.EvtIoDeviceControl = OnDeviceIoControl;

	WDF_OBJECT_ATTRIBUTES_INIT(&ioqAttributes);
	ioqAttributes.ExecutionLevel = WdfExecutionLevelPassive;
	ioqAttributes.SynchronizationScope = WdfSynchronizationScopeNone;
	status = WdfIoQueueCreate(
		device,
		&ioqConfig,
		&ioqAttributes,
		&queue);

	if (!NT_SUCCESS(status))
	{
		TraceEvents(
			TRACE_LEVEL_ERROR,
			TRACE_DEVICE,
			"WdfIoQueueCreate failed %!STATUS!",
			status);

		goto end;
	}

	status = WdfDeviceCreateSymbolicLink(device, &dosDeviceName);

	if (!NT_SUCCESS(status))
	{
		TraceEvents(
			TRACE_LEVEL_ERROR,
			TRACE_DEVICE,
			"WdfDeviceCreateSymbolicLink failed %!STATUS!",
			status);

		goto end;
	}

end:

	return status;
}

_Use_decl_annotations_
NTSTATUS
BuildKernelMapping(
	PVOID PhysicalAddress,
	PVOID KernelAddress,
	ULONG Length,
	PWINWIRE_KERNEL_MEMORY_MAPPING KernelMapping
	)
{
	NTSTATUS status;
	PHYSICAL_ADDRESS MmPhysicalAddress;

	PAGED_CODE();

	if (KernelAddress == NULL)
	{
		MmPhysicalAddress.QuadPart = (LONGLONG)PhysicalAddress;

		KernelMapping->KernelAddress = MmMapIoSpaceEx(
			MmPhysicalAddress,
			(SIZE_T)Length,
			PAGE_READWRITE | PAGE_NOCACHE);

		if (KernelMapping->KernelAddress == NULL)
		{
			TraceEvents(
				TRACE_LEVEL_ERROR,
				TRACE_DEVICE,
				"Failed to map physical memory to virtual address");

			status = STATUS_UNSUCCESSFUL;
			goto end;
		}
	}
	else
	{
		KernelMapping->KernelAddress = KernelAddress;
	}

	KernelMapping->Length = Length;
	KernelMapping->PhysicalAddress = PhysicalAddress;

	// Prepare the MDL describing the memory region
	KernelMapping->Mdl = IoAllocateMdl(
		KernelMapping->KernelAddress,
		KernelMapping->Length,
		FALSE,
		FALSE,
		NULL);

	NT_ASSERT(KernelMapping->Mdl != NULL);

	MmBuildMdlForNonPagedPool(KernelMapping->Mdl);

	status = STATUS_SUCCESS;

end:
	return status;
}


_Use_decl_annotations_
PWINWIREKM_PROCESS_DATA
FindProcessData(
	PEPROCESS Process,
	PLIST_ENTRY ProcessDataHead
	)
{
	PLIST_ENTRY entry;

	PAGED_CODE();

	for (entry = ProcessDataHead->Flink;
	entry != ProcessDataHead;
		entry = entry->Flink)
	{
		PWINWIREKM_PROCESS_DATA data =
			(PWINWIREKM_PROCESS_DATA)CONTAINING_RECORD(
				entry,
				WINWIREKM_PROCESS_DATA,
				Entry);

		if (data->Process == Process)
		{
			// found item
			return data;
		}
	}

	return NULL;
}

_Use_decl_annotations_
PWINWIRE_KERNEL_MEMORY_MAPPING
FindKernelMappingByPhysicalAddress(
	PVOID Address,
	PLIST_ENTRY KernelMappingsHead
	)
{
	PLIST_ENTRY entry;

	PAGED_CODE();

	for (entry = KernelMappingsHead->Flink;
	entry != KernelMappingsHead;
		entry = entry->Flink)
	{
		PWINWIRE_KERNEL_MEMORY_MAPPING data =
			(PWINWIRE_KERNEL_MEMORY_MAPPING)CONTAINING_RECORD(
				entry,
				WINWIRE_KERNEL_MEMORY_MAPPING,
				Entry);

		if (data->PhysicalAddress == Address)
		{
			// found item
			return data;
		}
	}

	return NULL;
}

_Use_decl_annotations_
PWINWIREKM_USER_MEMORY_MAPPING
FindUserMappingByPhysicalAddress(
	_In_ PVOID Address,
	_In_ PLIST_ENTRY UserMappingsHead
	)
{
	PLIST_ENTRY entry;

	PAGED_CODE();

	for (entry = UserMappingsHead->Flink;
	entry != UserMappingsHead;
		entry = entry->Flink)
	{
		PWINWIREKM_USER_MEMORY_MAPPING data =
			(PWINWIREKM_USER_MEMORY_MAPPING)CONTAINING_RECORD(
				entry,
				WINWIREKM_USER_MEMORY_MAPPING,
				Entry);

		if (data->KernelMapping->PhysicalAddress == Address)
		{
			// found item
			return data;
		}
	}

	return NULL;
}

_Use_decl_annotations_
VOID
OnDeviceIoControl(
	WDFQUEUE FxQueue,
	WDFREQUEST FxRequest,
	size_t OutputBufferLength,
	size_t InputBufferLength,
	ULONG IoControlCode
	)
{
	NTSTATUS status;
	ULONG_PTR lengthReturned = 0;
	PDEVICE_CONTEXT context;
	WDFDEVICE fxDevice;
	PFILE_CONTEXT fileContext;

	UNREFERENCED_PARAMETER(OutputBufferLength);
	UNREFERENCED_PARAMETER(InputBufferLength);

	PAGED_CODE();

	fxDevice = WdfIoQueueGetDevice(FxQueue);
	context = DeviceGetContext(fxDevice);
	fileContext = FileGetContext(WdfRequestGetFileObject(FxRequest));

	switch (IoControlCode)
	{
	case IOCTL_WINWIREKM_MMAP:
	{
		WINWIREKM_MMAP_INPUT_BUFFER *in;

		status = WdfRequestRetrieveInputBuffer(
			FxRequest,
			sizeof(*in),
			(PVOID*)&in,
			NULL);

		if (!NT_SUCCESS(status))
		{
			TraceEvents(
				TRACE_LEVEL_ERROR,
				TRACE_DEVICE,
				"Failed to retrieve input buffer");

			goto end;
		}

		WINWIREKM_MMAP_OUTPUT_BUFFER *out;

		status = WdfRequestRetrieveOutputBuffer(
			FxRequest,
			sizeof(*out),
			(PVOID*)&out,
			NULL);

		if (!NT_SUCCESS(status))
		{
			TraceEvents(
				TRACE_LEVEL_ERROR,
				TRACE_DEVICE,
				"Failed to retrieve output buffer");

			goto end;
		}

		status = MMap(context, fileContext, in, out);

		if (!NT_SUCCESS(status))
		{
			TraceEvents(
				TRACE_LEVEL_ERROR,
				TRACE_DEVICE,
				"MMap failed to map physical memory %!STATUS!",
				status);


			goto end;
		}

		lengthReturned = sizeof(*out);
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_WINWIREKM_ARROW:
	{
		LARGE_INTEGER hitTime = KeQueryPerformanceCounter(NULL);

		WINWIREKM_ARROW_OUTPUT_BUFFER *out;

		status = WdfRequestRetrieveOutputBuffer(
			FxRequest,
			sizeof(*out),
			(PVOID*)&out,
			NULL);

		if (!NT_SUCCESS(status))
		{
			TraceEvents(
				TRACE_LEVEL_ERROR,
				TRACE_DEVICE,
				"Failed to retrieve output buffer");

			goto end;
		}

		out->HitTime = hitTime;
		lengthReturned = sizeof(*out);
		status = STATUS_SUCCESS;

		out->ThrowBackTime = KeQueryPerformanceCounter(NULL);
		break;
	}
	default:
		// unrecognized IOCTL
		status = STATUS_NOT_SUPPORTED;
		break;
	}

end:

	WdfRequestCompleteWithInformation(FxRequest, status, lengthReturned);
}

_Use_decl_annotations_
VOID
OnFileCreate(
	WDFDEVICE FxDevice,
	WDFREQUEST FxRequest,
	WDFFILEOBJECT FxFile
	)
{
	NTSTATUS status;
	PFILE_CONTEXT fileContext;
	WDF_REQUEST_PARAMETERS params;
	ACCESS_MASK desiredAccess;
	const GENERIC_MAPPING *mapping;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(FxDevice);

	status = STATUS_SUCCESS;

	//
	// Only usermode requests are allowed
	//
	if (WdfRequestGetRequestorMode(FxRequest) != UserMode)
	{
		TraceEvents(
			TRACE_LEVEL_ERROR,
			TRACE_DEVICE,
			"WINWIREKM can only be opened from usermode");

		status = STATUS_INVALID_DEVICE_REQUEST;
		goto end;
	}

	fileContext = FileGetContext(FxFile);

	//
	// User must specify both GENERIC_READ and GENERIC_WRITE access
	//
	WDF_REQUEST_PARAMETERS_INIT(&params);
	WdfRequestGetParameters(FxRequest, &params);

	desiredAccess =
		params.Parameters.Create.SecurityContext->DesiredAccess;

	mapping = IoGetFileObjectGenericMapping();

	if (((desiredAccess & mapping->GenericRead) != mapping->GenericRead) ||
		((desiredAccess & mapping->GenericWrite) != mapping->GenericWrite))
	{
		TraceEvents(
			TRACE_LEVEL_ERROR,
			TRACE_DEVICE,
			"WinWireKm resources must be opened with both "
			"GENERIC_READ and GENERIC_WRITE access");

		status = STATUS_INVALID_PARAMETER;
		goto end;
	}


	fileContext->ProcessData = NULL;

end:

	WdfRequestComplete(FxRequest, status);
}

_Use_decl_annotations_
VOID
FreeUserMappingsList(
	_In_ PLIST_ENTRY UserMappingsHead
	)
{
	PLIST_ENTRY userEntry;

	for (userEntry = UserMappingsHead->Flink;
	userEntry != UserMappingsHead;)
	{
		PWINWIREKM_USER_MEMORY_MAPPING userMapping =
			CONTAINING_RECORD(
				userEntry,
				WINWIREKM_USER_MEMORY_MAPPING,
				Entry);

		NT_ASSERT(userMapping != NULL);

		MmUnmapLockedPages(
			userMapping->UserAddress,
			userMapping->KernelMapping->Mdl);

		// Advance the current pointer forward first before deleting
		// the node data
		userEntry = userEntry->Flink;
		// Remove node from the list and delete it from memory
		RemoveEntryList(&userMapping->Entry);
		ExFreePoolWithTag(userMapping, WINWIRE_POOL_TAG);
	}
}

_Use_decl_annotations_
VOID
OnFileCleanup(
	WDFFILEOBJECT FxFile
	)
{
	PFILE_CONTEXT fileContext;

	PAGED_CODE();

	fileContext = FileGetContext(FxFile);

	//
	// If the file owner has not created any memory mappings before, then it has
	// not made any references or contributed to the process mapping history
	// fast return since there is side effect caused by this file handle creation
	//
	if (fileContext->ProcessData == NULL)
		return;

	NT_ASSERT(fileContext->ProcessData->RefCount > 0);

	//
	// Decrement process data refcount. If refcount goes to zero, unmap memory 
	// and deallocate per-process structure
	//
	if (InterlockedDecrement(&fileContext->ProcessData->RefCount) == 0)
	{
		//
		// Unmap all Usermode mapped memory to this particular process
		//
		FreeUserMappingsList(&fileContext->ProcessData->UserMemoryMappingsHead);

		// Remove process data from the list maintained by the device context
		RemoveEntryList(&fileContext->ProcessData->Entry);

		ExFreePoolWithTag(fileContext->ProcessData, WINWIRE_POOL_TAG);

		fileContext->ProcessData = NULL;
	}
}

_Use_decl_annotations_
VOID
OnDeviceContextCleanup(
	_In_ WDFOBJECT FxDevice
	)
{
	PDEVICE_CONTEXT deviceContext;

	deviceContext = DeviceGetContext(FxDevice);

	PLIST_ENTRY entry;

	//
	// Undo all kernel mappings and free the mappings list
	//
	for (entry = deviceContext->KernelMemoryMappingsHead.Flink;
	entry != &deviceContext->KernelMemoryMappingsHead;)
	{
		PWINWIRE_KERNEL_MEMORY_MAPPING data =
			(PWINWIRE_KERNEL_MEMORY_MAPPING)CONTAINING_RECORD(
				entry,
				WINWIRE_KERNEL_MEMORY_MAPPING,
				Entry);
		IoFreeMdl(data->Mdl);
		MmUnmapIoSpace(data->KernelAddress, data->Length);

		// Advance the current pointer forward first before deleting
		// the node data
		entry = entry->Flink;

		// We don't need to remove entry from the list, since the node
		// is going to be destroyed anyway, just delete the node
		ExFreePoolWithTag(data, WINWIRE_POOL_TAG);
	}

	//
	// Delete the processes data
	//
	PLIST_ENTRY procEntry;

	for (procEntry = deviceContext->ProcessDataHead.Flink;
	procEntry != &deviceContext->ProcessDataHead;)
	{
		PWINWIREKM_PROCESS_DATA procData =
			CONTAINING_RECORD(
				entry,
				WINWIREKM_PROCESS_DATA,
				Entry);

		// Advance the current pointer forward first before deleting
		// the node data
		procEntry = procEntry->Flink;

		// We don't need to remove entry from the list, since the node
		// is going to be destroyed anyway, just delete the node
		ExFreePoolWithTag(procData, WINWIRE_POOL_TAG);
	}

	RtlZeroMemory(deviceContext, sizeof(*deviceContext));
}


_Use_decl_annotations_
NTSTATUS
MMap(
	PDEVICE_CONTEXT deviceCtx,
	PFILE_CONTEXT fileCtx,
	PWINWIREKM_MMAP_INPUT_BUFFER In,
	PWINWIREKM_MMAP_OUTPUT_BUFFER Out
	)
{
	NTSTATUS status;
	PVOID physicalAddress = In->PhysicalAddress;
	PVOID kernelAddress = NULL;

	if (physicalAddress == NULL)
	{
		PHYSICAL_ADDRESS lowAddress = { 0, 0 };
		PHYSICAL_ADDRESS highAddress = { 0, 0 };
		PHYSICAL_ADDRESS boundaryAddress = { 0, 0 };
		highAddress.LowPart = MAXULONG;

		if (In->Length & (PAGE_SIZE - 1))
		{
			TraceEvents(
				TRACE_LEVEL_ERROR,
				TRACE_DEVICE,
				"Memory block size should be page aligned");

			status = STATUS_INVALID_PARAMETER;
			goto end;
		}

		kernelAddress = MmAllocateContiguousMemorySpecifyCache(
			In->Length,
			lowAddress,
			highAddress,
			boundaryAddress,
			MmNonCached);

		if (kernelAddress == NULL)
		{
			TraceEvents(
				TRACE_LEVEL_ERROR,
				TRACE_DEVICE,
				"ExAllocatePoolWithTag failed!");

			status = STATUS_UNSUCCESSFUL;
			goto end;
		}

		RtlZeroMemory(kernelAddress, In->Length);

		PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(kernelAddress);
		NT_ASSERT(pa.HighPart == 0);
		physicalAddress = (PVOID)pa.LowPart;
	}

	PWINWIRE_KERNEL_MEMORY_MAPPING kernelMapping =
		FindKernelMappingByPhysicalAddress(physicalAddress, &deviceCtx->KernelMemoryMappingsHead);
	// 
	// If physical address has never been mapped before, create a mapping for it
	//
	if (kernelMapping == NULL)
	{
		kernelMapping = (PWINWIRE_KERNEL_MEMORY_MAPPING)ExAllocatePoolWithTag(
			PagedPool,
			sizeof(WINWIRE_KERNEL_MEMORY_MAPPING),
			WINWIRE_POOL_TAG);

		if (kernelMapping == NULL)
		{
			TraceEvents(
				TRACE_LEVEL_ERROR,
				TRACE_DEVICE,
				"ExAllocatePoolWithTag failed!");

			status = STATUS_INSUFFICIENT_RESOURCES;
			goto end;
		}

		status = BuildKernelMapping(physicalAddress, kernelAddress, In->Length, kernelMapping);

		if (!NT_SUCCESS(status))
		{
			TraceEvents(
				TRACE_LEVEL_ERROR,
				TRACE_DEVICE,
				"Failed to map resource into kernel space %!STATUS!",
				status);

			status = STATUS_UNSUCCESSFUL;
			goto end;
		}

		// Add kernel mapping entry to the mappings list
		InsertHeadList(&deviceCtx->KernelMemoryMappingsHead, &kernelMapping->Entry);
	}

	//
	// Has this memory already been mapped into this process?
	// Find the per-process data structure corresponding to the 
	// current process
	//
	PEPROCESS currentProcess = PsGetCurrentProcess();

	PWINWIREKM_PROCESS_DATA perProcessData = FindProcessData(currentProcess, &deviceCtx->ProcessDataHead);

	//
	// If this process has not mapped any memory before, then create a record for it
	// to be used by subsequent IOCTLs
	//
	if (perProcessData == NULL)
	{
		perProcessData = (PWINWIREKM_PROCESS_DATA)ExAllocatePoolWithTag(
			PagedPool,
			sizeof(WINWIREKM_PROCESS_DATA),
			WINWIRE_POOL_TAG);

		if (perProcessData == NULL)
		{
			TraceEvents(
				TRACE_LEVEL_ERROR,
				TRACE_DEVICE,
				"ExAllocatePoolWithTag failed!");

			status = STATUS_INSUFFICIENT_RESOURCES;
			goto end;
		}

		perProcessData->Process = currentProcess;
		// This is the first ref
		perProcessData->RefCount = 1;
		// Initialize empty user memory mappings list
		InitializeListHead(&perProcessData->UserMemoryMappingsHead);

		// Add process entry to the process data list
		InsertHeadList(&deviceCtx->ProcessDataHead, &perProcessData->Entry);

		fileCtx->ProcessData = perProcessData;
	}

	NT_ASSERT(perProcessData != NULL);

	// If there is already a record for this process but the file context has no
	// process data assigned, this means that this is not the first handle to be
	// opened within the same process, just increment ref count
	if (fileCtx->ProcessData == NULL)
	{
		//
		// Increment refcount of process mapping and store a pointer
		// to the per-process structure in the file context
		//
		fileCtx->ProcessData = perProcessData;
		InterlockedIncrement(&fileCtx->ProcessData->RefCount);
	}

	PWINWIREKM_USER_MEMORY_MAPPING userMapping =
		FindUserMappingByPhysicalAddress(physicalAddress, &fileCtx->ProcessData->UserMemoryMappingsHead);

	//
	// If this process has not mapped that address before, map it to the process usermode virutal address space
	//
	if (userMapping == NULL)
	{
		PVOID userAddress;

		//
		// MmMapLockedPagesSpecifyCache must be executed in the 
		// context of the calling process and must be called at IRQL <= APC_LEVEL
		//
		NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

		__try
		{
			userAddress = MmMapLockedPagesSpecifyCache(
				kernelMapping->Mdl,
				UserMode,
				MmNonCached,
				NULL,
				FALSE,
				NormalPagePriority);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			TraceEvents(
				TRACE_LEVEL_ERROR,
				TRACE_DEVICE,
				"MmMapLockedPagesSpecifyCache failed");

			status = STATUS_UNSUCCESSFUL;
			goto end;
		}

		NT_ASSERT(userAddress != NULL);

		userMapping = (PWINWIREKM_USER_MEMORY_MAPPING)ExAllocatePoolWithTag(
			PagedPool,
			sizeof(WINWIREKM_USER_MEMORY_MAPPING),
			WINWIRE_POOL_TAG);

		if (userMapping == NULL)
		{
			TraceEvents(
				TRACE_LEVEL_ERROR,
				TRACE_DEVICE,
				"ExAllocatePoolWithTag failed!");

			MmUnmapLockedPages(userAddress, kernelMapping->Mdl);

			status = STATUS_INSUFFICIENT_RESOURCES;
			goto end;
		}

		userMapping->KernelMapping = kernelMapping;
		userMapping->Length = kernelMapping->Length;
		userMapping->UserAddress = userAddress;

		InsertHeadList(&fileCtx->ProcessData->UserMemoryMappingsHead, &userMapping->Entry);
	}

	Out->PhysicalAddress = physicalAddress;
	Out->UserAddress = userMapping->UserAddress;
	Out->Length = userMapping->Length;
	status = STATUS_SUCCESS;

end:
	return status;
}

#pragma code_seg(pop) // PAGE