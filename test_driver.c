#include <ntddk.h>

NTSTATUS DriverDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG_PTR inputAddress = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG_PTR physAddr;
    
    physAddr = *(PULONG_PTR)Irp->UserBuffer;
    
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS MmioReadWord(PVOID param_1)
{
    ULONG value;
    PVOID mapped;

    mapped = MmMapIoSpace(param_1, 4, MmNonCached);
    if (mapped)
    {
        value = *(PULONG)mapped;
        MmUnmapIoSpace(mapped, 4);
    }
    
    return value;
}

NTSTATUS SafeMmioRead(PVOID param_1)
{
    ULONG value;
    PVOID mapped;
    
    if (param_1 == NULL)
        return STATUS_INVALID_PARAMETER;
    
    if ((ULONG_PTR)param_1 > 0xFFFFFFFF)
        return STATUS_INVALID_PARAMETER;
    
    mapped = MmMapIoSpace(param_1, 4, MmNonCached);
    if (mapped)
    {
        value = *(PULONG)mapped;
        MmUnmapIoSpace(mapped, 4);
    }
    
    return value;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;
    
    return STATUS_SUCCESS;
}