#include <ntddk.h>

// 定义设备对象名称, 符号链接名称
#define DEV_NAME L"\\device\\drv1"
#define LINK_NAME L"\\dosdevices\\drv1"

#define IOCTRL_BASE 0x8000
#define MYIOCTRL_CODE(i) CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTRL_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CTL_HELLO MYIOCTRL_CODE(0)
#define CTL_PRINT MYIOCTRL_CODE(1)
#define CTL_BYE MYIOCTRL_CODE(2)

NTSTATUS DispatchCommon(PDEVICE_OBJECT pDevObj, PIRP pIrp) {
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


VOID DriverUnload(PDRIVER_OBJECT pDrvObj) {
    // 删除链接, 设备对象
    UNICODE_STRING uLinkName = {0};
    RtlInitUnicodeString(&uLinkName, LINK_NAME);
    IoDeleteSymbolicLink(&uLinkName);

    IoDeleteDevice(pDrvObj->DeviceObject);
    DbgPrint("卸载驱动成功!\n");
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp) {
    UNREFERENCED_PARAMETER(pDevObj);

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DispatchRead(PDEVICE_OBJECT pDevObj, PIRP pIrp) {
    PVOID pReadBuf = NULL;
    ULONG uReadLen = 0;
    PIO_STACK_LOCATION pStack = NULL;

    // 获取缓存
    pReadBuf = pIrp->AssociatedIrp.SystemBuffer;
    pStack = IoGetCurrentIrpStackLocation(pIrp);
    uReadLen = pStack->Parameters.Read.Length;

    WCHAR *h = L"Hello";
    ULONG hLen = wcslen(h) + 1 * sizeof(WCHAR);
    ULONG uMin = uReadLen < hLen ? uReadLen : hLen;

    RtlCopyMemory(pReadBuf, h, uMin);

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = uMin;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DispatchWrite(PDEVICE_OBJECT pDevObj, PIRP pIrp) {
    PVOID pWriteBuf = NULL;
    ULONG uWriteLen = 0;
    PIO_STACK_LOCATION pStack = NULL;
    PVOID pBuf = NULL;

    pWriteBuf = pIrp->AssociatedIrp.SystemBuffer;
    pStack = IoGetCurrentIrpStackLocation(pIrp);
    uWriteLen = pStack->Parameters.Write.Length;

    // 分配缓存
    pBuf = ExAllocatePoolWithTag(PagedPool, uWriteLen, 'TSET');
    if (pBuf == NULL) {
        pIrp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        pIrp->IoStatus.Information = 0;
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 清零
    memset(pBuf, 0, uWriteLen);
    
    // 拷贝
    RtlCopyMemory(pBuf, pWriteBuf, uWriteLen);

    ExFreePool(pBuf);
    pBuf = NULL;

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = uWriteLen;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DispatchIoControl(PDEVICE_OBJECT pDevObj, PIRP pIrp) {
    ULONG uIoCtrlCode = 0;
    PVOID pInputBuf = NULL;
    PVOID pOutputBuf = NULL;
    ULONG uInputlen = 0;
    ULONG uOutputlen = 0;
    PIO_STACK_LOCATION pStack = NULL;

    pInputBuf = pOutputBuf = pIrp->AssociatedIrp.SystemBuffer;
    pStack = IoGetCurrentIrpStackLocation(pIrp);
    uInputlen = pStack->Parameters.DeviceIoControl.InputBufferLength;
    uOutputlen = pStack->Parameters.DeviceIoControl.OutputBufferLength;
    uIoCtrlCode = pStack->Parameters.DeviceIoControl.IoControlCode;

    switch (uIoCtrlCode) {
        case CTL_HELLO:
            DbgPrint("Hello in ioCtrl\n");
            break;
        case CTL_PRINT:
            DbgPrint("Print in ioCtrl\n");
            break;
        case CTL_BYE:
            DbgPrint("Bye in ioCtrl\n");
            break;
        default:
            DbgPrint("Unknown ioCtrlCode\n");
            break;
    }

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DispatchClean(PDEVICE_OBJECT pDevObj, PIRP pIrp) {
    UNREFERENCED_PARAMETER(pDevObj);

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp) {
    UNREFERENCED_PARAMETER(pDevObj);

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING32 pRegPath) {
    DbgPrint("加载驱动...");

    NTSTATUS ntStatus = 0;
    PDEVICE_OBJECT pDevObj = NULL;

    // 定义设备对象名称, 符号链接名称
    UNICODE_STRING uDevName = {0};
    UNICODE_STRING uLinkName = {0};
    RtlInitUnicodeString(&uDevName, DEV_NAME);
    RtlInitUnicodeString(&uLinkName, LINK_NAME);
    
    // 创建设备对象, 赋值给pDevObj
    ntStatus = IoCreateDevice(
        pDrvObj,
        0, 
        &uDevName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &pDevObj
    );

    // 判断创建成功与否
    if (!NT_SUCCESS(ntStatus)) {
        DbgPrint("加载驱动失败: %x\n", ntStatus);
        return ntStatus;
    }

    // 通信方式
    pDevObj->Flags |= DO_BUFFERED_IO;

    // 创建符号链接
    ntStatus = IoCreateSymbolicLink(&uLinkName, &uDevName);

    // 判断创建成功与否
    if (!NT_SUCCESS(ntStatus)) {
        // 删除设备对象
        IoDeleteDevice(pDevObj);
        DbgPrint("创建符号链接失败: %x\n", ntStatus);
        return ntStatus;
    }

    // 注册分发函数
    for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
        pDrvObj->MajorFunction[i] = DispatchCommon;
    }
    pDrvObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    pDrvObj->MajorFunction[IRP_MJ_READ] = DispatchRead;
    pDrvObj->MajorFunction[IRP_MJ_WRITE] = DispatchWrite;
    pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;
    pDrvObj->MajorFunction[IRP_MJ_CLEANUP] = DispatchClean;
    pDrvObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    pDrvObj->DriverUnload = DriverUnload;

    DbgPrint("创建成功!\n");
    return STATUS_SUCCESS;
}
