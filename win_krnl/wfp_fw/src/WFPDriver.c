#include "WFPDriver.h"
#include "ExampleCallout.h"


// Global handle to the WFP Base Filter Engine
HANDLE filter_engine_handle = NULL;

UINT64 example_filter_id = 0;

/************************************
			Functions
************************************/
NTSTATUS DriverEntry(IN PDRIVER_OBJECT driver_obj, IN PUNICODE_STRING registry_path)
{
	NTSTATUS status = STATUS_SUCCESS;
	WDFDRIVER driver = { 0 };
	WDFDEVICE device = { 0 };
	DEVICE_OBJECT * wdm_device = NULL;
	FWPM_SESSION wdf_session = { 0 }; // 用于保存FwpmEngineOpen创建的会话的信息
	BOOLEAN in_transaction = FALSE;
	BOOLEAN callout_registered = FALSE;

	status = init_driver_objects(driver_obj, registry_path, &driver, &device);
	if (!NT_SUCCESS(status)) goto Exit;

	// 开启一个对过滤器引擎的事务. 需要在这个事务的上下文中注册filter, callouts, sublayers
	wdf_session.flags = FWPM_SESSION_FLAG_DYNAMIC;	// 在会话结束时自动销毁所有过滤器和callout
	status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &wdf_session, &filter_engine_handle); // 打开一个过滤器引擎的会话
	if (!NT_SUCCESS(status)) goto Exit;
	status = FwpmTransactionBegin(filter_engine_handle, 0); // 在当前会话中开启一个事务
	if (!NT_SUCCESS(status)) goto Exit;
	in_transaction = TRUE;

	// 向过滤器引擎注册一个新的Callout 
	wdm_device = WdfDeviceWdmGetDeviceObject(device);
	status = register_example_callout(wdm_device);
	if (!NT_SUCCESS(status)) goto Exit;
	callout_registered = TRUE;

	// 向过滤器引擎注册一个新的sublayer 
	status = register_example_sublayer();
	if (!NT_SUCCESS(status)) goto Exit;

	// 注册一个使用example callout的过滤器
	status = register_example_filter();
	if (!NT_SUCCESS(status)) goto Exit;
	
	// 向过滤器引擎提交一个新的事务
	status = FwpmTransactionCommit(filter_engine_handle);
	if (!NT_SUCCESS(status)) goto Exit;
	in_transaction = FALSE;

	driver_obj->DriverUnload = DriverUnload;

	// Cleanup and handle any errors
Exit:
	if (!NT_SUCCESS(status)) {
		DbgPrint("WFPDriver example driver failed to load, status 0x%08x", status);
		if (in_transaction == TRUE){
			FwpmTransactionAbort(filter_engine_handle); // 将当前会话中的当前事务中断并回滚
			_Analysis_assume_lock_not_held_(filter_engine_handle); // Potential leak if "FwpmTransactionAbort" fails
		}
		if (callout_registered == TRUE){
			unregister_example_callout();
		}
		status = STATUS_FAILED_DRIVER_ENTRY;
	}
	else{
		DbgPrint("--- WFPDriver example driver loaded successfully ---");
	}

	return status;
}

NTSTATUS init_driver_objects(DRIVER_OBJECT * driver_obj, UNICODE_STRING * registry_path,
	WDFDRIVER * driver, WDFDEVICE * device)
{
	NTSTATUS status = STATUS_SUCCESS;
	WDF_DRIVER_CONFIG config = { 0 };
	UNICODE_STRING device_name = { 0 };
	UNICODE_STRING device_symlink = { 0 };
	PWDFDEVICE_INIT device_init = NULL;

	RtlInitUnicodeString(&device_name, CM_DEVICE_STRING);
	RtlInitUnicodeString(&device_symlink, CM_DOS_DEVICE_STRING);

	// 创建WDFDRIVER
	WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK); // 初始化config, 二参是设置回调函数EvtDriverDeviceAdd
	config.DriverInitFlags = WdfDriverInitNonPnpDriver; // 不支持即插即用
	config.EvtDriverUnload = empty_evt_unload; // 设置回调函数EvtDriverUnload（驱动卸载前调用的）
	status = WdfDriverCreate(driver_obj, registry_path, WDF_NO_OBJECT_ATTRIBUTES, &config, driver); // 返回的句柄放在driver变量
	if (!NT_SUCCESS(status)) goto Exit;

	// 生成一个WDFDEVICE_INIT结构体
	device_init = WdfControlDeviceInitAllocate(*driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);	// 只有管理员和内核态可访问设备 ; SSDL是安全描述符定义语言
	if (!device_init){
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	// 配置device_init，赋予一个名字，以便用户态访问
	WdfDeviceInitSetDeviceType(device_init, FILE_DEVICE_NETWORK);
	WdfDeviceInitSetCharacteristics(device_init, FILE_DEVICE_SECURE_OPEN, FALSE);
	WdfDeviceInitAssignName(device_init, &device_name);
	WdfPdoInitAssignRawDevice(device_init, &GUID_DEVCLASS_NET);
	WdfDeviceInitSetDeviceClass(device_init, &GUID_DEVCLASS_NET);

	// 创建WDFDEVICE
	status = WdfDeviceCreate(&device_init, WDF_NO_OBJECT_ATTRIBUTES, device);
	if (!NT_SUCCESS(status)){
		WdfDeviceInitFree(device_init); // 释放device_init
		goto Exit;
	}

	WdfControlFinishInitializing(*device); // 通知框架, 驱动已经完成指定控制设备对象的初始化

Exit:
	return status;
}

NTSTATUS register_example_callout(DEVICE_OBJECT * wdm_device)
{
	NTSTATUS status = STATUS_SUCCESS;
	FWPS_CALLOUT s_callout = { 0 };
	FWPM_CALLOUT m_callout = { 0 };
	FWPM_DISPLAY_DATA display_data = { 0 };

	if (filter_engine_handle == NULL)
		return STATUS_INVALID_HANDLE;

	display_data.name = EXAMPLE_CALLOUT_NAME;
	display_data.description = EXAMPLE_CALLOUT_DESCRIPTION;

	// 在过滤器引擎上注册新的callout
	s_callout.calloutKey = EXAMPLE_CALLOUT_GUID;
	s_callout.classifyFn = example_classify; // callout处理网络数据时要用到的函数
	s_callout.notifyFn = example_notify; // 过滤器引擎添加或移除过滤器时, 调用该函数向callout驱动通知相关事件
	s_callout.flowDeleteFn = example_flow_delete; // 过滤器引擎在callout处理的数据流即将被终止时, 调用该函数 (只有在这个数据流被关联了上下文(调用FwpsFlowAssociateContext进行关联)的情况下, 该函数会被调用)
	status = FwpsCalloutRegister((void *)wdm_device, &s_callout, &example_callout_id); // 向过滤器引擎注册callout
	if (!NT_SUCCESS(status)){
		DbgPrint("Failed to register callout functions for example callout, status 0x%08x", status);
		goto Exit;
	}

	// 设置FWPM_CALLOUT结构，用于保存/追踪 FWPS_CALLOUT 的状态
	m_callout.calloutKey = EXAMPLE_CALLOUT_GUID;
	m_callout.displayData = display_data; // 保存一些可供人阅读的标注
	m_callout.applicableLayer = FWPM_LAYER_OUTBOUND_TRANSPORT_V4; // 指定可以使用该callout的分层
	m_callout.flags = 0;
	status = FwpmCalloutAdd(filter_engine_handle, &m_callout, NULL, NULL); // 将新的callout对象添加到系统
	if (!NT_SUCCESS(status)){
		DbgPrint("Failed to register example callout, status 0x%08x", status);
	}
	else{
		DbgPrint("Example Callout Registered");
	}

Exit:
	return status;
}

NTSTATUS unregister_example_callout()
{
	return FwpsCalloutUnregisterById(example_callout_id);
}

NTSTATUS register_example_sublayer()
{
	NTSTATUS status = STATUS_SUCCESS;
	FWPM_SUBLAYER sublayer = { 0 };

	sublayer.subLayerKey = EXAMPLE_SUBLAYER_GUID;
	sublayer.displayData.name = EXAMPLE_SUBLAYER_NAME;
	sublayer.displayData.description = EXAMPLE_SUBLAYER_DESCRIPTION;
	sublayer.flags = 0;
	sublayer.weight = 0x0f;
	status = FwpmSubLayerAdd(filter_engine_handle, &sublayer, NULL);
	if (!NT_SUCCESS(status)){
		DbgPrint("Failed to register example sublayer, status 0x%08x", status);
	}
	else{
		DbgPrint("Example sublayer registered");
	}
	return status;
}

NTSTATUS register_example_filter()
{
	NTSTATUS status = STATUS_SUCCESS;
	FWPM_FILTER filter = { 0 };

	filter.displayData.name = EXAMPLE_FILTER_NAME;
	filter.displayData.description = EXAMPLE_FILTER_DESCRIPTION;
	filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;	// 指定分层。跟上面callout所属分层一样
	filter.subLayerKey = EXAMPLE_SUBLAYER_GUID; // 子层GUID, 表明过滤器添加到哪个子层
	filter.weight.type = FWP_UINT8; // type决定FWP_VALUE0联合体中哪个成员被使用
	filter.weight.uint8 = 0xf;		// 该子层的过滤器的权重

	// 指定过滤条件
	filter.numFilterConditions = 0;	// 过滤条件的个数. 为0, 则该过滤器为其所在层的所有流量调用callouut
	FWPM_FILTER_CONDITION conditions[1] = { 0 }; // 过滤条件数组
	conditions[0].fieldKey = FWPM_CONDITION_IP_DESTINATION_ADDRESS; // 网络数据包字段的标识
	conditions[0].matchType = FWP_MATCH_EQUAL; // 匹配的类型. FWP_MATCH_EQUAL就表示fieldKey指定的字段值和conditionValue相等时, 过滤条件成立
	conditions[0].conditionValue.type = FWP_UINT32;
	conditions[0].conditionValue.uint32 = 0x0	;
	filter.filterCondition = conditions;	// 

	// 指定过滤器动作
	filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;	// 在所有过滤器条件为真时，这个过滤器的callout需要做阻止/允许的决策
	filter.action.calloutKey = EXAMPLE_CALLOUT_GUID;

	status = FwpmFilterAdd(filter_engine_handle, &filter, NULL, &(example_filter_id));
	if (status != STATUS_SUCCESS){
		DbgPrint("Failed to register example filter, status 0x%08x", status);
	}
	else{
		DbgPrint("Example filter registered");
	}

	return status;
}

NTSTATUS unregister_example_filter()
{
	return FwpmFilterDeleteById(filter_engine_handle, example_filter_id);
}

VOID DriverUnload(PDRIVER_OBJECT driver_obj)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING symlink = { 0 };
	UNREFERENCED_PARAMETER(driver_obj);

	status = unregister_example_filter(); // 注销过滤器
	if (!NT_SUCCESS(status)) DbgPrint("Failed to unregister filters, status: 0x%08x", status);
	status = unregister_example_callout(); // 注销callout
	if (!NT_SUCCESS(status)) DbgPrint("Failed to unregister callout, status: 0x%08x", status);

	// 关闭WFP过滤器引擎的句柄
	if (filter_engine_handle){
		FwpmEngineClose(filter_engine_handle);
		filter_engine_handle = NULL;
	}

	RtlInitUnicodeString(&symlink, CM_DOS_DEVICE_STRING);
	IoDeleteSymbolicLink(&symlink);

	DbgPrint("--- WFPDriver example driver unloaded ---");
	return;
}

VOID empty_evt_unload(WDFDRIVER Driver)
{
	UNREFERENCED_PARAMETER(Driver);
	return;
}