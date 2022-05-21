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
	FWPM_SESSION wdf_session = { 0 }; // ���ڱ���FwpmEngineOpen�����ĻỰ����Ϣ
	BOOLEAN in_transaction = FALSE;
	BOOLEAN callout_registered = FALSE;

	status = init_driver_objects(driver_obj, registry_path, &driver, &device);
	if (!NT_SUCCESS(status)) goto Exit;

	// ����һ���Թ��������������. ��Ҫ������������������ע��filter, callouts, sublayers
	wdf_session.flags = FWPM_SESSION_FLAG_DYNAMIC;	// �ڻỰ����ʱ�Զ��������й�������callout
	status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &wdf_session, &filter_engine_handle); // ��һ������������ĻỰ
	if (!NT_SUCCESS(status)) goto Exit;
	status = FwpmTransactionBegin(filter_engine_handle, 0); // �ڵ�ǰ�Ự�п���һ������
	if (!NT_SUCCESS(status)) goto Exit;
	in_transaction = TRUE;

	// �����������ע��һ���µ�Callout 
	wdm_device = WdfDeviceWdmGetDeviceObject(device);
	status = register_example_callout(wdm_device);
	if (!NT_SUCCESS(status)) goto Exit;
	callout_registered = TRUE;

	// �����������ע��һ���µ�sublayer 
	status = register_example_sublayer();
	if (!NT_SUCCESS(status)) goto Exit;

	// ע��һ��ʹ��example callout�Ĺ�����
	status = register_example_filter();
	if (!NT_SUCCESS(status)) goto Exit;
	
	// ������������ύһ���µ�����
	status = FwpmTransactionCommit(filter_engine_handle);
	if (!NT_SUCCESS(status)) goto Exit;
	in_transaction = FALSE;

	driver_obj->DriverUnload = DriverUnload;

	// Cleanup and handle any errors
Exit:
	if (!NT_SUCCESS(status)) {
		DbgPrint("WFPDriver example driver failed to load, status 0x%08x", status);
		if (in_transaction == TRUE){
			FwpmTransactionAbort(filter_engine_handle); // ����ǰ�Ự�еĵ�ǰ�����жϲ��ع�
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

	// ����WDFDRIVER
	WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK); // ��ʼ��config, ���������ûص�����EvtDriverDeviceAdd
	config.DriverInitFlags = WdfDriverInitNonPnpDriver; // ��֧�ּ��弴��
	config.EvtDriverUnload = empty_evt_unload; // ���ûص�����EvtDriverUnload������ж��ǰ���õģ�
	status = WdfDriverCreate(driver_obj, registry_path, WDF_NO_OBJECT_ATTRIBUTES, &config, driver); // ���صľ������driver����
	if (!NT_SUCCESS(status)) goto Exit;

	// ����һ��WDFDEVICE_INIT�ṹ��
	device_init = WdfControlDeviceInitAllocate(*driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);	// ֻ�й���Ա���ں�̬�ɷ����豸 ; SSDL�ǰ�ȫ��������������
	if (!device_init){
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	// ����device_init������һ�����֣��Ա��û�̬����
	WdfDeviceInitSetDeviceType(device_init, FILE_DEVICE_NETWORK);
	WdfDeviceInitSetCharacteristics(device_init, FILE_DEVICE_SECURE_OPEN, FALSE);
	WdfDeviceInitAssignName(device_init, &device_name);
	WdfPdoInitAssignRawDevice(device_init, &GUID_DEVCLASS_NET);
	WdfDeviceInitSetDeviceClass(device_init, &GUID_DEVCLASS_NET);

	// ����WDFDEVICE
	status = WdfDeviceCreate(&device_init, WDF_NO_OBJECT_ATTRIBUTES, device);
	if (!NT_SUCCESS(status)){
		WdfDeviceInitFree(device_init); // �ͷ�device_init
		goto Exit;
	}

	WdfControlFinishInitializing(*device); // ֪ͨ���, �����Ѿ����ָ�������豸����ĳ�ʼ��

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

	// �ڹ�����������ע���µ�callout
	s_callout.calloutKey = EXAMPLE_CALLOUT_GUID;
	s_callout.classifyFn = example_classify; // callout������������ʱҪ�õ��ĺ���
	s_callout.notifyFn = example_notify; // ������������ӻ��Ƴ�������ʱ, ���øú�����callout����֪ͨ����¼�
	s_callout.flowDeleteFn = example_flow_delete; // ������������callout�������������������ֹʱ, ���øú��� (ֻ���������������������������(����FwpsFlowAssociateContext���й���)�������, �ú����ᱻ����)
	status = FwpsCalloutRegister((void *)wdm_device, &s_callout, &example_callout_id); // �����������ע��callout
	if (!NT_SUCCESS(status)){
		DbgPrint("Failed to register callout functions for example callout, status 0x%08x", status);
		goto Exit;
	}

	// ����FWPM_CALLOUT�ṹ�����ڱ���/׷�� FWPS_CALLOUT ��״̬
	m_callout.calloutKey = EXAMPLE_CALLOUT_GUID;
	m_callout.displayData = display_data; // ����һЩ�ɹ����Ķ��ı�ע
	m_callout.applicableLayer = FWPM_LAYER_OUTBOUND_TRANSPORT_V4; // ָ������ʹ�ø�callout�ķֲ�
	m_callout.flags = 0;
	status = FwpmCalloutAdd(filter_engine_handle, &m_callout, NULL, NULL); // ���µ�callout������ӵ�ϵͳ
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
	filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;	// ָ���ֲ㡣������callout�����ֲ�һ��
	filter.subLayerKey = EXAMPLE_SUBLAYER_GUID; // �Ӳ�GUID, ������������ӵ��ĸ��Ӳ�
	filter.weight.type = FWP_UINT8; // type����FWP_VALUE0���������ĸ���Ա��ʹ��
	filter.weight.uint8 = 0xf;		// ���Ӳ�Ĺ�������Ȩ��

	// ָ����������
	filter.numFilterConditions = 0;	// ���������ĸ���. Ϊ0, ��ù�����Ϊ�����ڲ��������������callouut
	FWPM_FILTER_CONDITION conditions[1] = { 0 }; // ������������
	conditions[0].fieldKey = FWPM_CONDITION_IP_DESTINATION_ADDRESS; // �������ݰ��ֶεı�ʶ
	conditions[0].matchType = FWP_MATCH_EQUAL; // ƥ�������. FWP_MATCH_EQUAL�ͱ�ʾfieldKeyָ�����ֶ�ֵ��conditionValue���ʱ, ������������
	conditions[0].conditionValue.type = FWP_UINT32;
	conditions[0].conditionValue.uint32 = 0x0	;
	filter.filterCondition = conditions;	// 

	// ָ������������
	filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;	// �����й���������Ϊ��ʱ�������������callout��Ҫ����ֹ/����ľ���
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

	status = unregister_example_filter(); // ע��������
	if (!NT_SUCCESS(status)) DbgPrint("Failed to unregister filters, status: 0x%08x", status);
	status = unregister_example_callout(); // ע��callout
	if (!NT_SUCCESS(status)) DbgPrint("Failed to unregister callout, status: 0x%08x", status);

	// �ر�WFP����������ľ��
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