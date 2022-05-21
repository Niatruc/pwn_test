/** ExampleCallout.c

Implementation of an example Callout that inspects
outbound TCP traffic at the FWPM_OUTBOUND_TRANSPORT_V4
layer. This callout's ClassifyFn function prints the packets
TCP 4-tuple, and blocks the packet if it is bound for remote
port 1234. This Callout's NotifyFn function prints a message.

Author: Jared Wright - 2015
*/

#include "ExampleCallout.h"

#define FORMAT_ADDR(x) (x>>24)&0xFF, (x>>16)&0xFF, (x>>8)&0xFF, x&0xFF

/*************************
	ClassifyFn Function
**************************/
void example_classify(
	const FWPS_INCOMING_VALUES* inFixedValues, // 这个结构体包含被过滤的层的每个数据域
	const FWPS_INCOMING_METADATA_VALUES * inMetaValues, // 这个结构体包含被过滤的层的每个元数据域, 包括进程id，数据流句柄等
	void * layerData, // 这个结构体描述层中的原生数据
	const void * classifyContext, // callout相关的上下文数据
	const FWPS_FILTER * filter,
	UINT64 flowContext, // 与数据流相关的上下文
	FWPS_CLASSIFY_OUT * classifyOut) // 这个变量用来存放本classifyFn最后返回给调用者的数据
{
	UINT32 local_address = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;
	UINT32 remote_address = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
	UINT16 local_port = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
	UINT16 remote_port = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;

	UNREFERENCED_PARAMETER(inMetaValues);
	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(filter);

	// inMetaValues->currentMetadataValues 值的某一位为1, 则该位对应的inMetaValues结构体中的成员有效
	if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
		UINT64 processId = inMetaValues->processId;
		DbgPrint("cm: current process id (inMetaValues->processId): %I64d\n", processId);
	}

	// 若远端口为1234, 则阻止该包
	if (remote_port == 1234){
		DbgPrint("Blocking Packet to port 1234");
		classifyOut->actionType = FWP_ACTION_BLOCK;
		return;
	} else { // 否则打印tcp四元组
		DbgPrint("Example Classify found a packet: %d.%d.%d.%d:%hu --> %d.%d.%d.%d:%hu \n",
			FORMAT_ADDR(local_address), local_port, FORMAT_ADDR(remote_address), remote_port);
	}

	classifyOut->actionType = FWP_ACTION_PERMIT;
	return;
}

/*************************
	NotifyFn Function
**************************/
NTSTATUS example_notify(
	FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	const GUID * filterKey,
	const FWPS_FILTER * filter)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	switch (notifyType){
	case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
		DbgPrint("A new filter has registered Example Callout as its action");
		break;
	case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
		DbgPrint("A filter that uses Example Callout has just been deleted");
		break;
	}
	return status;
}

/***************************
	FlowDeleteFn Function
****************************/
NTSTATUS example_flow_delete(UINT16 layerId, UINT32 calloutId, UINT64 flowContext)
{
	UNREFERENCED_PARAMETER(layerId);
	UNREFERENCED_PARAMETER(calloutId);
	UNREFERENCED_PARAMETER(flowContext);
	return STATUS_SUCCESS;
}
