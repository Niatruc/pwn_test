/** WFPDriver.h

Imports needed for the Windows Filtering Platform

Author: Jared Wright - 2015
*/

#ifndef WFPDriver_H
#define WFPDriver_H

#define NDIS61 1				// Need to declare this to compile WFP stuff on Win7, I'm not sure why

#include "Ntifs.h"
#include <ntddk.h>				// Windows Driver Development Kit
#include <wdf.h>				// Windows Driver Foundation

#pragma warning(push)
#pragma warning(disable: 4201)	// Disable "Nameless struct/union" compiler warning for fwpsk.h only!
#include <fwpsk.h>				// Functions and enumerated types used to implement callouts in kernel mode
#pragma warning(pop)			// Re-enable "Nameless struct/union" compiler warning

#include <fwpmk.h>				// Functions used for managing IKE and AuthIP main mode (MM) policy and security associations
#include <fwpvi.h>				// Mappings of OS specific function versions (i.e. fn's that end in 0 or 1)
#include <guiddef.h>			// Used to define GUID's
#include <initguid.h>			// Used to define GUID's
#include "devguid.h"

/************************************
	Private Data and Prototypes
************************************/

#define CM_DEVICE_STRING L"\\Device\\cm_z_fw"
#define CM_DOS_DEVICE_STRING L"\\DosDevices\\cm_z_fw"

#define EXAMPLE_CALLOUT_NAME		L"ExampleCallout"
#define EXAMPLE_CALLOUT_DESCRIPTION	L"A callout used for demonstration purposes"
UINT32 example_callout_id;	// 由过滤器引擎分配
DEFINE_GUID(EXAMPLE_CALLOUT_GUID, // 工具 -> 创建GUID
	0xdb9827d2, 0xea74, 0x4aa5, 0x8b, 0xed, 0x9, 0x25, 0x42, 0x74, 0x78, 0xd7); // {DB9827D2-EA74-4AA5-8BED-0925427478D7}

#define EXAMPLE_SUBLAYER_NAME L"ExampleSublayer"
#define EXAMPLE_SUBLAYER_DESCRIPTION L"A sublayer used to hold filters in an example callout driver"
DEFINE_GUID(EXAMPLE_SUBLAYER_GUID,
	0xac2ebcd9, 0xf02c, 0x4813, 0xb4, 0xce, 0x6, 0xcf, 0x61, 0x5a, 0x2c, 0xdf); // {AC2EBCD9-F02C-4813-B4CE-06CF615A2CDF}

#define EXAMPLE_FILTER_NAME L"ExampleFilter"
#define EXAMPLE_FILTER_DESCRIPTION L"A filter that uses the example callout"

//驱动出入口函数
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
EVT_WDF_DRIVER_UNLOAD empty_evt_unload;

// 初始化WDFDriver对象和WDFDevice对象
NTSTATUS init_driver_objects(DRIVER_OBJECT* driver_obj, UNICODE_STRING* registry_path,
	WDFDRIVER* driver, WDFDEVICE* device);

// 注册及注销callout, 子层, 过滤器
NTSTATUS register_example_callout(DEVICE_OBJECT* wdm_device);
NTSTATUS unregister_example_callout();
NTSTATUS register_example_sublayer();
NTSTATUS register_example_filter();
NTSTATUS unregister_example_filter();
#endif // include guard