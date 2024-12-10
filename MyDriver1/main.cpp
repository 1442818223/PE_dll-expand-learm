#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include "Util.h"
#include "Comm.h"
#include "hide.h"






PVOID pPoolBase = NULL;
VOID MyUnloadDriver(PDRIVER_OBJECT DriverObject) {

}
// 宏定义，计算某个地址的相对地址
#define RELATIVE_ADDR(addr, size) ((PVOID)((PBYTE)(addr) + *(PINT)((PBYTE)(addr) + ((size) - (INT)sizeof(INT))) + (size)))

//VOID NTAPI Main() {
VOID NTAPI Main() {
	

	UNICODE_STRING DriverName;
	RtlInitUnicodeString(&DriverName, L"MyDriver1.sys");

	// 隐藏驱动程序相关的信息，如果隐藏成功，则打印成功日志，否则打印失败日志
	if (NT_SUCCESS(Hide::HideEverything(DriverName))) {
		DbgPrintEx(77,0,"Hid everything!\n");
	}
	else {
		DbgPrintEx(77,0,"Failed to hide stuff\n");
	}
	

	// 初始化内存相关函数并检查其是否成功
	NTSTATUS Status = Memory::InitializeFuncs();
	if (NT_SUCCESS(Status)) {
		DbgPrintEx(77,0,"great found addresses needed!\n");
	}
	else {
		DbgPrintEx(77,0," didnt find func addresses.\n");
	}
	

	// 初始化通信相关功能，如果失败则打印调试信息
	if (!NT_SUCCESS(Comm::Initialize())) {
		DbgPrintEx(77,0,"failed to initalize communication\n\n");

	}
	else {
		DbgPrintEx(77,0, "try to communicate now\n\n");
	}
	

	// 结束系统线程
	PsTerminateSystemThread(STATUS_SUCCESS);
	
}

extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	HANDLE ThreadHandle = NULL;

	
	PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)Main, NULL);

	ZwClose(ThreadHandle);


	return STATUS_SUCCESS;
}
