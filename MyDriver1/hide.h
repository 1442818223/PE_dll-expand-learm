#pragma once
#include <ntifs.h>


//#define PIDDB_LOCK_PATTERN "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C\x24\x00\x00\x00\x00\x48\x8D\x4C\x24\x00\x48\x8B\xD6\xE8\x00\x00\x00\x00\x8B\xD8"
#define PIDDB_LOCK_PATTERN "\x48\x8D\x0D\x00\x00\x00\x00\xB2\x01\x66\xFF\x88\xE4\x01\x00\x00\x90\xE8\x00\x00\x00\x00\x4C\x8B\x8C\x24\x88\x00\x00\x00"//��PpCheckInDriverDatabase��
//#define PIDDB_LOCK_MASK "xxx????x????xxxx????xxxx?xxxx????xx"
#define PIDDB_LOCK_MASK "xxx????xxxxxxxxxxx????xxxxxxxx"


//#define PIDDB_TABLE_PATTERN "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8D\x1D\x00\x00\x00\x00\x48\x85\xC0\x0F"
#define PIDDB_TABLE_PATTERN "\x66\x03\xD2\x48\x8D\x0D"
//#define PIDDB_TABLE_MASK "xxx????x????xxx????xxxx"
#define PIDDB_TABLE_MASK "xxxxxx"


#define MMU_PATTERN "\x4C\x8B\x15\x00\x00\x00\x00\x4C\x8B\xC9"//MmLocateUnloadedDriver��
#define MMU_MASK "xxx????xxx"


#define MML_PATTERN "\x8B\x05\x00\x00\x00\x00\x83\xF8\x32"//��MiRememberUnloadedDriver��
#define MML_MASK "xx????xxx"


#define CI_DLL_KERNEL_HASH_BUCKET_PATTERN "\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00"//��I_SetSecurityState��
#define CI_DLL_KERNEL_HASH_BUCKET_MASK "xxx????x?xxxxxxx"




namespace Hide {

	NTSTATUS HideEverything(UNICODE_STRING DriverName);

	BOOLEAN FindPoolTable(uintptr_t* PoolBigPageTable, SIZE_T* PoolBigPageTableSize, PVOID ModuleBase);
	BOOLEAN NullPfn(PMDL mdl);

	NTSTATUS Hide(PVOID BigPoolAddress);
	


}



