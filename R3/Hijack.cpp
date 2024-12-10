#include "Hijack.h"


typedef BOOL (__fastcall* NtAlertThreadByThreadID)(uintptr_t ThreadID);

bool MemoryCmp(const BYTE* Data, const BYTE* Mask, const char* szMask) {
	for (; *szMask; ++szMask, ++Data, ++Mask) {
		if (*szMask == '\?' && *Data != *Mask) {
			return false;
		}
	}
	return (*szMask == NULL);
}



uintptr_t FindSignaturee(uintptr_t Start, UINT32 Size, const char* Sig, const char* Mask, HANDLE ProcessID) {
	BYTE* Data = new BYTE[Size];
	SIZE_T BytesRead;
	ReadMemory(ProcessID, (PVOID)Start, Size, Data);

	for (uint32_t i = 0; i < Size; i++) {
		if (MemoryCmp((const BYTE*)(Data + i), (const BYTE*)Sig, Mask)) {
			return Start + i;
		}
	}
	delete[] Data;
	return NULL;

}


BYTE RemoteCallDllMain[] = {//0x48 first byte   
	    0x48, 0x83, 0xEC, 0x38,
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x48, 0x39, 0xFF, 0x90, 0x39, 0xC0,
		0x90,
		0x48, 0x89, 0x44, 0x24, 0x20,
		0x48, 0x8B, 0x44, 0x24,
		0x20, 0x83, 0x38, 0x00, 0x75, 0x39,
		0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x48, 0x8B, 0x44, 0x24, 0x20,
		0x48, 0x8B, 0x40, 0x08, 0x48, 0x89, 0x44, 0x24, 0x28, 0x45, 0x33, 0xC0, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20,
		0x48, 0x8B,
		0x48, 0x10, 0xFF, 0x54, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x81, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0x48,
		0x39, 0xC0, 0x90, 0xCC
}; DWORD ShellDataOffset = 0x6;
/*
start:
	sub rsp, 0x38                  ; 为调用创建栈空间（56 字节）

	mov rax, 0x0000000000000000    ; RAX <- 目标地址（占位符，会被动态替换）
									; ShellDataOffset 指向此处

	cmp rdi, rdi                   ; 比较 RDI 寄存器与自身（这里似乎是无意义的代码）
	nop                            ; 空操作（填充字节）
	cmp eax, eax                   ; 再次比较（可能为了对齐或混淆）

	mov [rsp + 0x20], rax          ; 将 RAX 的值（目标地址）存储到 [rsp+0x20]

	mov rax, [rsp + 0x20]          ; 将 [rsp+0x20] 的值加载到 RAX
	cmp byte ptr [rax], 0          ; 检查 [RAX] 是否为 0
	jne skip_null_check            ; 如果 [RAX] 不为 0，则跳过

	mov rax, [rsp + 0x20]          ; 加载 [rsp+0x20] 到 RAX
	mov dword ptr [rax], 0x1       ; 将 1 写入目标地址的 [RAX] 指向的内存
	jmp done                       ; 跳转到结束

skip_null_check:
	mov rax, [rsp + 0x20]          ; 再次加载 [rsp+0x20] 到 RAX
	mov rax, [rax + 0x8]           ; 加载 RAX 指向结构的偏移 +8 地址（通常是 DLL 的句柄）

	mov [rsp + 0x28], rax          ; 将上述加载的值存储到 [rsp+0x28]
	xor r8d, r8d                   ; 清空 R8D（设置为 0）
	mov edx, 0x1                   ; 将 RDX 设置为 1（第二个参数，原因码）
	mov rax, [rsp + 0x20]          ; 再次加载 [rsp+0x20] 到 RAX
	mov rcx, [rax + 0x10]          ; 加载 RAX 指向结构的偏移 +10 地址（模块句柄）

	call qword ptr [rsp + 0x28]    ; 调用目标地址，传入参数（R8, RDX, RCX）
	mov rax, [rsp + 0x20]          ; 加载 [rsp+0x20] 到 RAX
	mov dword ptr [rax], 0x81      ; 将状态值 0x81 写入 RAX 指向的内存

done:
	add rsp, 0x38                  ; 恢复栈空间
	ret                            ; 返回

invalid:
	int3                           ; 调试中断

*/


BYTE Shellcode[] = { 0x48, 0xB8, 
0x00, 0xBE, 0xBA, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 
0xFF, 0xE0 };
/*
start:
	mov rax, 0x00DEADBEEFBABE00    ; 将立即数 0x00DEADBEEFBABE00 加载到 RAX 寄存器
	jmp rax                        ; 跳转到 RAX 指向的内存地址

*/


typedef struct _MAIN_STRUCT {
	INT Status;
	uintptr_t FnDllMain;
	HINSTANCE DllBase;
} MAIN_STRUCT, * PMAIN_STRUCT;


BOOL Hijack::CallDllMain(DWORD ProcessID, DWORD ThreadID, PVOID DllBase, DWORD AddressOfEntryPoint) {
	PVOID AllocShellCode = NULL;
	AllocMemory((HANDLE)ProcessID, &AllocShellCode, 0x1000, PAGE_EXECUTE_READWRITE);

	if (!AllocShellCode) {
		printf(skCrypt("[-] Failed to Allocate ShellCode...\n"));
		return FALSE;
	}

	DWORD ShellSize = sizeof(RemoteCallDllMain) + sizeof(MAIN_STRUCT);
	PVOID AllocLocal = VirtualAlloc(NULL, ShellSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!AllocLocal) {
		printf(skCrypt("[-] Failed to allocate local mem\n"));
		return FALSE;
	}
	// 将 RemoteCallDllMain 的内容复制到本地内存
	memcpy(AllocLocal, &RemoteCallDllMain, sizeof(RemoteCallDllMain));

	// 计算 ShellData 的地址并设置
	ULONGLONG ShellData = (ULONGLONG)AllocShellCode + sizeof(RemoteCallDllMain);
	memcpy((void*)((std::uintptr_t)AllocLocal + 0x6), &ShellData, sizeof(std::uintptr_t));

	// 设置 MAIN_STRUCT 结构体
	auto remote = (PMAIN_STRUCT)((std::uintptr_t)AllocLocal + sizeof(RemoteCallDllMain));
	remote->DllBase = (HINSTANCE)DllBase;// 设置 DLL 基地址
	remote->FnDllMain = ((std::uintptr_t)DllBase + AddressOfEntryPoint);// 设置 DLL Main 函数地址
	// 将本地内存中的数据写入到目标进程的分配内存中
	WriteMemory((HANDLE)ProcessID, (DWORD64)AllocShellCode, ShellSize, AllocLocal);

	// 获取目标进程中指定 DLL 的基址
	PVOID ModBase{0};
	PVOID ModBaseSize{ 0 };
	//GetBase(&ModBase, &ModBaseSize, "DiscordHook64.dll", (HANDLE)ProcessID);
	GetBase(&ModBase, &ModBaseSize, "win32u.dll", (HANDLE)ProcessID);////////////////////////

	if (!ModBase) {
		printf(skCrypt("[-] Failed to obtain DLL base for hook!\n\n"));
		return FALSE;
	}

	// 计算要钩取的函数地址 (SwapChain::Present)
	uintptr_t FuncToHook = ((uintptr_t)ModBase + 0xE8090);//E8090 SwapChain::Present
	printf(skCrypt("[*] Shellcode Allocation -> 0x%X\n"), AllocShellCode);



	// 交换指定函数地址与分配的 shellcode 地址
	PVOID pOldFuncPtr;
	SwapPointer((HANDLE)ProcessID, (PVOID)FuncToHook, (PVOID)AllocShellCode, &pOldFuncPtr);

	
	// 监控远程 DLL 执行状态
	HWND hWnd = 0;
	while (remote->Status != 0x81)
	{
		
		printf("[*] Status -> %d\n", remote->Status);
		// 查找游戏窗口
		//hWnd = FindWindowA(skCrypt("gfx_test"), NULL);
		hWnd = FindWindowA("Bandizip (Standard)", NULL);//////////////////////////////////////////
		
		// 如果游戏窗口关闭，退出
		if (hWnd == NULL) {
			printf(skCrypt("\n[-]Game Closed.. exiting\n"));
			return FALSE;
		}
		Sleep(10);

		// 从目标进程读取 ShellData 并更新远程内存
		ReadMemory((HANDLE)ProcessID, (PVOID)ShellData, sizeof(MAIN_STRUCT), (PVOID)remote);
	}

	printf(skCrypt("[*] Executed DLL!\n"));

	// 恢复原来的函数地址
	PVOID pNewOldPtr{ 0 };
	SwapPointer((HANDLE)ProcessID, (PVOID)FuncToHook, (PVOID)pOldFuncPtr, &pNewOldPtr);
	
	// 隐藏痕迹，清空分配的内存
	printf(skCrypt("[*] Hiding Traces...\n"));

	// 清除 shellcode 分配的内存区域内容
	BYTE ZeroData[0x1000] = {0};
	WriteMemory((HANDLE)ProcessID, (DWORD64)AllocShellCode, 0x1000, &ZeroData);

	// 释放在目标进程分配的内存
	FreeMemory((HANDLE)ProcessID, (PVOID)AllocShellCode);

	// 释放本地分配的内存
	LI_FN(VirtualFree).get()((PVOID)AllocLocal, 0, MEM_RELEASE);

    return true;
}
