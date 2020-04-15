#include "ShadowSSDT.h"

NTSTATUS ShadowSSDT::InitializationShadowSSDT()
{
	m_KeServiceDescriptorTableShadow = (PSYSTEM_SERVICE_TABLE)GetKeServiceDescriptorTableShadow64();
	if (!m_KeServiceDescriptorTableShadow)
	{
		//这里找不到SSSDT 你那边铁定在玩腾讯游戏
		//提前加载驱动就可以解决
		//TP HOOK了MSR导致的.__readmsr(0xC0000082) 获取到的是错误的。所以没找到
		DPRINT("ShadowSSDT.cpp Line 8 Triggers An Error.InitializationShadowSSDT() Internal Function\n");
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}

PVOID ShadowSSDT::Get3SDTFunAddress(ULONG uIndex)
{
	PVOID pRetAddr = NULL;
	PULONG W32pServiceTable = NULL;
	PVOID FunctionAddress = NULL;
	PSYSTEM_SERVICE_TABLE pKeServiceDescriptorTable = m_KeServiceDescriptorTableShadow;
	if (!pKeServiceDescriptorTable || uIndex > pKeServiceDescriptorTable->NumberOfServices) {
		DPRINT("ShadowSSDT.cpp Line 20 Triggers An Error.Get3SDTFunAddress() Internal Function\n");
		return NULL;
	}

	W32pServiceTable = (PULONG)pKeServiceDescriptorTable->ServiceTableBase;
	if (!W32pServiceTable) {
		// 诡异。
		DPRINT("ShadowSSDT.cpp Line 26 Triggers An Error.Get3SDTFunAddress() Internal Function\n");
		return NULL;
	}

	if (!MmIsAddressValid((PVOID)W32pServiceTable)) {
		// 这里触发错误 当前线程 不是GUI线程导致的
		DPRINT("ShadowSSDT.cpp Line 31 Triggers An Error.Get3SDTFunAddress() Internal Function\n");
		return NULL;
	}

	__try {
		FunctionAddress = (PVOID)(((LONG64)(W32pServiceTable[uIndex] >> 4) + (LONG64)W32pServiceTable) & 0xFFFFFFFF0FFFFFFF);
	}
	__except (1) {
		// 这里触发异常 原因很简单。当前线程 不是GUI线程导致的
		DPRINT("ShadowSSDT.cpp Line 40 Triggers An Exception.Get3SDTFunAddress() Internal Function\n");
		return NULL;
	}

	return FunctionAddress;
}

PVOID ShadowSSDT::Get3SDTFunAddress(PCWSTR name)
{
	ULONG Id = GetShadowSSDTFuncIDByName(name);
	if (Id == 0)
	{
		//函数不存在。要不然就是我抄的那张表报废了。
		//就是那个字符串数组 在NtHread.h里 。实在不行就用SSSDT ID来找函数吧 
		//嘿嘿
		DPRINT("ShadowSSDT.cpp Line 58 Triggers An Error.Get3SDTFunAddress(PCWSTR name) Internal Function\n");
		return NULL;
	}
	DPRINT("[+] The syscall index of %s is %i \n", name, Id);
	return Get3SDTFunAddress(Id);
}

LONG ShadowSSDT::GetShadowSSDTFuncIDByName(PCWSTR name)
{

	UNICODE_STRING BaseFuncName;
	UNICODE_STRING DestFuncName;
	LONG i = 0;
	RtlInitUnicodeString(&DestFuncName, name);
	for (i = 0; i < 830; i++)
	{
		RtlInitUnicodeString(&BaseFuncName, g_SSSDTTableName[i]);
		if (RtlEqualUnicodeString(&BaseFuncName, &DestFuncName, FALSE))
		{
			return i;
		}
	}
	return 0;

}

ULONGLONG ShadowSSDT::GetKeServiceDescriptorTableShadow64()
{
	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONG templong = 0;
	ULONGLONG addr = 0;
	for (i = StartSearchAddress; i < EndSearchAddress; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			__try
			{
				b1 = *i;
				b2 = *(i + 1);
				b3 = *(i + 2);
				if (b1 == 0x4c && b2 == 0x8d && b3 == 0x1d) //4c8d1d
				{

					memcpy(&templong, i + 3, 4);
					addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
					addr = addr + sizeof(SYSTEM_SERVICE_TABLE);
					return addr;
				}
			}
			__except (1) {
				continue;
			}
		}

	}
	return 0;
}