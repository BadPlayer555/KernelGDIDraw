#pragma once
#include "NtHread.h"
class ShadowSSDT
{
public:
	/*
	   初始化SSDT
	*/
	NTSTATUS InitializationShadowSSDT();

	/*
		根据索引获取函数地址
		返回:函数地址
	*/
	PVOID Get3SDTFunAddress(ULONG uIndex);

	/*
	   根据函数名获取地址
	*/
	PVOID Get3SDTFunAddress(PCWSTR name);


	/*
		通过函数名字返回 SSSDT ID
	*/
	LONG GetShadowSSDTFuncIDByName(PCWSTR name);




private:
	ULONGLONG GetKeServiceDescriptorTableShadow64();
private:
	PSYSTEM_SERVICE_TABLE m_KeServiceDescriptorTableShadow;
};
