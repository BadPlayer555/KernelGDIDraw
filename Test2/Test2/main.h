#pragma once
///
/// Includes.
///

#pragma warning(push, 0)
#include <ntifs.h>
#include <ntdef.h>
#include <ntddk.h>
#include <ntstatus.h>
#pragma warning(pop)
#include <ntimage.h>
#include "helpers.h"
#include "InfinityHook\infinityhook.h"
#include <wsk.h>
#include <intrin.h>
#include <ntstrsafe.h>
#include <WinDef.h>
#include <wingdi.h>
///
/// Structures and typedefs.
///

#define NTGDIDDDDISUBMMITCOMMAND_SYSCALL_INDEX 0x1250 //check out for your index https://github.com/j00ru/windows-syscalls/blob/master/x64/csv/win32k.csv
#define NTUSERGETDC_SYSCALL_INDEX 0x100d //check out for your index https://github.com/j00ru/windows-syscalls/blob/master/x64/csv/win32k.csv
#define NTGDIPATBLT_SYSCALL_INDEX 0x105c //check out for your index https://github.com/j00ru/windows-syscalls/blob/master/x64/csv/win32k.csv
#define NTGDISELECTBRUSH_SYSCALL_INDEX 0x1302 //check out for your index https://github.com/j00ru/windows-syscalls/blob/master/x64/csv/win32k.csv
#define NTUSERRELEASEDC_SYSCALL_INDEX 0x1477 //check out for your index https://github.com/j00ru/windows-syscalls/blob/master/x64/csv/win32k.csv
#define NTGDICREATESOLIDBRUSH_SYSCALL_INDEX 0x10b3 //check out for your index https://github.com/j00ru/windows-syscalls/blob/master/x64/csv/win32k.csv
#define NTGDIDELETEOBJECTAPP_SYSCALL_INDEX 0x1026 //check out for your index https://github.com/j00ru/windows-syscalls/blob/master/x64/csv/win32k.csv

#define DIRTY_BACKGROUND                    0x00000008
#define DIRTY_CHARSET                       0x00000010
#define SLOW_WIDTHS                         0x00000020
#define COLOR_MENUBAR 30
#define MAXMSG_WIDTH	0x100
#define MAXMSG_HEIGHT	0x100
#define DIRTY_FILL                          0x00000001
#define DIRTY_LINE                          0x00000002
#define DIRTY_TEXT                          0x00000004
#define GDI_HANDLE_TYPE_MASK  0x007f0000
#define GDI_HANDLE_COUNT 0x10000
#define GDI_HANDLE_INDEX_MASK (GDI_HANDLE_COUNT - 1)
#define GDI_HANDLE_GET_TYPE(h)     \
    (((ULONG_PTR)(h)) & GDI_HANDLE_TYPE_MASK)
#define GDI_HANDLE_GET_INDEX(h)    \
    (((ULONG_PTR)(h)) & GDI_HANDLE_INDEX_MASK)

#define D3DDDI_MAX_BROADCAST_CONTEXT 64
#define D3DDDI_MAX_WRITTEN_PRIMARIES 16
typedef FLOAT FLOATOBJ, *PFLOATOBJ;
typedef unsigned short GLYPH;
typedef long long          int64_t;
typedef unsigned int        UINT;
typedef int                 BOOL;
typedef DWORD LFTYPE;
typedef ULONGLONG D3DGPU_VIRTUAL_ADDRESS;
typedef struct _D3DKMT_SUBMITCOMMANDFLAGS
{
	UINT    NullRendering : 1;  // 0x00000001
	UINT    PresentRedirected : 1;  // 0x00000002
	UINT    Reserved : 30;  // 0xFFFFFFFC
} D3DKMT_SUBMITCOMMANDFLAGS;
typedef UINT D3DKMT_HANDLE;
typedef struct _D3DKMT_SUBMITCOMMAND
{
	D3DGPU_VIRTUAL_ADDRESS      Commands;
	UINT                        CommandLength;
	D3DKMT_SUBMITCOMMANDFLAGS   Flags;
	ULONGLONG                   PresentHistoryToken;                            // in: Present history token for redirected present calls
	UINT                        BroadcastContextCount;
	D3DKMT_HANDLE               BroadcastContext[D3DDDI_MAX_BROADCAST_CONTEXT];
	VOID*                       pPrivateDriverData;
	UINT                        PrivateDriverDataSize;
	UINT                        NumPrimaries;
	D3DKMT_HANDLE               WrittenPrimaries[D3DDDI_MAX_WRITTEN_PRIMARIES];
	UINT                        NumHistoryBuffers;
	D3DKMT_HANDLE*              HistoryBufferArray;
} D3DKMT_SUBMITCOMMAND;
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	// ...
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
typedef struct
{
	BOOL	state;
	int		countdown;
	BOOL	started;
	int		runlen;
	int		blippos;
	int		bliplen;
	int		length;
	GLYPH	*glyph;

} MATRIX_COLUMN;
typedef struct
{
	WORD	message[MAXMSG_WIDTH][MAXMSG_HEIGHT];
	int		msgindex;
	int		counter;
	WORD	random_reg1;
	int		width, height;
} MATRIX_MESSAGE;

typedef struct
{
	int				width;
	int				height;
	int				numcols;
	int				numrows;
	HDC				hdcBitmap;
	HBITMAP			hbmBitmap;
	MATRIX_MESSAGE *message;
	MATRIX_COLUMN	column[1];
} MATRIX;
typedef struct _RGN_ATTR
{
	ULONG AttrFlags;
	ULONG iComplexity;     /* Clipping region's complexity. NULL, SIMPLE & COMPLEXREGION */
	RECTL Rect;
} RGN_ATTR, *PRGN_ATTR;
typedef struct _DC_ATTR
{
	PVOID pvLDC;
	ULONG ulDirty_;
	HANDLE hbrush;
	HANDLE hpen;
	COLORREF crBackgroundClr;
	ULONG ulBackgroundClr;
	COLORREF crForegroundClr;
	ULONG ulForegroundClr;
	COLORREF crBrushClr;
	ULONG ulBrushClr;
	COLORREF crPenClr;
	ULONG ulPenClr;
	DWORD iCS_CP;
	INT iGraphicsMode;
	BYTE jROP2;
	BYTE jBkMode;
	BYTE jFillMode;
	BYTE jStretchBltMode;
	POINTL ptlCurrent;
	POINTL ptfxCurrent;
	LONG lBkMode;
	LONG lFillMode;
	LONG lStretchBltMode;
	FLONG flFontMapper;
	LONG lIcmMode;
	HANDLE hcmXform;
	HCOLORSPACE hColorSpace;
	FLONG flIcmFlags;
	INT IcmBrushColor;
	INT IcmPenColor;
	PVOID pvLIcm;
	FLONG flTextAlign;
	LONG lTextAlign;
	LONG lTextExtra;
	LONG lRelAbs;
	LONG lBreakExtra;
	LONG cBreak;
	HANDLE hlfntNew;
	MATRIX mxWorldToDevice;
	MATRIX mxDeviceToWorld;
	MATRIX mxWorldToPage;
	FLOATOBJ efM11PtoD;
	FLOATOBJ efM22PtoD;
	FLOATOBJ efDxPtoD;
	FLOATOBJ efDyPtoD;
	INT iMapMode;
	DWORD dwLayout;
	LONG lWindowOrgx;
	POINTL ptlWindowOrg;
	SIZEL szlWindowExt;
	POINTL ptlViewportOrg;
	SIZEL szlViewportExt;
	FLONG flXform;
	SIZEL szlVirtualDevicePixel;
	SIZEL szlVirtualDeviceMm;
	SIZEL szlVirtualDeviceSize;
	POINTL ptlBrushOrigin;
	RGN_ATTR VisRectRegion;
} DC_ATTR, *PDC_ATTR;
typedef enum GDILoObjType
{
	GDILoObjType_LO_BRUSH_TYPE = 0x100000,
	GDILoObjType_LO_DC_TYPE = 0x10000,
	GDILoObjType_LO_BITMAP_TYPE = 0x50000,
	GDILoObjType_LO_PALETTE_TYPE = 0x80000,
	GDILoObjType_LO_FONT_TYPE = 0xa0000,
	GDILoObjType_LO_REGION_TYPE = 0x40000,
	GDILoObjType_LO_ICMLCS_TYPE = 0x90000,
	GDILoObjType_LO_CLIENTOBJ_TYPE = 0x60000,
	GDILoObjType_LO_ALTDC_TYPE = 0x210000,
	GDILoObjType_LO_PEN_TYPE = 0x300000,
	GDILoObjType_LO_EXTPEN_TYPE = 0x500000,
	GDILoObjType_LO_DIBSECTION_TYPE = 0x250000,
	GDILoObjType_LO_METAFILE16_TYPE = 0x260000,
	GDILoObjType_LO_METAFILE_TYPE = 0x460000,
	GDILoObjType_LO_METADC16_TYPE = 0x660000
} GDILOOBJTYPE, *PGDILOOBJTYPE;
typedef struct
{
	LPVOID pKernelAddress;
	USHORT wProcessId;
	USHORT wCount;
	USHORT wUpper;
	USHORT wType;
	LPVOID pUserAddress;
} GDICELL;
typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
}SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;
typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
}SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0x0,
	SystemProcessorInformation = 0x1,
	SystemPerformanceInformation = 0x2,
	SystemTimeOfDayInformation = 0x3,
	SystemPathInformation = 0x4,
	SystemProcessInformation = 0x5,
	SystemCallCountInformation = 0x6,
	SystemDeviceInformation = 0x7,
	SystemProcessorPerformanceInformation = 0x8,
	SystemFlagsInformation = 0x9,
	SystemCallTimeInformation = 0xa,
	SystemModuleInformation = 0xb,
	SystemLocksInformation = 0xc,
	SystemStackTraceInformation = 0xd,
	SystemPagedPoolInformation = 0xe,
	SystemNonPagedPoolInformation = 0xf,
	SystemHandleInformation = 0x10,
	SystemObjectInformation = 0x11,
	SystemPageFileInformation = 0x12,
	SystemVdmInstemulInformation = 0x13,
	SystemVdmBopInformation = 0x14,
	SystemFileCacheInformation = 0x15,
	SystemPoolTagInformation = 0x16,
	SystemInterruptInformation = 0x17,
	SystemDpcBehaviorInformation = 0x18,
	SystemFullMemoryInformation = 0x19,
	SystemLoadGdiDriverInformation = 0x1a,
	SystemUnloadGdiDriverInformation = 0x1b,
	SystemTimeAdjustmentInformation = 0x1c,
	SystemSummaryMemoryInformation = 0x1d,
	SystemMirrorMemoryInformation = 0x1e,
	SystemPerformanceTraceInformation = 0x1f,
	SystemObsolete0 = 0x20,
	SystemExceptionInformation = 0x21,
	SystemCrashDumpStateInformation = 0x22,
	SystemKernelDebuggerInformation = 0x23,
	SystemContextSwitchInformation = 0x24,
	SystemRegistryQuotaInformation = 0x25,
	SystemExtendServiceTableInformation = 0x26,
	SystemPrioritySeperation = 0x27,
	SystemVerifierAddDriverInformation = 0x28,
	SystemVerifierRemoveDriverInformation = 0x29,
	SystemProcessorIdleInformation = 0x2a,
	SystemLegacyDriverInformation = 0x2b,
	SystemCurrentTimeZoneInformation = 0x2c,
	SystemLookasideInformation = 0x2d,
	SystemTimeSlipNotification = 0x2e,
	SystemSessionCreate = 0x2f,
	SystemSessionDetach = 0x30,
	SystemSessionInformation = 0x31,
	SystemRangeStartInformation = 0x32,
	SystemVerifierInformation = 0x33,
	SystemVerifierThunkExtend = 0x34,
	SystemSessionProcessInformation = 0x35,
	SystemLoadGdiDriverInSystemSpace = 0x36,
	SystemNumaProcessorMap = 0x37,
	SystemPrefetcherInformation = 0x38,
	SystemExtendedProcessInformation = 0x39,
	SystemRecommendedSharedDataAlignment = 0x3a,
	SystemComPlusPackage = 0x3b,
	SystemNumaAvailableMemory = 0x3c,
	SystemProcessorPowerInformation = 0x3d,
	SystemEmulationBasicInformation = 0x3e,
	SystemEmulationProcessorInformation = 0x3f,
	SystemExtendedHandleInformation = 0x40,
	SystemLostDelayedWriteInformation = 0x41,
	SystemBigPoolInformation = 0x42,
	SystemSessionPoolTagInformation = 0x43,
	SystemSessionMappedViewInformation = 0x44,
	SystemHotpatchInformation = 0x45,
	SystemObjectSecurityMode = 0x46,
	SystemWatchdogTimerHandler = 0x47,
	SystemWatchdogTimerInformation = 0x48,
	SystemLogicalProcessorInformation = 0x49,
	SystemWow64SharedInformationObsolete = 0x4a,
	SystemRegisterFirmwareTableInformationHandler = 0x4b,
	SystemFirmwareTableInformation = 0x4c,
	SystemModuleInformationEx = 0x4d,
	SystemVerifierTriageInformation = 0x4e,
	SystemSuperfetchInformation = 0x4f,
	SystemMemoryListInformation = 0x50,
	SystemFileCacheInformationEx = 0x51,
	SystemThreadPriorityClientIdInformation = 0x52,
	SystemProcessorIdleCycleTimeInformation = 0x53,
	SystemVerifierCancellationInformation = 0x54,
	SystemProcessorPowerInformationEx = 0x55,
	SystemRefTraceInformation = 0x56,
	SystemSpecialPoolInformation = 0x57,
	SystemProcessIdInformation = 0x58,
	SystemErrorPortInformation = 0x59,
	SystemBootEnvironmentInformation = 0x5a,
	SystemHypervisorInformation = 0x5b,
	SystemVerifierInformationEx = 0x5c,
	SystemTimeZoneInformation = 0x5d,
	SystemImageFileExecutionOptionsInformation = 0x5e,
	SystemCoverageInformation = 0x5f,
	SystemPrefetchPatchInformation = 0x60,
	SystemVerifierFaultsInformation = 0x61,
	SystemSystemPartitionInformation = 0x62,
	SystemSystemDiskInformation = 0x63,
	SystemProcessorPerformanceDistribution = 0x64,
	SystemNumaProximityNodeInformation = 0x65,
	SystemDynamicTimeZoneInformation = 0x66,
	SystemCodeIntegrityInformation = 0x67,
	SystemProcessorMicrocodeUpdateInformation = 0x68,
	SystemProcessorBrandString = 0x69,
	SystemVirtualAddressInformation = 0x6a,
	SystemLogicalProcessorAndGroupInformation = 0x6b,
	SystemProcessorCycleTimeInformation = 0x6c,
	SystemStoreInformation = 0x6d,
	SystemRegistryAppendString = 0x6e,
	SystemAitSamplingValue = 0x6f,
	SystemVhdBootInformation = 0x70,
	SystemCpuQuotaInformation = 0x71,
	SystemNativeBasicInformation = 0x72,
	SystemErrorPortTimeouts = 0x73,
	SystemLowPriorityIoInformation = 0x74,
	SystemBootEntropyInformation = 0x75,
	SystemVerifierCountersInformation = 0x76,
	SystemPagedPoolInformationEx = 0x77,
	SystemSystemPtesInformationEx = 0x78,
	SystemNodeDistanceInformation = 0x79,
	SystemAcpiAuditInformation = 0x7a,
	SystemBasicPerformanceInformation = 0x7b,
	SystemQueryPerformanceCounterInformation = 0x7c,
	SystemSessionBigPoolInformation = 0x7d,
	SystemBootGraphicsInformation = 0x7e,
	SystemScrubPhysicalMemoryInformation = 0x7f,
	SystemBadPageInformation = 0x80,
	SystemProcessorProfileControlArea = 0x81,
	SystemCombinePhysicalMemoryInformation = 0x82,
	SystemEntropyInterruptTimingInformation = 0x83,
	SystemConsoleInformation = 0x84,
	SystemPlatformBinaryInformation = 0x85,
	SystemThrottleNotificationInformation = 0x86,
	SystemHypervisorProcessorCountInformation = 0x87,
	SystemDeviceDataInformation = 0x88,
	SystemDeviceDataEnumerationInformation = 0x89,
	SystemMemoryTopologyInformation = 0x8a,
	SystemMemoryChannelInformation = 0x8b,
	SystemBootLogoInformation = 0x8c,
	SystemProcessorPerformanceInformationEx = 0x8d,
	SystemSpare0 = 0x8e,
	SystemSecureBootPolicyInformation = 0x8f,
	SystemPageFileInformationEx = 0x90,
	SystemSecureBootInformation = 0x91,
	SystemEntropyInterruptTimingRawInformation = 0x92,
	SystemPortableWorkspaceEfiLauncherInformation = 0x93,
	SystemFullProcessInformation = 0x94,
	SystemKernelDebuggerInformationEx = 0x95,
	SystemBootMetadataInformation = 0x96,
	SystemSoftRebootInformation = 0x97,
	SystemElamCertificateInformation = 0x98,
	SystemOfflineDumpConfigInformation = 0x99,
	SystemProcessorFeaturesInformation = 0x9a,
	SystemRegistryReconciliationInformation = 0x9b,
	MaxSystemInfoClass = 0x9c,
} SYSTEM_INFORMATION_CLASS;
///
///Syscall typedef
///

//using dxgk_submit_command_t = NTSTATUS(__fastcall*)(D3DKMT_SUBMITCOMMAND* data);
//NTSTATUS __fastcall DetourNtGdiDdDDISubmitCommand(D3DKMT_SUBMITCOMMAND* data);

typedef int64_t(*dxgk_submit_command_t)(D3DKMT_SUBMITCOMMAND* data);
int64_t __fastcall DetourNtGdiDdDDISubmitCommand(D3DKMT_SUBMITCOMMAND* data);

typedef HDC(*GetDC_t)(HWND hwnd);//verified

typedef BOOL(*PatBlt_t)(HDC hdcDest, INT x, INT y, INT cx, INT cy, DWORD dwRop);//verified

typedef HBRUSH (*SelectBrush_t)(HDC hdc, HBRUSH hbrush); //verified

typedef int (*ReleaseDC_t)(HDC hdc); //verified

typedef HBRUSH (*CreateSolidBrush_t)( COLORREF cr, HBRUSH hbr); //verified

typedef BOOL (*DeleteObjectApp_t)(HANDLE hobj); //verified

typedef BOOL (*ExtTextOutW_t)(IN HDC hDC, //verified
	IN INT 	XStart,
	IN INT 	YStart,
	IN UINT 	fuOptions,
	IN OPTIONAL LPRECT 	UnsafeRect,
	IN LPWSTR 	UnsafeString,
	IN INT 	Count,
	IN OPTIONAL LPINT 	UnsafeDx,
	IN DWORD 	dwCodePage
);

typedef HFONT (*HfontCreate_t)(IN PENUMLOGFONTEXDVW pelfw, IN ULONG cjElfw, IN LFTYPE lft, IN FLONG fl, IN PVOID pvCliData); //verified

typedef HFONT (*SelectFont_t)(_In_ HDC 	hdc, //verified
	_In_ HFONT 	hfont
);
///
/// Imports
///
extern "C" LPSTR PsGetProcessImageFileName(PEPROCESS Process);

extern "C" DRIVER_INITIALIZE DriverEntry;

void __fastcall SyscallStub(
	_In_ unsigned int SystemCallIndex,
	_Inout_ void** SystemCallFunction);

NTSTATUS initSysCalls();

extern "C" __declspec(dllimport)
PVOID
NTAPI
RtlImageDirectoryEntryToData(
	PVOID ImageBase,
	BOOLEAN MappedAsImage,
	USHORT DirectoryEntry,
	PULONG Size
);
extern "C"
__declspec(dllimport)
PVOID
NTAPI
RtlFindExportedRoutineByName(
	_In_ PVOID BaseOfImage,
	_In_ PCSTR RoutineName
);

extern "C" __declspec(dllimport) 
PPEB 
NTAPI 
PsGetProcessPeb(IN PEPROCESS Process);

extern "C" __declspec(dllimport) 
PVOID 
NTAPI 
PsGetProcessWow64Process(
	_In_ PEPROCESS Process
);
extern "C" __declspec(dllimport)
NTSTATUS
NTAPI
ZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);
///
///The functions
///
PVOID get_system_routine_address(LPCWSTR routine_name)
{
	UNICODE_STRING name;
	RtlInitUnicodeString(&name, routine_name);
	return MmGetSystemRoutineAddress(&name);
}
PVOID NTAPI RtlxFindExportedRoutineByName(_In_ PVOID DllBase, _In_ const char* ExportName)
{
	PULONG NameTable;
	PUSHORT OrdinalTable;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory;
	LONG Low = 0, Mid = 0, High, Ret;
	USHORT Ordinal;
	PVOID Function;
	ULONG ExportSize;
	PULONG ExportTable;

	ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(DllBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &ExportSize);
	if (!ExportDirectory)
		return NULL;

	NameTable = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNames);
	OrdinalTable = (PUSHORT)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNameOrdinals);
	High = ExportDirectory->NumberOfNames - 1;
	for (Low = 0; Low <= High; Low++)
	{
		Ret = strcmp(ExportName, (PCHAR)DllBase + NameTable[Low]);
		//PRINT("> NameTable %i : %s\n", Low, (PCHAR)DllBase + NameTable[Low]);
		if (Ret == 0) {
			//kprintf("> Found the thing\n");
			break;
		}
	}

	if (High < Low)
		return NULL;

	Ordinal = OrdinalTable[Low];
	if (Ordinal >= ExportDirectory->NumberOfFunctions)
		return NULL;

	ExportTable = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfFunctions);
	Function = (PVOID)((ULONG_PTR)DllBase + ExportTable[Ordinal]);
	return Function;
}
PVOID get_system_module_base(LPCWSTR module_name)
{
	//lkd > dt nt!_LDR_DATA_TABLE_ENTRY - l 0xffff8f8a`0f25f110
	//	at 0xffff8f8a`0f25f110
	//	-------------------------------------------- -
	//	+ 0x000 InLoadOrderlinks : _LIST_ENTRY[0xffff8f8a`0cee8c90 - 0xffff8f8a`0f25b010]
	//	+ 0x010 InMemoryOrderlinks : _LIST_ENTRY[0xfffff3ae`f4708000 - 0x00000000`00017034]
	//	+ 0x020 InInitializationOrderlinks : _LIST_ENTRY[0x00000000`00000000 - 0xffff8f8a`0f25f290]
	//	+ 0x030 DllBase          : 0xfffff3ae`f4520000 Void
	//	+ 0x038 EntryPoint       : 0xfffff3ae`f4751010 Void
	//	+ 0x040 SizeOfImage      : 0x26d000
	//	+ 0x048 FullDllName : _UNICODE_STRING "\SystemRoot\System32\win32kbase.sys"
	//	+ 0x058 BaseDllName : _UNICODE_STRING "win32kbase.sys"
	//	+ 0x068 FlagGroup : [4]  ""

	PVOID module_base = NULL;

	__try {

		PLIST_ENTRY module_list = reinterpret_cast<PLIST_ENTRY>(get_system_routine_address(L"PsLoadedModuleList"));

		if (!module_list)
			return NULL;

		UNICODE_STRING name;
		RtlInitUnicodeString(&name, module_name);

		//  InLoadOrderlinks.Flink at 0xffff8f8a`0f25f110
		//	-------------------------------------------- -
		//	+ 0x000 InLoadOrderlinks :  [0xffff8f8a`0cee8c90 - 0xffff8f8a`0f25b010]
		//	+ 0x048 FullDllName : _UNICODE_STRING "\SystemRoot\System32\win32kbase.sys"

		for (PLIST_ENTRY link = module_list; link != module_list->Blink; link = link->Flink)
		{
			LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			// DbgPrint( "driver: %ws\n", entry->FullDllName.Buffer );

			if (RtlEqualUnicodeString(&entry->BaseDllName, &name, TRUE))
			{
				module_base = entry->DllBase;
				break;
			}
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		module_base = NULL;
	}

	return module_base;
}
PVOID get_system_module_export(LPCWSTR module_name, LPCSTR routine_name)
{
	PVOID lpModule = get_system_module_base(module_name);
	//kprintf("[+] infinityhook: Found module_base %p.\n", lpModule);
	if (!lpModule)
		return NULL;

	return RtlxFindExportedRoutineByName(lpModule, routine_name);
	//return RtlFindExportedRoutineByName(lpModule, routine_name);
}