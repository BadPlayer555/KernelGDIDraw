#include "main.h"

dxgk_submit_command_t OriginalNtGdiDdDDISubmitCommand = NULL;
GetDC_t NtUserGetDC = NULL;
SelectBrush_t NtGdiSelectBrush = NULL;
PatBlt_t NtGdiPatBlt = NULL;
ReleaseDC_t NtUserReleaseDC = NULL;
CreateSolidBrush_t NtGdiCreateSolidBrush = NULL;
DeleteObjectApp_t NtGdiDeleteObjectApp = NULL;
ExtTextOutW_t NtGdiExtTextOutW = NULL;
HfontCreate_t NtGdiHfontCreate = NULL;
SelectFont_t NtGdiSelectFont = NULL;

extern "C" NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	UNREFERENCED_PARAMETER(DriverObject);

	kprintf("[+] Test2: Loaded.\n");
	/*NTSTATUS Status = m_ShadowSSDT.InitializationShadowSSDT();
	if (!NT_SUCCESS(Status))
	{
		kprintf("[-] ShadowSSDT: InitializationShadowSSDT() An Error.GDIInitialization Internal Function\r\n");
		return Status;
	}
	kprintf("[+] ShadowSSDT: initialized with status: 0x%lx.\n", Status);*/

	NTSTATUS Status1 = initSysCalls();
	if (!NT_SUCCESS(Status1)) {
		kprintf("[-] infinityhook: Failed to initialize with status: 0x%lx.\n", Status1);
		return Status1;
	}
	kprintf("[+] SysCalls: initialized with status: 0x%lx.\n", Status1);

	NTSTATUS Status2 = IfhInitialize(SyscallStub);
	if (!NT_SUCCESS(Status2))
	{
		kprintf("[-] infinityhook: Failed to initialize with status: 0x%lx.\n", Status2);
		return Status2;
	}
	kprintf("[+] infinityhook: initialized with status: 0x%lx.\n", Status2);
	return STATUS_SUCCESS;
}

NTSTATUS initSysCalls() {
	NtUserGetDC = (GetDC_t)get_system_module_export(L"win32kbase.sys", "NtUserGetDC");
	kprintf("[+] SysCall: NtUserGetDC module_export: 0x%p \n", NtUserGetDC);
	NtGdiPatBlt = (PatBlt_t)get_system_module_export(L"win32kfull.sys", "NtGdiPatBlt");
	kprintf("[+] SysCall: NtGdiPatBlt module_export: 0x%p \n", NtGdiPatBlt);
	NtGdiSelectBrush = (SelectBrush_t)get_system_module_export(L"win32kbase.sys", "GreSelectBrush");
	kprintf("[+] SysCall: NtGdiSelectBrush module_export: 0x%p \n", NtGdiSelectBrush);
	NtUserReleaseDC = (ReleaseDC_t)get_system_module_export(L"win32kbase.sys", "NtUserReleaseDC");
	kprintf("[+] SysCall: NtUserReleaseDC module_export: 0x%p \n", NtUserReleaseDC);
	NtGdiCreateSolidBrush = (CreateSolidBrush_t)get_system_module_export(L"win32kfull.sys", "NtGdiCreateSolidBrush");
	kprintf("[+] SysCall: NtGdiCreateSolidBrush module_export: 0x%p \n", NtGdiCreateSolidBrush);
	NtGdiDeleteObjectApp = (DeleteObjectApp_t)get_system_module_export(L"win32kbase.sys", "NtGdiDeleteObjectApp");//NtGdiDeleteObjectApp
	kprintf("[+] SysCall: NtGdiDeleteObjectApp module_export: 0x%p \n", NtGdiDeleteObjectApp);
	NtGdiExtTextOutW = (ExtTextOutW_t)get_system_module_export(L"win32kfull.sys", "NtGdiExtTextOutW");
	kprintf("[+] SysCall: NtGdiExtTextOutW module_export: 0x%p \n", NtGdiExtTextOutW);
	NtGdiHfontCreate = (HfontCreate_t)get_system_module_export(L"win32kfull.sys", "hfontCreate");
	kprintf("[+] SysCall: NtGdiHfontCreate module_export: 0x%p \n", NtGdiHfontCreate);
	NtGdiSelectFont = (SelectFont_t)get_system_module_export(L"win32kfull.sys", "NtGdiSelectFont");
	kprintf("[+] SysCall: NtGdiSelectFont module_export: 0x%p \n", NtGdiSelectFont);
	//Checks syscall
	if (NtUserGetDC == NULL) {
		return STATUS_UNSUCCESSFUL;
	}
	if (NtUserReleaseDC == NULL) {
		return STATUS_UNSUCCESSFUL;
	}
	if (NtGdiCreateSolidBrush == NULL) {
		return STATUS_UNSUCCESSFUL;
	}
	if (NtGdiDeleteObjectApp == NULL) {
		return STATUS_UNSUCCESSFUL;
	}
	if (NtGdiSelectBrush == NULL) {
		return STATUS_UNSUCCESSFUL;
	}
	if (NtGdiPatBlt == NULL) {
		return STATUS_UNSUCCESSFUL;
	}
	if (NtGdiExtTextOutW == NULL) {
		return STATUS_UNSUCCESSFUL;
	}
	if (NtGdiHfontCreate == NULL) {
		return STATUS_UNSUCCESSFUL;
	}
	if (NtGdiSelectFont == NULL) {
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}

void __fastcall SyscallStub(
	_In_ unsigned int SystemCallIndex,
	_Inout_ void** SystemCallFunction)
{
	/*if (SystemCallIndex == NTUSERGETDC_SYSCALL_INDEX) {
		kprintf("[+] infinityhook: NtUserGetDC 0x100d SYSCALL %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
		//NtUserGetDC = (GetDC_t)*SystemCallFunction;
		NtUserGetDC = (GetDC_t)get_system_module_export(L"win32kbase.sys", "NtUserGetDC");
		kprintf("[+] infinityhook: NtUserGetDC module_export: 0x%p \n", NtUserGetDC);
		//kprintf("[+] infinityhook: NtUserGetDC ShadowSSDT: 0x%p \n", m_ShadowSSDT.Get3SDTFunAddress(L"NtUserGetDC"));
	}
	if (SystemCallIndex == NTGDIPATBLT_SYSCALL_INDEX) {
		kprintf("[+] infinityhook: NtGdiPatBlt 0x105c SYSCALL %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
		//NtGdiPatBlt = (PatBlt_t)*SystemCallFunction;
		NtGdiPatBlt = (PatBlt_t)get_system_module_export(L"win32kfull.sys", "NtGdiPatBlt");
		kprintf("[+] infinityhook: NtGdiPatBlt module_export: 0x%p \n", NtGdiPatBlt);
	}
	if (SystemCallIndex == NTGDISELECTBRUSH_SYSCALL_INDEX) {
		kprintf("[+] infinityhook: NtGdiSelectBrush 0x1302 SYSCALL %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
		//NtGdiSelectBrush = (SelectBrush_t)*SystemCallFunction;
		NtGdiSelectBrush = (SelectBrush_t)get_system_module_export(L"win32kfull.sys", "NtGdiSelectBrush");
		kprintf("[+] infinityhook: NtGdiSelectBrush module_export: 0x%p \n", NtGdiSelectBrush);
	}
	if (SystemCallIndex == NTUSERRELEASEDC_SYSCALL_INDEX) {
		kprintf("[+] infinityhook: NtUserReleaseDC 0x1477 SYSCALL %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
		NtUserReleaseDC = (ReleaseDC_t)*SystemCallFunction;
	}
	if (SystemCallIndex == NTGDICREATESOLIDBRUSH_SYSCALL_INDEX) {
		kprintf("[+] infinityhook: NtGdiCreateSolidBrush 0x10b3 SYSCALL %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
		NtGdiCreateSolidBrush = (CreateSolidBrush_t)*SystemCallFunction;
	}
	if (SystemCallIndex == NTGDIDELETEOBJECTAPP_SYSCALL_INDEX) {
		kprintf("[+] infinityhook: NtGdiDeleteObjectApp 0x10b3 SYSCALL %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
		NtGdiDeleteObjectApp = (DeleteObjectApp_t)*SystemCallFunction;
	}*/
	if (SystemCallIndex == NTGDIDDDDISUBMMITCOMMAND_SYSCALL_INDEX) {
		kprintf("[+] infinityhook: NtGdiDdDDISubmitCommand 0x1250 SYSCALL %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
		if (*SystemCallFunction != DetourNtGdiDdDDISubmitCommand) {
			OriginalNtGdiDdDDISubmitCommand = (dxgk_submit_command_t)*SystemCallFunction;
			*SystemCallFunction = DetourNtGdiDdDDISubmitCommand;
		}
		else {
			kprintf("[+] infinityhook: It is hooked wtf.\n");
		}
	}
}

PVOID AllocateVirtualMemory(SIZE_T Size)
{
	PVOID pMem = NULL;
	NTSTATUS statusAlloc = ZwAllocateVirtualMemory(NtCurrentProcess(), &pMem, 0, &Size, MEM_COMMIT, PAGE_READWRITE);
	//kprintf("[+] AllocateVirtualMemory statusAlloc: %x \n", statusAlloc);
	return pMem;
}

VOID FreeVirtualMemory(PVOID VirtualAddress, SIZE_T Size)
{
	if (MmIsAddressValid(VirtualAddress))
	{
		NTSTATUS Status = ZwFreeVirtualMemory(NtCurrentProcess(), &VirtualAddress, &Size, MEM_RELEASE);

		if (!NT_SUCCESS(Status)) {
			kprintf("[-] GDI.cpp Warning : Released memory failed.FreeVirtualMemory Internal Function\r\n");
		}
		return;
	}
	kprintf("[-] GDI.cpp Warning: Released memory does not exist.FreeVirtualMemory Internal Function\r\n");
}

BOOL extTextOutW(HDC hdc, INT x, INT y, UINT fuOptions, RECT * lprc, LPWSTR lpString, UINT cwc, INT * lpDx)
{
	BOOL		nRet = FALSE;
	PVOID       local_lpString = NULL;
	RECT*       local_lprc = NULL;
	INT*        local_lpDx = NULL;

	if (lprc != NULL)
	{
		SIZE_T Len = sizeof(RECT);
		local_lprc = (RECT *)AllocateVirtualMemory(Len);
		if (local_lprc != NULL)
		{
			__try
			{
				RtlZeroMemory(local_lprc, Len);
				RtlCopyMemory(local_lprc, lprc, Len);
			}
			__except (1)
			{
				kprintf("GDI.cpp Line RtlCopyMemory  Triggers An Error.ExtTextOutW Internal Function\r\n");
				goto $EXIT;
			}
		}
		else
		{
			kprintf("GDI.cpp Line local_lprc = null  Triggers An Error.ExtTextOutW Internal Function\r\n");
			goto $EXIT;
		}
	}

	if (cwc != 0)
	{
		SIZE_T     AllocSize = sizeof(WCHAR)*cwc + 1;
		local_lpString = AllocateVirtualMemory(AllocSize);

		if (local_lpString != NULL)
		{
			__try
			{
				RtlZeroMemory(local_lpString, AllocSize);
				RtlCopyMemory(local_lpString, lpString, AllocSize);
			}
			__except (1)
			{
				kprintf("[-] GDI.cpp Line RtlCopyMemory  Triggers An Error.ExtTextOutW Internal Function\r\n");
				goto $EXIT;
			}
		}
		else
		{
			kprintf("[-] GDI.cpp Line local_lpString = null  Triggers An Error.ExtTextOutW Internal Function\r\n");
			goto $EXIT;
		}
	}

	if (local_lpDx != NULL)
	{
		SIZE_T     AllocSize = sizeof(INT);
		local_lpDx = (INT *)AllocateVirtualMemory(AllocSize);
		if (local_lpDx != NULL)
		{
			__try
			{
				RtlZeroMemory(local_lpString, AllocSize);
				*local_lpDx = *lpDx;
			}
			__except (1)
			{
				kprintf("[-] GDI.cpp Line RtlCopyMemory  Triggers An Error.ExtTextOutW Internal Function\r\n");
				goto $EXIT;
			}
		}
		else
		{
			kprintf("[-] GDI.cpp Line local_lpDx = null  Triggers An Error.ExtTextOutW Internal Function\r\n");
		}
	}

	if (NtGdiExtTextOutW != NULL) {
		nRet = NtGdiExtTextOutW(hdc, x, y, fuOptions, local_lprc, (LPWSTR)local_lpString, cwc, local_lpDx, 0);
	}
	else {
		kprintf("[-] GDI.cpp Line NtGdiExtTextOutW = NULL Triggers An Error.TextOutW Internal Function\r\n");
	}
$EXIT:
	if (lprc != NULL)
	{
		FreeVirtualMemory(lprc, sizeof(RECT));
		lprc = NULL;
	}

	if (local_lpDx != NULL)
	{
		FreeVirtualMemory(local_lpDx, sizeof(INT));
		local_lpDx = NULL;
	}

	if (local_lpString != NULL)
	{
		FreeVirtualMemory(local_lpString, cwc);
		local_lpString = NULL;
	}

	return nRet;
}

BOOL extTextOutA(HDC hdc, INT x, INT y, UINT fuOptions, RECT * lprc, LPCSTR lpString, UINT cch, INT * lpDx)
{
	ANSI_STRING StringA;
	UNICODE_STRING StringU;
	BOOL ret;
	RtlInitAnsiString(&StringA, (LPSTR)lpString);
	RtlAnsiStringToUnicodeString(&StringU, &StringA, TRUE);
	ret = extTextOutW(hdc, x, y, fuOptions, lprc, StringU.Buffer, cch, lpDx);
	RtlFreeUnicodeString(&StringU);
	return ret;
}

PVOID GetProcessPeb(PEPROCESS Eprocess)
{
	PVOID pPeb = PsGetProcessPeb(Eprocess);
	if (pPeb == NULL)
	{
		pPeb = PsGetProcessWow64Process(Eprocess);
		if (pPeb == NULL)
		{
			kprintf("Process.cpp PsGetProcessWow64Process() An Error.GetProcessPeb Internal Function");
		}
	}
	return pPeb;
}

BOOL GdiGetHandleUserData(HGDIOBJ hGdiObj, DWORD ObjectType, PVOID * UserData)
{
	PEPROCESS Eprocess = IoGetCurrentProcess();
	PVOID ppeb = GetProcessPeb(Eprocess);
	//kprintf("[+] ppeb: %p \n",ppeb);
	if (ppeb == NULL) {
		kprintf("SetTextColor.cpp GetProcessPeb() An Error.GdiGetHandleUserData() Internal Function\r\n");
	}
	GDICELL* Entry = (GDICELL*)*(LPVOID*)((ULONG64)ppeb + 0xF8);//GdiSharedHandleTable
	if (Entry == NULL) {
		kprintf("SetTextColor.cpp Entry == NULL An Error.GdiGetHandleUserData() Internal Function\r\n");
		return FALSE;
	}
	Entry = Entry + GDI_HANDLE_GET_INDEX(hGdiObj);
	if (Entry == NULL) {
		kprintf("SetTextColor.cpp  Entry + GDI_HANDLE_GET_INDEX(hGdiObj) == NULL An Error.GdiGetHandleUserData() Internal Function\r\n");
		return FALSE;
	}

	if (MmIsAddressValid(Entry->pUserAddress) != TRUE) {
		kprintf("SetTextColor.cpp  MmIsAddressValid(Entry->pUserAddress) != TRUE An Error.GdiGetHandleUserData() Internal Function\r\n");
		return FALSE;
	}

	*UserData = Entry->pUserAddress;
	//kprintf("[+] UserData: %p \n", *UserData);
	//kprintf("[+] Entry->pUserAddress: %p \n", Entry->pUserAddress);

	return TRUE;
}

PDC_ATTR GdiGetDcAttr(HDC hdc)
{

	GDILOOBJTYPE eDcObjType;
	PDC_ATTR pdcattr;

	/* Check DC object type */
	eDcObjType = (GDILOOBJTYPE)GDI_HANDLE_GET_TYPE(hdc); //ok
	//kprintf("[+] eDcObjType: %x \n", eDcObjType);

	if ((eDcObjType != GDILoObjType_LO_DC_TYPE) &&
		(eDcObjType != GDILoObjType_LO_ALTDC_TYPE))
	{
		return NULL;
	}
	if (!GdiGetHandleUserData((HGDIOBJ)hdc, eDcObjType, (PVOID*)&pdcattr))
	{
		return NULL;
	}
	return pdcattr;


}
COLORREF SetTextColor(HDC hdc, COLORREF crColor)
{
	PDC_ATTR pdcattr;
	COLORREF crOldColor;
	pdcattr = GdiGetDcAttr(hdc);
	kprintf("[+] pdcattr pointer: %p \n", pdcattr);
	kprintf("[+] pdcattr crForegroundClr: %x \n", pdcattr->crForegroundClr);
	kprintf("[+] pdcattr ulForegroundClr: %x \n", pdcattr->ulForegroundClr);
	kprintf("[+] pdcattr iGraphicsMode: %i \n", pdcattr->iGraphicsMode);
	kprintf("[+] pdcattr crBackgroundClr: %x \n", pdcattr->crBackgroundClr);
	kprintf("[+] pdcattr ulBackgroundClr: %x \n", pdcattr->ulBackgroundClr);
	kprintf("[+] pdcattr crBrushClr: %x \n", pdcattr->crBrushClr);
	kprintf("[+] pdcattr dwLayout: %x \n", pdcattr->dwLayout);
	if (pdcattr == NULL)
	{
		return CLR_INVALID;
	}

	crOldColor = (COLORREF)pdcattr->ulForegroundClr;
	pdcattr->ulForegroundClr = (ULONG)crColor;

	if (pdcattr->crForegroundClr != crColor)
	{
		//kprintf("[+] They are not the same color\n");
		pdcattr->ulDirty_ |= (DIRTY_TEXT | DIRTY_LINE | DIRTY_FILL);
		pdcattr->crForegroundClr = crColor;
	}

	return crOldColor;
}
int SetBkMode(
	_In_ HDC hdc,
	_In_ int iBkMode)
{
	PDC_ATTR pdcattr;
	INT iOldMode;

	/* Get the DC attribute */
	pdcattr = GdiGetDcAttr(hdc);
	if (pdcattr == NULL)
	{
		return 0;
	}

	iOldMode = pdcattr->lBkMode;
	pdcattr->jBkMode = iBkMode; // Processed
	pdcattr->lBkMode = iBkMode; // Raw

	return iOldMode;
}

bool FrameRect(HDC hDC, CONST RECT *lprc, HBRUSH hbr)
{
	HBRUSH oldbrush = NULL;
	RECT r = *lprc;

	if ((r.right <= r.left) || (r.bottom <= r.top)) return false;
	//if (!(oldbrush = NtGdiSelectBrush(hDC, hbr))) return false;
	oldbrush = NtGdiSelectBrush(hDC, hbr);
	NtGdiPatBlt(hDC, r.left, r.top, 1, r.bottom - r.top, PATCOPY);
	NtGdiPatBlt(hDC, r.right - 1, r.top, 1, r.bottom - r.top, PATCOPY);
	NtGdiPatBlt(hDC, r.left, r.top, r.right - r.left, 1, PATCOPY);
	NtGdiPatBlt(hDC, r.left, r.bottom - 1, r.right - r.left, 1, PATCOPY);

	if (oldbrush)
		NtGdiSelectBrush(hDC, oldbrush);
	return true;
}

bool FillRect(HDC hDC, CONST RECT *lprc, HBRUSH hbr)
{
	BOOL Ret;
	HBRUSH prevhbr = NULL;

	/* Select brush if specified */
	/*if (hbr)
	{
		/* Handle system colors
		/*if (hbr <= (HBRUSH)(COLOR_MENUBAR + 1))
			hbr = GetSysColorBrush(PtrToUlong(hbr) - 1);

		prevhbr = NtGdiSelectBrush(hDC, hbr);
		if (prevhbr == NULL)
			return (INT)FALSE;
	}*/
	prevhbr = NtGdiSelectBrush(hDC, hbr);
	Ret = NtGdiPatBlt(hDC, lprc->left, lprc->top, lprc->right - lprc->left,
		lprc->bottom - lprc->top, PATCOPY);

	/* Select old brush */
	if (prevhbr)
		NtGdiSelectBrush(hDC, prevhbr);

	return Ret;
}
bool FillRect(HDC hDC, int x, int y, int w, int h, HBRUSH hbr)
{
	BOOL Ret;
	HBRUSH prevhbr = NULL;

	RECT lprc = { x, y, x + w, y + h };
	prevhbr = NtGdiSelectBrush(hDC, hbr);
	Ret = NtGdiPatBlt(hDC, lprc.left, lprc.top, lprc.right - lprc.left,
		lprc.bottom - lprc.top, PATCOPY);

	/* Select old brush */
	if (prevhbr)
		NtGdiSelectBrush(hDC, prevhbr);

	return Ret;
}
bool DrawBorderBox(HDC hDC, int x, int y, int w, int h, int thickness, HBRUSH hbr)
{
	BOOL Ret;
	HBRUSH prevhbr = NULL;
	FillRect(hDC, x, y, w, thickness, hbr); //Top horiz line
	FillRect(hDC, x, y, thickness, h, hbr); //Left vertical line
	FillRect(hDC, (x + w), y, thickness, h, hbr); //right vertical line
	FillRect(hDC, x, y + h, w + thickness, thickness, hbr); //bottom horiz line
	return true;
}

HFONT
CreateFontIndirectExW(const ENUMLOGFONTEXDVW *elfexd)
{
	/* Msdn: Note, this function ignores the elfDesignVector member in
			 ENUMLOGFONTEXDV.
	 */
	if (elfexd)
	{
		return NtGdiHfontCreate((PENUMLOGFONTEXDVW)elfexd, 0, 0, 0, NULL);
	}
	else {
		kprintf("[-] CreateFontIndirectExW elfexd is missing");
		return NULL;
	}
}
HFONT
CreateFontIndirectW(
	CONST LOGFONTW      *lplf
)
{
	if (lplf)
	{
		ENUMLOGFONTEXDVW Logfont;

		RtlCopyMemory(&Logfont.elfEnumLogfontEx.elfLogFont, lplf, sizeof(LOGFONTW));
		// Need something other than just cleaning memory here.
		// Guess? Use caller data to determine the rest.
		RtlZeroMemory(&Logfont.elfEnumLogfontEx.elfFullName,
			sizeof(Logfont.elfEnumLogfontEx.elfFullName));
		RtlZeroMemory(&Logfont.elfEnumLogfontEx.elfStyle,
			sizeof(Logfont.elfEnumLogfontEx.elfStyle));
		RtlZeroMemory(&Logfont.elfEnumLogfontEx.elfScript,
			sizeof(Logfont.elfEnumLogfontEx.elfScript));

		Logfont.elfDesignVector.dvNumAxes = 0; // No more than MM_MAX_NUMAXES

		RtlZeroMemory(&Logfont.elfDesignVector, sizeof(DESIGNVECTOR));

		return CreateFontIndirectExW(&Logfont);
	}
	else {
		kprintf("[-] CreateFontIndirectW lplf is missing");
		return NULL;
	}
}

HFONT CreateFontW(int nHeight,
	int nWidth,
	int nEscapement,
	int nOrientation,
	int nWeight,
	DWORD   fnItalic,
	DWORD   fdwUnderline,
	DWORD   fdwStrikeOut,
	DWORD   fdwCharSet,
	DWORD   fdwOutputPrecision,
	DWORD   fdwClipPrecision,
	DWORD   fdwQuality,
	DWORD   fdwPitchAndFamily,
	LPCWSTR lpszFace) {
	LOGFONTW logfont;
	logfont.lfHeight = nHeight;
	logfont.lfWidth = nWidth;
	logfont.lfEscapement = nEscapement;
	logfont.lfOrientation = nOrientation;
	logfont.lfWeight = nWeight;
	logfont.lfItalic = (BYTE)fnItalic;
	logfont.lfUnderline = (BYTE)fdwUnderline;
	logfont.lfStrikeOut = (BYTE)fdwStrikeOut;
	logfont.lfCharSet = (BYTE)fdwCharSet;
	logfont.lfOutPrecision = (BYTE)fdwOutputPrecision;
	logfont.lfClipPrecision = (BYTE)fdwClipPrecision;
	logfont.lfQuality = (BYTE)fdwQuality;
	logfont.lfPitchAndFamily = (BYTE)fdwPitchAndFamily;
	if (NULL != lpszFace)
	{
		int Size = sizeof(logfont.lfFaceName) / sizeof(WCHAR);
		wcsncpy((wchar_t *)logfont.lfFaceName, lpszFace, Size - 1);
		/* Be 101% sure to have '\0' at end of string */
		logfont.lfFaceName[Size - 1] = '\0';
	}
	else
	{
		logfont.lfFaceName[0] = L'\0';
	}
	return CreateFontIndirectW(&logfont);
}

int
GetBkMode(HDC hdc)
{
	PDC_ATTR pdcattr;

	/* Get the DC attribute */
	pdcattr = GdiGetDcAttr(hdc);
	if (pdcattr == NULL)
	{
		/* Don't set LastError here! */
		return 0;
	}

	return pdcattr->lBkMode;
}

COLORREF
SetBkColor(
	_In_ HDC hdc,
	_In_ COLORREF crColor)
{
	PDC_ATTR pdcattr;
	COLORREF crOldColor;

	/* Get the DC attribute */
	pdcattr = GdiGetDcAttr(hdc);
	if (pdcattr == NULL)
	{
		return CLR_INVALID;
	}

	/* Get old color and store the new */
	crOldColor = pdcattr->ulBackgroundClr;
	pdcattr->ulBackgroundClr = crColor;

	if (pdcattr->crBackgroundClr != crColor)
	{
		pdcattr->ulDirty_ |= (DIRTY_BACKGROUND | DIRTY_LINE | DIRTY_FILL);
		pdcattr->crBackgroundClr = crColor;
	}
	return crOldColor;
}

COLORREF
GetBkColor(
	_In_ HDC hdc)
{
	PDC_ATTR pdcattr;

	/* Get the DC attribute */
	pdcattr = GdiGetDcAttr(hdc);
	if (pdcattr == NULL)
	{
		/* Don't set LastError here! */
		return CLR_INVALID;
	}

	return pdcattr->ulBackgroundClr;
}

int64_t __fastcall DetourNtGdiDdDDISubmitCommand(
	D3DKMT_SUBMITCOMMAND* data)
{

	//DEBUG info
	kprintf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n");
	kprintf("[+] NtGdiDdDDISubmitCommand: Sucessfully hooked \n");
	kprintf("[+] NtGdiDdDDISubmitCommand: Commands %p \n", data->Commands);
	kprintf("[+] NtGdiDdDDISubmitCommand: CommandLength %i \n", data->CommandLength);
	kprintf("[+] NtGdiDdDDISubmitCommand: SUBMITCOMMANDFLAGS %i %i %i \n", data->Flags.NullRendering, data->Flags.PresentRedirected, data->Flags.Reserved);
	kprintf("[+] NtGdiDdDDISubmitCommand: BroadcastContextCount %i \n", data->BroadcastContextCount);
	kprintf("[+] NtGdiDdDDISubmitCommand: PrivateDriverDataSize %i \n", data->PrivateDriverDataSize);
	kprintf("[+] NtGdiDdDDISubmitCommand: NumPrimaries %i \n", data->NumPrimaries);
	kprintf("[+] NtGdiDdDDISubmitCommand: NumHistoryBuffers %i \n", data->NumHistoryBuffers);

	//get process name
	PEPROCESS current_process = IoGetCurrentProcess();
	int pid = (int)PsGetProcessId(current_process);
	kprintf("[+] NtGdiDdDDISubmitCommand: Process ID %i \n", pid);

	//UNICODE_STRING process_name = getProcessNameByPid(pid);
	//kprintf("[+] NtGdiDdDDISubmitCommand: Process %wZ \n", process_name);
	char* process_name = PsGetProcessImageFileName(current_process);
	kprintf("[+] NtGdiDdDDISubmitCommand: Process %s \n", process_name);

	//Get Context
	HDC hdc = NtUserGetDC(NULL);
	if (hdc == NULL) {
		kprintf("[-] NtGdiDdDDISubmitCommand: The handle is NULL\n");
		return OriginalNtGdiDdDDISubmitCommand(data);
	}
	else {
		kprintf("[+] NtGdiDdDDISubmitCommand: The handle have something %p\n", hdc);
	}

	//Draw shit
	HBRUSH brush = NtGdiCreateSolidBrush(RGB(255, 255, 255), NULL);
	kprintf("[+] NtGdiDdDDISubmitCommand: Brush %p\n", brush);
	HBRUSH brush1 = NtGdiCreateSolidBrush(RGB(0, 255, 0), NULL);
	kprintf("[+] NtGdiDdDDISubmitCommand: Brush %p\n", brush1);

	RECT rect = { 0, 0, 200, 200 };

	bool drawFillRect = FillRect(hdc, &rect, brush);
	if (drawFillRect) {
		kprintf("[+] NtGdiDdDDISubmitCommand: drawFillRect Sucess\n");
	}
	else {
		kprintf("[-] NtGdiDdDDISubmitCommand: drawFillRect oof \n");
	}
	bool borderSucess = DrawBorderBox(hdc, 0, 200, 100, 200, 3, brush1);
	if (borderSucess) {
		kprintf("[+] NtGdiDdDDISubmitCommand: border Sucess \n");
	}
	else {
		kprintf("[-] NtGdiDdDDISubmitCommand: border oof \n");
	}
	//DEFAULT_CHARSET
	HFONT font = CreateFontW(65, 0, 0, 0, FW_NORMAL, 0, 0, 0, CHINESEBIG5_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY, FF_DONTCARE, L"Arial");//L"Arial"
	kprintf("[+] NtGdiDdDDISubmitCommand: font %p\n", font);
	HFONT oldfont = NtGdiSelectFont(hdc, font);

	bool textSucess = extTextOutW(hdc, 0, 500, 0, NULL, L"习大大万岁万万岁!", 9, 0);
	if (textSucess) {
		kprintf("[+] NtGdiDdDDISubmitCommand: text Sucess\n");
	}
	else {
		kprintf("[-] NtGdiDdDDISubmitCommand: text oof \n");
	}

	//clean up
	bool deleted = NtGdiDeleteObjectApp(brush);
	kprintf("[+] NtGdiDdDDISubmitCommand: deleted %i\n", deleted);
	bool deleted1 = NtGdiDeleteObjectApp(brush1);
	kprintf("[+] NtGdiDdDDISubmitCommand: deleted %i\n", deleted1);
	NtGdiSelectFont(hdc, oldfont);
	bool deleted2 = NtGdiDeleteObjectApp(font);
	kprintf("[+] NtGdiDdDDISubmitCommand: deleted %i\n", deleted2);
	int releaseStatus = NtUserReleaseDC(hdc);
	kprintf("[+] NtGdiDdDDISubmitCommand: ReleaseStatus %i \n", releaseStatus);
	kprintf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n");
	return OriginalNtGdiDdDDISubmitCommand(data);
}




/* Experimental or broken shit
	 PVOID pBuf = NULL;
UNICODE_STRING getProcessNameByPid(int pid) { //blackbone shit
	pBuf = ExAllocatePoolWithTag(NonPagedPool, 1024 * 1024, 'enoB');
	PSYSTEM_PROCESS_INFO pInfo = (PSYSTEM_PROCESS_INFO)pBuf;
	UNICODE_STRING Error = RTL_CONSTANT_STRING(L"Error");
	if (!pInfo)
	{
		ExFreePoolWithTag(pBuf, 'enoB');
		kprintf("[-] Failed to allocate memory for process list\n");
		return Error;
	}

	// Get the process thread list
	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, pInfo, 1024 * 1024, NULL);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(pBuf, 'enoB');
		return Error;
	}

	// Find target thread
	if (NT_SUCCESS(status))
	{
		status = STATUS_NOT_FOUND;
		for (;;)
		{
			if ((int)pInfo->UniqueProcessId == pid) {
				UNICODE_STRING result = pInfo->ImageName;
				return result;
				break;
			}
			else if (pInfo->NextEntryOffset)
				pInfo = (PSYSTEM_PROCESS_INFO)((PUCHAR)pInfo + pInfo->NextEntryOffset);
			else
				break;
		}
	}
	ExFreePoolWithTag(pBuf, 'enoB');
	return Error;
}



	//SetTextColor(hdc, oldcolor);

	//LPSTR process_name = PsGetProcessImageFileName(current_process);

	bool drawSucess = FrameRect(hdc, &rect, brush1);
	if (drawSucess) {
		kprintf("[+] NtGdiDdDDISubmitCommand: draw Sucess \n");
	}
	else {
		kprintf("[-] NtGdiDdDDISubmitCommand: draw oof \n");
	}


	COLORREF oldBkcolor = SetBkColor(hdc, RGB(255, 255, 255));
	kprintf("[+] NtGdiDdDDISubmitCommand: oldBkcolor: %x \n", oldBkcolor);
	COLORREF Bkcolor = GetBkColor(hdc);
	kprintf("[+] NtGdiDdDDISubmitCommand: Bkcolor: %x \n", Bkcolor);

	COLORREF oldcolor = SetTextColor(hdc, RGB(0, 255, 0));
	kprintf("[+] NtGdiDdDDISubmitCommand: oldcolor: %x \n", oldcolor);

	int oldBkmode = SetBkMode(hdc, TRANSPARENT);
	kprintf("[+] NtGdiDdDDISubmitCommand: oldBkmode: %i \n", oldBkmode);
	int Bkmode = GetBkMode(hdc);
	kprintf("[+] NtGdiDdDDISubmitCommand: Bkmode: %i \n", Bkmode);
*/