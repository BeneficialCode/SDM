// SDM.cpp : main source file for SDM.exe
//

#include "stdafx.h"

#include "resource.h"

#include "MainDlg.h"

CAppModule _Module;

int WINAPI _tWinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/, LPTSTR /*lpstrCmdLine*/, int /*nCmdShow*/)
{
	HRESULT hRes = ::CoInitialize(NULL);
	ATLASSERT(SUCCEEDED(hRes));

	AtlInitCommonControls(ICC_BAR_CLASSES);	// add flags to support other controls
	BOOL wow = false;
	if (IsWow64Process(GetCurrentProcess(), &wow));
	if (wow) {
		PVOID oldValue = nullptr;
		Wow64DisableWow64FsRedirection(&oldValue);
	}

	hRes = _Module.Init(nullptr, hInstance);
	ATLASSERT(SUCCEEDED(hRes));

	CMessageLoop ml;
	_Module.AddMessageLoop(&ml);

	CMainDlg dlg;
	dlg.Create(nullptr);
	dlg.ShowWindow(SW_SHOW);

	int ret = ml.Run();

	_Module.RemoveMessageLoop();
	_Module.Term();

	::CoUninitialize();

	return ret;
}
