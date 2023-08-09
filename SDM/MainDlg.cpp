// MainDlg.cpp : implementation of the CMainDlg class
//
/////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "resource.h"

#include "MainDlg.h"
#include <filesystem>
#include <fstream>
#include "PEParser.h"
#include <WinInet.h>

#pragma comment(lib,"Wininet")
#pragma comment(lib,"ntdll")

BOOL CMainDlg::PreTranslateMessage(MSG* pMsg) {
	if (m_hAccel && ::TranslateAccelerator(*this, m_hAccel, pMsg))
		return TRUE;
	return CWindow::IsDialogMessage(pMsg);
}

LRESULT CMainDlg::OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
{
	// center the dialog on the screen
	CenterWindow();
	
	m_List.Attach(GetDlgItem(IDC_LIST));
	m_List.SetExtendedListViewStyle(LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_INFOTIP);
	m_Progress.Attach(GetDlgItem(IDC_PROGRESS1));

	m_hAccel = AtlLoadAccelerators(IDR_MAINFRAME);

	_Module.GetMessageLoop()->AddMessageFilter(this);

	CImageList images;
	images.Create(16, 16, ILC_COLOR32, 2, 2);
	images.AddIcon(AtlLoadIconImage(IDI_FILE, 0, 16, 16));
	images.AddIcon(AtlLoadIconImage(IDI_FOLDER, 0, 16, 16));
	m_List.SetImageList(images, LVSIL_SMALL);

	m_List.InsertColumn(0, L"Source", LVCFMT_LEFT, 300);
	m_List.InsertColumn(1, L"Size", LVCFMT_RIGHT, 100);
	m_List.InsertColumn(2, L"Destination", LVCFMT_LEFT, 250);
	// m_List.InsertColumn(3, L"Pdb Path", LVCFMT_LEFT, 200);

	// set icons
	HICON hIcon = AtlLoadIconImage(IDR_MAINFRAME, LR_DEFAULTCOLOR, ::GetSystemMetrics(SM_CXICON), ::GetSystemMetrics(SM_CYICON));
	SetIcon(hIcon, TRUE);
	HICON hIconSmall = AtlLoadIconImage(IDR_MAINFRAME, LR_DEFAULTCOLOR, ::GetSystemMetrics(SM_CXSMICON), ::GetSystemMetrics(SM_CYSMICON));
	SetIcon(hIconSmall, FALSE);

	WCHAR path[MAX_PATH];
	::GetCurrentDirectory(MAX_PATH, path);
	wcscat_s(path, L"\\bin");
	bool isExist = std::filesystem::is_directory(path);
	if (isExist) {
		m_CanDownload = true;
	}

	UpdateButtons();

	return TRUE;
}

void CMainDlg::UpdateButtons() {
	auto count = m_List.GetItemCount();
	GetDlgItem(IDC_PULL).EnableWindow(!m_Running);
	GetDlgItem(IDC_DOWNLOAD).EnableWindow(m_CanDownload);
	auto selected = m_List.GetSelectedCount();
	GetDlgItem(IDC_REMOVE).EnableWindow(!m_Running && selected > 0);
	GetDlgItem(IDC_SET_DEST).EnableWindow(!m_Running && selected > 0 || (m_Destinations == 0 && count > 0));
	GetDlgItem(IDC_ADD_FILES).EnableWindow(!m_Running);
}

LRESULT CMainDlg::OnAppAbout(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
	CSimpleDialog<IDD_ABOUTBOX, FALSE> dlg;
	dlg.DoModal();
	return 0;
}

LRESULT CMainDlg::OnCancel(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
	if (m_Running) {
		AtlMessageBox(*this, L"Copy in progress... cannot close application", IDR_MAINFRAME, MB_ICONWARNING);
		return 0;
	}
	DestroyWindow();
	return 0;
}

LRESULT CMainDlg::OnDestroy(UINT, WPARAM, LPARAM, BOOL&) {
	PostQuitMessage(0);
	return 0;
}

std::string CMainDlg::GetNtosFileName() {
	ULONG size = 1 << 18;
	wil::unique_virtualalloc_ptr<> buffer(::VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	NTSTATUS status;
	status = ::NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation),
		buffer.get(), size, nullptr);
	if (!NT_SUCCESS(status)) {
		return "";
	}

	auto info = (RTL_PROCESS_MODULES*)buffer.get();

	std::string name;
	name = std::string((PCSTR)((BYTE*)info->Modules[0].FullPathName + info->Modules[0].OffsetToFileName));
	return name;
}

std::wstring CMainDlg::StringToWstring(const std::string& str) {
	int len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
	len += 1;
	std::unique_ptr<wchar_t[]> buffer = std::make_unique<wchar_t[]>(len);
	memset(buffer.get(), 0, sizeof(wchar_t) * len);
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.size(), buffer.get(), len);
	std::wstring wstr(buffer.get());
	return wstr;
}

void CMainDlg::AddFile(std::wstring fileName) {
	WCHAR path[MAX_PATH];
	::GetSystemDirectory(path, MAX_PATH);
	wcscat_s(path, L"\\");
	wcscat_s(path, fileName.c_str());
	wil::unique_handle hFile(::CreateFile(path, 0, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
	if (!hFile) {
		AtlMessageBox(*this, L"Failed to open the file", IDR_MAINFRAME, MB_ICONEXCLAMATION);
		return;
	}
	LARGE_INTEGER size;
	::GetFileSizeEx(hFile.get(), &size);
	int n = m_List.AddItem(m_List.GetItemCount(), 0, path, 0);
	m_List.SetItemText(n, 1, FormatSize(size.QuadPart));
	m_List.SetItemData(n, (DWORD_PTR)Type::File);
	m_List.EnsureVisible(m_List.GetItemCount() - 1, FALSE);
	UpdateButtons();
}

void CMainDlg::SetDestination(std::wstring path) {
	auto count = m_List.GetItemCount();
	for (int i = 0; i < count; i++)
		m_List.SetItemText(i, 2, path.c_str());
	m_Destinations = count;
}

void CMainDlg::StartCopy() {
	m_OperationCount = 0;

	for (auto& data : m_Data) {
		// open source file for async I/O
		wil::unique_handle hSrc(::CreateFile(data.Src, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 
			FILE_FLAG_OVERLAPPED, nullptr));
		if (!hSrc) {
			PostMessage(WM_ERROR, ::GetLastError());
			continue;
		}

		// get file size
		LARGE_INTEGER size;
		::GetFileSizeEx(hSrc.get(), &size);

		// create target file and set final size
		CString filename = data.Src.Mid(data.Src.ReverseFind(L'\\'));
		wil::unique_handle hDst(::CreateFile(data.Dst + filename, GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS, FILE_FLAG_OVERLAPPED,
			nullptr));
		if (!hDst) {
			PostMessage(WM_ERROR, ::GetLastError());
			continue;
		}

		::SetFilePointerEx(hDst.get(), size, nullptr, FILE_BEGIN);
		::SetEndOfFile(hDst.get());

		// create two thread pool I/O objects and associate them with the two files
		data.tpDst.reset(::CreateThreadpoolIo(hDst.get(), WriteCallback, this, nullptr));
		data.tpSrc.reset(::CreateThreadpoolIo(hSrc.get(), ReadCallback, data.tpDst.get(), nullptr));

		data.hSrc = std::move(hSrc);
		data.hDst = std::move(hDst);

		// initiate first read operation
		auto io = new IOData;
		io->Size = size.QuadPart;
		io->Buffer = std::make_unique<BYTE[]>(chunkSize);
		io->hSrc = data.hSrc.get();
		io->hDst = data.hDst.get();
		::ZeroMemory(io, sizeof(OVERLAPPED));
		::StartThreadpoolIo(data.tpSrc.get());
		auto ok = ::ReadFile(io->hSrc, io->Buffer.get(), chunkSize, nullptr, io);
		ATLASSERT(!ok && ::GetLastError() == ERROR_IO_PENDING);
		::InterlockedAdd64(&m_OperationCount, (size.QuadPart + chunkSize - 1) / chunkSize);
	}

	PostMessage(WM_PROGRESS_START, (WPARAM)m_OperationCount);
}

LRESULT CMainDlg::OnPull(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/) {
	std::string osFileName = GetNtosFileName();
	std::wstring fileName = StringToWstring(osFileName);

	AddFile(fileName);
	AddFile(L"user32.dll");
	AddFile(L"ntdll.dll");
	AddFile(L"win32k.sys");
	AddFile(L"drivers\\fltmgr.sys");

	WCHAR path[MAX_PATH];
	::GetCurrentDirectory(MAX_PATH, path);
	wcscat_s(path, L"\\bin");
	std::filesystem::create_directories(path);
	SetDestination(path);
	UpdateButtons();

	// transfer list data to vector
	m_Data.clear();
	int count = m_List.GetItemCount();
	m_Data.reserve(count);
	for (int i = 0; i < count; i++) {
		if (m_List.GetItemData(i) != (DWORD_PTR)Type::File) {
			continue;
		}

		FileData data;
		m_List.GetItemText(i, 0, data.Src);
		m_List.GetItemText(i, 2, data.Dst);
		m_Data.push_back(std::move(data));
	}

	StartCopy();

	m_Progress.SetPos(0);
	m_Running = true;
	UpdateButtons();

	return 0;
}

CString CMainDlg::FormatSize(LONGLONG size) {
	CString text;
	if (size < 1 << 16)
		text.Format(L"%u B", (ULONG)size);
	else if (size < 1 << 22)
		text.Format(L"%u KB", size >> 10);
	else if (size < 1LL << 34)
		text.Format(L"%u MB", size >> 20);
	else
		text.Format(L"%u GB", size >> 30);
	return text;
}

LRESULT CMainDlg::OnAddFiles(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/) {
	WCHAR path[MAX_PATH];
	::GetSystemDirectory(path, MAX_PATH);
	CMultiFileDialog dlg(nullptr, path, OFN_FILEMUSTEXIST | OFN_ALLOWMULTISELECT,
		L"All Files (*.*)\0*.*\0", *this);
	dlg.ResizeFilenameBuffer(1 << 16);

	if (dlg.DoModal() == IDOK) {
		CString path;
		int errors = 0;
		dlg.GetFirstPathName(path);
		do {
			wil::unique_handle hFile(::CreateFile(path, 0, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
			if (!hFile) {
				errors++;
				continue;
			}
			LARGE_INTEGER size;
			::GetFileSizeEx(hFile.get(), &size);
			int n = m_List.AddItem(m_List.GetItemCount(), 0, path, 0);
			m_List.SetItemText(n, 1, FormatSize(size.QuadPart));
			m_List.SetItemData(n, (DWORD_PTR)Type::File);
		} while (dlg.GetNextPathName(path));
		m_List.EnsureVisible(m_List.GetItemCount() - 1, FALSE);
		UpdateButtons();
		if (errors > 0)
			AtlMessageBox(*this, L"Some files failed to open", IDR_MAINFRAME, MB_ICONEXCLAMATION);
	}
	return 0;
}

LRESULT CMainDlg::OnSetDestination(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/) {
	CFolderDialog dlg(*this, L"Select Destination Directory", BIF_RETURNONLYFSDIRS | BIF_USENEWUI);
	if (dlg.DoModal() == IDOK) {
		auto selected = m_List.GetSelectedCount();
		if (selected == 0) {
			auto count = m_List.GetItemCount();
			for (int i = 0; i < count; i++)
				m_List.SetItemText(i, 2, dlg.m_szFolderPath);
			m_Destinations = count;
		}
		else {
			int index = -1;
			CString text;
			for (;;) {
				index = m_List.GetNextItem(index, LVNI_SELECTED);
				if (index < 0)
					break;
				m_List.GetItemText(index, 2, text);
				m_List.SetItemText(index, 2, dlg.m_szFolderPath);
				if (text.IsEmpty())
					m_Destinations++;
			}
		}
		UpdateButtons();
	}
	return LRESULT();
}

LRESULT CMainDlg::OnItemChanged(int /*idCtrl*/, LPNMHDR /*pnmh*/, BOOL& /*bHandled*/) {
	UpdateButtons();
	return 0;
}

LRESULT CMainDlg::OnRemove(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/) {
	ATLASSERT(m_List.GetSelectedCount() > 0);
	int index = -1;
	CString text;
	for (;;) {
		index = m_List.GetNextItem(index, LVNI_SELECTED);
		if (index < 0)
			break;
		m_List.GetItemText(index, 1, text);
		if (!text.IsEmpty())
			m_Destinations--;
		m_List.DeleteItem(index);
		index--;
	}
	return 0;
}

LRESULT CMainDlg::OnProgress(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/) {
	m_Progress.StepIt();
	return 0;
}

LRESULT CMainDlg::OnProgressStart(UINT /*uMsg*/, WPARAM wParam, LPARAM /*lParam*/, BOOL& /*bHandled*/) {
	m_Progress.SetStep(1);
	m_Progress.SetRange(0, static_cast<int>(wParam));

	return 0;
}

LRESULT CMainDlg::OnDone(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/) {
	WCHAR path[MAX_PATH];
	::GetCurrentDirectory(MAX_PATH, path);
	wcscat_s(path, L"\\Symbols\\sdm.json");
	std::fstream r;
	r.open(path,std::ios::out);
	r.close();
	m_Data.clear();
	m_Running = false;
	AtlMessageBox(*this, L"All done!", IDR_MAINFRAME, MB_ICONINFORMATION);
	m_CanDownload = true;
	m_Progress.SetPos(0);
	UpdateButtons();




	return 0;
}

void CMainDlg::ReadCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PVOID Overlapped, ULONG IoResult,
	ULONG_PTR NumberOfBytesTransferred, PTP_IO Io) {
	if (IoResult == ERROR_SUCCESS) {
		auto io = static_cast<IOData*>(Overlapped);
		ULARGE_INTEGER offset = { io->Offset,io->OffsetHigh };
		offset.QuadPart += chunkSize;
		if (offset.QuadPart < io->Size) {
			auto newio = new IOData;
			newio->Size = io->Size;
			newio->Buffer = std::make_unique<BYTE[]>(chunkSize);
			newio->hSrc = io->hSrc;
			newio->hDst = io->hDst;
			::ZeroMemory(newio, sizeof(OVERLAPPED));
			newio->Offset = offset.LowPart;
			newio->OffsetHigh = offset.HighPart;
			::StartThreadpoolIo(Io);
			auto ok = ::ReadFile(newio->hSrc, newio->Buffer.get(), chunkSize, nullptr, newio);
			auto error = ::GetLastError();
			ATLASSERT(!ok && error == ERROR_IO_PENDING);
		}

		// read done, initiate write to the same offset in the target file
		io->Internal = io->InternalHigh = 0;
		auto writeIo = (PTP_IO)Context;
		::StartThreadpoolIo(writeIo);
		auto ok = ::WriteFile(io->hDst, io->Buffer.get(), (ULONG)NumberOfBytesTransferred, nullptr, io);
		auto error = ::GetLastError();
		ATLASSERT(!ok && error == ERROR_IO_PENDING);
	}
}

void CMainDlg::WriteCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PVOID Overlapped, ULONG IoResult,
	ULONG_PTR NumberOfBytesTransferred, PTP_IO Io) {
	if (IoResult == ERROR_SUCCESS) {
		auto pThis = static_cast<CMainDlg*>(Context);
		pThis->PostMessage(WM_PROGRESS);
		auto io = static_cast<IOData*>(Overlapped);
		delete io;
		if (0 == InterlockedDecrement64(&pThis->m_OperationCount)) {
			pThis->PostMessage(WM_DONE);
		}
	}
}

LRESULT CMainDlg::OnDownload(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/) {
	HANDLE hThread = ::CreateThread(nullptr, 0, [](auto param)->DWORD {
		auto pThis = static_cast<CMainDlg*>(param);
		WCHAR path[MAX_PATH];
		::GetCurrentDirectory(MAX_PATH, path);
		wcscat_s(path, L"\\bin");
		for (auto& iter : std::filesystem::directory_iterator(path)) {
			auto fileName = iter.path().filename().wstring();
			pThis->InitSymbols(fileName);
		}
		pThis->PostMessage(WM_DONE);
		return 0;
		},this,0,nullptr);
	return 0;
}

void CMainDlg::InitSymbols(std::wstring fileName) {
	WCHAR path[MAX_PATH];
	::GetCurrentDirectory(MAX_PATH, path);
	wcscat_s(path, L"\\bin\\");
	wcscat_s(path, fileName.c_str());
	PEParser parser(path);
	auto dir = parser.GetDataDirectory(IMAGE_DIRECTORY_ENTRY_DEBUG);
	if (dir != nullptr) {
		auto entry = static_cast<PIMAGE_DEBUG_DIRECTORY>(parser.GetAddress(dir->VirtualAddress));
		ULONG_PTR VA = reinterpret_cast<ULONG_PTR>(parser.GetBaseAddress());
		GetPdbSignature(VA, entry);
		::GetCurrentDirectory(MAX_PATH, path);
		wcscat_s(path, L"\\Symbols");
		std::filesystem::create_directory(path);
		bool success = SymDownloadSymbol(path);
		if (!success)
			m_Ok = false;
	}
	else {
		m_Ok = false;
	}
}

bool CMainDlg::SymDownloadSymbol(std::wstring localPath) {
	std::string url = "http://msdl.microsoft.com/download/symbols";

	if (url.back() != '/')
		url += '/';

	CString temp = _pdbFile + L"/" + _pdbSignature + L"/" + _pdbFile;
	std::wstring symbolUrl = temp.GetBuffer();
	url += std::string(symbolUrl.begin(), symbolUrl.end());
	std::wstring oldFileName = _pdbFile.GetBuffer();
	std::string deleteFile(oldFileName.begin(), oldFileName.end());
	std::wstring fileName = localPath + L"\\" + _pdbSignature.GetBuffer() + L"_" + _pdbFile.GetBuffer();
	bool isExist = std::filesystem::is_regular_file(fileName);
	if (isExist) {
		auto fileSize = std::filesystem::file_size(fileName);
		if (fileSize)
			return true;
	}

	for (auto& iter : std::filesystem::directory_iterator(localPath)) {
		auto filename = iter.path().filename().string();
		if (filename.find(deleteFile.c_str()) != std::string::npos) {
			std::filesystem::remove(iter.path());
			break;
		}
	}

	auto result = Download(url, fileName, "SDM", 1000,
		[](void* userdata, unsigned long long readBytes, unsigned long long totalBytes) {
			CMainDlg* pDlg = (CMainDlg*)userdata;
			if (totalBytes) {
				pDlg->UpdateProgress(totalBytes);
			}
			return true;
		},
		this);
	return result == downslib_error::ok ? true : false;
}

bool CMainDlg::GetPdbSignature(ULONG_PTR imageBase, PIMAGE_DEBUG_DIRECTORY entry) {
	if (entry->SizeOfData < sizeof(CV_INFO_PDB20))
		return false;

	ULONG_PTR offset = 0;

	offset = entry->PointerToRawData;
	auto cvData = (unsigned char*)(imageBase + offset);
	auto signature = *(DWORD*)cvData;

	if (signature == '01BN') {
		auto cv = (CV_INFO_PDB20*)cvData;
		_pdbSignature.Format(L"%X%X", cv->Signature, cv->Age);
		std::string file((const char*)cv->PdbFileName, entry->SizeOfData - FIELD_OFFSET(CV_INFO_PDB20, PdbFileName));
		_pdbFile = StringToWstring(file).c_str();
		_pdbValidation.signature = cv->Signature;
		_pdbValidation.age = cv->Age;
	}
	else if (signature == 'SDSR') {
		auto cv = (CV_INFO_PDB70*)cvData;
		_pdbSignature.Format(L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
			cv->Signature.Data1, cv->Signature.Data2, cv->Signature.Data3,
			cv->Signature.Data4[0], cv->Signature.Data4[1], cv->Signature.Data4[2],
			cv->Signature.Data4[3], cv->Signature.Data4[4], cv->Signature.Data4[5],
			cv->Signature.Data4[6], cv->Signature.Data4[7], cv->Age);
		std::string file((const char*)cv->PdbFileName, entry->SizeOfData - FIELD_OFFSET(CV_INFO_PDB70, PdbFileName));
		_pdbFile = StringToWstring(file).c_str();
		memcpy(&_pdbValidation.guid, &cv->Signature, sizeof(GUID));
		_pdbValidation.signature = 0;
		_pdbValidation.age = cv->Age;
	}
	return true;
}

downslib_error CMainDlg::Download(std::string url, std::wstring fileName,
	std::string userAgent, unsigned int timeout, downslib_cb cb, void* userdata) {
	HINTERNET hInternet = nullptr;
	HINTERNET hUrl = nullptr;
	HANDLE hFile = nullptr;
	HINTERNET hConnect = nullptr;

	Cleanup cleanup([&]()
		{
			DWORD lastError = ::GetLastError();
			if (hFile != INVALID_HANDLE_VALUE) {
				bool doDelete = false;
				LARGE_INTEGER fileSize;
				if (lastError != ERROR_SUCCESS || (::GetFileSizeEx(hFile, &fileSize) && fileSize.QuadPart == 0)) {
					doDelete = true;
				}
				::CloseHandle(hFile);
				if (doDelete)
					DeleteFile(fileName.c_str());
			}
			if (hUrl != nullptr)
				::InternetCloseHandle(hUrl);
			if (hInternet != NULL)
				::InternetCloseHandle(hInternet);
			if (hConnect != nullptr)
				::InternetCloseHandle(hConnect);
			::SetLastError(lastError);
		});

	hFile = ::CreateFile(fileName.c_str(), GENERIC_WRITE | FILE_READ_ATTRIBUTES, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return downslib_error::createfile;

	hInternet = ::InternetOpenA(userAgent.c_str(), INTERNET_OPEN_TYPE_PRECONFIG,
		nullptr, nullptr, 0);


	if (!hInternet)
		return downslib_error::inetopen;

	DWORD flags;
	DWORD len = sizeof(flags);

	::InternetSetOptionA(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
	flags = INTERNET_FLAG_RELOAD;
	if (strncmp(url.c_str(), "https://", 8) == 0)
		flags |= INTERNET_FLAG_SECURE;

	hUrl = InternetOpenUrlA(hInternet, url.c_str(), nullptr, 0, flags, 0);
	DWORD error = ::GetLastError();
	if (error == ERROR_INTERNET_INVALID_CA) {
		std::string serviceName = "msdl.microsoft.com";
		// Connect to the http server
		hConnect = InternetConnectA(hInternet, serviceName.c_str(),
			INTERNET_DEFAULT_HTTP_PORT, nullptr,
			nullptr, INTERNET_SERVICE_HTTP, 0, 0);
		int pos = url.find(".com") + 4;
		std::string objName(url.begin() + pos, url.end());
		hUrl = HttpOpenRequestA(hConnect, "GET",
			objName.c_str(), nullptr, nullptr, nullptr, INTERNET_FLAG_KEEP_CONNECTION, 0);

		HttpSendRequest(hUrl, nullptr, 0, nullptr, 0);
		error = ::GetLastError();
		if (error == ERROR_INTERNET_INVALID_CA) {
			// https://stackoverflow.com/questions/41357008/how-to-ignore-certificate-in-httppost-request-in-winapi
			flags = 0;
			InternetQueryOption(hUrl, INTERNET_OPTION_SECURITY_FLAGS, &flags, &len);
			flags |= SECURITY_SET_MASK;
			InternetSetOptionA(hUrl, INTERNET_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
			HttpSendRequest(hUrl, nullptr, 0, nullptr, 0);
		}
	}
	if (error == ERROR_INTERNET_HTTP_TO_HTTPS_ON_REDIR) {
		url.insert(4, "s");
		flags |= INTERNET_FLAG_SECURE;
		hUrl = ::InternetOpenUrlA(hInternet, url.c_str(), nullptr, 0, flags, 0);
	}
	if (!hUrl)
		return downslib_error::openurl;

	// Get HTTP content length
	char buffer[1 << 11];
	memset(buffer, 0, sizeof(buffer));
	len = sizeof(buffer);
	unsigned long long totalBytes = 0;
	if (::HttpQueryInfoA(hUrl, HTTP_QUERY_CONTENT_LENGTH, buffer, &len, 0)) {
		if (sscanf_s(buffer, "%llu", &totalBytes) != 1)
			totalBytes = 0;
	}

	PostMessage(WM_PROGRESS_START, totalBytes);

	// Get HTTP status code
	len = sizeof(buffer);
	if (::HttpQueryInfoA(hUrl, HTTP_QUERY_STATUS_CODE, buffer, &len, 0)) {
		int statusCode = 0;
		if (sscanf_s(buffer, "%d", &statusCode) != 1)
			statusCode = 500;
		if (statusCode != 200) {
			::SetLastError(statusCode);
			return downslib_error::statuscode;
		}
	}

	DWORD read = 0;
	DWORD written = 0;
	unsigned long long readBytes = 0;
	while (::InternetReadFile(hUrl, buffer, sizeof(buffer), &read)) {
		readBytes += read;

		// We are done if nothing more to read, so now we can report total size in our final cb call
		if (read == 0)
			totalBytes = readBytes;

		// Call the callback to report progress and cancellation
		if (cb && !cb(userdata, readBytes, totalBytes)) {
			::SetLastError(ERROR_OPERATION_ABORTED);
			return downslib_error::cancel;
		}

		// Exit if noting more read
		if (read == 0)
			break;

		::WriteFile(hFile, buffer, read, &written, nullptr);
	}

	if (totalBytes > 0 && readBytes != totalBytes) {
		::SetLastError(ERROR_IO_INCOMPLETE);
		return downslib_error::incomplete;
	}

	::SetLastError(ERROR_SUCCESS);
	return downslib_error::ok;
}

void CMainDlg::UpdateProgress(int value) {
	m_Progress.SetPos(value);
}