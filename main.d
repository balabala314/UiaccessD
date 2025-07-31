pragma(lib,"kernel32.lib");
pragma(lib,"advapi32.lib");
pragma(lib,"shell32.lib");
pragma(lib,"shcore.lib");
import std.process;
import core.sys.windows.windows;
import core.sys.windows.tlhelp32;
import core.sys.windows.winbase;
import core.sys.windows.security;
import core.sys.windows.winnt;
import core.sys.windows.winuser;
import core.sys.windows.shellapi;
import core.stdc.string;
import core.stdc.stdlib : exit; // for exit(0)
import std.conv : to;
import std.string;
import std.stdio;
import run_dlg;

extern(Windows) DWORD GetLastError();
extern(Windows) BOOL IsUserAnAdmin();
extern(Windows) int SetProcessDpiAwareness(int);

const int PROCESS_QUERY_LIMITED_INFORMATION = 4096;


size_t wstrlen(const(wchar)[] arr) {
    foreach (i, c; arr) {
        if (c == 0)
            return i;
    }
    return arr.length;
}

DWORD duplicateWinloginToken(DWORD dwSessionId, DWORD dwDesiredAccess, HANDLE* phToken) {
    DWORD dwErr;
    PRIVILEGE_SET ps;
    ps.PrivilegeCount = 1;
    ps.Control = PRIVILEGE_SET_ALL_NECESSARY;

    if (!LookupPrivilegeValueW(null, SE_TCB_NAME.ptr, &ps.Privilege[0].Luid)) {
        return GetLastError();
    }
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }
    BOOL bCont, bFound = FALSE;
    PROCESSENTRY32W pe;
    pe.dwSize = PROCESSENTRY32W.sizeof;
    dwErr = ERROR_NOT_FOUND;

    for (bCont = Process32FirstW(hSnapshot, &pe); bCont; bCont = Process32NextW(hSnapshot, &pe)) {
        string exeName = to!string(pe.szExeFile[0 .. wstrlen(pe.szExeFile)]);
        if (exeName != "winlogon.exe")
            continue;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (!hProcess) {
            continue;
        }
        
        HANDLE hToken;
        DWORD dwRetLen, sid;
        if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) {
            CloseHandle(hProcess);
            continue;
        }
        BOOL fTcb;
        if (!PrivilegeCheck(hToken, &ps, &fTcb) && fTcb) {
            CloseHandle(hToken);
            CloseHandle(hProcess);
            continue;
        }
        if (GetTokenInformation(hToken,
            TOKEN_INFORMATION_CLASS.TokenSessionId,
            &sid,
            DWORD.sizeof,
            &dwRetLen) && sid == dwSessionId) {
            bFound = TRUE;
            if (DuplicateTokenEx(hToken, dwDesiredAccess, null,
                SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                TOKEN_TYPE.TokenImpersonation, phToken)) {
                dwErr = ERROR_SUCCESS;
            } else {
                dwErr = GetLastError();
            }
        }
        
        CloseHandle(hToken);
        
        CloseHandle(hProcess);
        
        if (bFound) break;
    }
    CloseHandle(hSnapshot);
    return dwErr;
}

DWORD createUIAccessToken(HANDLE* phToken) {
    DWORD dwErr;
    HANDLE hTokenSelf;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &hTokenSelf)) {
        return GetLastError();
    }
    DWORD dwSessionId, dwRetLen;
    if (!GetTokenInformation(hTokenSelf,
        TOKEN_INFORMATION_CLASS.TokenSessionId,
        &dwSessionId, DWORD.sizeof, &dwRetLen)) {
            return GetLastError();
        }
    HANDLE hTokenSystem;
    dwErr = duplicateWinloginToken(dwSessionId, TOKEN_IMPERSONATE, &hTokenSystem);
    if (dwErr != ERROR_SUCCESS) {
        return dwErr;
    }
    if (!SetThreadToken(null, hTokenSystem)) {
        return GetLastError();
    }
    if (DuplicateTokenEx(hTokenSelf,
        TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
        null, SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous,
        TOKEN_TYPE.TokenPrimary, phToken)) {
        BOOL bUIAccess = TRUE;
        if (!SetTokenInformation(*phToken,
            TOKEN_INFORMATION_CLASS.TokenUIAccess,
            &bUIAccess, BOOL.sizeof)) {
            dwErr = GetLastError();
            CloseHandle(*phToken);
        }
    } else {
        dwErr = GetLastError();
    }
    RevertToSelf();

    CloseHandle(hTokenSystem);
    CloseHandle(hTokenSelf);
    
    return dwErr;
}

BOOL checkForUIAccess(DWORD* pdwErr, DWORD* pfUIAccess) {
    BOOL result = FALSE;
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        DWORD dwRetLen;
        if (GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenUIAccess, pfUIAccess, DWORD.sizeof, &dwRetLen)) {
            result = TRUE;
        } else {
            *pdwErr = GetLastError();
        }
        CloseHandle(hToken);
    } else {
        *pdwErr = GetLastError();
    }
    return result;
}

DWORD prepareForUIAccess() {
    DWORD dwErr;
    HANDLE hTokenUIAccess;
    uint fUIAccess;
    if (!checkForUIAccess(&dwErr, &fUIAccess)) {
        return dwErr;
    }
    if (fUIAccess) {
        return ERROR_SUCCESS;
    } 
    dwErr = createUIAccessToken(&hTokenUIAccess);
    if (dwErr == ERROR_SUCCESS) {
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        GetStartupInfoW(&si);
        auto cmd = GetCommandLineW();
        if (CreateProcessAsUserW(hTokenUIAccess, null, cmd, null, null, FALSE, 0, null, null, &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return 1;
            // exit(0);
        } else {
            dwErr = GetLastError();
        }
        CloseHandle(hTokenUIAccess);
        
    }
    return dwErr;
}
extern (Windows)
int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, // @suppress(dscanner.style.phobos_naming_convention)
            LPSTR lpCmdLine, int nCmdShow){
    SetProcessDpiAwareness(1); // @suppress(dscanner.unused_result)
    if (!IsUserAnAdmin()){
        writefln("Admin is required!");
        return 0;
    }
    if (prepareForUIAccess() != 0){
        return 1;
    }
    runDlg("C:\\"w, "Run With UIAccess"w, "Run a program with UIAccess token:"w);
    return 0;
}
