module run_dlg;
pragma(lib, "shell32.lib");

import core.sys.windows.windows;

// 声明函数指针类型
alias RUNFILEDLG = extern(Windows) void function(
    HWND   hwndOwner,
    HICON  hIcon,
    LPCWSTR lpszDirectory,
    LPCWSTR lpszTitle,
    LPCWSTR lpszDescription,
    UINT   uFlags
);

void runDlg(wstring sPath, wstring title, wstring tipText) {

    // 获取已加载的 shell32.dll 句柄
    HMODULE hShell32 = GetModuleHandleW("shell32.dll");
    if (hShell32 is null) {
        hShell32 = LoadLibraryW("shell32.dll");
    }

    if (hShell32 !is null) {
        // 通过序号获取函数地址 (61)
        RUNFILEDLG RunFileDlg = cast(RUNFILEDLG)GetProcAddress(hShell32, cast(LPCSTR)61);
        
        if (RunFileDlg !is null) {
            RunFileDlg(
                null,          // 父窗口句柄
                null,          // 图标句柄
                &sPath[0],       // 工作目录 (D 的宽字符串语法)
                &title[0], // 对话框标题
                &tipText[0], // 描述文本
                0              // 标志位
            );
        }
        
        // 仅释放动态加载的库
        if (GetModuleHandleW("shell32.dll") != hShell32) {
            FreeLibrary(hShell32);
        }
    }
}
