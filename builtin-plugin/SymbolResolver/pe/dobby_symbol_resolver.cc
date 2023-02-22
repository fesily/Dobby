#include "SymbolResolver/dobby_symbol_resolver.h"
#include "dobby/common.h"

#include <windows.h>
#include <DbgHelp.h>

#include <string>
#include <vector>
#include <filesystem>
#include <memory>
#include <string.h>

#include "PlatformUtil/ProcessRuntimeUtility.h"

#undef LOG_TAG
#define LOG_TAG "DobbySymbolResolver"

#pragma comment(lib, "dbghelp.lib")

using SymHandler = std::unique_ptr<void, decltype(&SymCleanup)>;
inline std::string searchpath(bool SymBuildPath, bool SymUseSymSrv) {
  // Build the sym-path:
  if (SymBuildPath) {
    std::string searchpath;
    searchpath.reserve(4096);
    searchpath.append(".;");
    std::error_code ec;
    auto current_path = std::filesystem::current_path(ec);
    if (!ec) {
      searchpath.append(current_path.string().c_str());
      searchpath += ';';
    }
    const size_t nTempLen = 1024;
    char szTemp[nTempLen];

    // Now add the path for the main-module:
    if (GetModuleFileNameA(NULL, szTemp, nTempLen) > 0) {
      std::filesystem::path path(szTemp);
      searchpath.append(path.parent_path().string());
      searchpath += ';';
    }
    if (GetEnvironmentVariableA("_NT_SYMBOL_PATH", szTemp, nTempLen) > 0) {
      szTemp[nTempLen - 1] = 0;
      searchpath.append(szTemp);
      searchpath += ';';
    }
    if (GetEnvironmentVariableA("_NT_ALTERNATE_SYMBOL_PATH", szTemp, nTempLen) > 0) {
      szTemp[nTempLen - 1] = 0;
      searchpath.append(szTemp);
      searchpath += ';';
    }
    if (GetEnvironmentVariableA("SYSTEMROOT", szTemp, nTempLen) > 0) {
      szTemp[nTempLen - 1] = 0;
      searchpath.append(szTemp);
      searchpath += ';';
      searchpath.append(szTemp);
      searchpath.append("\\system32;");
    }

    if (SymUseSymSrv) {
      if (GetEnvironmentVariableA("SYSTEMDRIVE", szTemp, nTempLen) > 0) {
        szTemp[nTempLen - 1] = 0;
        searchpath.append("SRV*");
        searchpath.append(szTemp);
        searchpath.append("\\websymbols*https://msdl.microsoft.com/download/symbols;");
      } else
        searchpath.append("SRV*c:\\websymbols*https://msdl.microsoft.com/download/symbols;");
    }
    return searchpath;
  } // if SymBuildPath
  return {};
}

inline HANDLE createSymHandler(bool SymBuildPath, bool SymUseSymSrv) {
  HANDLE proc = GetCurrentProcess();
  auto path = searchpath(SymBuildPath, SymUseSymSrv);
  if (!SymInitialize(proc, path.c_str(), TRUE)) {
    if (GetLastError() != 87) {
      return nullptr;
    }
  }
  DWORD symOptions = SymGetOptions(); // SymGetOptions
  symOptions |= SYMOPT_LOAD_LINES;
  symOptions |= SYMOPT_FAIL_CRITICAL_ERRORS;
  symOptions = SymSetOptions(symOptions);
  return proc;
}

inline SymHandler &GetSymHandler() {
  static SymHandler handler{createSymHandler(true, true), SymCleanup};
  return handler;
}

inline bool is_target_symbol(PSYMBOL_INFO pSymbol, HMODULE hMod) {
  enum {
    SymTagFunction = 5,
    SymTagData = 7,
    SymTagPublicSymbol = 10,
  };
  #ifndef SYMFLAG_PUBLIC_CODE
  #define SYMFLAG_PUBLIC_CODE 0x00400000
  #endif
  // skip public code
  if (pSymbol->Flags & SYMFLAG_PUBLIC_CODE) {
    return false;
  }
  if ((HMODULE)pSymbol->ModBase != hMod) {
    return false;
  }

  return pSymbol->Tag == SymTagFunction || pSymbol->Tag == SymTagPublicSymbol || pSymbol->Tag == SymTagData;
}

PUBLIC void *DobbySymbolResolver(const char *image_name, const char *symbol_name_pattern) {
  HMODULE hmod; 
  if (image_name) {
      hmod = LoadLibraryExA(image_name, NULL, DONT_RESOLVE_DLL_REFERENCES);
  } else {
    if (!GetModuleHandleEx(0, 0, &hmod)) {
      return nullptr;
    }
  }
  if (!hmod)
    return nullptr;
  
  void *result = NULL;

  std::unique_ptr<std::remove_pointer_t<HMODULE>, decltype(&FreeLibrary)> hMod{hmod, &FreeLibrary};
  
  result = GetProcAddress(hMod.get(), symbol_name_pattern);
  if (result)
    return result;
  SymHandler &handler = GetSymHandler();
  if (!handler)
    return nullptr;

  std::unique_ptr<char[]> pattern;
  size_t len = 0;
  if (image_name) {
    auto moduleName = std::filesystem::path(image_name).filename().replace_extension().string();
    len = moduleName.size() + strlen(symbol_name_pattern) + 1 + 1;
    pattern = std::make_unique<char[]>(len);
    snprintf(pattern.get(), len, "%s!%s", moduleName.c_str(), symbol_name_pattern);
    ULONG64 buffer[(sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR) + sizeof(ULONG64) - 1) / sizeof(ULONG64)];
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;

    if (SymFromName(handler.get(), pattern.get(), pSymbol)) {
      if (is_target_symbol(pSymbol, hMod.get())) {
        return (void *)pSymbol->Address;
      }
    }
  }
  // enum Symbols in every module
  std::tuple<void*&, HMODULE> ctx {result, (HMODULE)hMod.get()};
  if (len == 0 || !pattern) {
    len = strlen(symbol_name_pattern) + 2 + 1;
    pattern = std::make_unique<char[]>(len);
  }
  snprintf(pattern.get(), len, "*!%s", symbol_name_pattern);

  SymEnumSymbolsEx(handler.get(), 0, pattern.get(),
    [](PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext)->BOOL {
      auto& [result, hMod] = *(decltype(ctx)*)UserContext;
      if (is_target_symbol(pSymInfo, hMod)) {
        result = (void*)pSymInfo->Address;
        return FALSE;
      }
      return TRUE;
  }, (void*)&ctx, 1);

  return result;
}