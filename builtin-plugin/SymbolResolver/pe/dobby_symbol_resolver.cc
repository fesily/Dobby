#include "SymbolResolver/dobby_symbol_resolver.h"
#include "common_header.h"

#include <windows.h>

#include <string>
#include <string.h>

#include "PlatformUtil/ProcessRuntimeUtility.h"

#include <vector>
#include <Windows.h>
#include <DbgHelp.h>
#include <filesystem>
#include <memory>
#undef LOG_TAG
#define LOG_TAG "DobbySymbolResolver"

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

PUBLIC void *DobbySymbolResolver(const char *image_name, const char *symbol_name_pattern) {
  void *result = NULL;

  HMODULE hMod = LoadLibraryExA(image_name, NULL, DONT_RESOLVE_DLL_REFERENCES);
  if (!hMod)
    return nullptr;
  result = GetProcAddress(hMod, symbol_name_pattern);
  if (!result) {
    SymHandler &handler = GetSymHandler();
    if (handler) {
      ULONG64 buffer[(sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR) + sizeof(ULONG64) - 1) / sizeof(ULONG64)];
      PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

      pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
      pSymbol->MaxNameLen = MAX_SYM_NAME;
      if (SymFromName(handler.get(), symbol_name_pattern, pSymbol)) {
        if (ProcessRuntimeUtility::GetProcessModule(image_name).load_address == (void *)pSymbol->ModBase) {
          return (void *)pSymbol->Address;
        }
      }
    }
  }

  FreeLibrary(hMod);
  return result;
}