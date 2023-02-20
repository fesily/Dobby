#include "PlatformUtil/ProcessRuntimeUtility.h"
#include "common_header.h"
#include <vector>

#include <windows.h>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")
#define LINE_MAX 2048

// ================================================================
// GetProcessMemoryLayout

static bool memory_region_comparator(MemRegion a, MemRegion b) {
  return (a.start > b.start);
}

// https://gist.github.com/jedwardsol/9d4fe1fd806043a5767affbd200088ca

std::vector<MemRegion> ProcessMemoryLayout;
const std::vector<MemRegion> &ProcessRuntimeUtility::GetProcessMemoryLayout() {
  if (!ProcessMemoryLayout.empty()) {
    ProcessMemoryLayout.clear();
  }

  char *address{nullptr};
  MEMORY_BASIC_INFORMATION region;

  while (VirtualQuery(address, &region, sizeof(region))) {
    address += region.RegionSize;
    if (!(region.State & (MEM_COMMIT | MEM_RESERVE))) {
      continue;
    }

    MemoryPermission permission = MemoryPermission::kNoAccess;
    auto mask = PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE;
    switch (region.Protect & ~mask) {
    case PAGE_NOACCESS:
    case PAGE_READONLY:
      break;

    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
      permission = MemoryPermission::kReadExecute;
      break;

    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
      permission = MemoryPermission::kReadWrite;
      break;

    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
      permission = MemoryPermission::kReadWriteExecute;
      break;
    }

    ProcessMemoryLayout.push_back(MemRegion{(addr_t)(void *)region.BaseAddress, region.RegionSize, permission});
  }
  return ProcessMemoryLayout;
}

// ================================================================
// GetProcessModuleMap

static std::vector<RuntimeModule> ProcessModuleMap;

PUBLIC void DobbyUpdateModuleMap() {
  ProcessModuleMap.clear();
  HANDLE hProcess = GetCurrentProcess();
  HMODULE hModules[1024];
  DWORD lNeed = 0;
  DWORD flags = 0;
#if defined(_M_IX86)
  flags = LIST_MODULES_32BIT;
#else
  flags = LIST_MODULES_64BIT;
#endif
  if (EnumProcessModulesEx(hProcess, hModules, sizeof(hModules), &lNeed, flags) != 0) {
    lNeed = lNeed / sizeof(HMODULE);
    for (DWORD i = 0; i < lNeed; i++) {
      HMODULE module = hModules[i];
      RuntimeModule rm;
      if (GetModuleFileNameExA(hProcess, module, rm.path, sizeof(rm.path)) == 0) {
        ZeroMemory(rm.path, sizeof(rm.path));
      }
      MODULEINFO info = {};
      if (GetModuleInformation(hProcess, module, &info, sizeof(MODULEINFO))) {
        rm.load_address = info.lpBaseOfDll;
      }
      ProcessModuleMap.emplace_back(std::move(rm));
    }
  }
}

const std::vector<RuntimeModule>& ProcessRuntimeUtility::GetProcessModuleMap() {
  if (!ProcessMemoryLayout.empty()) {
    ProcessMemoryLayout.clear();
  }
  if (ProcessModuleMap.empty())
    DobbyUpdateModuleMap();
  return ProcessModuleMap;
}

RuntimeModule ProcessRuntimeUtility::GetProcessModule(const char *name) {
  const auto& ProcessModuleMap = GetProcessModuleMap();
  for (auto module : ProcessModuleMap) {
    if (strstr(module.path, name) != 0) {
      return module;
    }
  }
  return RuntimeModule{0, 0};
}