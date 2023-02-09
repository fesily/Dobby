#include "PlatformUtil/ProcessRuntimeUtility.h"

#include <vector>

#include <windows.h>

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

std::vector<RuntimeModule> ProcessModuleMap;

static HMODULE enumerateModules(HANDLE hProcess, HMODULE hModuleLast, PIMAGE_NT_HEADERS32 pNtHeader) {
  MEMORY_BASIC_INFORMATION mbi = {0};
  for (PBYTE pbLast = (PBYTE)hModuleLast + 0x10000;; pbLast = (PBYTE)mbi.BaseAddress + mbi.RegionSize) {
    if (VirtualQueryEx(hProcess, (PVOID)pbLast, &mbi, sizeof(mbi)) <= 0) {
      break;
    }
    if (((PBYTE)mbi.BaseAddress + mbi.RegionSize) < pbLast) {
      break;
    }
    if ((mbi.State != MEM_COMMIT) || ((mbi.Protect & 0xff) == PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD)) {
      continue;
    }
    __try {
      IMAGE_DOS_HEADER idh;
      if (!ReadProcessMemory(hProcess, pbLast, &idh, sizeof(idh), NULL)) {
        continue;
      }
      if (idh.e_magic != IMAGE_DOS_SIGNATURE || (DWORD)idh.e_lfanew > mbi.RegionSize ||
          (DWORD)idh.e_lfanew < sizeof(idh)) {
        continue;
      }
      if (!ReadProcessMemory(hProcess, pbLast + idh.e_lfanew, pNtHeader, sizeof(*pNtHeader), NULL)) {
        continue;
      }
      if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
        continue;
      }
      return (HMODULE)pbLast;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      continue;
    }
  }
  return NULL;
}

const std::vector<RuntimeModule>& ProcessRuntimeUtility::GetProcessModuleMap() {
  if (!ProcessMemoryLayout.empty()) {
    ProcessMemoryLayout.clear();
  }
  HANDLE hProcess = GetCurrentProcess();
  HMODULE hModule = NULL;
  for (;;) {
    IMAGE_NT_HEADERS32 inh;
    if ((hModule = enumerateModules(hProcess, hModule, &inh)) == NULL)
      break;
    ProcessModuleMap.push_back({});
    auto &module = ProcessModuleMap.back();
    auto ec = GetModuleFileNameA(hModule, module.path, sizeof(module.path));
    if (ec == 0) {
      ProcessModuleMap.pop_back();
      continue;
    }
  }
  return ProcessModuleMap;
}

RuntimeModule ProcessRuntimeUtility::GetProcessModule(const char *name) {
  std::vector<RuntimeModule> ProcessModuleMap = GetProcessModuleMap();
  for (auto module : ProcessModuleMap) {
    if (strstr(module.path, name) != 0) {
      return module;
    }
  }
  return RuntimeModule{0};
}