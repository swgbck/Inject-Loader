#pragma once

#include <iostream>
#include <vector>
#include "spoofer.h"

DWORD FindProcessByName(const wchar_t* processName);
BOOL  InitializeSyscalls();
bool  injectShellcode(std::vector<uint8_t>& shellcode, HANDLE hProcess, DWORD processId);
void  LoadShellcodeFromBytes(std::vector<uint8_t>& shellcode);
