#pragma once
#include <cstdint>

// chave do XOR+rol que o pack_bin.exe aplicou no shellcode .rsrc.
// Precisa bater com o argumento passado no PreBuildEvent.
inline constexpr uint32_t kScKey = 0x7F3C92A1u;
