#pragma once
#include <intrin.h>
#include <cstdint>
#include <cstring>

#define STR_SEED (__LINE__ * 0x9E3779B9u ^ (uint32_t)(__COUNTER__ * 0x517CC1B7u))

namespace strenc_detail {

static constexpr int MAX_LEN = 256;

static thread_local char tls_buf[MAX_LEN] = { 0 };

static inline uint32_t derive_env_key() noexcept
{
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

#if defined(_MSC_VER)
    int info[4] = { 0 };
    __cpuid(info, 1);
    eax = (uint32_t)info[0];
    ebx = (uint32_t)info[1];
    ecx = (uint32_t)info[2];
    edx = (uint32_t)info[3];
#elif defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1) :);
#endif

    uintptr_t stack_marker = (uintptr_t)&eax;
    uint32_t  stack_bits   = (uint32_t)(stack_marker ^ (stack_marker >> 16));
    return eax ^ ecx ^ (ebx >> 8) ^ (edx << 5) ^ stack_bits;
}

template<int N, uint32_t Seed>
__forceinline const char* decrypt(const uint8_t (&enc)[N]) noexcept
{
    // Removido derive_env_key() - causa incompatibilidade compile/runtime
    uint32_t key = Seed;
    uint8_t  prev_raw = 0;

    for (int i = 0; i < N - 1; i++)
    {
        uint8_t mask  = (uint8_t)((key >> ((i & 7) * 4)) ^ (i * 0x1Bu));
        uint8_t delta = enc[i] ^ mask;
        uint8_t c     = (uint8_t)(delta + prev_raw);
        tls_buf[i]    = (char)c;
        prev_raw      = c;
        if ((i & 7) == 7)
            key = (key >> 13) | (key << 19);
    }
    tls_buf[N - 1] = '\0';
    key = 0;
    return tls_buf;
}

template<int N, uint32_t Seed>
__forceinline void decrypt_to(const uint8_t (&enc)[N], char* out) noexcept
{
    // Removido derive_env_key() - causa incompatibilidade compile/runtime
    uint32_t key = Seed;
    uint8_t  prev_raw = 0;

    for (int i = 0; i < N - 1; i++)
    {
        uint8_t mask  = (uint8_t)((key >> ((i & 7) * 4)) ^ (i * 0x1Bu));
        uint8_t delta = enc[i] ^ mask;
        uint8_t c     = (uint8_t)(delta + prev_raw);
        out[i]        = (char)c;
        prev_raw      = c;
        if ((i & 7) == 7)
            key = (key >> 13) | (key << 19);
    }
    out[N - 1] = '\0';
    key = 0;
}

template<int N, uint32_t Seed>
struct EncStr
{
    uint8_t data[N];

    constexpr EncStr(const char (&s)[N]) noexcept : data{}
    {
        uint32_t key  = Seed;
        uint8_t  prev = 0;
        for (int i = 0; i < N - 1; i++)
        {
            uint8_t mask  = (uint8_t)((key >> ((i & 7) * 4)) ^ (i * 0x1Bu));
            uint8_t delta = (uint8_t)((uint8_t)s[i] - prev);
            data[i]       = delta ^ mask;
            prev          = (uint8_t)s[i];
            if ((i & 7) == 7)
                key = (key >> 13) | (key << 19);
        }
        data[N - 1] = 0;
    }

    __forceinline const char* get() const noexcept { return decrypt<N, Seed>(data); }
    __forceinline void get(char* out) const noexcept { decrypt_to<N, Seed>(data, out); }
};

} // namespace strenc_detail

#define ENC(str) \
    ([]() -> const char* { \
        static constexpr strenc_detail::EncStr< \
            sizeof(str), \
            (uint32_t)(__COUNTER__ * 0x9E3779B9u ^ __LINE__ * 0x517CC1B7u ^ 0xDEADBEEFu) \
        > _e(str); \
        return _e.get(); \
    }())

#define ENC_BUF(buf, str) \
    do { \
        static constexpr strenc_detail::EncStr< \
            sizeof(str), \
            (uint32_t)(__COUNTER__ * 0x9E3779B9u ^ __LINE__ * 0x517CC1B7u ^ 0xDEADBEEFu) \
        > _e(str); \
        _e.get(buf); \
    } while(0)

namespace strenc_detail {

static thread_local inline wchar_t tls_wbuf[MAX_LEN] = { 0 };

template<int N, uint32_t Seed>
struct EncWStr
{
    uint16_t data[N];

    constexpr EncWStr(const wchar_t (&s)[N]) noexcept : data{}
    {
        uint32_t key  = Seed;
        uint16_t prev = 0;
        for (int i = 0; i < N - 1; i++)
        {
            uint32_t mask  = (key >> ((i & 3) * 8)) ^ (i * 0x1Bu);
            uint16_t delta = (uint16_t)((uint16_t)s[i] - prev);
            data[i]        = (uint16_t)(delta ^ (uint16_t)(mask & 0xFFFF));
            prev           = (uint16_t)s[i];
            if ((i & 3) == 3)
                key = (key >> 13) | (key << 19);
        }
        data[N - 1] = 0;
    }

    __forceinline const wchar_t* get() const noexcept
    {
        // Removido derive_env_key() - causa incompatibilidade compile/runtime
        uint32_t key  = Seed;
        uint16_t prev = 0;
        for (int i = 0; i < N - 1; i++)
        {
            uint32_t mask  = (key >> ((i & 3) * 8)) ^ (i * 0x1Bu);
            uint16_t delta = data[i] ^ (uint16_t)(mask & 0xFFFF);
            uint16_t c     = (uint16_t)(delta + prev);
            tls_wbuf[i]    = (wchar_t)c;
            prev           = c;
            if ((i & 3) == 3)
                key = (key >> 13) | (key << 19);
        }
        tls_wbuf[N - 1] = L'\0';
        key = 0;
        return tls_wbuf;
    }
};

} // namespace strenc_detail

#define WENC(str) \
    ([]() -> const wchar_t* { \
        static constexpr strenc_detail::EncWStr< \
            sizeof(str)/sizeof(wchar_t), \
            (uint32_t)(__COUNTER__ * 0x9E3779B9u ^ __LINE__ * 0x517CC1B7u ^ 0xCAFEBABEu) \
        > _e(str); \
        return _e.get(); \
    }())

// Zera os buffers TLS onde ENC/WENC armazenam strings decryptadas.
// Chamar depois de uma sessao de uso (ex. apos resolver todos os SSNs,
// apos PebGetModuleBase). Deixa a janela de "string em memoria" curta.
inline void ScrubEncTLS() noexcept
{
    volatile char*    p  = strenc_detail::tls_buf;
    volatile wchar_t* pw = strenc_detail::tls_wbuf;
    for (int i = 0; i < strenc_detail::MAX_LEN; ++i) { p[i] = 0; pw[i] = 0; }
}
