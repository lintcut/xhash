#include <Windows.h>
#include "xhashcpp.h"
#include "xhash.h"

#ifdef __cplusplus
extern "C" {
#endif

// MD5 Types
# define MD5_LONG           unsigned int
# define MD5_CBLOCK         64
# define MD5_LBLOCK         (MD5_CBLOCK/4)
# define MD5_DIGEST_LENGTH  16
typedef struct MD5state_st {
    MD5_LONG A, B, C, D;
    MD5_LONG Nl, Nh;
    MD5_LONG data[MD5_LBLOCK];
    unsigned int num;
} MD5_CTX;
int MD5_Init(MD5_CTX *c);
int MD5_Update(MD5_CTX *c, const void *data, size_t len);
int MD5_Final(unsigned char *md, MD5_CTX *c);

// SHA1 Types
# define SHA_LONG           unsigned int
# define SHA_LBLOCK         16
# define SHA_CBLOCK         (SHA_LBLOCK*4)
# define SHA_LAST_BLOCK     (SHA_CBLOCK-8)
# define SHA_DIGEST_LENGTH  20
typedef struct SHAstate_st {
    SHA_LONG h0, h1, h2, h3, h4;
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    unsigned int num;
} SHA_CTX;
int SHA1_Init(SHA_CTX *c);
int SHA1_Update(SHA_CTX *c, const void *data, size_t len);
int SHA1_Final(unsigned char *md, SHA_CTX *c);


# define SHA256_CBLOCK   (SHA_LBLOCK*4)/* SHA-256 treats input data as a
                                        * contiguous array of 32 bit wide
                                        * big-endian values. */
typedef struct SHA256state_st {
    SHA_LONG h[8];
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    unsigned int num, md_len;
} SHA256_CTX;
int SHA256_Init(SHA256_CTX *c);
int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA256_Final(unsigned char *md, SHA256_CTX *c);

#ifdef __cplusplus
}
#endif

using namespace xsec;

static std::string ucharToHex(uint8_t uc)
{
    static const char* hex = "0123456789abcdef";
    char s[3] = { 0, 0, 0 };
    s[0] = hex[(uc >> 4) & 0xF];
    s[1] = hex[uc & 0xF];
    s[2] = 0;
    return s;
}

xmd5::xmd5()
    : xhash()
{
    memset(result, 0, 16);
    context = malloc(sizeof(MD5_CTX));
    if (nullptr != context) {
        memset(context, 0, sizeof(MD5_CTX));
        if (!MD5_Init((MD5_CTX*)context)) {
            free(context);
            context = nullptr;
        }
    }
}

xmd5::~xmd5()
{
    if (nullptr != context) {
        free(context);
        context = nullptr;
    }
}

void xmd5::compute(const void* data, size_t size)
{
    if (nullptr == context)
        return;
    MD5_Update((MD5_CTX*)context, data, size);
}

void xmd5::finalize()
{
    if (nullptr == context)
        return;
    MD5_Final(result, (MD5_CTX*)context);
    finalized = true;
}

void xmd5::reset()
{
    if (nullptr != context) {
        finalized = false;
        memset(result, 0, 16);
        memset(context, 0, sizeof(MD5_CTX));
        MD5_Init((MD5_CTX*)context);
    }
}

std::string xmd5::to_string()
{
    std::string s;
    if (nullptr != context && finalized) {
        for (int i = 0; i < 16; i++)
            s.append(ucharToHex(result[i]));
    }
    return s;
}

std::vector<uint8_t> xmd5::get_hash(const void* data, size_t size)
{
    std::vector<uint8_t> h(16, 0);
    if (!XhMd5(data, size, h.data()))
        h.clear();
    return h;
}

std::string xmd5::get_hash_string(const void* data, size_t size)
{
    std::string s;
    const std::vector<uint8_t>& h = xmd5::get_hash(data, size);
    for (auto uc : h) {
        s.append(ucharToHex(uc));
    }
    return s;
}

xsha1::xsha1()
    : xhash()
{
    memset(result, 0, 20);
    context = malloc(sizeof(SHA_CTX));
    if (nullptr != context) {
        memset(context, 0, sizeof(SHA_CTX));
        if (!SHA1_Init((SHA_CTX*)context)) {
            free(context);
            context = nullptr;
        }
    }
}

xsha1::~xsha1()
{
    if (nullptr != context) {
        free(context);
        context = nullptr;
    }
}

void xsha1::compute(const void* data, size_t size)
{
    if (nullptr == context)
        return;
    SHA1_Update((SHA_CTX*)context, data, size);
}

void xsha1::finalize()
{
    if (nullptr == context)
        return;
    SHA1_Final(result, (SHA_CTX*)context);
    finalized = true;
}

void xsha1::reset()
{
    if (nullptr != context) {
        finalized = false;
        memset(result, 0, 20);
        memset(context, 0, sizeof(SHA_CTX));
        SHA1_Init((SHA_CTX*)context);
    }
}

std::string xsha1::to_string()
{
    std::string s;
    if (nullptr != context && finalized) {
        for (int i = 0; i < 20; i++)
            s.append(ucharToHex(result[i]));
    }
    return s;
}

std::vector<uint8_t> xsha1::get_hash(const void* data, size_t size)
{
    std::vector<uint8_t> h(20, 0);
    if (!XhSha1(data, size, h.data()))
        h.clear();
    return h;
}

std::string xsha1::get_hash_string(const void* data, size_t size)
{
    std::string s;
    const std::vector<uint8_t>& h = xsha1::get_hash(data, size);
    for (auto uc : h) {
        s.append(ucharToHex(uc));
    }
    return s;
}

xsha256::xsha256()
{
    memset(result, 0, 32);
    context = malloc(sizeof(SHA256_CTX));
    if (nullptr != context) {
        memset(context, 0, sizeof(SHA256_CTX));
        if (!SHA256_Init((SHA256_CTX*)context)) {
            free(context);
            context = nullptr;
        }
    }
}

xsha256::~xsha256()
{
    if (nullptr != context) {
        free(context);
        context = nullptr;
    }
}

void xsha256::compute(const void* data, size_t size)
{
    if (nullptr == context)
        return;
    SHA256_Update((SHA256_CTX*)context, data, size);
}

void xsha256::finalize()
{
    if (nullptr == context)
        return;
    SHA256_Final(result, (SHA256_CTX*)context);
    finalized = true;
}

void xsha256::reset()
{
    if (nullptr != context) {
        finalized = false;
        memset(result, 0, 32);
        memset(context, 0, sizeof(SHA256_CTX));
        SHA256_Init((SHA256_CTX*)context);
    }
}

std::string xsha256::to_string()
{
    std::string s;
    if (nullptr != context && finalized) {
        for (int i = 0; i < 32; i++)
            s.append(ucharToHex(result[i]));
    }
    return s;
}

std::vector<uint8_t> xsha256::get_hash(const void* data, size_t size)
{
    std::vector<uint8_t> h(32, 0);
    if (!XhSha256(data, size, h.data()))
        h.clear();
    return h;
}

std::string xsha256::get_hash_string(const void* data, size_t size)
{
    std::string s;
    const std::vector<uint8_t>& h = xsha256::get_hash(data, size);
    for (auto uc : h) {
        s.append(ucharToHex(uc));
    }
    return s;
}