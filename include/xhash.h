#pragma once

#ifdef __cplusplus
extern "C" {
#endif

unsigned int XhCrc32(unsigned int init, const void* data, size_t size);
unsigned __int64 XhCrc64(unsigned __int64 init, const void* data, size_t size);
int XhMd5(const void* data, size_t size, unsigned char* md5);
int XhSha1(const void* data, size_t size, unsigned char* sha1);
int XhSha256(const void* data, size_t size, unsigned char* sha256);

#ifdef __cplusplus
}
#endif