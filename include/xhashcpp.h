#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace xsec
{

class xhash
{
public:
    virtual ~xhash() {}
    virtual void compute(const void* data, size_t size) = 0;
    virtual void finalize() = 0;
    virtual void reset() = 0;
    virtual std::string to_string() = 0;
protected:
    xhash() : context(nullptr), finalized(false) {}
    void* context;
    bool finalized;
};

class xmd5 : public xhash
{
public:
    xmd5();
    virtual ~xmd5();

    virtual void compute(const void* data, size_t size);
    virtual void finalize();
    virtual void reset();
    virtual std::string to_string();

    inline const uint8_t* get() const { return result; }

    static std::vector<uint8_t> get_hash(const void* data, size_t size);
    static std::string get_hash_string(const void* data, size_t size);

private:
    uint8_t result[16];
};

class xsha1 : public xhash
{
public:
    xsha1();
    virtual ~xsha1();

    virtual void compute(const void* data, size_t size);
    virtual void finalize();
    virtual void reset();
    virtual std::string to_string();

    inline const uint8_t* get() const { return result; }

    static std::vector<uint8_t> get_hash(const void* data, size_t size);
    static std::string get_hash_string(const void* data, size_t size);

private:
    void* context;
    uint8_t result[20];
};

class xsha256 : public xhash
{
public:
    xsha256();
    virtual ~xsha256();

    virtual void compute(const void* data, size_t size);
    virtual void finalize();
    virtual void reset();
    virtual std::string to_string();

    inline const uint8_t* get() const { return result; }

    static std::vector<uint8_t> get_hash(const void* data, size_t size);
    static std::string get_hash_string(const void* data, size_t size);

private:
    void* context;
    uint8_t result[32];
};

}