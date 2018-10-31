#include <Windows.h>
#include <boost/test/unit_test.hpp>

#include "xhashcpp.h"

static const unsigned char md5Ntdll[16] = { 0x06, 0xf3, 0x2d, 0xb8, 0x2e, 0x57, 0x42, 0xc5, 0x1a, 0xe3, 0x05, 0x5b, 0xfb, 0xe1, 0xe0, 0xc5 };

BOOST_AUTO_TEST_SUITE(MD5)

BOOST_AUTO_TEST_CASE(TestXmd5Static)
{
    const std::vector<uint8_t>& hash = xsec::xmd5::get_hash("ntdll.dll", 9);
    BOOST_ASSERT_MSG(hash.size() == 16 && 0 == memcmp(md5Ntdll, hash.data(), 16), "Wrong ntdll.dll md5 hash");

    const std::string& shash = xsec::xmd5::get_hash_string("ntdll.dll", 9);
    BOOST_ASSERT_MSG(shash == "06f32db82e5742c51ae3055bfbe1e0c5", "Wrong ntdll.dll md5 hash string");
}

BOOST_AUTO_TEST_CASE(TestXmd5Dynamic)
{
    xsec::xmd5 hasher;
    hasher.compute("n", 1);
    hasher.compute("t", 1);
    hasher.compute("d", 1);
    hasher.compute("l", 1);
    hasher.compute("l", 1);
    hasher.compute(".", 1);
    hasher.compute("d", 1);
    hasher.compute("l", 1);
    hasher.compute("l", 1);
    hasher.finalize();
    BOOST_ASSERT_MSG(0 == memcmp(md5Ntdll, hasher.get(), 16), "Wrong ntdll.dll md5 hash (dyn)");

    const std::string& shash = hasher.to_string();
    BOOST_ASSERT_MSG(shash == "06f32db82e5742c51ae3055bfbe1e0c5", "Wrong ntdll.dll md5 hash string (dyn)");
}

BOOST_AUTO_TEST_CASE(TestXmd5Combine)
{
    xsec::xmd5 hasher;
    hasher.compute("ntdll.dll", 9);
    hasher.finalize();
    BOOST_ASSERT_MSG(0 == memcmp(md5Ntdll, hasher.get(), 16), "Wrong ntdll.dll md5 hash (combined - 0)");
    const std::string& shash = hasher.to_string();
    BOOST_ASSERT_MSG(shash == "06f32db82e5742c51ae3055bfbe1e0c5", "Wrong ntdll.dll md5 hash string (combined - 0)");

    hasher.reset();
    hasher.compute("n", 1);
    hasher.compute("t", 1);
    hasher.compute("d", 1);
    hasher.compute("l", 1);
    hasher.compute("l", 1);
    hasher.compute(".", 1);
    hasher.compute("d", 1);
    hasher.compute("l", 1);
    hasher.compute("l", 1);
    hasher.finalize();
    BOOST_ASSERT_MSG(0 == memcmp(md5Ntdll, hasher.get(), 16), "Wrong ntdll.dll md5 hash (combined - 1)");

    const std::string& shash2 = hasher.to_string();
    BOOST_ASSERT_MSG(shash2 == "06f32db82e5742c51ae3055bfbe1e0c5", "Wrong ntdll.dll md5 hash string (combined - 1)");
}

BOOST_AUTO_TEST_SUITE_END()