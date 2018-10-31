
#include <Windows.h>
#include <boost/test/unit_test.hpp>

#include "xhashcpp.h"

static const unsigned char sha1Ntdll[20] = { 0x0E, 0xBD, 0x8D, 0x88, 0x9E, 0x0E, 0x2C, 0x63, 0xB7, 0xA4, 0x36, 0x1A, 0x8D, 0xFE, 0x00, 0x17, 0x7C, 0xDD, 0x90, 0xBB };


BOOST_AUTO_TEST_SUITE(SHA1)

BOOST_AUTO_TEST_CASE(TestXsha1Static)
{
    const std::vector<uint8_t>& hash = xsec::xsha1::get_hash("ntdll.dll", 9);
    BOOST_ASSERT_MSG(hash.size() == 20 && 0 == memcmp(sha1Ntdll, hash.data(), 20), "Wrong ntdll.dll sha1 hash");

    const std::string& shash = xsec::xsha1::get_hash_string("ntdll.dll", 9);
    BOOST_ASSERT_MSG(shash == "0ebd8d889e0e2c63b7a4361a8dfe00177cdd90bb", "Wrong ntdll.dll sha1 hash string");
}

BOOST_AUTO_TEST_CASE(TestXsha1Dynamic)
{
    xsec::xsha1 hasher;
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
    BOOST_ASSERT_MSG(0 == memcmp(sha1Ntdll, hasher.get(), 20), "Wrong ntdll.dll sha1 hash (dyn)");

    const std::string& shash = hasher.to_string();
    BOOST_ASSERT_MSG(shash == "0ebd8d889e0e2c63b7a4361a8dfe00177cdd90bb", "Wrong ntdll.dll sha1 hash string (dyn)");
}

BOOST_AUTO_TEST_CASE(TestXsha1Combine)
{
    xsec::xsha1 hasher;
    hasher.compute("ntdll.dll", 9);
    hasher.finalize();
    BOOST_ASSERT_MSG(0 == memcmp(sha1Ntdll, hasher.get(), 20), "Wrong ntdll.dll sha1 hash (combined - 0)");
    const std::string& shash = hasher.to_string();
    BOOST_ASSERT_MSG(shash == "0ebd8d889e0e2c63b7a4361a8dfe00177cdd90bb", "Wrong ntdll.dll sha1 hash string (combined - 0)");

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
    BOOST_ASSERT_MSG(0 == memcmp(sha1Ntdll, hasher.get(), 20), "Wrong ntdll.dll sha1 hash (combined - 1)");

    const std::string& shash2 = hasher.to_string();
    BOOST_ASSERT_MSG(shash2 == "0ebd8d889e0e2c63b7a4361a8dfe00177cdd90bb", "Wrong ntdll.dll sha1 hash string (combined - 1)");
}

BOOST_AUTO_TEST_SUITE_END()
