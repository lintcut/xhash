#include <Windows.h>
#include <boost/test/unit_test.hpp>

#include "xhashcpp.h"

static const unsigned char sha256Ntdll[32] = { 0x97, 0x99, 0xDD, 0xA2, 0x25, 0x7C, 0xAF, 0xA9, 0x91, 0xAA, 0x38, 0xA1, 0x6B, 0xCA, 0x3F, 0xEF, 0x8E, 0x1D, 0xC7, 0x4A, 0x71, 0x0A, 0x45, 0x54, 0x0F, 0x92, 0xB1, 0xFA, 0x6B, 0xEB, 0xB3, 0x25 };


BOOST_AUTO_TEST_SUITE(SHA2)

BOOST_AUTO_TEST_CASE(TestXsha256Static)
{
    const std::vector<uint8_t>& hash = xsec::xsha256::get_hash("ntdll.dll", 9);
    BOOST_ASSERT_MSG(hash.size() == 32 && 0 == memcmp(sha256Ntdll, hash.data(), 32), "Wrong ntdll.dll sha256 hash");

    const std::string& shash = xsec::xsha256::get_hash_string("ntdll.dll", 9);
    BOOST_ASSERT_MSG(shash == "9799dda2257cafa991aa38a16bca3fef8e1dc74a710a45540f92b1fa6bebb325", "Wrong ntdll.dll sha256 hash string");
}

BOOST_AUTO_TEST_CASE(TestXsha256Dynamic)
{
    xsec::xsha256 hasher;
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
    BOOST_ASSERT_MSG(0 == memcmp(sha256Ntdll, hasher.get(), 32), "Wrong ntdll.dll sha256 hash (dyn)");

    const std::string& shash = hasher.to_string();
    BOOST_ASSERT_MSG(shash == "9799dda2257cafa991aa38a16bca3fef8e1dc74a710a45540f92b1fa6bebb325", "Wrong ntdll.dll sha256 hash string (dyn)");
}

BOOST_AUTO_TEST_CASE(TestXsha256Combine)
{
    xsec::xsha256 hasher;
    hasher.compute("ntdll.dll", 9);
    hasher.finalize();
    BOOST_ASSERT_MSG(0 == memcmp(sha256Ntdll, hasher.get(), 32), "Wrong ntdll.dll sha256 hash (combined - 0)");
    const std::string& shash = hasher.to_string();
    BOOST_ASSERT_MSG(shash == "9799dda2257cafa991aa38a16bca3fef8e1dc74a710a45540f92b1fa6bebb325", "Wrong ntdll.dll sha256 hash string (combined - 0)");

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
    BOOST_ASSERT_MSG(0 == memcmp(sha256Ntdll, hasher.get(), 32), "Wrong ntdll.dll sha256 hash (combined - 1)");

    const std::string& shash2 = hasher.to_string();
    BOOST_ASSERT_MSG(shash2 == "9799dda2257cafa991aa38a16bca3fef8e1dc74a710a45540f92b1fa6bebb325", "Wrong ntdll.dll sha256 hash string (combined - 1)");
}

BOOST_AUTO_TEST_SUITE_END()
