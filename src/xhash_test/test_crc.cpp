#include <Windows.h>
#include <boost/test/unit_test.hpp>

#include "xhash.h"

BOOST_AUTO_TEST_SUITE(CRC)

BOOST_AUTO_TEST_CASE(TestCrc32)
{
    BOOST_ASSERT_MSG(0x84c05e40 == XhCrc32(0, "ntdll.dll", 9), "Wrong ntdll.dll module base");
}

BOOST_AUTO_TEST_CASE(TestCrc64)
{
    BOOST_ASSERT_MSG(0x77d251e00b88e495ULL == XhCrc64(0, "ntdll.dll", 9), "Wrong ntdll.dll module base");
}

BOOST_AUTO_TEST_SUITE_END()