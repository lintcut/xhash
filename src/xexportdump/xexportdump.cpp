#include <Windows.h>

#include "xhashcpp.h"

#include <boost/program_options.hpp>
#include <iostream>
#include <string>


enum HashType {
    MD5 = 0,
    SHA1,
    SHA256
};

enum HashFormat {
    HEXSTRING = 0,
    HEXARRAY
};

void dumpExports(const std::string& file, HashType hashtype, HashFormat format);
std::string getCurrentDirectory();
std::string getFullpath(const std::string& file);

int main(int argc, char** argv)
{
    int result = 0;
    try
    {
        boost::program_options::options_description desc{ "Options" };
        desc.add_options()
            ("help,h", "Help screen")
            ("md5", "Use MD5 hash algorithm")
            ("sha1", "Use SHA1 hash algorithm")
            ("sha256", "Use SHA256 hash algorithm")
            ("hexarray,a", "Show hex array instead of string")
            ("file,f", boost::program_options::value<std::string>(), "Target DLL file path");

        boost::program_options::variables_map vm;
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
        boost::program_options::notify(vm);

        if (vm.count("help") || !vm.count("file")) {
            std::cout << desc << std::endl;
        }
        else if (!vm.count("file")) {
            throw std::exception("Missing otpion --file or -f");
        }
        else {
            HashType type = SHA1;
            HashFormat format = HEXSTRING;
            if (vm.count("md5"))
                type = MD5;
            else if  (vm.count("sha256"))
                type = SHA256;
            else
                type = SHA1;
            if (vm.count("hexarray"))
                format = HEXARRAY;
            else
                format = HEXSTRING;
            dumpExports(vm["file"].as<std::string>(), type, format);
        }
    }
    catch (const boost::program_options::error &ex)
    {
        std::cerr << ex.what() << std::endl;
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}

std::string getCurrentDirectory()
{
    char szPath[MAX_PATH] = { 0 };
    ::GetModuleFileNameA(NULL, szPath, MAX_PATH);
    char* pos = strrchr(szPath, '\\');
    if (pos == NULL)
        return "";
    *pos = 0;
    return szPath;
}

std::string getFullpath(const std::string& file)
{
    if (std::string::npos != file.find('\\'))
        return file;
    std::string fullPath = getCurrentDirectory();
    if (!fullPath.empty())
        fullPath.append("\\");
    fullPath.append(file);
    return fullPath;
}

static std::string ucharToHex(uint8_t uc)
{
    static const char* hex = "0123456789abcdef";
    char s[3] = { 0, 0, 0 };
    s[0] = hex[(uc >> 4) & 0xF];
    s[1] = hex[uc & 0xF];
    s[2] = 0;
    return s;
}

void dumpExports(const std::string& file, HashType hashtype, HashFormat format)
{
    const std::string& fullPath = getFullpath(file);
    HANDLE h = INVALID_HANDLE_VALUE;
    HANDLE hMap = NULL;
    LPVOID pData = NULL;

    try {

        h = ::CreateFileA(file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (INVALID_HANDLE_VALUE == h)
            throw std::exception("Fail to open target file");

        hMap = ::CreateFileMappingA(h, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, NULL);
        if(NULL == hMap)
            throw std::exception("Fail to map target file as image");

        pData = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
        if(NULL == pData)
            throw std::exception("Fail to get view of file mapping");

        PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)pData;
        if(dh->e_magic != IMAGE_DOS_SIGNATURE)
            throw std::exception("Not a PE file (dos magic mismatch)");
        PIMAGE_NT_HEADERS nh = (PIMAGE_NT_HEADERS)((ULONG_PTR)pData + dh->e_lfanew);
        if(nh->Signature != IMAGE_NT_SIGNATURE)
            throw std::exception("Not a PE file (nt signature mismatch)");

        PIMAGE_DATA_DIRECTORY entry = NULL;
        PIMAGE_EXPORT_DIRECTORY exports = NULL;

        if (nh->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            PIMAGE_NT_HEADERS32 nh32 = (PIMAGE_NT_HEADERS32)nh;
            entry = &(nh32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
        }
        else if (nh->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            PIMAGE_NT_HEADERS64 nh64 = (PIMAGE_NT_HEADERS64)nh;
            entry = &(nh64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
        }
        else
        {
            throw std::exception("Invalid PE OptionalHeader magic");
        }
        
        exports = (PIMAGE_EXPORT_DIRECTORY)(entry->Size != 0 && entry->VirtualAddress != 0) ? ((PIMAGE_EXPORT_DIRECTORY)((uintptr_t)pData + entry->VirtualAddress)) : NULL;

        UINT* funcAddrTable = (UINT*)((ULONG_PTR)pData + exports->AddressOfFunctions);
        UINT* nameAddrTable = (UINT*)((ULONG_PTR)pData + exports->AddressOfNames);
        USHORT* nameOrdTable = (USHORT*)((ULONG_PTR)pData + exports->AddressOfNameOrdinals);
        for (UINT i = 0; i < exports->NumberOfNames; i++)
        {
            const char* name = (const char*)((ULONG_PTR)pData + nameAddrTable[i]);
            if (format == HEXARRAY)
            {
                const std::vector<uint8_t>& hash = (hashtype == MD5 ? xsec::xmd5::get_hash(name, strlen(name)) : (hashtype == SHA256 ? xsec::xsha256::get_hash(name, strlen(name)) : xsec::xsha1::get_hash(name, strlen(name))));
                std::cout << name << ": \t{";
                for (int i=0; i<(int)hash.size(); i++)
                {
                    if(i > 0)
                        std::cout << ",";
                    std::cout << " 0x";
                    std::cout << ucharToHex(hash[i]);
                }
                std::cout << " }" << std::endl;
            }
            else
            {
                const std::string& hash = (hashtype == MD5 ? xsec::xmd5::get_hash_string(name, strlen(name)) : (hashtype == SHA256 ? xsec::xsha256::get_hash_string(name, strlen(name)) : xsec::xsha1::get_hash_string(name, strlen(name))));
                std::cout << name << ": \t" << hash << std::endl;
            }
        }

        // Cleanup
        ::UnmapViewOfFile(pData);
        CloseHandle(hMap);
        hMap = NULL;
        CloseHandle(h);
        h = INVALID_HANDLE_VALUE;
    }
    catch (const std::exception& e) {
        if (pData != NULL) {
            ::UnmapViewOfFile(pData);
            pData = NULL;
        }
        if (NULL != hMap) {
            CloseHandle(hMap);
            hMap = NULL;
        }
        if (INVALID_HANDLE_VALUE != h) {
            CloseHandle(h);
            h = INVALID_HANDLE_VALUE;
        }
        throw e;
    }
}