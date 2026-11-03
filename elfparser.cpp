#include <iostream>
#include <cstdint>

#include <fstream>
#include <stdexcept>
#include <string>

#include <iomanip>

#include <cstdlib> // for calloc and free

#define ELF_32 1
#define ELF_64 2

#define ELF_LITTLE_ENDIAN 1
#define ELF_BIG_ENDIAN 2 // not like the x86 bootloader gives a shit about bigend but still

#define ET_EXEC 2
#define ET_DYN 3

#define EM_86 0x03
#define EM_8664 0x3E

#define PN_XNUM 0xFFFF

#define PT_LOAD 0x01
#define PF_X 0x1
#define PF_W 0x2
#define PF_R 0x4

#define SBL_MAX_REGION 8192 // max bytes SBL will check

#define MAJOR 26
#define MINOR 9

struct ELFHeader {
    uint8_t magic[4]; // Magic number
    uint8_t class_;   // 32-bit or 64-bit
    uint8_t data;     // Endianness
    uint8_t version;  // ELF version
    uint8_t osabi;    // Operating System ABI identification
    uint8_t abiversion; // ABI version
    uint8_t pad[7];   // Padding bytes

} __attribute__((packed));

struct ELF32Header {
    ELFHeader e_ident;
    uint16_t e_type;      // Object file type
    uint16_t e_machine;   // Architecture
    uint32_t e_version;   // Object file version
    uint32_t e_entry;     // Entry point virtual address
    uint32_t e_phoff;     // Program header table file offset
    uint32_t e_shoff;     // Section header table file offset
    uint32_t e_flags;     // Processor-specific flags
    uint16_t e_ehsize;    // ELF header size in bytes
    uint16_t e_phentsize; // Program header table entry size
    uint16_t e_phnum;     // Program header table entry count
    uint16_t e_shentsize; // Section header table entry size
    uint16_t e_shnum;     // Section header table entry count
    uint16_t e_shstrndx;  // Section header string table index
} __attribute__((packed));

struct ELF64Header {
    ELFHeader e_ident;
    uint16_t e_type;      // Object file type
    uint16_t e_machine;   // Architecture
    uint32_t e_version;   // Object file version
    uint64_t e_entry;     // Entry point virtual address
    uint64_t e_phoff;     // Program header table file offset
    uint64_t e_shoff;     // Section header table file offset
    uint32_t e_flags;     // Processor-specific flags
    uint16_t e_ehsize;    // ELF header size in bytes
    uint16_t e_phentsize; // Program header table entry size
    uint16_t e_phnum;     // Program header table entry count
    uint16_t e_shentsize; // Section header table entry size
    uint16_t e_shnum;     // Section header table entry count
    uint16_t e_shstrndx;  // Section header string table index
} __attribute__((packed));

struct pheader32 {
    uint32_t p_type;   // Segment type
    uint32_t p_offset; // Segment file offset
    uint32_t p_vaddr;  // Segment virtual address
    uint32_t p_paddr;  // Segment physical address
    uint32_t p_filesz; // Segment size in file
    uint32_t p_memsz;  // Segment size in memory
    uint32_t p_flags;  // Segment flags
    uint32_t p_align;  // Segment alignment
} __attribute__((packed));

struct pheader64 {
    uint32_t p_type;   // Segment type
    uint32_t p_flags;  // Segment flags
    uint64_t p_offset; // Segment file offset
    uint64_t p_vaddr;  // Segment virtual address
    uint64_t p_paddr;  // Segment physical address
    uint64_t p_filesz; // Segment size in file
    uint64_t p_memsz;  // Segment size in memory
    uint64_t p_align;  // Segment alignment
} __attribute__((packed));

void PrintELFHeader(const ELFHeader& header) {
    std::cout << "ELF Header:" << std::endl;
    std::cout << "\t" << ((header.class_ == 1) ? "32-bit" : (header.class_ == 2) ? "64-bit" : "Unknown class") << std::endl;
    std::cout << "\t" << ((header.data == 1) ? "Little-endian" : (header.data == 2) ? "Big-endian" : "Unknown endianness") << std::endl;
    std::cout << "\tVersion: " << static_cast<int>(header.version) << std::endl;
    switch (header.osabi) {
        case 0: std::cout << "\tOS ABI: System V" << std::endl; break;
        case 1: std::cout << "\tOS ABI: HP-UX" << std::endl; break;
        case 2: std::cout << "\tOS ABI: NetBSD" << std::endl; break;
        case 3: std::cout << "\tOS ABI: Linux" << std::endl; break;
        case 6: std::cout << "\tOS ABI: Solaris" << std::endl; break;
        case 7: std::cout << "\tOS ABI: AIX" << std::endl; break;
        case 8: std::cout << "\tOS ABI: IRIX" << std::endl; break;
        case 9: std::cout << "\tOS ABI: FreeBSD" << std::endl; break;
        case 10: std::cout << "\tOS ABI: Tru64" << std::endl; break;
        case 11: std::cout << "\tOS ABI: Novell Modesto" << std::endl; break;
        case 12: std::cout << "\tOS ABI: OpenBSD" << std::endl; break;
        default: std::cout << "\tOS ABI: Unknown (" << static_cast<int>(header.osabi) << ")" << std::endl; break;
    }
    std::cout << "\tABI Version: " << static_cast<int>(header.abiversion) << std::endl << std::endl;
}

enum class ELFHeaderValidationResult {
    BadMagic,
    BadClass,
    BadData,
    BadVersion,
    Good
};

ELFHeaderValidationResult ValidateELFHeader(const ELFHeader& header) {
    if (header.magic[0] != 0x7F || header.magic[1] != 'E' || header.magic[2] != 'L' || header.magic[3] != 'F') return ELFHeaderValidationResult::BadMagic;
    if (header.class_ != ELF_32 && header.class_ != ELF_64) return ELFHeaderValidationResult::BadClass;
    if (header.data != ELF_LITTLE_ENDIAN) return ELFHeaderValidationResult::BadData; // Only support little-endian for now
    if (header.version != 1) return ELFHeaderValidationResult::BadVersion; // Only version 1 really exists
    return ELFHeaderValidationResult::Good;
}

enum class ElfLongHeaderValidationResult {
    BadType,
    UnsupportedType,
    BadMachine,
    BadVersion,
    BadEntryPoint,
    BadProgramHeaderOffset,
    BadSectionHeaderOffset,
    BadHeaderSize,
    BadProgramHeaderEntrySize,
    BadProgramHeaderEntryCount,
    BadSectionHeaderStringTableIndex,
    UnsupportedCombination,
    UnsupportedProgramHeaderEntryCount,
    UnsupportedOther,
    Good
};

// assumes that the ELFHeader has already been validated and is good
ElfLongHeaderValidationResult ValidateELF32Header(const ELF32Header& header, const uint64_t fileSize) {
    if (header.e_type == ET_DYN) return ElfLongHeaderValidationResult::UnsupportedType;
    if (header.e_type != ET_EXEC) return ElfLongHeaderValidationResult::BadType;
    if (header.e_machine == EM_8664) return ElfLongHeaderValidationResult::UnsupportedCombination; // 64-bit architecture with 32-bit header is not supported
    if (header.e_machine != EM_86) return ElfLongHeaderValidationResult::BadMachine;
    if (header.e_version != 1) return ElfLongHeaderValidationResult::BadVersion;
    // if (header.e_entry > ) // was about to check if a uint32_t may be greater than uint32_max whoops
    if (header.e_phoff > fileSize) return ElfLongHeaderValidationResult::BadProgramHeaderOffset;
    if (header.e_shoff > fileSize) return ElfLongHeaderValidationResult::BadSectionHeaderOffset;
    if (header.e_ehsize != sizeof(ELF32Header)) return ElfLongHeaderValidationResult::BadHeaderSize;
    if (header.e_phentsize != sizeof(pheader32)) return ElfLongHeaderValidationResult::BadProgramHeaderEntrySize;
    if (header.e_phnum == 0) return ElfLongHeaderValidationResult::BadProgramHeaderEntryCount;
    if (header.e_phnum == PN_XNUM) return ElfLongHeaderValidationResult::UnsupportedProgramHeaderEntryCount; // extended program header count is not supported
    if (uint64_t(header.e_phnum) * header.e_phentsize + header.e_phoff > fileSize) return ElfLongHeaderValidationResult::BadProgramHeaderEntryCount;
    return ElfLongHeaderValidationResult::Good;
}

template<typename T>
void PrintLongELFHeader(const T& header) {
    if constexpr (std::is_same_v<T, ELF32Header>) {
        std::cout << "ELF32 Header:" << std::endl;
    } else if constexpr (std::is_same_v<T, ELF64Header>) {
        std::cout << "ELF64 Header:" << std::endl;
    } else {
        static_assert(false, "Unsupported ELF header type");
    }
    std::cout << "\tObject type: ";
    switch(header.e_type) {
        case 0: std::cout << "None" << std::endl; break;
        case 1: std::cout << "Relocatable file" << std::endl; break;
        case 2: std::cout << "Executable file" << std::endl; break;
        case 3: std::cout << "Shared object file" << std::endl; break;
        case 4: std::cout << "Core file" << std::endl; break;
        default: std::cout << "Unknown (" << header.e_type << ")" << std::endl; break;
    }
    switch(header.e_machine) {
        case EM_86: std::cout << "\tArchitecture: x86" << std::endl; break;
        case EM_8664: std::cout << "\tArchitecture: x86-64" << std::endl; break;
        default: std::cout << "\tUnknown/unsupported architecture (" << header.e_machine << ")" << std::endl; break;
    }
    std::cout << "\tEntry point: 0x" << std::hex << header.e_entry << std::dec << std::endl;
    std::cout << "\tProgram header offset: " << header.e_phoff << " bytes" << std::endl;
    std::cout << "\tSection header offset: " << header.e_shoff << " bytes" << std::endl;
    std::cout << "\tHeader size: " << header.e_ehsize << " bytes" << std::endl;
    std::cout << "\tProgram header entry size: " << header.e_phentsize << " bytes" << std::endl;
    std::cout << "\tProgram header entry count: " << header.e_phnum << std::endl;
    std::cout << "\tSection header entry size: " << header.e_shentsize << " bytes" << std::endl;
    std::cout << "\tSection header entry count: " << header.e_shnum << std::endl;
    std::cout << "\tSection header string table index: " << header.e_shstrndx << std::endl << std::endl;
}

// assumes that the ELFHeader has already been validated and is good
ElfLongHeaderValidationResult ValidateELF64Header(const ELF64Header& header, const uint64_t fileSize) {
    if (header.e_type == ET_DYN) return ElfLongHeaderValidationResult::UnsupportedType;
    if (header.e_type != ET_EXEC) return ElfLongHeaderValidationResult::BadType;
    if (header.e_machine == EM_86) return ElfLongHeaderValidationResult::UnsupportedCombination; // 32-bit architecture with 64-bit header is not supported
    if (header.e_machine != EM_8664) return ElfLongHeaderValidationResult::BadMachine;
    if (header.e_version != 1) return ElfLongHeaderValidationResult::BadVersion;
    if (header.e_entry > UINT32_MAX) return ElfLongHeaderValidationResult::BadEntryPoint; // only support 32-bit entry points for now
    if (header.e_phoff > fileSize) return ElfLongHeaderValidationResult::BadProgramHeaderOffset;
    if (header.e_shoff > fileSize) return ElfLongHeaderValidationResult::BadSectionHeaderOffset;
    if (header.e_ehsize != sizeof(ELF64Header)) return ElfLongHeaderValidationResult::BadHeaderSize;
    if (header.e_phentsize != sizeof(pheader64)) return ElfLongHeaderValidationResult::BadProgramHeaderEntrySize;
    if (header.e_phnum == 0) return ElfLongHeaderValidationResult::BadProgramHeaderEntryCount;
    if (header.e_phnum == PN_XNUM) return ElfLongHeaderValidationResult::UnsupportedProgramHeaderEntryCount; // extended program header count is not supported
    if (uint64_t(header.e_phnum) * header.e_phentsize > fileSize - header.e_phoff) return ElfLongHeaderValidationResult::BadProgramHeaderEntryCount;
    return ElfLongHeaderValidationResult::Good;
}

enum class ProgramHeaderValidationResult {
    UnloadableSegment,
    InvalidFlags,
    InvalidOffset,
    InvalidSegmentSize,
    InvalidMemoryLocation,
    InvalidAlignment,
    Good
};

template<typename R>
ProgramHeaderValidationResult ValidateProgramHeader(const R& header, const uint64_t fileSize) {
    constexpr uint64_t ADDRESS_SPACE_SIZE = uint64_t{1} << 32;

    if (header.p_type != PT_LOAD) return ProgramHeaderValidationResult::UnloadableSegment;
    if (header.p_flags & ~(PF_X | PF_W | PF_R)) return ProgramHeaderValidationResult::InvalidFlags;
    if (header.p_offset > fileSize || header.p_filesz > fileSize - header.p_offset) return ProgramHeaderValidationResult::InvalidOffset;
    if (header.p_filesz > header.p_memsz) return ProgramHeaderValidationResult::InvalidSegmentSize;
    if (header.p_paddr >= ADDRESS_SPACE_SIZE || header.p_memsz > ADDRESS_SPACE_SIZE - header.p_paddr) return ProgramHeaderValidationResult::InvalidMemoryLocation;
    if (header.p_vaddr != header.p_paddr) return ProgramHeaderValidationResult::InvalidMemoryLocation;
    if (header.p_align > 1) {
        if ((header.p_align & (header.p_align - 1)) != 0) return ProgramHeaderValidationResult::InvalidAlignment;
        if ((header.p_vaddr % header.p_align) != (header.p_offset % header.p_align)) return ProgramHeaderValidationResult::InvalidAlignment;
    }
    return ProgramHeaderValidationResult::Good;
}

template<typename R>
void PrintProgramHeader(const R& header) {
    std::cout << "\tSegment type: ";
    switch (header.p_type) {
        case 0: std::cout << "Unused" << std::endl; break;
        case 1: std::cout << "Loadable segment" << std::endl; break;
        case 2: std::cout << "Dynamic linking" << std::endl; break;
        case 3: std::cout << "Interpreter information" << std::endl; break;
        case 4: std::cout << "Auxiliary information" << std::endl; break;
        case 5: std::cout << "Reserved" << std::endl; break;
        case 6: std::cout << "Program header table" << std::endl; break;
        case 7: std::cout << "Thread-local storage" << std::endl; break;
        default: std::cout << "Unknown program header type: " << header.p_type << std::endl; break;
    }

    std::cout << "\tSegment flags: ";
    if (header.p_flags & 0x1) std::cout << "Executable; ";
    if (header.p_flags & 0x2) std::cout << "Writable; ";
    if (header.p_flags & 0x4) std::cout << "Readable; ";
    std::cout << std::endl;

    std::cout << "\tSegment offset: " << header.p_offset << " bytes" << std::endl;
    std::cout << "\tSegment virtual address: 0x" << std::hex << header.p_vaddr << std::dec << std::endl;

    std::cout << "\tSegment physical address: 0x" << std::hex << header.p_paddr << std::dec << std::endl;
    std::cout << "\tSegment size in file: " << header.p_filesz << " bytes" << std::endl;
    std::cout << "\tSegment size in memory: " << header.p_memsz << " bytes" << std::endl;
    std::cout << "\tSegment alignment: " << header.p_align << " bytes" << std::endl;

    std::cout << std::endl;
}

static_assert(sizeof(ELFHeader) == 0x10, "ELFHeader size is not 16 bytes");
static_assert(sizeof(ELF32Header) == 0x34, "ELF32Header size is not 52 bytes");
static_assert(sizeof(ELF64Header) == 0x40, "ELF64Header size is not 64 bytes");

struct SBLHeader {
    uint8_t magic[8]; // "NEKONEK0"
    uint16_t major; // contract year
    uint16_t minor; // contract month
    uint32_t size; // header size
    uint64_t flags; // flags for SBL
    uint64_t stack; // stack size
    uint8_t padding[24]; // zeroed out
    uint64_t checksum; // crc32 checksum of the header

} __attribute__((packed));

static_assert(sizeof(SBLHeader) == 0x40, "SBLHeader size is not 64 bytes");

uint64_t crc64(uint8_t* data, uint64_t len) {
    uint64_t crc = 0;
    uint64_t poly = 0x42F0E1EBA9EA3693;

    for (uint64_t i = 0; i < len; i++) {
        crc ^= (uint64_t)data[i] << 56ULL;
        for (uint8_t j = 0; j < 8; j++) {
            if (crc & (1ULL << 63)) crc = ((crc << 1) ^ poly) & 0xFFFFFFFFFFFFFFFF;
            else crc = (crc << 1) & 0xFFFFFFFFFFFFFFFF;
        }
    }

    return crc;
}


int main(int argc, char* argv[]) {
    
    const char* filename = "./bin/neko.elf";

    // open file
    std::ifstream file(filename, std::ios::binary);
    if (!file) throw std::runtime_error("Failed to open file");

    file.seekg(0, std::ios::end);
    std::streampos fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::cout << filename << " filesize: " << fileSize << " bytes" << std::endl;

    // read ELF header
    uint8_t* buffer = (uint8_t*)calloc(1, sizeof(ELF64Header));
    file.read((char*)buffer, sizeof(ELF64Header));
    if (!file) {
        free(buffer);
        file.close();
        throw std::runtime_error("Failed to read ELF header");
    }
    ELFHeader* elfHeader = (ELFHeader*)buffer;
    ELFHeaderValidationResult validationResult = ValidateELFHeader(*elfHeader);
    if (validationResult != ELFHeaderValidationResult::Good) {
        free(buffer);
        file.close();
        switch(validationResult) {
            case ELFHeaderValidationResult::BadMagic: throw std::runtime_error("malformed magic");
            case ELFHeaderValidationResult::BadClass: throw std::runtime_error("invalid elf class");
            case ELFHeaderValidationResult::BadData: throw std::runtime_error("data encoding malformed or big-endian (if big-endian then fuck you fatass)");
            case ELFHeaderValidationResult::BadVersion: throw std::runtime_error("elf version is 1 and only 1 please fix your file");
            default: throw std::runtime_error("some fucked up shit just happened idek");
        }
    }

    PrintELFHeader(*elfHeader);


    bool isSBLFile = false;
    uint16_t sblSeekSize = [](uint64_t x, uint64_t y) -> uint16_t { return (x < y) ? x : y; }(SBL_MAX_REGION, fileSize);
    buffer = (uint8_t*)calloc(1, sblSeekSize);
    file.seekg(0, std::ios::beg);
    if (!file) {
        free(buffer);
        file.close();
        throw std::runtime_error("Failed to seek to beginning of file");
    }
    file.read((char*)buffer, sblSeekSize);
    if (!file) {
        free(buffer);
        file.close();
        throw std::runtime_error("Failed to read SBL region");
    }
    SBLHeader* sblHeader = (SBLHeader*)buffer;
    for (uint16_t i = 0; i < sblSeekSize - sizeof(SBLHeader); i++) {
        sblHeader = (SBLHeader*)(buffer + i);
        if (!(sblHeader->magic[0] == 'N' && sblHeader->magic[1] == 'E' && sblHeader->magic[2] == 'K' && sblHeader->magic[3] == 'O' &&
            sblHeader->magic[4] == 'N' && sblHeader->magic[5] == 'E' && sblHeader->magic[6] == 'K' && sblHeader->magic[7] == 'O')) continue;
        uint64_t calculatedChecksum = crc64((uint8_t*)sblHeader, sizeof(SBLHeader) - sizeof(uint64_t));
        if (calculatedChecksum != sblHeader->checksum) continue;
        isSBLFile = true;
        std::cout << "SBL Header found at offset: " << i << std::endl;
        std::cout << "\tMajor: " << sblHeader->major << std::endl;
        std::cout << "\tMinor: " << sblHeader->minor << std::endl;
        std::cout << "\tHeader size: " << sblHeader->size << " bytes" << std::endl;
        std::cout << "\tFlags: 0x" << std::hex << sblHeader->flags << std::dec << std::endl;
        uint64_t stackSize = sblHeader->stack;
        if (sblHeader->stack == 0) stackSize = 0x10000; // default stack size if not specified
        std::cout << "\tStack size: " << stackSize << " bytes" << std::endl;
        std::cout << "\tChecksum: 0x" << std::hex << sblHeader->checksum << std::dec << std::endl;
        break;
    }
    if (!isSBLFile) std::cerr << "No valid SBL header found in the first " << sblSeekSize << " bytes of the file." << std::endl;

    if (elfHeader->class_ == 1) {
        ELF32Header* elf32Header = (ELF32Header*)buffer;
        auto validationResult2 = ValidateELF32Header(*elf32Header, fileSize);
        if (validationResult2 != ElfLongHeaderValidationResult::Good) {
            free(buffer);
            file.close();
            switch(validationResult2) {
                case ElfLongHeaderValidationResult::BadType: throw std::runtime_error("file is not executable, full stop");
                case ElfLongHeaderValidationResult::UnsupportedType: throw std::runtime_error("dynamic object support not yet implemented");
                case ElfLongHeaderValidationResult::BadMachine: throw std::runtime_error("architecture not supported");
                case ElfLongHeaderValidationResult::BadVersion: throw std::runtime_error("elf version is 1 and only 1 please fix your file");
                case ElfLongHeaderValidationResult::BadEntryPoint: throw std::runtime_error("entry point way out there");
                case ElfLongHeaderValidationResult::BadProgramHeaderOffset: throw std::runtime_error("program header offset is out of bounds");
                case ElfLongHeaderValidationResult::BadSectionHeaderOffset: throw std::runtime_error("section header offset is out of bounds");
                case ElfLongHeaderValidationResult::BadHeaderSize: throw std::runtime_error("header size is not 52 bytes");
                case ElfLongHeaderValidationResult::BadProgramHeaderEntrySize: throw std::runtime_error("program header entry size is not 32 bytes");
                case ElfLongHeaderValidationResult::BadProgramHeaderEntryCount: throw std::runtime_error("program header entry count is 0 or out of bounds");
                case ElfLongHeaderValidationResult::BadSectionHeaderStringTableIndex: throw std::runtime_error("section header string table index is out of bounds");
                case ElfLongHeaderValidationResult::UnsupportedCombination: throw std::runtime_error("unsupported combination of header values");
                case ElfLongHeaderValidationResult::UnsupportedProgramHeaderEntryCount: throw std::runtime_error("unsupported program header entry count");
                case ElfLongHeaderValidationResult::UnsupportedOther: throw std::runtime_error("some other unsupported feature is present");
                default: throw std::runtime_error("some fucked up shit just happened idek");
            }
        }
        PrintLongELFHeader(*elf32Header);

        std::cout << "Program Headers:" << std::endl;
        pheader32* programHeaders = (pheader32*)calloc(elf32Header->e_phnum, elf32Header->e_phentsize);
        file.seekg(elf32Header->e_phoff, std::ios::beg);
        file.read((char*)programHeaders, elf32Header->e_phentsize * elf32Header->e_phnum);
        if (!file) {
            free(buffer);
            free(programHeaders);
            file.close();
            throw std::runtime_error("Failed to read program headers");
        }
        for (uint16_t i = 0; i < elf32Header->e_phnum; i++) {
            auto validationResult3 = ValidateProgramHeader(programHeaders[i], fileSize);
            if (validationResult3 != ProgramHeaderValidationResult::Good) {
                switch (validationResult3) {
                    case ProgramHeaderValidationResult::UnloadableSegment: std::cerr << "Unloadable segment" << std::endl; break;
                    case ProgramHeaderValidationResult::InvalidFlags: std::cerr << "Invalid segment flags" << std::endl; break;
                    case ProgramHeaderValidationResult::InvalidOffset: std::cerr << "Invalid segment offset" << std::endl; break;
                    case ProgramHeaderValidationResult::InvalidSegmentSize: std::cerr << "Invalid segment size" << std::endl; break;
                    case ProgramHeaderValidationResult::InvalidMemoryLocation: std::cerr << "Invalid memory location" << std::endl; break;
                    case ProgramHeaderValidationResult::InvalidAlignment: std::cerr << "Invalid alignment" << std::endl; break;
                }
                continue; // skip printing this segment if it's invalid
            }
            PrintProgramHeader(programHeaders[i]);
        }
        free(programHeaders);
    }
    else if (elfHeader->class_ == 2) {
        ELF64Header* elf64Header = (ELF64Header*)buffer;
        auto validationResult2 = ValidateELF64Header(*elf64Header, fileSize);
        if (validationResult2 != ElfLongHeaderValidationResult::Good) {
            free(buffer);
            file.close();
            switch(validationResult2) {
                case ElfLongHeaderValidationResult::BadType: throw std::runtime_error("file is not executable, full stop");
                case ElfLongHeaderValidationResult::UnsupportedType: throw std::runtime_error("dynamic object support not yet implemented");
                case ElfLongHeaderValidationResult::BadMachine: throw std::runtime_error("architecture not supported");
                case ElfLongHeaderValidationResult::BadVersion: throw std::runtime_error("elf version is 1 and only 1 please fix your file");
                case ElfLongHeaderValidationResult::BadEntryPoint: throw std::runtime_error("entry point way out there");
                case ElfLongHeaderValidationResult::BadProgramHeaderOffset: throw std::runtime_error("program header offset is out of bounds");
                case ElfLongHeaderValidationResult::BadSectionHeaderOffset: throw std::runtime_error("section header offset is out of bounds");
                case ElfLongHeaderValidationResult::BadHeaderSize: throw std::runtime_error("header size is not 64 bytes");
                case ElfLongHeaderValidationResult::BadProgramHeaderEntrySize: throw std::runtime_error("program header entry size is not 56 bytes");
                case ElfLongHeaderValidationResult::BadProgramHeaderEntryCount: throw std::runtime_error("program header entry count is 0 or out of bounds");
                case ElfLongHeaderValidationResult::BadSectionHeaderStringTableIndex: throw std::runtime_error("section header string table index is out of bounds");
                case ElfLongHeaderValidationResult::UnsupportedCombination: throw std::runtime_error("unsupported combination of header values");
                case ElfLongHeaderValidationResult::UnsupportedProgramHeaderEntryCount: throw std::runtime_error("unsupported program header entry count");
                case ElfLongHeaderValidationResult::UnsupportedOther: throw std::runtime_error("some other unsupported feature is present");
                default: throw std::runtime_error("some fucked up shit just happened idek");
            }
        }
        PrintLongELFHeader(*elf64Header);

        std::cout << "Program Headers:" << std::endl;
        pheader64* programHeaders = (pheader64*)calloc(elf64Header->e_phnum, elf64Header->e_phentsize);
        file.seekg(elf64Header->e_phoff, std::ios::beg);
        file.read((char*)programHeaders, elf64Header->e_phentsize * elf64Header->e_phnum);
        if (!file) {
            free(buffer);
            free(programHeaders);
            file.close();
            throw std::runtime_error("Failed to read program headers");
        }
        for (uint16_t i = 0; i < elf64Header->e_phnum; i++) {
            auto validationResult3 = ValidateProgramHeader(programHeaders[i], fileSize);
            if (validationResult3 != ProgramHeaderValidationResult::Good) {
                switch (validationResult3) {
                    case ProgramHeaderValidationResult::UnloadableSegment: std::cerr << "Unloadable segment" << std::endl; break;
                    case ProgramHeaderValidationResult::InvalidFlags: std::cerr << "Invalid segment flags" << std::endl; break;
                    case ProgramHeaderValidationResult::InvalidOffset: std::cerr << "Invalid segment offset" << std::endl; break;
                    case ProgramHeaderValidationResult::InvalidSegmentSize: std::cerr << "Invalid segment size" << std::endl; break;
                    case ProgramHeaderValidationResult::InvalidMemoryLocation: std::cerr << "Invalid memory location" << std::endl; break;
                    case ProgramHeaderValidationResult::InvalidAlignment: std::cerr << "Invalid alignment" << std::endl; break;
                }
                continue; // skip printing this segment if it's invalid
            }
            PrintProgramHeader(programHeaders[i]);
        }
        free(programHeaders);
    }
    else {
        file.close();
        free(buffer);
        throw std::runtime_error("Unknown ELF class");
    }
    // end of program close file
    file.close();
    free(buffer);
    return 0;
}

#if false
// this is pseudocode btw. well technically real code but you get the point.
for (segment s : program) {
    if (isValidSegment(segment) && segment.p_type == PT_LOAD) {
        uint8_t* membuffer = (uint8_t*)(segment.p_addr);
        for (uint64_t i = 0; i < segment.p_filesz; i++) membuffer[i] = ((uint8_t*)(&program))[segment.p_offset + i];
        for (uint64_t i = segment.p_filesz; i < segment.p_memsz; i++) membuffer[i] = 0;
    }
}
jmp(program.e_entry);
#endif