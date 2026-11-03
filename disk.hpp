#ifndef DISK_HPP
#define DISK_HPP

#include <cstdint>
#include <fstream>
#include <stdexcept>
#include <string>

class Disk {
    private:
        std::ifstream file;
        std::size_t sectorSize;
    
    public:

        explicit Disk(const std::string& path) : file(path, std::ios::binary) {
            if (!file) throw std::runtime_error("Failed to open disk image: " + path);
            sectorSize = 512; // default sector size
        }

        void SetSectorSize(std::size_t size) {
            if (size == 0) throw std::invalid_argument("Sector size must be greater than zero.");
            sectorSize = size;
        }

        // Just like a real disk driver, this only returns one sector at a time. Fuck you.
        bool getSector(std::uint64_t lba, void* buffer) {
            const std::size_t offset = lba * sectorSize;
            file.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
            if (!file) return false;
            file.read(static_cast<char*>(buffer), static_cast<std::streamsize>(sectorSize));
            if (!file) return false;
            return true;
        }

        uint64_t getDiskSize() {
            file.seekg(0, std::ios::end);
            return static_cast<uint64_t>(file.tellg());
        }
        
};

#endif // DISK_HPP