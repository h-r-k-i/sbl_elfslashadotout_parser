# elf (Which Is Going To Be More Than An ELF Parser But The Name Stays)

Here is a readme for a project that much like the fat32 parser is going to contain more than
just ELF parsing but for which I can't be fucked to change the name of so yeah.

Right now it reads an ELF file, checks that the headers are sane, looks for an SBL header
somewhere in the first 8 KiB, and prints everything it found.

## Why

SBL has to load the Neko kernel, and the Neko kernel is an ELF file. Before I write an ELF
loader in a bootloader, where every bug is a triple fault and a QEMU window eating shit,
I wanted the same logic running in userspace, where a bug is actually not a nightmare to fix.
So this is the loader's validation code with `std::cout` stapled to it.

The checks are strict on purpose. If it passes here, SBL should be able to load it. If it
doesn't pass here, SBL shouldn't even try.

## Dependencies

- A C++17 compiler. I use g++. `if constexpr` and `std::is_same_v` are in there, so C++14
  won't cut it.
- That's it. No Make this time. God has spared us this once.

If you want to build the example binaries in `src/` yourself:

- `nasm` and `ld` for the assembly ones
- `gcc` for the C one

## Build & run

```sh
git clone https://github.com/h-r-k-i/elf.git
cd elf
g++ -std=c++17 -Wall -Wextra elfparser.cpp -o elfparser
./elfparser
```

You will get some warnings about `argc` and `argv` being unused. They are unused. See
[Known rough edges](#known-rough-edges).

The file it reads is hardcoded to `./bin/neko.elf`. `bin/` is in `.gitignore`, so a fresh
clone won't have one. Grab an ELF binary from... literally anywhere... (hell use the ELF
binary generated compiling this program if you so dare, and if you use Linux) and drop it
in `bin/`, or change the `filename` line at the top of `main()` and recompile.

To build the examples in `src/`:

```sh
mkdir -p bin

# 32-bit, exits with code 81 and does nothing else
nasm -f elf32 src/example.s -o example.o && ld -m elf_i386 example.o -o bin/example

# 64-bit hello world, straight syscalls
nasm -f elf64 src/example2.s -o example2.o && ld example2.o -o bin/example2

# normal C program (gets rejected, it's a PIE, see below)
gcc src/example3.c -o bin/example3
```

Example output (on `neko.elf`):

```
./bin/neko.elf filesize: 5144 bytes
ELF Header:
	32-bit
	Little-endian
	Version: 1
	OS ABI: System V
	ABI Version: 0

SBL Header found at offset: 4096
	Major: 26
	Minor: 10
	Header size: 64 bytes
	Flags: 0x0
	Stack size: 65536 bytes
	Checksum: 0x350764ea1a2e2546
ELF32 Header:
	Object type: Executable file
	Architecture: x86
	Entry point: 0x200040
	Program header offset: 52 bytes
	Section header offset: 4824 bytes
	Header size: 52 bytes
	Program header entry size: 32 bytes
	Program header entry count: 1
	Section header entry size: 40 bytes
	Section header entry count: 8
	Section header string table index: 7

Program Headers:
	Segment type: Loadable segment
	Segment flags: Executable; Readable; 
	Segment offset: 4096 bytes
	Segment virtual address: 0x200000
	Segment physical address: 0x200000
	Segment size in file: 269 bytes
	Segment size in memory: 269 bytes
	Segment alignment: 4096 bytes

```

`elf.txt` has a dump of the other binaries in `bin/`. It came from an older build, so it
still shows `example3` getting parsed. The current build rejects it.

## How it works

1. Read the first 64 bytes, which is enough for either ELF header size.
2. Check `e_ident`: magic is `0x7F 'E' 'L' 'F'`, class is 32 or 64, data is little-endian,
   version is 1. Big-endian gets an error message I'm not going to repeat here.
3. Read up to 8 KiB (`SBL_MAX_REGION`) from the start of the file and slide over it one byte
   at a time looking for `NEKONEKO`. A hit only counts if the CRC-64 of the first 56 bytes
   of the header matches the checksum stored in the last 8.
4. Validate the full header for the class:
   - `e_type` must be `ET_EXEC`. `ET_DYN` (PIEs, shared objects) is "not yet implemented".
   - `e_machine` must match the class. x86 for 32-bit, x86-64 for 64-bit. Mixing them is
     an `UnsupportedCombination`.
   - On 64-bit, the entry point has to fit in 32 bits, because SBL lives in 32-bit land.
   - Header and program header entry sizes have to be exactly what the spec says.
   - Program header table has to exist, has to fit in the file, and can't use `PN_XNUM`.
5. Read the program header table and check each segment:
   - Has to be `PT_LOAD`. Anything else goes to stderr as "Unloadable segment" and is
     skipped.
   - Flags can only be some mix of R, W, X.
   - File range has to fit in the file, and `p_filesz <= p_memsz`.
   - Physical range has to fit under 4 GiB, and `p_vaddr == p_paddr`, because there is no
     paging when SBL loads you.
   - Alignment has to be a power of two, and `p_vaddr` and `p_offset` have to agree modulo
     it.
6. Print whatever survived.

The `#if false` block at the bottom of `elfparser.cpp` is the actual load step: copy
`p_filesz` bytes to `p_paddr`, zero the rest up to `p_memsz`, jump to `e_entry`. It doesn't
compile and it isn't supposed to. That part goes in SBL.

### The SBL header

64 bytes, packed, can be anywhere in the first 8 KiB of the file. On `neko.elf` it's at the
start of the loadable segment, offset 4096.

| Offset | Size | Field      | What                                                  |
|--------|------|------------|-------------------------------------------------------|
| 0x00   | 8    | `magic`    | `NEKONEKO`                                            |
| 0x08   | 2    | `major`    | contract year (26)                                    |
| 0x0A   | 2    | `minor`    | contract month                                        |
| 0x0C   | 4    | `size`     | header size, 64                                       |
| 0x10   | 8    | `flags`    | flags for SBL, none defined yet                       |
| 0x18   | 8    | `stack`    | stack size; 0 means default (64 KiB)                  |
| 0x20   | 24   | `padding`  | zeroed                                                |
| 0x38   | 8    | `checksum` | CRC-64 of bytes 0x00 to 0x37                          |

The CRC is the ECMA-182 polynomial (`0x42F0E1EBA9EA3693`), MSB-first, init 0, no reflection,
no final XOR, no salvation, no hope, no methamphetamine to relieve yourself, no (I'm not 
getting a job am I?). The struct comment says crc32. It's not crc32. The comment is lying.
I lied. Fuck you.

## Known rough edges

- The input path is hardcoded. `argc` and `argv` are right there and I'm not using them.
- `bin/` and `src/` are both in `.gitignore`, so a clone gets the parser and none of the
  stuff to run it on.
- No PIEs, no shared objects, no relocatable files, no big-endian, nothing except x86 and
  x86-64. So any normal binary `gcc` spits out today gets rejected. That's on purpose, SBL
  can't load those either.
- Section headers get counted and nothing else. `e_shoff` is bounds-checked and that's it.
- `MAJOR` and `MINOR` are `#define`d as 26 and 9 and never used. `neko.elf` says 26.10. Nothing
  checks the contract version yet.
- Every fatal error is an uncaught `std::runtime_error`, so you get `terminate called after
  throwing an instance of...` and an abort. Exit codes are vibes.
- The first `calloc` (the 64-byte ELF header buffer) gets overwritten by the second one and
  never freed. It's 64 bytes and the process exits right after. Still a leak though. Whatever.
- The 32-bit and 64-bit paths in `main()` are the same 50 lines pasted twice.
- `disk.hpp` isn't included by anything. It's a one-sector-at-a-time disk image reader for
  whatever this repo turns into next (see the first line of this README). Its comment on
  `getSector` is "Fuck you." Clap for me for I am the second coming of Terry Davis if Davis
  was an autistic trans woman.
- Notably this project does not include support for a.out which is mandated by the contract
  that I haven't finished writing yet. Claude didn't know this when writing this readme.
  But also it took me a month to push out a new commit for SBL/Neko. I take time. I'm slow
  and spend time having a fucking life outside of programming. Be glad I even remembered to
  LLM-hallucinate a README and push this to GitHub.

## Files

| File             | What                                                           |
|------------------|----------------------------------------------------------------|
| `elfparser.cpp`  | the whole parser: structs, validators, printers, `main()`      |
| `disk.hpp`       | sector-based disk image reader, unused for now                 |
| `elf.txt`        | output from an older build, run on everything in `bin/`        |
| `src/example.s`  | 32-bit NASM, `int 0x80` exit with code 81                      |
| `src/example2.s` | 64-bit NASM hello world                                        |
| `src/example3.c` | C hello world, becomes a PIE, gets rejected                    |
| `bin/`           | test binaries, including `neko.elf` (not in git)               |

## References

- [System V ABI / ELF spec (TIS ELF 1.2)](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [ELF on the OSDev Wiki](https://wiki.osdev.org/ELF)
- [Executable and Linkable Format on Wikipedia](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format).
- `man 5 elf`
- `readelf -lh` to check my work against something that actually works

## License

MIT. See [`LICENSE`](LICENSE). Copyright 2026 Renee Graves. All rights reserved unless they're
released by the license which in that case good fucking luck by the time you catch me for
fucking up your system I'll have moved to a country with no extradition treaty with the
United States living my best life.
