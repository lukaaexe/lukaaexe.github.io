---
title: "PE File Structure - Analysis Walkthrough"
date: 2026-05-25 16:00:00 +0700
categories: [Reverse Engineering]
tags: [pe-format, reverse-engineering, malware-analysis, windows, static-analysis]
---

## Portable Executable File Structure

For malware analysis, knowledge of PE File Structure on Windows is essential — many static analysis techniques rely on understanding it.

This walkthrough uses **Lab01-01.exe** from *Practical Malware Analysis* (Sikorski & Honig) as the sample.

**Resources**:
- Sample: [PracticalMalwareAnalysis-Labs](https://github.com/mikesiko/PracticalMalwareAnalysis-Labs)
- Tools: [Detect It Easy](https://github.com/horsicq/Detect-It-Easy), [PE-Bear](https://github.com/hasherezade/pe-bear)
- Reference: [0xRick's PE Internals](https://0xrick.github.io/win-internals/pe2/)

## Initial Identification with Detect It Easy

![DIE output](/assets/img/pe-die.png)

Lab01-01.exe is a **32-bit PE file** written in Microsoft C++.

## 1. DOS Header

Within `IMAGE_DOS_HEADER`, the analysis focuses on two key fields: `e_magic` and `e_lfanew`. Inspection with PE-Bear:

![DOS Header](/assets/img/pe-dos-header.png)

- **e_magic** (offset `0x00`) holds the value `0x5A4D`, corresponding to the "MZ" signature. This fixed magic number indicates the file conforms to the MS-DOS executable header format and is a valid PE candidate.
- **e_lfanew** (offset `0x3C`) contains the value `0xE8`. This file offset points to the start of the NT Headers — seeking to `0xE8` leads directly to the PE signature.

## 2. DOS Stub

![DOS Stub](/assets/img/pe-dos-stub.png)

The DOS Stub appears immediately after the DOS Header and contains the conventional message:

> "This program cannot be run in DOS mode."

This stub provides backward-compatibility behavior for DOS environments and does not contribute further to modern Windows PE loading.

## 3. Rich Header

The Rich Header is **not formally part of documented PE structures**, but commonly appears in binaries produced by Microsoft Visual Studio toolchains. It may encode metadata related to the build environment, which can occasionally support attribution or clustering efforts during malware analysis.

![Rich Header](/assets/img/pe-rich-header.png)

Since this walkthrough focuses on canonical PE layout, Rich Header interpretation is out of scope.

## 4. NT Headers

NT Headers are defined in `winnt.h` as `IMAGE_NT_HEADERS` (PE32) and `IMAGE_NT_HEADERS64` (PE32+). Since this sample is 32-bit, the relevant structure is `IMAGE_NT_HEADERS`.

### 4.1 PE Signature

The first component is the PE Signature — a 4-byte DWORD with the expected value `0x50450000`, corresponding to the ASCII string "PE\0\0".

![PE Signature](/assets/img/pe-signature.png)

Inspection confirms the sample contains a valid PE signature at the offset specified by `e_lfanew`.

### 4.2 File Header

The COFF File Header (`IMAGE_FILE_HEADER`) is a 20-byte structure containing baseline metadata about the image and pointers to other PE structures.

#### Machine field

The `Machine` field is a 2-byte enum (WORD) defined in `winnt.h` that identifies the target CPU architecture. The Windows loader uses this value to verify the binary is compatible with the host system before mapping it into memory — a mismatched value will cause the loader to reject the file.

Common enum values:

| Value    | Constant                       | Architecture              |
|----------|--------------------------------|---------------------------|
| `0x014C` | `IMAGE_FILE_MACHINE_I386`      | Intel 386 / x86 (32-bit)  |
| `0x8664` | `IMAGE_FILE_MACHINE_AMD64`     | x64 / AMD64 (64-bit)      |
| `0x01C0` | `IMAGE_FILE_MACHINE_ARM`       | ARM little-endian         |
| `0xAA64` | `IMAGE_FILE_MACHINE_ARM64`     | ARM64                     |
| `0x0200` | `IMAGE_FILE_MACHINE_IA64`      | Intel Itanium             |
| `0x0000` | `IMAGE_FILE_MACHINE_UNKNOWN`   | Any machine type          |

**Why this matters for analysis**: the Machine value determines which PE variant follows in the Optional Header — `IMAGE_NT_HEADERS` (PE32) for `0x014C`, or `IMAGE_NT_HEADERS64` (PE32+) for `0x8664`. Picking the wrong structure when parsing will cause offset misalignment in all subsequent fields.

For Lab01-01.exe: Machine = `0x014C` (Intel 386) → 32-bit PE32.

#### Other fields

- **NumberOfSections**: number of section headers in the Section Table
- **TimeDateStamp**: Unix timestamp generally reflecting link time
- **PointerToSymbolTable / NumberOfSymbols**: COFF symbol fields (often stripped in release malware)
- **SizeOfOptionalHeader**: size of the Optional Header
- **Characteristics**: bit flags describing file attributes

For Lab01-01.exe, PE-Bear reports:

![File Header](/assets/img/pe-file-header.png)

- Machine: Intel 386 (`0x014C`)
- NumberOfSections: 3
- TimeDateStamp: Sunday, 19.12.2010
- SizeOfOptionalHeader: 224 bytes
- Characteristics (selected):
  - `0x0001` — relocations stripped
  - `0x0002` — executable image
  - `0x0004` — line numbers stripped
  - `0x0008` — local symbols stripped
  - `0x0100` — 32-bit machine

### 4.3 Optional Header

Despite its name, the Optional Header is **mandatory** for executable images and is the most semantically important header region for the Windows loader.

![Optional Header](/assets/img/pe-optional-header.png)

Key fields:
- **Magic**: `0x10B` indicating PE32
- **Linker Version**: Major `0x06`, Minor `0x00`
- **SizeOfCode**: `0x1000` (typically mapped from `.text`)
- **SizeOfInitializedData**: `0x2000` (commonly `.data`)
- **SizeOfUninitializedData**: `0x00` (commonly `.bss`)
- **AddressOfEntryPoint** (RVA): `0x1820` (first instruction executed after loading)
- **BaseOfCode** (RVA): `0x1000` (start of code section in memory)
- **BaseOfData** (RVA, PE32 only): `0x2000` (start of data section in memory)

#### Windows-Specific Fields

- **ImageBase**: `0x00400000` (preferred load address)
- **SectionAlignment**: `0x1000` (alignment in memory)
- **FileAlignment**: `0x1000` (alignment on disk)
- **OS/Image/Subsystem Versions**: compatibility values (Windows 95 / NT 4.0 in this sample)
- **Win32VersionValue**: reserved, expected `0`
- **SizeOfImage**: `0x4000` (total image size in memory)
- **SizeOfHeaders**: `0x1000` (combined header size)
- **CheckSum**: loader checksum for validation
- **Subsystem**: required Windows subsystem (GUI/CUI)
- **DllCharacteristics**: compatibility/security flags
- **SizeOfStackReserve / Commit**: `0x100000` / `0x1000`
- **SizeOfHeapReserve / Commit**: `0x100000` / `0x1000`
- **LoaderFlags**: reserved, expected `0`
- **NumberOfRvaAndSizes**: `0x10` (16 Data Directory entries)

## 5. Data Directory

The Data Directory is an array of 16 `IMAGE_DATA_DIRECTORY` entries at the end of the Optional Header. Each entry provides an RVA/size pair referencing loader-critical tables.

For this sample, two entries relevant to behavioral and API analysis:

![Data Directory](/assets/img/pe-data-directory.png)

- **Import Directory**: `0x3C`
- **Import Address Table (IAT)**: `0x6C`

These structures govern imported API resolution and are central to static capability assessment and unpacking triage.

---
