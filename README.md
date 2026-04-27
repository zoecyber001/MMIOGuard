# MMIOGuard

Windows Kernel Driver MMIO Vulnerability Scanner

## What is MmMapIoSpace?

`MmMapIoSpace` is a Windows kernel-mode function that maps a physical address into virtual memory, allowing the kernel to access hardware I/O memory (MMIO - Memory-Mapped I/O).

```c
PVOID MmMapIoSpace(
    PHYSICAL_ADDRESS PhysicalAddress,  // Input: physical address to map
    SIZE_T NumberOfBytes,               // Size to map
    MEMORY_CACHING_TYPE CacheType      // Caching type
);
```

### The Vulnerability

Many kernel drivers use `MmMapIoSpace` to map physical addresses provided by user-mode applications:

```c
// VULNERABLE: No validation
NTSTATUS DrvIoctl(PVOID param_1) {
    PVOID mapped = MmMapIoSpace(param_1, 4, MmNonCached); // param_1 from user!
    // ... read/write physical memory
}
```

This is **critical** because an attacker can:
- Pass any physical address
- Read arbitrary kernel memory
- Write to any physical memory location
- Achieve kernel privilege escalation

### Why It's Dangerous

A user-mode application can pass any physical address:
- Read kernel memory (credential theft, secrets)
- Write to device registers (privilege escalation)
- Access physical memory directly

## What This Tool Detects

MMIOGuard scans kernel driver source code for vulnerable `MmMapIoSpace` patterns:

1. **Direct user input** - Physical addresses from user-mode
2. **Missing validation** - No address range checks
3. **Function parameters** - Passed directly to MmMapIoSpace

### Detection Examples

```c
// DETECTED: No validation
NTSTATUS Read物理Addr(PVOID addr) {
    map = MmMapIoSpace(addr, 4, 0);  // VULN: addr not validated
}

// IGNORED: Has validation
NTSTATUS SafeRead(PVOID addr) {
    if (!Validate(addr)) return ERROR;  // Validated!
    map = MmMapIoSpace(addr, 4, 0);   // OK
}
```

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

```bash
# Scan a single file
python mmio_scanner.py driver.c

# Scan a directory
python mmio_scanner.py /path/to/drivers/

# JSON output for CI/CD
python mmio_scanner.py /path/to/drivers/ -j results.json
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `-e` | File extensions | .c .cpp .h .hpp |
| `-v` | Verbose output | false |
| `-o` | Text output file | - |
| `-j` | JSON output file | - |

## Example Output

```
=== MMIO Vulnerability Scan Results ===

[FILE] driver.c
  [VULN] Line 42: function parameter 'phys_addr' passed to MmMapIoSpace without validation
  [VULN] Line 87: user-controlled address 'irpbp->UserBuffer' passed to MmMapIoSpace

Summary: 2 VULN | 0 LIKELY_VULN | 0 CHECK
```

## Exit Codes

- `0` - No vulnerabilities found
- `1` - Vulnerabilities found

## Related CVEs

This scanner detects vulnerabilities similar to these real-world CVEs:

| CVE | Driver | Description |
|-----|--------|-------------|
| CVE-2024-36055 | Hw64.sys (Marvin Test) | Arbitrary physical memory mapping |
| CVE-2024-34332 | SANDRA | MmMapIoSpace without validation |
| CVE-2024-26507 | AIDA64 | Arbitrary physical memory read/write |
| CVE-2024-41498 | IOMap64.sys | Physical memory read/write primitive |
| CVE-2020-15368 | Win32k.sys | MmMapIoSpace exploitation |

These CVEs all share the same root cause: **no validation on physical address passed to MmMapIoSpace**.

## License

MIT License