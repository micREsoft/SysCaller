#pragma once
#define CM_EXTENDED_PARAMETER_TYPE_BITS 8

// ADD THESE TO GITHUB LATER
#define PAGE_SIZE 0x1000
#define PAGE_MASK 0xFFF
#define PAGE_SHIFT 0xC

#define PAGE_NOACCESS 0x01              // Disables all access to the committed region of pages. An attempt to read from, write to, or execute the committed region results in an access violation.
#define PAGE_READONLY 0x02              // Enables read-only access to the committed region of pages. An attempt to write or execute the committed region results in an access violation.
#define PAGE_READWRITE 0x04             // Enables read-only or read/write access to the committed region of pages.
#define PAGE_WRITECOPY 0x08             // Enables read-only or copy-on-write access to a mapped view of a file mapping object.
#define PAGE_EXECUTE 0x10               // Enables execute access to the committed region of pages. An attempt to write to the committed region results in an access violation.
#define PAGE_EXECUTE_READ 0x20          // Enables execute or read-only access to the committed region of pages. An attempt to write to the committed region results in an access violation.
#define PAGE_EXECUTE_READWRITE 0x40     // Enables execute, read-only, or read/write access to the committed region of pages.
#define PAGE_EXECUTE_WRITECOPY 0x80     // Enables execute, read-only, or copy-on-write access to a mapped view of a file mapping object.
#define PAGE_GUARD 0x100                // Pages in the region become guard pages. Any attempt to access a guard page causes the system to raise a STATUS_GUARD_PAGE_VIOLATION exception.
#define PAGE_NOCACHE 0x200              // Sets all pages to be non-cachable. Applications should not use this attribute. Using interlocked functions with memory that is mapped with SEC_NOCACHE can result in an EXCEPTION_ILLEGAL_INSTRUCTION exception.
#define PAGE_WRITECOMBINE 0x400         // Sets all pages to be write-combined. Applications should not use this attribute. Using interlocked functions with memory that is mapped with SEC_NOCACHE can result in an EXCEPTION_ILLEGAL_INSTRUCTION exception.
#define PAGE_REVERT_TO_FILE_MAP     0x80000000 // Pages in the region can revert modified copy-on-write pages to the original unmodified page when using the mapped view of a file mapping object.
#define PAGE_ENCLAVE_THREAD_CONTROL 0x80000000 // Pages in the region contain a thread control structure (TCS) from the Intel Software Guard Extensions programming model.
#define PAGE_TARGETS_NO_UPDATE      0x40000000 // Pages in the region will not update the CFG bitmap when the protection changes. The default behavior for VirtualProtect is to mark all locations as valid call targets for CFG.
#define PAGE_TARGETS_INVALID        0x40000000 // Pages in the region are excluded from the CFG bitmap as valid targets. Any indirect call to locations in those pages will terminate the process using the __fastfail intrinsic.
#define PAGE_ENCLAVE_UNVALIDATED    0x20000000 // Pages in the region are excluded from measurement with the EEXTEND instruction of the Intel Software Guard Extensions programming model.
#define PAGE_ENCLAVE_NO_CHANGE      0x20000000
#define PAGE_ENCLAVE_MASK           0x10000000
#define PAGE_ENCLAVE_DECOMMIT       (PAGE_ENCLAVE_MASK | 0)
#define PAGE_ENCLAVE_SS_FIRST       (PAGE_ENCLAVE_MASK | 1)
#define PAGE_ENCLAVE_SS_REST        (PAGE_ENCLAVE_MASK | 2)

//
// Memory Region and Section Constants
//
#define GENERIC_ALL 0x10000000
#define MEM_COMMIT 0x00001000
#define MEM_RESERVE 0x00002000
#define MEM_DECOMMIT 0x00004000
#define MEM_RELEASE 0x00008000
#define MEM_FREE 0x00010000
#define MEM_PRIVATE 0x00020000
#define MEM_MAPPED 0x00040000
#define MEM_RESET 0x00080000
#define MEM_TOP_DOWN 0x00100000
#define MEM_WRITE_WATCH 0x00200000
#define MEM_PHYSICAL 0x00400000
#define MEM_ROTATE 0x00800000
#define MEM_DIFFERENT_IMAGE_BASE_OK 0x00800000
#define MEM_RESET_UNDO 0x01000000
#define MEM_LARGE_PAGES 0x20000000
#define MEM_DOS_LIM 0x40000000
#define MEM_4MB_PAGES 0x80000000
#define MEM_64K_PAGES (MEM_LARGE_PAGES | MEM_PHYSICAL)
#define MEM_UNMAP_WITH_TRANSIENT_BOOST 0x00000001
#define MEM_COALESCE_PLACEHOLDERS 0x00000001
#define MEM_PRESERVE_PLACEHOLDER 0x00000002
#define MEM_REPLACE_PLACEHOLDER 0x00004000
#define MEM_RESERVE_PLACEHOLDER 0x00040000
#define SEC_HUGE_PAGES 0x00020000
#define SEC_PARTITION_OWNER_HANDLE 0x00040000
#define SEC_64K_PAGES 0x00080000
#define SEC_DRIVER_IMAGE 0x00100000 // rev
#define SEC_BASED 0x00200000
#define SEC_NO_CHANGE 0x00400000
#define SEC_FILE 0x00800000
#define SEC_IMAGE 0x01000000
#define SEC_PROTECTED_IMAGE 0x02000000
#define SEC_RESERVE 0x04000000
#define SEC_COMMIT 0x08000000
#define SEC_NOCACHE 0x10000000
#define SEC_GLOBAL 0x20000000
#define SECTION_ALL_ACCESS 0x10000000
#define SEC_WRITECOMBINE 0x40000000
#define SEC_LARGE_PAGES 0x80000000
#define SEC_IMAGE_NO_EXECUTE (SEC_IMAGE | SEC_NOCACHE)