#include "../../include/Resolver/PebUtils.h"

HMODULE FindNtdllBase()
{
    PPEB peb = GetPeb();

    if (!peb || !peb->Ldr)
    {
        return NULL;
    }

    PPEB_LDR_DATA ldr = peb->Ldr;

    /* walk InMemoryOrderModuleList (more reliable than InLoadOrder) */
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    while (entry != head && entry)
    {
        /* get the LDR_DATA_TABLE_ENTRY from the list entry */
        PLDR_DATA_TABLE_ENTRY_SYSCALLER ldrEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY_SYSCALLER, InMemoryOrderLinks);

        if (!ldrEntry || !ldrEntry->DllBase)
        {
            entry = entry->Flink;
            continue;
        }

        /* check if this is ntdll.dll by examining the BaseDllName */
        __try {
            if (ldrEntry->BaseDllName.Length > 0 && ldrEntry->BaseDllName.Buffer)
            {
                /* convert to lowercase for comparison */
                WCHAR baseNameLower[256] = {0};
                size_t len = ldrEntry->BaseDllName.Length / sizeof(WCHAR);
                if (len >= 256) len = 255;

                for (size_t i = 0; i < len; i++)
                {
                    baseNameLower[i] = (ldrEntry->BaseDllName.Buffer[i] >= L'A' && ldrEntry->BaseDllName.Buffer[i] <= L'Z') ?
                        ldrEntry->BaseDllName.Buffer[i] + 0x20 : ldrEntry->BaseDllName.Buffer[i];
                }

                if (wcsstr(baseNameLower, L"ntdll.dll") != NULL)
                {
                    return (HMODULE)ldrEntry->DllBase;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            /* skip this entry if we cant access the name */
            entry = entry->Flink;
            continue;
        }

        entry = entry->Flink;
    }

    return NULL;
}
